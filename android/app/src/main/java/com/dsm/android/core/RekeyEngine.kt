package com.dsm.android.core

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Minimal session state for the rekey FSM. Mirrors the `State` values
 * `dsm/rekey.py` and `dsm/session.py` exercise on the data path. The Android
 * side does not validate transitions (the full `SessionFSM` guard lives in the
 * Python core) — it only tracks ESTABLISHED vs REKEYING to gate init/ack.
 */
enum class SessionState { ESTABLISHED, REKEYING }

/**
 * Mutable rekey state shared by the send/recv paths. Mirrors `RekeyState` in
 * `dsm/session.py` (lines 589-629).
 */
class RekeyState {
    var inProgress = false
    var lastTimeMs: Long? = null
    var pendingEpoch: Int? = null
    var lastInitPayload: ByteArray? = null
    var lastInitSentAtMs: Long? = null
    var retriesUsed = 0
    var cachedAckPayload: ByteArray? = null
    var cachedAckEpoch: Int? = null

    fun resetRetry() {
        lastInitPayload = null
        lastInitSentAtMs = null
        retriesUsed = 0
    }
}

/**
 * Key-rotation state machine, porting `dsm/rekey.py` and the rekey handlers in
 * `dsm/session.py` (`tun_send_loop` initiate/retry, `_handle_rekey_ack`,
 * `_handle_rekey_init`).
 *
 * Rekey packets ride the bounded direct send path here (the paced-envelope
 * `paced_send` variant is the anonymity-shaper concern, Task B3b). [sendInner]
 * frames+encrypts+sends one inner packet; [onTeardown] is invoked when the
 * retry budget is exhausted; [onRekeyComplete] fires after a successful
 * initiator rotation so the caller can rebind its UDP port (H-ANON-4).
 */
class RekeyEngine(
    private val crypto: SessionCrypto,
    private val state: RekeyState,
    private val localStaticPub: ByteArray,
    private val remoteStaticPub: ByteArray,
    private val clock: MonotonicClock,
    private val sendInner: (InnerPacket) -> Unit,
    private val onTeardown: () -> Unit,
    private val onRekeyComplete: () -> Unit,
    private val log: (String) -> Unit = {},
) {
    @Volatile
    var fsmState: SessionState = SessionState.ESTABLISHED
        private set

    /**
     * Send side: start a rotation when due and none is in flight. Mirrors the
     * `needs_rotation()` block in `tun_send_loop` + `initiate_rekey`.
     */
    fun maybeInitiate() {
        if (!crypto.needsRotation() || state.inProgress) return
        if (fsmState != SessionState.ESTABLISHED) {
            log("cannot initiate rekey in state $fsmState")
            return
        }
        if (isRateLimited()) return

        // Rate-limit/state checks done BEFORE initiateRotation so we never leave
        // a dangling pending rotation in the manager (mirrors the ordering note
        // in tun_send_loop: do NOT commit in_progress before a real INIT goes).
        fsmState = SessionState.REKEYING
        val init = crypto.initiateRotation()
        val payload = packRekeyPayload(init.newEpoch, init.ephemeralPub)
        sendRekey(PacketType.REKEY_INIT, payload)
        val now = clock.nowMillis()
        state.lastTimeMs = now
        state.pendingEpoch = init.newEpoch
        state.inProgress = true
        state.lastInitPayload = payload
        state.lastInitSentAtMs = now
        state.retriesUsed = 0
        log("rekey initiated, new epoch=${init.newEpoch}")
    }

    /**
     * Send side: retransmit the in-flight INIT on ACK timeout; tear down after
     * MAX_REKEY_RETRIES. Mirrors the retry scheduler in `tun_send_loop`.
     */
    fun maybeRetry() {
        if (!state.inProgress) return
        val payload = state.lastInitPayload ?: return
        val sentAt = state.lastInitSentAtMs ?: return
        if (clock.nowMillis() - sentAt < REKEY_ACK_TIMEOUT_MS) return

        if (state.retriesUsed >= MAX_REKEY_RETRIES) {
            log("rekey giving up after ${state.retriesUsed} retries — tearing down")
            onTeardown()
            return
        }
        state.retriesUsed += 1
        log("rekey ACK timeout — retransmitting INIT (attempt ${state.retriesUsed}/$MAX_REKEY_RETRIES)")
        sendRekey(PacketType.REKEY_INIT, payload)
        state.lastInitSentAtMs = clock.nowMillis()
    }

    /**
     * Recv side: complete an initiator rotation on REKEY_ACK. Returns true iff
     * the rotation completed (caller then rebinds its UDP port). Mirrors
     * `handle_rekey_ack` + the `_handle_rekey_ack` cleanup.
     */
    fun handleAck(payload: ByteArray): Boolean {
        if (fsmState != SessionState.REKEYING) {
            log("rekey ack received in state $fsmState, ignoring")
            return false
        }
        val expected = state.pendingEpoch
        if (expected == null) {
            log("rekey ack received but no rekey was initiated, ignoring")
            return false
        }
        var completed = false
        if (payload.size < REKEY_PAYLOAD_SIZE) {
            log("rekey ack payload too short, ignoring")
        } else {
            val ackEpoch = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN).int
            if (ackEpoch != expected) {
                // Mirror handle_rekey_ack: returns None WITHOUT an FSM transition
                // on epoch mismatch (NB: this leaves fsmState REKEYING — see the
                // matching Python behaviour).
                log("rekey ack epoch mismatch: got $ackEpoch, expected $expected")
            } else {
                val remoteEph = payload.copyOfRange(4, 36)
                try {
                    val newEpoch = crypto.completeRotationInitiator(remoteEph)
                    fsmState = SessionState.ESTABLISHED
                    completed = true
                    log("rekey completed as initiator, epoch=$newEpoch")
                } catch (e: Exception) {
                    log("rekey initiator completion failed: ${e.message}")
                    fsmState = SessionState.ESTABLISHED
                }
            }
        }
        // _handle_rekey_ack clears pending state on BOTH success and failure so a
        // stale counter cannot block the next needs_rotation()-driven cycle.
        state.pendingEpoch = null
        state.resetRetry()
        state.inProgress = false
        if (completed) onRekeyComplete()
        return completed
    }

    /**
     * Recv side: respond to a REKEY_INIT (two-phase responder), including the
     * mutual-init tie-break/abort. Mirrors `handle_rekey_init`.
     */
    fun handleInit(payload: ByteArray) {
        if (fsmState != SessionState.ESTABLISHED) {
            if (fsmState == SessionState.REKEYING && state.inProgress) {
                // Both sides initiated within an RTT: the lower canonical static
                // pub "wins" and keeps its INIT; the higher pub yields.
                if (lessThanUnsigned(localStaticPub, remoteStaticPub)) {
                    log("mutual REKEY_INIT race — local pub is lower; keeping our INIT")
                    return
                }
                log("mutual REKEY_INIT race — local pub is higher; yielding to peer")
                if (!crypto.abortRotation()) {
                    log("mutual-init yield: no pending rotation to abort (unexpected)")
                }
                state.inProgress = false
                state.resetRetry()
                state.pendingEpoch = null
                fsmState = SessionState.ESTABLISHED
                // fall through to process the peer's INIT
            } else {
                log("rekey init received in state $fsmState, ignoring")
                return
            }
        }

        if (payload.size < REKEY_PAYLOAD_SIZE) {
            log("rekey init payload too short, ignoring")
            return
        }
        val newEpoch = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN).int
        val remoteEph = payload.copyOfRange(4, 36)

        // Duplicate-INIT short-circuit: our previous ACK was lost. If we are
        // already at the requested epoch and have the ACK cached, re-send it.
        val cachedEpoch = state.cachedAckEpoch
        val cachedAck = state.cachedAckPayload
        if (cachedEpoch != null && cachedEpoch == newEpoch && crypto.epoch() == newEpoch && cachedAck != null) {
            log("duplicate REKEY_INIT for epoch $newEpoch — re-sending cached ACK")
            sendRekey(PacketType.REKEY_ACK, cachedAck)
            return
        }

        if (isRateLimited()) {
            log("REKEY_INIT received but last rekey was recent; dropping (initiator will retransmit)")
            return
        }

        fsmState = SessionState.REKEYING

        // Two-phase: derive new keys (prepare) but send the ACK under the OLD
        // keys before apply, so the still-old-epoch peer can decrypt it.
        val prepared = try {
            crypto.prepareRotationResponder(remoteEph, newEpoch)
        } catch (e: Exception) {
            log("rekey responder prepare failed: ${e.message}")
            fsmState = SessionState.ESTABLISHED
            return
        }
        val ackPayload = packRekeyPayload(prepared.newEpoch, prepared.ourEphemeralPub)
        sendRekey(PacketType.REKEY_ACK, ackPayload)

        val completedEpoch = try {
            crypto.applyRotationResponder()
        } catch (e: Exception) {
            log("rekey responder apply failed: ${e.message}")
            fsmState = SessionState.ESTABLISHED
            return
        }
        fsmState = SessionState.ESTABLISHED
        state.lastTimeMs = clock.nowMillis()
        // Cache the ACK (under the NEW keys after apply) so a retransmitted INIT
        // is answered with the same bytes instead of a re-rotate.
        state.cachedAckEpoch = completedEpoch
        state.cachedAckPayload = ackPayload
        log("rekey completed as responder, epoch=$completedEpoch")
    }

    private fun sendRekey(ptype: PacketType, payload: ByteArray) {
        // epoch_id is stamped at build time from the live epoch (the bounded
        // direct path has no queue delay, so no send-time re-stamp is needed;
        // the paced path's H-BUG-1 re-stamp is a B3b concern).
        sendInner(InnerPacket(ptype, crypto.epoch() and 0x0F, payload))
    }

    private fun isRateLimited(): Boolean {
        val last = state.lastTimeMs ?: return false
        return clock.nowMillis() - last < MIN_REKEY_INTERVAL_MS
    }

    private fun packRekeyPayload(epoch: Int, ephemeralPub: ByteArray): ByteArray =
        ByteBuffer.allocate(4 + ephemeralPub.size)
            .order(ByteOrder.BIG_ENDIAN)
            .putInt(epoch)
            .put(ephemeralPub)
            .array()

    companion object {
        /** 4 (epoch) + 32 (ephemeral pub). Mirrors `REKEY_PAYLOAD_SIZE`. */
        const val REKEY_PAYLOAD_SIZE = 36

        /** Minimum interval between rekeys. Mirrors `MIN_REKEY_INTERVAL` (60 s). */
        const val MIN_REKEY_INTERVAL_MS = 60_000L

        /** ACK-timeout before retransmit. Mirrors `REKEY_ACK_TIMEOUT` (8 s). */
        const val REKEY_ACK_TIMEOUT_MS = 8_000L

        /** Max INIT retransmits before teardown. Mirrors `MAX_REKEY_RETRIES`. */
        const val MAX_REKEY_RETRIES = 9

        /** Unsigned lexicographic compare: true iff a < b (`bytes(a) < bytes(b)`). */
        private fun lessThanUnsigned(a: ByteArray, b: ByteArray): Boolean {
            val n = minOf(a.size, b.size)
            for (i in 0 until n) {
                val ai = a[i].toInt() and 0xFF
                val bi = b[i].toInt() and 0xFF
                if (ai != bi) return ai < bi
            }
            return a.size < b.size
        }
    }
}
