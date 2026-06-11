# Phase 1 — Reliability & Data-Path Correctness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make DSM's data path correct and crash-safe — rekey recovers from a lost ACK and can never wedge, server forwarding works, IPv6/resolv.conf/sysctls survive partial-configure and SIGKILL, TCP framing is segment-safe, PMTU is respected, the daemon exits nonzero and re-accepts, and config/CLI/example are usable.

**Architecture:** Twelve master-plan items (1.1–1.12) plus one security sub-task (1.13), implemented TDD-first against the real working tree. Most fixes are surgical edits to existing Python modules; one (1.2) is a behavior change to the existing Rust `tuncore` method `prepare_rotation_responder` (tolerate/overwrite a stale pending — NO new public API, per owner decision 2026-06-11); one (1.9) adds a `dsm cleanup` subcommand consumed by a systemd `ExecStopPost`.

**Tech Stack:** Python 3.11+ asyncio, `pytest`/`unittest`, Rust (PyO3/maturin `tuncore`), nftables, systemd, `dnspython`, `tomllib`, `argparse`.

---

## Environment notes (apply to every step)

- **Python tests** run from the repo root: `python3 -m pytest tests/<file> -q`. The system `python3` already has `dsm` + `tuncore` importable.
- **Rust tests:** `cargo test --release --manifest-path rust/tuncore/Cargo.toml <filter>` (release — the 512 MiB Argon2 tests are slow in dev).
- **After any Rust change**, rebuild + reinstall the wheel before re-running Python tests that touch tuncore (`maturin develop` does NOT work — there is no venv):
  ```bash
  maturin build --release -m rust/tuncore/Cargo.toml && \
  pip3 install --user --force-reinstall --break-system-packages \
    rust/tuncore/target/wheels/dsm_tuncore-0.1.0-cp313-cp313-manylinux_2_34_x86_64.whl
  ```
- **No git commits anywhere.** Each task ends with a one-line "Report" step. The owner commits.
- **Never edit a pre-existing test file.** New tests go in NEW files. The only test files this effort created and MAY edit are: `test_handshake_dos.py`, `test_dns_proxy_source.py`, `test_attest_gate.py`, `test_config_perms.py`, `test_hardening.py`, `test_netaudit_no_leak.py`. Edits to any of those are called out explicitly where they occur.
- Type hints on all new Python signatures; `black`/88; specific exceptions; `raise X from e`. Rust: `String` errors (the crate's convention), no `unwrap` outside tests, `zeroize` on key material, `OsRng`.

---

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `dsm/rekey.py` | Modify | 1.1 ACK exempt+old-key re-encrypt cache; 1.2 abort on ACK-send timeout. |
| `dsm/session.py` | Modify | 1.1 exempt REKEY_ACK from `decrypt_packet` epoch check; 1.6 stop wrapping framed TCP recv in `wait_for`; 1.7 clamp shaper ceiling in `auto_mtu_loop`. |
| `dsm/net/transport/tcp.py` | Modify | 1.6 store partial-frame state across `recv()` calls; add a separate idle-tick path. |
| `dsm/net/tunnel.py` | Modify | 1.3 `server_mode` flag on `configure()`; 1.4 separate IPv6-mutation flag + global `all`/`default` capture/restore. |
| `dsm/net/resolv_conf.py` | Modify | 1.5 managed-marker self-capture guard + persistent `/var/lib/dsm/resolv.conf.orig` backup. |
| `dsm/traffic/shaper.py` | Modify | 1.7 `set_size_class_ceiling()`; 1.11 `padding_min>max-class` clamp. |
| `dsm/net/dns.py` | Modify | 1.10 IP-literal-only providers; NXDOMAIN/NODATA vs transport-failure typed result; `_cache_heap` bound; TTL clamp. |
| `dsm/net/dns_proxy.py` | Modify | 1.10 relay NXDOMAIN/NODATA instead of SERVFAIL. |
| `dsm/__main__.py` | Modify | 1.8 `sys.exit(run_*)`; ConfigError→stderr+exit(2); 1.9 `cleanup` subcommand; 1.11 SUPPRESS passphrase defaults, enroll CSR-path precheck. |
| `dsm/client.py` | Modify | 1.8 return int exit status; signal handlers before pre-killswitch. |
| `dsm/server.py` | Modify | 1.8 return int exit status; sequential re-accept loop; 1.13 coarse cert-auth audit label. |
| `dsm/core/config.py` | Modify | 1.11 type-check pass; `key_file` absolute; IPv6 `server_ip` reject; `DEFAULT_TUN_MTU` decision. |
| `dsm/core/atomic_io.py` | Modify | 1.11 loop `os.write` return value. |
| `dsm/net/cleanup.py` | Create | 1.9 idempotent host-state cleanup used by `dsm cleanup`. |
| `deploy/dsm.service` | Modify | 1.9 `ExecStopPost`, `StartLimit*`→`[Unit]`, `CAP_IPC_LOCK` doc. |
| `config.example.toml` | Modify | 1.12 boot-as-shipped + document every field. |
| `rust/tuncore/src/lib.rs` | Modify | 1.2 `prepare_rotation_responder` tolerates/overwrites a stale pending (behavior change, no new API). |
| `tests/test_rekey_lost_ack.py` | Create | 1.1 regression. |
| `tests/test_rekey_responder_abort.py` | Create | 1.2 wedge-recovery regression. |
| `tests/test_tunnel_server_mode.py` | Create | 1.3 command-list assertions. |
| `tests/test_tunnel_ipv6_restore.py` | Create | 1.4 partial-configure + global-restore. |
| `tests/test_resolv_conf_crash.py` | Create | 1.5 self-capture crash safety. |
| `tests/test_tcp_framing.py` | Create | 1.6 split-frame desync. |
| `tests/test_pmtu_shaper.py` | Create | 1.7 ceiling clamp. |
| `tests/test_lifecycle.py` | Create | 1.8 exit codes / handler ordering / re-accept. |
| `tests/test_cleanup.py` | Create | 1.9 `dsm cleanup` command. |
| `tests/test_dns_robustness.py` | Create | 1.10 IP-literal/NXDOMAIN/cache-bound. |
| `tests/test_config_ux.py` | Create | 1.11 type-check/key_file/IPv6/atomic_write/padding clamp. |
| `tests/test_example_config.py` | Create | 1.12 example boots as shipped. |
| `tests/test_netaudit_no_leak.py` | **Modify (effort-created file)** | 1.13 update server expectation to `error="cert_auth"`. |

---

## FLAG FOR OWNER — read before execution

1. **tuncore behavior change, NO new API (1.2) — owner-decided 2026-06-11:** instead of adding `abort_responder_rotation()`, Task 1.2 changes the EXISTING `prepare_rotation_responder` to overwrite a stale `pending_responder_rotation` instead of erroring. No PyO3/`.pyi` surface change. SAFETY (verified): the only path that leaves a lingering pending is the ACK-send-timeout (rekey.py:301–304); a successful rotation applies-and-clears within the same `handle_rekey_init` call, and `apply_rotation_responder` `.take()`s the pending even on its own error path — so any pending a later `prepare` finds is ALWAYS stale, and overwriting it can never clobber a legitimate in-flight rotation. The abandoned `ResponderPending` (LockedKey32 send/recv keys) is zeroized on drop. Tradeoff vs the abort-API: the stale keys linger until the next REKEY_INIT (one rekey interval) rather than being dropped immediately on timeout — accepted.
2. **Existing-test expectation change (1.13):** the effort-created `tests/test_netaudit_no_leak.py` currently asserts the **server** emit yields `error == "CNNotAllowedError"`. Coarsening to `error == "cert_auth"` for cert-auth classes requires updating that assertion. The file is editable (effort-created), but the change is deliberate — approve the new expectation.
3. **netaudit schema lock is bidirectional (1.13):** task 1.13 does NOT add a new event *name* (it changes a field *value* on the existing `handshake_end` event), so `tests/test_netaudit.py::EXPECTED_EVENT_NAMES` needs no edit. No pre-existing-test edit is required for 1.13 beyond the no-leak file. Confirmed: no new emit() name is introduced.

## DESIGN FORKS — confirm with owner before execution

- **A. TCP framing (1.6):** chosen approach = *buffer partial-frame state inside `TCPTransport`* and stop wrapping the framed read in a 0.1 s `wait_for`; drive the per-loop idle `tick()` from a separate timer task instead. The alternative (keep `wait_for`, make `recv()` resumable) is more invasive. **Confirm approach.**
- **B. Server re-accept shape (1.8):** chosen approach = *wrap the post-handshake session block in an outer `while not shutdown` loop* that tears down per-session host state and returns to the accept phase (single active session preserved, per owner decision). The alternative (document single-session + `Restart=always`) is rejected because it relies on systemd churn. **Confirm approach.**
- **C. `DEFAULT_TUN_MTU` (1.11):** the finding recommends lowering 1400→1360 so a full TUN packet fits one 1400-class outer. Lowering the default changes throughput characteristics for every existing deployment. Chosen default for this plan = **keep 1400, fix the misleading overhead comment, and rely on 1.7's auto_mtu clamp** for constrained paths; do NOT silently lower the shipped default. **Confirm: keep 1400 (comment-only fix) vs lower to 1360.**

---

## Task 1.1: Rekey lost-ACK recovery

**Problem (rekey.py ~228–253, session.py ~355–364):** when the initiator's first INIT got an ACK that was lost, the initiator retransmits the SAME INIT while still at the OLD epoch. The responder's duplicate-INIT short-circuit re-sends the cached ACK, but `_send_rekey_packet` stamps `epoch_id = session_keys.epoch & 0x0F` (the NEW epoch) and `make_send_fn` re-patches the header byte to NEW. The initiator, still at OLD epoch, drops it twice: `decrypt_packet`'s epoch check (session.py:355–364) requires `inner.epoch_id == session_keys.epoch & 0x0F`, and the cached ACK is now NEW-stamped. The documented lost-ACK recovery never lands and the initiator tears down after `MAX_REKEY_RETRIES`.

**Wire-format facts (verified):** `REKEY_ACK` carries its own 4-byte epoch field in the payload (`ack_payload = struct.pack("!I", prepared_epoch) + our_pub`), and `handle_rekey_ack` validates that field against `expected_epoch` (rekey.py:346–351) before completing. So the ACK *self-validates* via its payload epoch + AEAD; the outer `inner.epoch_id` nibble check is redundant for REKEY_ACK and is exactly what blocks recovery.

**Fix:** exempt `REKEY_ACK` from the `decrypt_packet` epoch-id check (it self-validates), AND have the responder re-send the cached ACK so the still-old-epoch initiator can decrypt it. The responder's `send` key stays on the OLD key for `GRACE_PERIOD_SECS` after `apply_rotation_responder` (deferred-send-swap, verified in session_keys.rs `apply_rotation_with_grace` / `tick`), so a cached-ACK re-send during grace already encrypts under the OLD send key — the initiator can decrypt it. The only blocker is the receiver-side nibble check. Exempting REKEY_ACK there is sufficient and minimal.

**Files:**
- Modify: `dsm/session.py:355` (the `if inner.ptype != PacketType.CHAFF:` epoch-id guard)
- Test: `tests/test_rekey_lost_ack.py` (Create)

- [ ] **Step 1: Write the failing test**

```python
"""Phase 1.1 regression: a lost REKEY_ACK recovers without teardown.

decrypt_packet must NOT drop a REKEY_ACK on the epoch-id nibble check —
the ACK self-validates via its own 4-byte epoch field + AEAD, and the
initiator that retransmits its INIT is still at the OLD epoch so a
NEW-stamped ACK would otherwise be dropped (Phase 1.1).
"""

from __future__ import annotations

import unittest

try:
    import tuncore

    _HAS_TUNCORE = True
except ImportError:
    tuncore = None  # type: ignore[assignment]
    _HAS_TUNCORE = False

from dsm.core.protocol import (
    GCM_TAG_SIZE,
    OUTER_HEADER_SIZE,
    SEQ_STRUCT,
    InnerPacket,
    OuterPacket,
    PacketType,
)
from dsm.session import decrypt_packet


def _pair() -> tuple[tuncore.SessionKeyManager, tuncore.SessionKeyManager]:
    ours = tuncore.BootstrapEphemeral.generate()
    peer = tuncore.BootstrapEphemeral.generate()
    our_pub = ours.public_key_bytes
    peer_pub = peer.public_key_bytes
    initiator = tuncore.complete_bootstrap(ours, peer_pub, True)
    responder = tuncore.complete_bootstrap(peer, our_pub, False)
    return initiator, responder


@unittest.skipUnless(_HAS_TUNCORE, "tuncore extension not built")
class RekeyAckEpochExempt(unittest.TestCase):
    def test_rekey_ack_new_stamp_decrypts_at_old_epoch_during_grace(self) -> None:
        initiator, responder = _pair()
        start_epoch = responder.epoch

        # Rotate the RESPONDER one epoch, leaving the INITIATOR at the OLD
        # epoch — this simulates the lost-ACK case: the initiator never got
        # the first ACK, never completed rotation, and is retransmitting its
        # INIT. The responder uses the deferred-send-swap (session_keys.rs
        # H-BUG-2/3), so it now reports epoch+1 but still SENDS under the OLD
        # (start_epoch) key for the grace window. responder_send(start_epoch)
        # == initiator_recv(start_epoch), so the initiator can still decrypt.
        rot_eph = tuncore.BootstrapEphemeral.generate()
        new_epoch = start_epoch + 1
        responder.prepare_rotation_responder(rot_eph.public_key_bytes, new_epoch)
        responder.apply_rotation_responder()
        # The recv-swap is immediate so epoch() should already report new_epoch
        # while the send key stays old during grace. If epoch() lags, derive
        # new_eid from new_epoch directly — the test needs ack epoch_id != the
        # initiator's expected (start_epoch) nibble.
        self.assertEqual(initiator.epoch, start_epoch)

        # Build a REKEY_ACK stamped with the NEW epoch nibble — exactly what
        # _send_rekey_packet + make_send_fn produce when re-sending the cached
        # ACK — and AEAD-encrypt it via the responder (which is in send-grace,
        # so the bytes go out under the OLD send key).
        new_eid = new_epoch & 0x0F
        ack_payload = new_epoch.to_bytes(4, "big") + b"\x00" * 32
        inner = InnerPacket(
            ptype=PacketType.REKEY_ACK, epoch_id=new_eid, payload=ack_payload
        )
        plaintext = inner.serialize()
        seq = 1
        aad = SEQ_STRUCT.pack(seq)
        nonce, ct, _e = responder.encrypt(plaintext, aad)
        wire = OuterPacket(
            seq=seq, nonce=bytes(nonce), ciphertext=bytes(ct)
        ).serialize(OUTER_HEADER_SIZE + len(ct))

        # Initiator is still at start_epoch: its current-epoch recv key matches
        # the responder's grace send key, so AEAD succeeds — but the inner
        # epoch_id nibble (new) != the initiator's expected (old), so WITHOUT
        # the fix decrypt_packet drops the ACK on the nibble check.
        replay = tuncore.ReplayWindow()
        result = decrypt_packet(wire, initiator, replay)
        self.assertIsNotNone(result, "REKEY_ACK must survive the epoch nibble check")
        out_inner, _prev = result
        self.assertEqual(out_inner.ptype, PacketType.REKEY_ACK)
        self.assertEqual(out_inner.payload, ack_payload)

    def test_data_packet_still_dropped_on_epoch_mismatch(self) -> None:
        # Control: DATA with a wrong epoch_id nibble is STILL dropped (the
        # exemption must be REKEY_ACK-only). Same-epoch pair, deliberately
        # wrong nibble.
        sender, receiver = _pair()
        wrong_eid = (sender.epoch + 1) & 0x0F
        inner = InnerPacket(
            ptype=PacketType.DATA, epoch_id=wrong_eid, payload=b"hello"
        )
        plaintext = inner.serialize()
        seq = 1
        aad = SEQ_STRUCT.pack(seq)
        nonce, ct, _epoch = sender.encrypt(plaintext, aad)
        wire = OuterPacket(seq=seq, nonce=bytes(nonce), ciphertext=bytes(ct)).serialize(
            OUTER_HEADER_SIZE + len(ct)
        )
        replay = tuncore.ReplayWindow()
        self.assertIsNone(decrypt_packet(wire, receiver, replay))


if __name__ == "__main__":
    unittest.main()
```

> **CRITICAL for the implementer:** the regression test MUST actually rotate the responder (above) so it reports a DIFFERENT epoch than the initiator — otherwise the nibble matches and the test passes vacuously (proving nothing). Verify at Step 2 that `test_rekey_ack_new_stamp_decrypts_at_old_epoch_during_grace` genuinely FAILS before the fix and PASSES after. If `responder.epoch` does NOT advance immediately after `apply_rotation_responder` (i.e. it stays at `start_epoch`), then the grace-send-key and the stamped nibble would both be `start_epoch` and the test can't reproduce the mismatch — in that case STOP and report, because the premise (responder reports new epoch while sending old) needs re-checking against `session_keys.rs`. Also confirm `tuncore.encrypt(plaintext, aad)` does NOT itself rewrite the inner `epoch_id` byte (the H-BUG-1 epoch patching lives in `dsm/session.py`'s `encrypt_packet`, not in the Rust `encrypt`); if the Rust call leaves the plaintext untouched, the manually-stamped `new_eid` is preserved as intended.

- [ ] **Step 2: Run the test to verify the control passes and the regression fails**

Run: `python3 -m pytest tests/test_rekey_lost_ack.py -q`
Expected: `test_data_packet_still_dropped_on_epoch_mismatch` PASSES; `test_rekey_ack_new_stamp_decrypts_at_old_epoch_during_grace` FAILS at `assertIsNotNone` because the current code drops REKEY_ACK when its epoch nibble doesn't match the receiver's epoch. If the regression test PASSES before the fix, the rotation didn't take effect — STOP and report (see the CRITICAL note above).

- [ ] **Step 3: Exempt REKEY_ACK from the epoch-id nibble check**

In `dsm/session.py`, change the guard at line 355 from CHAFF-only to also exempt REKEY_ACK:

```python
    # Verify epoch_id matches the key epoch used for decryption.
    # Audit M3: epoch_id widened to 4 bits (0x0F mask).
    #
    # Phase 1.1: REKEY_ACK is ALSO exempt. A re-sent cached ACK is stamped
    # with the responder's NEW epoch nibble, but a retransmitted INIT means
    # the initiator is still at the OLD epoch, so the nibble check would drop
    # the very ACK that completes recovery. REKEY_ACK self-validates via its
    # own 4-byte epoch field (handle_rekey_ack checks it against
    # pending_epoch) plus AEAD, so the outer nibble check is redundant for it.
    if inner.ptype not in (PacketType.CHAFF, PacketType.REKEY_ACK):
        if decrypted_prev_epoch:
            expected_eid = (session_keys.epoch - 1) & 0x0F
        else:
            expected_eid = session_keys.epoch & 0x0F
        if inner.epoch_id != expected_eid:
            log.debug(
                "epoch_id mismatch: got %d, expected %d", inner.epoch_id, expected_eid
            )
            return None
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_rekey_lost_ack.py -q`
Expected: both tests PASS.

- [ ] **Step 5: Run the focused gate**

Run: `python3 -m pytest tests/test_rekey_lost_ack.py tests/test_data_path_integration.py -q`
Expected: PASS (no regression in the existing data-path round-trip).

- [ ] **Step 6: Report** — one line: REKEY_ACK exempted from the receiver epoch-id nibble check so a lost-ACK retransmit recovers; DATA still epoch-checked.

---

## Task 1.2: Responder-rotation wedge — tolerate a stale pending in `prepare_rotation_responder` (NO new API)

> **Owner decision (2026-06-11):** fix this WITHOUT adding a new `tuncore` method. Change the existing `prepare_rotation_responder` to overwrite a stale `pending_responder_rotation` instead of erroring. The wedge self-heals on the next REKEY_INIT.

**Problem (rekey.py ~290–304, lib.rs ~563–595):** `prepare_rotation_responder` stores `pending_responder_rotation` inside the Rust `PySessionKeyManager`. If the REKEY_ACK send then times out (rekey.py:301, the `except TimeoutError` path), `handle_rekey_init` logs, transitions to ESTABLISHED, and returns WITHOUT calling `apply_rotation_responder`. `pending_responder_rotation` is only cleared by `apply`. Every later REKEY_INIT then fails `prepare_rotation_responder` with `"responder rotation already prepared"` (lib.rs:568–569), which `handle_rekey_init` catches and drops (rekey.py:281–284). The responder can never rotate again.

**Fix + safety argument:** remove the `is_some()` early-error in `prepare_rotation_responder` and instead `take()` (drop) any stale pending before deriving the fresh one. This is safe — and CANNOT clobber a legitimate in-flight rotation — because the ONLY path that leaves a lingering pending is the ACK-send-timeout: in `handle_rekey_init` the success path is prepare (rekey.py:277) → send ACK (291) → apply (308) all in one call, and `apply_rotation_responder` `.take()`s the pending even on its own error path (lib.rs:587–589). So any pending a later `prepare` finds is ALWAYS a stale failed-ACK one; dropping it (which zeroizes its `LockedKey32` send/recv keys) and preparing fresh is exactly the recovery we want. No PyO3 surface change, no `.pyi` change. Tradeoff: the stale keys linger until the next REKEY_INIT rather than being dropped on timeout — accepted by the owner.

### Part A — Rust behavior change

**Files:**
- Modify: `rust/tuncore/src/lib.rs:568–578` (`prepare_rotation_responder` body)
- Test: inline `#[cfg(test)]` in `rust/tuncore/src/lib.rs`

- [ ] **Step 1: Verify the inner method is stateless w.r.t. pending.** Read `rust/tuncore/src/session_keys.rs:513` (`prepare_rotation_responder`). Confirm it is a PURE derivation that RETURNS a `ResponderPending` and stores NO pending state of its own inside the inner `SessionKeyManager` — so clearing the PyO3 wrapper's `pending_responder_rotation` is sufficient and re-calling the inner method twice cannot error on inner state. If the inner method DOES keep its own pending state, STOP and report — the design assumption is wrong.

- [ ] **Step 2: Write the failing Rust unit test.** Find the `#[cfg(test)] mod tests` block in `rust/tuncore/src/lib.rs` (search `mod tests`). Add a test that calls `prepare_rotation_responder` twice in a row and asserts BOTH succeed (the second currently returns `Err("responder rotation already prepared")`):

```rust
    #[test]
    fn prepare_rotation_responder_overwrites_stale_pending() {
        // Build a responder PySessionKeyManager. Mirror however the existing
        // lib.rs tests construct one (search the test module for an existing
        // PySessionKeyManager / from_bootstrap_shared_secret setup and reuse
        // it). If none exists, add a `#[cfg(test)] pub(crate) fn for_test`
        // constructor on the impl rather than fighting field privacy.
        let mut mgr = make_test_responder_manager(); // implementer: real ctor

        let next_epoch = mgr.inner.epoch() + 1;
        let eph = [9u8; 32]; // not low-order: DH stays contributory

        // First prepare sets pending_responder_rotation.
        mgr.prepare_rotation_responder(&eph, next_epoch).unwrap();
        // A stale pending now sits here (simulating the ACK-send-timeout
        // path that never applied). The SECOND prepare must OVERWRITE it and
        // succeed — before the fix it returns Err("...already prepared").
        mgr.prepare_rotation_responder(&eph, next_epoch).unwrap();
        // apply must still consume exactly one pending and succeed.
        mgr.apply_rotation_responder().unwrap();
    }
```

> NOTE: use the SAME construction the existing tests use for `PySessionKeyManager` / its inner manager. Keep `[9u8; 32]` (not a low-order point) so the DH is contributory.

- [ ] **Step 3: Run the Rust test to verify it fails.** Run: `cargo test --release --manifest-path rust/tuncore/Cargo.toml prepare_rotation_responder_overwrites_stale_pending`
Expected: FAIL — the second `prepare_rotation_responder` returns `Err("responder rotation already prepared")`, so `.unwrap()` panics.

- [ ] **Step 4: Apply the behavior change.** In `rust/tuncore/src/lib.rs`, replace the early-error guard at the top of `prepare_rotation_responder` (lines 568–570):

```rust
        if self.pending_responder_rotation.is_some() {
            return Err(py_err("responder rotation already prepared"));
        }
```

with a take-and-drop of any stale pending:

```rust
        // Phase 1.2: a prior responder rotation whose REKEY_ACK send timed
        // out (dsm/rekey.py ACK-send-timeout path) leaves its pending here
        // with no apply. That is the ONLY way a pending lingers — a
        // successful rotation applies-and-clears within the same
        // handle_rekey_init call, and apply_rotation_responder().take()s the
        // pending even on its own error path. So any pending we find here is
        // always stale: drop it (zeroizing its LockedKey32 send/recv keys via
        // ResponderPending's Drop) and prepare fresh, rather than erroring
        // and wedging the responder forever.
        let _ = self.pending_responder_rotation.take();
```

(Leave lines 571–578 — the `pub_key_from_slice`, the inner `prepare_rotation_responder` call, and the `self.pending_responder_rotation = Some(pending)` store — unchanged.)

- [ ] **Step 5: Run the Rust test to verify it passes; clippy + fmt.** Run:
```bash
cargo test --release --manifest-path rust/tuncore/Cargo.toml prepare_rotation_responder_overwrites_stale_pending
cargo clippy --release --manifest-path rust/tuncore/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path rust/tuncore/Cargo.toml -- --check
```
Expected: test PASSES; clippy + fmt clean.

- [ ] **Step 6: Rebuild the wheel + reinstall.** Run:
```bash
maturin build --release -m rust/tuncore/Cargo.toml && \
pip3 install --user --force-reinstall --break-system-packages \
  rust/tuncore/target/wheels/dsm_tuncore-0.1.0-cp313-cp313-manylinux_2_34_x86_64.whl
python3 -c "import tuncore; print('ok')"
```
Expected: prints `ok`.

### Part B — Python end-to-end regression (no Python code change needed)

The fix is entirely in Rust; `handle_rekey_init` needs no functional change. This test proves the wedge is gone end-to-end. Add only a clarifying comment at the timeout path (Step 9).

**Files:**
- Modify: `dsm/rekey.py` (comment only, at the `except TimeoutError` block ~301–304)
- Test: `tests/test_rekey_responder_abort.py` (Create)

- [ ] **Step 7: Write the failing Python regression test.** Verify every symbol against `dsm/rekey.py` (`handle_rekey_init` signature at line 138) and `tuncore.pyi` (`BootstrapEphemeral.generate`, `complete_bootstrap`, `SessionKeyManager.epoch`, `prepare_rotation_responder`) before relying on it; adapt names to the real API if any differ.

```python
"""Phase 1.2 regression: an ACK-send timeout leaves a stale responder
pending in Rust, but the NEXT REKEY_INIT must still rotate (the wedge is
gone because prepare_rotation_responder now overwrites a stale pending)."""

from __future__ import annotations

import asyncio
import struct
import unittest

try:
    import tuncore

    _HAS_TUNCORE = True
except ImportError:
    tuncore = None  # type: ignore[assignment]
    _HAS_TUNCORE = False

from dsm.core.fsm import SessionFSM, State
from dsm.rekey import handle_rekey_init
from dsm.traffic.shaper import TrafficShaper


def _responder() -> "tuncore.SessionKeyManager":
    ours = tuncore.BootstrapEphemeral.generate()
    peer = tuncore.BootstrapEphemeral.generate()
    return tuncore.complete_bootstrap(ours, peer.public_key_bytes, False)


@unittest.skipUnless(_HAS_TUNCORE, "tuncore extension not built")
class ResponderWedgeRecovery(unittest.IsolatedAsyncioTestCase):
    async def test_ack_send_timeout_does_not_wedge_next_rekey(self) -> None:
        session_keys = _responder()
        fsm = SessionFSM()
        fsm.transition(State.CONNECTING)
        fsm.transition(State.HANDSHAKING)
        fsm.transition(State.ESTABLISHED)
        shaper = TrafficShaper(128, 1400)

        async def hanging_send(_data: bytes, _size: int) -> None:
            await asyncio.sleep(3600)  # forces the ACK-send TimeoutError path

        new_epoch = session_keys.epoch + 1
        eph = tuncore.BootstrapEphemeral.generate()
        payload = struct.pack("!I", new_epoch) + eph.public_key_bytes

        # Shrink the internal 5s wait_for bound so the timeout fires fast.
        import dsm.rekey as rekey_mod

        orig_wait_for = rekey_mod.asyncio.wait_for

        async def fast_wait_for(coro, timeout):  # type: ignore[no-untyped-def]
            return await orig_wait_for(coro, 0.05)

        rekey_mod.asyncio.wait_for = fast_wait_for  # type: ignore[assignment]
        try:
            # First INIT: ACK send hangs -> times out -> stale pending left.
            await handle_rekey_init(
                payload,
                session_keys,
                fsm,
                shaper,
                hanging_send,
                last_rekey_time=None,
            )
        finally:
            rekey_mod.asyncio.wait_for = orig_wait_for  # type: ignore[assignment]

        # The wedge check: a SECOND prepare must now OVERWRITE the stale
        # pending and succeed. Before the Rust fix this raises
        # "responder rotation already prepared".
        next_epoch = session_keys.epoch + 1
        eph2 = tuncore.BootstrapEphemeral.generate()
        session_keys.prepare_rotation_responder(eph2.public_key_bytes, next_epoch)
        # And apply must still consume exactly that one pending.
        session_keys.apply_rotation_responder()


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 8: Run the test.** Run: `python3 -m pytest tests/test_rekey_responder_abort.py -q`
With Part A already landed and the wheel rebuilt, this should PASS. To confirm it is non-vacuous, the implementer may temporarily revert the lib.rs change, rebuild, and observe the FAIL (`responder rotation already prepared`), then re-apply — OPTIONAL; do not leave the revert in place.

- [ ] **Step 9: Add a clarifying comment at the timeout path (no functional change).** In `dsm/rekey.py`, in the `except TimeoutError` block after the ACK send (~301–304), add a comment above the `return` documenting the self-heal:

```python
    except TimeoutError:
        log.warning("REKEY_ACK send timed out — peer may be wedged")
        # Phase 1.2: this leaves pending_responder_rotation set in Rust with
        # no apply. That is tolerated: the next REKEY_INIT's
        # prepare_rotation_responder overwrites the stale pending (dropping
        # and zeroizing its keys), so the responder self-heals on the next
        # rekey instead of wedging permanently.
        fsm.transition(State.ESTABLISHED)
        return last_rekey_time, cached_ack_epoch, cached_ack_payload
```

- [ ] **Step 10: Run the focused gate.** Run:
```bash
cargo test --release --manifest-path rust/tuncore/Cargo.toml prepare_rotation_responder_overwrites_stale_pending
python3 -m pytest tests/test_rekey_responder_abort.py tests/test_rekey_mutual_init.py tests/test_data_path_integration.py -q
```
Expected: all PASS.

- [ ] **Step 11: Report** — one line: changed `prepare_rotation_responder` to overwrite a stale pending instead of erroring (no new API); responder self-heals on the next REKEY_INIT after an ACK-send timeout; verified the inner method is stateless and the only lingering pending is the failed-ACK case.

---

## Task 1.3: Server-mode `configure()` — skip the client full-tunnel policy route

**Problem (tunnel.py:224–266):** `configure()` always adds `default dev TUN table 100` and the `ip rule not fwmark 0x1 table 100` rule. `server.py:353` calls the same `configure()`. Forwarded client packets (unmarked, dst=internet) match `not fwmark 0x1 → table 100 → dev mtun0`, routing back into the TUN instead of out the WAN. Server forwarding is broken.

**Fix:** add `server_mode: bool = False` to `configure()`. In server mode, skip the table-100 default route AND the not-fwmark rule (the server's MASQUERADE + main-table routing handles egress). `deconfigure()` already deletes those best-effort (`strict=False`), so leaving them un-added is safe.

**Files:**
- Modify: `dsm/net/tunnel.py:224–268` (signature + the route/rule block)
- Modify: `dsm/server.py:353` (pass `server_mode=True`)
- Test: `tests/test_tunnel_server_mode.py` (Create)

- [ ] **Step 1: Write the failing test**

```python
"""Phase 1.3: server-mode configure() must NOT add the client full-tunnel
policy route (table 100 default) or the not-fwmark ip rule, which would
loop forwarded traffic back into the TUN.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from dsm.net import tunnel
from dsm.net.tunnel import TunDevice


class ServerModeConfigure(unittest.TestCase):
    def _captured_cmds(self, **configure_kwargs: object) -> list[list[str]]:
        seen: list[list[str]] = []

        def fake_run_commands(cmds: list[list[str]], *, strict: bool = True) -> None:
            seen.extend(cmds)

        with (
            patch.object(tunnel, "_run_commands", side_effect=fake_run_commands),
            patch.object(TunDevice, "_capture_ipv6_state", return_value={}),
            patch.object(TunDevice, "_save_ipv6_state"),
            patch.object(tunnel.subprocess, "run"),  # the ip-rule del probe
        ):
            tun = TunDevice(name="mtun0")
            tun.configure(local_ip="10.8.0.1", **configure_kwargs)  # type: ignore[arg-type]
        return seen

    def test_server_mode_omits_table100_default_route(self) -> None:
        cmds = self._captured_cmds(server_mode=True)
        for cmd in cmds:
            self.assertNotIn(
                "100", cmd, f"server mode must not touch table 100: {cmd}"
            )
        # And no `ip rule add ... not fwmark` should have been emitted.
        self.assertFalse(
            any(cmd[:3] == ["ip", "rule", "add"] for cmd in cmds),
            "server mode must not add the not-fwmark ip rule",
        )

    def test_client_mode_still_adds_table100_route(self) -> None:
        cmds = self._captured_cmds(server_mode=False)
        self.assertTrue(
            any(
                cmd[:4] == ["ip", "route", "replace", "default"] and "100" in cmd
                for cmd in cmds
            ),
            "client mode must keep the table-100 default route",
        )
        self.assertTrue(
            any(cmd[:3] == ["ip", "rule", "add"] for cmd in cmds),
            "client mode must add the not-fwmark ip rule",
        )


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_tunnel_server_mode.py -q`
Expected: `test_server_mode_omits_table100_default_route` FAILS (configure() has no `server_mode` kwarg → `TypeError`, then once added but unimplemented the table-100 route is still present).

- [ ] **Step 3: Implement the server_mode flag**

In `dsm/net/tunnel.py`, change the `configure` signature and the route/rule block. New signature:

```python
    def configure(
        self,
        local_ip: str = "10.8.0.2",
        netmask: int = TUN_PREFIX_LEN,
        mtu: int = 1400,
        *,
        server_mode: bool = False,
    ) -> None:
        """Configure IP address, bring up the interface, and set routing.

        ``server_mode``: when True, SKIP the client full-tunnel policy route
        (``default dev TUN table 100``) and the ``not fwmark`` ip rule. On
        the server those would match forwarded client traffic and loop it
        back into the TUN instead of out the WAN (Phase 1.3). The server
        relies on the main routing table + MASQUERADE for egress.
        """
```

Then split the unconditional route block. Replace the `cmds = [...]` list and the rule-add block so the table-100 route + ip rule are client-only:

```python
        cmds = [
            ["ip", "addr", "replace", f"{local_ip}/{netmask}", "dev", self._name],
            ["ip", "link", "set", self._name, "mtu", str(mtu)],
            ["ip", "link", "set", self._name, "up"],
            # Disable IPv6 on non-TUN interfaces to prevent dual-stack leaks.
            ["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"],
            ["sysctl", "-w", f"net.ipv6.conf.{self._name}.disable_ipv6=0"],
        ]
        if not server_mode:
            # Client full-tunnel policy route: send all traffic through TUN
            # except VPN's own marked traffic. The server skips this — see
            # the server_mode docstring (Phase 1.3).
            cmds.insert(
                3,
                ["ip", "route", "replace", "default", "dev", self._name,
                 "table", "100"],
            )
            rule_args = [
                "not", "fwmark", str(FWMARK), "table", "100", "priority", "10",
            ]
            subprocess.run(  # pylint: disable=subprocess-run-check
                ["ip", "rule", "del", *rule_args],
                capture_output=True,
                timeout=5,
            )  # ignore errors — rule may not exist yet
            cmds.append(["ip", "rule", "add", *rule_args])

        _run_commands(cmds)
        self._configured = True
```

(Delete the now-duplicated old `rule_args` / `subprocess.run` / `cmds.append` block that previously ran unconditionally.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_tunnel_server_mode.py -q`
Expected: both tests PASS.

- [ ] **Step 5: Pass `server_mode=True` from the server**

In `dsm/server.py:353`, change:

```python
        tun.configure(local_ip=SERVER_TUN_IP, mtu=config.mtu)
```
to:
```python
        tun.configure(local_ip=SERVER_TUN_IP, mtu=config.mtu, server_mode=True)
```

- [ ] **Step 6: Run the focused gate**

Run: `python3 -m pytest tests/test_tunnel_server_mode.py tests/test_tunnel_ipv6.py -q`
Expected: PASS (the existing `test_tunnel_ipv6.py` patches `_run_commands` / `_restore_ipv6_state`, so it is unaffected by the route split — do NOT edit it).

- [ ] **Step 7: Report** — one line: `configure(server_mode=True)` skips the table-100 route + not-fwmark rule; server now egresses via main table + MASQUERADE.

---

## Task 1.4: IPv6 restore on partial-configure failure + global `disable_ipv6` capture/restore

**Problem (tunnel.py:224–266, 290–318):** (a) `configure()` saves IPv6 state then runs `disable_ipv6=1` mid-sequence; if a later command fails it raises with `_configured` still False, and `deconfigure()` guards restore behind `if self._configured`, so IPv6 stays disabled and the next run captures the disabled baseline. (b) `_capture_ipv6_state` only iterates `/sys/class/net` (real interfaces), so `net.ipv6.conf.all.disable_ipv6` and `.default.disable_ipv6` are set but never captured or restored.

**Fix:** (a) set a separate `self._ipv6_mutated` flag immediately after `_save_ipv6_state(...)` and gate `_restore_ipv6_state()` on `(self._configured or self._ipv6_mutated)`. (b) capture `all` and `default` alongside per-iface and write them into the same state file so the existing validated-restore path handles them.

**Files:**
- Modify: `dsm/net/tunnel.py` — `__init__` (add `_ipv6_mutated`), `_capture_ipv6_state` (add `all`/`default`), `configure` (set flag), `deconfigure` (gate on flag), `_restore_ipv6_state` (accept `all`/`default` keys past the iface-name regex)
- Test: `tests/test_tunnel_ipv6_restore.py` (Create)

> NOTE: the iface-name regex (`_IFACE_NAME_RE`) in `_restore_ipv6_state` will reject keys like `all`/`default`? Verify: `LINUX_IFACE_NAME_RE` matches `[A-Za-z0-9_.-]{1,15}` style — `all` and `default` are alphanumeric and ≤15 chars, so they pass. Confirm by reading `dsm/core/_validators.py:LINUX_IFACE_NAME_RE` before implementing; if it would reject them, special-case `all`/`default` in the restore loop instead of relying on the regex.

- [ ] **Step 1: Write the failing test**

```python
"""Phase 1.4: IPv6 state is restored even when configure() fails partway,
and the global all/default disable_ipv6 sysctls are captured + restored.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dsm.net import tunnel
from dsm.net.tunnel import TunDevice


class _Boom(RuntimeError):
    pass


class Ipv6PartialConfigureRestore(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.state_path = Path(self._tmp.name) / "ipv6_state.json"

    def test_restore_runs_after_partial_configure_failure(self) -> None:
        # _run_commands raises after IPv6 was already disabled mid-sequence.
        with (
            patch.object(TunDevice, "_IPV6_STATE_PATH", self.state_path),
            patch.object(TunDevice, "_capture_ipv6_state", return_value={"eth0": False}),
            patch.object(tunnel, "_run_commands", side_effect=_Boom("cmd failed")),
            patch.object(tunnel.subprocess, "run"),
            patch.object(TunDevice, "_restore_ipv6_state") as restore_mock,
        ):
            tun = TunDevice(name="mtun0")
            with self.assertRaises(_Boom):
                tun.configure(local_ip="10.8.0.2")
            self.assertFalse(tun._configured)  # never fully configured
            # ...but the IPv6 mutation flag IS set, so deconfigure restores.
            tun.deconfigure()
            restore_mock.assert_called_once()

    def test_capture_includes_global_all_and_default(self) -> None:
        # _capture_ipv6_state must include net.ipv6.conf.all/default.
        fake_proc = {
            "all": "0",
            "default": "0",
            "eth0": "0",
        }

        real_read_text = Path.read_text

        def fake_read_text(self_path: Path, *a: object, **k: object) -> str:
            name = self_path.parent.name  # .../conf/<name>/disable_ipv6
            if name in fake_proc:
                return fake_proc[name] + "\n"
            return real_read_text(self_path, *a, **k)  # type: ignore[arg-type]

        with (
            patch.object(Path, "read_text", fake_read_text),
            patch.object(
                Path, "iterdir",
                return_value=[Path("/sys/class/net/eth0")],
            ),
            patch.object(Path, "exists", return_value=True),
        ):
            tun = TunDevice(name="mtun0")
            state = tun._capture_ipv6_state()
        self.assertIn("all", state)
        self.assertIn("default", state)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_tunnel_ipv6_restore.py -q`
Expected: both FAIL — `_ipv6_mutated` doesn't exist (deconfigure won't restore), and `_capture_ipv6_state` doesn't return `all`/`default`.

- [ ] **Step 3: Add the mutation flag in `__init__`**

In `dsm/net/tunnel.py` `TunDevice.__init__`, after `self._configured = False`:

```python
        # Phase 1.4: set True the moment configure() disables IPv6, BEFORE
        # _configured. deconfigure() restores IPv6 whenever this is set, even
        # if a later configure() command failed and _configured stayed False.
        self._ipv6_mutated = False
```

- [ ] **Step 4: Capture the global `all`/`default` sysctls**

In `_capture_ipv6_state`, after the per-iface loop (before `return state`), add:

```python
        # Phase 1.4: configure() also writes net.ipv6.conf.all.disable_ipv6=1
        # but the per-iface loop above never sees `all`/`default`. Capture them
        # explicitly so _restore_ipv6_state can put them back.
        for scope in ("all", "default"):
            sysctl_path = Path(f"/proc/sys/net/ipv6/conf/{scope}/disable_ipv6")
            try:
                state[scope] = sysctl_path.read_text().strip() == "1"  # noqa: E501  # pylint: disable=unspecified-encoding
            except OSError:
                continue
```

- [ ] **Step 5: Set the flag in `configure()`**

In `configure()`, immediately after `self._save_ipv6_state(ipv6_state)` (line ~233):

```python
        # Phase 1.4: from here on IPv6 may be disabled; mark mutated so
        # deconfigure() restores even if a later command fails.
        self._ipv6_mutated = True
```

- [ ] **Step 6: Gate restore on the mutation flag in `deconfigure()`**

In `deconfigure()`, change the restore guard (lines ~315–318):

```python
        # Phase 1.4: restore IPv6 if EITHER configure fully succeeded OR it
        # disabled IPv6 before failing partway. The state file still reflects
        # the pre-disable host state in both cases.
        if self._configured or self._ipv6_mutated:
            self._restore_ipv6_state()
            self._configured = False
            self._ipv6_mutated = False
            netaudit.emit("tun_deconfigure", iface=self._name)
```

> NOTE: confirm `_validators.LINUX_IFACE_NAME_RE` accepts `all`/`default`. If it does (alphanumeric), `_restore_ipv6_state` already builds `net.ipv6.conf.all.disable_ipv6=...` correctly. If it rejects them, add `all`/`default` to an allowlist in the restore loop before the regex check.

- [ ] **Step 7: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_tunnel_ipv6_restore.py -q`
Expected: both PASS.

- [ ] **Step 8: Run the focused gate**

Run: `python3 -m pytest tests/test_tunnel_ipv6_restore.py tests/test_tunnel_ipv6.py tests/test_tunnel_server_mode.py -q`
Expected: PASS. (`test_tunnel_ipv6.py` is pre-existing and unedited; verify its `test_restore_issues_correct_sysctl_commands` still passes — it patches a 2-key state file and asserts exactly those commands, unaffected by the new capture path which only runs inside `_capture_ipv6_state`.)

- [ ] **Step 9: Report** — one line: IPv6 restore now gated on a separate mutation flag (survives partial configure) and captures+restores global `all`/`default` disable_ipv6.

---

## Task 1.5: resolv.conf self-capture guard + persistent backup

**Problem (resolv_conf.py:36–112):** `apply()` captures the current `/etc/resolv.conf` as "the original" with no managed-by-dsm marker check. After SIGKILL/crash (restore never ran), the next start captures dsm's own payload (`nameserver 10.8.0.1`) as the original; clean teardown then "restores" the dead nameserver. No persistent backup exists.

**Fix:** (a) if captured contents start with the managed-by-dsm marker, treat as "no original from this read" and instead load the persisted original from `/var/lib/dsm/resolv.conf.orig`. (b) on first apply of a genuine (non-marker) file, persist that original to the backup via `atomic_write`. (c) on restore, prefer the persistent backup. (d) the systemd-resolved/NetworkManager symlink case stays the existing symlink branch (note it).

**Files:**
- Modify: `dsm/net/resolv_conf.py` — add a marker constant + backup path; rework `apply()` capture; prefer backup in `remove()`
- Test: `tests/test_resolv_conf_crash.py` (Create)

- [ ] **Step 1: Write the failing test**

```python
"""Phase 1.5: a crash (apply twice without restore) must NOT clobber the
real original. The persistent backup preserves it, and a self-captured
managed file is never treated as the original.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dsm.net import resolv_conf
from dsm.net.resolv_conf import ResolvConfManager

NAMESERVER = "10.8.0.1"


class ResolvConfCrashSafety(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        self.resolv = self.root / "resolv.conf"
        self.backup = self.root / "var" / "resolv.conf.orig"
        self._p1 = patch.object(resolv_conf, "RESOLV_CONF", self.resolv)
        self._p2 = patch.object(resolv_conf, "RESOLV_BACKUP", self.backup)
        self._p1.start()
        self._p2.start()
        self.addCleanup(self._p1.stop)
        self.addCleanup(self._p2.stop)

    def test_crash_then_restart_preserves_real_original(self) -> None:
        original = b"nameserver 1.1.1.1\noptions timeout:1\n"
        self.resolv.write_bytes(original)

        # First apply: captures the real original + writes the backup.
        ResolvConfManager(NAMESERVER).apply()
        self.assertIn(b"nameserver 10.8.0.1", self.resolv.read_bytes())
        self.assertTrue(self.backup.exists())
        self.assertEqual(self.backup.read_bytes(), original)

        # CRASH: no remove() ran. Simulate restart -> a NEW manager applies
        # again over the dsm-managed file.
        mgr2 = ResolvConfManager(NAMESERVER)
        mgr2.apply()  # current file IS dsm-managed -> must NOT capture it

        # Clean teardown now must restore the REAL original, not dsm's payload.
        mgr2.remove()
        self.assertEqual(self.resolv.read_bytes(), original)

    def test_first_apply_of_managed_file_uses_backup_if_present(self) -> None:
        # No live original, but a backup exists from a prior run.
        original = b"nameserver 9.9.9.9\n"
        self.backup.parent.mkdir(parents=True, exist_ok=True)
        self.backup.write_bytes(original)
        self.resolv.write_bytes(
            b"# Managed by dsm while the VPN is up\nnameserver 10.8.0.1\n"
        )
        mgr = ResolvConfManager(NAMESERVER)
        mgr.apply()
        mgr.remove()
        self.assertEqual(self.resolv.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_resolv_conf_crash.py -q`
Expected: FAIL — `RESOLV_BACKUP` doesn't exist, and the manager re-captures the managed file as "original".

- [ ] **Step 3: Add marker + backup constants and helpers**

In `dsm/net/resolv_conf.py`, after `RESOLV_CONF = Path("/etc/resolv.conf")`:

```python
# Persistent backup of the operator's REAL resolv.conf, written on the first
# apply over a non-dsm file. Survives a crash so a restart that finds the
# dsm-managed file (restore never ran) can still recover the true original.
RESOLV_BACKUP = Path("/var/lib/dsm/resolv.conf.orig")

# Marker that identifies a file WE wrote. If apply() reads this back as the
# "current" file (after a crash), it must NOT treat that as the original.
_DSM_MARKER = b"# Managed by dsm"
```

- [ ] **Step 4: Rework `apply()`'s capture path**

In `apply()`, replace the `elif RESOLV_CONF.exists():` regular-file capture branch (lines ~91–97) with marker-aware capture + backup. The new branch:

```python
        elif RESOLV_CONF.exists():
            try:
                current = RESOLV_CONF.read_bytes()
            except OSError:
                current = b""
            if current.startswith(_DSM_MARKER):
                # Phase 1.5: this is OUR file (a prior run crashed before
                # restore). Do NOT capture it as the original — recover the
                # real original from the persistent backup instead.
                self._original_contents = self._load_backup()
            else:
                self._original_contents = current
                # First apply over a genuine file: persist it so a later
                # crash can still recover it.
                self._save_backup(current)
```

Add two helpers to the class:

```python
    @staticmethod
    def _load_backup() -> bytes | None:
        try:
            if RESOLV_BACKUP.exists():
                return RESOLV_BACKUP.read_bytes()
        except OSError as e:
            log.warning("could not read resolv.conf backup: %s", e)
        return None

    @staticmethod
    def _save_backup(contents: bytes) -> None:
        # Only write the backup once — never overwrite a good backup with a
        # later (possibly dsm-managed) capture.
        if RESOLV_BACKUP.exists():
            return
        try:
            atomic_write(RESOLV_BACKUP, contents, mode=0o600, mkdir=True)
        except OSError as e:
            log.warning("could not persist resolv.conf backup: %s", e)
```

- [ ] **Step 5: Prefer the backup in `remove()`**

In `remove()`, before the `elif self._original_contents is not None:` branch, fall back to the persistent backup if in-memory state is empty (covers the crash-restart manager that captured a marker file and found a backup). The cleanest change: at the top of the `try:` block in `remove()`, if `self._original_symlink_target is None and self._original_contents is None`, attempt to load the backup:

```python
        try:
            if (
                self._original_symlink_target is None
                and self._original_contents is None
            ):
                # Phase 1.5: nothing captured in-memory — prefer the persistent
                # backup (a crash-restart manager that found a dsm-managed file).
                self._original_contents = self._load_backup()
            if self._original_symlink_target is not None:
                ...  # (existing symlink restore unchanged)
```

After a successful restore from contents, remove the backup so a subsequent genuine apply re-captures fresh state. In the `finally:` of `remove()`, after clearing the in-memory fields:

```python
            # Phase 1.5: the backup has served its purpose; drop it so the
            # next apply over a genuine file captures a fresh original.
            try:
                RESOLV_BACKUP.unlink(missing_ok=True)
            except OSError:
                pass
```

> M-NET-1 note: the systemd-resolved / NetworkManager symlink case is still handled by the existing `if RESOLV_CONF.is_symlink():` branch (it captures `os.readlink`). The backup path only applies to the regular-file case. The existing one-shot warning at apply() about those services is unchanged.

- [ ] **Step 6: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_resolv_conf_crash.py -q`
Expected: both PASS.

- [ ] **Step 7: Run the focused gate**

Run: `python3 -m pytest tests/test_resolv_conf_crash.py tests/test_resolv_conf.py -q`
Expected: PASS. (`test_resolv_conf.py` is pre-existing and unedited — it patches only `RESOLV_CONF`, not `RESOLV_BACKUP`; the backup writes to the real `/var/lib/dsm` path in those tests but `_save_backup` swallows OSError and `mkdir=True` makes it best-effort, so those tests still pass. VERIFY this during execution; if `_save_backup` writing the real path is undesirable in those unedited tests, gate the backup write behind `RESOLV_BACKUP` being patchable — it already is a module global, but `test_resolv_conf.py` doesn't patch it, so the write would hit the real FS. If that causes a failure or permission noise, that is a FLAG to the owner to patch `RESOLV_BACKUP` in the pre-existing file — do NOT edit it without approval; instead make `_save_backup` no-op when its parent is unwritable, which it already does via the OSError swallow.)

- [ ] **Step 8: Report** — one line: resolv.conf apply skips self-captured managed files and persists/restores the real original via `/var/lib/dsm/resolv.conf.orig`, crash-safe.

---

## Task 1.6: TCP framing desync — separate idle-tick loop (never cancel a partial framed read)

> **DESIGN FORK A (owner-decided 2026-06-11): SEPARATE IDLE-TICK LOOP.** Stop wrapping the TCP framed read in a 0.1 s `wait_for`; drive idle `tick()` from a dedicated timer task. `TCPTransport.recv()` is left AS-IS — no partial-frame buffering is added (it is unnecessary: `StreamReader.readexactly` already buffers internally, and once we never cancel the read mid-frame, no desync is possible).

**Problem (session.py:681–688, tcp.py:119–159):** `recv_loop` wraps `transport.recv()` (which does `readexactly(prefix)` then `readexactly(length)`) in `asyncio.wait_for(..., 0.1)`. If the 0.1 s timeout fires after the 4-byte prefix is consumed but before the payload arrives (a >100 ms inter-segment gap — exactly the degraded path TCP fallback targets), the in-progress `_read()` coroutine is cancelled mid-frame, the length is lost, and the next read treats payload bytes as a new prefix → permanent desync → session-killing `ValueError`.

**Fix (one approach — do NOT also buffer in TCPTransport):** for the TCP branch of `recv_loop`, call `transport.recv()` WITHOUT the external 0.1 s `wait_for`, so a partial framed read is never cancelled. Move the periodic `session_keys.tick()` idle work into a dedicated `_tcp_idle_tick_loop` task that wakes every 0.1 s and calls `tick()` independent of the framed read, wired into `run_data_loops` alongside the existing loops (and torn down with them). The UDP branch keeps its `wait_for` (UDP `recv()` is a single queue get — cancelling it loses no framing state). `TCPTransport` is unchanged.

**Files:**
- Modify: `dsm/session.py:666–692` (recv_loop TCP branch) + add a TCP idle-tick loop wired into `run_data_loops`
- Test: `tests/test_tcp_framing.py` (Create)

> NOTE: `TCPTransport.recv()` already has the `timeout` parameter but `recv_loop` doesn't use it (it wraps the call externally). The fix keeps `recv()` as-is and removes the EXTERNAL `wait_for` for the TCP branch; the UDP branch keeps its `wait_for` (UDP `recv()` is a single queue get — cancelling it loses nothing, no framing state).

- [ ] **Step 1: Write the failing test**

```python
"""Phase 1.6: a TCP frame split across reads with a >100ms inter-segment gap
must NOT desync the length prefix. Drives the real TCPTransport over a
loopback socket pair.
"""

from __future__ import annotations

import asyncio
import struct
import unittest
from unittest.mock import patch

from dsm.net.transport.tcp import TCPTransport


class TcpFramingSplitRead(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._p = patch("dsm.net.transport.tcp.apply_so_mark", lambda sock: None)
        self._p.start()
        self.addCleanup(self._p.stop)

    async def test_frame_split_with_gap_does_not_desync(self) -> None:
        # Wire two TCPTransports back-to-back over loopback.
        server = TCPTransport()

        async def run_server() -> int:
            return await server.listen("127.0.0.1", 0)

        listen_task = asyncio.ensure_future(run_server())
        await asyncio.sleep(0.05)
        # Pull the port the server bound.
        port = server._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]

        client = TCPTransport()
        await client.connect("127.0.0.1", port)
        await listen_task
        self.addCleanup(client.close)
        self.addCleanup(server.close)

        payload = b"DSM-FRAME-PAYLOAD-32-bytes-long!"
        frame = struct.pack("!I", len(payload)) + payload

        # Send the prefix, wait >100ms, then send the payload — simulating the
        # degraded-path inter-segment gap that the old wait_for(0.1) cancelled
        # mid-frame.
        writer = client._writer
        assert writer is not None
        writer.write(frame[:4])
        await writer.drain()

        async def delayed_tail() -> None:
            await asyncio.sleep(0.2)  # > 100ms gap
            writer.write(frame[4:])
            await writer.drain()

        tail_task = asyncio.ensure_future(delayed_tail())
        # recv() must return the full payload despite the gap.
        got = await asyncio.wait_for(server.recv(), timeout=2.0)
        await tail_task
        self.assertEqual(got, payload)

        # And a SECOND frame must still frame correctly (no desync).
        payload2 = b"second-frame-ok"
        frame2 = struct.pack("!I", len(payload2)) + payload2
        writer.write(frame2)
        await writer.drain()
        got2 = await asyncio.wait_for(server.recv(), timeout=2.0)
        self.assertEqual(got2, payload2)


if __name__ == "__main__":
    unittest.main()
```

> NOTE: this test passes against the CURRENT `TCPTransport.recv()` in isolation (because `recv()` itself doesn't time out). The desync bug lives in `recv_loop`'s EXTERNAL `wait_for(0.1)`. So the regression must be tested at the recv_loop level. Add a second test that exercises the recv_loop TCP branch path. To keep the test deterministic without a full handshake, add a focused unit test asserting that `run_data_loops`'s TCP recv branch does NOT wrap `transport.recv()` in a 0.1 s `wait_for`. Implement that via a recording fake:

Add to the same file:

```python
class RecvLoopDoesNotCancelTcpRead(unittest.IsolatedAsyncioTestCase):
    async def test_tcp_branch_calls_recv_without_short_timeout(self) -> None:
        # A fake TCP transport whose recv() takes 0.25s the first call (a
        # frame straddling a gap). If recv_loop wrapped it in wait_for(0.1),
        # it would raise TimeoutError and desync. After the fix it must wait.
        from dsm.net.transport.tcp import TCPTransport

        class _SlowTcp(TCPTransport):
            def __init__(self) -> None:
                super().__init__()
                self.calls = 0

            async def recv(self, timeout: float | None = None) -> bytes:  # type: ignore[override]
                self.calls += 1
                if self.calls == 1:
                    await asyncio.sleep(0.25)  # straddles the old 0.1 bound
                    raise ConnectionError("eof")  # end the loop cleanly
                raise ConnectionError("eof")

        slow = _SlowTcp()
        # Drive only the recv_loop branch shape via a minimal harness: import
        # the helper and confirm it completes without a TimeoutError-driven
        # desync. We assert recv was awaited to completion (calls==1, no
        # premature cancel).
        # (Full run_data_loops wiring is exercised by test_data_path_integration;
        # here we assert the no-short-timeout contract directly.)
        self.assertTrue(True)  # placeholder; replaced by source-contract check below
```

> The implementer should keep the loopback `test_frame_split_with_gap_does_not_desync` as the primary regression and additionally add a **source-contract assertion** (grep-style) confirming the TCP branch in `run_data_loops` does not wrap `transport.recv()` in `wait_for` — see Step 3. The placeholder above should be replaced by that contract test.

- [ ] **Step 2: Run the test to verify it fails (after Step 3's contract test is written)**

Run: `python3 -m pytest tests/test_tcp_framing.py -q`
Expected: the loopback test passes already (recv() is correct in isolation); the source-contract test FAILS against the current code (recv_loop wraps TCP recv in `wait_for(0.1)`).

- [ ] **Step 3: Implement — split the TCP recv from its idle tick**

In `dsm/session.py`'s `run_data_loops`, the `recv_loop` currently is (lines ~666–692). Change the TCP branch to NOT wrap `recv()` in `wait_for`, and move the idle `tick()` to a separate loop. New `recv_loop`:

```python
    async def recv_loop() -> None:
        while not ctx.shutdown.is_set():
            recv_addr: tuple[str, int] | None = None
            try:
                if isinstance(transport, UDPTransport):
                    data, recv_addr = await asyncio.wait_for(
                        transport.recv(),
                        timeout=0.1,
                    )
                    if udp_addr_filter is not None and not udp_addr_filter(recv_addr):
                        log.debug(
                            "packet from unexpected source %s, dropping", recv_addr
                        )
                        continue
                else:
                    # Phase 1.6: do NOT wrap the framed TCP read in a short
                    # cancellable timeout. Cancelling mid-frame (after the
                    # 4-byte length prefix but before the payload) loses the
                    # length and desyncs the stream on the next read. The
                    # framed read blocks until a full frame arrives or the
                    # peer closes; idle ticks come from _tcp_idle_tick_loop.
                    # The shutdown race is handled by transport.aclose() in
                    # the caller's AsyncExitStack, which raises ConnectionError
                    # out of the pending readexactly.
                    data = await transport.recv()
            except TimeoutError:
                session_keys.tick()
                continue
            except ConnectionError as e:
                log.info("transport closed by peer: %s", e)
                ctx.shutdown.set()
                return

            result = decrypt_packet(data, session_keys, replay)
            if result is None:
                continue

            ctx.liveness.last_recv_time = time.monotonic()
            if post_authenticate is not None and recv_addr is not None:
                post_authenticate(recv_addr)
            inner, _prev_epoch = result
            await dispatch_inner(ctx, inner)

    async def _tcp_idle_tick_loop() -> None:
        # Phase 1.6: drive session_keys.tick() (grace-period cleanup) on a
        # fixed cadence independent of the blocking framed recv. UDP gets its
        # tick from the recv_loop's 0.1s timeout; TCP's recv blocks, so it
        # needs its own ticker. Exits promptly on shutdown.
        if isinstance(transport, UDPTransport):
            return
        while not ctx.shutdown.is_set():
            try:
                await asyncio.wait_for(ctx.shutdown.wait(), timeout=0.1)
                return
            except TimeoutError:
                session_keys.tick()
```

Then add `_tcp_idle_tick_loop` to the supervised gather. Find the `asyncio.gather(...)` call (lines ~732–737) and add the ticker:

```python
        await asyncio.gather(
            _supervised(recv_loop(), "recv"),
            _supervised(tun_send_loop(ctx), "tun_send"),
            _supervised(liveness_loop(ctx), "liveness"),
            _supervised(_tcp_idle_tick_loop(), "tcp_tick"),
            *(_supervised(c, f"extra[{i}]") for i, c in enumerate(extra_loops)),
        )
```

Now write the real source-contract test (replace the placeholder in Step 1's `RecvLoopDoesNotCancelTcpRead`):

```python
class RecvLoopSourceContract(unittest.TestCase):
    def test_tcp_recv_not_wrapped_in_short_wait_for(self) -> None:
        import inspect

        from dsm import session

        src = inspect.getsource(session.run_data_loops)
        # The TCP branch must read via a bare `await transport.recv()` — not
        # wrapped in wait_for. Assert the marker comment + bare call exist.
        self.assertIn("await transport.recv()", src)
        self.assertIn("_tcp_idle_tick_loop", src)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_tcp_framing.py -q`
Expected: all PASS.

- [ ] **Step 5: Run the focused gate**

Run: `python3 -m pytest tests/test_tcp_framing.py tests/test_data_path_integration.py -q`
Expected: PASS (UDP data-path round-trip unaffected; the new `_tcp_idle_tick_loop` returns immediately under UDP).

- [ ] **Step 6: Report** — one line: TCP recv no longer cancelled mid-frame by a 0.1 s timeout; idle `tick()` moved to a dedicated `_tcp_idle_tick_loop`; segmented paths no longer desync.

---

## Task 1.7: PMTU vs shaper size class — clamp the ceiling when auto_mtu lowers the path

**Problem (session.py:786–811, shaper.py:168–233):** `auto_mtu_loop` lowers only the inner TUN MTU. The shaper still pads outer packets to the static 1400 size class (`padding_max`), so on a sub-1428-PMTU path with DF set, 1400-class packets (wire ~1428) are dropped with EMSGSIZE, only logged in `error_received`, never resized.

**Fix:** give `TrafficShaper` a `set_size_class_ceiling(max_outer)` method that filters `_active_classes` to classes ≤ ceiling and rebuilds the `SizeTracker`. Call it from `auto_mtu_loop` whenever it lowers the path: the outer-packet ceiling is `path_mtu - IP(20) - UDP(8) = path_mtu - 28` (the outer wire budget). Use the existing `WIRE_OVERHEAD`-adjacent math: a size class is the OUTER DSM packet size, and the on-wire datagram is `size_class + 28`. So the ceiling on size class is `path_mtu - 28`.

**Files:**
- Modify: `dsm/traffic/shaper.py` — add `set_size_class_ceiling`
- Modify: `dsm/session.py:790–812` (auto_mtu_loop lower branch) — call the clamp
- Test: `tests/test_pmtu_shaper.py` (Create)

- [ ] **Step 1: Write the failing test**

```python
"""Phase 1.7: when auto_mtu lowers the path, the shaper's size-class ceiling
must drop so outer packets fit the constrained PMTU (no 1400-class on a
sub-1428 DF path).
"""

from __future__ import annotations

import unittest

from dsm.core.protocol import InnerPacket, PacketType, SIZE_CLASSES
from dsm.traffic.shaper import TrafficShaper

# On-wire datagram overhead beyond the DSM outer packet (IP 20 + UDP 8).
_LINK_OVERHEAD = 28


class ShaperCeilingClamp(unittest.TestCase):
    def test_clamp_caps_size_classes_to_fit_path(self) -> None:
        shaper = TrafficShaper(128, 1400)
        # Path MTU 1300 -> outer ceiling = 1300 - 28 = 1272.
        shaper.set_size_class_ceiling(1300 - _LINK_OVERHEAD)
        # Sample many padded packets; every outer target must be <= 1272.
        for _ in range(200):
            inner = InnerPacket(ptype=PacketType.DATA, epoch_id=0, payload=b"x" * 64)
            _padded, target = shaper.pad_packet(inner)
            self.assertLessEqual(
                target + _LINK_OVERHEAD, 1300,
                f"outer {target} + link {_LINK_OVERHEAD} exceeds path 1300",
            )

    def test_clamp_is_idempotent_and_raise_restores(self) -> None:
        shaper = TrafficShaper(128, 1400)
        shaper.set_size_class_ceiling(1272)
        capped = max(shaper._active_classes)
        self.assertLessEqual(capped, 1272)
        # Raising the ceiling back to the original padding_max restores the
        # full class set (bounded by padding_max=1400).
        shaper.set_size_class_ceiling(1400)
        self.assertEqual(max(shaper._active_classes), max(SIZE_CLASSES))

    def test_clamp_below_smallest_class_keeps_one_class(self) -> None:
        shaper = TrafficShaper(128, 1400)
        # Absurdly small ceiling: must still leave at least one usable class.
        shaper.set_size_class_ceiling(50)
        self.assertGreaterEqual(len(shaper._active_classes), 1)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_pmtu_shaper.py -q`
Expected: FAIL — `set_size_class_ceiling` does not exist (`AttributeError`).

- [ ] **Step 3: Implement `set_size_class_ceiling`**

In `dsm/traffic/shaper.py`, add to `TrafficShaper` (after `__init__`):

```python
    def set_size_class_ceiling(self, max_outer: int) -> None:
        """Phase 1.7: cap the size classes the shaper pads to at ``max_outer``
        (the DSM outer-packet size budget = path_mtu - IP - UDP).

        Filters the active classes to those <= max_outer and rebuilds the
        size tracker so subsequent pad_packet / chaff sizes fit a constrained
        path. Always keeps at least one class (the smallest), so an absurdly
        low ceiling degrades gracefully rather than emptying the set. The
        ceiling is bounded above by the configured ``padding_max`` (raising it
        cannot exceed the operator's padding policy).
        """
        ceiling = min(max_outer, self._padding_max)
        kept = tuple(
            sc for sc in SIZE_CLASSES if self._padding_min <= sc <= ceiling
        )
        if not kept:
            # Below the smallest configured class — keep the single smallest
            # class that satisfies padding_min so padding still works.
            kept = (min(sc for sc in SIZE_CLASSES if sc >= self._padding_min),)
        self._active_classes = kept
        self._size_tracker = SizeTracker(self._active_classes)
```

(`SIZE_CLASSES` and `SizeTracker` are already imported/defined in the module.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_pmtu_shaper.py -q`
Expected: all PASS.

- [ ] **Step 5: Call the clamp from `auto_mtu_loop`**

In `dsm/session.py`, in `auto_mtu_loop`'s lower branch (after `ctx.tun.set_mtu(usable)` succeeds, lines ~792–811), add a shaper clamp. The outer ceiling = `path_mtu - 28` (IP+UDP). Insert right after the successful `set_mtu` and before `current = usable`:

```python
            # Phase 1.7: also clamp the shaper's size-class ceiling so padded
            # / chaff outer packets fit the constrained path. The outer DSM
            # packet rides inside IP(20)+UDP(8), so the size-class ceiling is
            # path_mtu - 28.
            ctx.shaper.set_size_class_ceiling(path_mtu - 28)
```

And in the RAISE branch (after a successful `set_mtu(usable)` on the hysteresis path, ~line 817), restore the ceiling toward the full budget:

```python
                ctx.shaper.set_size_class_ceiling(path_mtu - 28)
```

- [ ] **Step 6: Run the focused gate**

Run: `python3 -m pytest tests/test_pmtu_shaper.py tests/test_auto_mtu.py tests/test_shaper.py -q`
Expected: PASS. (`test_auto_mtu.py` and `test_shaper.py` are pre-existing and unedited — the new method is additive and the auto_mtu loop change only ADDS a call; verify they still pass.)

- [ ] **Step 7: Report** — one line: `TrafficShaper.set_size_class_ceiling()` added and called from `auto_mtu_loop` so padded/chaff outer packets fit a lowered PMTU.

---

## Task 1.8: Daemon lifecycle — exit codes, signal-handler ordering, server re-accept

> **DESIGN FORK B (confirm):** server re-accept = wrap the post-handshake session block in an outer `while not shutdown` loop (single active session preserved).

This task has three independent sub-parts plus the deferred Phase-0 ConfigError wrapping. Implement them in order; each has its own test in `tests/test_lifecycle.py`.

### Part A — `run_client`/`run_server` return int; `main()` exits it

**Problem (`__main__.py:136–155`, every `return` in `run_client`/`run_server`):** the coroutines return `None` on every error path and after teardown; `main()` runs them via `asyncio.run(...)` and exits 0 always. With `Restart=on-failure`, outages look like clean exits.

**Fix:** make `run_client`/`run_server` return `int` (0 success/clean shutdown, nonzero on every error path). In `main()`, `sys.exit(asyncio.run(run_*(...)))`.

**Files:**
- Modify: `dsm/client.py` — change return type to `int`, return `1` on each error `return`, `0` at the end
- Modify: `dsm/server.py` — same
- Modify: `dsm/__main__.py:136–152` — `sys.exit(asyncio.run(...))`
- Test: `tests/test_lifecycle.py` (Create)

- [ ] **Step 1: Write the failing test**

```python
"""Phase 1.8: lifecycle correctness — nonzero exit on error paths, signal
handlers installed before the pre-handshake kill switch, server re-accept.
"""

from __future__ import annotations

import asyncio
import unittest
from dataclasses import replace
from unittest.mock import patch

from dsm.core.config import Config


def _client_config() -> Config:
    return Config(
        mode="client",
        server_ip="10.0.0.1",
        server_port=51820,
        listen_port=0,
        key_file="/tmp/dsm-test.key",
        cert_file="/tmp/dsm-test.crt",
        ca_root_file="/tmp/dsm-test-ca.pem",
        attest_key_file="/tmp/dsm-test-attest.key",
        expected_server_cn="dsm-test-server",
        transport="udp",
    )


class ClientExitCode(unittest.IsolatedAsyncioTestCase):
    async def test_run_client_returns_nonzero_on_attest_policy_failure(self) -> None:
        from dsm.client import run_client

        cfg = _client_config()
        with (
            patch("tuncore.harden_process"),
            patch("dsm.core.hardening.set_process_nondumpable"),
            patch(
                "dsm.crypto.attest_gate.enforce_attest_backend_policy",
                side_effect=__import__(
                    "dsm.crypto.attest_gate", fromlist=["SoftAttestNotAllowedError"]
                ).SoftAttestNotAllowedError("nope"),
            ),
        ):
            rc = await run_client(cfg)
        self.assertNotEqual(rc, 0)
        self.assertIsInstance(rc, int)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_lifecycle.py::ClientExitCode -q`
Expected: FAIL — `run_client` returns `None`, so `rc != 0` fails (`None != 0` is True but `assertIsInstance(None, int)` fails).

- [ ] **Step 3: Make `run_client` return int**

In `dsm/client.py`, change the signature:

```python
async def run_client(
    config: Config,
    passphrase_fd: int | None = None,
    passphrase_env_file: str | None = None,
) -> int:
```

Change EVERY early `return` in the function to `return 1` (the attest-policy failure ~line 111, cert-materials failure ~121, store-unlock failure ~138, cert/identity mismatch ~150, handshake failure ~248). At the very end of the function (after `await run_data_loops(...)`, ~line 411–413), add:

```python
        # Clean shutdown (signal / SESSION_CLOSE / dead-peer): exit 0.
        return 0
```

> NOTE: `load_daemon_stores(...)` returning False currently does `return` (line 138) — change to `return 1`.

- [ ] **Step 4: Make `run_server` return int**

In `dsm/server.py`, change the signature to `-> int`. Change every early `return` to `return 1` (attest policy ~109, cert materials ~119, allowed_cns missing ~126, CN allowlist load fail ~131, empty allowlist ~137, store unlock ~151, cert/identity mismatch ~163). The shutdown-during-handshake `return` (~325) is a CLEAN shutdown → `return 0`. The end of the function (after `run_data_loops`, ~485) → `return 0`. (Part C below changes the end into a loop; for now return 0 at the bottom.)

- [ ] **Step 5: `sys.exit` the return value in `main()`**

In `dsm/__main__.py`, wrap the `asyncio.run(...)` calls:

```python
    if config.mode == "client":
        from dsm.client import run_client

        sys.exit(
            asyncio.run(
                run_client(
                    config,
                    passphrase_fd=args.passphrase_fd,
                    passphrase_env_file=args.passphrase_env_file,
                )
            )
        )
    elif config.mode == "server":
        from dsm.server import run_server

        sys.exit(
            asyncio.run(
                run_server(
                    config,
                    passphrase_fd=args.passphrase_fd,
                    passphrase_env_file=args.passphrase_env_file,
                )
            )
        )
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_lifecycle.py::ClientExitCode -q`
Expected: PASS.

### Part B — Client installs signal handlers before the pre-handshake kill switch

**Problem (client.py:167–169 vs 352–353):** `pre_killswitch.apply()` runs at line 168 but `setup_signal_handlers(shutdown)` only runs at 353 (after the tunnel is up). A SIGTERM during connect kills the process with the kill switch still applied and the AsyncExitStack never unwound.

**Fix:** create `shutdown = asyncio.Event()` and call `setup_signal_handlers(shutdown)` at the TOP of the `async with AsyncExitStack()` block, BEFORE `pre_killswitch.apply()` — mirroring `server.py:196–197`. Reuse that same `shutdown` event later instead of creating a second one at line 352.

**Files:**
- Modify: `dsm/client.py:154–169` (move handler setup up) and `:352` (drop the second `asyncio.Event()`/`setup_signal_handlers`)
- Test: `tests/test_lifecycle.py::ClientSignalOrdering`

- [ ] **Step 7: Write the failing test**

```python
class ClientSignalOrdering(unittest.TestCase):
    def test_signal_handlers_set_up_before_pre_killswitch(self) -> None:
        import inspect

        from dsm import client

        src = inspect.getsource(client.run_client)
        idx_handlers = src.find("setup_signal_handlers(shutdown)")
        idx_killswitch = src.find("pre_killswitch.apply()")
        self.assertNotEqual(idx_handlers, -1)
        self.assertNotEqual(idx_killswitch, -1)
        self.assertLess(
            idx_handlers,
            idx_killswitch,
            "signal handlers must be installed before the pre-handshake "
            "kill switch (Phase 1.8 H10)",
        )
```

- [ ] **Step 8: Run it to verify it fails**

Run: `python3 -m pytest tests/test_lifecycle.py::ClientSignalOrdering -q`
Expected: FAIL — handler setup is after the kill switch in source order.

- [ ] **Step 9: Move handler setup to the top of the stack**

In `dsm/client.py`, right after `async with AsyncExitStack() as stack:` and the keystore/attest callbacks (after line 159), add:

```python
        # Phase 1.8 (H10): create the shutdown event and install signal
        # handlers BEFORE the pre-handshake kill switch, mirroring server.py.
        # A SIGTERM during connect must trigger the AsyncExitStack unwind
        # (removing the kill switch) rather than killing the process with the
        # kill switch still applied and the host offline.
        shutdown = asyncio.Event()
        setup_signal_handlers(shutdown)
```

Then DELETE the later duplicate at lines ~352–353:

```python
        shutdown = asyncio.Event()
        setup_signal_handlers(shutdown)
```

(The `shutdown` variable is now created once at the top and reused; `make_send_fn(..., shutdown=shutdown)` and `DataPathContext(shutdown=shutdown)` still reference it.)

- [ ] **Step 10: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_lifecycle.py::ClientSignalOrdering -q`
Expected: PASS.

### Part C — Server sequential re-accept loop

**Problem (server.py:348–486):** after a successful session ends (dead-peer timeout, transport close, SESSION_CLOSE), `run_data_loops` returns and `run_server` falls off the end → exit. One client blip permanently downs the service.

**Fix:** wrap the post-handshake session block (TUN configure → data loops) in an outer `while not shutdown.is_set()` loop. After `run_data_loops` returns, tear down the per-session host state (TUN, forwarding, MASQUERADE, DNS proxy, scheduler) and, if not shutting down, loop back to the accept phase. Single active session is preserved.

> NOTE: the post-handshake block currently registers per-session resources on the OUTER `AsyncExitStack`, which only unwinds at process exit. To re-accept, those resources must be torn down per session. The cleanest minimal change is to wrap the post-handshake block in its OWN nested `AsyncExitStack` inside the re-accept loop, so each session's TUN/forwarding/DNS get torn down when that session ends — while the process-lifetime resources (keystore, rate limiter, tcp_ts, transport-for-UDP) stay on the outer stack.

**Files:**
- Modify: `dsm/server.py` — restructure the handshake + session region into a re-accept loop
- Test: `tests/test_lifecycle.py::ServerReAccept`

- [ ] **Step 11: Write the failing test**

```python
class ServerReAccept(unittest.TestCase):
    def test_run_server_has_outer_reaccept_loop(self) -> None:
        import inspect

        from dsm import server

        src = inspect.getsource(server.run_server)
        # The post-handshake session must live inside a re-accept loop that
        # tears down per-session state and returns to accept on session end.
        self.assertIn("re-accept", src.lower())
        # The per-session resources must be in a nested AsyncExitStack so they
        # unwind per session, not only at process exit.
        self.assertGreaterEqual(
            src.count("AsyncExitStack"), 2,
            "expected a nested per-session AsyncExitStack for re-accept",
        )
```

- [ ] **Step 12: Run it to verify it fails**

Run: `python3 -m pytest tests/test_lifecycle.py::ServerReAccept -q`
Expected: FAIL — only one `AsyncExitStack`, no re-accept loop.

- [ ] **Step 13: Implement the re-accept loop**

In `dsm/server.py`, restructure so the region from "Successful TCP transport" / `fsm.transition(State.ESTABLISHED)` through `run_data_loops(...)` runs inside an outer loop. Wrap the whole handshake-accept + session in:

```python
        # Phase 1.8 (H11): sequential re-accept loop. After a session ends
        # (dead-peer timeout, transport close, SESSION_CLOSE), tear down the
        # per-session host state and return to the handshake-accept phase
        # rather than exiting. Single active session at a time is preserved
        # (owner decision). Process-lifetime resources (keystore, rate
        # limiter, tcp_ts, the UDP transport) stay on the OUTER stack; each
        # session's TUN / forwarding / MASQUERADE / DNS proxy / scheduler go
        # on a nested per-session stack that unwinds when the session ends.
        while not shutdown.is_set():
            # ... (the existing handshake accept loop: lines ~216-325, which
            # sets session_keys / client_pub / transport_obj or returns 0 on
            # shutdown) ...

            # If shutdown happened during handshake, exit cleanly.
            if shutdown.is_set() or session_keys is None or client_pub is None:
                break

            async with AsyncExitStack() as session_stack:
                # ... (the per-session block: TUN configure(server_mode=True),
                # IPForwardingManager, MasqueradeManager, DNS proxy, shaper,
                # scheduler, DataPathContext, run_data_loops) — registering
                # cleanups on session_stack instead of the outer `stack` ...
                await run_data_loops(
                    ctx,
                    transport,
                    session_keys,
                    replay,
                    fsm,
                    post_authenticate=_record_client_addr,
                    shutdown_log="server shutting down",
                )
            # session_stack unwound here: TUN/forwarding/DNS/scheduler torn
            # down. Reset per-session FSM + state for the next accept.
            if shutdown.is_set():
                break
            log.info("session ended — returning to accept")
            fsm.transition(State.CONNECTING)
            session_keys = None
            client_pub = None
            # For UDP the transport is reused; for TCP the accept loop above
            # re-creates it on the next iteration.

        return 0
```

> IMPLEMENTER NOTES (critical for a correct restructure):
> - The handshake accept loop (current lines ~220–325) and the per-session block (current ~327–485) must BOTH move inside the new `while not shutdown.is_set():`. The accept loop's own inner `while not shutdown.is_set():` (line 220) stays — it retries FAILED handshakes; the new OUTER loop re-accepts after SUCCESSFUL sessions end.
> - Move these registrations from `stack` to `session_stack`: `tun.close`, `ip_forward.remove`, `masquerade.remove`, `dns_proxy.stop`, `resolver.close`, `server_scheduler.stop`. Keep on the OUTER `stack`: `keystore.unload`, `attest_store.unload`, `rate_limiter.remove`, `tcp_ts.remove`, and (UDP) `transport_obj.aclose`.
> - For TCP, the per-session transport is registered on `session_stack` (so it closes when the session ends) and a fresh one is accepted next iteration. For UDP, the single bound transport stays on the outer stack and is reused.
> - `seq`, `rekey`, `liveness`, `reassembly`, `client_addr`, `shaper` must be RE-CREATED inside each session iteration (a fresh `SequenceCounter`/`ReplayWindow`/`RekeyState` per session — reusing a stale sequence counter across sessions would be a nonce-reuse hazard).
> - `replay = tuncore.ReplayWindow()` and `shaper = TrafficShaper(...)` move inside the session iteration.
> - This is the largest single edit in Phase 1. Do it carefully; the diff reviewer should confirm resource ownership (outer vs session stack) explicitly.

- [ ] **Step 14: Run the re-accept test + the full lifecycle file**

Run: `python3 -m pytest tests/test_lifecycle.py -q`
Expected: all PASS.

### Part D — Wrap `load()` calls in `__main__` (deferred Phase-0 item)

**Problem (`__main__.py:123, 173, 260`):** `load(args.config)` is unwrapped in `main()`, `_run_enroll`, and `_run_show_pubkey`. `ConfigError` (and TOMLDecodeError / TypeError unknown-key) surface as raw tracebacks.

**Fix:** wrap each `load()` call in a small helper `_load_config_or_exit(path)` that catches `ConfigError`, `tomllib.TOMLDecodeError`, `ValueError`, `TypeError`, prints `config: <msg>` to stderr, and `sys.exit(2)`.

**Files:**
- Modify: `dsm/__main__.py` — add `_load_config_or_exit`, use it at all three call sites
- Test: `tests/test_lifecycle.py::ConfigLoadErrors`

- [ ] **Step 15: Write the failing test**

```python
class ConfigLoadErrors(unittest.TestCase):
    def test_missing_config_exits_2_with_clean_message(self) -> None:
        import io
        from contextlib import redirect_stderr

        from dsm.__main__ import _load_config_or_exit

        buf = io.StringIO()
        from pathlib import Path

        with redirect_stderr(buf):
            with self.assertRaises(SystemExit) as cm:
                _load_config_or_exit(Path("/nonexistent/dsm-config.toml"))
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("config:", buf.getvalue())
        self.assertNotIn("Traceback", buf.getvalue())
```

- [ ] **Step 16: Run it to verify it fails**

Run: `python3 -m pytest tests/test_lifecycle.py::ConfigLoadErrors -q`
Expected: FAIL — `_load_config_or_exit` does not exist.

- [ ] **Step 17: Add the helper and use it**

In `dsm/__main__.py`, add near the top (after imports):

```python
import tomllib

from dsm.core.config import ConfigError, load


def _load_config_or_exit(config_path: Path | None) -> "Config":
    """Load config, turning every load-time failure into a clean stderr
    message + exit(2) instead of a raw traceback (Phase 1.8 / Phase-0 tail).
    """
    try:
        return load(config_path)
    except ConfigError as e:
        print(f"config: {e}", file=sys.stderr)
        sys.exit(2)
    except tomllib.TOMLDecodeError as e:
        print(f"config: malformed TOML: {e}", file=sys.stderr)
        sys.exit(2)
    except TypeError as e:
        # Unknown / missing key surfaces as "unexpected keyword argument".
        print(f"config: invalid or unknown key: {e}", file=sys.stderr)
        sys.exit(2)
    except ValueError as e:
        print(f"config: {e}", file=sys.stderr)
        sys.exit(2)
```

> NOTE: `from dsm.core.config import Config` is needed for the return annotation — add it (the existing import is `from dsm.core.config import load`; widen to `from dsm.core.config import Config, ConfigError, load` and drop the duplicate `load` import line). Use a string annotation `"Config"` only if avoiding the top-level import; prefer importing `Config` directly.

Replace `config = load(args.config)` in `main()` (line 123) with `config = _load_config_or_exit(args.config)`. Replace `config = load(config_path)` in `_run_enroll` (line 173) and `_run_show_pubkey` (line 260) with `config = _load_config_or_exit(config_path)`.

- [ ] **Step 18: Run the test + focused gate**

Run: `python3 -m pytest tests/test_lifecycle.py tests/test_cli.py -q`
Expected: all PASS (`test_cli.py` is pre-existing and unedited — verify the helper change doesn't break its config-load expectations; it calls `config.load` directly, not `_load_config_or_exit`, so it's unaffected).

- [ ] **Step 19: Report** — one line: `run_client`/`run_server` return int exit codes (`sys.exit`-ed in main), client installs signal handlers before the pre-killswitch, server re-accepts after session end, and `__main__` config-load errors exit(2) cleanly.

---

## Task 1.9: systemd unit — `ExecStopPost` cleanup, `StartLimit*` to `[Unit]`, `CAP_IPC_LOCK` doc

**Problem (`deploy/dsm.service`):** no `ExecStopPost` cleanup (SIGKILL/OOM leaves nft tables, table-100 route, ip rule, resolv.conf, and sysctls unrestored); `StartLimitIntervalSec`/`StartLimitBurst` are in `[Service]` where systemd ignores `StartLimitIntervalSec`. `CAP_IPC_LOCK` is documented but not cross-referenced as panic-critical (already in the bounding set; just document).

**Fix:** add a `dsm cleanup` subcommand backed by a new `dsm/net/cleanup.py` (idempotent host-state cleanup), wire it as `ExecStopPost=/usr/bin/python3 -m dsm cleanup`, and move `StartLimit*` to `[Unit]`. (`LimitCORE`/`CoredumpFilter` are already present from Phase 0 — do NOT duplicate.)

### Part A — `dsm/net/cleanup.py` + `dsm cleanup` subcommand

**Files:**
- Create: `dsm/net/cleanup.py`
- Modify: `dsm/__main__.py` — add the `cleanup` subcommand + dispatch
- Test: `tests/test_cleanup.py` (Create)

- [ ] **Step 1: Write the failing test**

```python
"""Phase 1.9: `dsm cleanup` removes all dsm host state idempotently. Only the
subprocess boundary is mocked.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch, call

from dsm.net import cleanup


class CleanupHostState(unittest.TestCase):
    def test_cleanup_deletes_all_dsm_nft_tables(self) -> None:
        runs: list[list[str]] = []

        def fake_run(cmd, *a, **k):  # type: ignore[no-untyped-def]
            runs.append(list(cmd))
            class _R:
                returncode = 0
            return _R()

        with patch.object(cleanup.subprocess, "run", side_effect=fake_run):
            cleanup.cleanup_host_state()

        flat = [" ".join(c) for c in runs]
        for table in (
            "dsm_killswitch_pre",
            "dsm_killswitch",
            "dsm_dns_leak",
            "dsm_server_ratelimit",
            "dsm_server_nat",
        ):
            self.assertTrue(
                any(f"delete table inet {table}" in f for f in flat),
                f"cleanup must delete table {table}",
            )
        # Flushes table 100 + deletes the priority-10 ip rule.
        self.assertTrue(any("flush table 100" in f for f in flat))
        self.assertTrue(
            any("rule del" in f and "priority" in f and "10" in c for f, c in zip(flat, runs))
        )

    def test_cleanup_is_idempotent_swallows_missing(self) -> None:
        # Every subprocess call fails (nothing exists) — cleanup must not raise.
        def boom(cmd, *a, **k):  # type: ignore[no-untyped-def]
            import subprocess
            raise subprocess.CalledProcessError(1, cmd)

        with patch.object(cleanup.subprocess, "run", side_effect=boom):
            cleanup.cleanup_host_state()  # must not raise


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m pytest tests/test_cleanup.py -q`
Expected: FAIL — `dsm.net.cleanup` does not exist.

- [ ] **Step 3: Implement `dsm/net/cleanup.py`**

```python
"""Idempotent host-state cleanup for crash / forced-stop recovery.

Run by systemd `ExecStopPost=` on BOTH clean and crash stops so a SIGKILL /
OOM that bypasses the in-process AsyncExitStack unwind does not leave the
host with a kill switch up, a dead resolv.conf, a stale table-100 route /
ip rule, or modified sysctls. Every operation is best-effort: a missing
table / rule / file is fine — the goal is to converge on a clean state.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from dsm.net._addresses import SERVER_TUN_IP  # noqa: F401  (kept for symmetry)
from dsm.net.resolv_conf import RESOLV_BACKUP, RESOLV_CONF
from dsm.net.transport._fwmark import SO_MARK_VALUE as FWMARK

log = logging.getLogger(__name__)

_DSM_TABLES = (
    "dsm_killswitch_pre",
    "dsm_killswitch",
    "dsm_dns_leak",
    "dsm_server_ratelimit",
    "dsm_server_nat",
)


def _best_effort(cmd: list[str]) -> None:
    try:
        subprocess.run(cmd, capture_output=True, timeout=5, check=False)
    except (FileNotFoundError, subprocess.SubprocessError) as e:
        log.debug("cleanup cmd %s: %s", " ".join(cmd), type(e).__name__)


def cleanup_host_state() -> None:
    """Remove every host mutation dsm could have made. Idempotent."""
    # 1. nftables tables.
    for table in _DSM_TABLES:
        _best_effort(["nft", "delete", "table", "inet", table])
    # 2. Flush the policy-route table and delete the not-fwmark ip rule.
    _best_effort(["ip", "route", "flush", "table", "100"])
    _best_effort(
        [
            "ip", "rule", "del", "not", "fwmark", str(FWMARK),
            "table", "100", "priority", "10",
        ]
    )
    # 3. Restore resolv.conf from the persistent backup if present.
    _restore_resolv_conf()
    # 4. Restore the global IPv6 + forwarding sysctls to safe defaults.
    for key, value in (
        ("net.ipv6.conf.all.disable_ipv6", "0"),
        ("net.ipv6.conf.default.disable_ipv6", "0"),
        ("net.ipv4.ip_forward", "0"),
    ):
        _best_effort(["sysctl", "-w", f"{key}={value}"])
    log.info("dsm host-state cleanup complete")


def _restore_resolv_conf() -> None:
    try:
        if RESOLV_BACKUP.exists():
            data = RESOLV_BACKUP.read_bytes()
            from dsm.core.atomic_io import atomic_write

            atomic_write(RESOLV_CONF, data, mode=0o644, mkdir=False)
            RESOLV_BACKUP.unlink(missing_ok=True)
            log.info("restored resolv.conf from backup")
        else:
            # No backup: if the live file is dsm-managed, remove it so the
            # host falls back to DHCP / NM regeneration.
            if RESOLV_CONF.exists():
                head = RESOLV_CONF.read_bytes()[:16]
                if head.startswith(b"# Managed by dsm"):
                    RESOLV_CONF.unlink(missing_ok=True)
    except OSError as e:
        log.warning("resolv.conf cleanup failed: %s", e)
```

> NOTE: this imports `RESOLV_BACKUP` from `dsm/net/resolv_conf.py` (added in Task 1.5). Implement Task 1.5 before 1.9, or add `RESOLV_BACKUP` in 1.5 first. The sysctl restore-to-`0` is a SAFE-default heuristic for the crash path (the captured-state JSON in `/run/dsm` is the precise restore; cleanup is the coarse fallback when that path was bypassed). The precise per-iface restore is still done by the in-process teardown when it runs.

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_cleanup.py -q`
Expected: both PASS.

- [ ] **Step 5: Wire the `cleanup` subcommand**

In `dsm/__main__.py`, add a subparser (after the `show-pubkey` subparser):

```python
    subparsers.add_parser(
        "cleanup",
        help="Remove all dsm host state (nft tables, table-100 route, ip "
        "rule, resolv.conf, sysctls). Idempotent; for ExecStopPost / crash "
        "recovery.",
    )
```

And dispatch it in `main()` (before the `config = _load_config_or_exit(...)` line, since cleanup needs no config):

```python
    if args.command == "cleanup":
        from dsm.net.cleanup import cleanup_host_state

        dsm_log.configure("info")
        cleanup_host_state()
        return
```

- [ ] **Step 6: Run a CLI smoke check**

Run: `python3 -m dsm cleanup` (in a non-root env the nft/ip/sysctl calls fail best-effort; the command must exit 0 with an "cleanup complete" log line and no traceback).
Expected: exit 0, no traceback.

### Part B — Edit the unit file

**Files:**
- Modify: `deploy/dsm.service`
- Test: `tests/test_cleanup.py::UnitFile` (optional `systemd-analyze verify`)

- [ ] **Step 7: Add `ExecStopPost`, move `StartLimit*`, document `CAP_IPC_LOCK`**

In `deploy/dsm.service`:

1. Add to `[Service]` (after the `ExecStart=` block, near `KillSignal=`):

```ini
# Phase 1.9: crash-safe cleanup. ExecStopPost runs on BOTH clean and crash
# stops (SIGKILL/OOM that bypass the in-process AsyncExitStack unwind), so
# the host never stays with the kill switch up, a dead resolv.conf, a stale
# table-100 route / ip rule, or modified sysctls. Idempotent — safe to run
# when there is nothing to clean.
ExecStopPost=/usr/bin/python3 -m dsm cleanup
```

2. Move the StartLimit stanza from `[Service]` to `[Unit]`. Delete these two lines from `[Service]`:

```ini
StartLimitIntervalSec=10min
StartLimitBurst=5
```

and add them to the `[Unit]` section (after `Wants=network-online.target`):

```ini
# Phase 1.9: StartLimitIntervalSec is only honored in [Unit] (systemd
# ignores it in [Service], silently removing the crash-loop guard).
StartLimitIntervalSec=10min
StartLimitBurst=5
```

3. In the `CapabilityBoundingSet` comment block, no value change needed (CAP_IPC_LOCK is already in the set); confirm the comment already names it panic-critical (it does, lines 107–111). No edit required there beyond verifying.

- [ ] **Step 8: (Optional) Validate the unit if systemd-analyze is available**

```python
import shutil
import subprocess
import unittest


class UnitFile(unittest.TestCase):
    @unittest.skipUnless(shutil.which("systemd-analyze"), "systemd-analyze absent")
    def test_unit_verifies(self) -> None:
        from pathlib import Path

        unit = Path(__file__).resolve().parent.parent / "deploy" / "dsm.service"
        # `verify` warns on unknown keys; StartLimitIntervalSec in [Service]
        # would warn — after the move it must not.
        proc = subprocess.run(
            ["systemd-analyze", "verify", str(unit)],
            capture_output=True, text=True,
        )
        self.assertNotIn("StartLimitIntervalSec", proc.stderr)
```

Run: `python3 -m pytest tests/test_cleanup.py -q`
Expected: PASS (the unit-verify test is skipped if `systemd-analyze` is unavailable — note this is optional).

- [ ] **Step 9: Run the focused gate**

Run: `python3 -m pytest tests/test_cleanup.py -q`
Expected: PASS.

- [ ] **Step 10: Report** — one line: added `dsm cleanup` + `dsm/net/cleanup.py`, wired `ExecStopPost`, moved `StartLimit*` to `[Unit]`; crash/forced-stop now converges to a clean host.

---

## Task 1.10: DNS robustness — IP-literal providers, NXDOMAIN vs failure, cache-heap bound, TTL clamp

Three independent fixes in `dsm/net/dns.py` (+ one relay change in `dns_proxy.py`). Each has its own test in `tests/test_dns_robustness.py`.

### Part A — IP-literal-only DoH/DoT providers

**Problem (dns.py:507–512, config.py:196–235):** `_open_pinned_tls_connection` calls `loop.getaddrinfo(host)` per query. A hostname-form provider dead-loops through the TUN (the server's own resolution is routed into mtun0).

**Fix:** in `Config._validate_dns`, require each provider's `urlparse(provider).hostname` to parse as an `ipaddress.ip_address` (mirroring `_validate_server_ip`). Raise `ValueError` on a hostname-form provider.

**Files:**
- Modify: `dsm/core/config.py` `_validate_dns` (after the scheme warning)
- Test: `tests/test_dns_robustness.py::IpLiteralProviders`

- [ ] **Step 1: Write the failing test**

```python
"""Phase 1.10: DNS robustness — IP-literal providers, NXDOMAIN distinction,
bounded cache heap, TTL clamp.
"""

from __future__ import annotations

import unittest
from typing import Any

from dsm.core.config import Config


def _server_base(**overrides: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "mode": "server",
        "server_ip": "10.0.0.1",
        "server_port": 51820,
        "listen_port": 51820,
        "key_file": "/tmp/k.key",
        "cert_file": "/tmp/c.crt",
        "ca_root_file": "/tmp/ca.pem",
        "attest_key_file": "/tmp/a.key",
        "expected_server_cn": None,
        "allowed_cns_file": "/tmp/cns.txt",
        "transport": "udp",
    }
    d.update(overrides)
    return d


class IpLiteralProviders(unittest.TestCase):
    def test_hostname_form_provider_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Config(
                **_server_base(
                    dns_providers=["https://dns.example.com/dns-query"],
                    dns_provider_pins={
                        "https://dns.example.com/dns-query": ["a" * 64]
                    },
                )
            )

    def test_ip_literal_provider_accepted(self) -> None:
        c = Config(
            **_server_base(
                dns_providers=["https://1.1.1.1/dns-query"],
                dns_provider_pins={"https://1.1.1.1/dns-query": ["a" * 64]},
            )
        )
        self.assertEqual(c.mode, "server")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m pytest tests/test_dns_robustness.py::IpLiteralProviders -q`
Expected: `test_hostname_form_provider_rejected` FAILS — a hostname provider currently passes config validation.

- [ ] **Step 3: Require IP-literal providers in `_validate_dns`**

In `dsm/core/config.py` `_validate_dns`, inside the `for provider in c.dns_providers:` loop, after the scheme warning block and before the pins check, add:

```python
        # Phase 1.10: provider host MUST be an IP literal. A hostname-form
        # provider triggers per-query getaddrinfo, whose unmarked UDP is
        # routed into the server's own TUN (tunnel.py ip rule), dead-looping
        # resolution. Mirror _validate_server_ip's IP-literal requirement.
        parsed_host = urlparse(provider).hostname
        if parsed_host is not None:
            try:
                ipaddress.ip_address(parsed_host)
            except ValueError as e:
                raise ValueError(
                    f"dns_provider {provider!r} host must be an IP literal, "
                    f"got {parsed_host!r}. Resolve it once offline and pin the "
                    f"IP (a hostname provider dead-loops through the TUN)."
                ) from e
```

Add `from urllib.parse import urlparse` to the imports at the top of `config.py` (it already imports `ipaddress`).

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_dns_robustness.py::IpLiteralProviders -q`
Expected: both PASS.

### Part B — NXDOMAIN/NODATA vs transport failure (typed result + relay)

**Problem (dns.py:438–460, 156–222; dns_proxy.py:335–341):** `_parse_dns_response` returns `[]` for any non-NOERROR rcode AND for empty answers, so `resolve()` cannot distinguish authoritative NXDOMAIN/NODATA from provider failure: every nonexistent name fans out to every provider, logs ERROR, and the proxy returns SERVFAIL. No negative caching.

**Fix:** make `_parse_dns_response` return a typed result `_DnsResult(addresses, ttl, rcode, authoritative)`. `resolve()` returns a typed outcome too: on an authoritative NXDOMAIN/NODATA it STOPS fan-out, negative-caches per RFC 2308, and signals "authoritative empty" distinctly from "all providers failed". The proxy relays NXDOMAIN (or empty-NOERROR for NODATA) instead of SERVFAIL.

> SCOPE NOTE: this is the largest DNS change. To keep it testable and minimal, introduce an `Enum`/dataclass result and thread it through `resolve` → `_resolve_with_dedup` (proxy) → `_handle_query`. The proxy's `addresses`-empty branch currently always SERVFAILs (dns_proxy.py:338–340). Change it to: SERVFAIL only on transport failure; NXDOMAIN on authoritative NXDOMAIN; empty-NOERROR on NODATA.

**Files:**
- Modify: `dsm/net/dns.py` — `_DnsResult` dataclass, `_parse_dns_response`, `resolve` return type, `_cache_result` negative-cache
- Modify: `dsm/net/dns_proxy.py` — relay the rcode
- Test: `tests/test_dns_robustness.py::NxdomainDistinction`

- [ ] **Step 5: Write the failing test**

```python
import dns.message
import dns.rcode

from dsm.net.dns import _parse_dns_response


class NxdomainDistinction(unittest.TestCase):
    def _resp(self, qname: str, rcode: int, answers: bool) -> bytes:
        q = dns.message.make_query(qname, dns.rdatatype.A)  # type: ignore[attr-defined]
        r = dns.message.make_response(q)
        r.set_rcode(rcode)
        if answers:
            import dns.rrset, dns.rdataclass, dns.rdatatype
            rr = dns.rrset.from_text_list(
                q.question[0].name, 60, dns.rdataclass.IN, dns.rdatatype.A,
                ["1.2.3.4"],
            )
            r.answer.append(rr)
        return r.to_wire()

    def test_nxdomain_is_authoritative_empty_not_failure(self) -> None:
        import dns.rdatatype  # noqa: F401

        wire = self._resp("nope.invalid", dns.rcode.NXDOMAIN, answers=False)
        result = _parse_dns_response(wire)
        # New typed result: rcode == NXDOMAIN, authoritative True, no addrs.
        self.assertEqual(result.addresses, [])
        self.assertEqual(result.rcode, int(dns.rcode.NXDOMAIN))
        self.assertTrue(result.authoritative)

    def test_noerror_with_answers_has_addresses(self) -> None:
        import dns.rdatatype  # noqa: F401

        wire = self._resp("ok.example", dns.rcode.NOERROR, answers=True)
        result = _parse_dns_response(wire)
        self.assertEqual(result.addresses, ["1.2.3.4"])
        self.assertEqual(result.rcode, int(dns.rcode.NOERROR))
        self.assertTrue(result.authoritative)
```

- [ ] **Step 6: Run it to verify it fails**

Run: `python3 -m pytest tests/test_dns_robustness.py::NxdomainDistinction -q`
Expected: FAIL — `_parse_dns_response` returns a 2-tuple `(addresses, ttl)`, not a result object with `.rcode`/`.authoritative`.

- [ ] **Step 7: Implement the typed parse result**

In `dsm/net/dns.py`, add near the top (after `_CacheEntry`):

```python
@dataclass(slots=True)
class _DnsResult:
    """Outcome of parsing an upstream DNS response (Phase 1.10).

    ``authoritative`` is True when the response was a well-formed DNS
    message with a definitive rcode (NOERROR / NXDOMAIN), so callers can
    stop provider fan-out and negative-cache instead of treating an empty
    answer as a transport failure.
    """

    addresses: list[str]
    ttl: int
    rcode: int
    authoritative: bool
```

Rewrite `_parse_dns_response`:

```python
def _parse_dns_response(data: bytes) -> _DnsResult:
    """Parse a DNS response into a typed result (addresses + rcode)."""
    try:
        msg = dns.message.from_wire(data)
    except dns.exception.DNSException:
        # Not a parseable DNS message — a transport-level failure, NOT
        # authoritative.
        return _DnsResult(addresses=[], ttl=300, rcode=-1, authoritative=False)

    rcode = msg.rcode()
    if rcode == dns.rcode.NXDOMAIN:
        return _DnsResult(addresses=[], ttl=MIN_TTL, rcode=int(rcode), authoritative=True)
    if rcode != dns.rcode.NOERROR:
        # SERVFAIL / REFUSED etc. — treat as a (non-authoritative) failure so
        # other providers are still tried.
        return _DnsResult(addresses=[], ttl=300, rcode=int(rcode), authoritative=False)

    addresses: list[str] = []
    min_ttl = MAX_TTL  # Phase 1.10: was 300, capping long TTLs at 300.
    for rrset in msg.answer:
        if rrset.rdtype != dns.rdatatype.A:
            continue
        min_ttl = min(min_ttl, rrset.ttl)
        for rdata in cast(Iterable[dns.rdata.Rdata], rrset):
            if isinstance(rdata, dns.rdtypes.IN.A.A):
                addresses.append(rdata.address)
    if not addresses:
        # NOERROR with no A records = NODATA, authoritative.
        return _DnsResult(addresses=[], ttl=MIN_TTL, rcode=int(rcode), authoritative=True)
    return _DnsResult(addresses=addresses, ttl=min_ttl, rcode=int(rcode), authoritative=True)
```

Update `_resolve_doh` / `_resolve_dot` callers (they unpack `addresses, ttl = _parse_dns_response(...)`): change to use the result object. For example in `_resolve_doh`:

```python
        result = _parse_dns_response(body)
        if result.addresses:
            self._cache_result(hostname, result.addresses, result.ttl)
            return result.addresses
        if result.authoritative:
            # NXDOMAIN / NODATA: stop fan-out, negative-cache. Signal the
            # authoritative-empty outcome to resolve() by raising a sentinel.
            raise _AuthoritativeEmpty(result.rcode)
        return []
```

Add a small sentinel exception and have `resolve()` catch it to stop fan-out and return an authoritative-empty marker. The simplest contract that keeps the proxy change minimal: `resolve()` returns `list[str]` as today on success, but also expose the last authoritative rcode via a companion method, OR change `resolve()` to return `_DnsResult`. Given the proxy is the only caller, change `resolve()` to return `_DnsResult` and update the proxy.

> IMPLEMENTER NOTE: pick ONE shape. Recommended: `resolve()` returns `_DnsResult`. Then `_resolve_doh`/`_resolve_dot` return `_DnsResult`, `resolve()` returns the first authoritative result (stopping fan-out) or, after all providers, a non-authoritative failure result. Negative-cache authoritative-empty results in `_cache_result` with an empty address list + the rcode. This is a focused refactor of ~40 lines; keep `_DnsResult` internal (leading underscore) so no public API changes.

- [ ] **Step 8: Relay the rcode in the proxy**

In `dsm/net/dns_proxy.py` `_handle_query` (lines ~335–343), change the empty-addresses branch to relay NXDOMAIN/NODATA. `_resolve_with_dedup` must return the `_DnsResult` (or at least the rcode). Update its signature to return the result object, then:

```python
        result = await self._resolve_with_dedup(qname, qtype)
        try:
            if result.addresses:
                send(self._build_response(query, result.addresses), addr)
            elif result.authoritative and result.rcode == int(dns.rcode.NXDOMAIN):
                send(_make_error(query, dns.rcode.NXDOMAIN), addr)
            elif result.authoritative:
                # NODATA: empty NOERROR.
                resp = dns.message.make_response(query)
                resp.flags |= dns.flags.RA
                send(resp.to_wire(), addr)
            else:
                # Transport failure — SERVFAIL as before.
                send(_make_error(query, dns.rcode.SERVFAIL), addr)
        except Exception as e:  # noqa: BLE001
            log.exception("failed to send DNS response to %s: %s", addr, e)
```

(`_resolve_with_dedup` returns `_DnsResult` now; the inflight future stores `_DnsResult` instead of `list[str]`. Update its type annotations accordingly.)

- [ ] **Step 9: Run the test + proxy tests to verify**

Run: `python3 -m pytest tests/test_dns_robustness.py::NxdomainDistinction tests/test_dns_proxy_coalescing.py -q`
Expected: the parse tests PASS. `test_dns_proxy_coalescing.py` is pre-existing and unedited — if its fixtures assume `resolve()` returns `list[str]`, this change may break it. VERIFY: if it breaks, that is a **FLAG FOR OWNER** (a pre-existing test would need its expectation updated, which is not permitted without approval). To avoid the break, consider keeping `resolve()` returning `list[str]` and adding a SEPARATE `resolve_detailed()` returning `_DnsResult` that the proxy calls — leaving the old `resolve()` shape intact for existing tests. **Decide this in execution; prefer the non-breaking `resolve_detailed()` shape if `test_dns_proxy_coalescing.py` couples to `resolve()`.**

### Part C — Bound `_cache_heap` growth + TTL clamp

**Problem (dns.py:386–406, 449):** heap entries are popped only inside the eviction loop, which runs only at ≥2000 cache entries. A server under 2000 distinct names leaks heap entries forever. Separately, `min_ttl` initialized to 300 makes `MAX_TTL=3600` dead.

**Fix:** opportunistically pop expired heap heads on every `_cache_result`; the TTL clamp is already fixed in Part B (`min_ttl = MAX_TTL`).

**Files:**
- Modify: `dsm/net/dns.py` `_cache_result`
- Test: `tests/test_dns_robustness.py::CacheHeapBound`

- [ ] **Step 10: Write the failing test**

```python
import time

from dsm.net.dns import DNSResolver


class CacheHeapBound(unittest.TestCase):
    def test_heap_does_not_grow_unboundedly_under_2000_names(self) -> None:
        r = DNSResolver(
            providers=["https://1.1.1.1/dns-query"],
            provider_pins={"https://1.1.1.1/dns-query": ["a" * 64]},
            hosts_file="/nonexistent",
        )
        # Re-resolve the SAME small set of names many times with tiny TTL so
        # each re-cache pushes a heap entry. The heap must self-compact.
        for i in range(500):
            r._cache_result(f"h{i % 5}.example", ["1.2.3.4"], ttl=1)
        # Expire them.
        time.sleep(0)  # monotonic-based; rely on the opportunistic pop logic
        # Force expiry by re-caching with already-past expiry via monkeypatch
        # is overkill; assert the heap never exceeds 2x the live cache.
        self.assertLessEqual(len(r._cache_heap), 2 * len(r._cache) + 10)
```

- [ ] **Step 11: Run it to verify it fails**

Run: `python3 -m pytest tests/test_dns_robustness.py::CacheHeapBound -q`
Expected: FAIL — the heap grows to ~500 while the live cache is 5.

- [ ] **Step 12: Opportunistically pop expired heap heads**

In `dsm/net/dns.py` `_cache_result`, at the very top (before the eviction-at-MAX loop):

```python
        # Phase 1.10: opportunistically drop expired heap heads on every cache
        # write so the heap can't grow unboundedly when the live cache stays
        # below MAX_CACHE_ENTRIES (a server resolving <2000 distinct names
        # never entered the eviction loop, leaking a heap entry per
        # re-resolution).
        now = time.monotonic()
        while self._cache_heap and self._cache_heap[0][0] < now:
            exp, key = heapq.heappop(self._cache_heap)
            entry = self._cache.get(key)
            if entry is not None and entry.expires <= now and entry.expires == exp:
                del self._cache[key]
```

- [ ] **Step 13: Run the test + the focused DNS gate**

Run: `python3 -m pytest tests/test_dns_robustness.py tests/test_dns_padding.py tests/test_dns_proxy_coalescing.py -q`
Expected: PASS (modulo the Part B `resolve()` shape decision — if it broke a pre-existing test, switch to `resolve_detailed()`).

- [ ] **Step 14: Report** — one line: DNS now rejects hostname-form providers, distinguishes authoritative NXDOMAIN/NODATA from transport failure (relays NXDOMAIN, negative-caches), bounds `_cache_heap`, and the TTL clamp reaches MAX_TTL.

---

## Task 1.11: Config / CLI UX mediums

Group of small, independently-testable fixes. All new tests in `tests/test_config_ux.py` (plus argparse/atomic checks). Implement in sub-steps.

**Files:**
- Modify: `dsm/core/config.py` (type-check pass; `key_file` absolute; IPv6 `server_ip` reject; MTU comment)
- Modify: `dsm/core/atomic_io.py` (os.write loop)
- Modify: `dsm/traffic/shaper.py` (`padding_min>max-class` clamp)
- Modify: `dsm/__main__.py` (passphrase SUPPRESS defaults; enroll CSR-path precheck)
- Test: `tests/test_config_ux.py` (Create)

### Part A — Type-check pass before range validators

- [ ] **Step 1: Write the failing test**

```python
"""Phase 1.11: config/CLI UX — typed errors, absolute key_file, IPv6 reject,
atomic_write write-loop, padding clamp."""

from __future__ import annotations

import unittest
from typing import Any

from dsm.core.config import Config


def _base(**o: Any) -> dict[str, Any]:
    d: dict[str, Any] = {
        "mode": "client",
        "server_ip": "10.0.0.1",
        "server_port": 51820,
        "listen_port": 51821,
        "key_file": "/tmp/k.key",
        "cert_file": "/tmp/c.crt",
        "ca_root_file": "/tmp/ca.pem",
        "attest_key_file": "/tmp/a.key",
        "expected_server_cn": "dsm-test-server",
        "transport": "udp",
    }
    d.update(o)
    return d


class TypedConfigErrors(unittest.TestCase):
    def test_string_port_raises_valueerror_not_typeerror(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(server_port="51820"))  # type: ignore[arg-type]

    def test_string_mtu_raises_valueerror(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(mtu="1400"))  # type: ignore[arg-type]


class KeyFileAbsolute(unittest.TestCase):
    def test_relative_key_file_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(key_file="relative.key"))


class Ipv6ServerIpRejected(unittest.TestCase):
    def test_ipv6_server_ip_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Config(**_base(server_ip="2001:db8::1"))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m pytest tests/test_config_ux.py -q`
Expected: `test_string_port_raises_valueerror_not_typeerror` FAILS (raises `TypeError`), `test_relative_key_file_rejected` FAILS (relative key_file accepted), `test_ipv6_server_ip_rejected` FAILS (IPv6 accepted).

- [ ] **Step 3: Add a type-check pass + the three rejections**

In `dsm/core/config.py`:

(i) Add a type-validator run FIRST in `_VALIDATORS`:

```python
def _validate_types(c: Config) -> None:
    """Phase 1.11: type-check numeric/bool fields before range validators so a
    wrong-typed TOML value (e.g. server_port = "51820") raises a readable
    ValueError instead of a cryptic TypeError from a `<=` comparison.
    """
    int_fields = (
        ("server_port", c.server_port),
        ("listen_port", c.listen_port),
        ("padding_min", c.padding_min),
        ("padding_max", c.padding_max),
        ("jitter_ms_min", c.jitter_ms_min),
        ("jitter_ms_max", c.jitter_ms_max),
        ("rotation_packets", c.rotation_packets),
        ("rotation_seconds", c.rotation_seconds),
        ("mtu", c.mtu),
    )
    for name, value in int_fields:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(
                f"{name} must be an integer, got {type(value).__name__}"
            )
    if not isinstance(c.pmtu_check_interval_s, (int, float)) or isinstance(
        c.pmtu_check_interval_s, bool
    ):
        raise ValueError(
            "pmtu_check_interval_s must be a number, got "
            f"{type(c.pmtu_check_interval_s).__name__}"
        )
```

Insert `_validate_types` as the FIRST entry in `_VALIDATORS` (before `_validate_mode`).

(ii) `key_file` absolute — extend `_validate_key_file`:

```python
def _validate_key_file(c: Config) -> None:
    if not c.key_file:
        raise ValueError("key_file must not be empty")
    if not Path(c.key_file).is_absolute():
        raise ValueError(f"key_file must be absolute, got {c.key_file!r}")
```

(iii) IPv6 `server_ip` reject — extend `_validate_server_ip` after the `ipaddress.ip_address` check:

```python
    addr = ipaddress.ip_address(c.server_ip)
    if addr.version == 6:
        raise ValueError(
            f"IPv6 server_ip {c.server_ip!r} is not supported (AF_INET-only "
            "transport; configure disables IPv6). Use an IPv4 server endpoint."
        )
```

> NOTE: `_validate_server_ip` currently does `ipaddress.ip_address(c.server_ip)` inside a `try`. Capture the return value and add the version check after the `try/except`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_config_ux.py -q`
Expected: the four type/keyfile/IPv6 tests PASS.

> NOTE for the implementer: `test_config.py` (pre-existing) sets `key_file = "/tmp/test.key"` (absolute) and uses IPv4 server_ip, so the new validators don't break it. VERIFY by running `python3 -m pytest tests/test_config.py -q` after this step — it MUST stay green. If any pre-existing config test used a relative key_file or IPv6 server_ip, that is a FLAG (do not edit the pre-existing test).

### Part B — `atomic_write` os.write return-value loop

- [ ] **Step 5: Write the failing test**

```python
import os
from pathlib import Path
import tempfile
from unittest.mock import patch

from dsm.core import atomic_io


class AtomicWriteFullWrite(unittest.TestCase):
    def test_short_write_is_completed_in_a_loop(self) -> None:
        data = b"x" * 10000
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "out.bin"
            real_write = os.write
            calls = {"n": 0}

            def short_write(fd: int, buf: bytes) -> int:
                # First call writes only half; loop must continue.
                calls["n"] += 1
                if calls["n"] == 1:
                    return real_write(fd, buf[: len(buf) // 2])
                return real_write(fd, buf)

            with patch.object(atomic_io.os, "write", side_effect=short_write):
                atomic_io.atomic_write(target, data, mkdir=False)
            self.assertEqual(target.read_bytes(), data)
```

- [ ] **Step 6: Run it to verify it fails**

Run: `python3 -m pytest tests/test_config_ux.py::AtomicWriteFullWrite -q`
Expected: FAIL — the single `os.write` writes only half and the file is truncated.

- [ ] **Step 7: Loop `os.write`**

In `dsm/core/atomic_io.py`, replace `os.write(fd, data)` with a loop:

```python
        # Phase 1.11: os.write may write fewer bytes than requested (ENOSPC
        # mid-write, >2GiB, interruption). Loop until all bytes are written so
        # the atomically-renamed file is never silently truncated.
        view = memoryview(data)
        written = 0
        while written < len(view):
            written += os.write(fd, view[written:])
```

- [ ] **Step 8: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_config_ux.py::AtomicWriteFullWrite -q`
Expected: PASS.

### Part C — `padding_min > max class` clamp in the shaper

- [ ] **Step 9: Write the failing test**

```python
from dsm.traffic.shaper import TrafficShaper


class PaddingClamp(unittest.TestCase):
    def test_padding_min_above_max_class_does_not_crash(self) -> None:
        # padding_min in (1400, 1500] passes Config range validation but the
        # shaper's class filter is empty -> must clamp, not raise.
        shaper = TrafficShaper(padding_min=1450, padding_max=1500)
        self.assertGreaterEqual(len(shaper._active_classes), 1)
```

- [ ] **Step 10: Run it to verify it fails**

Run: `python3 -m pytest tests/test_config_ux.py::PaddingClamp -q`
Expected: FAIL — the fallback `min(sc for sc in SIZE_CLASSES if sc >= padding_min)` is an empty generator → `ValueError`.

- [ ] **Step 11: Clamp the fallback in `TrafficShaper.__init__`**

In `dsm/traffic/shaper.py` `__init__`, change the fallback block:

```python
        if not self._active_classes:
            # Phase 1.11: padding_min may exceed the largest SIZE_CLASS (1400)
            # while still passing Config's <=1500 range check. Clamp to the
            # largest available class rather than crashing on an empty
            # generator.
            largest = SIZE_CLASSES[-1]
            candidates = [sc for sc in SIZE_CLASSES if sc >= padding_min]
            self._active_classes = (candidates[0],) if candidates else (largest,)
```

- [ ] **Step 12: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_config_ux.py::PaddingClamp -q`
Expected: PASS.

### Part D — argparse passphrase SUPPRESS + enroll CSR-path precheck

**Problem (`__main__.py:24–37, 177–207`):** `--passphrase-fd`/`--passphrase-env-file` are defined on both the parent parser and each subparser with `default=None`; argparse applies the subparser's default over the parent-parsed value, silently dropping `dsm --passphrase-fd 3 enroll ...`. Separately, `enroll --csr-out` persists keys before validating the CSR output path.

- [ ] **Step 13: Write the failing test (passphrase clobber)**

```python
import argparse

from dsm.__main__ import _add_passphrase_args


class PassphraseFlagClobber(unittest.TestCase):
    def test_parent_passphrase_survives_subcommand(self) -> None:
        parser = argparse.ArgumentParser()
        _add_passphrase_args(parser)
        sub = parser.add_subparsers(dest="command")
        enroll = sub.add_parser("enroll")
        enroll.add_argument("--csr-out", default=None)
        _add_passphrase_args(enroll)
        args = parser.parse_args(["--passphrase-fd", "3", "enroll", "--csr-out", "x"])
        self.assertEqual(args.passphrase_fd, 3)
```

- [ ] **Step 14: Run it to verify it fails**

Run: `python3 -m pytest tests/test_config_ux.py::PassphraseFlagClobber -q`
Expected: FAIL — `args.passphrase_fd` is `None` (subparser default clobbers the parent value).

- [ ] **Step 15: Use `SUPPRESS` defaults**

In `dsm/__main__.py` `_add_passphrase_args`, change both `default=None` to `default=argparse.SUPPRESS`:

```python
def _add_passphrase_args(p: argparse.ArgumentParser) -> None:
    """Non-interactive passphrase sources (stronger than DSM_PASSPHRASE env).

    Phase 1.11: default=SUPPRESS so a flag placed BEFORE the subcommand
    (`dsm --passphrase-fd 3 enroll ...`) is not clobbered by the subparser's
    own default — argparse only writes the attr when the flag is present.
    """
    p.add_argument(
        "--passphrase-fd",
        type=int,
        default=argparse.SUPPRESS,
        help="Read passphrase from file descriptor N (e.g. systemd socket pipe)",
    )
    p.add_argument(
        "--passphrase-env-file",
        type=str,
        default=argparse.SUPPRESS,
        help="Read passphrase from file at PATH (must be 0600)",
    )
```

Because `SUPPRESS` means the attribute may be absent, replace `args.passphrase_fd` / `args.passphrase_env_file` reads in `main()` with `getattr(args, "passphrase_fd", None)` / `getattr(args, "passphrase_env_file", None)` at all four use-site pairs (verified at lines 110–111, 118–119, 139–140, 149–150).

- [ ] **Step 16: Run the passphrase test to verify it passes**

Run: `python3 -m pytest tests/test_config_ux.py::PassphraseFlagClobber -q`
Expected: PASS.

- [ ] **Step 17: Write the failing test (enroll CSR-path precheck)**

```python
import io
from contextlib import redirect_stderr
from pathlib import Path

from dsm.__main__ import _run_enroll


class EnrollCsrPathPrecheck(unittest.TestCase):
    def test_unwritable_csr_dir_exits_before_keygen(self) -> None:
        # A CSR path whose parent does not exist must exit 2 with a clean
        # message BEFORE generate_enrollment persists any keys.
        buf = io.StringIO()
        with redirect_stderr(buf):
            with self.assertRaises(SystemExit) as cm:
                _run_enroll(
                    None,
                    csr_out=Path("/nonexistent-dir-xyz/out.csr"),
                    import_cert=None,
                    cn=None,
                    role="client",
                    passphrase_fd=None,
                    passphrase_env_file=None,
                )
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("enroll:", buf.getvalue())
```

> NOTE: `_run_enroll` calls `_load_config_or_exit(None)` which loads `/opt/mtun/config.toml`; in a test env that likely doesn't exist → it would exit(2) on config load before reaching the CSR check, which still satisfies `exit code 2` but for the wrong reason. To test the CSR precheck specifically, the precheck must run BEFORE config load OR the test must patch config load. Implement the CSR-parent-writability check at the TOP of the `if csr_out is not None:` block (after config load) but make the test patch `_load_config_or_exit` to return a dummy Config. Adjust the test to patch it:

```python
        from unittest.mock import patch
        from tests.test_lifecycle import _client_config  # reuse the builder

        with patch("dsm.__main__._load_config_or_exit", return_value=_client_config()):
            with redirect_stderr(buf):
                with self.assertRaises(SystemExit) as cm:
                    _run_enroll(None, csr_out=Path("/nonexistent-dir-xyz/out.csr"),
                                import_cert=None, cn=None, role="client",
                                passphrase_fd=None, passphrase_env_file=None)
```

- [ ] **Step 18: Run it to verify it fails**

Run: `python3 -m pytest tests/test_config_ux.py::EnrollCsrPathPrecheck -q`
Expected: FAIL — no precheck; the code reaches `read_passphrase` (which would prompt/raise) rather than exiting 2 on the CSR path.

- [ ] **Step 19: Add the CSR-path precheck**

In `dsm/__main__.py` `_run_enroll`, at the top of `if csr_out is not None:` (after the `effective_role` validation, before `read_passphrase`):

```python
        # Phase 1.11: validate the CSR output path BEFORE we persist any keys.
        # generate_enrollment writes identity + attest keys to disk; if the CSR
        # write then fails the operator is stranded with keys on disk and no
        # CSR, and re-running errors "identity key already exists".
        csr_parent = csr_out.parent
        if not csr_parent.is_dir():
            print(
                f"enroll: cannot write CSR to {csr_out}: directory "
                f"{csr_parent} does not exist",
                file=sys.stderr,
            )
            sys.exit(2)
        if not os.access(csr_parent, os.W_OK):
            print(
                f"enroll: cannot write CSR to {csr_out}: directory "
                f"{csr_parent} is not writable",
                file=sys.stderr,
            )
            sys.exit(2)
```

Add `import os` to `__main__.py` if not already imported (it is not currently — add it).

- [ ] **Step 20: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_config_ux.py::EnrollCsrPathPrecheck -q`
Expected: PASS.

### Part E — DEFAULT_TUN_MTU comment fix (DESIGN FORK C: keep 1400)

- [ ] **Step 21: Fix the misleading overhead comment (no default change)**

> DESIGN FORK C: keep `DEFAULT_TUN_MTU = 1400`. Do NOT lower to 1360 (that silently changes throughput for existing deployments; auto_mtu's 1.7 clamp handles constrained paths). ONLY correct the comment so it separates link overhead (IP+UDP=28, below the DSM outer) from the 40 bytes that count against the 1400 size class.

In `dsm/core/config.py`, update the MTU-bounds comment (lines ~39–46):

```python
# TUN MTU bounds. 576 is the IPv4 minimum path MTU (RFC 791). 1500 is
# standard Ethernet. Two distinct overheads matter and must not be conflated:
#   * Link overhead = IP(20) + UDP(8) = 28 B, charged against the LINK MTU
#     (it rides OUTSIDE the DSM outer packet / size class).
#   * Size-class overhead = outer header(20) + GCM tag(16) + inner header(4)
#     = 40 B, charged against the 1400-byte top SIZE_CLASS.
# So a full TUN packet of N bytes becomes an N+40 outer packet, which becomes
# an N+40+28 wire datagram. DEFAULT_TUN_MTU 1400 leaves slack for VPN-in-VPN
# / PPPoE paths; auto_mtu lowers it (and the shaper ceiling) on constrained
# links (Phase 1.7).
```

- [ ] **Step 22: Run the full 1.11 focused gate**

Run: `python3 -m pytest tests/test_config_ux.py tests/test_config.py tests/test_cli.py tests/test_shaper.py -q`
Expected: PASS (pre-existing files unedited and still green).

- [ ] **Step 23: Report** — one line: config gains a type-check pass + absolute `key_file` + IPv6-`server_ip` reject; `atomic_write` loops short writes; shaper clamps `padding_min>max-class`; passphrase flags use SUPPRESS; enroll prechecks the CSR path; MTU comment corrected (default unchanged).

---

## Task 1.12: `config.example.toml` boots as shipped + documents every field

**Problem:** as copied the example refuses to start (`crl_strict=true` default with `crl_file` commented out, all-zeros `ca_root_sha256`), documents 0640 allowlist perms the code rejects, sets `jitter_ms_max=50` (reverting the M-ANON-4 bump to 100), and omits `debug_dns`/`debug_net`/`auto_mtu`/`pmtu_check_interval_s`/`allow_soft_attest`.

**Fix:** rewrite `config.example.toml` so a copy with the two required secrets filled (real `ca_root_sha256`, a `crl_file` or explicit `crl_strict=false`) loads; document every field; fix the perms note (0600 not 0640); set `jitter_ms_max=100`; add the missing fields.

**Files:**
- Modify: `config.example.toml`
- Test: `tests/test_example_config.py` (Create)

- [ ] **Step 1: Write the failing test**

```python
"""Phase 1.12: the shipped example config loads after the operator fills the
two required secrets (ca_root_sha256 + a CRL decision), and documents every
Config field.
"""

from __future__ import annotations

import os
import re
import tempfile
import unittest
from dataclasses import fields
from pathlib import Path

from dsm.core.config import Config, load

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = REPO_ROOT / "config.example.toml"


class ExampleConfigBoots(unittest.TestCase):
    def test_example_loads_with_minimal_secrets_filled(self) -> None:
        text = EXAMPLE.read_text()
        # Fill the all-zeros pin placeholder with a real 64-hex value and set
        # crl_strict=false (the documented dev escape hatch) so a no-CRL copy
        # loads. Both substitutions are documented in the example itself.
        text = text.replace("0" * 64, "ab" * 32)
        if "crl_strict" not in text:
            self.fail("example must document crl_strict")
        text = re.sub(r"#\s*crl_strict\s*=.*", "crl_strict = false", text)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "config.toml"
            p.write_text(text)
            os.chmod(p, 0o600)
            cfg = load(p)
        self.assertEqual(cfg.jitter_ms_max, 100)

    def test_example_documents_every_field(self) -> None:
        text = EXAMPLE.read_text()
        # Every Config field name should appear somewhere in the example
        # (commented or active), except the internal-only config_dir.
        for f in fields(Config):
            if f.name == "config_dir":
                continue
            self.assertIn(
                f.name, text, f"example must mention config field {f.name!r}"
            )


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m pytest tests/test_example_config.py -q`
Expected: FAIL — `jitter_ms_max` is 50, several fields (`debug_dns`/`auto_mtu`/etc.) are absent, and `crl_strict` is undocumented.

- [ ] **Step 3: Rewrite `config.example.toml`**

Replace `config.example.toml` so it documents every field and boots. Key changes from the current file:
- Add a documented `crl_strict` block explaining the fail-closed default and the dev escape hatch.
- Add a "REPLACE before first start" note on the `ca_root_sha256` placeholder.
- Change the allowlist perms note from `0o600 or 0o640` to `mode 0600 (or 0400)`.
- Set `jitter_ms_max = 100`.
- Add commented `debug_dns`, `debug_net`, `auto_mtu` (recommend `true` for cellular), `pmtu_check_interval_s`, `allow_soft_attest`.

New file content:

```toml
# DSM VPN Configuration
# Copy to /opt/mtun/config.toml (mode 0600) and edit. All file paths must be
# absolute.
#
# Trust model: every device runs `dsm enroll --csr-out` once, walks the CSR to
# the offline CA laptop, gets a cert back, and runs `dsm enroll --import`.
# At runtime the daemon authenticates peers against the pinned CA root +
# (server) CN allowlist or (client) expected_server_cn. See deploy/GUIDE.txt.

mode = "client"                              # "client" | "server"
server_ip = "203.0.113.1"                    # Server public IPv4 literal (not a hostname, not IPv6)
server_port = 51820                          # Server's service port
listen_port = 0                              # client: 0 = ephemeral; server: real bind port

# ─── Identity & device cert ────────────────────────────────────────────────
key_file = "/opt/mtun/identity.key"          # Argon2id-wrapped X25519 Noise static (absolute path)
cert_file = "/opt/mtun/device.crt"           # X.509 leaf cert (DER or PEM), signed by internal CA
ca_root_file = "/opt/mtun/dsm_ca_root.pem"   # Pinned CA root cert (PEM)
# REQUIRED — REPLACE the all-zeros placeholder BEFORE first start. SHA-256 of
# ca_root_file (64 hex chars). The daemon refuses to start without a real value
# (it pins the trust anchor so a swapped on-disk CA PEM is rejected). Compute:
#   sha256sum /opt/mtun/dsm_ca_root.pem | cut -d' ' -f1
ca_root_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
attest_key_file = "/opt/mtun/attest.key"     # Argon2id-wrapped ECDSA P-256 attestation key

# Refuse to start on the extractable software attestation backend
# (dev-soft-attest), whose key is recoverable from process memory and gives NO
# hardware binding. Leave false in production; set true ONLY to acknowledge the
# risk in dev/lab. Startup then logs a prominent WARNING + netaudit event.
# allow_soft_attest = false

# ─── Certificate revocation (CRL) ──────────────────────────────────────────
# crl_strict is true BY DEFAULT and fail-closed: the daemon refuses to start
# unless a crl_file is configured AND it is not past next_update. A fresh copy
# of this example WITHOUT a crl_file will refuse to start. Either provide a CRL:
# crl_file = "/opt/mtun/dsm_ca.crl"          # DER or PEM; refresh monthly via walked-USB
# ...or, for dev/lab only, drop to a warning:
# crl_strict = false

# ─── Role-specific cert policy ─────────────────────────────────────────────
# Client only: subject CN we accept on the server cert.
expected_server_cn = "dsm-1234abcd-server"

# Server only: file with one allowed client subject CN per line. Mode 0600
# (or 0400) — any group/world bits are rejected at startup.
# allowed_cns_file = "/opt/mtun/allowed_cns.txt"

# Server only: DNS providers + pinned SPKI SHA-256 (server resolves on behalf
# of clients). Provider host MUST be an IP literal (a hostname dead-loops
# through the TUN).
# dns_providers = ["https://1.1.1.1/dns-query"]
# [dns_provider_pins]
# "https://1.1.1.1/dns-query" = ["<64-char hex SPKI SHA-256>"]
# debug_dns = false                          # true logs plaintext qnames (privacy off)

# ─── Network ───────────────────────────────────────────────────────────────
transport = "udp"                            # "udp" | "tcp"
tun_name = "mtun0"
log_level = "warning"                        # "debug" | "info" | "warning" | "error"

# TUN MTU. Default 1400 leaves slack for VPN-in-VPN / PPPoE paths.
mtu = 1400
# pmtu_discover = false                      # Enable IP_MTU_DISCOVER (sets DF bit)
# auto_mtu = false                           # Track kernel PMTU + adjust TUN MTU; recommend true for cellular/roaming
# pmtu_check_interval_s = 30.0               # auto_mtu poll cadence (seconds)

# Structured JSON audit stream on the dsm.netaudit logger. May also be enabled
# with --debug-net. Note: enabling it on a shared log host re-exposes some
# handshake-failure detail; see deploy/GUIDE.txt §9.
# debug_net = false

# ─── Traffic shaping ───────────────────────────────────────────────────────
padding_min = 128
padding_max = 1400
jitter_ms_min = 1
# jitter_ms_max widens the packet-reorder window for anonymity. 100 is the
# M-ANON-4 default; lower values trade anonymity for interactive latency.
jitter_ms_max = 100

# ─── Key rotation ──────────────────────────────────────────────────────────
rotation_packets = 5000                      # Rotate after N packets
rotation_seconds = 600                       # Rotate after N seconds (10 min)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_example_config.py -q`
Expected: both PASS.

- [ ] **Step 5: Run the focused gate**

Run: `python3 -m pytest tests/test_example_config.py tests/test_config.py -q`
Expected: PASS.

- [ ] **Step 6: Report** — one line: `config.example.toml` now boots after filling the two required secrets, documents every field incl. `crl_strict`/`auto_mtu`/`debug_*`/`allow_soft_attest`, fixes the perms note to 0600, and restores `jitter_ms_max=100`.

---

## Task 1.13: Coarse server-side cert-auth audit label (anti-enumeration)

> **FLAG FOR OWNER:** this edits the effort-created `tests/test_netaudit_no_leak.py` (the server assertion changes from `"CNNotAllowedError"` to `"cert_auth"`). That file is editable (created during this effort). No new netaudit event NAME is added, so `tests/test_netaudit.py::EXPECTED_EVENT_NAMES` needs no edit.

**Problem (server.py:56–69, 284):** the SERVER's `_emit_handshake_failure` emits `error=type(err).__name__`, so under `--debug-net` a journald reader can distinguish `CNNotAllowedError` (allowlist miss) from `CertRevokedError` (CRL hit) from `CertAuthError` (binding mismatch) — enabling enumeration of the allowlist / CRL that the opaque human WARNING deliberately hides.

**Fix:** in the SERVER's `_emit_handshake_failure`, map any `CertAuthError` subclass (`CNNotAllowedError`/`CertRevokedError`/`CertAuthError`/`CNMismatchError`) to a single `error="cert_auth"` family label. Keep the precise class name for non-cert `HandshakeError` (and leave the CLIENT side precise — the client owns its server and needs the detail to debug).

**Files:**
- Modify: `dsm/server.py:56–69` (`_emit_handshake_failure`)
- Modify (effort-created file): `tests/test_netaudit_no_leak.py` — update the server expectation
- Test: covered by the updated `test_netaudit_no_leak.py`

- [ ] **Step 1: Update the failing test expectation (effort-created file)**

In `tests/test_netaudit_no_leak.py`, the server test `test_failed_event_omits_message` currently asserts `ev["error"] == "CNNotAllowedError"`. Add a new assertion that the SERVER coarsens cert-auth classes, and keep the client precise. Replace `test_failed_event_omits_message` with:

```python
    def test_server_failed_event_coarsens_cert_auth_class(self) -> None:
        # Phase 1.13: the SERVER must not distinguish allowlist-miss
        # (CNNotAllowedError) from CRL-hit (CertRevokedError) in the audit
        # stream — both map to a single "cert_auth" family label so a
        # journald reader cannot enumerate the allowlist / CRL.
        secret = "client CN 'dsm-secret-victim-client' not in allowlist"
        with _AuditCapture() as cap:
            _emit_handshake_failure(CNNotAllowedError(secret))
        events = cap.events()
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event"], "handshake_end")
        self.assertEqual(ev["outcome"], "failed")
        self.assertEqual(ev["error"], "cert_auth")  # coarse family label
        self.assertNotIn("message", ev)
        self.assertNotIn("dsm-secret-victim-client", cap.text())

    def test_server_non_cert_handshake_error_keeps_class(self) -> None:
        # A non-cert HandshakeError keeps its precise class (no enumeration
        # risk — it doesn't reveal allowlist/CRL membership).
        from dsm.crypto.handshake import HandshakeError

        with _AuditCapture() as cap:
            _emit_handshake_failure(HandshakeError("malformed msg1"))
        ev = cap.events()[0]
        self.assertEqual(ev["error"], "HandshakeError")
```

The CLIENT test `test_client_failed_event_omits_message` stays unchanged (client keeps `error="CNNotAllowedError"`).

> NOTE: add `from dsm.crypto.handshake import CertAuthError` to the imports if needed for clarity, though the test only needs `CNNotAllowedError` (already imported) and `HandshakeError`.

- [ ] **Step 2: Run the updated test to verify it fails**

Run: `python3 -m pytest tests/test_netaudit_no_leak.py -q`
Expected: `test_server_failed_event_coarsens_cert_auth_class` FAILS — the server currently emits `"CNNotAllowedError"`, not `"cert_auth"`.

- [ ] **Step 3: Coarsen the server emit**

In `dsm/server.py`, change `_emit_handshake_failure`:

```python
def _emit_handshake_failure(err: Exception) -> None:
    """Emit the failed-handshake audit event WITHOUT the exception message,
    and with a COARSE family label for cert-auth rejections.

    Phase 1.13: the human WARNING/DEBUG logs already hide cert-auth detail so
    a journald reader can't distinguish CNNotAllowedError (allowlist miss)
    from CertRevokedError (CRL hit) from a binding mismatch and enumerate the
    allowlist / CRL. The netaudit stream (enabled by --debug-net) must apply
    the SAME redaction: collapse every CertAuthError subclass to "cert_auth".
    Non-cert HandshakeErrors keep their precise class (no enumeration risk).
    The client side stays precise — a client owns its server.
    """
    from dsm.crypto.handshake import CertAuthError

    error_label = "cert_auth" if isinstance(err, CertAuthError) else type(err).__name__
    netaudit.emit(
        "handshake_end",
        role="server",
        outcome="failed",
        error=error_label,
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_netaudit_no_leak.py -q`
Expected: all PASS.

- [ ] **Step 5: Run the focused gate**

Run: `python3 -m pytest tests/test_netaudit_no_leak.py tests/test_netaudit.py -q`
Expected: PASS. (`test_netaudit.py::EXPECTED_EVENT_NAMES` is unaffected — no new event NAME; the value of the `error` field changed, not the event name. Confirm `test_call_sites_in_repo` still passes since `handshake_end` is still emitted.)

- [ ] **Step 6: Report** — one line: server cert-auth audit failures collapse to `error="cert_auth"` (anti-enumeration); client stays precise; updated effort-created `test_netaudit_no_leak.py`.

---

## Phase exit gate (run after all tasks)

Run from repo root:

```bash
# Rebuild tuncore once (Task 1.2 changed the extension):
maturin build --release -m rust/tuncore/Cargo.toml && \
pip3 install --user --force-reinstall --break-system-packages \
  rust/tuncore/target/wheels/dsm_tuncore-0.1.0-cp313-cp313-manylinux_2_34_x86_64.whl

# Python lint/type/test gate:
black --check dsm tests
isort --check-only dsm tests
ruff check dsm tests
pylint dsm
pyright
python3 -m pytest tests/ -q

# Rust gate:
cargo fmt --manifest-path rust/tuncore/Cargo.toml -- --check
cargo clippy --release --manifest-path rust/tuncore/Cargo.toml -- -D warnings
cargo test --release --manifest-path rust/tuncore/Cargo.toml
```

Expected: all green. Then an owner review checkpoint per the master plan.
