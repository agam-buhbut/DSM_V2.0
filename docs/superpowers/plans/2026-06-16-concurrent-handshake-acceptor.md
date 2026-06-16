# Design: Concurrent, Bounded Handshake Acceptance (review finding #5)

> **Status: DEFERRED (owner decision 2026-06-16).** Design complete; not implemented.
> Implement when the connection-starvation DoS is prioritized. Owner pre-approved
> adding the `max_inflight_handshakes` Config field and confirmed UDP-first scope.

## Problem

`dsm/server.py`'s accept path is a single serial coroutine: `_accept_one_session`
calls `server_handshake` once per iteration, and `_recv_initial` blocks on one
`transport.recv()` for up to `MSG1_WAIT_TIMEOUT = 30s`. Because there is ONE shared
UDP socket feeding one queue (udp.py: no `SO_REUSEPORT`), an attacker who sends a
well-formed-length msg1 then goes silent makes the single responder advance to msg2
and block waiting for msg3 across `MAX_RETRIES=3 × HANDSHAKE_TIMEOUT=5s` + backoff
(~18s). A low-rate stream of such attempts keeps the one coroutine permanently busy
and starves legitimate clients. nftables rate-limiting bounds packet rate but cannot
distinguish a slow legitimate handshake from a slow bogus one.

## Determination: single session, concurrent VALIDATION only

N simultaneous live tunnels is architecturally impossible — per-session host state is
singleton: one TUN named `config.tun_name`, one `IPForwardingManager`/`MasqueradeManager`,
one `LocalDNSProxy` bound to `SERVER_TUN_IP:53`, one shared UDP socket (no `SO_REUSEPORT`).

**Chosen model:** concurrently VALIDATE handshake attempts with bounded concurrency +
per-attempt timeouts; the first attempt to FULLY authenticate wins and becomes the single
admitted live session; all other in-flight attempts are cancelled/cheaply rejected; while
a session is live, new handshake traffic is dropped at the cheapest layer.

## Concurrency model

A bounded pool of handshake workers feeds a single "winner" `asyncio.Future`:
- One `_demux_loop` is the SOLE caller of the real `transport.recv()`. For each datagram
  it routes `(data, addr)` to a per-`addr` in-memory inbox (bounded `asyncio.Queue`).
- First datagram from a never-seen addr (if a worker slot is free) spawns a worker bound
  to a `_PerPeerUDPView` — a thin object exposing the `recv()`/`send()` surface
  `server_handshake` expects, where `recv()` drains that peer's inbox and `send()`
  delegates to the real socket with the peer's addr pre-bound. **`server_handshake` needs
  NO change** (the per-peer view satisfies its existing transport contract, and its
  per-message source-pinning is automatically satisfied).
- Workers run inside `asyncio.TaskGroup` + `Semaphore(MAX_INFLIGHT)`, each with a hard
  per-attempt deadline. First to return `(keys, pub)` sets the winner; the TaskGroup is
  cancelled (all losers die), and the winner's `(keys, pub, real_transport)` is handed to
  the EXISTING `_run_one_session` UNCHANGED.

TCP has no demux problem but needs a persistent multi-accept listener (a `TCPTransport`
change) — **deferred; UDP-first** (UDP is the real DoS vector — no kernel accept-queue gating).

## Integration points (server.py)

- **Replace** `_accept_one_session` with `_accept_until_winner` (same return contract:
  `(keys|None, pub|None, transport)`; same `(None, None, transport)` shutdown sentinel).
- `run_server`'s outer loop, the outer/inner `AsyncExitStack`s, rate limiter, signal
  handlers, UDP bind, and **`_run_one_session` itself are UNCHANGED.** Reuse
  `_emit_handshake_failure` and `_backoff_or_shutdown`.
- **Zero changes** to `dsm/session.py`, `dsm/crypto/handshake.py`, transports, `tuncore`.

## Bounds / backpressure

| Knob | Value | Rationale |
|---|---|---|
| `max_inflight_handshakes` (new Config field, default 8, validated >=1) | 8 | bounds peak NoiseResponders + CPU; far above steady-state (1 client); operator-tunable |
| `_HANDSHAKE_ATTEMPT_DEADLINE` | 12s | covers one lost+retransmitted message; caps slot-occupancy an attacker buys with one msg1 (vs old ~18s+30s); supersedes MSG1_WAIT_TIMEOUT under an outer `wait_for` |
| `_PER_PEER_INBOX_FRAMES` | 8 | a correct handshake has ≤1 unconsumed frame; overflow drops (peer DoSes only itself) |
| `_ACCEPT_DEMUX_POLL` | 0.1s | matches data-loop cadence so shutdown is seen within 100ms |

**Saturated (attempt N+1):** UDP drops a NEW-source datagram (no msg2, no state) — the
cheapest rejection; an EXISTING in-flight addr routes to its inbox (drops if full). A legit
client relies on `client_handshake`'s own msg1 retransmission to land in a freed slot
(slots free every ≤12s). All-fail-saturated reuses the existing jittered backoff.

## Property preservation

AsyncExitStack teardown, path-validation roaming, nft kill-switch + rate-limit,
shutdown-driven teardown, nonce/seq/replay freshness, and the single-TUN model are ALL
intact because exactly one `_run_one_session` runs at a time and the acceptor allocates NO
host state (only in-memory queues + TaskGroup-scoped tasks, all cancelled before admission).
**Most delicate point:** after `winner.set_result`, stop the demux and hand the UNDRAINED
real socket to the data path so no post-handshake frame is lost (demux writes per-peer
in-memory inboxes, NOT the real `_recv_queue`, so residual frames remain for the data path).
Recommend a security-agent review of the demux + this handoff.

## Test plan (new file `tests/test_handshake_concurrency.py`, no sleeps, no real net)

Reuse `_ScriptedUDPTransport`/`_NoopScheduler`/`_FakeClock` (test_server_peer_roaming.py)
and the `test_handshake_dos.py` patterns. Cases: (1) no-starvation under a stalled bogus
attempt [fails today, passes after]; (2) bounded concurrency; (3) per-attempt deadline frees
slot; (4) first-to-auth wins + losers cancelled cleanly (no "Task destroyed pending", no
second `_run_one_session`); (5) clean teardown on shutdown-during-accept; (6) post-handshake
socket handoff loses no frame; (7) fresh per-session counters across cycles.

## Interface sketch

```python
async def _accept_until_winner(config, fsm, keystore, attest_store, materials,
    cn_allowlist, transport_obj, process_shutdown
) -> tuple[tuncore.SessionKeyManager | None, bytes | None,
           UDPTransport | TCPTransport | None]: ...

class _PerPeerUDPView:
    def __init__(self, real: UDPTransport, peer_addr: tuple[str, int],
                 inbox: asyncio.Queue[bytes]) -> None: ...
    async def recv(self, timeout: float | None = None
                   ) -> tuple[bytes, tuple[str, int]]: ...   # always (data, peer_addr)
    async def send(self, data: bytes, addr: tuple[str, int]) -> None: ...

# dsm/core/config.py Config:
max_inflight_handshakes: int = 8   # validated >= 1
```

## Resolved / open

- Python floor `>=3.11` confirmed → `asyncio.TaskGroup` available.
- Owner approved the new Config field; scope = UDP-only first (TCP follow-up).
- Open style choice: new code in `server.py` vs a new `dsm/net/handshake_acceptor.py`
  (recommend the latter for isolation). Not blocking.
