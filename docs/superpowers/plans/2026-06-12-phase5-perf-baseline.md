# DSM_V2.0 Packet Hot-Path Performance Baseline & Bottleneck Analysis

> Phase-5 deliverable. **Static analysis only — no code changed, no daemon
> profiled.** Per the measure-first rule, this identifies WHERE to measure and
> the likely hot spots with code evidence; it does NOT optimize. A later
> optimization task must write the benches, measure, THEN change code.
> `CONFIRMED` = readable from code; `SUSPECTED` = needs measurement to size.

## Hot-path map (one DATA packet)

- **Send** (`tun_send_loop`, session.py:936-1063): TUN read → `fragment_ip_packet`
  → `shaper.pad_packet` → `observe_real_packet` → `scheduler.enqueue`; later
  scheduler tick → `send_packet` (session.py:200) → epoch patch →
  `session_keys.encrypt` (FFI) → `OuterPacket.serialize` → `transport.send`.
- **Recv** (`recv_loop`, session.py:717-767): `transport.recv` → `decrypt_packet`
  (session.py:311) → `replay.check` (FFI) → slice nonce/ct → `try_decrypt_with_fallback`
  (FFI) → `replay.update` (FFI) → `InnerPacket.deserialize` → `dispatch_inner` → `tun.awrite`.

## 1. Per-packet allocation profile

- **🔴 Send epoch-patch double-copy — CONFIRMED.** session.py:219-222:
  `buf = bytearray(data)` (copy #1, intentional — fresh buffer so the
  scheduler-held reference isn't mutated) then `data = bytes(buf)` (copy #2,
  **avoidable** — the FFI `encrypt` accepts `&[u8]`, so a `bytearray` works
  directly). ~2.8 KB alloc+memcpy per 1400B packet to rewrite ONE byte.
  MEASURE: tracemalloc allocations/packet on `send_packet`; A/B `bytearray`
  vs `bytes(buf)` into `encrypt`.
- **🟠 Shaper `_serialize_padded` `bytes(buf)` — CONFIRMED (mostly necessary).**
  shaper.py:395-401: one bytearray + payload memcpy + `os.urandom(pad)` + final
  `bytes(buf)`. The padding build is necessary; the final `bytes(buf)` is the
  same avoidable pattern, stacking with §1 ⇒ a real packet's plaintext is
  copied ~3-4× before AEAD.
- **🟠 Recv slice copies — CONFIRMED.** session.py:344-346:
  `data[OUTER_HEADER_SIZE:]` copies the whole ciphertext (Python slices aren't
  zero-copy); FFI re-copies again. A `memoryview` slice would avoid the
  Python-side copy.
- **🟡 `OuterPacket.serialize`** (protocol.py:151-155) one assembly + `bytes(buf)`.
- **🟡 dataclass(slots=True) churn** (InnerPacket/OuterPacket/_ScheduledPacket) — minor.
- **✅ struct parsing pre-compiled** (protocol.py:48-50) — module-level `struct.Struct`.

## 2. FFI boundary cost

- Crossings/packet: send 1 (`encrypt`), recv 3 (`replay.check`, `try_decrypt_with_fallback`,
  `replay.update`; the two replay calls are trivial scalar in/bool out).
- **🟠 Encrypt/decrypt: input borrowed (zero-copy `&[u8]`), output Vec→PyBytes copy** —
  CONFIRMED (lib.rs:403-416 / 450-492). The `aes-gcm` crate allocates the output
  Vec; lib.rs copies it into PyBytes. One avoidable copy each, bounded by the
  crate's allocating API (an `encrypt_in_place_detached` into a caller buffer
  would remove it — larger change).
- **✅ GIL released during AEAD** (lib.rs:410/432/467 `py.allow_threads`).
- **✅ Key bytes never cross FFI** (LockedKey32, mlock'd).
- Note: the constant-time forgery defense (lib.rs:467-490) runs a 2nd AEAD on the
  failure path only (deliberate, M1) — a forgery flood costs 2× AEAD/dropped pkt.

## 3. Async/await structure

- **🟠 Scheduler poll cadence + envelope ceiling = the throughput cap (by design).**
  scheduler.py:35-36 wakes every 30-70 ms; throughput = `envelope_pps`, capped at
  `_ENVELOPE_CEILING_PPS = 600` (shaper.py:71). This is the anonymity pacing, not a
  bug — but it is THE single-flow ceiling; per-tick sends are awaited sequentially.
- **🟠 TUN read add_reader/remove_reader per packet — CONFIRMED.** tunnel.py:376-394:
  every read does future alloc + add_reader + remove_reader (finally), plus
  `wait_for(..., 0.1)` (session.py:1023). The remove is correctness-required
  (dropped-packet bug); a persistent-reader redesign would amortize it.
- **🟡 `enqueue` csprng_float jitter + heappush O(log n)** per packet (scheduler.py:110-114).
- **✅ awrite sync-first** (tunnel.py:400-414, os.write then executor only on EAGAIN).
- **✅ No per-packet task spawning.**

## 4. Algorithmic

- **🟡 Chaff/size O(classes≤11) scans** (shaper.py:139/294/151), SizeTracker EMA O(11)
  (shaper.py:122) — tiny n; cumulative prior precomputed once (shaper.py:203).
- **🟡 csprng_float per packet/poll** — backed by thread-local batched SystemRandom
  (rand.py:36-45), no syscall each (already optimized, M-PERF-1/2).
- **✅ Replay window O(1)** (u128 bitmap). **✅ Reassembly dict O(1)** on the common
  (non-fragment) path. **✅ No regex/.format in the loop.**

## 5. Crypto floor (irreducible)

AES-256-GCM per packet (aes_gcm.rs:57-91); key schedule cached once
(aes_gcm.rs:38-46). ~0.5-1.5 µs/1400B with AES-NI; 10-40× slower without (relevant
for low-power/ARM targets). This is the floor; §1-§3 are overhead around it.
SUSPECTED: at 128-512B the Python plumbing dominates AEAD; approaches parity at 1400B.

## 6. Measurement plan (execute later — NOT now)

1. **Rust AEAD criterion** — `benches/aead.rs`: `AesKey::encrypt`/`decrypt` at
   {128,512,1024,1400}B; ns/op + GB/s; reveals AES-NI presence. (The Cargo.toml
   `[[bench]]` wiring contests Phase-3's Cargo.toml — schedule after Phase 3.)
2. **FFI marshaling micro-bench** — tight Python loop on `encrypt`/`try_decrypt_with_fallback`,
   subtract the criterion floor ⇒ PyO3 + Vec→PyBytes cost.
3. **Python pump throughput** — TrafficShaper+SendScheduler+mock send_fn+real
   SessionKeyManager; packets/sec + allocations/packet (tracemalloc); isolates §1/§3.
4. **Allocations/packet** — tracemalloc snapshot diff around one send + one recv.
5. **py-spy flamegraph** on a synthetic loopback/mock-transport driver (not the live daemon).

SUSPECTED baselines: AEAD ~0.5-1.5 µs/1400B (AES-NI); Python plumbing ~5-20 µs/packet
(likely dominating at small sizes); single-flow wire ≤600 pps by envelope design.

## 7. Phase-2 envelope overhead — CONFIRMED O(1), not a per-packet cost

`update_envelope` (shaper.py:415-464) + `release_budget` (shaper.py:479-504) are
O(1), allocation-free, called once per ~50 ms poll (one `pow()` + a few float ops).
The Phase-2 rework introduced no per-packet hot spot.

## Prioritized "measure these 5 first"

1. Send-path allocations/packet (§1 epoch-patch + serialize copies) — most likely avoidable win.
2. Rust AEAD criterion floor (§5).
3. Python pump throughput + py-spy (§3/§6).
4. Recv-path slice allocations (§1).
5. FFI round-trip minus AEAD floor (§2).

**Already efficient — do not spend budget here:** pre-compiled struct, GIL-released
AEAD, cached AES key schedule, O(1) u128 replay, O(1) envelope, batched-CSPRNG
csprng_float, sync-first awrite.

## 8. TPM attest-sign cost — per connection-establishment, NOT per packet

The TPM attest key signs ONCE per connection-establishment (`build_attest_payload`,
over the handshake hash), never on the data hot path — so it does not appear in the
per-packet map above. Each sign uses the stateless re-open model
(`device_attest_tpm::TpmAttestKey::sign`): open an Esys context, re-derive the
deterministic Owner primary, `TPM2_Load` the child, `TPM2_Sign`, then flush both
transient handles. That is roughly tens of milliseconds (open + create_primary +
load + sign), bounded and acceptable for v1 since it is connection-setup latency,
not steady-state throughput.

A post-v1 optimization is a per-session cached TPM context (re-use one open context
+ loaded child for the session's lifetime instead of re-opening every sign).
`tss_esapi::Context` is `!Send`/`!Sync` (it owns a raw `ESYS_CONTEXT` pointer), so a
cache cannot simply live in the `#[pyclass(unsendable)]` key; it needs a dedicated
TPM thread that owns the context and serves sign requests over a channel. Deferred —
no measurement yet justifies the added complexity, and the current per-establishment
cost is not on the packet hot path.
