# Phase 2 — Adaptive-Envelope Traffic Shaping Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This is the CORE ANONYMITY phase — the **DESIGN FORKS** section MUST be brought to the owner and resolved before any code is written.

**Goal:** Make the DSM wire rate **independent of instantaneous real-traffic volume**. Today (finding H8, `dsm/traffic/shaper.py`) chaff is purely *additive*: real packets are released immediately (1–100 ms jitter only) and chaff merely fills idle time at an EMA rate, so a passive observer sees active-period volume and burst onset directly. The owner chose (2026-06-11) the **adaptive envelope** model: real packets are *paced* into a slowly-varying target wire rate (the "envelope"); chaff fills the gap when real < envelope; bursts raise the envelope slowly (bounded rise rate) so burst onset is smeared over seconds, bounded by a per-packet **latency budget**. The README's "no observable boundary between active and idle" claim — currently FALSE for active traffic — is rewritten to claim exactly what the envelope provides.

**Architecture:** The change is concentrated in three modules. `dsm/traffic/shaper.py` gains an **envelope estimator** (a paced target rate with bounded rise/fall and an idle floor) and a **release-decision** method that the scheduler polls each tick to decide how many queued packets may leave now. `dsm/traffic/scheduler.py` becomes envelope-driven: instead of "drain everything whose jitter time arrived + at most one chaff", it asks the shaper for the per-tick wire budget and emits exactly that many packets from a unified stream (real queue first, chaff to fill). `dsm/session.py`'s `tun_send_loop` stops marking burst onset by enqueuing real packets with size-correlated immediacy — real packets enter the *same* paced queue. Two correctness findings ride along: the EMA ceiling-snap on burst (`shaper.py:336`) and chaff sizes leaking the real-traffic profile (`shaper.py:292`). To make the statistical tests deterministic, `TrafficShaper` and `SendScheduler` gain an **injectable monotonic clock** (default `time.monotonic`) — the only way to test pacing without wall-clock sleeps, since the CSPRNG (`dsm/core/rand.py`, `random.SystemRandom`) is deliberately non-seedable.

**Tech Stack:** Python 3.11+ asyncio, `pytest`/`unittest`, `dsm.core.rand` (CSPRNG), `dsm.core.protocol` size classes, `dsm.core.config` (new envelope knobs), `dsm.core.netaudit` (existing event stream — see FLAG 4). No new third-party dependencies.

---

## Environment notes (apply to every step)

- **Python tests** run from the repo root: `python3 -m pytest tests/<file> -q`. The system `python3` has `dsm` + `tuncore` importable. None of the Phase-2 code touches Rust, so no wheel rebuild is required.
- **No git commits anywhere.** Each task ends with a one-line **Report** step. The owner commits.
- **New tests go in NEW files:** `tests/test_adaptive_envelope.py`, `tests/test_envelope_statistics.py`, `tests/test_chaff_size_prior.py`, `tests/test_envelope_config.py`.
- **PRE-EXISTING test_shaper.py — OWNER-APPROVED rewrite (2026-06-11):** the owner approved deleting/rewriting the obsolete additive-model test classes/functions that assert the model the envelope replaces: `TestRateEMA`, `TestPoissonChaffScheduling`, `TestNoFixedCadence`, and `test_burst_smoothing_is_permanently_none` (and any other test that asserts immediate-release / additive-Poisson / `burst_smoothing_delay`-is-None semantics). Their coverage is replaced by the new envelope statistical + distribution tests. **Before deleting/rewriting any test, the implementer MUST list the exact tests it will change in its report and the orchestrator confirms the list with the owner.** All OTHER test_shaper.py tests (e.g. `TestNoModeBoundary`, size-class/padding tests) must stay GREEN — if the envelope breaks one of those (not in the approved obsolete set), STOP and FLAG it; do not edit it. `tests/test_symmetric_shaping.py` is NOT edited (it should stay green under the fixed-prior chaff — it only checks size-class support).
- **Determinism rule (critical):** the CSPRNG is non-seedable by design. Statistical tests MUST drive an **injected monotonic clock** (a callable the shaper/scheduler read instead of `time.monotonic`) and record the resulting wire-emission timestamps, then assert statistical properties with **generous bounds**. No `time.sleep`, no `asyncio.sleep` against wall clock in tests.
- Type hints on all new signatures; `black`/88; `isort` profile black; specific exceptions; `raise X from e`. Keep `pylint` at 10.00 — `shaper.py`/`scheduler.py` do NOT have `too-many-lines`/`too-many-*` disabled (only `session.py` does), so keep new methods small and extract helpers rather than growing one god-method.
- **Performance rule:** the envelope runs on the per-packet hot path and on every scheduler poll (~30–70 ms). The release-decision must be O(1), allocation-free in the steady state (no per-packet list/dict construction in the pacing loop), and must not add a CSPRNG call per packet beyond what already exists. Note any added per-packet cost in the task Report.

---

## DESIGN FORKS — ✅ RESOLVED (owner-confirmed 2026-06-11): recommended profile adopted in full

**All 8 forks = the RECOMMENDED option.** Fork 1 budget = **250 ms**; Forks 2–6,8 = the recommended profile (rise ×2/s cap, ~4s fall half-life, soft 600pps ceiling, per-session randomized idle floor [0.5,2.0]pps, packets/sec envelope, fixed-prior chaff sizes, the 6 `envelope_*` knobs); Fork 7 = **YES** (pace rekey + normal SESSION_CLOSE; Task 2.6 is IN). The original fork analysis is retained below for reference and rationale.

These were genuine decisions that change observable anonymity / latency / bandwidth. Each has a recommendation and the tradeoff. The recommended defaults are internally consistent (they form one coherent envelope profile).

### Fork 1 — Latency budget (max queueing delay for a real packet)

**Options:** 50 ms (aggressive, interactive-friendly) / **250 ms** / 1 s (strong hiding).
The budget caps how long a real packet may wait in the paced queue before the envelope is forced to rise faster (or the packet is released early). Lower = the envelope must ramp quickly to drain, which lets burst onset bleed through sooner (less hiding); higher = better hiding but visible added latency under sustained burst.

**Recommendation: 250 ms, configurable as `envelope_latency_budget_ms` (default 250).** 250 ms is below the threshold where interactive traffic (web, SSH echo) feels laggy for most users, yet long enough that a sub-second burst is smeared rather than passed through. Couples with Fork 2: a 250 ms budget pairs with a rise rate that can roughly double the envelope per ~1–2 s.

**Tradeoff:** at 250 ms a bulk-transfer burst adds up to a quarter-second of head-of-line latency to the first packets until the envelope catches up; VoIP/gaming operators who need <50 ms RTT should lower it (and accept faster onset leakage).

### Fork 2 — Envelope rise / fall rates

**Options for rise:** fast (envelope reaches real rate in <1 s — defeats the point) / **slow, multiplicative cap ~×2 per second** / very slow (×1.3/s — best hiding, highest queueing).
**Options for fall:** snap-to-floor on idle (re-exposes the boundary — rejected) / **exponential decay with ~3–5 s half-life**.
The rise rate is THE burst-onset-smearing knob: the slower it rises, the longer onset is hidden, the more real packets queue (bounded by the latency budget, Fork 1).

**Recommendation: rise = multiplicative, capped so the envelope can at most ~double per second (`envelope_rise_per_s = 2.0`); fall = exponential decay with a ~4 s half-life (`envelope_fall_half_life_s = 4.0`).** This smears a burst onset across ~2–4 s — long enough to defeat a 1 s-granularity step detector (the discriminator in Task 2.4) while the latency budget (Fork 1) guarantees no real packet waits more than 250 ms (when the budget would be exceeded the envelope rises faster than the cap for that tick — the budget *overrides* the rise cap; see Task 2.1).

**Tradeoff:** slower rise = stronger hiding but more queued real packets and a larger post-burst chaff tail (the envelope decays for several seconds after the burst ends, burning bandwidth). The half-life sets how long that tail lasts.

### Fork 3 — Envelope ceiling (max wire rate)

**Options:** fixed config ceiling (caps overhead AND throughput) / **config ceiling that the latency budget can temporarily pierce** / unbounded-but-latency-limited.
A hard ceiling caps both chaff bandwidth and real throughput; if real traffic exceeds the ceiling, packets queue past the latency budget and the budget-override (Fork 1) would fight a hard cap.

**Recommendation: a configurable soft ceiling `envelope_ceiling_pps` (default 600 pps ≈ the current `_CHAFF_RATE_CEIL_PPS=200` raised to accommodate real throughput) that the latency-budget override MAY exceed.** Normal chaff-fill never exceeds the ceiling; only the budget-override (a real packet about to breach its latency budget) may push the instantaneous release rate above it, so the ceiling caps *idle/chaff* overhead without throttling genuine throughput.

**Tradeoff:** a soft ceiling means a sustained high-rate real flow can drive the wire rate above the nominal cap, so the operator's worst-case bandwidth is bounded by the *real* peak, not the ceiling. A hard ceiling would bound bandwidth absolutely but cap throughput and add unbounded latency under load (rejected). 600 pps × ~1400 B ≈ 6.7 MB/s — note this caps *chaff* bandwidth, not real.

### Fork 4 — Idle floor (min wire rate / chaff floor)

**Options:** keep a fixed low floor (current `_CHAFF_RATE_FLOOR_PPS = 1.0`) / raise it (more cover, more steady overhead) / **randomize it per-session within a small band**.
Finding `shaper.py:62`: an always-on 1 pps floor is a steady DSM baseline — a constant ~1 pps stream is itself a (weak) DSM fingerprint and a fixed ~1.4 kB/s idle overhead.

**Recommendation: keep a low floor but make it a per-session random draw in a small band (`envelope_idle_floor_pps` drawn uniformly in [0.5, 2.0] at shaper construction, configurable bounds).** A per-session randomized floor removes the *exact-1-pps* constant signature while keeping idle overhead negligible (~0.7–2.8 kB/s). The floor is fixed for the session lifetime (re-randomizing it would itself create a time-varying signal).

**Tradeoff:** a randomized floor means two DSM sessions don't share an identical idle cadence, but the *presence* of a low steady floor is still detectable (documented as accepted residual in the README rewrite, Task 2.5). Raising the floor for stronger cover is an operator choice via config bounds.

### Fork 5 — Bytes/sec vs packets/sec envelope

**Options:** **packets/sec envelope** (simpler; the current model is pps; size is handled separately by padding+chaff size prior) / bytes/sec envelope (hides size/volume better but must reconcile with the discrete size classes and is materially more complex).

**Recommendation: packets/sec envelope (keep the pps model).** Size is already hidden by (a) padding every real packet to a size class and (b) drawing chaff sizes from a fixed published prior (Fork 6 / Task 2.3). With both real and chaff drawn from the *same* size-class distribution, a constant *packet* rate yields a near-constant *byte* rate as a consequence — a bytes/sec envelope adds significant complexity (fractional-packet accounting, size-vs-rate coupling) for marginal additional hiding.

**Tradeoff:** a pps envelope leaves a *residual* byte-rate signal only if the real and chaff size distributions diverge; Task 2.3 (fixed prior) closes most of that gap. If a future review shows the residual byte-rate leak matters, a bytes/sec envelope is the post-v1 upgrade. Recommend documenting the pps choice + residual in the README.

### Fork 6 — Chaff size distribution

**Options:** current **real-EMA-mirroring** (finding `shaper.py:292` — leaks the coarse app profile into the aggregate size histogram) / **fixed published prior** / normalize so each class emits at a target-independent rate.

**Recommendation: draw chaff sizes from a FIXED published prior, independent of the live `SizeTracker` EMA.** Use the already-published `SIZE_CLASS_WEIGHTS` (`dsm/core/protocol.py`: `(20, 15, 12, 10, 8, 7, 6, 6, 5, 6, 5)` over the 11 classes) as the chaff prior. Real packets still pad to whatever class fits (driven by actual size), but chaff no longer *tracks* the real distribution — so the *aggregate* (real+chaff) histogram trends toward the published prior rather than amplifying the user's actual app profile. This is the fix for `shaper.py:292`. Keep the ±1-class perturbation for chaff (it further decorrelates) but apply it on top of the fixed prior, not the EMA.

**Tradeoff:** if a user's real traffic is heavily skewed to one class, the aggregate histogram is real-skew + fixed-prior-chaff — still partially reveals the skew when real volume dominates chaff. Under the envelope, chaff volume is high whenever real is low (fill-to-envelope), so the prior dominates exactly when the user is most exposed (idle). The published prior becomes the DSM "house" size distribution (a fleet-wide constant), which is the intended anonymity-set property.

### Fork 7 — Control-plane packets through the envelope

**Options:** **route rekey / SESSION_CLOSE through the paced scheduler** (finding `rekey.py:64` — currently they bypass the scheduler via direct `send_fn`, so their timing doesn't match the envelope) / leave them out-of-band (simpler, but a rekey/close emits an un-paced packet whose timing differs from the steady stream).

**Recommendation: route rekey INIT/ACK and SESSION_CLOSE through the scheduler/envelope, with one carve-out — SESSION_CLOSE at teardown still falls back to a direct bounded send if the scheduler is already stopped.** Rekey packets are not latency-critical to the millisecond (the retry budget is 8 s × 9), so pacing them into the envelope removes a control-plane timing fingerprint. SESSION_CLOSE during normal operation goes through the envelope; the teardown path (`run_data_loops`' `finally`, after `scheduler.stop`) keeps its existing direct bounded `send_fn` because the scheduler is gone by then.

**Tradeoff:** pacing rekey adds up to one latency-budget of delay (≤250 ms) to INIT/ACK — negligible against the 8 s ACK timeout. **Risk/complexity:** rekey currently calls `send_fn` directly from `dsm/rekey.py`, so this requires threading the scheduler (or a paced-enqueue callable) into the rekey helpers — a wider blast radius than the rest of Phase 2. **If the owner picks "leave out-of-band", Task 2.6 is dropped** and the README documents the control-plane timing as a residual. Recommend YES but flag it as the highest-risk fork to retrofit (see "Retrofit risks").

### Fork 8 — Overhead cap / config knobs (how much bandwidth the operator will burn)

**Options:** hard-code the envelope profile / **expose the profile as config with sane defaults** / expose a single "overhead budget" knob that derives the rest.

**Recommendation: expose the envelope as discrete, documented config fields with the defaults above, all optional (backward-compatible):** `envelope_latency_budget_ms=250`, `envelope_rise_per_s=2.0`, `envelope_fall_half_life_s=4.0`, `envelope_ceiling_pps=600`, `envelope_idle_floor_min_pps=0.5`, `envelope_idle_floor_max_pps=2.0`. Document the idle overhead (idle floor × mean packet size) and the burst-tail overhead (decay half-life) in `config.example.toml` and the README so an operator can reason about bandwidth. Provide one summary line: "idle overhead ≈ floor_pps × ~900 B/pkt; expect ~0.5–2 kB/s idle."

**Tradeoff:** six knobs is more surface than one budget knob, but each maps to a single observable property (latency, onset-hiding, tail length, throughput cap, idle cover) and the defaults form a coherent profile — operators who don't care leave them unset. A single derived "overhead budget" knob is friendlier but couples the properties opaquely; rejected in favor of explicit knobs given the anonymity-sensitivity.

---

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `dsm/traffic/shaper.py` | Modify | Add envelope estimator (paced target rate w/ bounded rise/fall, randomized idle floor, soft ceiling); add `release_budget(now)` (how many packets may leave this tick) + `note_queue_state(...)`; fix EMA ceiling-snap (`shaper.py:336` — floor `dt`/rate-limit EMA updates, Task 2.2); decouple chaff size from `SizeTracker` EMA → fixed `SIZE_CLASS_WEIGHTS` prior (`shaper.py:292`, Task 2.3); inject `clock` callable for testability; make `burst_smoothing_delay()` either real or removed-from-callsite (Task 2.1 decides — see note). |
| `dsm/traffic/scheduler.py` | Modify | Envelope-driven drain: each poll, ask shaper for the wire budget, emit that many from the unified stream (real queue first, chaff fills); remove the 1-chaff/poll cap (`scheduler.py:150`); inject `clock`. |
| `dsm/session.py` | Modify | `tun_send_loop`: real packets enter the paced queue (no size-correlated immediacy); drop the `burst_smoothing_delay()`+`asyncio.sleep` interim (the envelope subsumes it); keep fragment spread but reconcile with pacing. |
| `dsm/core/config.py` | Modify | Add the six `envelope_*` fields (Fork 8) + validators; keep all optional/back-compat. |
| `dsm/rekey.py` | Modify | **Only if Fork 7 = YES (Task 2.6):** route rekey INIT/ACK through a paced-enqueue callable instead of direct `send_fn`. |
| `dsm/client.py` | Modify | Pass `clock`/envelope config into `TrafficShaper`/`SendScheduler`; **Fork 7=YES:** wire the paced-enqueue into the rekey path. |
| `dsm/server.py` | Modify | Same as client (symmetry — divergence reintroduces a direction fingerprint; cf. `test_symmetric_shaping.py`). |
| `config.example.toml` | Modify | Document the six `envelope_*` knobs + the idle/tail overhead note. |
| `README.txt` | Modify | Rewrite the ANONYMITY/Chaff/Timing + THREAT MODEL sections to claim EXACTLY what the envelope provides (Task 2.5): active-period smoothing within latency budget; randomized idle floor as residual baseline; chaff fixed-prior sizes; boot-handshake fingerprint as documented accepted v1 risk; TCP caveat unchanged. |
| `tests/test_adaptive_envelope.py` | Create | 2.1: envelope estimator unit tests + paced-release unit tests (simulated clock). |
| `tests/test_chaff_size_prior.py` | Create | 2.3: chaff sizes follow the fixed prior and do NOT track a skewed real-EMA. |
| `tests/test_envelope_statistics.py` | Create | 2.4: SEEDED-clock statistical tests — wire-rate variance bounded under burst; onset not step-detectable at 1 s granularity; idle floor maintained; real-packet latency within budget. |
| `tests/test_envelope_config.py` | Create | 2.4/2.8: config validators for the `envelope_*` fields. |

---

## FLAG FOR OWNER — read before execution

1. **`tests/test_symmetric_shaping.py` is tautological (do NOT edit — FLAG only).** Its three "same support" tests assert that two shapers built with identical config produce the same *size-class support set* (the set of distinct sizes seen over 500 trials). With the Fork-6 fixed-prior chaff this still holds (both ends draw from the same `SIZE_CLASS_WEIGHTS`), so the file should keep passing **unchanged**. However the test is weak — it only checks the *support* (which classes appear), not the *distribution* (how often), so it cannot catch a real direction-asymmetry in frequencies and gives false confidence. Per the review it is tautological. **Decision needed:** leave it as-is (it still passes; new `tests/test_chaff_size_prior.py` adds the distribution assertion it lacks), OR the owner approves strengthening it. The plan does NOT edit it.

2. **`tests/test_shaper.py` couples to envelope internals (do NOT edit — FLAG only).** Several tests assert the *current* additive-Poisson model and WILL conflict with the envelope:
   - `TestRateEMA::test_real_packet_updates_rate` / `test_rate_ema_lags_real_traffic_onset` / `test_ema_alpha_is_small` — assert behavior of `_target_rate_pps` as an EMA of *observed wire rate*. The envelope replaces "EMA of past sends" with "paced target with bounded rise/fall", so these assertions describe a model that no longer exists. They reference `_RATE_EMA_ALPHA`, `_observe_wire_send`, `_target_rate_pps`.
   - `TestPoissonChaffScheduling::*` and `TestNoFixedCadence::*` — assert chaff IPTs are a pure Poisson process at `_target_rate_pps`. Under the envelope, chaff is paced to *fill to the envelope rate*, which is still memoryless-ish but is no longer a free-running Poisson independent of the queue.
   - `test_burst_smoothing_is_permanently_none` — asserts `burst_smoothing_delay()` returns `None` forever. Task 2.1 either makes it real or removes the callsite; either way this assertion's intent (no boundary jitter) is superseded by the envelope.
   - `TestNoModeBoundary::*` (`test_no_idle_threshold_symbol`, `test_shaper_has_no_burst_state`) — assert NO active/idle symbols exist. The envelope is a *single continuous* rate (no active/idle binary), so these SHOULD still pass **if** new state is named to avoid `IDLE_*`/`_ACTIVE_*`/`_chaff_rate_multiplier`/etc. **Constraint for the implementer:** name new envelope state to NOT collide with that banned list, so `TestNoModeBoundary` keeps passing unchanged.

   **What would need to change (described, NOT planned as an edit):** the EMA-model and Poisson-model tests in `test_shaper.py` either need rewriting to assert the envelope's properties or deleting in favor of the new `tests/test_adaptive_envelope.py` + `tests/test_envelope_statistics.py`. **This is a hard stop — bring the conflict list to the owner; the implementer must NOT edit `test_shaper.py` to make it pass.** If the envelope is implemented as a *new* code path while leaving `_target_rate_pps`/`_observe_wire_send` as a now-unused compatibility shim, some of these tests can keep passing — but that leaves dead code (pylint will flag) and is not recommended. The clean path is owner-approved deletion/rewrite of the conflicting `test_shaper.py` classes.

3. **`burst_smoothing_delay()` is on the public API and called from `session.py:1023`.** Removing it requires editing that callsite (in-scope, not a test). The plan removes the `burst_smoothing_delay()`+`asyncio.sleep` interim from `tun_send_loop` because the envelope subsumes it (Task 2.1). `tests/test_shaper.py::test_burst_smoothing_is_permanently_none` references the method — see FLAG 2.

4. **`tests/test_netaudit.py` has a bidirectional repo-grep schema lock (lines ~154–213).** It greps `dsm/` for every `netaudit.emit("…")` literal and asserts the set EXACTLY equals `EXPECTED_EVENT_NAMES`. **If any Phase-2 code adds a new `netaudit.emit("envelope_…")` event, this pre-existing test breaks** (`unexpected = seen - EXPECTED_EVENT_NAMES`). **Decision needed:** the plan deliberately adds NO new netaudit event (the envelope is observable in tests via the injected clock, not via a new audit event), so `test_netaudit.py` needs no edit. If the owner wants an `envelope_change`/`envelope_ceiling_hit` audit event for the two-box pentest replays, that requires editing the pre-existing `test_netaudit.py::EXPECTED_EVENT_NAMES` — a FLAG. **Recommend: no new event in v1.**

5. **Boot-handshake fingerprint (`handshake.py:76`) is an ACCEPTED v1 risk — DOCUMENT, do not fix.** Per the master plan, the fixed-1400 B pre-key frame sequence at establishment is a DSM fingerprint that masking pre-key traffic (post-v1 research) would address. Task 2.5 documents it in the README threat-model rewrite; no code masks it.

---

## DESIGN — the envelope, made explicit

State added to `TrafficShaper` (names chosen to avoid the `test_shaper.py::TestNoModeBoundary` banned list — no `IDLE_*`, no `_ACTIVE_*`, no `_chaff_rate_multiplier`):

- `_envelope_pps: float` — the current target wire rate (real+chaff). Initialized to the per-session randomized idle floor (Fork 4).
- `_idle_floor_pps: float` — drawn once at construction in `[envelope_idle_floor_min_pps, envelope_idle_floor_max_pps]`.
- `_ceiling_pps: float` — `envelope_ceiling_pps` (Fork 3, soft).
- `_rise_per_s: float`, `_fall_half_life_s: float` — Fork 2.
- `_latency_budget_s: float` — Fork 1.
- `_last_release_time: float | None` — last time `release_budget` ran (for dt).
- `_release_credit: float` — fractional-packet accumulator so a slow envelope (<1 pkt/tick) still releases on average the right rate (no per-tick rounding bias).

Two new methods, both O(1) and allocation-free:

```
def update_envelope(self, now, real_queue_depth, oldest_real_age_s):
    # 1. Decay the envelope toward the idle floor (exponential, half-life).
    # 2. If real is queued, the envelope must rise to drain it:
    #      desired = real_queue_depth / latency_budget_s   (pps needed to
    #                clear the queue within the budget)
    #    Raise the envelope toward `desired`, but cap the per-second rise
    #    at `_rise_per_s` (multiplicative) UNLESS the oldest queued real
    #    packet's age exceeds the latency budget, in which case the budget
    #    OVERRIDES the rise cap (raise straight to `desired`, even above
    #    the soft ceiling) so no real packet breaches its budget.
    # 3. Clamp to [_idle_floor_pps, _ceiling_pps] EXCEPT the budget-override
    #    branch may pierce the ceiling.

def release_budget(self, now):
    # dt since last release; credit += _envelope_pps * dt; n = floor(credit);
    # credit -= n; return n  (number of packets the scheduler may emit now).
```

Scheduler change (`_run` loop): per poll, compute `now`, call `shaper.update_envelope(now, len(real_queue), oldest_real_age)` then `n = shaper.release_budget(now)`; emit `n` packets total — pop from the real queue first (respecting each packet's jitter `send_time`), and when the real queue is empty/not-yet-due, fill the remainder with chaff via `chaff_fn`. This replaces both the "drain all due" loop and the "≤1 chaff/poll" cap (`scheduler.py:150`). The jitter on real packets is retained as intra-tick ordering noise but no longer gates *whether* a packet leaves — the envelope does.

**Note on `burst_smoothing_delay()`:** with the envelope, the `tun_send_loop` interim (`smoothing_delay = ...; await asyncio.sleep(...)`, `session.py:1023`) is removed — real packets are paced by the scheduler, not by a one-shot sleep. The method is removed from the callsite; whether to delete the method itself is gated on FLAG 2 (the pre-existing test references it).

---

## Task 2.1 — Envelope estimator + paced release

**Files:** Modify `dsm/traffic/shaper.py`, `dsm/traffic/scheduler.py`, `dsm/session.py`. Create `tests/test_adaptive_envelope.py`.

**Goal:** Introduce the envelope state + `update_envelope`/`release_budget` and make the scheduler envelope-driven, with an injectable clock for determinism.

- [ ] **Step 1 — Write the failing test (envelope unit + paced release, injected clock).** Create `tests/test_adaptive_envelope.py`:

```python
"""Phase 2.1: envelope estimator + paced release (deterministic clock).

These tests drive an injected monotonic clock (no wall-clock sleeps) and
assert the envelope's paced-release contract directly. The CSPRNG is NOT
seedable, so we assert on the DETERMINISTIC pacing math (release_budget),
not on chaff randomness.
"""

from __future__ import annotations

import unittest

from dsm.traffic.shaper import TrafficShaper


class _Clock:
    """Injectable monotonic clock for deterministic pacing tests."""

    def __init__(self, start: float = 1000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


class TestEnvelopeRelease(unittest.TestCase):
    def _shaper(self, clock: _Clock) -> TrafficShaper:
        # Explicit envelope profile so the test is independent of config
        # defaults: floor 1pps, ceiling 100pps, rise x2/s, fall 4s half-life,
        # 250ms budget. (Construction-time floor randomization is pinned by
        # passing equal min/max bounds.)
        return TrafficShaper(
            clock=clock,
            envelope_idle_floor_min_pps=1.0,
            envelope_idle_floor_max_pps=1.0,
            envelope_ceiling_pps=100.0,
            envelope_rise_per_s=2.0,
            envelope_fall_half_life_s=4.0,
            envelope_latency_budget_ms=250,
        )

    def test_idle_release_tracks_floor(self) -> None:
        clk = _Clock()
        s = self._shaper(clk)
        # No real queued: over 10s at 1pps floor, ~10 packets released.
        released = 0
        for _ in range(1000):
            clk.advance(0.01)  # 10ms ticks
            s.update_envelope(clk(), real_queue_depth=0, oldest_real_age_s=0.0)
            released += s.release_budget(clk())
        self.assertAlmostEqual(released, 10, delta=2)

    def test_release_credit_no_rounding_bias(self) -> None:
        # At 1pps with 10ms ticks the per-tick budget is 0.01 pkt — must
        # accumulate via fractional credit, not round to 0 every tick.
        clk = _Clock()
        s = self._shaper(clk)
        total = 0
        for _ in range(500):
            clk.advance(0.01)
            s.update_envelope(clk(), 0, 0.0)
            total += s.release_budget(clk())
        self.assertGreaterEqual(total, 3)  # ~5 expected; never 0

    def test_burst_onset_is_smeared_not_stepped(self) -> None:
        # 200 real packets arrive at t=0 (a burst). With a 2x/s rise cap and
        # a 1pps start, the envelope must NOT jump to drain them in <1 tick:
        # the first 100ms must release far fewer than 200.
        clk = _Clock()
        s = self._shaper(clk)
        depth = 200
        released_first_100ms = 0
        for _ in range(10):  # 10 x 10ms = 100ms
            clk.advance(0.01)
            s.update_envelope(clk(), real_queue_depth=depth, oldest_real_age_s=0.0)
            n = s.release_budget(clk())
            released_first_100ms += n
            depth = max(0, depth - n)
        # Onset smeared: well under half the burst in the first 100ms.
        self.assertLess(released_first_100ms, 50)
        self.assertGreater(depth, 100)

    def test_latency_budget_overrides_rise_cap(self) -> None:
        # A single real packet that has waited past the 250ms budget must be
        # releasable even though the rise cap alone would still be low.
        clk = _Clock()
        s = self._shaper(clk)
        clk.advance(0.30)  # 300ms > 250ms budget
        s.update_envelope(clk(), real_queue_depth=1, oldest_real_age_s=0.30)
        self.assertGreaterEqual(s.release_budget(clk()), 1)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2 — Run, expect failure.** `python3 -m pytest tests/test_adaptive_envelope.py -q` → fails: `TrafficShaper.__init__` has no `clock`/`envelope_*` kwargs; `update_envelope`/`release_budget` don't exist.

- [ ] **Step 3 — Implement the envelope in `dsm/traffic/shaper.py`.** Add the injectable clock and the six envelope params to `__init__` (all keyword, defaulted so existing call sites still work), the per-session idle-floor draw, and the two methods. Real implementation (derived from the current `__init__`/`_schedule_next_chaff` structure):

```python
def __init__(
    self,
    padding_min: int = 128,
    padding_max: int = 1400,
    *,
    clock: Callable[[], float] = time.monotonic,
    envelope_idle_floor_min_pps: float = 0.5,
    envelope_idle_floor_max_pps: float = 2.0,
    envelope_ceiling_pps: float = 600.0,
    envelope_rise_per_s: float = 2.0,
    envelope_fall_half_life_s: float = 4.0,
    envelope_latency_budget_ms: int = 250,
) -> None:
    ...  # existing size-class setup unchanged
    self._clock = clock
    # Per-session randomized idle floor (Fork 4): removes the exact-1pps
    # constant DSM baseline. Fixed for the session lifetime — re-drawing
    # would itself be a time-varying signal.
    lo, hi = envelope_idle_floor_min_pps, envelope_idle_floor_max_pps
    self._idle_floor_pps = lo + csprng_float() * (hi - lo)
    self._ceiling_pps = envelope_ceiling_pps
    self._rise_per_s = envelope_rise_per_s
    self._fall_half_life_s = envelope_fall_half_life_s
    self._latency_budget_s = envelope_latency_budget_ms / 1000.0
    self._envelope_pps = self._idle_floor_pps
    self._last_envelope_time: float | None = None
    self._last_release_time: float | None = None
    self._release_credit = 0.0

def update_envelope(
    self, now: float, real_queue_depth: int, oldest_real_age_s: float
) -> None:
    """Advance the envelope toward the floor (decay) or toward the rate
    needed to drain the real queue within the latency budget (rise)."""
    if self._last_envelope_time is None:
        self._last_envelope_time = now
        return
    dt = now - self._last_envelope_time
    self._last_envelope_time = now
    if dt <= 0:
        return
    if real_queue_depth <= 0:
        # Exponential decay toward the idle floor.
        decay = 0.5 ** (dt / self._fall_half_life_s)
        self._envelope_pps = (
            self._idle_floor_pps
            + (self._envelope_pps - self._idle_floor_pps) * decay
        )
        return
    # Rate needed to clear the queue within the budget.
    desired = real_queue_depth / self._latency_budget_s
    if oldest_real_age_s >= self._latency_budget_s:
        # Budget breach imminent: override the rise cap AND the soft ceiling.
        self._envelope_pps = max(self._envelope_pps, desired)
        return
    # Bounded multiplicative rise (cap per second), clamped to the ceiling.
    max_rise = self._rise_per_s ** dt
    target = min(desired, self._envelope_pps * max_rise, self._ceiling_pps)
    if target > self._envelope_pps:
        self._envelope_pps = target

def release_budget(self, now: float) -> int:
    """Number of packets the scheduler may emit on the wire this tick.

    Fractional-packet credit avoids per-tick rounding bias at low rates.
    """
    if self._last_release_time is None:
        self._last_release_time = now
        return 0
    dt = now - self._last_release_time
    self._last_release_time = now
    if dt <= 0:
        return 0
    self._release_credit += self._envelope_pps * dt
    n = int(self._release_credit)
    self._release_credit -= n
    return n
```

(Import `Callable` from `collections.abc` at the top if not already present.)

- [ ] **Step 4 — Run, expect pass.** `python3 -m pytest tests/test_adaptive_envelope.py -q` → green.

- [ ] **Step 5 — Make the scheduler envelope-driven.** In `dsm/traffic/scheduler.py`: add `clock: Callable[[], float] = time.monotonic` and a `shaper` (or two callables `update_envelope_fn`/`release_budget_fn`) to `__init__`. In `_run`, replace the "drain all due + ≤1 chaff" block with: compute `now`; `oldest_age = now - self._queue[0].send_time` (or 0 if empty); call `update_envelope(now, len(self._queue), max(0, oldest_age))`; `budget = release_budget(now)`; then emit up to `budget` packets — pop due real packets first, then call `chaff_fn` to fill the remainder. Removes the `scheduler.py:150` 1/poll cap. Keep the existing exception handling (`TimeoutError/ConnectionError/OSError` → warning; `Exception` → error+continue) verbatim.

- [ ] **Step 6 — Reconcile `tun_send_loop` (`dsm/session.py`).** Remove the `burst_smoothing_delay()`+`asyncio.sleep` interim (lines ~1023–1025) — the envelope subsumes it. Real packets still go through `ctx.shaper.pad_packet` + `ctx.scheduler.enqueue`; the fragment `extra_delay` spread is kept (it's intra-burst ordering, still useful) but note in the Report that fragment spread now interacts with the envelope's pacing. Keep `observe_real_packet` for the size tracker (real-packet *size* still feeds the SizeTracker used for *padding*; only chaff *size* is decoupled in Task 2.3).

- [ ] **Step 7 — Wire the clock/config through `client.py`/`server.py` (symmetric).** Both construct `TrafficShaper(config.padding_min, config.padding_max, ...)` and `SendScheduler(...)` — pass the new envelope params from config (Task 2.8 adds them) and a shared `clock` (default `time.monotonic` in production; tests inject). Keep client and server identical (divergence reintroduces a direction fingerprint — cf. `test_symmetric_shaping.py`).

- [ ] **Step 8 — Focused gate.** `black dsm/traffic/shaper.py dsm/traffic/scheduler.py dsm/session.py tests/test_adaptive_envelope.py` → `isort` (same) → `ruff check` (same) → `pylint dsm/traffic/shaper.py dsm/traffic/scheduler.py` (expect 10.00; extract helpers if `update_envelope` trips `too-many-branches`) → `pyright` → `python3 -m pytest tests/test_adaptive_envelope.py -q`.

- [ ] **Step 9 — Report.** One line: envelope estimator + paced release landed; scheduler envelope-driven; `burst_smoothing_delay` removed from callsite; note any per-packet cost (should be O(1), no new allocation in the pacing loop) and whether `pylint` needed a helper extraction.

---

## Task 2.2 — Fix the EMA / envelope ceiling-snap on burst (`shaper.py:336`)

**Files:** Modify `dsm/traffic/shaper.py`. Append to `tests/test_adaptive_envelope.py` (effort-created, editable).

**Problem (current `_observe_wire_send`, shaper.py:363–367):** when two sends land in the same monotonic tick (`dt <= 0`) the instantaneous rate is set to `_CHAFF_RATE_CEIL_PPS`, and a tiny `dt` yields `1/dt` huge — a burst snaps the rate to the ceiling within one packet, defeating the slow-lag intent and creating a post-burst chaff tail. Under the envelope (Task 2.1) the *envelope* already rises slowly, but the residual `_observe_wire_send`/`_target_rate_pps` path (if retained as a shim) still has this bug, and the *general* rule — burst onset must not ramp the rate faster than the intended slow envelope — must be enforced.

**Fix:** in the envelope's `update_envelope`, the rise is already capped by `_rise_per_s` (Task 2.1) and a sub-tick `dt` cannot snap it (the `max_rise = _rise_per_s ** dt` term → ~1.0 as dt→0). The remaining work is: (a) **floor `dt`** in `release_budget`/`update_envelope` so a zero/negative monotonic delta can't divide-by-near-zero, and (b) if `_observe_wire_send`/`_target_rate_pps` survive as compatibility shims (FLAG 2), apply the same `dt` floor there. Add a `_MIN_ENVELOPE_DT` (e.g. 1e-4 s) and clamp `dt = max(dt, _MIN_ENVELOPE_DT)` is NOT applied (that would *inflate* rate); instead the methods already early-return on `dt <= 0` — verify and lock that with a test.

- [ ] **Step 1 — Write the failing test.** Append to `tests/test_adaptive_envelope.py`:

```python
class TestNoCeilingSnapOnBurst(unittest.TestCase):
    def test_same_tick_sends_do_not_snap_envelope(self) -> None:
        clk = _Clock()
        s = TrafficShaper(
            clock=clk,
            envelope_idle_floor_min_pps=1.0,
            envelope_idle_floor_max_pps=1.0,
            envelope_ceiling_pps=100.0,
            envelope_rise_per_s=2.0,
            envelope_fall_half_life_s=4.0,
            envelope_latency_budget_ms=250,
        )
        # Many update_envelope calls at the SAME now (dt=0) must not move
        # the envelope at all — no snap-to-ceiling.
        before = s._envelope_pps
        for _ in range(1000):
            s.update_envelope(clk(), real_queue_depth=500, oldest_real_age_s=0.0)
        self.assertEqual(s._envelope_pps, before)

    def test_rise_capped_under_sustained_burst(self) -> None:
        clk = _Clock()
        s = TrafficShaper(
            clock=clk,
            envelope_idle_floor_min_pps=1.0,
            envelope_idle_floor_max_pps=1.0,
            envelope_ceiling_pps=1000.0,
            envelope_rise_per_s=2.0,
            envelope_fall_half_life_s=4.0,
            envelope_latency_budget_ms=10_000,  # huge budget: no override
        )
        # 1s of sustained large queue at a huge latency budget: the rise cap
        # (2x/s) must bound the envelope to ~<= 2x the start, not the ceiling.
        for _ in range(100):
            clk.advance(0.01)
            s.update_envelope(clk(), real_queue_depth=500, oldest_real_age_s=0.0)
        self.assertLessEqual(s._envelope_pps, 1.0 * 2.0 + 0.5)  # ~2pps, not 1000
```

- [ ] **Step 2 — Run, expect failure if the `dt<=0` early-return is missing or the rise cap is wrong.** (If Task 2.1 already implemented both correctly, `test_same_tick...` passes; `test_rise_capped...` is the real lock — run and confirm it discriminates.)

- [ ] **Step 3 — Implement / verify the fix.** Ensure `update_envelope` early-returns on `dt <= 0` (no state mutation) and the rise branch uses `max_rise = self._rise_per_s ** dt`. If a `_target_rate_pps`/`_observe_wire_send` shim is retained, replace the `dt <= 0 → instant = _CHAFF_RATE_CEIL_PPS` branch with an early-return (no EMA update on a zero/negative tick) and floor the EMA-update rate so a sub-millisecond `dt` cannot exceed the configured rise. Document the change with a `# Task 2.2` comment explaining the snap it prevents.

- [ ] **Step 4 — Run, expect pass.** `python3 -m pytest tests/test_adaptive_envelope.py -q`.

- [ ] **Step 5 — Focused gate** (black/isort/ruff/pylint/pyright on `shaper.py` + the test).

- [ ] **Step 6 — Report.** One line: ceiling-snap closed — same-tick sends don't move the envelope; sustained burst is rise-capped, not snapped.

---

## Task 2.3 — Decouple chaff SIZE from the real-traffic EMA → fixed prior (`shaper.py:292`)

**Files:** Modify `dsm/traffic/shaper.py`. Create `tests/test_chaff_size_prior.py`.

**Problem (current `make_chaff`, shaper.py:319):** chaff sizes are sampled from `self._size_tracker.sample_with_idx()` — the SAME EMA that tracks real-traffic sizes. So chaff *mirrors* the user's app profile, and the aggregate (real+chaff) size histogram amplifies it (finding `shaper.py:292`). `SizeTracker` is still the right thing for *padding real packets* (a real packet pads to a class near its actual size), but chaff must NOT track it.

**Fix (Fork 6):** add a fixed-prior sampler to `TrafficShaper` (or a second `SizeTracker` frozen at the published `SIZE_CLASS_WEIGHTS`, never `observe()`d) and have `make_chaff` draw from THAT, not the live EMA. Keep the ±1-class perturbation on top of the fixed prior. The live `SizeTracker` continues to drive `pad_packet` for real packets only.

- [ ] **Step 1 — Write the failing test.** Create `tests/test_chaff_size_prior.py`:

```python
"""Phase 2.3: chaff sizes follow a FIXED published prior, not the live
real-traffic size EMA (fix for shaper.py:292 — aggregate-histogram leak).

The CSPRNG is not seedable, so we assert on the size-class *distribution*
with generous statistical bounds over many samples.
"""

from __future__ import annotations

import asyncio
import collections
import unittest

from dsm.core.protocol import SIZE_CLASSES, InnerPacket, PacketType
from dsm.traffic.shaper import TrafficShaper, make_chaff_packet


def _chaff_size_hist(shaper: TrafficShaper, n: int) -> collections.Counter:
    async def _run() -> collections.Counter:
        c: collections.Counter = collections.Counter()
        for _ in range(n):
            _, target = await make_chaff_packet(shaper, epoch_id=0)
            c[target] += 1
        return c

    return asyncio.run(_run())


class TestChaffSizeFixedPrior(unittest.TestCase):
    def test_chaff_size_does_not_track_skewed_real_traffic(self) -> None:
        shaper = TrafficShaper(128, 1400)
        # Hammer the real-size EMA hard toward the LARGEST class only.
        for _ in range(2000):
            shaper.observe_real_packet(1400)
        hist = _chaff_size_hist(shaper, 4000)
        # If chaff tracked the real EMA, ~all chaff would be 1400. With the
        # fixed prior, the smallest class (128, prior weight 20/100) must
        # still appear frequently — assert it is a meaningful fraction.
        smallest = SIZE_CLASSES[0]
        self.assertGreater(
            hist[smallest] / 4000,
            0.05,
            "chaff still tracks the real-size EMA — fixed prior not applied",
        )

    def test_chaff_size_support_is_all_classes(self) -> None:
        shaper = TrafficShaper(128, 1400)
        hist = _chaff_size_hist(shaper, 5000)
        for sc in SIZE_CLASSES:
            self.assertIn(sc, hist)
```

- [ ] **Step 2 — Run, expect failure.** `test_chaff_size_does_not_track_skewed_real_traffic` fails: chaff currently follows the EMA, so after 2000×1400 observations the smallest class is ~never produced.

- [ ] **Step 3 — Implement the fixed prior.** Add a frozen prior sampler. Minimal approach: construct a second `SizeTracker` over the active classes that is NEVER `observe()`d — but note `SizeTracker.__init__` already seeds from `SIZE_CLASS_WEIGHTS` when `classes == SIZE_CLASSES`; for filtered active classes it falls back to uniform. Cleaner: add `_chaff_size_prior` weights = the published `SIZE_CLASS_WEIGHTS` restricted+renormalized to `self._active_classes`, and a `_sample_chaff_size()` that samples from those fixed weights (reuse the cumulative-scan from `SizeTracker.sample_with_idx`). In `make_chaff`, replace `size_class, idx = self._size_tracker.sample_with_idx()` with `size_class, idx = self._sample_chaff_size()`. Keep the ±1 perturbation block verbatim. Add a `# Task 2.3` comment: chaff sizes are target-independent so the aggregate histogram trends to the published prior, not the user's app profile.

- [ ] **Step 4 — Run, expect pass.** `python3 -m pytest tests/test_chaff_size_prior.py -q`.

- [ ] **Step 5 — Cross-check symmetric shaping still holds.** Run the pre-existing `python3 -m pytest tests/test_symmetric_shaping.py -q` — it must still pass UNCHANGED (both ends draw chaff from the same fixed prior → same support). If it fails, STOP and FLAG (do not edit it).

- [ ] **Step 6 — Focused gate** (black/isort/ruff/pylint/pyright on `shaper.py` + new test).

- [ ] **Step 7 — Report.** One line: chaff sizes now drawn from the fixed published prior (`SIZE_CLASS_WEIGHTS`), decoupled from the real-size EMA; `test_symmetric_shaping.py` still green unchanged.

---

## Task 2.4 — SEEDED statistical tests (the discriminators)

**Files:** Create `tests/test_envelope_statistics.py`. (No production code unless a test surfaces a bug — if it does, that's a fix in `shaper.py`/`scheduler.py`, never a test edit.)

**Goal:** Deterministic statistical tests that genuinely discriminate *burst-visible* from *burst-hidden*. Determinism comes from the **injected clock** + recording wire-emission timestamps and asserting on the deterministic pacing math (the CSPRNG affects only chaff *content/size*, not the *count* the envelope releases — `release_budget` is RNG-free). The key discriminator: feed a **step-function** real-traffic input and assert the wire-rate timeseries does NOT show a corresponding step within 1 s (the envelope smears it). Bounds are generous so the tests are not flaky, but tight enough that the *current additive model would FAIL them* (sanity-check that during review).

- [ ] **Step 1 — Write the discriminating tests.** Create `tests/test_envelope_statistics.py`:

```python
"""Phase 2.4: deterministic statistical discriminators for the envelope.

Determinism: an injected monotonic clock drives all pacing; release_budget
is RNG-free, so the per-tick wire counts are fully reproducible. We build a
'wire rate timeseries' by bucketing released-packet counts into 1s bins and
assert the envelope HIDES a real-traffic step (the additive model would
expose it).
"""

from __future__ import annotations

import unittest

from dsm.traffic.shaper import TrafficShaper


class _Clock:
    def __init__(self, start: float = 5000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt


def _simulate(
    real_arrivals_per_tick,  # list[int]: real packets arriving each 10ms tick
    *,
    ceiling_pps: float = 600.0,
    floor_pps: float = 1.0,
    rise_per_s: float = 2.0,
    budget_ms: int = 250,
    tick_s: float = 0.01,
) -> list[int]:
    """Drive the envelope tick-by-tick; return packets released per tick."""
    clk = _Clock()
    s = TrafficShaper(
        clock=clk,
        envelope_idle_floor_min_pps=floor_pps,
        envelope_idle_floor_max_pps=floor_pps,
        envelope_ceiling_pps=ceiling_pps,
        envelope_rise_per_s=rise_per_s,
        envelope_fall_half_life_s=4.0,
        envelope_latency_budget_ms=budget_ms,
    )
    queue = 0
    oldest_age = 0.0
    released_per_tick: list[int] = []
    for arrivals in real_arrivals_per_tick:
        clk.advance(tick_s)
        queue += arrivals
        oldest_age = oldest_age + tick_s if queue > 0 else 0.0
        # Exactly ONE update_envelope + ONE release_budget per tick.
        s.update_envelope(clk(), real_queue_depth=queue, oldest_real_age_s=oldest_age)
        n = s.release_budget(clk())  # the wire count this tick (real + chaff fill)
        real_sent = min(n, queue)  # real drains first; chaff fills the rest
        queue -= real_sent
        if queue == 0:
            oldest_age = 0.0
        released_per_tick.append(n)
    return released_per_tick


def _per_second(released_per_tick: list[int], ticks_per_s: int = 100) -> list[int]:
    return [
        sum(released_per_tick[i : i + ticks_per_s])
        for i in range(0, len(released_per_tick), ticks_per_s)
    ]


class TestEnvelopeHidesBurstOnset(unittest.TestCase):
    def test_step_input_is_not_a_wire_step_within_1s(self) -> None:
        # 5s idle, then a hard step: 50 real pkts/tick (5000pps) for 5s.
        idle = [0] * 500
        burst = [50] * 500
        released = _simulate(idle + burst)
        per_s = _per_second(released)
        # The real input steps from ~0 to ~5000pps at second 5. The WIRE
        # rate must NOT step to ~5000 in the first burst-second: the rise
        # cap (2x/s from ~1pps) keeps second-6 well under 1000.
        idle_secs = per_s[:5]
        first_burst_sec = per_s[5]
        self.assertLess(
            max(idle_secs) + 10,
            first_burst_sec,
            "sanity: some rise expected",
        )
        self.assertLess(
            first_burst_sec,
            1000,
            f"burst onset leaked: wire jumped to {first_burst_sec} pps in 1s "
            "(additive model would show ~5000) — envelope failed to smear",
        )

    def test_wire_rate_variance_bounded_under_burst(self) -> None:
        # Under a steady burst the per-second wire rate must vary SMOOTHLY
        # (bounded second-over-second delta), never a step.
        burst = [20] * 1500  # 15s steady
        per_s = _per_second(_simulate(burst))
        deltas = [abs(per_s[i + 1] - per_s[i]) for i in range(len(per_s) - 1)]
        # No single second more than doubles the previous (rise cap = 2x/s),
        # plus a small additive slack for credit rounding.
        for i in range(1, len(per_s)):
            self.assertLessEqual(per_s[i], per_s[i - 1] * 2 + 5)


class TestIdleFloorMaintained(unittest.TestCase):
    def test_idle_floor_never_drops_to_zero(self) -> None:
        released = _simulate([0] * 2000, floor_pps=1.0)
        per_s = _per_second(released)
        for sec in per_s[2:]:  # allow 2s warmup
            self.assertGreaterEqual(sec, 1, "idle floor collapsed — no cover traffic")


class TestRealPacketLatencyWithinBudget(unittest.TestCase):
    def test_no_real_packet_exceeds_budget(self) -> None:
        # Track the worst-case age at which a real packet is finally released.
        clk = _Clock()
        s = TrafficShaper(
            clock=clk,
            envelope_idle_floor_min_pps=1.0,
            envelope_idle_floor_max_pps=1.0,
            envelope_ceiling_pps=600.0,
            envelope_rise_per_s=2.0,
            envelope_fall_half_life_s=4.0,
            envelope_latency_budget_ms=250,
        )
        queue_ages: list[float] = []  # age of each queued packet
        worst = 0.0
        # A burst of 300 packets at t=0, then idle; budget override must
        # drain the oldest before it exceeds 250ms by much.
        pending = 300
        for tick in range(400):  # 4s
            clk.advance(0.01)
            queue_ages = [a + 0.01 for a in queue_ages]
            if tick == 0:
                queue_ages.extend([0.0] * pending)
            oldest = max(queue_ages) if queue_ages else 0.0
            s.update_envelope(clk(), real_queue_depth=len(queue_ages), oldest_real_age_s=oldest)
            n = s.release_budget(clk())
            for _ in range(min(n, len(queue_ages))):
                worst = max(worst, queue_ages.pop(0))  # FIFO oldest first
        # Generous bound: budget is 250ms; one override tick (~10ms) of slop.
        self.assertLess(worst, 0.30, f"a real packet waited {worst*1000:.0f}ms > budget")
```

> **Implementer note (load-bearing):** `release_budget` advances `_last_release_time` on every call, so it MUST be called **exactly once per tick** — the `_simulate` helper above does this (one `update_envelope` then one `release_budget`, appending the returned `n`). Do NOT add a second `release_budget` call per tick (e.g. to recompute the wire count) — that would advance the clock-state twice and halve the observed rate. Verify each method is called once per tick before relying on the assertions.

- [ ] **Step 2 — Run, expect pass against the Task-2.1 envelope.** `python3 -m pytest tests/test_envelope_statistics.py -q`.

- [ ] **Step 3 — Discriminator sanity check (review-time, no code).** Confirm the tests genuinely discriminate: reason through (and note in the Report) that the *additive* model (release real immediately) would make `first_burst_sec ≈ 5000` and FAIL `test_step_input_is_not_a_wire_step_within_1s`. If a test passes for BOTH the additive and envelope models, it is not a real discriminator — tighten it. This is the core deliverable: the test must catch "burst onset is visible".

- [ ] **Step 4 — Focused gate** (black/isort/ruff on the test; pyright; pytest).

- [ ] **Step 5 — Report.** One line: deterministic statistical suite green; confirm each test discriminates burst-visible from burst-hidden (the additive model would fail the step test); note worst-case observed real-packet latency vs the 250 ms budget.

---

## Task 2.8 — Envelope config knobs + validators (Fork 8)

> Numbered 2.8 to match the fork; execute BEFORE 2.1's Step 7 wiring needs them, or stub the config defaults in 2.1 and land this in parallel. Recommended order: 2.8 first so `client.py`/`server.py` can read real config.

**Files:** Modify `dsm/core/config.py`, `config.example.toml`. Create `tests/test_envelope_config.py`.

- [ ] **Step 1 — Write the failing config test.** Create `tests/test_envelope_config.py` asserting: (a) a `Config` with no envelope fields gets the documented defaults (back-compat); (b) out-of-range values raise `ValueError` (e.g. `envelope_latency_budget_ms = 0`, `envelope_rise_per_s = 1.0` [must be > 1 to rise], `envelope_ceiling_pps` below the idle-floor max, `envelope_idle_floor_min_pps > envelope_idle_floor_max_pps`). Mirror the existing `_validate_jitter`/`_validate_padding` test style (construct `Config(**fixture)` and assert the message). Use a minimal valid client fixture (cf. `tests/test_config.py` patterns — read it, do NOT edit it).

- [ ] **Step 2 — Run, expect failure** (fields don't exist).

- [ ] **Step 3 — Add the fields + validator.** In `dsm/core/config.py` add the six `envelope_*` fields to the frozen `Config` dataclass with the recommended defaults (Fork 8), a `_validate_envelope(c)` in the `_VALIDATORS` tuple (placed after `_validate_jitter` to keep the stable order), and add the new int fields to `_validate_types`'s `int_fields` / float fields list. Constraints: `latency_budget_ms` in `[10, 5000]`; `rise_per_s` in `(1.0, 100.0]`; `fall_half_life_s` in `(0, 60]`; `ceiling_pps` in `[idle_floor_max, 100000]`; `0 < idle_floor_min <= idle_floor_max <= 1000`. `raise ValueError(...) from None`/`from e` per the module's style.

- [ ] **Step 4 — Document in `config.example.toml`.** Add the six knobs with the overhead note (idle overhead ≈ floor_pps × ~900 B; burst tail ≈ fall_half_life). Keep it boot-as-shipped (Phase 1.12 invariant).

- [ ] **Step 5 — Run, expect pass.** `python3 -m pytest tests/test_envelope_config.py -q`; also run `tests/test_config.py` (pre-existing) to confirm no regression — must pass UNCHANGED.

- [ ] **Step 6 — Focused gate** (black/isort/ruff/pylint/pyright on `config.py`; pytest).

- [ ] **Step 7 — Report.** One line: six `envelope_*` config knobs added with validators + example docs; `test_config.py` green unchanged.

---

## Task 2.5 — README threat-model rewrite (claim EXACTLY what holds)

**Files:** Modify `README.txt` (ANONYMITY AND TRAFFIC RESISTANCE + THREAT MODEL sections). No test (documentation).

**Goal:** Replace the now-false claims with precise ones matching the envelope. The current text (README.txt §148–166) describes "Active mode / Idle mode" multipliers and "size distribution mirrors observed real traffic" — both now wrong.

- [ ] **Step 1 — Rewrite the Chaff/Timing subsections** to state:
  - **Adaptive envelope:** the wire rate is a slowly-varying target ("envelope") independent of instantaneous real volume; real packets are paced into the envelope and chaff fills the gap when real < envelope.
  - **Burst onset is smeared** over seconds (bounded rise rate), hiding short-term volume and burst onset from a passive observer — *within a configurable per-packet latency budget* (default 250 ms): a real packet is never delayed more than the budget, so a sustained burst that would exceed the budget DOES eventually raise the wire rate (the residual: very long sustained transfers are visible as a higher steady rate, just not as an onset step).
  - **Chaff sizes** are drawn from a FIXED published size-class prior, so the aggregate (real+chaff) size histogram trends to a fleet-wide constant rather than the user's app profile.
  - **Idle floor:** a low, per-session-randomized chaff floor (default ~0.5–2 pps) keeps cover traffic flowing when idle — note this is a residual steady-baseline (the *presence* of DSM cover traffic is detectable; its exact cadence is randomized per session). State the idle overhead (~0.5–2 kB/s).

- [ ] **Step 2 — State the residuals/accepted risks explicitly in THREAT MODEL:**
  - **Boot-handshake fingerprint (accepted v1 risk):** the establishment exchange emits a fixed-size pre-key frame sequence (`handshake.py`) that is NOT covered by the envelope (the envelope only governs post-key data traffic). A passive observer can fingerprint DSM *session establishment*. Masking pre-key traffic is post-v1 research. (Per master-plan owner decision.)
  - **TCP caveat (unchanged, keep/relocate):** TCP is obfuscation-only against simple DPI; the TCP SYN/FIN/RST handshake+teardown fingerprint and connection-establishment pattern are visible to passive traffic analysis. Reach for TCP only when UDP is blocked.
  - **Latency-budget residual:** sustained high-rate real traffic raises the steady wire rate (volume over many seconds is not hidden — only onset and short-term volume within the budget are).
  - **Packet-rate (not byte-rate) envelope (Fork 5):** the envelope paces packets, not bytes; residual byte-rate signal is bounded by the shared size prior but not eliminated.

- [ ] **Step 3 — Remove the stale "Active mode / Idle mode multiplier / mirrors observed real traffic" lines** (README.txt §157–162) — they describe the deleted model.

- [ ] **Step 4 — Self-check.** Re-read the rewritten section against the implemented behavior (Tasks 2.1–2.3) — every claim must be backed by code or a documented residual. No claim of "no observable boundary" for active traffic (that was the false H8 claim); the precise claim is "burst onset and short-term volume are hidden within the latency budget."

- [ ] **Step 5 — Report.** One line: README anonymity + threat-model rewritten to match the envelope; boot-handshake fingerprint + TCP + latency-budget + pps-envelope residuals documented as accepted v1 risks.

---

## Task 2.6 — Control-plane packets through the envelope (ONLY if Fork 7 = YES)

**Files:** Modify `dsm/rekey.py`, `dsm/session.py`, `dsm/client.py`, `dsm/server.py`. Append to `tests/test_adaptive_envelope.py` (effort-created) OR a small new `tests/test_control_plane_paced.py`.

**Goal:** Route rekey INIT/ACK and normal-operation SESSION_CLOSE through the paced scheduler so their timing matches the steady stream (finding `rekey.py:64`). Teardown SESSION_CLOSE keeps the direct bounded send (scheduler already stopped).

> **DROP THIS TASK if Fork 7 = "leave out-of-band".** In that case Task 2.5 documents control-plane timing as a residual instead.

**Retrofit complexity (why this is the riskiest fork):** rekey helpers (`dsm/rekey.py`) currently call `send_fn` directly (`_send_rekey_packet` → `await send_fn(...)`). The scheduler's `enqueue` is fire-and-forget (no await of actual send), but rekey's send sites are bounded with `asyncio.wait_for(..., 5.0)` and some depend on the packet actually leaving (e.g. ACK retransmit). Routing through the scheduler changes the timing contract (paced, up to one latency budget) and the bounded-await semantics. The cleanest seam: pass a `paced_send: Callable[[bytes, int], None]` (= `scheduler.enqueue`) into the rekey helpers ALONGSIDE the direct `send_fn`, and use `paced_send` for INIT/ACK while keeping the direct path for the duplicate-ACK retransmit timeout-bounded case. **This needs careful review** — get owner sign-off on the exact carve-outs.

- [ ] **Step 1 — Write the failing test.** Assert that a rekey INIT enqueues through the scheduler (paced) rather than calling `send_fn` directly: construct a scheduler with a recording `send_fn` and a fake clock, trigger `initiate_rekey` with a `paced_send=scheduler.enqueue`, advance the clock past the envelope budget, and assert the INIT appears on the wire via the paced path (not before the envelope releases it).

- [ ] **Step 2 — Run, expect failure** (rekey calls `send_fn` directly today).

- [ ] **Step 3 — Implement the paced seam.** Add an optional `paced_send` param to `_send_rekey_packet`/`initiate_rekey`/`handle_rekey_init`/`resend_rekey_init`; when provided, INIT/ACK go through `paced_send` (which pads + enqueues). Keep `send_fn` for the timeout-bounded duplicate-ACK retransmit (it must be observable within 5 s). Update `_build_control_packet`/`send_session_close`: normal-operation SESSION_CLOSE (if any path sends it outside teardown) goes paced; the teardown `finally` path keeps the direct bounded send. Wire `paced_send=scheduler.enqueue` from `client.py`/`server.py` into the rekey call sites (via `RekeyState`/`DataPathContext` or an added param).

- [ ] **Step 4 — Run, expect pass.** Re-run the new test + `tests/test_rekey_*.py` (pre-existing, must pass UNCHANGED — if a pre-existing rekey test breaks because of the timing change, STOP and FLAG; do not edit it).

- [ ] **Step 5 — Focused gate** (black/isort/ruff/pylint/pyright on rekey.py + session.py; pytest the rekey + envelope suites).

- [ ] **Step 6 — Report.** One line: rekey INIT/ACK + normal SESSION_CLOSE routed through the envelope; teardown close keeps the direct bounded send; pre-existing rekey tests green unchanged (or FLAG if not).

---

## Phase exit gate

- `black` → `isort` → `ruff` → `pylint` (10.00 on `shaper.py`, `scheduler.py`, `config.py`; `session.py` keeps its `too-many-lines` disable) → `pyright` (strict, 0 errors) → `python3 -m pytest tests/ -q` (full suite green; new envelope tests + ALL pre-existing tests — any pre-existing failure that isn't a FLAGGED-and-approved conflict is a STOP).
- Statistical suite (`tests/test_envelope_statistics.py`) green AND deterministic (run 3×, identical results — the injected clock guarantees this).
- Security re-review pass on the diff (the change is anonymity-critical): confirm the envelope actually decouples wire rate from real volume and the README claims match code.
- Documented claims match a netns capture (per master-plan Phase-2 gate) — a manual two-box check that the wire rate under a real burst does not step at 1 s granularity.

---

## Retrofit risks (so the orchestrator knows before execution)

1. **`test_shaper.py` model coupling (FLAG 2) is the biggest blocker.** ~10 tests assert the additive-Poisson EMA model. The envelope replaces that model; those tests cannot pass against the new code. The clean path requires owner-approved deletion/rewrite of `TestRateEMA`, `TestPoissonChaffScheduling`, `TestNoFixedCadence`, and `test_burst_smoothing_is_permanently_none` in `test_shaper.py`. Until approved, the implementer must NOT touch them — which means the full-suite gate will show those as failing. **The orchestrator must resolve FLAG 2 with the owner before Task 2.1 lands**, otherwise the phase gate can't go green.
2. **`_target_rate_pps`/`_observe_wire_send`/`should_send_chaff`/`make_chaff_packet`'s `observe_chaff_packet` form the current public-ish surface** used by `client.py`/`server.py` (`should_chaff_fn=shaper.should_send_chaff`, `chaff_fn=make_chaff_packet`). The envelope changes how chaff is *triggered* (scheduler asks for a budget, not `should_send_chaff()` per poll). Decide whether `should_send_chaff` is removed (cleaner) or kept as a now-unused shim (dead code, pylint flag). Recommend removing it and updating the two call sites — but that's a `client.py`/`server.py` edit, in scope.
3. **Rekey-through-envelope (Fork 7 / Task 2.6)** has the widest blast radius: `dsm/rekey.py`'s direct `send_fn` contract is bounded-await; pacing changes it. Highest chance of breaking a pre-existing `test_rekey_*` timing assumption (→ FLAG). If the owner is risk-averse, take Fork 7 = NO for v1 and document the residual.
4. **`SendScheduler` jitter vs envelope:** the per-packet jitter (`enqueue` adds 1–100 ms) and the per-poll jitter (30–70 ms) now interact with the envelope's release budget. The envelope governs *count*; jitter governs *intra-tick ordering*. Verify they compose (a packet's jitter `send_time` should not let it leave *before* the envelope budget allows). Low risk but must be checked in Task 2.1 Step 5.
5. **Fragment spread (`session.py:1047`, `extra_delay`)** was designed against the old immediate-release model. Under pacing, fragments already queue; the `extra_delay` may now be redundant or double-counted. Reconcile in Task 2.1 Step 6 (keep it as ordering noise; confirm it doesn't fight the envelope).
