//! Tier shaper core: decides WHEN packets leave and HOW BIG they are.
//!
//! Packets leave at a steady rate that only changes in a few fixed steps
//! ("tiers"). Real packets take free slots; the caller fills the rest with
//! chaff. Apart from decoys, the rate steps up when real packets have
//! waited past a random point inside the latency budget, or when real
//! packets have filled nearly all of the tier for a few seconds. It steps
//! down slowly (holds of about 1-5 minutes, a usage check, an optional
//! linger before idle). Decoys are fake backlogs: they climb to a target
//! tier through the exact same step-up path, then hold a fake busy stretch.
//! A full tier starts the same climb as a decoy aimed one tier up, so the
//! two look alike. Each session draws its own secret timing values and
//! draws them again now and then.
//!
//! Plain Rust with no Python types; the PyO3 wrapper lives in `lib.rs`.
//! Secret values have no getters and never appear in `Debug` output.

use std::collections::VecDeque;
use std::fmt;

use rand::rngs::StdRng;
use rand::{CryptoRng, Rng, RngCore, SeedableRng};

/// Padded outer packet sizes in bytes: the fixed, published size list.
pub const SIZE_CLASSES: [u16; 11] = [128, 256, 384, 512, 640, 768, 896, 1024, 1152, 1280, 1400];
/// Draw weights for [`SIZE_CLASSES`], same order (smaller packets likelier).
pub const SIZE_CLASS_WEIGHTS: [u16; 11] = [20, 15, 12, 10, 8, 7, 6, 6, 5, 6, 5];
/// Chaff sizing: a draw below this moves the class one up.
pub const CHAFF_PERTURB_UP_P: f64 = 0.15;
/// Chaff sizing: a draw from `CHAFF_PERTURB_UP_P` up to this moves it one down.
pub const CHAFF_PERTURB_DOWN_P: f64 = 0.30;
/// How far from zero a clock value (s) may be: one billion seconds, about
/// 31 years of uptime. Far below where float rounding would stall the slot
/// loop, even at the fastest allowed tier (5000 packets/s).
pub const MAX_CLOCK_S: f64 = 1.0e9;

const LARGEST_CLASS: u16 = SIZE_CLASSES[SIZE_CLASSES.len() - 1];
/// Bytes a padded packet needs beyond its payload: outer header (20) +
/// GCM tag (16) + inner header (4). Mirrors `dsm.core.protocol`.
const PACKET_OVERHEAD: usize = 40;

/// A poll more than this many seconds behind the schedule is a stall: the
/// missed slots are skipped instead of sent as a burst.
const STALL_RESET_S: f64 = 1.0;
/// Secret values are drawn again after a uniform wait in this range (s).
const REPICK_S: (f64, f64) = (600.0, 2400.0);
/// The step-up point is a fresh fraction of the latency budget per step.
const STEP_UP_FRACTION: (f64, f64) = (0.5, 1.0);
/// Real-sent counts closer together than this (s) share one log entry.
const USAGE_BUCKET_S: f64 = 0.1;
/// The same for the full-tier check, which needs a finer clock: at most
/// 1% of its shortest window.
const FILL_BUCKET_S: f64 = 0.01;
/// Slack for the step-up comparison. A real backlog's start is recomputed
/// as `now - oldest_wait` at every poll, so float rounding can put the
/// step-up time a hair after the wake meant for it; without slack that
/// would re-poll at the same instant.
const STEP_UP_SLACK_S: f64 = 1e-6;

// Secret value ranges.
const TIER_SCALE: (f64, f64) = (0.8, 1.2);
const GAP_SPREAD: (f64, f64) = (0.3, 0.7);
const OVERSHOOT_P: (f64, f64) = (0.2, 0.5);
const HOLD_MIN_S: (f64, f64) = (45.0, 75.0);
const HOLD_MAX_S: (f64, f64) = (240.0, 360.0);
const DECOY_TOP_P: (f64, f64) = (0.5, 0.8);
const LOOKBACK_S: (f64, f64) = (5.0, 15.0);
const USAGE_LIMIT: (f64, f64) = (0.35, 0.65);
/// log2 of the decoy-mean factor: x0.5 to x2.0, centred on x1.0.
const DECOY_MEAN_LOG2: (f64, f64) = (-1.0, 1.0);
const BUSY_MEAN_S: (f64, f64) = (60.0, 360.0);
/// Full tier: the share of the tier's slots real packets must take...
const FILL_LIMIT: (f64, f64) = (0.85, 0.95);
/// ...over this many seconds, all at the current tier.
const FILL_WINDOW_S: (f64, f64) = (1.0, 3.0);
/// Step down also when real use is at most this share of the lower tier:
/// it fits there with room to spare. Below `FILL_LIMIT.0`, so a steady
/// stream that stepped down does not fill the lower tier and climb back.
const FIT_LIMIT: (f64, f64) = (0.5, 0.7);

// Config rules (the same limits dsm/core/config.py enforces).
const TIER_COUNT: (usize, usize) = (2, 8);
const TIER_PPS: (f64, f64) = (1.0, 5000.0);
const BUDGET_S: (f64, f64) = (0.01, 5.0);
const DECOY_INTERVAL_S: (f64, f64) = (300.0, 86_400.0);
const MAX_LINGER_S: f64 = 7200.0;

/// Public shaper settings, taken from the config file. Not secret.
#[derive(Clone, Debug, PartialEq)]
pub struct ShaperConfig {
    /// Tier rates in packets per second: 2 to 8 entries, strictly rising.
    pub tiers_pps: Vec<f64>,
    /// How long a real packet may wait before the rate steps up (s).
    pub latency_budget_s: f64,
    /// Average time between decoys (s); 0 turns decoys off.
    pub decoy_interval_s: f64,
    /// Range for the stay at tier 1 before idle (s); (0, 0) turns it off.
    pub linger_s: (f64, f64),
    /// Smallest padded size a packet may get (bytes).
    pub padding_min: u16,
    /// Largest padded size a packet may get (bytes).
    pub padding_max: u16,
}

impl ShaperConfig {
    fn validate(&self) -> Result<(), ShaperError> {
        let tiers = &self.tiers_pps;
        let count_ok = (TIER_COUNT.0..=TIER_COUNT.1).contains(&tiers.len());
        let values_ok = tiers.iter().all(|t| (TIER_PPS.0..=TIER_PPS.1).contains(t));
        let rising = tiers.windows(2).all(|w| w[0] < w[1]);
        if !(count_ok && values_ok && rising) {
            return Err(ShaperError::Tiers);
        }
        if !(BUDGET_S.0..=BUDGET_S.1).contains(&self.latency_budget_s) {
            return Err(ShaperError::LatencyBudget);
        }
        // The longest gap at tier 0 must end before the earliest step-up
        // point, or a lone real packet could step the rate up and so move
        // the send times. As a rate: tier 0 must be above this minimum.
        // dsm/core/config.py checks the same rule with the same arithmetic.
        let min_tier0 =
            (1.0 + GAP_SPREAD.1) / (TIER_SCALE.0 * STEP_UP_FRACTION.0 * self.latency_budget_s);
        if tiers[0] <= min_tier0 {
            return Err(ShaperError::IdleTooSlow);
        }
        let d = self.decoy_interval_s;
        if !(d == 0.0 || (DECOY_INTERVAL_S.0..=DECOY_INTERVAL_S.1).contains(&d)) {
            return Err(ShaperError::DecoyInterval);
        }
        let (lo, hi) = self.linger_s;
        let off = lo == 0.0 && hi == 0.0;
        if !(off || (lo > 0.0 && lo <= hi && hi <= MAX_LINGER_S)) {
            return Err(ShaperError::Linger);
        }
        if self.padding_min > self.padding_max {
            return Err(ShaperError::Padding);
        }
        Ok(())
    }
}

/// Why [`Shaper::new`] refused to start: a [`ShaperConfig`] rule was broken,
/// or (`Clock`) the start time was not a finite number or was more than
/// [`MAX_CLOCK_S`] from zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShaperError {
    Tiers,
    LatencyBudget,
    /// The first tier is too slow for the latency budget.
    IdleTooSlow,
    DecoyInterval,
    Linger,
    Padding,
    Clock,
}

impl fmt::Display for ShaperError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tiers => {
                "tiers_pps must have 2-8 entries, each 1-5000 packets/s, strictly rising"
            }
            Self::LatencyBudget => "latency_budget_s must be 0.01-5.0",
            Self::IdleTooSlow => {
                "tiers_pps[0] is too slow for latency_budget_s: its longest gap must end \
                 before the earliest step-up point"
            }
            Self::DecoyInterval => "decoy_interval_s must be 0 (off) or 300-86400",
            Self::Linger => "linger_s must be (0, 0) (off) or 0 < min <= max <= 7200",
            Self::Padding => "padding_min must not exceed padding_max",
            Self::Clock => "now must be a number of seconds between minus and plus one billion",
        })
    }
}

impl std::error::Error for ShaperError {}

/// What the caller should do now.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Poll {
    /// Packets to send now: real ones first, chaff for the rest.
    pub slots_due: u32,
    /// When to poll again, on the same clock as `now`.
    pub next_wake: f64,
}

/// Per-session secret timing values. No getters, no `Debug`.
struct Secrets {
    tier_scale: f64,
    gap_spread: f64,
    overshoot_p: f64,
    hold_min_s: f64,
    hold_max_s: f64,
    decoy_top_p: f64,
    lookback_s: f64,
    usage_limit: f64,
    decoy_mean_s: f64,
    busy_mean_s: f64,
    fill_limit: f64,
    fill_window_s: f64,
    fit_limit: f64,
}

impl Secrets {
    fn draw<R: Rng + ?Sized>(rng: &mut R, decoy_interval_s: f64) -> Self {
        Self {
            tier_scale: uniform(rng, TIER_SCALE),
            gap_spread: uniform(rng, GAP_SPREAD),
            overshoot_p: uniform(rng, OVERSHOOT_P),
            hold_min_s: uniform(rng, HOLD_MIN_S),
            hold_max_s: uniform(rng, HOLD_MAX_S),
            decoy_top_p: uniform(rng, DECOY_TOP_P),
            lookback_s: uniform(rng, LOOKBACK_S),
            usage_limit: uniform(rng, USAGE_LIMIT),
            decoy_mean_s: decoy_interval_s * uniform(rng, DECOY_MEAN_LOG2).exp2(),
            busy_mean_s: uniform(rng, BUSY_MEAN_S),
            fill_limit: uniform(rng, FILL_LIMIT),
            fill_window_s: uniform(rng, FILL_WINDOW_S),
            fit_limit: uniform(rng, FIT_LIMIT),
        }
    }
}

fn uniform<R: Rng + ?Sized>(rng: &mut R, (lo, hi): (f64, f64)) -> f64 {
    lo + (hi - lo) * rng.gen::<f64>()
}

/// Exponential wait with the given mean: `-mean * ln(u)` with `u` in (0, 1].
fn exponential<R: Rng + ?Sized>(rng: &mut R, mean: f64) -> f64 {
    -mean * (1.0 - rng.gen::<f64>()).ln()
}

/// Add `n` real packets sent at `now` to a (time, count) log: counts less
/// than `bucket` seconds apart share an entry, and entries more than `keep`
/// seconds old are dropped.
fn add_to_log(log: &mut VecDeque<(f64, u32)>, now: f64, n: u32, bucket: f64, keep: f64) {
    if n > 0 {
        match log.back_mut() {
            Some((t, count)) if now - *t < bucket => *count = count.saturating_add(n),
            _ => log.push_back((now, n)),
        }
    }
    while log.front().is_some_and(|(t, _)| now - *t > keep) {
        log.pop_front();
    }
}

fn class_weight(class: u16) -> f64 {
    SIZE_CLASSES
        .iter()
        .position(|&c| c == class)
        .map_or(1.0, |i| f64::from(SIZE_CLASS_WEIGHTS[i]))
}

/// A clock value the shaper can use: at most [`MAX_CLOCK_S`] from zero.
/// NaN and both infinities fail this test too.
fn clock_ok(now: f64) -> bool {
    now.abs() <= MAX_CLOCK_S
}

/// The one class to use when the padding range holds no size class: the
/// smallest class at or above `padding_min`, else the largest class.
fn fallback_class(padding_min: u16) -> u16 {
    SIZE_CLASSES
        .iter()
        .copied()
        .find(|&c| c >= padding_min)
        .unwrap_or(LARGEST_CLASS)
}

/// Tier shaper for one session and one direction.
pub struct Shaper<R> {
    cfg: ShaperConfig,
    /// Timing and secret draws.
    rng: R,
    /// Size draws, seeded once from `rng`. A separate stream so that sizing
    /// real packets never shifts the timing draws: traffic that fits the
    /// current tier must leave departure times exactly as they were.
    size_rng: StdRng,
    secrets: Secrets,
    tier: usize,
    last_now: f64,
    last_departure: f64,
    next_departure: f64,
    hold_until: f64,
    linger_until: Option<f64>,
    step_up_after: f64,
    last_step_up: f64,
    /// Tier a climb is heading for, and when its fake backlog began. A climb
    /// is a decoy's or a full tier's; both run the same way.
    decoy_target: Option<usize>,
    decoy_since: f64,
    /// Whether the climb is a decoy's: only a decoy's ends in a busy stretch.
    climb_is_decoy: bool,
    busy_until: f64,
    next_decoy: Option<f64>,
    next_repick: f64,
    /// (time, real packets sent) for the step-down usage check.
    real_log: VecDeque<(f64, u32)>,
    /// When the current tier began, and (time, real packets sent) since
    /// then, for the full-tier check.
    tier_since: f64,
    fill_log: VecDeque<(f64, u32)>,
    active: Vec<u16>,
    cumulative: Vec<f64>,
}

impl<R> fmt::Debug for Shaper<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately opaque: timing state and secrets never reach logs.
        f.debug_struct("Shaper").finish_non_exhaustive()
    }
}

impl<R: RngCore + CryptoRng> Shaper<R> {
    /// Start a session at `now`: seconds on one monotonic clock, at most
    /// [`MAX_CLOCK_S`] from zero. Use that same clock for every later call.
    ///
    /// # Errors
    /// Returns [`ShaperError`] when `cfg` breaks a config rule, or when `now`
    /// is not a finite number or is more than [`MAX_CLOCK_S`] from zero.
    pub fn new(cfg: ShaperConfig, mut rng: R, now: f64) -> Result<Self, ShaperError> {
        cfg.validate()?;
        if !clock_ok(now) {
            return Err(ShaperError::Clock);
        }
        let mut seed = <StdRng as SeedableRng>::Seed::default();
        rng.fill_bytes(&mut seed);
        let secrets = Secrets::draw(&mut rng, cfg.decoy_interval_s);
        let padding_max = cfg.padding_max;
        let mut shaper = Self {
            cfg,
            rng,
            size_rng: StdRng::from_seed(seed),
            secrets,
            tier: 0,
            last_now: now,
            last_departure: now,
            next_departure: now,
            hold_until: now,
            linger_until: None,
            step_up_after: 0.0,
            last_step_up: f64::NEG_INFINITY,
            decoy_target: None,
            decoy_since: now,
            climb_is_decoy: false,
            busy_until: f64::NEG_INFINITY,
            next_decoy: None,
            next_repick: now,
            real_log: VecDeque::new(),
            tier_since: now,
            fill_log: VecDeque::new(),
            active: Vec::new(),
            cumulative: Vec::new(),
        };
        shaper.next_departure = now + shaper.draw_gap();
        shaper.step_up_after = shaper.draw_step_up_point();
        shaper.next_repick = now + uniform(&mut shaper.rng, REPICK_S);
        shaper.next_decoy = shaper.draw_next_decoy(now);
        shaper.rebuild_classes(padding_max);
        Ok(shaper)
    }

    /// Advance the schedule to `now`; say how many packets leave and when
    /// to poll again.
    ///
    /// `now` is seconds on the same monotonic clock as in `Shaper::new`. A
    /// `now` that is earlier than the last poll's, not a finite number, or
    /// more than [`MAX_CLOCK_S`] from zero counts as the last poll's time:
    /// no time passes.
    ///
    /// `queue_len` is the number of real packets waiting, `oldest_wait` how
    /// long (s) the oldest sendable one has waited (0 if none), and
    /// `real_sent` how many real packets the caller sent since the last poll.
    pub fn poll(&mut self, now: f64, queue_len: usize, oldest_wait: f64, real_sent: u32) -> Poll {
        let now = if clock_ok(now) {
            now.max(self.last_now)
        } else {
            self.last_now
        };
        self.last_now = now;
        let oldest_wait = if oldest_wait.is_finite() {
            oldest_wait.max(0.0)
        } else {
            0.0
        };
        self.record_real_sent(now, real_sent);
        if now >= self.next_repick {
            self.repick(now);
        }
        if now - self.next_departure > STALL_RESET_S {
            // Stalled: skip the missed slots and restart from now.
            self.next_departure = now;
        }
        if self.next_decoy.is_some_and(|t| now >= t) {
            self.start_decoy(now);
        }
        if self.tier_is_full(now) {
            self.start_climb(now, self.tier + 1, false);
        }
        if self
            .step_up_at(now, queue_len, oldest_wait)
            .is_some_and(|at| now + STEP_UP_SLACK_S >= at)
        {
            self.step_up(now);
        }
        self.end_climb(now);
        self.maybe_step_down(now);
        let slots_due = self.take_due_slots(now);
        Poll {
            slots_due,
            next_wake: self.next_wake(now, queue_len, oldest_wait),
        }
    }

    /// Size class for a real packet with `payload_len` payload bytes: a draw
    /// from the fixed size mix, bumped up to the smallest class that fits.
    /// If no class fits, the exact size needed (padding only grows packets),
    /// capped at 65535, the most a `u16` holds.
    pub fn real_size_class(&mut self, payload_len: usize) -> u16 {
        let idx = self.sample_class_index();
        let need = payload_len.saturating_add(PACKET_OVERHEAD);
        self.active[idx..]
            .iter()
            .copied()
            .find(|&c| usize::from(c) >= need)
            .unwrap_or_else(|| u16::try_from(need).unwrap_or(u16::MAX))
    }

    /// Size class for a chaff packet: a draw from the fixed size mix, then
    /// moved one class up or down with the published chances (clamped).
    pub fn chaff_size_class(&mut self) -> u16 {
        let mut idx = self.sample_class_index();
        let r: f64 = self.size_rng.gen();
        if r < CHAFF_PERTURB_UP_P {
            if idx + 1 < self.active.len() {
                idx += 1;
            }
        } else if r < CHAFF_PERTURB_DOWN_P && idx > 0 {
            idx -= 1;
        }
        self.active[idx]
    }

    /// Use only classes up to `max_outer` bytes (never above `padding_max`).
    /// At least one class always stays usable.
    pub fn set_size_class_ceiling(&mut self, max_outer: u16) {
        self.rebuild_classes(max_outer);
    }

    /// The size classes in use now. Public information, not a secret.
    pub fn active_classes(&self) -> &[u16] {
        &self.active
    }

    fn top(&self) -> usize {
        self.cfg.tiers_pps.len() - 1
    }

    fn rate_of(&self, tier: usize) -> f64 {
        self.cfg.tiers_pps[tier] * self.secrets.tier_scale
    }

    /// Gap to the next departure at the current tier.
    fn draw_gap(&mut self) -> f64 {
        let w = self.secrets.gap_spread;
        uniform(&mut self.rng, (1.0 - w, 1.0 + w)) / self.rate_of(self.tier)
    }

    fn draw_step_up_point(&mut self) -> f64 {
        uniform(&mut self.rng, STEP_UP_FRACTION) * self.cfg.latency_budget_s
    }

    fn draw_next_decoy(&mut self, now: f64) -> Option<f64> {
        if self.cfg.decoy_interval_s > 0.0 {
            Some(now + exponential(&mut self.rng, self.secrets.decoy_mean_s))
        } else {
            None
        }
    }

    /// When the backlog reaches the step-up point, or `None` without one.
    /// The backlog starts at the oldest real packet's arrival or at a
    /// climbing decoy's start, whichever is earlier; the point counts from
    /// the later of that start and the last step-up. The result is an
    /// absolute time, so a decoy climbs at the same instants however often
    /// the caller polls.
    fn step_up_at(&self, now: f64, queue_len: usize, oldest_wait: f64) -> Option<f64> {
        let real = (queue_len > 0).then_some(now - oldest_wait);
        let decoy = self.decoy_target.map(|_| self.decoy_since);
        let start = match (real, decoy) {
            (Some(r), Some(d)) => r.min(d),
            (Some(r), None) => r,
            (None, Some(d)) => d,
            (None, None) => return None,
        };
        Some(start.max(self.last_step_up) + self.step_up_after)
    }

    /// Every tier change starts a hold of random length.
    fn change_tier(&mut self, tier: usize, now: f64) {
        if tier != self.tier {
            // The full-tier check measures one tier at a time.
            self.tier_since = now;
            self.fill_log.clear();
        }
        self.tier = tier;
        let hold = (self.secrets.hold_min_s, self.secrets.hold_max_s);
        self.hold_until = now + uniform(&mut self.rng, hold);
    }

    /// Up one tier, or two with the secret overshoot chance, capped at the
    /// top. Real backlogs, full tiers and decoys all come through here.
    fn step_up(&mut self, now: f64) {
        let top = self.top();
        if self.tier >= top {
            return;
        }
        let steps = if self.rng.gen::<f64>() < self.secrets.overshoot_p {
            2
        } else {
            1
        };
        self.change_tier((self.tier + steps).min(top), now);
        self.linger_until = None;
        self.last_step_up = now;
        self.step_up_after = self.draw_step_up_point();
        // The faster rate may let the next packet leave sooner, but never in
        // the past: no burst at the step.
        let candidate = self.last_departure + self.draw_gap();
        if candidate < self.next_departure {
            self.next_departure = candidate.max(now);
        }
    }

    /// A decoy: a fake backlog that climbs like a real page load. It picks a
    /// target tier (the top with the secret chance, otherwise a random tier
    /// from 1 to the one below the top) and climbs there one step-up point at
    /// a time through the normal step-up path. One climb at a time, and no
    /// decoy starts at the top tier.
    fn start_decoy(&mut self, now: f64) {
        let top = self.top();
        if self.tier < top && self.decoy_target.is_none() {
            let target = if top == 1 || self.rng.gen::<f64>() < self.secrets.decoy_top_p {
                top
            } else {
                self.rng.gen_range(1..top)
            };
            self.start_climb(now, target, true);
        }
        self.next_decoy = self.draw_next_decoy(now);
    }

    /// A fake backlog that begins now and climbs to `target`, one step-up
    /// point at a time. Decoys and full tiers both start their climbs here,
    /// so a full tier climbs exactly like a decoy aimed one tier up.
    fn start_climb(&mut self, now: f64, target: usize, decoy: bool) {
        self.decoy_target = Some(target);
        self.decoy_since = now;
        self.climb_is_decoy = decoy;
    }

    /// A full tier: over the last `fill_window_s` seconds, all of them at
    /// this tier, real packets took at least `fill_limit` of the slots the
    /// tier offers. Measured against the tier's rate, not against the slots
    /// handed out: their count jitters with the gap spread, which would let
    /// steady traffic well below the limit look full now and then. Only
    /// real packets count, so decoys and chaff never fill a tier. Draws
    /// nothing, so traffic that does not fill the tier leaves the timing
    /// exactly as it was.
    fn tier_is_full(&self, now: f64) -> bool {
        let window = self.secrets.fill_window_s;
        if self.tier >= self.top() || self.decoy_target.is_some() || now - self.tier_since < window
        {
            return false;
        }
        let sent = self
            .fill_log
            .iter()
            .filter(|(t, _)| now - *t <= window)
            .fold(0_u32, |acc, (_, n)| acc.saturating_add(*n));
        f64::from(sent) >= self.secrets.fill_limit * window * self.rate_of(self.tier)
    }

    /// Once a climb has reached its target it ends. A decoy's fake busy
    /// stretch starts then; a full tier needs none, since its real traffic
    /// keeps the usage up. After that, the normal step-down and linger take
    /// over.
    fn end_climb(&mut self, now: f64) {
        if self.decoy_target.is_some_and(|target| self.tier >= target) {
            self.decoy_target = None;
            if self.climb_is_decoy {
                let busy = exponential(&mut self.rng, self.secrets.busy_mean_s);
                self.busy_until = self.busy_until.max(now + busy);
            }
        }
    }

    /// At a hold end: step down if recent real use is low or fits the lower
    /// tier with room to spare, else hold again. A step from tier 1 to idle
    /// lingers at tier 1 first. The linger end runs the same usage check:
    /// while the link is still in use, or a decoy is climbing or busy, it
    /// holds at tier 1 again, and the next return to idle lingers again.
    fn maybe_step_down(&mut self, now: f64) {
        if let Some(end) = self.linger_until {
            if now >= end {
                self.linger_until = None;
                if self.usage_is_low(now) {
                    self.change_tier(0, now);
                } else {
                    // Still in use: hold again at tier 1, where linger runs.
                    self.change_tier(self.tier, now);
                }
            }
            return;
        }
        if self.tier == 0 || now < self.hold_until {
            return;
        }
        if self.usage_is_low(now) {
            if self.tier == 1 && self.cfg.linger_s.1 > 0.0 {
                let linger = uniform(&mut self.rng, self.cfg.linger_s);
                self.linger_until = Some(now + linger);
            } else {
                self.change_tier(self.tier - 1, now);
            }
        } else {
            // Still in use: hold again at the same tier.
            self.change_tier(self.tier, now);
        }
    }

    /// usage = real sent in the look-back window / (window x lower tier rate).
    /// Low below `usage_limit`; at or below `fit_limit` the traffic fits
    /// the lower tier with room to spare. Either one steps down.
    fn usage_is_low(&self, now: f64) -> bool {
        if self.decoy_target.is_some() || now < self.busy_until {
            // A climb or a busy stretch: usage counts as high.
            return false;
        }
        let window = self.secrets.lookback_s;
        let sent = self
            .real_log
            .iter()
            .filter(|(t, _)| now - *t <= window)
            .fold(0_u32, |acc, (_, n)| acc.saturating_add(*n));
        let sent = f64::from(sent);
        let lower = window * self.rate_of(self.tier - 1);
        sent < self.secrets.usage_limit * lower || sent <= self.secrets.fit_limit * lower
    }

    fn record_real_sent(&mut self, now: f64, n: u32) {
        add_to_log(&mut self.real_log, now, n, USAGE_BUCKET_S, LOOKBACK_S.1);
        add_to_log(&mut self.fill_log, now, n, FILL_BUCKET_S, FILL_WINDOW_S.1);
    }

    /// Draw all secret values again. A running hold, linger or busy stretch
    /// keeps its end time; the next decoy is re-timed with the new mean
    /// (exponential waits are memoryless, so this does not bias the rate).
    fn repick(&mut self, now: f64) {
        self.secrets = Secrets::draw(&mut self.rng, self.cfg.decoy_interval_s);
        self.next_repick = now + uniform(&mut self.rng, REPICK_S);
        self.next_decoy = self.draw_next_decoy(now);
    }

    fn take_due_slots(&mut self, now: f64) -> u32 {
        let mut slots = 0_u32;
        while self.next_departure <= now {
            slots = slots.saturating_add(1);
            self.last_departure = self.next_departure;
            self.next_departure += self.draw_gap();
        }
        slots
    }

    fn next_wake(&self, now: f64, queue_len: usize, oldest_wait: f64) -> f64 {
        let mut wake = self.next_departure.min(self.next_repick);
        if let Some(t) = self.next_decoy {
            wake = wake.min(t);
        }
        if let Some(t) = self.linger_until {
            wake = wake.min(t);
        } else if self.tier > 0 {
            wake = wake.min(self.hold_until);
        }
        // At the top tier a backlog cannot step up, so it must not set a
        // wake either (that would poll in a tight loop).
        let step = self
            .step_up_at(now, queue_len, oldest_wait)
            .filter(|_| self.tier < self.top());
        if let Some(at) = step {
            wake = wake.min(at.max(now));
        }
        wake
    }

    fn rebuild_classes(&mut self, ceiling: u16) {
        let lo = self.cfg.padding_min;
        let hi = ceiling.min(self.cfg.padding_max);
        self.active = SIZE_CLASSES
            .iter()
            .copied()
            .filter(|&c| lo <= c && c <= hi)
            .collect();
        if self.active.is_empty() {
            self.active = vec![fallback_class(lo)];
        }
        let weights: Vec<f64> = self.active.iter().map(|&c| class_weight(c)).collect();
        let total: f64 = weights.iter().sum();
        let mut running = 0.0;
        self.cumulative = weights
            .iter()
            .map(|w| {
                running += w / total;
                running
            })
            .collect();
    }

    fn sample_class_index(&mut self) -> usize {
        let r: f64 = self.size_rng.gen();
        self.cumulative
            .iter()
            .position(|&cum| r < cum)
            .unwrap_or(self.active.len() - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: f64 = 1000.0;

    fn cfg() -> ShaperConfig {
        ShaperConfig {
            tiers_pps: vec![10.0, 50.0, 200.0, 800.0],
            latency_budget_s: 0.5,
            decoy_interval_s: 0.0,
            linger_s: (0.0, 0.0),
            padding_min: 128,
            padding_max: 1400,
        }
    }

    type Edit = fn(&mut ShaperConfig);

    /// The test config with one change applied.
    fn with(edit: Edit) -> ShaperConfig {
        let mut c = cfg();
        edit(&mut c);
        c
    }

    fn shaper(cfg: ShaperConfig, seed: u64) -> Shaper<StdRng> {
        Shaper::new(cfg, StdRng::seed_from_u64(seed), T0).expect("test config is valid")
    }

    fn count(n: usize) -> f64 {
        f64::from(u32::try_from(n).expect("test counts fit in u32"))
    }

    /// One packet on the wire, with the state that drew the gap after it.
    #[derive(Clone, Copy, Debug)]
    struct Departure {
        at: f64,
        tier: usize,
        scale: f64,
        spread: f64,
        real: bool,
    }

    #[derive(Debug, Default)]
    struct Trace {
        departures: Vec<Departure>,
        /// Seconds each real packet waited from arrival to departure.
        waits: Vec<f64>,
        /// (time, new tier) at every tier change.
        tier_changes: Vec<(f64, usize)>,
    }

    impl Trace {
        fn times(&self) -> Vec<f64> {
            self.departures.iter().map(|d| d.at).collect()
        }

        fn real_count(&self) -> usize {
            self.departures.iter().filter(|d| d.real).count()
        }
    }

    /// Drive `s` the way the scheduler does: poll at each `next_wake`, send
    /// real packets first and chaff for the rest, size every packet.
    /// `arrivals` are real-packet arrival times, ascending.
    fn simulate(s: &mut Shaper<StdRng>, start: f64, arrivals: &[f64], end: f64) -> Trace {
        let mut trace = Trace::default();
        let mut queue: VecDeque<f64> = VecDeque::new();
        let mut next_arrival = 0;
        let mut real_sent = 0_u32;
        let mut tier = s.tier;
        let mut now = start;
        while now <= end {
            while next_arrival < arrivals.len() && arrivals[next_arrival] <= now {
                queue.push_back(arrivals[next_arrival]);
                next_arrival += 1;
            }
            let oldest_wait = queue.front().map_or(0.0, |&t| now - t);
            let poll = s.poll(now, queue.len(), oldest_wait, real_sent);
            real_sent = 0;
            if s.tier != tier {
                tier = s.tier;
                trace.tier_changes.push((now, tier));
            }
            for _ in 0..poll.slots_due {
                let real = if let Some(arrived) = queue.pop_front() {
                    trace.waits.push(now - arrived);
                    real_sent += 1;
                    s.real_size_class(100);
                    true
                } else {
                    s.chaff_size_class();
                    false
                };
                trace.departures.push(Departure {
                    at: now,
                    tier: s.tier,
                    scale: s.secrets.tier_scale,
                    spread: s.secrets.gap_spread,
                    real,
                });
            }
            assert!(poll.next_wake >= now, "next_wake must not go back in time");
            now = poll.next_wake;
        }
        trace
    }

    /// Real-packet arrivals spaced evenly at `rate` per second, from `T0`
    /// until `end`.
    fn steady(rate: f64, end: f64) -> Vec<f64> {
        (0..u32::MAX)
            .map(|i| T0 + f64::from(i) / rate)
            .take_while(|&t| t < end)
            .collect()
    }

    /// Every gap between two departures at the same tier, with the same
    /// secrets and no tier change between them, lies in the tier's band.
    fn assert_gaps_follow_tiers(trace: &Trace, tiers: &[f64]) {
        let mut checked = 0;
        for pair in trace.departures.windows(2) {
            let (a, b) = (pair[0], pair[1]);
            let changed = trace
                .tier_changes
                .iter()
                .any(|&(t, _)| t > a.at && t <= b.at);
            if changed || a.tier != b.tier || a.scale.to_bits() != b.scale.to_bits() {
                continue;
            }
            let rate = tiers[a.tier] * a.scale;
            let gap = b.at - a.at;
            let (lo, hi) = ((1.0 - a.spread) / rate, (1.0 + a.spread) / rate);
            assert!(
                gap >= lo - 1e-9 && gap <= hi + 1e-9,
                "gap {gap} outside [{lo}, {hi}] at tier {}",
                a.tier
            );
            checked += 1;
        }
        assert!(checked > 0, "no gaps were checked");
    }

    #[test]
    fn rejects_configs_that_break_the_rules() {
        let cases: [(Edit, ShaperError); 16] = [
            (|c| c.tiers_pps = vec![10.0], ShaperError::Tiers),
            (|c| c.tiers_pps = vec![10.0; 9], ShaperError::Tiers),
            (|c| c.tiers_pps = vec![10.0, 10.0], ShaperError::Tiers),
            (|c| c.tiers_pps = vec![50.0, 10.0], ShaperError::Tiers),
            (|c| c.tiers_pps = vec![0.5, 10.0], ShaperError::Tiers),
            (|c| c.tiers_pps = vec![10.0, 5001.0], ShaperError::Tiers),
            (|c| c.tiers_pps = vec![10.0, f64::NAN], ShaperError::Tiers),
            (|c| c.latency_budget_s = 0.009, ShaperError::LatencyBudget),
            (|c| c.latency_budget_s = 5.01, ShaperError::LatencyBudget),
            (|c| c.decoy_interval_s = 299.0, ShaperError::DecoyInterval),
            (
                |c| c.decoy_interval_s = 86_401.0,
                ShaperError::DecoyInterval,
            ),
            (|c| c.decoy_interval_s = -1.0, ShaperError::DecoyInterval),
            (|c| c.linger_s = (0.0, 10.0), ShaperError::Linger),
            (|c| c.linger_s = (10.0, 5.0), ShaperError::Linger),
            (|c| c.linger_s = (10.0, 7201.0), ShaperError::Linger),
            (|c| c.padding_min = 1401, ShaperError::Padding),
        ];
        for (edit, want) in cases {
            let got = Shaper::new(with(edit), StdRng::seed_from_u64(0), T0);
            assert!(matches!(got, Err(e) if e == want), "expected {want:?}");
        }
    }

    #[test]
    fn accepts_the_edges_of_every_rule() {
        // The 1 packet/s and 0.01 s edges get a partner value that meets the
        // first-tier rule (above 4.25 / budget packets/s).
        let cases: [Edit; 8] = [
            |c| {
                c.tiers_pps = vec![1.0, 5000.0];
                c.latency_budget_s = 5.0;
            },
            |c| {
                c.tiers_pps = (1..=8).map(f64::from).collect();
                c.latency_budget_s = 5.0;
            },
            |c| {
                c.latency_budget_s = 0.01;
                c.tiers_pps = vec![430.0, 5000.0];
            },
            |c| c.latency_budget_s = 5.0,
            |c| c.decoy_interval_s = 300.0,
            |c| c.decoy_interval_s = 86_400.0,
            |c| c.linger_s = (7200.0, 7200.0),
            |c| c.padding_min = 1400,
        ];
        for edit in cases {
            assert!(Shaper::new(with(edit), StdRng::seed_from_u64(0), T0).is_ok());
        }
    }

    /// The first tier must be fast enough that its longest gap ends before
    /// the earliest step-up point: above 4.25 / budget packets/s with the
    /// secret ranges in use (8.5 at 0.5 s, 425 at 0.01 s).
    #[test]
    fn the_first_tier_must_be_fast_enough_for_the_budget() {
        let refused: [Edit; 3] = [
            |c| c.tiers_pps = vec![8.4, 50.0],
            // Exactly at the limit is refused too: it must be above.
            |c| c.tiers_pps = vec![8.5, 50.0],
            |c| {
                c.latency_budget_s = 0.01;
                c.tiers_pps = vec![420.0, 5000.0];
            },
        ];
        for edit in refused {
            let got = Shaper::new(with(edit), StdRng::seed_from_u64(0), T0);
            assert!(matches!(got, Err(ShaperError::IdleTooSlow)));
        }
        let accepted: [Edit; 3] = [
            |c| c.tiers_pps = vec![8.6, 50.0],
            |c| {
                c.latency_budget_s = 0.01;
                c.tiers_pps = vec![430.0, 5000.0];
            },
            |c| {
                c.latency_budget_s = 5.0;
                c.tiers_pps = vec![1.0, 50.0];
            },
        ];
        for edit in accepted {
            assert!(Shaper::new(with(edit), StdRng::seed_from_u64(0), T0).is_ok());
        }
        // The default config (10 packets/s at 0.5 s) passes.
        assert!(Shaper::new(cfg(), StdRng::seed_from_u64(0), T0).is_ok());
    }

    #[test]
    fn debug_output_shows_no_values() {
        let s = shaper(cfg(), 1);
        assert_eq!(format!("{s:?}"), "Shaper { .. }");
    }

    /// KEY: traffic that fits in the current tier does not change send times.
    /// Same seed with and without that traffic gives identical departures.
    #[test]
    fn fitting_traffic_does_not_move_departures() {
        let end = T0 + 600.0;
        // About one packet a second: each leaves at the next slot (gaps are
        // at most 0.2125 s at tier 0), long before the earliest step-up point
        // (0.25 s at the 0.5 s budget).
        let arrivals: Vec<f64> = (0..560_u32)
            .map(|i| T0 + 0.5 + f64::from(i) * 1.05)
            .collect();
        let quiet = simulate(&mut shaper(cfg(), 7), T0, &[], end);
        let busy = simulate(&mut shaper(cfg(), 7), T0, &arrivals, end);
        assert!(busy.real_count() >= 550, "the traffic was carried");
        assert!(
            busy.waits.iter().all(|&w| w < 0.25),
            "every packet left before the earliest step-up point"
        );
        assert!(quiet.tier_changes.is_empty() && busy.tier_changes.is_empty());
        assert_eq!(busy.times(), quiet.times());
    }

    /// KEY, across decoys, holds, step-downs and linger: still identical.
    #[test]
    fn fitting_traffic_does_not_move_departures_across_decoys() {
        let edit: Edit = |c| {
            c.decoy_interval_s = 300.0;
            c.linger_s = (300.0, 600.0);
        };
        let end = T0 + 2.0 * 3600.0;
        let arrivals: Vec<f64> = (0..3500_u32)
            .map(|i| T0 + 0.5 + f64::from(i) * 2.0)
            .collect();
        let quiet = simulate(&mut shaper(with(edit), 11), T0, &[], end);
        let busy = simulate(&mut shaper(with(edit), 11), T0, &arrivals, end);
        assert!(quiet.tier_changes.len() >= 4, "decoys ran");
        assert_eq!(busy.real_count(), arrivals.len());
        assert_eq!(busy.tier_changes, quiet.tier_changes);
        assert_eq!(busy.times(), quiet.times());
    }

    #[test]
    fn idle_rate_matches_tier_zero_and_gaps_stay_in_range() {
        let mut s = shaper(cfg(), 3);
        let rate = 10.0 * s.secrets.tier_scale;
        // 500 s: before the first secret re-pick (at least 600 s away).
        let trace = simulate(&mut s, T0, &[], T0 + 500.0);
        let measured = count(trace.departures.len()) / 500.0;
        assert!(
            (measured - rate).abs() < rate * 0.05,
            "rate {measured} vs {rate}"
        );
        assert_gaps_follow_tiers(&trace, &cfg().tiers_pps);
    }

    #[test]
    fn a_stall_skips_missed_slots_instead_of_bursting() {
        let mut s = shaper(cfg(), 31);
        s.poll(T0 + 0.5, 0, 0.0, 0);
        let after = s.poll(T0 + 10.5, 0, 0.0, 0);
        assert_eq!(after.slots_due, 1);
        assert!(after.next_wake > T0 + 10.5);
    }

    #[test]
    fn a_bad_clock_or_wait_value_counts_as_no_time_passing() {
        // A start time that is not a finite number is refused.
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let got = Shaper::new(cfg(), StdRng::seed_from_u64(0), bad);
            assert!(matches!(got, Err(ShaperError::Clock)), "started at {bad}");
        }
        // A poll time that is not finite, or is earlier than the last poll's,
        // counts as the last poll's time. A twin that never sees those calls
        // must keep giving the same answers.
        let mut s = shaper(cfg(), 51);
        let mut twin = shaper(cfg(), 51);
        let at = T0 + 1.0;
        assert_eq!(s.poll(at, 0, 0.0, 0), twin.poll(at, 0, 0.0, 0));
        for bad in [
            f64::INFINITY,
            f64::NAN,
            f64::NEG_INFINITY,
            T0 - 5.0,
            at - 0.5,
        ] {
            let poll = s.poll(bad, 0, 0.0, 0);
            assert_eq!(poll.slots_due, 0, "time passed at {bad}");
            assert_eq!(
                s.last_now.to_bits(),
                at.to_bits(),
                "the clock moved at {bad}"
            );
        }
        let later = T0 + 2.0;
        let got = s.poll(later, 0, 0.0, 0);
        assert_eq!(got, twin.poll(later, 0, 0.0, 0));
        assert!(
            got.slots_due > 0 && got.next_wake > later,
            "the shaper got stuck"
        );
        // A wait that is not a finite number counts as no wait: it must not
        // step the rate up.
        let mut s = shaper(cfg(), 52);
        let mut now = T0;
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            now += 0.01;
            let poll = s.poll(now, 5, bad, 0);
            assert_eq!(s.tier, 0, "stepped up on a wait of {bad}");
            assert!(poll.next_wake.is_finite() && poll.next_wake >= now);
        }
    }

    /// A clock value more than `MAX_CLOCK_S` from zero (say nanoseconds
    /// passed as seconds) is refused at the start and counts as no time
    /// passing in a poll, so float rounding can never stall the slot loop.
    #[test]
    fn a_clock_value_beyond_the_bound_is_refused_or_ignored() {
        for bad in [1.0e10, -1.0e10] {
            let got = Shaper::new(cfg(), StdRng::seed_from_u64(0), bad);
            assert!(matches!(got, Err(ShaperError::Clock)), "started at {bad}");
        }
        for edge in [MAX_CLOCK_S, -MAX_CLOCK_S] {
            let got = Shaper::new(cfg(), StdRng::seed_from_u64(0), edge);
            assert!(got.is_ok(), "refused a start at {edge}");
        }
        // A twin that never sees the bad polls must keep giving the same
        // answers.
        let mut s = shaper(cfg(), 53);
        let mut twin = shaper(cfg(), 53);
        let at = T0 + 1.0;
        assert_eq!(s.poll(at, 0, 0.0, 0), twin.poll(at, 0, 0.0, 0));
        for bad in [1.0e10, -1.0e10] {
            let poll = s.poll(bad, 0, 0.0, 0);
            assert_eq!(poll.slots_due, 0, "time passed at {bad}");
            assert_eq!(
                s.last_now.to_bits(),
                at.to_bits(),
                "the clock moved at {bad}"
            );
        }
        let later = T0 + 2.0;
        let got = s.poll(later, 0, 0.0, 0);
        assert_eq!(got, twin.poll(later, 0, 0.0, 0));
        assert!(
            got.slots_due > 0 && got.next_wake > later,
            "the shaper got stuck"
        );
    }

    #[test]
    fn step_up_happens_at_the_step_up_point_and_never_after_the_budget() {
        for seed in 0..50 {
            let mut s = shaper(cfg(), seed);
            let point = s.step_up_after;
            assert!((0.25..=0.5).contains(&point));
            let burst_at = T0 + 10.0;
            let trace = simulate(&mut s, T0, &[burst_at; 300], T0 + 14.0);
            let (first, tier) = trace.tier_changes[0];
            assert!(tier >= 1);
            assert!(
                (first - (burst_at + point)).abs() < 1e-9,
                "stepped at {first}"
            );
            assert!(first - burst_at <= 0.5 + 1e-9, "stepped after the budget");
            // Still backed up: each next step comes after a fresh point.
            for pair in trace.tier_changes.windows(2) {
                let spacing = pair[1].0 - pair[0].0;
                assert!(
                    (0.25 - 1e-9..=0.5 + 1e-9).contains(&spacing),
                    "spacing {spacing}"
                );
            }
        }
    }

    #[test]
    fn a_step_up_moves_the_next_departure_earlier_but_not_into_the_past() {
        // Tier 0 at 1 packet/s puts the next packet at least 0.25 s away;
        // every tier 1 gap is at most 0.0425 s. So the step-up must pull the
        // departure in, whatever the session's secrets.
        for seed in 0..50 {
            // 0.001 s after the last departure the faster slot is still
            // ahead; at 0.2 s it is already behind.
            for (since_last, slot_passed) in [(0.001, false), (0.2, true)] {
                // A 1 packet/s first tier needs a long budget (first-tier
                // rule); step_up() is called directly, so it changes nothing.
                let mut s = shaper(
                    with(|c| {
                        c.tiers_pps = vec![1.0, 50.0];
                        c.latency_budget_s = 5.0;
                    }),
                    seed,
                );
                let now = s.last_departure + since_last;
                let before = s.next_departure;
                s.step_up(now);
                assert_eq!(s.tier, 1);
                assert!(
                    s.next_departure < before,
                    "the step-up left the departure at {before}"
                );
                assert!(s.next_departure >= now, "the departure moved into the past");
                if slot_passed {
                    // The slot is already past: the packet goes at `now`.
                    assert_eq!(s.next_departure.to_bits(), now.to_bits());
                } else {
                    // The slot is still ahead: the packet waits for it.
                    assert!(s.next_departure > now, "the packet left at once");
                }
            }
        }
    }

    #[test]
    fn overshoot_rate_matches_the_session_secret() {
        let mut s = shaper(cfg(), 5);
        let p = s.secrets.overshoot_p;
        let trials = 20_000_u32;
        let mut double = 0_u32;
        for _ in 0..trials {
            s.tier = 0;
            s.step_up(T0);
            if s.tier == 2 {
                double += 1;
            }
        }
        let rate = f64::from(double) / f64::from(trials);
        assert!((rate - p).abs() < 0.02, "overshoot {rate} vs secret {p}");
    }

    #[test]
    fn a_backlog_at_the_top_tier_does_not_poll_in_a_tight_loop() {
        let mut s = shaper(cfg(), 41);
        s.change_tier(3, T0);
        let poll = s.poll(T0 + 0.01, 500, 30.0, 0);
        assert_eq!(s.tier, 3);
        assert!(poll.next_wake > T0 + 0.01);
    }

    #[test]
    fn no_step_down_during_a_hold_then_one_tier_down_when_usage_is_low() {
        let mut s = shaper(cfg(), 9);
        s.change_tier(2, T0);
        let hold_end = s.hold_until;
        let len = hold_end - T0;
        assert!(len >= s.secrets.hold_min_s && len <= s.secrets.hold_max_s);
        simulate(&mut s, T0, &[], hold_end - 0.01);
        assert_eq!(s.tier, 2, "stepped down during the hold");
        s.poll(hold_end + 0.001, 0, 0.0, 0);
        assert_eq!(s.tier, 1);
        assert!(s.hold_until > hold_end, "the step down started a new hold");
    }

    #[test]
    fn hold_end_keeps_the_tier_while_usage_is_high() {
        let mut s = shaper(cfg(), 13);
        s.change_tier(2, T0);
        let hold_end = s.hold_until;
        // 100 real packets/s against a lower tier of at most 60 packets/s:
        // usage stays above any secret limit (at most 0.65).
        let mut t = T0;
        while t < hold_end + 0.05 {
            t += 0.1;
            s.poll(t, 0, 0.0, 10);
        }
        assert_eq!(s.tier, 2);
        assert!(
            s.hold_until > hold_end,
            "a new hold started at the same tier"
        );
    }

    #[test]
    fn dropping_to_idle_lingers_at_tier_one_first() {
        let mut s = shaper(with(|c| c.linger_s = (300.0, 600.0)), 17);
        s.change_tier(1, T0);
        let at = s.hold_until + 0.001;
        s.poll(at, 0, 0.0, 0);
        assert_eq!(s.tier, 1);
        let end = s.linger_until.expect("lingering");
        assert!((300.0..=600.0).contains(&(end - at)));
        s.poll(end - 0.001, 0, 0.0, 0);
        assert_eq!(s.tier, 1);
        s.poll(end + 0.001, 0, 0.0, 0);
        assert_eq!(s.tier, 0);
    }

    #[test]
    fn a_step_up_during_linger_cancels_it_and_the_next_drop_lingers_again() {
        let mut s = shaper(with(|c| c.linger_s = (300.0, 600.0)), 19);
        s.change_tier(1, T0);
        let at = s.hold_until + 0.001;
        s.poll(at, 0, 0.0, 0);
        assert!(s.linger_until.is_some());
        s.step_up(at + 1.0);
        assert!(s.tier >= 2);
        assert!(s.linger_until.is_none());
        s.change_tier(1, at + 2.0);
        s.poll(s.hold_until + 0.001, 0, 0.0, 0);
        assert_eq!(s.tier, 1);
        assert!(
            s.linger_until.is_some(),
            "the next return to idle lingers again"
        );
    }

    #[test]
    fn linger_off_drops_straight_to_idle() {
        let mut s = shaper(cfg(), 21);
        s.change_tier(1, T0);
        s.poll(s.hold_until + 0.001, 0, 0.0, 0);
        assert_eq!(s.tier, 0);
        assert!(s.linger_until.is_none());
    }

    /// The linger end runs the usage check: a link still in use keeps tier 1,
    /// even at the top of a two-tier config, where a backlog cannot step up.
    #[test]
    fn linger_end_keeps_tier_one_while_the_link_is_in_use() {
        for seed in 0..20 {
            let mut s = shaper(
                with(|c| {
                    c.tiers_pps = vec![10.0, 50.0];
                    c.linger_s = (300.0, 600.0);
                }),
                seed,
            );
            s.change_tier(1, T0);
            let at = s.hold_until + 0.001;
            s.poll(at, 0, 0.0, 0);
            let end = s.linger_until.expect("lingering");
            // 30 real packets a second against a tier 0 of at most 12 a
            // second: usage stays above any secret limit (at most 0.65).
            let mut t = at;
            while t < end + 1.0 {
                t += 0.1;
                s.poll(t, 0, 0.0, 3);
            }
            assert_eq!(s.tier, 1, "seed {seed}: dropped to idle while in use");
            assert!(s.linger_until.is_none());
            assert!(s.hold_until > end, "seed {seed}: no new hold at tier 1");
            // Once the traffic stops, the next return to idle lingers again.
            s.poll(s.hold_until + 0.001, 0, 0.0, 0);
            assert_eq!(s.tier, 1);
            assert!(s.linger_until.is_some(), "seed {seed}: no second linger");
        }
    }

    /// A decoy that starts during linger is not cut off by the linger end: it
    /// climbs from tier 1 to its target and runs its busy stretch.
    #[test]
    fn a_decoy_that_starts_during_linger_is_not_cut_off() {
        for seed in 0..20 {
            let mut s = shaper(
                with(|c| {
                    c.decoy_interval_s = 300.0;
                    c.linger_s = (300.0, 600.0);
                }),
                seed,
            );
            // Aim the decoy at the top tier, so it has steps to climb. A
            // re-pick would re-time it, and no decoy may start early.
            s.secrets.decoy_top_p = 1.0;
            s.next_repick = f64::INFINITY;
            s.next_decoy = None;
            s.change_tier(1, T0);
            let at = s.hold_until + 0.001;
            s.poll(at, 0, 0.0, 0);
            let end = s.linger_until.expect("lingering");
            // The decoy starts 0.1 s before the linger end. Its first step-up
            // point is at least 0.25 s later, so the end comes first.
            s.next_decoy = Some(end - 0.1);
            s.poll(end - 0.1, 0, 0.0, 0);
            assert_eq!(s.decoy_target, Some(3), "seed {seed}");
            s.next_decoy = None;
            s.poll(end + 0.001, 0, 0.0, 0);
            assert_eq!(s.tier, 1, "seed {seed}: the linger end cut the decoy off");
            assert!(s.linger_until.is_none());
            simulate(&mut s, end + 0.001, &[], end + 5.0);
            assert!(
                s.decoy_target.is_none(),
                "seed {seed}: the climb never ended"
            );
            assert_eq!(s.tier, 3, "seed {seed}: the decoy missed its target");
            assert!(s.busy_until > end + 0.001, "seed {seed}: no busy stretch");
        }
    }

    /// Light real traffic at the linger end still drops to idle.
    #[test]
    fn linger_end_with_light_traffic_still_drops_to_idle() {
        for seed in 0..20 {
            let mut s = shaper(with(|c| c.linger_s = (300.0, 600.0)), seed);
            s.change_tier(1, T0);
            let at = s.hold_until + 0.001;
            s.poll(at, 0, 0.0, 0);
            let end = s.linger_until.expect("lingering");
            // One real packet a second against a tier 0 of at least 8 a
            // second: usage stays below any secret limit (at least 0.35).
            let mut t = at;
            while t < end + 1.0 {
                t += 1.0;
                s.poll(t, 0, 0.0, 1);
            }
            assert_eq!(s.tier, 0, "seed {seed}: light traffic kept tier 1");
            assert!(s.linger_until.is_none());
        }
    }

    #[test]
    fn a_decoy_climbs_then_holds_while_busy() {
        let mut s = shaper(with(|c| c.decoy_interval_s = 300.0), 23);
        let due = s.next_decoy.expect("decoys are on");
        s.poll(due, 0, 0.0, 0);
        // A decoy is a fake backlog: nothing moves before its first point.
        assert_eq!(s.tier, 0);
        let target = s.decoy_target.expect("climbing");
        assert!((1..=3).contains(&target));
        assert!(s.next_decoy.expect("re-armed") > due);
        // No further decoys or re-picks (a re-pick re-times the next decoy).
        s.next_decoy = None;
        s.next_repick = f64::INFINITY;
        simulate(&mut s, due, &[], due + 3.0);
        assert!(s.decoy_target.is_none(), "the climb ended");
        assert!(s.tier >= target);
        assert!(s.busy_until > due);
        // While busy, hold ends keep the tier even with zero real use.
        let tier = s.tier;
        s.busy_until = due + 2000.0;
        let mut hold_ends = 0;
        while s.hold_until < s.busy_until {
            s.poll(s.hold_until + 0.001, 0, 0.0, 0);
            assert_eq!(s.tier, tier, "stepped down during the busy stretch");
            hold_ends += 1;
        }
        assert!(hold_ends >= 3);
        // After the busy stretch, the next hold end steps down one tier.
        s.poll(s.hold_until + 0.001, 0, 0.0, 0);
        assert_eq!(s.tier, tier - 1);
    }

    #[test]
    fn a_decoy_climbs_one_step_up_point_at_a_time_to_its_target() {
        for seed in 0..30 {
            let mut s = shaper(with(|c| c.decoy_interval_s = 300.0), seed);
            // Aim every decoy at the top tier.
            s.secrets.decoy_top_p = 1.0;
            s.next_repick = f64::INFINITY;
            let due = T0 + 10.0;
            s.next_decoy = Some(due);
            let first_point = s.step_up_after;
            let trace = simulate(&mut s, T0, &[], due + 3.0);
            let changes = &trace.tier_changes;
            assert!(
                (changes[0].0 - (due + first_point)).abs() < 1e-9,
                "the first step comes one step-up point after the start"
            );
            let mut tier = 0;
            for &(_, next) in changes {
                assert!(next == tier + 1 || next == tier + 2, "one tier, or two");
                tier = next;
            }
            assert_eq!(tier, 3, "reached the target");
            for pair in changes.windows(2) {
                let spacing = pair[1].0 - pair[0].0;
                assert!(
                    (0.25 - 1e-9..=0.5 + 1e-9).contains(&spacing),
                    "spacing {spacing}"
                );
            }
        }
    }

    #[test]
    fn decoys_reach_the_top_about_as_often_as_the_session_chance() {
        let mut s = shaper(with(|c| c.decoy_interval_s = 300.0), 31);
        s.next_repick = f64::INFINITY;
        let p = s.secrets.decoy_top_p;
        let o = s.secrets.overshoot_p;
        let trials = 20_000_u32;
        let (mut aimed, mut reached) = (0_u32, 0_u32);
        let mut t = T0;
        for _ in 0..trials {
            t += 10.0;
            s.change_tier(0, t);
            s.next_decoy = Some(t);
            s.poll(t, 0, 0.0, 0);
            if s.decoy_target == Some(3) {
                aimed += 1;
            }
            while s.decoy_target.is_some() {
                let at = s.decoy_since.max(s.last_step_up) + s.step_up_after;
                s.poll(at, 0, 0.0, 0);
            }
            if s.tier == 3 {
                reached += 1;
            }
        }
        let aimed = f64::from(aimed) / f64::from(trials);
        let reached = f64::from(reached) / f64::from(trials);
        assert!((aimed - p).abs() < 0.02, "aimed at the top {aimed} vs {p}");
        // A decoy aimed at tier 2 can overshoot to the top: from tier 1 a
        // double step lands on 3. With targets 1 and 2 equally likely, that
        // adds (1 - p) / 2 * (1 - o) * o.
        let want = p + (1.0 - p) / 2.0 * (1.0 - o) * o;
        assert!(
            (reached - want).abs() < 0.02,
            "reached the top {reached} vs {want}"
        );
    }

    #[test]
    fn a_decoy_steps_up_exactly_like_a_real_backlog() {
        let edit: Edit = |c| c.decoy_interval_s = 300.0;
        let mut decoy = shaper(with(edit), 29);
        let mut real = shaper(with(edit), 29);
        let at = T0 + 5.0;
        decoy.next_decoy = Some(at);
        real.next_decoy = None;
        let point = real.step_up_after;
        assert_eq!(decoy.step_up_after.to_bits(), point.to_bits());
        let decoy_trace = simulate(&mut decoy, T0, &[], at + 1.0);
        let real_trace = simulate(&mut real, T0, &[at; 200], at + 1.0);
        let (decoy_first, _) = decoy_trace.tier_changes[0];
        let (real_first, _) = real_trace.tier_changes[0];
        assert!((decoy_first - (at + point)).abs() < 1e-9);
        assert!((real_first - (at + point)).abs() < 1e-9);
    }

    #[test]
    fn decoys_never_start_at_the_top_tier() {
        let mut s = shaper(with(|c| c.decoy_interval_s = 300.0), 27);
        s.change_tier(3, T0);
        let hold_end = s.hold_until;
        let due = T0 + 1.0;
        s.next_decoy = Some(due);
        s.poll(due, 0, 0.0, 0);
        assert_eq!(s.tier, 3);
        assert!(s.decoy_target.is_none());
        assert_eq!(s.hold_until.to_bits(), hold_end.to_bits());
        assert!(s.busy_until < due);
        assert!(s.next_decoy.expect("re-armed") > due);
    }

    /// With two tiers no tier lies between idle and the top, so there is
    /// nothing to pick from: a decoy always aims at tier 1 and climbs there.
    #[test]
    fn a_decoy_with_two_tiers_aims_at_tier_one_and_reaches_it() {
        for seed in 0..30 {
            let mut s = shaper(
                with(|c| {
                    c.tiers_pps = vec![10.0, 50.0];
                    c.decoy_interval_s = 300.0;
                }),
                seed,
            );
            // A re-pick would re-time the decoy.
            s.next_repick = f64::INFINITY;
            let due = s.next_decoy.expect("decoys are on");
            let first_point = s.step_up_after;
            s.poll(due, 0, 0.0, 0);
            assert_eq!(s.decoy_target, Some(1), "seed {seed}");
            assert_eq!(s.tier, 0, "nothing moves before the first point");
            let trace = simulate(&mut s, due, &[], due + 3.0);
            assert_eq!(trace.tier_changes.len(), 1, "one step reaches the top");
            let (at, tier) = trace.tier_changes[0];
            assert_eq!(tier, 1);
            assert!((at - (due + first_point)).abs() < 1e-9, "stepped at {at}");
            assert!(s.decoy_target.is_none(), "the climb ended");
            assert!(s.busy_until > due);
        }
    }

    #[test]
    fn secrets_differ_per_session_and_stay_in_range() {
        let mut scales = Vec::new();
        for seed in 0..200 {
            let s = shaper(with(|c| c.decoy_interval_s = 7200.0), seed);
            let k = &s.secrets;
            assert!((0.8..=1.2).contains(&k.tier_scale));
            assert!((0.3..=0.7).contains(&k.gap_spread));
            assert!((0.2..=0.5).contains(&k.overshoot_p));
            assert!((45.0..=75.0).contains(&k.hold_min_s));
            assert!((240.0..=360.0).contains(&k.hold_max_s));
            assert!((0.5..=0.8).contains(&k.decoy_top_p));
            assert!((5.0..=15.0).contains(&k.lookback_s));
            assert!((0.35..=0.65).contains(&k.usage_limit));
            assert!((3600.0..=14_400.0).contains(&k.decoy_mean_s));
            assert!((60.0..=360.0).contains(&k.busy_mean_s));
            scales.push(k.tier_scale.to_bits());
        }
        scales.sort_unstable();
        scales.dedup();
        assert_eq!(scales.len(), 200, "two sessions drew the same scale");
    }

    #[test]
    fn secrets_change_during_the_session_and_running_holds_keep_their_end() {
        let mut s = shaper(cfg(), 33);
        let repick = s.next_repick;
        assert!((600.0..=2400.0).contains(&(repick - T0)));
        let before = s.secrets.tier_scale;
        s.change_tier(2, T0);
        s.hold_until = repick + 100.0;
        s.poll(repick, 0, 0.0, 0);
        assert_ne!(s.secrets.tier_scale.to_bits(), before.to_bits());
        assert_eq!(s.hold_until.to_bits(), (repick + 100.0).to_bits());
        assert_eq!(s.tier, 2);
        assert!((600.0..=2400.0).contains(&(s.next_repick - repick)));
    }

    #[test]
    fn a_repick_retimes_the_next_decoy_and_keeps_linger_and_busy_ends() {
        let mut s = shaper(
            with(|c| {
                c.decoy_interval_s = 300.0;
                c.linger_s = (300.0, 600.0);
            }),
            57,
        );
        let repick = s.next_repick;
        let (linger_end, busy_end) = (repick + 200.0, repick + 300.0);
        // A decoy so far off that only a re-pick can bring it closer.
        let old_decoy = repick + 1.0e6;
        s.change_tier(1, T0);
        s.linger_until = Some(linger_end);
        s.busy_until = busy_end;
        s.next_decoy = Some(old_decoy);
        let before = s.secrets.tier_scale;
        s.poll(repick, 0, 0.0, 0);
        assert_ne!(s.secrets.tier_scale.to_bits(), before.to_bits());
        let decoy = s.next_decoy.expect("decoys stay on");
        assert!(
            decoy > repick && decoy < old_decoy,
            "the decoy was not re-timed"
        );
        assert_eq!(s.linger_until, Some(linger_end));
        assert_eq!(s.busy_until.to_bits(), busy_end.to_bits());
    }

    fn histogram(draw: &mut dyn FnMut() -> u16, n: u32) -> Vec<(u16, f64)> {
        let mut counts = [0_u32; SIZE_CLASSES.len()];
        for _ in 0..n {
            let c = draw();
            let i = SIZE_CLASSES
                .iter()
                .position(|&x| x == c)
                .expect("a size class");
            counts[i] += 1;
        }
        SIZE_CLASSES
            .iter()
            .zip(counts)
            .map(|(&c, k)| (c, f64::from(k) / f64::from(n)))
            .collect()
    }

    fn published_mix() -> Vec<f64> {
        let total: f64 = SIZE_CLASS_WEIGHTS.iter().map(|&w| f64::from(w)).sum();
        SIZE_CLASS_WEIGHTS
            .iter()
            .map(|&w| f64::from(w) / total)
            .collect()
    }

    #[test]
    fn real_sizes_follow_the_fixed_mix() {
        let mut s = shaper(cfg(), 43);
        let hist = histogram(&mut || s.real_size_class(4), 50_000);
        for ((class, got), want) in hist.into_iter().zip(published_mix()) {
            assert!((got - want).abs() < 0.02, "class {class}: {got} vs {want}");
        }
    }

    #[test]
    fn chaff_sizes_follow_the_perturbed_mix() {
        let base = published_mix();
        let n = base.len();
        let up = CHAFF_PERTURB_UP_P;
        let down = CHAFF_PERTURB_DOWN_P - CHAFF_PERTURB_UP_P;
        let mut want = vec![0.0; n];
        for (i, p) in base.iter().enumerate() {
            want[i] += (1.0 - up - down) * p;
            want[(i + 1).min(n - 1)] += up * p;
            want[i.saturating_sub(1)] += down * p;
        }
        let mut s = shaper(cfg(), 47);
        let hist = histogram(&mut || s.chaff_size_class(), 50_000);
        for ((class, got), want) in hist.into_iter().zip(want) {
            assert!((got - want).abs() < 0.02, "class {class}: {got} vs {want}");
        }
    }

    #[test]
    fn real_size_bumps_up_to_fit_and_never_below_the_payload() {
        let mut s = shaper(cfg(), 53);
        for _ in 0..500 {
            assert_eq!(s.real_size_class(1360), 1400);
            assert_eq!(
                s.real_size_class(1361),
                1401,
                "exact size when no class fits"
            );
        }
        for payload in [0_usize, 1, 100, 300, 700, 1100] {
            for _ in 0..200 {
                let class = usize::from(s.real_size_class(payload));
                assert!(class >= payload + PACKET_OVERHEAD);
            }
        }
    }

    #[test]
    fn padding_range_and_ceiling_limit_the_classes() {
        let mut s = shaper(
            with(|c| {
                c.padding_min = 256;
                c.padding_max = 1024;
            }),
            59,
        );
        assert_eq!(s.active_classes(), &[256, 384, 512, 640, 768, 896, 1024]);
        s.set_size_class_ceiling(512);
        assert_eq!(s.active_classes(), &[256, 384, 512]);
        for _ in 0..2000 {
            assert!(s.chaff_size_class() <= 512);
            assert!(s.real_size_class(1) <= 512);
        }
        s.set_size_class_ceiling(2000);
        assert_eq!(
            s.active_classes().last(),
            Some(&1024),
            "never above padding_max"
        );
        s.set_size_class_ceiling(1);
        assert_eq!(
            s.active_classes(),
            &[256],
            "keeps the smallest usable class"
        );
        let high = shaper(
            with(|c| {
                c.padding_min = 1450;
                c.padding_max = 1500;
            }),
            61,
        );
        assert_eq!(
            high.active_classes(),
            &[1400],
            "falls back to the largest class"
        );
    }

    /// Trace check: idle, short bursts, a long download and a steady
    /// game-like stream. Within a tier the wire never follows real traffic:
    /// every gap stays in its tier's band, so only tier changes show.
    #[test]
    fn trace_check_the_wire_follows_tiers_not_traffic() {
        let tiers = cfg().tiers_pps;
        let bursts: Vec<f64> = (0..10_u32)
            .flat_map(|b| {
                (0..20_u32).map(move |i| T0 + 5.0 + f64::from(b) * 30.0 + f64::from(i) * 0.001)
            })
            .collect();
        let download: Vec<f64> = (0..72_000_u32)
            .map(|i| T0 + 10.0 + f64::from(i) / 600.0)
            .collect();
        let game: Vec<f64> = (0..7200_u32)
            .map(|i| T0 + 10.0 + f64::from(i) / 30.0)
            .collect();
        let patterns: [(&str, &[f64]); 4] = [
            ("idle", &[]),
            ("short bursts", &bursts),
            ("long download", &download),
            ("steady game", &game),
        ];
        for (seed, (name, arrivals)) in (100_u64..).zip(patterns) {
            let mut s = shaper(cfg(), seed);
            let trace = simulate(&mut s, T0, arrivals, T0 + 300.0);
            assert_gaps_follow_tiers(&trace, &tiers);
            let longest = trace
                .departures
                .windows(2)
                .map(|p| p[1].at - p[0].at)
                .fold(0.0_f64, f64::max);
            assert!(
                longest <= 1.7 / (10.0 * 0.8) + 1e-9,
                "{name}: the wire went quiet"
            );
            match name {
                "idle" => assert_eq!(trace.tier_changes, [] as [(f64, usize); 0]),
                "long download" => {
                    assert!(
                        trace.tier_changes.iter().any(|&(_, t)| t == 3),
                        "reached the top tier"
                    );
                }
                "steady game" => {
                    // One climb at the start, at most one settle afterwards.
                    let late = trace
                        .tier_changes
                        .iter()
                        .filter(|&&(t, _)| t > T0 + 40.0 && t < T0 + 250.0)
                        .count();
                    assert!(late <= 1, "{name}: the tier flapped {late} times");
                    assert!(trace
                        .departures
                        .iter()
                        .filter(|d| d.at > T0 + 40.0 && d.at < T0 + 250.0)
                        .all(|d| d.tier >= 1));
                }
                _ => {}
            }
        }
    }

    /// Live test 2026-10-07: a download from a sender that adapts to the
    /// rate it gets, as TCP does, fills nearly every slot of tier 2, and the
    /// rate must step up.
    ///
    /// The wait rule alone never fires here. It only looks at how long the
    /// oldest queued packet has waited (0.25-0.5 s at the 0.5 s budget), and
    /// an adaptive sender never lets the queue get that long: it only puts
    /// more packets in flight when earlier ones have been delivered. Here it
    /// keeps twice the delivered rate times the round trip in flight (the
    /// in-flight cap BBR uses), so about one round trip of packets waits in
    /// the queue: 0.1 s, well under the step-up point. On the wire this
    /// matches the capture: ~99% of the tier 2 slots carried real data for
    /// 37 s and the rate stayed at tier 2. The full-tier rule climbs.
    #[test]
    fn an_adaptive_download_that_fills_a_tier_steps_up() {
        // Round trip outside the shaper queue (s): link, far end and the
        // other side's slot wait. The in-tunnel round trip in the live test
        // was about 0.03-0.05 s under load.
        const RTT: f64 = 0.1;
        let end = T0 + 30.0;
        for seed in 0..20 {
            let mut s = shaper(with(|c| c.tiers_pps = vec![10.0, 50.0, 200.0, 400.0]), seed);
            // The live server was already at tier 2 when the download began.
            s.change_tier(2, T0);
            // Arrival time of each queued packet.
            let mut queue: VecDeque<f64> = VecDeque::new();
            // When each sent packet's acknowledgement reaches the sender.
            let mut acks: VecDeque<f64> = VecDeque::new();
            // Acknowledgements received in the last second.
            let mut delivered: VecDeque<f64> = VecDeque::new();
            let mut in_flight = 0_usize;
            let mut real_sent = 0_u32;
            let (mut slots, mut real) = (0_u32, 0_u32);
            let mut longest_wait = 0.0_f64;
            let mut now = T0;
            let mut wake = T0;
            while now <= end {
                while acks.front().is_some_and(|&t| t <= now) {
                    acks.pop_front();
                    in_flight -= 1;
                    delivered.push_back(now);
                }
                while delivered.front().is_some_and(|&t| now - t > 1.0) {
                    delivered.pop_front();
                }
                // The sender queues new packets as soon as its window allows
                // (starting from 10 packets). Queuing never wakes the shaper,
                // as in the scheduler: it is polled only at its next wake.
                let window = (2.0 * count(delivered.len()) * RTT).ceil().max(10.0);
                while count(in_flight) < window {
                    queue.push_back(now);
                    in_flight += 1;
                }
                if now >= wake {
                    let oldest_wait = queue.front().map_or(0.0, |&t| now - t);
                    longest_wait = longest_wait.max(oldest_wait);
                    let poll = s.poll(now, queue.len(), oldest_wait, real_sent);
                    real_sent = 0;
                    slots += poll.slots_due;
                    for _ in 0..poll.slots_due {
                        if queue.pop_front().is_some() {
                            real_sent += 1;
                            real += 1;
                            s.real_size_class(1320);
                            acks.push_back(now + RTT);
                        } else {
                            s.chaff_size_class();
                        }
                    }
                    assert!(poll.next_wake >= now, "next_wake must not go back in time");
                    wake = poll.next_wake;
                }
                now = acks.front().map_or(wake, |&t| t.min(wake));
            }
            assert_eq!(
                s.tier,
                3,
                "seed {seed}: real packets took {:.1}% of the slots for 30 s and the \
                 oldest one waited at most {longest_wait:.3} s (step-up point 0.25-0.5 s), \
                 and the rate ended at tier {} instead of the top",
                100.0 * f64::from(real) / f64::from(slots),
                s.tier
            );
        }
    }

    /// A tier that real packets keep full for the secret window climbs one
    /// tier through the decoy climb: one step-up point after the trigger,
    /// one tier or two (overshoot), then a hold. A decoy aimed at the same
    /// tier from the same moment makes the very same step: same time, same
    /// tier, same hold. Still full, it climbs again, but only after a whole
    /// window at the new tier. The sender keeps one fresh packet queued, so
    /// every slot carries real data but none waits long enough for the wait
    /// rule.
    #[test]
    fn a_full_tier_climbs_like_a_decoy_aimed_one_tier_up() {
        for seed in 0..30 {
            let mut real = shaper(cfg(), seed);
            let mut decoy = shaper(cfg(), seed);
            for s in [&mut real, &mut decoy] {
                // A re-pick would redraw the window mid-test.
                s.next_repick = f64::INFINITY;
                s.change_tier(1, T0);
            }
            let window = real.secrets.fill_window_s;
            let point = real.step_up_after;
            let (mut now, mut sent) = (T0, 0_u32);
            let mut trigger = None;
            let mut stepped = None;
            while stepped.is_none() {
                assert!(now < T0 + 10.0, "seed {seed}: the full tier never climbed");
                let poll = real.poll(now, 1, 0.001, sent);
                sent = poll.slots_due;
                let quiet = decoy.poll(now, 0, 0.0, 0);
                if trigger.is_none() && real.decoy_target.is_some() {
                    assert_eq!(real.decoy_target, Some(2), "seed {seed}: one tier up");
                    trigger = Some(now);
                    // The decoy climb, from the same moment to the same tier.
                    decoy.start_climb(now, 2, true);
                }
                if real.tier != 1 {
                    stepped = Some(now);
                }
                now = poll.next_wake.min(quiet.next_wake);
            }
            let trigger = trigger.expect("a climb started");
            let stepped = stepped.expect("a step");
            assert!(
                trigger >= T0 + window,
                "seed {seed}: full before a whole window"
            );
            assert!(
                (stepped - (trigger + point)).abs() < 1e-9,
                "seed {seed}: stepped {} s after the trigger, not one point ({point} s)",
                stepped - trigger
            );
            assert!(real.tier == 2 || real.tier == 3, "one tier, or two");
            assert_eq!(
                decoy.tier, real.tier,
                "seed {seed}: the decoy stepped elsewhere"
            );
            assert_eq!(decoy.hold_until.to_bits(), real.hold_until.to_bits());
            let hold = real.hold_until - stepped;
            assert!((real.secrets.hold_min_s..=real.secrets.hold_max_s).contains(&hold));
            // Both climbs are over; only the decoy fakes a busy stretch.
            assert!(real.decoy_target.is_none() && decoy.decoy_target.is_none());
            assert!(
                real.busy_until < T0,
                "seed {seed}: a busy stretch after a real climb"
            );
            assert!(decoy.busy_until > stepped);
            if real.tier == 2 {
                let mut again = None;
                while real.tier == 2 {
                    assert!(now < stepped + 10.0, "seed {seed}: no second climb");
                    let poll = real.poll(now, 1, 0.001, sent);
                    sent = poll.slots_due;
                    if again.is_none() && real.decoy_target.is_some() {
                        assert_eq!(real.decoy_target, Some(3));
                        again = Some(now);
                    }
                    now = poll.next_wake;
                }
                let again = again.expect("a second climb");
                assert!(
                    again >= stepped + window,
                    "seed {seed}: climbed again before a whole window at tier 2"
                );
                assert_eq!(real.tier, 3);
            }
        }
    }

    /// Steady real traffic that takes 60-70% of the tier's slots for ten
    /// minutes never fills it: it never climbs, and every send time is the
    /// same as with the full-tier rule switched off.
    #[test]
    fn traffic_below_the_full_limit_never_climbs_or_moves_send_times() {
        let end = T0 + 600.0;
        for (seed, tier, share) in [(61, 1, 0.6), (62, 1, 0.7), (63, 2, 0.6), (64, 2, 0.7)] {
            let start = |off: bool| {
                let mut s = shaper(cfg(), seed);
                // A re-pick would redraw the switched-off limit.
                s.next_repick = f64::INFINITY;
                if off {
                    s.secrets.fill_limit = f64::INFINITY;
                }
                s.change_tier(tier, T0);
                s
            };
            let (mut on, mut off) = (start(false), start(true));
            let rate = share * on.rate_of(tier);
            let arrivals = steady(rate, end);
            let with_rule = simulate(&mut on, T0, &arrivals, end);
            let without = simulate(&mut off, T0, &arrivals, end);
            assert!(
                with_rule.tier_changes.is_empty(),
                "seed {seed}: {share} of tier {tier} changed the tier"
            );
            assert_eq!(with_rule.times(), without.times());
            let used = count(with_rule.real_count()) / count(with_rule.departures.len());
            assert!((used - share).abs() < 0.02, "seed {seed}: used {used}");
        }
    }

    /// Softening: at a hold end the rate also steps down when real use fits
    /// the lower tier with room to spare, above the old usage limit. With the
    /// live test's tiers, a steady stream at about a quarter to a third of
    /// the top tier fits tier 2: it steps down at the first hold end and
    /// stays there. At tier 2 it takes at most 70% of the slots, below any
    /// full-tier limit, so it never climbs back. With only the old limit
    /// (here at its lowest) it would have stayed at the top.
    #[test]
    fn a_stream_that_fits_the_lower_tier_steps_down_and_stays() {
        let end = T0 + 1000.0;
        for seed in 0..10 {
            let start = |fit: bool| {
                let mut s = shaper(with(|c| c.tiers_pps = vec![10.0, 50.0, 200.0, 400.0]), seed);
                // A re-pick would redraw the limits set here.
                s.next_repick = f64::INFINITY;
                s.secrets.usage_limit = USAGE_LIMIT.0;
                if !fit {
                    s.secrets.fit_limit = 0.0;
                }
                s.change_tier(3, T0);
                s
            };
            let (mut soft, mut old) = (start(true), start(false));
            let hold_end = soft.hold_until;
            let rate = 0.95 * soft.secrets.fit_limit * soft.rate_of(2);
            let arrivals = steady(rate, end);
            let softened = simulate(&mut soft, T0, &arrivals, end);
            assert_eq!(softened.tier_changes.len(), 1, "seed {seed}: flapped");
            let (at, tier) = softened.tier_changes[0];
            assert_eq!(tier, 2, "seed {seed}");
            assert!((at - hold_end).abs() < 1e-9, "seed {seed}: stepped at {at}");
            assert!(
                softened.waits.iter().all(|&w| w < 0.25),
                "seed {seed}: tier 2 did not carry the stream"
            );
            let unsoftened = simulate(&mut old, T0, &arrivals, end);
            assert!(unsoftened.tier_changes.is_empty(), "seed {seed}");
        }
    }

    /// Decoys and chaff never fill a tier: only real packets count. Two
    /// hours of decoys with no real traffic run exactly as with the
    /// full-tier rule switched off: every poll gives the same answer.
    #[test]
    fn decoys_alone_never_fill_a_tier() {
        let edit: Edit = |c| {
            c.decoy_interval_s = 300.0;
            c.linger_s = (300.0, 600.0);
        };
        let end = T0 + 2.0 * 3600.0;
        for seed in 0..3 {
            let start = |off: bool| {
                let mut s = shaper(with(edit), seed);
                // A re-pick would redraw the switched-off limit.
                s.next_repick = f64::INFINITY;
                if off {
                    s.secrets.fill_limit = f64::INFINITY;
                }
                s
            };
            let (mut on, mut off) = (start(false), start(true));
            let (mut now, mut tier, mut climbs) = (T0, 0, 0);
            while now <= end {
                let poll = on.poll(now, 0, 0.0, 0);
                assert_eq!(
                    poll,
                    off.poll(now, 0, 0.0, 0),
                    "seed {seed}: parted at {now}"
                );
                assert_eq!(on.tier, off.tier);
                if on.tier > tier {
                    climbs += 1;
                }
                tier = on.tier;
                now = poll.next_wake;
            }
            assert!(climbs >= 4, "seed {seed}: decoys ran");
        }
    }

    #[test]
    fn full_tier_and_fit_secrets_stay_in_range_and_differ_per_session() {
        let mut draws: [Vec<u64>; 3] = Default::default();
        for seed in 0..200 {
            let s = shaper(cfg(), seed);
            let k = &s.secrets;
            assert!((0.85..=0.95).contains(&k.fill_limit));
            assert!((1.0..=3.0).contains(&k.fill_window_s));
            assert!((0.5..=0.7).contains(&k.fit_limit));
            // What fits the lower tier can never fill it.
            assert!(k.fit_limit < k.fill_limit);
            for (all, value) in draws
                .iter_mut()
                .zip([k.fill_limit, k.fill_window_s, k.fit_limit])
            {
                all.push(value.to_bits());
            }
        }
        for mut all in draws {
            all.sort_unstable();
            all.dedup();
            assert_eq!(all.len(), 200, "two sessions drew the same value");
        }
    }
}
