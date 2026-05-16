use rand::rngs::OsRng;
use rand::RngCore;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Structured 96-bit nonce: epoch(32) || counter(32) || random(32).
///
/// Counter guarantees uniqueness within an epoch.
/// Random portion prevents predictability.
/// Epoch separates key rotation periods.
pub struct NonceGenerator {
    epoch: u32,
    counter: AtomicU32,
    // Latches to true the first time the counter reaches its upper bound.
    // Without this, a wrapped fetch_add would re-issue counter=1 and cause
    // catastrophic AES-GCM nonce reuse if the caller kept invoking next()
    // past the exhaustion error.
    exhausted: AtomicBool,
}

impl NonceGenerator {
    pub fn new(epoch: u32) -> Self {
        Self {
            epoch,
            counter: AtomicU32::new(1), // 0 is reserved / never valid
            exhausted: AtomicBool::new(false),
        }
    }

    /// Generate the next unique 96-bit nonce.
    /// Returns None if the counter has exhausted (signals key rotation needed).
    /// Counter starts at 1; value 0 is reserved and never used as a valid count.
    ///
    /// Concurrency: a naive `fetch_add` can re-issue used counts under a
    /// concurrent wrap (T1 fetches MAX, T2 fetches 0 → wraps counter to 1,
    /// T3 fetches 1 and is *not* caught by the post-add check). The CAS
    /// loop below atomically transitions only from values that are safe to
    /// hand out — `counter < u32::MAX` — and latches `exhausted` at every
    /// other transition so re-entries observe the poisoned state.
    pub fn next(&self) -> Option<[u8; 12]> {
        if self.exhausted.load(Ordering::SeqCst) {
            return None;
        }

        let count = loop {
            let current = self.counter.load(Ordering::SeqCst);
            // Refuse to issue from a wrapped (0) or saturated (MAX) state.
            // The CAS below is the single point that hands out a count.
            if current == 0 || current == u32::MAX {
                self.exhausted.store(true, Ordering::SeqCst);
                return None;
            }
            // `current + 1` cannot overflow: current < u32::MAX here.
            let next = current + 1;
            match self.counter.compare_exchange(
                current,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break current,
                Err(_) => {
                    // Lost the race; retry. A concurrent thread either took
                    // a count or saw exhaustion — the loop re-checks both.
                    if self.exhausted.load(Ordering::SeqCst) {
                        return None;
                    }
                }
            }
        };

        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.epoch.to_be_bytes());
        nonce[4..8].copy_from_slice(&count.to_be_bytes());

        OsRng.fill_bytes(&mut nonce[8..12]);

        Some(nonce)
    }

    /// Return the current counter value (number of nonces generated).
    pub fn count(&self) -> u32 {
        self.counter.load(Ordering::SeqCst).saturating_sub(1)
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_nonce_uniqueness() {
        let gen = NonceGenerator::new(1);
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            let nonce = gen.next().unwrap();
            assert!(seen.insert(nonce), "duplicate nonce detected");
        }
    }

    #[test]
    fn test_nonce_epoch_encoded() {
        let gen = NonceGenerator::new(42);
        let nonce = gen.next().unwrap();
        let epoch = u32::from_be_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
        assert_eq!(epoch, 42);
    }

    #[test]
    fn test_nonce_counter_increments() {
        let gen = NonceGenerator::new(1);
        let n1 = gen.next().unwrap();
        let n2 = gen.next().unwrap();
        let c1 = u32::from_be_bytes([n1[4], n1[5], n1[6], n1[7]]);
        let c2 = u32::from_be_bytes([n2[4], n2[5], n2[6], n2[7]]);
        assert_eq!(c2, c1 + 1);
    }

    #[test]
    fn test_nonce_random_portion_varies() {
        let gen = NonceGenerator::new(1);
        let n1 = gen.next().unwrap();
        let n2 = gen.next().unwrap();
        // Random portions should differ (with overwhelming probability)
        assert_ne!(&n1[8..12], &n2[8..12]);
    }

    #[test]
    fn test_count_tracking() {
        let gen = NonceGenerator::new(0);
        assert_eq!(gen.count(), 0);
        gen.next().unwrap();
        assert_eq!(gen.count(), 1);
        gen.next().unwrap();
        assert_eq!(gen.count(), 2);
    }

    #[test]
    fn test_concurrent_wrap_no_nonce_reuse() {
        // Regression for the multi-threaded variant of the wrap bug. Before
        // the CAS loop, a raw fetch_add could let T1 fetch u32::MAX while
        // T2 fetched 0 (wrapping the counter to 1) and T3 fetched 1 (with
        // count=1 surviving the post-add check). The CAS only transitions
        // from values < u32::MAX, so once any thread sees MAX it latches
        // `exhausted` and no further `next()` produces a count <= MAX-1.
        use std::sync::Arc;
        use std::sync::atomic::AtomicU32;
        use std::thread;

        let gen = Arc::new(NonceGenerator::new(11));
        // Pre-warm a single nonce so we know count=1 was issued ONCE; any
        // duplicate count=1 from the threaded section would be a reuse.
        let first = gen.next().unwrap();

        // Position the counter one short of exhaustion. The threaded loop
        // then competes for the last legitimate transition (current=MAX-1
        // → counter=MAX) and the latching transition (current=MAX → None).
        gen.counter.store(u32::MAX - 1, Ordering::SeqCst);

        let n_threads = 16;
        let attempts_per_thread = 1000u32;
        let total_some = Arc::new(AtomicU32::new(0));

        let mut handles = Vec::with_capacity(n_threads);
        for _ in 0..n_threads {
            let gen = gen.clone();
            let total_some = total_some.clone();
            handles.push(thread::spawn(move || {
                let mut local: Vec<u32> = Vec::new();
                for _ in 0..attempts_per_thread {
                    if let Some(n) = gen.next() {
                        let c = u32::from_be_bytes([n[4], n[5], n[6], n[7]]);
                        local.push(c);
                        total_some.fetch_add(1, Ordering::SeqCst);
                    }
                }
                local
            }));
        }

        let mut all_counts: Vec<u32> = Vec::new();
        for h in handles {
            all_counts.extend(h.join().unwrap());
        }

        // At most ONE thread should have gotten a Some — the one that won
        // the CAS on counter=MAX-1 → MAX. Every other call must observe
        // exhaustion and return None.
        assert!(
            all_counts.len() <= 1,
            "expected ≤1 Some across all threads, got {}: {:?}",
            all_counts.len(),
            all_counts
        );
        if let Some(c) = all_counts.first() {
            assert_eq!(
                *c,
                u32::MAX - 1,
                "the surviving count must be the value at the CAS frontier"
            );
            // And it must NOT collide with the warm-up nonce's count.
            let first_count = u32::from_be_bytes([first[4], first[5], first[6], first[7]]);
            assert_ne!(*c, first_count);
        }
        // The generator must be permanently exhausted now.
        for _ in 0..8 {
            assert!(gen.next().is_none());
        }
    }

    #[test]
    fn test_property_no_duplicate_counts_under_contention() {
        // Property: across many threads concurrently calling `next()`
        // from a fresh generator, the returned counter portions are all
        // distinct. The previous fetch_add-based implementation could
        // re-issue a count under concurrent wrap; the CAS loop now
        // forbids it. We DON'T pre-position the counter near MAX here;
        // this test is the "normal contention" sibling of the existing
        // `test_concurrent_wrap_no_nonce_reuse` (which is the "edge of
        // exhaustion" version).
        use std::collections::HashSet;
        use std::sync::Arc;
        use std::sync::Mutex;
        use std::thread;

        let gen = Arc::new(NonceGenerator::new(99));
        let collected: Arc<Mutex<HashSet<u32>>> = Arc::new(Mutex::new(HashSet::new()));

        let n_threads = 32;
        let per_thread = 500usize;
        let mut handles = Vec::with_capacity(n_threads);
        for _ in 0..n_threads {
            let gen = gen.clone();
            let collected = collected.clone();
            handles.push(thread::spawn(move || {
                let mut local: Vec<u32> = Vec::with_capacity(per_thread);
                for _ in 0..per_thread {
                    if let Some(n) = gen.next() {
                        let c = u32::from_be_bytes([n[4], n[5], n[6], n[7]]);
                        local.push(c);
                    }
                }
                let mut guard = collected.lock().unwrap();
                for c in local {
                    assert!(
                        guard.insert(c),
                        "counter {c} was issued more than once under contention"
                    );
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let guard = collected.lock().unwrap();
        // Every accepted nonce produced a unique counter; total count
        // is bounded by per_thread * n_threads but may be lower if any
        // thread observed exhaustion. From a fresh generator with
        // 16_000 attempts and a u32 counter starting at 1, we should
        // see exactly 16_000 unique counters.
        assert_eq!(guard.len(), n_threads * per_thread);
    }

    #[test]
    fn test_property_random_starting_state_no_reuse() {
        // Property: placing the counter at random points across its
        // range and then running a burst of `next()` must never reissue
        // the same counter. Specifically tests the CAS loop's behavior
        // near the wrap boundary across a range of starting positions.
        use rand::rngs::OsRng;
        use rand::RngCore;
        use std::collections::HashSet;

        for _ in 0..16 {
            let gen = NonceGenerator::new(0);
            // Random starting counter in [1, u32::MAX-1] so wrap is
            // possible but not the first call. u32::MAX itself would
            // immediately latch exhaustion; u32::MAX-1 leaves exactly
            // one legitimate CAS.
            let mut rng_bytes = [0u8; 4];
            OsRng.fill_bytes(&mut rng_bytes);
            let start = (u32::from_be_bytes(rng_bytes) % (u32::MAX - 2)) + 1;
            gen.counter.store(start, Ordering::SeqCst);

            let mut seen = HashSet::new();
            for _ in 0..1024 {
                if let Some(n) = gen.next() {
                    let c = u32::from_be_bytes([n[4], n[5], n[6], n[7]]);
                    assert!(
                        seen.insert(c),
                        "counter {c} reissued from starting position {start}"
                    );
                }
            }
        }
    }

    #[test]
    fn test_exhaustion_is_sticky_no_nonce_reuse() {
        // Regression: when the atomic counter hits u32::MAX the raw fetch_add
        // would wrap through 0 back to 1 on subsequent calls and hand out a
        // nonce equal to the generator's very first output. Verify the
        // generator latches into the exhausted state instead.
        let gen = NonceGenerator::new(7);
        let first = gen.next().unwrap();

        // Jump the counter to u32::MAX so the next fetch_add wraps.
        gen.counter.store(u32::MAX, Ordering::SeqCst);
        assert!(gen.next().is_none(), "MAX call must not yield a nonce");

        // After wrap, further calls must stay exhausted and never emit the
        // nonce that reuses count=1.
        for _ in 0..4 {
            assert!(gen.next().is_none(), "post-exhaustion must stay None");
        }

        // And the first nonce is still unique — nothing reissued it.
        let gen2 = NonceGenerator::new(7);
        let first_again = gen2.next().unwrap();
        // Epoch and counter bytes match by construction; the random tail must
        // still differ with overwhelming probability (sanity check).
        assert_eq!(&first[0..8], &first_again[0..8]);
        // But we specifically never reissued `first` from the exhausted gen.
        assert!(gen.next().is_none());
    }
}
