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
    pub fn next(&self) -> Option<[u8; 12]> {
        if self.exhausted.load(Ordering::SeqCst) {
            return None;
        }

        let count = self.counter.fetch_add(1, Ordering::SeqCst);
        // count is the value BEFORE increment.
        // - count == u32::MAX means we're about to wrap to 0 → exhausted
        // - count == 0 means a previous fetch_add already wrapped the counter;
        //   poison permanently so subsequent calls cannot reissue used values
        if count >= u32::MAX || count == 0 {
            self.exhausted.store(true, Ordering::SeqCst);
            return None;
        }

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
