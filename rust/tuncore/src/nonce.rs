use rand::RngCore;
use std::sync::atomic::{AtomicU32, Ordering};

/// Structured 96-bit nonce: epoch(32) || counter(32) || random(32).
///
/// Counter guarantees uniqueness within an epoch.
/// Random portion prevents predictability.
/// Epoch separates key rotation periods.
pub struct NonceGenerator {
    epoch: u32,
    counter: AtomicU32,
}

impl NonceGenerator {
    pub fn new(epoch: u32) -> Self {
        Self {
            epoch,
            counter: AtomicU32::new(1), // 0 is reserved / never valid
        }
    }

    /// Generate the next unique 96-bit nonce.
    /// Returns None if the counter would overflow (signals key rotation needed).
    pub fn next(&self) -> Option<[u8; 12]> {
        let count = self.counter.fetch_add(1, Ordering::SeqCst);
        if count == 0 || count == u32::MAX {
            return None; // overflow or wrapped
        }

        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&self.epoch.to_be_bytes());
        nonce[4..8].copy_from_slice(&count.to_be_bytes());

        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut nonce[8..12]);

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
}
