/// Sliding window replay protection using a 128-bit bitmap.
///
/// Tracks which sequence numbers have been seen within the window.
/// Rejects duplicates and sequence numbers that fall behind the window.
pub struct ReplayWindow {
    /// Highest sequence number accepted so far.
    max_seq: u64,
    /// Bitmap covering [max_seq - WINDOW_SIZE + 1 .. max_seq].
    /// Bit 0 = max_seq, bit 1 = max_seq - 1, etc.
    bitmap: u128,
}

impl ReplayWindow {
    pub const WINDOW_SIZE: u64 = 128;

    pub fn new() -> Self {
        Self {
            max_seq: 0,
            bitmap: 0,
        }
    }

    /// Check a sequence number and mark it as seen if valid.
    /// Returns true if the packet should be accepted.
    /// Returns false if replayed or too old.
    pub fn check_and_update(&mut self, seq: u64) -> bool {
        if seq == 0 {
            return false; // 0 is never valid
        }

        if self.max_seq == 0 {
            // First packet
            self.max_seq = seq;
            self.bitmap = 1;
            return true;
        }

        if seq > self.max_seq {
            let shift = seq - self.max_seq;
            if shift >= Self::WINDOW_SIZE {
                self.bitmap = 1;
            } else {
                self.bitmap = self.bitmap.checked_shl(shift as u32).unwrap_or(0);
                self.bitmap |= 1;
            }
            self.max_seq = seq;
            true
        } else {
            let diff = self.max_seq - seq;
            if diff >= Self::WINDOW_SIZE {
                return false; // too old
            }
            let bit = 1u128 << diff;
            if self.bitmap & bit != 0 {
                return false; // replay
            }
            self.bitmap |= bit;
            true
        }
    }

    pub fn max_seq(&self) -> u64 {
        self.max_seq
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sequential_accept() {
        let mut w = ReplayWindow::new();
        for i in 1..=200 {
            assert!(w.check_and_update(i), "seq {i} should be accepted");
        }
    }

    #[test]
    fn test_reject_zero() {
        let mut w = ReplayWindow::new();
        assert!(!w.check_and_update(0));
    }

    #[test]
    fn test_reject_duplicate() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(5));
        assert!(!w.check_and_update(5));
    }

    #[test]
    fn test_accept_out_of_order_within_window() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(100));
        assert!(w.check_and_update(90)); // within window (diff=10 < 128)
        assert!(w.check_and_update(95));
        // But not duplicates
        assert!(!w.check_and_update(90));
        assert!(!w.check_and_update(95));
    }

    #[test]
    fn test_reject_too_old() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(200));
        // 200 - 50 = 150, diff = 150 >= 128
        assert!(!w.check_and_update(50));
    }

    #[test]
    fn test_window_boundary() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(128));
        // Exactly at window edge: diff = 128 - 1 = 127 < 128
        assert!(w.check_and_update(1));
        // One past: diff = 128 - 0 = 128, but 0 is invalid anyway
        // Test with diff exactly = WINDOW_SIZE
        assert!(w.check_and_update(256));
        // 256 - 128 = 128 >= WINDOW_SIZE
        assert!(!w.check_and_update(128));
    }

    #[test]
    fn test_large_jump_forward() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(1));
        assert!(w.check_and_update(10000));
        // Old packet far behind
        assert!(!w.check_and_update(1));
        // New sequential
        assert!(w.check_and_update(10001));
    }

    #[test]
    fn test_first_packet_any_value() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_update(999999));
        assert_eq!(w.max_seq(), 999999);
    }
}
