//! Zeroize-on-drop, mlock'd `Dh` implementation for `snow`.
//!
//! `snow`'s default `Dh25519` stores its 32-byte X25519 private scalar in a
//! plain `[u8; 32]` field on the heap with no `Zeroize` or `Drop` impl. When
//! the `HandshakeState` is consumed by `into_transport_mode` the
//! allocation is returned to the system allocator with the scalar bytes
//! still in place — readable until that slot is reused. On a host with
//! unencrypted swap the scalar can also be paged out during the handshake
//! window and survive on disk after the process exits.
//!
//! The static Noise private key is the *long-lived* identity scalar (it
//! re-enters memory every handshake when `IdentityKeyPair::secret_key` is
//! handed to snow), so leaking it through this slot would let a same-uid
//! attacker recover the device identity post-mortem.
//!
//! This module replaces snow's `Dh25519` with `SecureDh25519`, which keeps
//! the scalar in a [`LockedKey32`] — mlock'd to prevent swap and zeroized
//! by `Box<Zeroizing<[u8; 32]>>` on drop. The remaining primitives (cipher,
//! hash, RNG) are delegated to snow's `DefaultResolver` so the cipher-suite
//! choice is unchanged.
//!
//! Construction is `Box<dyn Dh>` so snow's `HandshakeState` keeps the value
//! at a stable heap address; the inner `LockedKey32` is a separate `Box`
//! so the locked page is independent of any movement of the outer struct.

use snow::params::{CipherChoice, DHChoice, HashChoice};
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::{Cipher, Dh, Hash, Random};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::secure_memory::LockedKey32;

/// X25519 Diffie-Hellman with mlock'd, zeroize-on-drop private scalar.
pub struct SecureDh25519 {
    /// The mlock'd 32-byte scalar buffer. Allocated eagerly in
    /// `Default::default()` so the only fallible syscall (`mlock`) happens
    /// at the moment snow's `CryptoResolver::resolve_dh` constructs the
    /// instance — before snow has built any handshake state. A failure
    /// there panics out of `NoiseInitiator::new` / `NoiseResponder::new`
    /// at a recoverable point; the PyO3 layer turns the panic into a
    /// Python exception.
    secret: LockedKey32,
    pubkey: [u8; 32],
    /// Sticky failure flag. Set when `Dh::set` is invoked with a
    /// wrong-length privkey: the trait signature has no `Result`, so the
    /// only safe recovery is to mark the instance permanently unusable.
    /// Once `true`, `dh()` returns `Err(snow::Error::Dh)` and the surrounding
    /// handshake aborts via snow's normal error channel. This prevents a
    /// partially-zeroed or truncated scalar from ever being used as a
    /// (weak-by-construction) X25519 key.
    poisoned: bool,
}

impl Default for SecureDh25519 {
    fn default() -> Self {
        // Pre-allocate the locked buffer here rather than lazily on first
        // `set()` / `generate()`. Two reasons:
        //   1. snow's `CryptoResolver::resolve_dh` callback runs before any
        //      handshake state is established; panicking here unwinds
        //      cleanly out of `Builder::build_initiator()` /
        //      `build_responder()` without leaving snow in a half-built
        //      cryptographic state.
        //   2. Removes the `Option<LockedKey32>` + `unwrap()` pattern from
        //      the hot path so `set()` and `dh()` no longer have to consider
        //      a None-secret edge case.
        //
        // mlock failure here means the process cannot get a locked page
        // (RLIMIT_MEMLOCK exhausted or kernel refusal). The PyO3 layer
        // converts the panic into a Python exception.
        let secret = LockedKey32::zeroed()
            .expect(
                "LockedKey32 allocation failed inside SecureDh25519::default \
                 — RLIMIT_MEMLOCK exhausted or out of memory",
            );
        Self {
            secret,
            pubkey: [0u8; 32],
            poisoned: false,
        }
    }
}

impl SecureDh25519 {
    fn derive_pubkey(&mut self) {
        // StaticSecret::from copies the 32 bytes into a fresh stack value;
        // its `ZeroizeOnDrop` impl scrubs that copy when the local goes
        // out of scope at the end of this function.
        let s = StaticSecret::from(*self.secret.as_array());
        self.pubkey = *PublicKey::from(&s).as_bytes();
    }

    /// Mark this Dh instance as permanently unusable and wipe any
    /// scalar bytes that may have been partially written. Called from
    /// `set()` when the input length doesn't match the protocol-required
    /// 32 bytes.
    fn poison(&mut self) {
        self.poisoned = true;
        // Even though the only way to reach `poison()` from `set` is the
        // wrong-length branch (where we never wrote into `secret`), wiping
        // here is cheap defense-in-depth in case future edits to `set`
        // partially populate the buffer before discovering the length
        // problem.
        self.secret.as_mut().zeroize();
        self.pubkey = [0u8; 32];
    }
}

impl Dh for SecureDh25519 {
    fn name(&self) -> &'static str {
        "25519"
    }

    fn pub_len(&self) -> usize {
        32
    }

    fn priv_len(&self) -> usize {
        32
    }

    fn set(&mut self, privkey: &[u8]) {
        // snow today always invokes `set` with exactly `priv_len()` = 32
        // bytes. The Dh trait signature has no Result channel, so the
        // safe response to an unexpected length is to mark this instance
        // poisoned and let `dh()` refuse to operate — rather than silently
        // zero-padding or truncating and ending up with a weak key.
        if privkey.len() != 32 {
            self.poison();
            return;
        }
        self.secret.as_mut().copy_from_slice(privkey);
        self.derive_pubkey();
    }

    fn generate(&mut self, rng: &mut dyn Random) {
        rng.fill_bytes(self.secret.as_mut());
        self.derive_pubkey();
    }

    fn pubkey(&self) -> &[u8] {
        &self.pubkey
    }

    fn privkey(&self) -> &[u8] {
        // Snow uses this to round-trip the scalar. We always return the
        // mlock'd buffer (which may be all-zero pre-`set`, or wiped if
        // poisoned). The poison flag fences the actual cryptographic
        // operation in `dh`; we don't need to vary this return.
        self.secret.as_array()
    }

    fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), snow::Error> {
        if self.poisoned {
            return Err(snow::Error::Dh);
        }
        if pubkey.len() < 32 || out.len() < 32 {
            return Err(snow::Error::Dh);
        }
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pubkey[..32]);

        // Build a fresh StaticSecret per call so the dalek-side scalar
        // copy is short-lived and ZeroizeOnDrop scrubs it at end-of-scope.
        let s = StaticSecret::from(*self.secret.as_array());
        let shared = s.diffie_hellman(&PublicKey::from(pk_arr));

        // Reject low-order points: a non-contributory shared secret would
        // hand snow a known/zero key. snow itself does not perform this
        // check, so the safer Dh impl does it here.
        if !shared.was_contributory() {
            return Err(snow::Error::Dh);
        }
        out[..32].copy_from_slice(shared.as_bytes());
        Ok(())
    }
}

/// Snow `CryptoResolver` that uses [`SecureDh25519`] for X25519 and
/// delegates every other primitive (cipher, hash, RNG, KEM) to snow's
/// `DefaultResolver` — keeping the ciphersuite identical to the prior
/// `Noise_XX_25519_AESGCM_SHA256` instantiation.
pub struct SecureResolver {
    inner: DefaultResolver,
}

impl SecureResolver {
    pub fn new() -> Self {
        Self { inner: DefaultResolver }
    }
}

impl Default for SecureResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoResolver for SecureResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        self.inner.resolve_rng()
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        match choice {
            DHChoice::Curve25519 => Some(Box::new(SecureDh25519::default())),
            // Any other DH (currently none in the standard Noise spec)
            // falls back to the default resolver, which will return None
            // and propagate the unknown-primitive error to snow.
            _ => self.inner.resolve_dh(choice),
        }
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        self.inner.resolve_hash(choice)
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        self.inner.resolve_cipher(choice)
    }

    // `resolve_kem` is gated behind snow's `hfs` feature, which we do not
    // enable; the trait's default impl returns None and is sufficient.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_dh_set_then_pubkey_matches_x25519_dalek() {
        let mut dh = SecureDh25519::default();
        let priv_bytes = [
            0x42u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 0x99,
        ];
        dh.set(&priv_bytes);

        let expected = *PublicKey::from(&StaticSecret::from(priv_bytes)).as_bytes();
        assert_eq!(dh.pubkey(), &expected);
        assert_eq!(dh.privkey(), &priv_bytes);
    }

    #[test]
    fn secure_dh_generate_produces_random_keys() {
        // Use snow's own DefaultResolver to supply a CryptoRng+RngCore that
        // already satisfies the `Random` trait bound — building a hand-rolled
        // wrapper that re-implements `CryptoRng` is unnecessary friction.
        let resolver = DefaultResolver;
        let mut a = SecureDh25519::default();
        let mut b = SecureDh25519::default();
        let mut rng_a = resolver.resolve_rng().expect("rng");
        let mut rng_b = resolver.resolve_rng().expect("rng");
        a.generate(&mut *rng_a);
        b.generate(&mut *rng_b);
        assert_ne!(a.privkey(), b.privkey());
        assert_ne!(a.pubkey(), b.pubkey());
    }

    #[test]
    fn secure_dh_roundtrip_matches_peer() {
        // Manually do an X25519 exchange between two SecureDh25519
        // instances and confirm both sides compute the same shared.
        let alice_priv = [0x11u8; 32];
        let bob_priv = [0x22u8; 32];

        let mut alice = SecureDh25519::default();
        let mut bob = SecureDh25519::default();
        alice.set(&alice_priv);
        bob.set(&bob_priv);

        let mut s_ab = [0u8; 32];
        let mut s_ba = [0u8; 32];
        alice.dh(bob.pubkey(), &mut s_ab).unwrap();
        bob.dh(alice.pubkey(), &mut s_ba).unwrap();
        assert_eq!(s_ab, s_ba);
    }

    #[test]
    fn secure_dh_rejects_low_order_pub() {
        let mut alice = SecureDh25519::default();
        alice.set(&[0x33u8; 32]);
        let mut out = [0u8; 32];
        // All-zeros peer pub → non-contributory shared secret → reject.
        let res = alice.dh(&[0u8; 32], &mut out);
        assert!(res.is_err(), "low-order peer pub must be rejected");
    }

    #[test]
    fn secure_dh_wrong_length_set_poisons_instance() {
        // snow always passes 32 bytes, but the Dh trait signature accepts
        // any &[u8]. The previous implementation silently zero-padded
        // short input, producing a weak (predictable) scalar. The
        // hardened impl marks the instance poisoned so `dh` refuses.
        let mut dh = SecureDh25519::default();
        let too_short = [0xABu8; 16];
        dh.set(&too_short);

        // After a poisoned `set`, `dh` must refuse to operate regardless
        // of the peer pubkey provided.
        let mut out = [0u8; 32];
        let res = dh.dh(&[0x44u8; 32], &mut out);
        assert!(res.is_err(), "poisoned Dh must not produce a shared secret");

        // The pubkey must NOT reflect a derivation from the truncated
        // scalar (which would publicly fingerprint the malformed input).
        assert_eq!(dh.pubkey(), &[0u8; 32]);
    }

    #[test]
    fn secure_dh_wrong_length_set_then_correct_set_stays_poisoned() {
        // Poisoning is sticky: even if a later `set` provides a correct
        // 32-byte scalar, the instance stays poisoned. Snow's flow does
        // not re-`set` after construction in practice, but if it ever
        // does, recovery would require the caller to construct a fresh
        // Dh — not silently un-poison this one.
        let mut dh = SecureDh25519::default();
        dh.set(&[0u8; 8]); // poisons
        dh.set(&[0x77u8; 32]); // would otherwise be a valid set

        let mut out = [0u8; 32];
        assert!(
            dh.dh(&[0x44u8; 32], &mut out).is_err(),
            "instance must remain poisoned across subsequent valid `set` calls"
        );
    }

    #[test]
    fn secure_dh_set_then_zeroized_secret_does_not_leak_old_bytes() {
        // After a valid `set`, the scalar lives in the mlock'd buffer.
        // Poisoning via a follow-up wrong-length `set` must scrub the
        // previously-stored scalar so a later `privkey()` cannot leak
        // what was there before.
        let mut dh = SecureDh25519::default();
        dh.set(&[0x55u8; 32]);
        assert_eq!(dh.privkey(), &[0x55u8; 32]);

        dh.set(&[0u8; 4]); // poisons + scrubs
        assert_eq!(
            dh.privkey(),
            &[0u8; 32],
            "poisoning must scrub the previously-stored scalar"
        );
    }
}
