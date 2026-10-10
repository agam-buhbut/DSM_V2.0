//! Header protection (wire v2): one AES-256 block hides the first 16 bytes of
//! every data packet, the seq, the nonce epoch and the nonce counter. One
//! `HeaderKey` per direction per key set, stored next to its AEAD key in
//! `session_keys.rs`, so it lives and dies with that key.

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;

use crate::secure_memory::LockedKey32;

/// One direction's header key: the raw AES-256 block cipher on exactly 16
/// bytes, no mode, no padding.
///
/// The 32 key bytes sit in a `LockedKey32` (locked in memory, wiped on drop).
/// The expanded round keys sit in `aes::Aes256` inside this struct, outside
/// locked memory (about 0.5 KB with AES-NI); the `aes` crate's `zeroize`
/// feature, on in `Cargo.toml`, wipes them on drop. A move of the struct can
/// leave an old copy that is not wiped (as with `AesKey`). Fields drop in
/// order: the round keys first, then the locked key bytes.
pub struct HeaderKey {
    cipher: Aes256,
    _key: LockedKey32,
}

impl HeaderKey {
    pub fn from_locked(key: LockedKey32) -> Self {
        let cipher = Aes256::new(GenericArray::from_slice(key.as_array()));
        Self { cipher, _key: key }
    }

    /// AES-256-encrypt one block: what the sender puts on the wire.
    pub fn protect(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut b = GenericArray::clone_from_slice(block);
        self.cipher.encrypt_block(&mut b);
        let mut out = [0u8; 16];
        out.copy_from_slice(&b);
        out
    }

    /// AES-256-decrypt one block: what the receiver reads back. Any 16 bytes
    /// decrypt to something; the caller checks the epoch.
    pub fn unprotect(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut b = GenericArray::clone_from_slice(block);
        self.cipher.decrypt_block(&mut b);
        let mut out = [0u8; 16];
        out.copy_from_slice(&b);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::RngCore;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn key_from(bytes: [u8; 32]) -> HeaderKey {
        HeaderKey::from_locked(LockedKey32::from_array(bytes).unwrap())
    }

    /// Spec §16.1 test 1, vector VH1 (§16.3): key 00..1f, seq 1,
    /// epoch 0x01234567, counter 1.
    #[test]
    fn vh1_known_answer() {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = i as u8;
        }
        let key = key_from(k);
        let block_in: [u8; 16] = unhex("00000000000000010123456700000001")
            .try_into()
            .unwrap();
        let block_out = key.protect(&block_in);
        assert_eq!(
            block_out.to_vec(),
            unhex("2bac181b9b28b24c91fc508da5d7baa5")
        );
        assert_eq!(key.unprotect(&block_out), block_in);
    }

    /// Spec §16.1 test 2.
    #[test]
    fn unprotect_undoes_protect_and_two_keys_differ() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut a);
        OsRng.fill_bytes(&mut b);
        let (ka, kb) = (key_from(a), key_from(b));
        for _ in 0..1000 {
            let mut block = [0u8; 16];
            OsRng.fill_bytes(&mut block);
            assert_eq!(ka.unprotect(&ka.protect(&block)), block);
            assert_ne!(ka.protect(&block), kb.protect(&block));
        }
    }

    /// Spec §16.1 test 3 (H6): this does not compile unless the `aes`
    /// crate's `zeroize` feature is on, so the round keys are wiped on drop.
    #[test]
    fn round_keys_are_wiped_on_drop() {
        fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        wipes_on_drop::<Aes256>();
    }
}
