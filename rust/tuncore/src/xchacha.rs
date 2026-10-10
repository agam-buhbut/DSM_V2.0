//! XChaCha20-Poly1305 seal and open for the wire v2 cookie reply (spec §7.3).
//! The key is the handshake gate's cookie key, which Python makes from the CA
//! certificate and the server's name; it is low value and lives in Python.
//! The cipher is the one `passphrase_store.rs` already uses.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;

fn cipher(key: &[u8]) -> Result<XChaCha20Poly1305, String> {
    if key.len() != KEY_LEN {
        return Err(format!(
            "XChaCha20-Poly1305 key must be {KEY_LEN} bytes, got {}",
            key.len()
        ));
    }
    XChaCha20Poly1305::new_from_slice(key).map_err(|e| format!("XChaCha20-Poly1305 key: {e}"))
}

/// Seal `plaintext`; returns the ciphertext and its 16-byte tag.
///
/// # Errors
/// A key that is not 32 bytes or a nonce that is not 24 bytes (programming
/// errors: both are ours).
pub fn seal(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = cipher(key)?;
    if nonce.len() != NONCE_LEN {
        return Err(format!(
            "XChaCha20-Poly1305 nonce must be {NONCE_LEN} bytes, got {}",
            nonce.len()
        ));
    }
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| format!("XChaCha20-Poly1305 seal: {e}"))
}

/// Open `ciphertext` (with its tag). `Ok(None)` when it does not open,
/// including a nonce of the wrong length: the nonce and the ciphertext come
/// from the peer.
///
/// # Errors
/// A key that is not 32 bytes (a programming error).
pub fn open(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Option<Vec<u8>>, String> {
    let cipher = cipher(key)?;
    if nonce.len() != NONCE_LEN {
        return Ok(None);
    }
    Ok(cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Spec §16.1 test 15: round trip; a wrong AAD, key or nonce gives None.
    #[test]
    fn round_trip_and_refusals() {
        let key = [7u8; KEY_LEN];
        let nonce = [9u8; NONCE_LEN];
        let sealed = seal(&key, &nonce, b"sixteen byte msg", b"aad").unwrap();
        assert_eq!(sealed.len(), 32);
        assert_eq!(
            open(&key, &nonce, &sealed, b"aad").unwrap().unwrap(),
            b"sixteen byte msg"
        );
        assert!(open(&key, &nonce, &sealed, b"bad").unwrap().is_none());
        assert!(open(&[8u8; KEY_LEN], &nonce, &sealed, b"aad")
            .unwrap()
            .is_none());
        assert!(open(&key, &[1u8; NONCE_LEN], &sealed, b"aad")
            .unwrap()
            .is_none());
        assert!(open(&key, &nonce[..23], &sealed, b"aad").unwrap().is_none());
        // Shorter than the tag: peer bytes, so None, never an error.
        assert!(open(&key, &nonce, &sealed[..15], b"aad").unwrap().is_none());
        assert!(seal(&key[..31], &nonce, b"x", b"").is_err());
        assert!(seal(&key, &nonce[..23], b"x", b"").is_err());
        assert!(open(&key[..31], &nonce, &sealed, b"aad").is_err());
    }

    /// Vector VC1 (spec §16.3): the cookie reply seal.
    #[test]
    fn vc1_cookie_reply() {
        let key = unhex("9277df7c0c97b8aeb1264a8500393c210c6cf3acd2770011f60045bb666dd289");
        let nonce = unhex("303132333435363738393a3b3c3d3e3f4041424344454647");
        let cookie = unhex("b1db5839f9fd47f550c7fb7ecc003ab7");
        let mac1 = unhex("7e514bf08f7358048433fedb4b9c47f7");
        assert_eq!(
            seal(&key, &nonce, &cookie, &mac1).unwrap(),
            unhex("e71df6741aad7dd6b0fbb156ebcfc17bfd3310e8d1d75cfe09903429e604ebb6")
        );
    }
}
