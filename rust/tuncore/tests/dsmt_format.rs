//! TPM-free tests for the `DSMT` context-blob format. No swtpm required.
//!
//! Mirrors `passphrase_store`'s DSMK discipline: magic + version +
//! bounds-checked parse with typed rejection of every tampered header byte
//! and every structural truncation. Pure bytes — fully deterministic, runs
//! under either feature build (the module has no TPM dependency).
//!
//! Layout under test:
//! `magic "DSMT"(4) | version 0x01(1) | hierarchy(1) | key_kind(1) |
//!  curve(1) | pub_len(2 BE) | TPMT_PUBLIC(pub_len) | priv_len(2 BE) |
//!  TPM2B_PRIVATE(priv_len)`.

use tuncore::tpm_blob::{self, DsmtBlob, DsmtError};

/// Realistic dummy blob: a ~120-byte marshalled `TPMT_PUBLIC` and a ~100-byte
/// `TPM2B_PRIVATE` buffer, sized like the real artifacts Task 3.6 persists.
fn sample() -> DsmtBlob {
    DsmtBlob {
        public_tpmt: (0..120u8).collect(),
        private_buf: (0..100u8).map(|i| i.wrapping_mul(3)).collect(),
    }
}

/// Byte offsets of the two length fields, given the sample's `pub_len`.
const PUB_LEN_OFF: usize = 8;
fn priv_len_off(pub_len: usize) -> usize {
    PUB_LEN_OFF + 2 + pub_len
}

#[test]
fn roundtrip_serialize_parse() {
    let b = sample();
    let bytes = tpm_blob::serialize(&b);
    assert_eq!(bytes.len(), 8 + 2 + 120 + 2 + 100);
    assert_eq!(&bytes[..4], b"DSMT");
    assert_eq!(bytes[4], 0x01); // version
    assert_eq!(bytes[5], 0x01); // OWNER
    assert_eq!(bytes[6], 0x01); // CONTEXT_BLOB
    assert_eq!(bytes[7], 0x01); // NIST_P256
                                // pub_len / priv_len are big-endian.
    assert_eq!(u16::from_be_bytes([bytes[8], bytes[9]]), 120);
    assert_eq!(
        u16::from_be_bytes([bytes[priv_len_off(120)], bytes[priv_len_off(120) + 1]]),
        100
    );
    let parsed = tpm_blob::parse(&bytes).expect("parse");
    assert_eq!(parsed.public_tpmt, b.public_tpmt);
    assert_eq!(parsed.private_buf, b.private_buf);
    assert_eq!(parsed, b);
}

#[test]
fn bad_magic_rejected() {
    let mut bytes = tpm_blob::serialize(&sample());
    bytes[0] = b'X';
    assert!(matches!(tpm_blob::parse(&bytes), Err(DsmtError::BadMagic)));
}

#[test]
fn bad_version_rejected() {
    let mut bytes = tpm_blob::serialize(&sample());
    bytes[4] = 0x02;
    assert!(matches!(
        tpm_blob::parse(&bytes),
        Err(DsmtError::UnsupportedVersion(0x02))
    ));
}

#[test]
fn bad_hierarchy_rejected() {
    let mut bytes = tpm_blob::serialize(&sample());
    bytes[5] = 0x09;
    assert!(matches!(
        tpm_blob::parse(&bytes),
        Err(DsmtError::UnknownHierarchy(0x09))
    ));
}

#[test]
fn bad_key_kind_rejected() {
    let mut bytes = tpm_blob::serialize(&sample());
    bytes[6] = 0x09;
    assert!(matches!(
        tpm_blob::parse(&bytes),
        Err(DsmtError::UnknownKeyKind(0x09))
    ));
}

#[test]
fn bad_curve_rejected() {
    let mut bytes = tpm_blob::serialize(&sample());
    bytes[7] = 0x09;
    assert!(matches!(
        tpm_blob::parse(&bytes),
        Err(DsmtError::UnknownCurve(0x09))
    ));
}

#[test]
fn truncated_in_header_rejected() {
    let bytes = tpm_blob::serialize(&sample());
    // Cut short anywhere inside the fixed 8-byte header -> Truncated, never
    // a slice-OOB panic.
    for cut in 0..8 {
        assert!(
            matches!(tpm_blob::parse(&bytes[..cut]), Err(DsmtError::Truncated)),
            "header cut at {cut} must be Truncated"
        );
    }
}

#[test]
fn truncated_missing_pub_len_rejected() {
    let bytes = tpm_blob::serialize(&sample());
    assert!(matches!(
        tpm_blob::parse(&bytes[..PUB_LEN_OFF]),
        Err(DsmtError::Truncated)
    ));
    assert!(matches!(
        tpm_blob::parse(&bytes[..=PUB_LEN_OFF]),
        Err(DsmtError::Truncated)
    ));
}

#[test]
fn truncated_mid_pub_rejected() {
    let bytes = tpm_blob::serialize(&sample());
    // pub_len claims 120, but the buffer ends inside the public field.
    let mid_pub = PUB_LEN_OFF + 2 + 60;
    assert!(matches!(
        tpm_blob::parse(&bytes[..mid_pub]),
        Err(DsmtError::Truncated)
    ));
}

#[test]
fn truncated_missing_priv_len_rejected() {
    let bytes = tpm_blob::serialize(&sample());
    let plo = priv_len_off(120);
    assert!(matches!(
        tpm_blob::parse(&bytes[..plo]),
        Err(DsmtError::Truncated)
    ));
    assert!(matches!(
        tpm_blob::parse(&bytes[..=plo]),
        Err(DsmtError::Truncated)
    ));
}

#[test]
fn truncated_mid_priv_rejected() {
    let bytes = tpm_blob::serialize(&sample());
    let plo = priv_len_off(120);
    // priv_len claims 100, buffer ends inside the private field.
    let mid_priv = plo + 2 + 50;
    assert!(matches!(
        tpm_blob::parse(&bytes[..mid_priv]),
        Err(DsmtError::Truncated)
    ));
}

#[test]
fn pub_len_overflow_rejected() {
    // The classic length-field overflow: pub_len claims far more bytes than
    // the buffer holds. Must be a typed Truncated, never a slice panic.
    let mut bytes = tpm_blob::serialize(&sample());
    bytes[8] = 0xFF;
    bytes[9] = 0xFF;
    assert!(matches!(tpm_blob::parse(&bytes), Err(DsmtError::Truncated)));
}

#[test]
fn priv_len_overflow_rejected() {
    let mut bytes = tpm_blob::serialize(&sample());
    let plo = priv_len_off(120);
    bytes[plo] = 0xFF;
    bytes[plo + 1] = 0xFF;
    assert!(matches!(tpm_blob::parse(&bytes), Err(DsmtError::Truncated)));
}

#[test]
fn trailing_garbage_rejected() {
    let mut bytes = tpm_blob::serialize(&sample());
    bytes.push(0x00);
    assert!(matches!(
        tpm_blob::parse(&bytes),
        Err(DsmtError::TrailingBytes)
    ));
    bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    assert!(matches!(
        tpm_blob::parse(&bytes),
        Err(DsmtError::TrailingBytes)
    ));
}

#[test]
fn empty_pub_and_priv_roundtrip() {
    // The format does not forbid zero-length fields (a real key blob is
    // non-empty, but the wire format itself round-trips them cleanly: no
    // out-of-band sentinel is needed because the explicit length fields make
    // 0 unambiguous).
    let empty = DsmtBlob {
        public_tpmt: Vec::new(),
        private_buf: Vec::new(),
    };
    let bytes = tpm_blob::serialize(&empty);
    // header(8) + pub_len(2) + 0 pub + priv_len(2) + 0 priv.
    assert_eq!(bytes.len(), 12);
    assert_eq!(u16::from_be_bytes([bytes[8], bytes[9]]), 0);
    let parsed = tpm_blob::parse(&bytes).expect("empty roundtrip");
    assert_eq!(parsed, empty);
}

#[test]
fn errors_are_displayable() {
    // The typed error implements Display/Error so callers can surface it
    // through the crate's String/`?` boundaries without leaking a panic.
    let mut bytes = tpm_blob::serialize(&sample());
    bytes[0] = b'Z';
    let Err(err) = tpm_blob::parse(&bytes) else {
        panic!("bad magic must produce a typed error");
    };
    assert!(format!("{err}").contains("bad magic"));
}
