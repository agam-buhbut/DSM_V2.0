//! Versioned, TPM-free `DSMT` context-blob format.
//!
//! The blob carries no usable secret (the TPM2B_PRIVATE sensitive area is
//! TPM-encrypted), so no AEAD is needed. `TPM2_Load` is itself the
//! integrity check on the private area. The header bytes are validated
//! *before* any TPM call, exactly as `passphrase_store` validates its DSMK
//! header, so a tampered header fails closed with a typed error.

const MAGIC: &[u8; 4] = b"DSMT";
const VERSION_1: u8 = 0x01;
const HIERARCHY_OWNER: u8 = 0x01;
const KEY_KIND_CONTEXT_BLOB: u8 = 0x01;
const CURVE_NIST_P256: u8 = 0x01;
const HEADER_LEN: usize = 8;

/// Parsed DSMT payload: the marshalled TPMT_PUBLIC and the raw TPM2B_PRIVATE
/// buffer bytes (`Private::value()`).
///
/// `Debug` is implemented MANUALLY (not derived) so the TPM-encrypted private
/// area is never printed verbatim: `private_buf` is redacted to a byte count.
/// Deriving `Debug` would dump the raw private bytes into any log line, panic
/// message, or `{:?}` format that ever touched a blob.
#[derive(Clone, PartialEq, Eq)]
pub struct DsmtBlob {
    pub public_tpmt: Vec<u8>,
    pub private_buf: Vec<u8>,
}

impl std::fmt::Debug for DsmtBlob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DsmtBlob")
            .field("public_tpmt_len", &self.public_tpmt.len())
            .field(
                "private_buf",
                &format_args!("<{} bytes redacted>", self.private_buf.len()),
            )
            .finish()
    }
}

/// Typed parse failures. All are detected before any TPM interaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DsmtError {
    BadMagic,
    UnsupportedVersion(u8),
    UnknownHierarchy(u8),
    UnknownKeyKind(u8),
    UnknownCurve(u8),
    Truncated,
    TrailingBytes,
}

impl std::fmt::Display for DsmtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DsmtError::BadMagic => write!(f, "DSMT blob: bad magic (not a TPM attest blob)"),
            DsmtError::UnsupportedVersion(v) => write!(f, "DSMT blob: unsupported version {v}"),
            DsmtError::UnknownHierarchy(h) => write!(f, "DSMT blob: unknown hierarchy byte {h}"),
            DsmtError::UnknownKeyKind(k) => write!(f, "DSMT blob: unknown key_kind byte {k}"),
            DsmtError::UnknownCurve(c) => write!(f, "DSMT blob: unknown curve byte {c}"),
            DsmtError::Truncated => write!(f, "DSMT blob: truncated"),
            DsmtError::TrailingBytes => write!(f, "DSMT blob: trailing bytes after payload"),
        }
    }
}

impl std::error::Error for DsmtError {}

/// Serialize a `DsmtBlob` to the versioned on-disk form. Infallible: the
/// length fields are bounded by the caller's own marshalled sizes (TPM2B
/// structures are well under u16::MAX).
#[must_use]
pub fn serialize(blob: &DsmtBlob) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(HEADER_LEN + 2 + blob.public_tpmt.len() + 2 + blob.private_buf.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION_1);
    out.push(HIERARCHY_OWNER);
    out.push(KEY_KIND_CONTEXT_BLOB);
    out.push(CURVE_NIST_P256);
    // Lengths are bounded by TPM2B max (<= 0xFFFF) for every blob this crate
    // produces (the inputs are a marshalled TPMT_PUBLIC and the TPM's own
    // TPM2B_PRIVATE area — never attacker-supplied wire bytes). The checked
    // conversion makes that invariant release-safe: a future >u16::MAX
    // structure trips a clear panic here instead of silently truncating the
    // length prefix and emitting a corrupt blob.
    let pub_len = u16::try_from(blob.public_tpmt.len())
        .expect("DSMT serialize: public_tpmt length exceeds u16::MAX");
    let priv_len = u16::try_from(blob.private_buf.len())
        .expect("DSMT serialize: private_buf length exceeds u16::MAX");
    out.extend_from_slice(&pub_len.to_be_bytes());
    out.extend_from_slice(&blob.public_tpmt);
    out.extend_from_slice(&priv_len.to_be_bytes());
    out.extend_from_slice(&blob.private_buf);
    out
}

/// Parse + validate. Rejects unknown header bytes with a typed error before
/// the caller touches the TPM.
///
/// # Errors
/// Returns a [`DsmtError`] on any header mismatch, length overrun, or
/// trailing garbage.
pub fn parse(bytes: &[u8]) -> Result<DsmtBlob, DsmtError> {
    if bytes.len() < HEADER_LEN {
        return Err(DsmtError::Truncated);
    }
    if &bytes[0..4] != MAGIC {
        return Err(DsmtError::BadMagic);
    }
    if bytes[4] != VERSION_1 {
        return Err(DsmtError::UnsupportedVersion(bytes[4]));
    }
    if bytes[5] != HIERARCHY_OWNER {
        return Err(DsmtError::UnknownHierarchy(bytes[5]));
    }
    if bytes[6] != KEY_KIND_CONTEXT_BLOB {
        return Err(DsmtError::UnknownKeyKind(bytes[6]));
    }
    if bytes[7] != CURVE_NIST_P256 {
        return Err(DsmtError::UnknownCurve(bytes[7]));
    }
    let mut off = HEADER_LEN;
    let pub_len = read_u16(bytes, &mut off)? as usize;
    let public_tpmt = read_slice(bytes, &mut off, pub_len)?;
    let priv_len = read_u16(bytes, &mut off)? as usize;
    let private_buf = read_slice(bytes, &mut off, priv_len)?;
    if off != bytes.len() {
        return Err(DsmtError::TrailingBytes);
    }
    Ok(DsmtBlob {
        public_tpmt,
        private_buf,
    })
}

fn read_u16(bytes: &[u8], off: &mut usize) -> Result<u16, DsmtError> {
    let end = off.checked_add(2).ok_or(DsmtError::Truncated)?;
    if end > bytes.len() {
        return Err(DsmtError::Truncated);
    }
    let v = u16::from_be_bytes([bytes[*off], bytes[*off + 1]]);
    *off = end;
    Ok(v)
}

fn read_slice(bytes: &[u8], off: &mut usize, len: usize) -> Result<Vec<u8>, DsmtError> {
    let end = off.checked_add(len).ok_or(DsmtError::Truncated)?;
    if end > bytes.len() {
        return Err(DsmtError::Truncated);
    }
    let v = bytes[*off..end].to_vec();
    *off = end;
    Ok(v)
}
