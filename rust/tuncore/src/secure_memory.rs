use libc::{mlock, munlock, RLIMIT_CORE, rlimit, setrlimit};
use zeroize::Zeroizing;

/// Check a libc return code, mapping non-zero to a descriptive error.
fn syscall_check(ret: i32, name: &str) -> Result<(), String> {
    if ret != 0 {
        Err(format!("{name} failed: {}", std::io::Error::last_os_error()))
    } else {
        Ok(())
    }
}

/// Lock a byte slice into physical memory, preventing swap.
///
/// # Safety
/// The slice must remain valid for the duration of the lock.
pub fn mlock_slice(data: &[u8]) -> Result<(), String> {
    if data.is_empty() {
        return Ok(());
    }
    syscall_check(
        unsafe { mlock(data.as_ptr() as *const libc::c_void, data.len()) },
        "mlock",
    )
}

/// Unlock a previously locked byte slice.
pub fn munlock_slice(data: &[u8]) -> Result<(), String> {
    if data.is_empty() {
        return Ok(());
    }
    syscall_check(
        unsafe { munlock(data.as_ptr() as *const libc::c_void, data.len()) },
        "munlock",
    )
}

/// Disable core dumps to prevent key material from being written to disk.
pub fn disable_core_dumps() -> Result<(), String> {
    let rlim = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    syscall_check(
        unsafe { setrlimit(RLIMIT_CORE, &rlim) },
        "setrlimit",
    )
}

/// Harden the process against memory inspection and privilege elevation.
///
/// - ``RLIMIT_CORE = 0`` — no core dumps (avoids keys-on-disk).
/// - ``PR_SET_DUMPABLE = 0`` — refuses ptrace from the same user and makes
///   the process non-dumpable. Under default ``ptrace_scope=1`` this is what
///   actually prevents a same-uid attacker from attaching.
/// - ``PR_SET_NO_NEW_PRIVS = 1`` — any child ``exec`` cannot gain privileges
///   via setuid binaries or file capabilities. Defense-in-depth.
pub fn harden_process() -> Result<(), String> {
    disable_core_dumps()?;
    syscall_check(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) as i32 },
        "prctl(PR_SET_DUMPABLE)",
    )?;
    syscall_check(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) as i32 },
        "prctl(PR_SET_NO_NEW_PRIVS)",
    )?;
    Ok(())
}

/// Securely zero a mutable byte slice.
/// Uses the zeroize crate which guarantees the write is not optimized away.
pub fn secure_zero(data: &mut [u8]) {
    use zeroize::Zeroize;
    data.zeroize();
}

/// A 32-byte secret pinned to a stable heap address, mlock'd for its
/// lifetime and zeroized before deallocation.
///
/// The indirection via `Box` matters: a bare `Zeroizing<[u8; 32]>` is a
/// value type, so moving the owner (e.g. returning from a constructor,
/// handing off to PyO3's `#[pyclass]` boxing) memcpys the 32 bytes to a
/// new address. Any `mlock` applied to the source is then stranded on a
/// stack frame that will be reused, and the moved-from bytes are never
/// zeroized because Rust does not run `Drop` on move sources. Putting the
/// `Zeroizing<[u8; 32]>` behind a `Box` makes the key bytes live at a
/// heap address that is stable across every move of the wrapping type.
///
/// Prefer `LockedKey32::zeroed()` followed by direct writes through
/// `as_mut()` when you are about to produce fresh key material — that
/// avoids any transient stack copy of the secret.
pub struct LockedKey32 {
    bytes: Box<Zeroizing<[u8; 32]>>,
}

impl LockedKey32 {
    /// Allocate a zeroed, mlock'd 32-byte heap buffer. Subsequent writes
    /// via `as_mut()` go straight to the locked heap address.
    pub fn zeroed() -> Result<Self, String> {
        let bytes = Box::new(Zeroizing::new([0u8; 32]));
        mlock_slice(&**bytes)?;
        Ok(Self { bytes })
    }

    /// Move an existing 32-byte array into a mlock'd heap location.
    ///
    /// **Caller contract (audit M4):** `src` is copied by value, which leaves
    /// a transient stack copy at the caller's frame that this function cannot
    /// zeroize. Callers MUST either:
    ///   (a) pass a `[u8; 32]` materialized only for this call and let it go
    ///       out of scope immediately afterwards, OR
    ///   (b) pass `*zeroizing.deref()` where `zeroizing: Zeroizing<[u8; 32]>`
    ///       so the owned copy is scrubbed on drop.
    ///
    /// Prefer `LockedKey32::zeroed()` + direct writes for key-generation paths
    /// so no transient stack copy of the key ever exists.
    pub fn from_array(src: [u8; 32]) -> Result<Self, String> {
        let bytes = Box::new(Zeroizing::new(src));
        mlock_slice(&**bytes)?;
        Ok(Self { bytes })
    }

    pub fn as_array(&self) -> &[u8; 32] {
        &**self.bytes
    }

    pub fn as_mut(&mut self) -> &mut [u8; 32] {
        &mut **self.bytes
    }
}

impl Drop for LockedKey32 {
    fn drop(&mut self) {
        // munlock before Box drops, so the kernel still has the mapping.
        // Zeroize + deallocation are handled by Box<Zeroizing<..>>'s drop.
        let _ = munlock_slice(&**self.bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlock_munlock_roundtrip() {
        let data = vec![0xABu8; 4096];
        mlock_slice(&data).expect("mlock should succeed");
        munlock_slice(&data).expect("munlock should succeed");
    }

    #[test]
    fn test_mlock_empty_slice() {
        let data: Vec<u8> = vec![];
        assert!(mlock_slice(&data).is_ok());
        assert!(munlock_slice(&data).is_ok());
    }

    #[test]
    fn test_secure_zero() {
        let mut data = vec![0xFF; 32];
        secure_zero(&mut data);
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_disable_core_dumps() {
        disable_core_dumps().expect("disable_core_dumps should succeed");
    }

    #[test]
    fn test_harden_process_sets_dumpable_zero() {
        harden_process().expect("harden_process should succeed");
        let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
        assert_eq!(dumpable, 0, "PR_GET_DUMPABLE should report 0 after harden_process");
    }
}
