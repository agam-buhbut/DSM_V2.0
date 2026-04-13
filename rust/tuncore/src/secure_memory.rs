use libc::{mlock, munlock, RLIMIT_CORE, rlimit, setrlimit};

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

/// Securely zero a mutable byte slice.
/// Uses the zeroize crate which guarantees the write is not optimized away.
pub fn secure_zero(data: &mut [u8]) {
    use zeroize::Zeroize;
    data.zeroize();
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
}
