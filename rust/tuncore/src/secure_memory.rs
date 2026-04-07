use libc::{mlock, munlock, RLIMIT_CORE, rlimit, setrlimit};
use std::ptr;

/// Lock a byte slice into physical memory, preventing swap.
///
/// # Safety
/// The slice must remain valid for the duration of the lock.
pub fn mlock_slice(data: &[u8]) -> Result<(), String> {
    if data.is_empty() {
        return Ok(());
    }
    let ret = unsafe { mlock(data.as_ptr() as *const libc::c_void, data.len()) };
    if ret != 0 {
        Err(format!(
            "mlock failed: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

/// Unlock a previously locked byte slice.
pub fn munlock_slice(data: &[u8]) -> Result<(), String> {
    if data.is_empty() {
        return Ok(());
    }
    let ret = unsafe { munlock(data.as_ptr() as *const libc::c_void, data.len()) };
    if ret != 0 {
        Err(format!(
            "munlock failed: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

/// Disable core dumps to prevent key material from being written to disk.
pub fn disable_core_dumps() -> Result<(), String> {
    let rlim = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let ret = unsafe { setrlimit(RLIMIT_CORE, &rlim) };
    if ret != 0 {
        Err(format!(
            "setrlimit failed: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

/// Securely zero a mutable byte slice using a volatile write.
pub fn secure_zero(data: &mut [u8]) {
    for byte in data.iter_mut() {
        unsafe {
            ptr::write_volatile(byte, 0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
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
