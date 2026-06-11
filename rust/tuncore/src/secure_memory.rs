use libc::{mlock, munlock, rlimit, setrlimit, RLIMIT_CORE};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};
use zeroize::Zeroizing;

/// Check a libc return code, mapping non-zero to a descriptive error.
fn syscall_check(ret: i32, name: &str) -> Result<(), String> {
    if ret != 0 {
        Err(format!(
            "{name} failed: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(())
    }
}

/// Lock a byte slice into physical memory, preventing swap.
///
/// WARNING: bypasses [`PAGE_REFCOUNTS`]. `munlock_slice` on a region
/// sharing a page with a live [`LockedKey32`] would re-enable swap for
/// that key. Currently has no production callers — new key material must
/// use `LockedKey32` (or route through `lock_key_pages`) instead.
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
    syscall_check(unsafe { setrlimit(RLIMIT_CORE, &rlim) }, "setrlimit")
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

/// Process-global page → live-key refcount. `mlock`/`munlock` are
/// page-granular and not refcounted by the kernel; multiple
/// `LockedKey32`s routinely share one allocator page, so dropping one key
/// must not `munlock` a page that still holds another live key. This map
/// makes `munlock` fire only when the last key on a page drops.
static PAGE_REFCOUNTS: LazyLock<Mutex<HashMap<usize, usize>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// `_SC_PAGESIZE` is constant for the process lifetime; query once.
fn page_size() -> usize {
    static PAGE: AtomicUsize = AtomicUsize::new(0);
    let cached = PAGE.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }
    let raw = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let sz = if raw <= 0 { 4096 } else { raw as usize };
    PAGE.store(sz, Ordering::Relaxed);
    sz
}

/// Page base addresses spanned by `[addr, addr+len)`.
fn page_bases(addr: usize, len: usize) -> Vec<usize> {
    let page = page_size();
    let first = addr & !(page - 1);
    let last = (addr + len - 1) & !(page - 1);
    (first..=last).step_by(page).collect()
}

fn mlock_page(base: usize) -> Result<(), String> {
    let page = page_size();
    syscall_check(unsafe { mlock(base as *const libc::c_void, page) }, "mlock")
}

fn munlock_page(base: usize) {
    // Teardown is unrecoverable and the kernel cleans the mapping on
    // process exit; deliberately drop the error (matches prior behavior).
    let page = page_size();
    unsafe {
        munlock(base as *const libc::c_void, page);
    }
}

/// Reference-count the pages of a key region and `mlock` each page on its
/// first resident key. On `mlock` failure, every increment made by THIS
/// call is rolled back and the error is propagated, so key construction
/// fails exactly as the old direct mlock did.
fn lock_key_pages(addr: usize, len: usize) -> Result<(), String> {
    // Guard the page math: `(addr + len - 1)` in `page_bases` would wrap
    // for len == 0 and register a page that no unlock can ever balance.
    debug_assert!(len > 0, "lock_key_pages: empty region");
    if len == 0 {
        return Ok(());
    }
    // `.expect` here is deliberate: a poisoned lock means a panic occurred
    // mid-mlock-accounting, and continuing with corrupt accounting would
    // silently void the swap-protection guarantee.
    let mut map = PAGE_REFCOUNTS.lock().expect("page-refcount mutex poisoned");
    let mut bumped: Vec<usize> = Vec::new();
    let mut newly_locked: Vec<usize> = Vec::new();
    for base in page_bases(addr, len) {
        let count = map.get(&base).copied().unwrap_or(0);
        if count == 0 {
            if let Err(e) = mlock_page(base) {
                for &b in &bumped {
                    if let Some(c) = map.get_mut(&b) {
                        *c -= 1;
                        if *c == 0 {
                            map.remove(&b);
                        }
                    }
                }
                for &b in &newly_locked {
                    munlock_page(b);
                }
                return Err(e);
            }
            newly_locked.push(base);
        }
        map.insert(base, count + 1);
        bumped.push(base);
    }
    Ok(())
}

/// Decrement the refcount of each page a key region spans; `munlock` only
/// the pages whose count reaches zero.
fn unlock_key_pages(addr: usize, len: usize) {
    debug_assert!(len > 0, "unlock_key_pages: empty region");
    if len == 0 {
        return;
    }
    let mut map = PAGE_REFCOUNTS.lock().expect("page-refcount mutex poisoned");
    for base in page_bases(addr, len) {
        match map.get_mut(&base) {
            Some(c) if *c > 1 => {
                *c -= 1;
            }
            Some(_) => {
                map.remove(&base);
                munlock_page(base);
            }
            None => {
                // Underflow: nothing locked here. Tolerated in release
                // (worst case is a leaked lock, never a lost one); loud in
                // debug/test builds so an accounting regression is caught.
                debug_assert!(false, "munlock underflow at {base:#x}");
            }
        }
    }
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
        lock_key_pages(bytes.as_ptr() as usize, 32)?;
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
        lock_key_pages(bytes.as_ptr() as usize, 32)?;
        Ok(Self { bytes })
    }

    pub fn as_array(&self) -> &[u8; 32] {
        &self.bytes
    }

    #[allow(clippy::should_implement_trait)]
    pub fn as_mut(&mut self) -> &mut [u8; 32] {
        &mut self.bytes
    }
}

/// Allocate a fresh mlock'd 32-byte buffer and fill it with `OsRng` bytes.
///
/// This is the only path that writes a fresh secret scalar directly into
/// mlock'd memory without going through a stack copy — `LockedKey32::zeroed`
/// reserves the page, then `OsRng.fill_bytes` writes into the heap buffer
/// in place. Audit-relevant: this pattern previously lived inline at two
/// callsites (`identity::IdentityKeyPair::generate` and
/// `session_keys::gen_ephemeral_secret`); centralised so a reviewer reads
/// the invariant once.
pub fn random_locked_key32() -> Result<LockedKey32, String> {
    use rand::rngs::OsRng;
    use rand::RngCore;
    let mut k = LockedKey32::zeroed()?;
    OsRng.fill_bytes(k.as_mut());
    Ok(k)
}

impl Drop for LockedKey32 {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        let addr = self.bytes.as_ptr() as usize;
        // Zeroize BEFORE releasing the page lock so the page is never
        // swappable while it still holds the secret. The page is only
        // actually munlock'd when the last live key on it drops (see
        // PAGE_REFCOUNTS); Box<Zeroizing<..>>'s own drop then re-zeroizes
        // (a no-op) and deallocates.
        self.bytes.zeroize();
        unlock_key_pages(addr, 32);
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
        assert_eq!(
            dumpable, 0,
            "PR_GET_DUMPABLE should report 0 after harden_process"
        );
    }

    #[test]
    fn page_refcount_keeps_lock_until_last_key_on_page_drops() {
        let page = page_size();
        // Real, mapped, mlockable memory spanning >1 page so we can place
        // two synthetic 32-byte keys on the SAME page deterministically.
        let buf = vec![0u8; page * 3];
        let raw = buf.as_ptr() as usize;
        let base = (raw + page - 1) & !(page - 1); // page-aligned addr in buf
        let a = base; // page P
        let b = base + 64; // same page P
        lock_key_pages(a, 32).expect("lock a");
        lock_key_pages(b, 32).expect("lock b");
        {
            let map = PAGE_REFCOUNTS.lock().expect("mutex");
            assert_eq!(map.get(&base).copied(), Some(2), "both keys counted");
        }
        unlock_key_pages(a, 32);
        {
            let map = PAGE_REFCOUNTS.lock().expect("mutex");
            assert_eq!(map.get(&base).copied(), Some(1), "page still held by b");
        }
        unlock_key_pages(b, 32);
        {
            let map = PAGE_REFCOUNTS.lock().expect("mutex");
            assert_eq!(map.get(&base).copied(), None, "page released last drop");
        }
        drop(buf);
    }

    #[test]
    fn locked_key32_registers_its_page_while_live() {
        let mut k = LockedKey32::zeroed().expect("alloc");
        k.as_mut().copy_from_slice(&[0xAB; 32]);
        let page = page_size();
        let base = (k.as_array().as_ptr() as usize) & !(page - 1);
        {
            let map = PAGE_REFCOUNTS.lock().expect("mutex");
            assert!(
                map.get(&base).copied().unwrap_or(0) >= 1,
                "live key's page must be registered"
            );
        }
        // Drop must not panic (zeroize-before-munlock + registry decrement).
        drop(k);
    }
}
