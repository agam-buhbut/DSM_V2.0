# Phase 0 — Security Blockers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the eight Phase-0 security blockers (one remote-DoS critical plus seven security-class high/medium findings) from `PRODUCTION_REVIEW.md` §3–5 so every one has a fix and a regression test.

**Architecture:** DSM is a Python asyncio daemon (`dsm/`) over a Rust PyO3 crypto core (`rust/tuncore/`, imported as `tuncore`). The handshake glue, DNS proxy, config loader, and daemon entry points live in Python; key memory, the sealed-blob format, and the Noise state machine live in Rust. Phase-0 fixes touch both sides plus the systemd unit and the example config.

**Tech Stack:** Python 3.13 (`black` 88 cols, `pyright`, `pytest`/`unittest`), Rust edition 2021 (`thiserror`-free string errors as the crate currently uses, `zeroize`, `libc`, `std::sync::LazyLock`), systemd unit hardening, `dnspython`, `cryptography`.

**Environment notes for every step:**
- No in-repo `.venv`. The system interpreter `python3` already has `dsm` and the built `tuncore` importable (verified). Run Python tests with `python3 -m pytest tests/<file> -q` from the repo root `/home/earl/Documents/prog/DSM_V2.0`.
- Rust tests: `cargo test --manifest-path rust/tuncore/Cargo.toml <filter>`.
- After any Rust source change that the Python side imports, rebuild the extension: `maturin develop --manifest-path rust/tuncore/Cargo.toml` (maturin 1.13 present) **or** from repo root `maturin develop -m rust/tuncore/Cargo.toml`. Tuncore-gated Python tests need the rebuilt wheel installed for the active `python3`.
- Tuncore-gated Python test files use the repo convention: `try: import tuncore; _HAS_TUNCORE = True except ImportError: tuncore = None; _HAS_TUNCORE = False`, then `@unittest.skipUnless(_HAS_TUNCORE, "requires tuncore")`.
- **NO git commits anywhere** — the owner commits manually. Each task ends with a one-line Report step.
- **Never edit an existing test file.** Where a task would force one, it carries a `FLAG FOR OWNER` note instead.

---

## File Structure

| File | Create/Modify | Responsibility |
|---|---|---|
| `dsm/crypto/handshake.py` | Modify | Add `_translate_noise_errors` helper; wrap the five peer-byte-parsing tuncore calls so malformed input raises typed `HandshakeError` (Task 1). |
| `tests/test_handshake_dos.py` | Create | Feed malformed/low-order/wrong-size msg1 through real tuncore; assert `HandshakeError` and that a server loop survives (Task 1). |
| `dsm/net/dns_proxy.py` | Modify | Validate datagram source against the in-tunnel subnet before scheduling; rate-limited DEBUG drop log (Task 2). |
| `tests/test_dns_proxy_source.py` | Create | Off-subnet source gets no reply + no pending state; in-subnet served (Task 2). |
| `rust/tuncore/src/secure_memory.rs` | Modify | Process-global page-refcount registry so `munlock` only fires on the last key sharing a page; zeroize-before-munlock ordering; new inline tests (Task 3). |
| `rust/tuncore/src/passphrase_store.rs` | Modify | v1 sealed-blob header (magic+version+Argon2id params), legacy reader, bounds-checked params, new `v1_*` inline tests (Task 4). |
| `rust/tuncore/src/device_attest.rs` | Modify | Expose `BACKEND_IS_SOFTWARE` compile-time constant (Task 5). |
| `rust/tuncore/src/lib.rs` | Modify | Re-export `ATTEST_BACKEND_IS_SOFTWARE` as a Python module attribute (Task 5). |
| `tuncore.pyi` | Modify | Stub the new `ATTEST_BACKEND_IS_SOFTWARE` attribute (Task 5). |
| `dsm/crypto/attest_gate.py` | Create | Startup gate refusing the extractable soft-attest backend unless `allow_soft_attest` (Task 5). |
| `dsm/core/config.py` | Modify | Add `allow_soft_attest` field (Task 5); enforce config-file permissions at `load()` (Task 6). |
| `config.example.toml` | Modify | Document `allow_soft_attest` (Task 5). |
| `tests/test_attest_gate.py` | Create | Refused-start without flag; warning + event with flag (Task 5). |
| `tests/test_config_perms.py` | Create | Good-mode config loads; group/world modes rejected (Task 6). |
| `dsm/core/hardening.py` | Create | ctypes `prctl(PR_SET_DUMPABLE,0)` backstop (Task 7). |
| `deploy/dsm.service` | Modify | Add `LimitCORE=0` + `CoredumpFilter=0x00` (Task 7). |
| `dsm/server.py` | Modify | Wire attest gate + nondumpable backstop; extract `_emit_handshake_failure` dropping the leaky `message` (Tasks 5,7,8). |
| `dsm/client.py` | Modify | Wire attest gate + nondumpable backstop (Tasks 5,7). |
| `tests/test_hardening.py` | Create | Subprocess asserts dumpable flag cleared; Linux-only (Task 7). |
| `tests/test_netaudit_no_leak.py` | Create | Failed handshake_end event omits the exception message (Task 8). |

---

### Task 1: Translate Rust `RuntimeError` from Noise parsing into `HandshakeError` (C1 remote DoS)

**Files:**
- Modify: `dsm/crypto/handshake.py` (imports line 39; add helper after line 118; wrap calls at lines 196, 278, 350, 376, 421)
- Test: `tests/test_handshake_dos.py` (Create)

Context confirmed from source: `run_server`'s retry loop (`dsm/server.py:212-217`) and `run_client`'s except (`dsm/client.py:189-194`) already catch `HandshakeError`, so once the translation lands no server/client code change is needed — the typed error is handled, logged, and (server) retried. The DoS surface is the five tuncore calls that parse peer-controlled bytes: `read_message_1/2/3` and the two `NoiseTransport.decrypt` bootstrap calls. Rust raises a bare `RuntimeError` (PyO3 `py_err`) on wrong frame size / low-order ephemeral / AEAD failure.

- [ ] **Write the failing test.** Create `tests/test_handshake_dos.py`:

```python
"""Regression: malformed unauthenticated msg1 must surface as a typed
HandshakeError, not an untranslated Rust RuntimeError that escapes the
server retry loop and kills asyncio.run (finding C1, remote DoS)."""

from __future__ import annotations

import asyncio
import os
import unittest
from unittest.mock import patch

from cryptography.x509.oid import ExtendedKeyUsageOID

try:
    import tuncore  # noqa: F401

    _HAS_TUNCORE = True
except ImportError:
    tuncore = None  # type: ignore[assignment]
    _HAS_TUNCORE = False

from dsm.crypto.cert_allowlist import CNAllowlist
from dsm.crypto.handshake import (
    HANDSHAKE_FRAME_SIZE,
    HandshakeError,
    server_handshake,
)
from dsm.net.transport.udp import UDPTransport


@unittest.skipUnless(_HAS_TUNCORE, "requires tuncore")
class TestHandshakeMalformedMsg1(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        from tests.cert_helpers import (
            SERVER_AUTH_OID,
            make_enrolled_device,
            make_test_ca,
        )

        # SO_MARK needs CAP_NET_ADMIN, absent in CI/test — stub it out.
        self._patches = [
            patch("dsm.net.transport.udp.apply_so_mark", lambda sock: None),
        ]
        for p in self._patches:
            p.start()
        self.ca = make_test_ca()
        self.server = make_enrolled_device(
            self.ca,
            subject_cn="dsm-server01-server",
            eku=SERVER_AUTH_OID,
        )
        self.allowlist = CNAllowlist(cns=frozenset({"dsm-client01-client"}))

    async def asyncTearDown(self) -> None:
        for p in self._patches:
            p.stop()

    async def _bind_pair(self) -> tuple[UDPTransport, UDPTransport, int]:
        server_transport = UDPTransport()
        server_port = await server_transport.bind("127.0.0.1", 0)
        self.addAsyncCleanup(server_transport.aclose)
        attacker = UDPTransport()
        await attacker.bind("127.0.0.1", 0)
        self.addAsyncCleanup(attacker.aclose)
        return server_transport, attacker, server_port

    async def _run_server_once(self, server_transport: UDPTransport) -> None:
        await asyncio.wait_for(
            server_handshake(
                server_transport,
                self.server.identity,
                attest_key=self.server.attest_key,
                cert_der=self.server.cert_der,
                ca_root=self.ca.certificate,
                cn_allowlist=self.allowlist,
                required_client_eku=ExtendedKeyUsageOID.CLIENT_AUTH,
            ),
            timeout=10.0,
        )

    async def test_wrong_size_msg1_raises_handshake_error(self) -> None:
        server_transport, attacker, port = await self._bind_pair()
        # 100 bytes != HANDSHAKE_FRAME_SIZE: Rust unpack_handshake rejects.
        await attacker.send(b"\x00" * 100, ("127.0.0.1", port))
        with self.assertRaises(HandshakeError):
            await self._run_server_once(server_transport)

    async def test_low_order_msg1_raises_handshake_error(self) -> None:
        server_transport, attacker, port = await self._bind_pair()
        # 32 zero bytes is a low-order X25519 point; Rust rejects before ee.
        frame = b"\x00" * 32 + os.urandom(HANDSHAKE_FRAME_SIZE - 32)
        await attacker.send(frame, ("127.0.0.1", port))
        with self.assertRaises(HandshakeError):
            await self._run_server_once(server_transport)

    async def test_server_loop_survives_malformed_msg1(self) -> None:
        # Mimic run_server's retry loop: a malformed msg1 must be a caught
        # HandshakeError, not a RuntimeError that escapes the loop.
        server_transport, attacker, port = await self._bind_pair()
        survived = False
        for _ in range(2):
            await attacker.send(b"\x00" * 100, ("127.0.0.1", port))
            try:
                await self._run_server_once(server_transport)
            except HandshakeError:
                survived = True
                continue
        self.assertTrue(survived)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Run it (expect red).** `python3 -m pytest tests/test_handshake_dos.py -q` — expected failure: `RuntimeError` (e.g. `handshake frame wrong size: 100 != 1400`) escapes `server_handshake` instead of `HandshakeError`, so `assertRaises(HandshakeError)` fails / errors.

- [ ] **Add the translation helper.** In `dsm/crypto/handshake.py`, change the typing import (line 39) from `from typing import TYPE_CHECKING` to `from typing import TYPE_CHECKING, TypeVar`, then insert after `_unpad_from_frame` (after line 118):

```python
_NoiseT = TypeVar("_NoiseT")


def _translate_noise_errors(what: str, call: Callable[[], _NoiseT]) -> _NoiseT:
    """Run a tuncore Noise/transport call that parses peer-controlled
    bytes, translating the PyO3 ``RuntimeError`` it raises on malformed
    input into a typed :class:`HandshakeError` (finding C1).

    Rust's Noise readers (``read_message_1/2/3``) and
    ``NoiseTransport.decrypt`` surface every internal failure — wrong
    frame size, low-order ephemeral, AEAD auth failure — as a bare
    ``RuntimeError`` (PyO3 ``py_err``). ``run_server`` / ``run_client``
    catch only ``HandshakeError`` / ``CertAuthError``, so an
    unauthenticated malformed ``msg1`` would otherwise escape the retry
    loop and terminate ``asyncio.run``.
    """
    try:
        return call()
    except RuntimeError as e:
        raise HandshakeError(f"{what}: {e}") from e
```

- [ ] **Wrap the five peer-parsing call sites.** In `client_handshake`, replace line 196:

```python
    server_static_raw, server_attest_payload = _translate_noise_errors(
        "read msg2", lambda: initiator.read_message_2(msg2)
    )
```

  and replace line 278 (`server_public = noise_transport.decrypt(bootstrap_resp_ct)`):

```python
    server_public = _translate_noise_errors(
        "decrypt bootstrap response",
        lambda: noise_transport.decrypt(bootstrap_resp_ct),
    )
```

  In `server_handshake`, replace line 350 (`responder.read_message_1(msg1)`):

```python
    _translate_noise_errors("read msg1", lambda: responder.read_message_1(msg1))
```

  replace line 376:

```python
    client_static_raw, client_attest_payload = _translate_noise_errors(
        "read msg3", lambda: responder.read_message_3(msg3)
    )
```

  and replace line 421 (`client_public = noise_transport.decrypt(bootstrap_init_ct)`):

```python
    client_public = _translate_noise_errors(
        "decrypt bootstrap init",
        lambda: noise_transport.decrypt(bootstrap_init_ct),
    )
```

- [ ] **Run it (expect green).** `python3 -m pytest tests/test_handshake_dos.py -q` — all three tests pass: malformed/low-order/wrong-size msg1 now raise `HandshakeError`, and the simulated loop survives.

- [ ] **Run the focused gate.** `python3 -m pytest tests/test_handshake_dos.py tests/test_handshake_retry_outage.py tests/test_handshake_integration.py -q`

- [ ] **Report.** One line: wrapped 5 peer-byte tuncore calls in `handshake.py` with `_translate_noise_errors`; malformed msg1 now fails closed as `HandshakeError`; no `server.py`/`client.py` change needed (both already catch `HandshakeError`).

---

### Task 2: Restrict the DNS proxy to in-tunnel sources (open resolver / reflector)

**Files:**
- Modify: `dsm/net/dns_proxy.py` (imports lines 13-29; `__init__` lines 68-88; add helper methods after line 150; protocol `datagram_received` lines 307-315)
- Test: `tests/test_dns_proxy_source.py` (Create)

Context confirmed: `LocalDNSProxy` is constructed in `dsm/server.py:344-349` with `bind_ip=SERVER_TUN_IP` (`10.8.0.1`, from `dsm/net/_addresses.py`). The server TUN is a `/24` (`dsm/net/tunnel.py:226`, `netmask=24`), so legitimate clients arrive from `10.8.0.0/24`. The allowed network is derived from `bind_ip`'s `/24` in `__init__`, so no `server.py` change is required (it already passes `SERVER_TUN_IP`). The check goes in `_ProxyProtocol.datagram_received` **before** `_schedule`, so off-subnet datagrams allocate no task and no inflight entry. The file already has a rate-limited log pattern (`_tasks_shed_last_log` + `5.0`); mirror it at DEBUG.

- [ ] **Write the failing test.** Create `tests/test_dns_proxy_source.py`:

```python
"""Regression: the local DNS proxy must answer only in-tunnel sources.
Off-subnet datagrams (open-resolver / reflection) get no reply and
allocate no pending state (finding: dns_proxy.py:307 open resolver)."""

from __future__ import annotations

import unittest

import dns.message
import dns.rdatatype

from dsm.net.dns_proxy import LocalDNSProxy, _ProxyProtocol


class _StubResolver:
    async def resolve(self, hostname: str) -> list[str]:
        return ["10.0.0.99"]

    async def close(self) -> None:
        return None


class _FakeTransport:
    def __init__(self) -> None:
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    def sendto(self, wire: bytes, to: tuple[str, int]) -> None:
        self.sent.append((wire, to))


def _query_wire(qname: str) -> bytes:
    return dns.message.make_query(qname, dns.rdatatype.A).to_wire()


class TestDnsProxySourceFilter(unittest.IsolatedAsyncioTestCase):
    async def _make_proxy(self) -> tuple[LocalDNSProxy, _ProxyProtocol, _FakeTransport]:
        proxy = LocalDNSProxy(_StubResolver(), bind_ip="10.8.0.1")  # type: ignore[arg-type]
        proto = _ProxyProtocol(proxy)
        fake = _FakeTransport()
        proto.connection_made(fake)  # type: ignore[arg-type]
        return proxy, proto, fake

    async def test_off_subnet_source_dropped_no_state(self) -> None:
        proxy, proto, fake = await self._make_proxy()
        proto.datagram_received(_query_wire("example.com"), ("9.9.9.9", 5353))
        # No reply, no scheduled task, no inflight allocation.
        self.assertEqual(fake.sent, [])
        self.assertEqual(len(proxy._tasks), 0)
        self.assertEqual(proxy._inflight, {})

    async def test_in_subnet_source_served(self) -> None:
        import asyncio

        proxy, proto, fake = await self._make_proxy()
        proto.datagram_received(_query_wire("example.com"), ("10.8.0.2", 5353))
        # A task was scheduled; let it run and confirm a reply was sent.
        self.assertGreaterEqual(len(proxy._tasks), 1)
        await asyncio.gather(*list(proxy._tasks))
        self.assertEqual(len(fake.sent), 1)
        resp = dns.message.from_wire(fake.sent[0][0])
        self.assertTrue(resp.answer)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Run it (expect red).** `python3 -m pytest tests/test_dns_proxy_source.py -q` — expected failure: `test_off_subnet_source_dropped_no_state` fails because the unfiltered proxy schedules a task and replies to `9.9.9.9` (`proxy._tasks` non-empty / `fake.sent` non-empty).

- [ ] **Add the import and constructor field.** In `dsm/net/dns_proxy.py`, add to the stdlib imports (after `import asyncio` on line 15) the line `import ipaddress`. Then in `__init__` (after line 78, `self._debug_dns = debug_dns`), add:

```python
        # Restrict to the in-tunnel /24 derived from the bind address.
        # The proxy binds on the server's TUN IP (10.8.0.1) and clients
        # arrive from 10.8.0.0/24; any other source reaching this socket
        # (Linux weak host model + rp_filter=2) is an off-tunnel
        # open-resolver / reflection attempt and must be dropped before
        # any task / inflight state is allocated.
        self._allowed_source_net = ipaddress.ip_network(
            f"{bind_ip}/24", strict=False
        )
        self._dropped_offnet: int = 0
        self._dropped_offnet_last_log: float = 0.0
```

- [ ] **Add the source-check helpers.** Insert after `_schedule` (after line 150, before `_parse_or_reject`):

```python
    def _source_allowed(self, addr: tuple[str, int]) -> bool:
        """True iff ``addr`` is inside the in-tunnel source network."""
        try:
            src = ipaddress.ip_address(addr[0])
        except ValueError:
            return False
        return src in self._allowed_source_net

    def _note_dropped_source(self, addr: tuple[str, int]) -> None:
        """Count an off-tunnel drop; DEBUG-log at most once per 5 s."""
        self._dropped_offnet += 1
        now = time.monotonic()
        if now - self._dropped_offnet_last_log > 5.0:
            log.debug(
                "dropped %d off-tunnel DNS queries since last log "
                "(most recent source %s)",
                self._dropped_offnet,
                addr[0],
            )
            self._dropped_offnet_last_log = now
            self._dropped_offnet = 0
```

- [ ] **Enforce the check before scheduling.** In `_ProxyProtocol.datagram_received` (lines 307-315), insert the source check immediately after the `if self._transport is None: return` guard so it runs before `_send`/`_schedule`:

```python
    def datagram_received(self, data: bytes, addr: tuple[str | Any, int]) -> None:
        if self._transport is None:
            return
        if not self._proxy._source_allowed(addr):  # type: ignore[arg-type]  # pylint: disable=protected-access  # intentional sibling-internal access
            self._proxy._note_dropped_source(addr)  # type: ignore[arg-type]  # pylint: disable=protected-access  # intentional sibling-internal access
            return
        transport = self._transport

        def _send(wire: bytes, to: tuple[str, int]) -> None:
            transport.sendto(wire, to)

        self._proxy._schedule(self._proxy._handle_query(data, addr, _send))  # type: ignore[arg-type]  # pylint: disable=protected-access  # intentional sibling-internal access
```

- [ ] **Run it (expect green).** `python3 -m pytest tests/test_dns_proxy_source.py -q` — off-subnet dropped with no state; in-subnet served.

- [ ] **Run the focused gate.** `python3 -m pytest tests/test_dns_proxy_source.py tests/test_dns_proxy.py tests/test_dns_proxy_coalescing.py -q` (existing `test_dns_proxy.py` calls `_handle_query` directly, bypassing the new datagram-level check, so it stays green.)

- [ ] **Report.** One line: `dns_proxy.py` now drops datagrams whose source is outside the bind-IP `/24` before any task/inflight allocation, with a rate-limited DEBUG log; allowed network derived from `bind_ip`, so `server.py` is unchanged.

---

### Task 3: Page-refcounted `munlock` in `LockedKey32` (swap-protection void)

**Files:**
- Modify: `rust/tuncore/src/secure_memory.rs` (imports line 1-2; `LockedKey32::zeroed` lines 100-104; `from_array` lines 118-122; `Drop` lines 151-160; new registry fns before the struct; new inline tests in the existing `#[cfg(test)] mod tests`)
- Test: inline `#[cfg(test)] mod tests` in `rust/tuncore/src/secure_memory.rs` (this is source-with-inline-tests — the project keeps Rust tests here, confirmed by reading the file; adding new `#[test]` fns is allowed)

Context confirmed: `LockedKey32` boxes a `Zeroizing<[u8;32]>`; many 32-byte keys share one 4 KiB allocator page. `mlock`/`munlock` are page-granular and not refcounted, so dropping any transient key `munlock`s the whole page and re-enables swap for live keys on it. Fix: a process-global `LazyLock<Mutex<HashMap<usize, usize>>>` keyed by page base; `mlock` only when a page's count goes 0→1, `munlock` only when it returns to 0. No new crate dependency (`std`, `libc`, `zeroize` already present; `LazyLock` is stable on the toolchain — `cargo 1.95`).

- [ ] **Write the failing tests.** Append to the existing `#[cfg(test)] mod tests { ... }` in `rust/tuncore/src/secure_memory.rs` (add these two functions inside the brace, after `test_harden_process_sets_dumpable_zero`):

```rust
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
```

- [ ] **Run it (expect red).** `cargo test --manifest-path rust/tuncore/Cargo.toml secure_memory::tests::page_refcount` — expected failure: compilation error `cannot find function 'lock_key_pages'` / `cannot find value 'PAGE_REFCOUNTS'` (the registry does not exist yet).

- [ ] **Add registry imports.** Change the top of `rust/tuncore/src/secure_memory.rs` (lines 1-2) to:

```rust
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};

use libc::{mlock, munlock, rlimit, setrlimit, RLIMIT_CORE};
use zeroize::Zeroizing;
```

- [ ] **Add the registry + helpers.** Insert just before `pub struct LockedKey32` (before line 93):

```rust
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
    let sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let sz = if sz == 0 { 4096 } else { sz };
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

fn mlock_page(base: usize, len: usize) -> Result<(), String> {
    syscall_check(
        unsafe { mlock(base as *const libc::c_void, len) },
        "mlock",
    )
}

fn munlock_page(base: usize, len: usize) {
    // Teardown is unrecoverable and the kernel cleans the mapping on
    // process exit; deliberately drop the error (matches prior behavior).
    unsafe {
        munlock(base as *const libc::c_void, len);
    }
}

/// Reference-count the pages of a key region and `mlock` each page on its
/// first resident key. On `mlock` failure, every increment made by THIS
/// call is rolled back and the error is propagated, so key construction
/// fails exactly as the old `mlock_slice(..)?` did.
fn lock_key_pages(addr: usize, len: usize) -> Result<(), String> {
    let page = page_size();
    let mut map = PAGE_REFCOUNTS
        .lock()
        .expect("page-refcount mutex poisoned");
    let mut bumped: Vec<usize> = Vec::new();
    let mut newly_locked: Vec<usize> = Vec::new();
    for base in page_bases(addr, len) {
        let count = *map.get(&base).unwrap_or(&0);
        if count == 0 {
            if let Err(e) = mlock_page(base, page) {
                // Roll back this call's increments + unlock what we locked.
                for &b in &bumped {
                    if let Some(c) = map.get_mut(&b) {
                        *c -= 1;
                        if *c == 0 {
                            map.remove(&b);
                        }
                    }
                }
                for &b in &newly_locked {
                    munlock_page(b, page);
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
    let page = page_size();
    let mut map = PAGE_REFCOUNTS
        .lock()
        .expect("page-refcount mutex poisoned");
    for base in page_bases(addr, len) {
        match map.get_mut(&base) {
            Some(c) if *c > 1 => {
                *c -= 1;
            }
            Some(_) => {
                map.remove(&base);
                munlock_page(base, page);
            }
            None => {} // underflow: nothing locked here (should not happen)
        }
    }
}
```

- [ ] **Route `zeroed` / `from_array` through the registry.** Replace the body of `zeroed` (lines 100-104):

```rust
    pub fn zeroed() -> Result<Self, String> {
        let bytes = Box::new(Zeroizing::new([0u8; 32]));
        let addr = (&**bytes).as_ptr() as usize;
        lock_key_pages(addr, 32)?;
        Ok(Self { bytes })
    }
```

  and the body of `from_array` (lines 118-122):

```rust
    pub fn from_array(src: [u8; 32]) -> Result<Self, String> {
        let bytes = Box::new(Zeroizing::new(src));
        let addr = (&**bytes).as_ptr() as usize;
        lock_key_pages(addr, 32)?;
        Ok(Self { bytes })
    }
```

- [ ] **Zeroize-before-munlock in `Drop`.** Replace `impl Drop for LockedKey32` (lines 151-160):

```rust
impl Drop for LockedKey32 {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        // Zeroize the secret BEFORE releasing the lock so the page never
        // sits swappable while still holding the secret (the conventional
        // ordering; Box<Zeroizing<..>> would also zeroize on its own drop
        // afterwards). Then decrement the page refcount; the page is only
        // munlock'd when the last key resident on it drops.
        let addr = (&**self.bytes).as_ptr() as usize;
        (**self.bytes).zeroize();
        unlock_key_pages(addr, 32);
    }
}
```

- [ ] **Run it (expect green).** `cargo test --manifest-path rust/tuncore/Cargo.toml secure_memory::tests` — the two new tests pass and the pre-existing `secure_memory` tests (`test_mlock_munlock_roundtrip`, `test_secure_zero`, `test_harden_process_sets_dumpable_zero`, etc.) still pass (they use `mlock_slice`/`munlock_slice` directly, which are unchanged).

- [ ] **Run the focused gate.** `cargo test --manifest-path rust/tuncore/Cargo.toml secure_memory` (whole module incl. the unchanged tests).

- [ ] **Report.** One line: added a process-global page-refcount registry to `secure_memory.rs` so `munlock` only fires on the last key per page; `Drop` now zeroizes before unlocking; two inline tests cover shared-page hold/release.

---

### Task 4: Versioned sealed-blob format with bounds-checked Argon2id params

**Files:**
- Modify: `rust/tuncore/src/passphrase_store.rs` (constants after line 38; `derive_argon2_key` lines 43-59; `seal` lines 74-109; `open` lines 122-153; new `v1_*` inline tests in the existing `#[cfg(test)] mod tests`)
- Test: inline `#[cfg(test)] mod tests` in `rust/tuncore/src/passphrase_store.rs`

Context confirmed: current wire layout is `salt(32) || nonce(24) || ct+tag`, AAD = `salt||nonce`, Argon2id params hard-frozen at `512 MiB / 4 / 2`. Callers `identity::decrypt_from_store` / `device_attest_soft::decrypt_from_store` do an up-front `>= salt+nonce+SECRET_LEN+TAG` length check then call `open`; a v1 blob (17 bytes longer) still satisfies that lower bound, so those modules need no change. v1 layout: `magic(4="DSMK") || version(1) || m(4 BE) || t(4 BE) || p(4 BE) || salt(32) || nonce(24) || ct+tag`. AAD binds the full header so a tampered version/param byte fails AEAD. Legacy blobs are detected by absent magic and decrypt with the frozen production params.

**FLAG FOR OWNER (existing inline tests will fail — do NOT edit them):** Bumping the writer to v1 changes the blob length/layout, so four existing inline tests in `passphrase_store.rs` that pin the *old* layout will fail and must be reconciled by the owner (deliberate format bump, not a code-vs-test conflict to be silently patched): `wire_layout_lock`, `empty_plaintext_is_valid`, `property_roundtrip_random_plaintext_lengths`, and `property_every_byte_flip_in_blob_fails_decrypt` (the last fails at the version byte, where `open` now returns `"unsupported sealed-blob version"` rather than `"decryption failed"`). The other existing tests (`seal_open_roundtrip`, `wrong_passphrase_fails`, `empty_passphrase_*`, `short_blob_rejected`, `corrupted_ciphertext/salt/nonce_rejected`, `distinct_seals_per_call`) still pass. The new `v1_*` tests below are added in new functions only.

- [ ] **Write the failing tests.** Append to the existing `#[cfg(test)] mod tests { ... }` in `rust/tuncore/src/passphrase_store.rs` (add these functions inside the brace, after `property_every_byte_flip_in_blob_fails_decrypt`):

```rust
    /// Build a pre-v1 (legacy) blob with the original layout + AAD so the
    /// legacy reader path can be exercised after the writer moved to v1.
    fn make_legacy_blob(plaintext: &[u8], passphrase: &[u8]) -> Vec<u8> {
        let mut salt = [0u8; ARGON2_SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        // Negligible (2^-32) chance salt starts with the v1 magic; if it
        // does the blob would route to the v1 reader — acceptable for a
        // test fixture.
        let derived = derive_argon2_key(passphrase, &salt, &PARAMS_V1).expect("kdf");
        let cipher = XChaCha20Poly1305::new_from_slice(derived.as_array()).expect("cipher");
        let mut nonce_bytes = [0u8; XCHACHA_NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);
        let aad = build_aad(&salt, &nonce_bytes);
        let ct = cipher
            .encrypt(nonce, Payload { msg: plaintext, aad: &aad })
            .expect("encrypt");
        let mut blob = Vec::new();
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);
        blob
    }

    #[test]
    fn v1_seal_open_roundtrip() {
        let secret = b"32-byte secret right here ******";
        let blob = seal(secret, b"passphrase").expect("seal");
        // Writer must emit the v1 magic + version.
        assert_eq!(&blob[..4], &BLOB_MAGIC);
        assert_eq!(blob[4], BLOB_VERSION_1);
        let pt = open(&blob, b"passphrase").expect("open");
        assert_eq!(&*pt, secret);
    }

    #[test]
    fn v1_legacy_blob_still_decrypts() {
        let blob = make_legacy_blob(b"legacy secret", b"pw");
        let pt = open(&blob, b"pw").expect("legacy open");
        assert_eq!(&*pt, b"legacy secret");
    }

    #[test]
    fn v1_tampered_version_rejected() {
        let mut blob = seal(b"secret", b"pw").expect("seal");
        blob[4] ^= 0xFF; // corrupt the version byte
        let err = open(&blob, b"pw").unwrap_err();
        assert!(
            err.contains("unsupported sealed-blob version"),
            "got: {err}"
        );
    }

    #[test]
    fn v1_tampered_params_rejected() {
        let mut blob = seal(b"secret", b"pw").expect("seal");
        // Flip the low byte of t_cost (offset 12) to a still-in-bounds but
        // different value; the header is in the AAD, so AEAD auth fails.
        blob[12] ^= 0x01;
        let err = open(&blob, b"pw").unwrap_err();
        assert!(err.contains("decryption failed"), "got: {err}");
    }

    #[test]
    fn v1_oversize_params_rejected_before_kdf() {
        // A v1 header advertising u32::MAX KiB of memory must be rejected
        // on the bounds check BEFORE Argon2 attempts the allocation (DoS).
        let kp = KdfParams {
            m_cost_kib: u32::MAX,
            t_cost: 3,
            parallelism: 1,
        };
        let header = build_v1_header(&kp);
        let mut blob = Vec::new();
        blob.extend_from_slice(&header);
        blob.extend_from_slice(&[0u8; ARGON2_SALT_LEN]);
        blob.extend_from_slice(&[0u8; XCHACHA_NONCE_LEN]);
        blob.extend_from_slice(&[0u8; TAG_LEN]); // dummy ct/tag, never reached
        let err = open(&blob, b"pw").unwrap_err();
        assert!(err.contains("out of bounds"), "got: {err}");
    }
```

- [ ] **Run it (expect red).** `cargo test --manifest-path rust/tuncore/Cargo.toml passphrase_store::tests::v1_` — expected failure: compilation error `cannot find value 'BLOB_MAGIC'` / `cannot find type 'KdfParams'` / `cannot find function 'build_v1_header'` / `derive_argon2_key` arity mismatch (the v1 surface does not exist yet).

- [ ] **Add v1 constants + param type.** In `rust/tuncore/src/passphrase_store.rs`, insert after the `MIN_BLOB_LEN` const (after line 38):

```rust
/// Sealed-blob magic + version. v1 layout:
/// `magic(4) || version(1) || m(4 BE) || t(4 BE) || p(4 BE) || salt(32)
///  || nonce(24) || ciphertext+tag`. Legacy blobs (no magic) decrypt via
/// `open_legacy` with the frozen production params.
pub const BLOB_MAGIC: [u8; 4] = *b"DSMK";
pub const BLOB_VERSION_1: u8 = 1;
/// magic(4) + version(1) + m,t,p (3 * u32 BE = 12) = 17.
pub const V1_HEADER_LEN: usize = 4 + 1 + 12;

// Argon2id parameter bounds — reject out-of-range header values before
// invoking the KDF so a hostile blob cannot trigger a multi-GiB
// allocation (DoS) or an impossibly weak derivation.
const MIN_MEM_COST_KIB: u32 = 8;
const MAX_MEM_COST_KIB: u32 = 2_097_152; // 2 GiB ceiling
const MIN_TIME_COST: u32 = 1;
const MAX_TIME_COST: u32 = 16;
const MIN_PARALLELISM: u32 = 1;
const MAX_PARALLELISM: u32 = 16;

#[derive(Clone, Copy)]
struct KdfParams {
    m_cost_kib: u32,
    t_cost: u32,
    parallelism: u32,
}

/// The production (and frozen-legacy) Argon2id parameters.
const PARAMS_V1: KdfParams = KdfParams {
    m_cost_kib: ARGON2_MEM_COST_KIB,
    t_cost: ARGON2_TIME_COST,
    parallelism: ARGON2_PARALLELISM,
};

fn validate_params(p: &KdfParams) -> Result<(), String> {
    if !(MIN_MEM_COST_KIB..=MAX_MEM_COST_KIB).contains(&p.m_cost_kib) {
        return Err(format!(
            "argon2 m_cost {} out of bounds [{MIN_MEM_COST_KIB},{MAX_MEM_COST_KIB}]",
            p.m_cost_kib
        ));
    }
    if !(MIN_TIME_COST..=MAX_TIME_COST).contains(&p.t_cost) {
        return Err(format!(
            "argon2 t_cost {} out of bounds [{MIN_TIME_COST},{MAX_TIME_COST}]",
            p.t_cost
        ));
    }
    if !(MIN_PARALLELISM..=MAX_PARALLELISM).contains(&p.parallelism) {
        return Err(format!(
            "argon2 parallelism {} out of bounds [{MIN_PARALLELISM},{MAX_PARALLELISM}]",
            p.parallelism
        ));
    }
    // Argon2 requires m_cost >= 8 * parallelism.
    if p.m_cost_kib < 8 * p.parallelism {
        return Err("argon2 m_cost too low for parallelism".into());
    }
    Ok(())
}

fn build_v1_header(kp: &KdfParams) -> [u8; V1_HEADER_LEN] {
    let mut h = [0u8; V1_HEADER_LEN];
    h[..4].copy_from_slice(&BLOB_MAGIC);
    h[4] = BLOB_VERSION_1;
    h[5..9].copy_from_slice(&kp.m_cost_kib.to_be_bytes());
    h[9..13].copy_from_slice(&kp.t_cost.to_be_bytes());
    h[13..17].copy_from_slice(&kp.parallelism.to_be_bytes());
    h
}

fn build_aad_v1(header: &[u8], salt: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + salt.len() + nonce.len());
    aad.extend_from_slice(header);
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad
}
```

- [ ] **Parameterize `derive_argon2_key`.** Replace `derive_argon2_key` (lines 43-59):

```rust
fn derive_argon2_key(
    passphrase: &[u8],
    salt: &[u8],
    kp: &KdfParams,
) -> Result<LockedKey32, String> {
    let mut derived = LockedKey32::zeroed()?;
    let params = Params::new(kp.m_cost_kib, kp.t_cost, kp.parallelism, Some(32))
        .map_err(|e| format!("argon2 params: {e}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into(passphrase, salt, derived.as_mut())
        .map_err(|e| format!("argon2 hash: {e}"))?;

    Ok(derived)
}
```

- [ ] **Emit v1 in `seal`.** Replace `seal` (lines 74-109):

```rust
pub fn seal(plaintext: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, String> {
    if passphrase.is_empty() {
        return Err("passphrase must not be empty".into());
    }

    let mut salt = [0u8; ARGON2_SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let kp = PARAMS_V1;
    let derived = derive_argon2_key(passphrase, &salt, &kp)?;

    let cipher = XChaCha20Poly1305::new_from_slice(derived.as_array())
        .map_err(|e| format!("cipher init: {e}"))?;

    let mut nonce_bytes = [0u8; XCHACHA_NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let header = build_v1_header(&kp);
    // Bind the full header into the AAD so a tampered version/param byte
    // is rejected by the AEAD, not merely by the bounds check.
    let aad = build_aad_v1(&header, &salt, &nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| format!("encrypt: {e}"))?;

    let mut blob = Vec::with_capacity(
        V1_HEADER_LEN + ARGON2_SALT_LEN + XCHACHA_NONCE_LEN + ciphertext.len(),
    );
    blob.extend_from_slice(&header);
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    Ok(blob)
}
```

- [ ] **Add format detection + readers in `open`.** Replace `open` (lines 122-153):

```rust
pub fn open(blob: &[u8], passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    if passphrase.is_empty() {
        return Err("passphrase must not be empty".into());
    }
    if blob.len() >= V1_HEADER_LEN && blob[..4] == BLOB_MAGIC {
        open_v1(blob, passphrase)
    } else {
        open_legacy(blob, passphrase)
    }
}

fn open_v1(blob: &[u8], passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let min = V1_HEADER_LEN + ARGON2_SALT_LEN + XCHACHA_NONCE_LEN + TAG_LEN;
    if blob.len() < min {
        return Err("blob too short".into());
    }
    let version = blob[4];
    if version != BLOB_VERSION_1 {
        return Err(format!("unsupported sealed-blob version {version}"));
    }
    let m = u32::from_be_bytes(blob[5..9].try_into().expect("4 bytes"));
    let t = u32::from_be_bytes(blob[9..13].try_into().expect("4 bytes"));
    let p = u32::from_be_bytes(blob[13..17].try_into().expect("4 bytes"));
    let kp = KdfParams {
        m_cost_kib: m,
        t_cost: t,
        parallelism: p,
    };
    validate_params(&kp)?;

    let header = &blob[..V1_HEADER_LEN];
    let salt = &blob[V1_HEADER_LEN..V1_HEADER_LEN + ARGON2_SALT_LEN];
    let nonce_bytes =
        &blob[V1_HEADER_LEN + ARGON2_SALT_LEN..V1_HEADER_LEN + ARGON2_SALT_LEN + XCHACHA_NONCE_LEN];
    let ciphertext = &blob[V1_HEADER_LEN + ARGON2_SALT_LEN + XCHACHA_NONCE_LEN..];

    let derived = derive_argon2_key(passphrase, salt, &kp)?;
    let cipher = XChaCha20Poly1305::new_from_slice(derived.as_array())
        .map_err(|e| format!("cipher init: {e}"))?;
    let nonce = XNonce::from_slice(nonce_bytes);
    let aad = build_aad_v1(header, salt, nonce_bytes);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| "decryption failed: wrong passphrase or corrupted data".to_string())?;

    Ok(Zeroizing::new(plaintext))
}

fn open_legacy(blob: &[u8], passphrase: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    // Pre-v1 layout: salt(32) || nonce(24) || ct+tag, AAD = salt||nonce,
    // Argon2 params frozen at the original production constants.
    if blob.len() < MIN_BLOB_LEN {
        return Err("blob too short".into());
    }
    let salt = &blob[..ARGON2_SALT_LEN];
    let nonce_bytes = &blob[ARGON2_SALT_LEN..ARGON2_SALT_LEN + XCHACHA_NONCE_LEN];
    let ciphertext = &blob[ARGON2_SALT_LEN + XCHACHA_NONCE_LEN..];

    let derived = derive_argon2_key(passphrase, salt, &PARAMS_V1)?;
    let cipher = XChaCha20Poly1305::new_from_slice(derived.as_array())
        .map_err(|e| format!("cipher init: {e}"))?;
    let nonce = XNonce::from_slice(nonce_bytes);
    let aad = build_aad(salt, nonce_bytes);

    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| "decryption failed: wrong passphrase or corrupted data".to_string())?;

    Ok(Zeroizing::new(plaintext))
}
```

  (`build_aad` at lines 61-66 and `MIN_BLOB_LEN` stay as-is — the legacy reader reuses them.)

- [ ] **Run it (expect green).** `cargo test --manifest-path rust/tuncore/Cargo.toml passphrase_store::tests::v1_` — the five `v1_*` tests pass.

- [ ] **Rebuild the extension** so dependent Rust modules / Python keep working: `maturin develop -m rust/tuncore/Cargo.toml`. Then sanity-check the round-trip across the FFI: `cargo test --manifest-path rust/tuncore/Cargo.toml identity::tests::test_encrypt_decrypt_roundtrip 2>/dev/null || cargo test --manifest-path rust/tuncore/Cargo.toml identity` (the identity/attest store seal+open round-trips through the new v1 format; they assert no exact length, only round-trip + last-byte corruption, so they pass).

- [ ] **Run the focused gate.** `cargo test --manifest-path rust/tuncore/Cargo.toml passphrase_store::tests::v1_` (the four pre-v1 layout-lock tests are expected to fail — see the FLAG FOR OWNER above; do not run the whole `passphrase_store` module as the gate).

- [ ] **Report.** One line: `passphrase_store.rs` now writes a v1 header (magic+version+Argon2id m/t/p, header bound into AAD), reads legacy blobs by absent-magic detection, and bounds-checks params before the KDF; five `v1_*` tests added; FLAG raised that four pre-v1 layout-lock tests now fail and need owner reconciliation.

---

### Task 5: Soft-attest acknowledgment gate at daemon startup

**Files:**
- Create: `dsm/crypto/attest_gate.py`
- Modify: `rust/tuncore/src/device_attest.rs` (after line 12, the soft re-export); `rust/tuncore/src/lib.rs` (pymodule, after line 832); `tuncore.pyi` (after line 213); `dsm/core/config.py` (field after line 104); `config.example.toml` (identity section, after line 22); `dsm/server.py` (after the harden block, ~line 72); `dsm/client.py` (after the harden block, ~line 73)
- Test: `tests/test_attest_gate.py` (Create)

Context confirmed: the active attest backend is chosen at Rust compile time in `device_attest.rs` (`dev-soft-attest` is the default Cargo feature, ships in release wheels; `tpm-attest` is a non-compiling placeholder). There is no runtime backend signal today, so Phase 0 exposes one compile-time constant and gates on it. `auth_loader.py` already uses the `netaudit.emit("…", action="refused_start"|"warned")` shape — mirror it.

**FLAG FOR OWNER (two items):**
1. **FFI surface addition.** Exposing `ATTEST_BACKEND_IS_SOFTWARE` adds a public Python attribute to the `tuncore` module (additive, not a signature change). Per the project's "changing a public API" hard-stop, get owner sign-off, and rebuild with `maturin develop -m rust/tuncore/Cargo.toml` so the active `python3` sees it.
2. **netaudit schema lock.** This task adds `netaudit.emit("soft_attest_acknowledged", …)`, a new event name. `tests/test_netaudit.py`'s `TestSchemaLock.test_call_sites_in_repo` asserts every emitted literal is in `EXPECTED_EVENT_NAMES`, so it will fail until the owner adds `"soft_attest_acknowledged"` to that set. Do NOT edit the test here.

- [ ] **Write the failing test.** Create `tests/test_attest_gate.py`:

```python
"""Phase-0 gate: refuse to start on the extractable software attest
backend unless allow_soft_attest is set; warn loudly + audit when it is.
"""

from __future__ import annotations

import datetime
import io
import json
import logging
import unittest

try:
    import tuncore

    _HAS_TUNCORE = True
except ImportError:
    tuncore = None  # type: ignore[assignment]
    _HAS_TUNCORE = False

from dsm.core import netaudit
from dsm.core.config import Config
from dsm.crypto.attest_gate import (
    SoftAttestNotAllowedError,
    enforce_attest_backend_policy,
)
from dsm.crypto.handshake import HandshakeError  # noqa: F401  (import-safety check)


def _client_config(allow_soft_attest: bool) -> Config:
    return Config(
        mode="client",
        server_ip="10.0.0.1",
        server_port=51820,
        listen_port=0,
        key_file="/opt/mtun/identity.key",
        cert_file="/opt/mtun/device.crt",
        ca_root_file="/opt/mtun/ca.pem",
        attest_key_file="/opt/mtun/attest.key",
        expected_server_cn="dsm-test-server",
        allow_soft_attest=allow_soft_attest,
    )


class _AuditCapture:
    """Capture netaudit JSON lines without disturbing other handlers."""

    def __init__(self) -> None:
        self.buf = io.StringIO()
        self._prev: list[logging.Handler] = []

    def __enter__(self) -> _AuditCapture:
        log = logging.getLogger(netaudit.LOGGER_NAME)
        self._prev = list(log.handlers)
        for h in self._prev:
            log.removeHandler(h)
        netaudit.configure(True)
        for h in log.handlers:
            if isinstance(h, logging.StreamHandler):
                h.stream = self.buf
                break
        return self

    def __exit__(self, *exc: object) -> None:
        log = logging.getLogger(netaudit.LOGGER_NAME)
        netaudit.configure(False)
        for h in list(log.handlers):
            log.removeHandler(h)
        for h in self._prev:
            log.addHandler(h)

    def events(self) -> list[dict[str, object]]:
        return [
            json.loads(ln)
            for ln in self.buf.getvalue().splitlines()
            if ln.strip()
        ]


class TestAttestBackendGate(unittest.TestCase):
    def setUp(self) -> None:
        # Make the gate's backend check deterministic regardless of how
        # tuncore was built: force "software" for these tests, restore after.
        self._had = hasattr(tuncore, "ATTEST_BACKEND_IS_SOFTWARE") if tuncore else False
        self._prev = (
            getattr(tuncore, "ATTEST_BACKEND_IS_SOFTWARE", None) if tuncore else None
        )
        if tuncore is not None:
            tuncore.ATTEST_BACKEND_IS_SOFTWARE = True

    def tearDown(self) -> None:
        if tuncore is None:
            return
        if self._had:
            tuncore.ATTEST_BACKEND_IS_SOFTWARE = self._prev
        else:
            try:
                delattr(tuncore, "ATTEST_BACKEND_IS_SOFTWARE")
            except AttributeError:
                pass

    @unittest.skipUnless(_HAS_TUNCORE, "requires tuncore")
    def test_refuses_without_flag(self) -> None:
        with _AuditCapture() as cap:
            with self.assertRaises(SoftAttestNotAllowedError):
                enforce_attest_backend_policy(_client_config(allow_soft_attest=False))
        events = cap.events()
        self.assertTrue(
            any(
                e["event"] == "soft_attest_acknowledged"
                and e.get("action") == "refused_start"
                for e in events
            )
        )

    @unittest.skipUnless(_HAS_TUNCORE, "requires tuncore")
    def test_allows_with_flag_warns_and_audits(self) -> None:
        with _AuditCapture() as cap:
            with self.assertLogs("dsm.crypto.attest_gate", level="WARNING") as logs:
                enforce_attest_backend_policy(_client_config(allow_soft_attest=True))
        self.assertTrue(any("extractable" in m.lower() for m in logs.output))
        events = cap.events()
        self.assertTrue(
            any(
                e["event"] == "soft_attest_acknowledged"
                and e.get("action") == "warned"
                for e in events
            )
        )

    @unittest.skipUnless(_HAS_TUNCORE, "requires tuncore")
    def test_constant_exposed_by_tuncore(self) -> None:
        # After the Rust rebuild, the real constant must exist + be bool.
        # Checked in a fresh subprocess: reloading a PyO3 extension module
        # in-process does NOT re-run module init, so delattr+reload would
        # not restore the real attribute here.
        import subprocess
        import sys

        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                "import tuncore; "
                "print(type(tuncore.ATTEST_BACKEND_IS_SOFTWARE).__name__)",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(proc.stdout.strip(), "bool")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Run it (expect red).** `python3 -m pytest tests/test_attest_gate.py -q` — expected failure: `ModuleNotFoundError: No module named 'dsm.crypto.attest_gate'` (and `Config` rejecting `allow_soft_attest`).

- [ ] **Add the config field.** In `dsm/core/config.py`, insert after the `debug_net` field (after line 104) inside the `Config` dataclass:

```python
    # When False (the default) the daemon refuses to start on the
    # extractable software attestation backend (dev-soft-attest), whose
    # key is recoverable from process memory and provides no hardware
    # binding. Set True to acknowledge and run anyway (NOT for production)
    # — startup then logs a prominent WARNING and emits a netaudit event.
    allow_soft_attest: bool = False
```

  (No validator entry is added — boolean fields `crl_strict`/`debug_net` have none either; matches the existing pattern.)

- [ ] **Document it in `config.example.toml`.** Insert after line 22 (`attest_key_file = …`):

```toml

# Refuse to start on the extractable software attestation backend
# (dev-soft-attest), which ships in current release wheels until the TPM
# backend lands. The soft backend's ECDSA P-256 key is recoverable from
# process memory and provides NO hardware binding. Leave false in
# production; set true only to acknowledge the risk in dev/lab.
# allow_soft_attest = false
```

- [ ] **Expose the Rust constant.** In `rust/tuncore/src/device_attest.rs`, add after the soft re-export (after line 12):

```rust

/// True when the active (compile-time) attestation backend is the
/// software backend, whose key is extractable from process memory.
/// Exposed to Python (`tuncore.ATTEST_BACKEND_IS_SOFTWARE`) so the daemon
/// can gate startup on it (Phase 0). The future `tpm-attest` arm sets
/// this to `false`.
#[cfg(feature = "dev-soft-attest")]
pub const BACKEND_IS_SOFTWARE: bool = true;
```

  Then in `rust/tuncore/src/lib.rs`, in the `#[pymodule] fn tuncore` body, add after the `HANDSHAKE_ATTEST_PAYLOAD_SIZE` add (after line 832, before `Ok(())`):

```rust
    m.add(
        "ATTEST_BACKEND_IS_SOFTWARE",
        device_attest::BACKEND_IS_SOFTWARE,
    )?;
```

  And in `tuncore.pyi`, add after line 213 (`def harden_process() -> None: ...`):

```python

# True when the compiled attestation backend is the extractable software
# backend (dev-soft-attest). The daemon refuses to start on it unless
# config.allow_soft_attest is set.
ATTEST_BACKEND_IS_SOFTWARE: bool
```

  Rebuild: `maturin develop -m rust/tuncore/Cargo.toml`.

- [ ] **Create the gate module.** Write `dsm/crypto/attest_gate.py`:

```python
"""Phase-0 gate: refuse to start on the extractable software attestation
backend unless the operator explicitly acknowledges it.

The dev-soft-attest backend keeps the ECDSA P-256 device-attestation
scalar in process memory in extractable form (Argon2id-wrapped at rest,
but recoverable by anyone who can read the running process). It is the
default Cargo feature and ships in release wheels until the TPM backend
lands, so starting on it without acknowledgement silently downgrades the
hardware-binding guarantee. Fail closed.
"""

from __future__ import annotations

import logging

from dsm.core import netaudit
from dsm.core.config import Config

log = logging.getLogger(__name__)


class SoftAttestNotAllowedError(Exception):
    """Active attest backend is software-based and ``allow_soft_attest``
    is not set; the daemon refuses to start."""


def enforce_attest_backend_policy(config: Config) -> None:
    """Refuse to start on the extractable soft-attest backend unless
    ``config.allow_soft_attest`` is true.

    Raises:
        SoftAttestNotAllowedError: software backend active and not
            acknowledged. When acknowledged, logs a prominent WARNING and
            emits a ``soft_attest_acknowledged`` netaudit event instead.
    """
    import tuncore

    # Fail closed if the build predates the constant: treat as software.
    if not getattr(tuncore, "ATTEST_BACKEND_IS_SOFTWARE", True):
        return  # hardware-backed backend (TPM / Keystore) — nothing to gate

    if not config.allow_soft_attest:
        netaudit.emit("soft_attest_acknowledged", action="refused_start")
        raise SoftAttestNotAllowedError(
            "active device-attestation backend is software-based "
            "(dev-soft-attest): the attestation key is extractable from "
            "process memory and provides no hardware binding. Refusing to "
            "start. Set allow_soft_attest = true in config.toml to run "
            "anyway (NOT recommended for production), or build tuncore with "
            "a hardware attest backend."
        )

    log.warning(
        "RUNNING WITH EXTRACTABLE SOFTWARE ATTESTATION BACKEND "
        "(dev-soft-attest): the device-attestation key is recoverable from "
        "process memory and provides NO hardware binding. allow_soft_attest "
        "is set, so startup continues. Do not use this in production."
    )
    netaudit.emit("soft_attest_acknowledged", action="warned")
```

- [ ] **Wire the gate into both daemons.** In `dsm/server.py`, immediately after the `tuncore.harden_process()` try/except block (after line 71, before `fsm = SessionFSM()` on line 73), add:

```python
    from dsm.crypto.attest_gate import (
        SoftAttestNotAllowedError,
        enforce_attest_backend_policy,
    )

    try:
        enforce_attest_backend_policy(config)
    except SoftAttestNotAllowedError as e:
        log.error("%s", e)
        return
```

  Make the identical insertion in `dsm/client.py` after the harden try/except (after line 72, before `fsm = SessionFSM()` on line 74).

- [ ] **Run it (expect green).** `python3 -m pytest tests/test_attest_gate.py -q` — refused-start raises + audits; allow path warns + audits; the constant is exposed as a bool.

- [ ] **Run the focused gate.** `python3 -m pytest tests/test_attest_gate.py tests/test_config.py -q` (`test_config.py` builds `Config(**_base())` directly and must still accept the new defaulted field.)

- [ ] **Report.** One line: added `allow_soft_attest` config field, a `tuncore.ATTEST_BACKEND_IS_SOFTWARE` constant, and `attest_gate.enforce_attest_backend_policy` wired into both daemons (refuse without flag; WARNING + `soft_attest_acknowledged` audit with it). FLAGs raised for the FFI addition and the netaudit schema lock.

---

### Task 6: Enforce config-file permissions at load (`config.toml` trust-anchor)

**Files:**
- Modify: `dsm/core/config.py` (imports after line 10; add `ConfigError` near line 39; perm check in `load`, lines 393-409)
- Test: `tests/test_config_perms.py` (Create)

Context confirmed: `load()` does `open(p, "rb")` with no ownership/mode check, yet `config.toml` sets `ca_root_file`, `ca_root_sha256`, `crl_strict`, `expected_server_cn`, `allowed_cns_file`, and every key path — all of which the cert/key files themselves guard via `check_user_file_permissions`. `test_config.py` builds `Config(**_base())` directly (does not call `load()`), so it is unaffected.

**FLAG FOR OWNER (existing test conflict — do NOT edit those tests):** `tests/test_cli.py` writes config fixtures via `write_bytes` without `chmod` (default `0644`, group/world-readable) and then calls `load()`. With the perm check in `load()`, these three tests will fail: `TestConfigDirPrecedence.test_env_var_unset_uses_config_parent`, `TestConfigDirPrecedence.test_env_var_overrides_config_parent`, and `TestShowPubkeyInsecurePerms.test_insecure_key_file_exits_2_with_message` (its config is `0644`, so `load()` now rejects the config before reaching the key-perm path the test targets). The owner must `chmod 0600` those fixtures (or otherwise reconcile). Do not modify `test_cli.py` in this plan; the Task-6 focused gate runs only the new file.

- [ ] **Write the failing test.** Create `tests/test_config_perms.py`:

```python
"""Regression: config.toml itself must be permission-checked at load —
it pins the CA root + crl_strict, so a group/world-accessible config is a
trust-anchor-substitution hole (finding: config.py:406)."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from dsm.core.config import ConfigError, load

_VALID_TOML = b"""\
mode = "client"
server_ip = "10.0.0.1"
server_port = 51820
listen_port = 51821
key_file = "/tmp/test.key"
cert_file = "/tmp/test.crt"
ca_root_file = "/tmp/test-ca.pem"
attest_key_file = "/tmp/test-attest.key"
expected_server_cn = "dsm-test-server"
transport = "udp"
"""


class TestConfigPermissions(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = Path(tempfile.mkdtemp())
        self.cfg = self._dir / "config.toml"
        self.cfg.write_bytes(_VALID_TOML)

    def tearDown(self) -> None:
        try:
            self.cfg.unlink()
        except FileNotFoundError:
            pass
        try:
            self._dir.rmdir()
        except OSError:
            pass

    def test_secure_mode_loads(self) -> None:
        os.chmod(self.cfg, 0o600)
        cfg = load(self.cfg)
        self.assertEqual(cfg.mode, "client")

    def test_group_readable_rejected(self) -> None:
        os.chmod(self.cfg, 0o640)
        with self.assertRaises(ConfigError):
            load(self.cfg)

    def test_world_readable_rejected(self) -> None:
        os.chmod(self.cfg, 0o644)
        with self.assertRaises(ConfigError):
            load(self.cfg)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Run it (expect red).** `python3 -m pytest tests/test_config_perms.py -q` — expected failure: `ImportError: cannot import name 'ConfigError'` (and, once that exists, the group/world cases would not raise without the check).

- [ ] **Add the import + error type.** In `dsm/core/config.py`, add after the existing `_validators` import (after line 10):

```python
from dsm.core.path_security import (
    InsecureFilePermissionsError,
    check_user_file_permissions,
)
```

  and define the error type just before `CONFIG_PATH` (after line 10's import block, before line 12):

```python
class ConfigError(Exception):
    """Config file is missing, malformed, or has insecure permissions."""
```

- [ ] **Check perms at load.** In `load()` (lines 393-409), insert the check right after `p = path or CONFIG_PATH` (after line 401), before the env-var branch:

```python
    try:
        check_user_file_permissions(Path(p))
    except InsecureFilePermissionsError as e:
        raise ConfigError(
            f"refusing to load config with insecure permissions: {e}. "
            "config.toml pins the CA root + crl_strict; run: chmod 600 "
            f"{p}"
        ) from e
```

- [ ] **Run it (expect green).** `python3 -m pytest tests/test_config_perms.py -q` — `0600` loads; `0640` and `0644` raise `ConfigError`.

- [ ] **Run the focused gate.** `python3 -m pytest tests/test_config_perms.py tests/test_config.py -q` (`test_config.py` constructs `Config` directly, so it is unaffected by the `load()` change. The Task-6 focused gate intentionally omits `test_cli.py` — see the FLAG above.)

- [ ] **Report.** One line: `config.py` `load()` now runs `check_user_file_permissions` on the config path and raises a typed `ConfigError` on group/world/other-owner/symlink violation; new tests cover good/bad modes; FLAG raised for three `test_cli.py` fixtures that ship `0644` configs.

---

### Task 7: Core-dump backstop (systemd `LimitCORE=0` + ctypes `PR_SET_DUMPABLE`)

**Files:**
- Create: `dsm/core/hardening.py`
- Modify: `deploy/dsm.service` (after `LimitMEMLOCK=infinity`, line 125); `dsm/server.py` (after the harden block, ~line 71); `dsm/client.py` (after the harden block, ~line 72)
- Test: `tests/test_hardening.py` (Create)

Context confirmed: `tuncore.harden_process()` (`secure_memory.rs`) is the primary hardener (`RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`, `PR_SET_NO_NEW_PRIVS`), but `server.py:65`/`client.py:66` catch any failure and continue with only a warning — so a crash after a partial Rust-hardening failure could write a core with key material. The unit has no `LimitCORE`/`CoredumpFilter`. The codebase already uses `ctypes` with `use_errno`/`find_library` in `dsm/core/passphrase.py`; mirror that. No new dependency (ctypes is stdlib).

- [ ] **Write the failing test.** Create `tests/test_hardening.py`:

```python
"""Regression: set_process_nondumpable() clears PR_SET_DUMPABLE so a
post-hardening crash cannot dump key material to a core file. Runs in a
subprocess so the test runner itself stays dumpable."""

from __future__ import annotations

import subprocess
import sys
import unittest


class TestNondumpableBackstop(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux prctl only")
    def test_set_process_nondumpable_clears_flag(self) -> None:
        code = (
            "import ctypes, ctypes.util\n"
            "from dsm.core.hardening import set_process_nondumpable\n"
            "set_process_nondumpable()\n"
            "libc = ctypes.CDLL(ctypes.util.find_library('c') or 'libc.so.6',"
            " use_errno=True)\n"
            "print(libc.prctl(3, 0, 0, 0, 0))\n"  # PR_GET_DUMPABLE == 3
        )
        proc = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(proc.stdout.strip(), "0")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Run it (expect red).** `python3 -m pytest tests/test_hardening.py -q` — expected failure: the subprocess raises `ModuleNotFoundError: No module named 'dsm.core.hardening'`, so `subprocess.run(..., check=True)` raises `CalledProcessError` and the test errors.

- [ ] **Create the backstop module.** Write `dsm/core/hardening.py`:

```python
"""Python-side process-hardening backstop.

``tuncore.harden_process()`` is the primary hardener; when it fails the
daemon catches the error and continues best-effort. This module provides
an independent ctypes backstop for the single most security-critical bit
— ``prctl(PR_SET_DUMPABLE, 0)`` — so a crash after a partial Rust
hardening failure cannot write a core file containing X25519 / ECDSA key
material.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
import sys

log = logging.getLogger(__name__)

# include/uapi/linux/prctl.h
_PR_SET_DUMPABLE = 4


class ProcessHardeningError(Exception):
    """``prctl(PR_SET_DUMPABLE, 0)`` failed at the libc boundary."""


def set_process_nondumpable() -> None:
    """Clear the process dumpable flag via ``prctl(PR_SET_DUMPABLE, 0)``.

    No-op on non-Linux platforms (``PR_SET_DUMPABLE`` is Linux-specific).

    Raises:
        ProcessHardeningError: the syscall is reachable but returned
            non-zero, so the caller can log it at WARNING rather than
            silently proceeding with a dumpable process.
    """
    if not sys.platform.startswith("linux"):
        return
    libc = ctypes.CDLL(
        ctypes.util.find_library("c") or "libc.so.6", use_errno=True
    )
    ret = libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0)
    if ret != 0:
        errno = ctypes.get_errno()
        raise ProcessHardeningError(
            f"prctl(PR_SET_DUMPABLE, 0) failed: errno={errno} "
            f"({os.strerror(errno)})"
        )
```

- [ ] **Run it (expect green).** `python3 -m pytest tests/test_hardening.py -q` — subprocess prints `0` (dumpable cleared).

- [ ] **Add `LimitCORE`/`CoredumpFilter` to the unit.** In `deploy/dsm.service`, insert immediately after `LimitMEMLOCK=infinity` (after line 125):

```ini

# Core-dump backstop. harden_process() sets RLIMIT_CORE=0 and
# PR_SET_DUMPABLE=0 in-process, but that runs after Python starts and its
# failure is non-fatal. These unit-level directives clamp core dumps
# before the process exists, so a crash during early startup (or after a
# partial in-process hardening failure) cannot persist X25519/ECDSA key
# material to a core file.
LimitCORE=0
CoredumpFilter=0x00
```

- [ ] **Wire the Python backstop into both daemons.** In `dsm/server.py`, immediately after the `tuncore.harden_process()` try/except (after line 71), add:

```python
    from dsm.core.hardening import ProcessHardeningError, set_process_nondumpable

    try:
        set_process_nondumpable()
    except ProcessHardeningError as e:
        log.warning("core-dump backstop (PR_SET_DUMPABLE) failed: %s", e)
```

  Make the identical insertion in `dsm/client.py` after its harden try/except (after line 72). (If Task 5's gate insertion already lives here, place this block just before the attest-gate block so hardening happens first.)

- [ ] **Run it (expect green again).** `python3 -m pytest tests/test_hardening.py -q`

- [ ] **Run the focused gate.** `python3 -m pytest tests/test_hardening.py -q`

- [ ] **Report.** One line: added `dsm/core/hardening.set_process_nondumpable` (ctypes `prctl`, WARNING on failure, no-op off-Linux) wired into both daemons, and `LimitCORE=0`/`CoredumpFilter=0x00` to `dsm.service`; subprocess test confirms the dumpable flag is cleared.

---

### Task 8: Stop the netaudit cert-auth detail leak under `--debug-net`

**Files:**
- Modify: `dsm/server.py` (extract a helper near line 53; replace the `handshake_end` emit at lines 246-252)
- Test: `tests/test_netaudit_no_leak.py` (Create)

Context confirmed: the human WARNING log for cert-auth rejection is intentionally opaque ("handshake rejected (cert auth)"), with class+message only at DEBUG, so a journald reader cannot enumerate the allowlist/CRL. But `server.py:246-252` emits `netaudit.emit("handshake_end", role="server", outcome="failed", error=err_name, message=str(e))` to the same journald stream whenever `--debug-net` is on, re-exposing `str(e)`. The leaky emit lives inline in `run_server`'s except block (hard to unit-test), so extract it into a small testable helper. The `test_netaudit.py` schema lock pins event *names* only — `"handshake_end"` is unchanged, so the lock is NOT tripped (no FLAG needed).

- [ ] **Write the failing test.** Create `tests/test_netaudit_no_leak.py`:

```python
"""Regression: the failed-handshake netaudit event must carry only the
exception class name, never str(e) — otherwise --debug-net re-leaks the
cert-auth detail the human log deliberately hides (finding: server.py:246)."""

from __future__ import annotations

import io
import json
import logging
import unittest

from dsm.core import netaudit
from dsm.crypto.handshake import CNNotAllowedError


class _AuditCapture:
    def __init__(self) -> None:
        self.buf = io.StringIO()
        self._prev: list[logging.Handler] = []

    def __enter__(self) -> "_AuditCapture":
        log = logging.getLogger(netaudit.LOGGER_NAME)
        self._prev = list(log.handlers)
        for h in self._prev:
            log.removeHandler(h)
        netaudit.configure(True)
        for h in log.handlers:
            if isinstance(h, logging.StreamHandler):
                h.stream = self.buf
                break
        return self

    def __exit__(self, *exc: object) -> None:
        log = logging.getLogger(netaudit.LOGGER_NAME)
        netaudit.configure(False)
        for h in list(log.handlers):
            log.removeHandler(h)
        for h in self._prev:
            log.addHandler(h)

    def text(self) -> str:
        return self.buf.getvalue()

    def events(self) -> list[dict[str, object]]:
        return [
            json.loads(ln)
            for ln in self.buf.getvalue().splitlines()
            if ln.strip()
        ]


class TestHandshakeFailureNoLeak(unittest.TestCase):
    def test_failed_event_omits_message(self) -> None:
        from dsm.server import _emit_handshake_failure

        secret = "client CN 'dsm-secret-victim-client' not in allowlist"
        with _AuditCapture() as cap:
            _emit_handshake_failure(CNNotAllowedError(secret))
        events = cap.events()
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event"], "handshake_end")
        self.assertEqual(ev["outcome"], "failed")
        self.assertEqual(ev["error"], "CNNotAllowedError")
        self.assertNotIn("message", ev)
        self.assertNotIn("dsm-secret-victim-client", cap.text())


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Run it (expect red).** `python3 -m pytest tests/test_netaudit_no_leak.py -q` — expected failure: `ImportError: cannot import name '_emit_handshake_failure' from 'dsm.server'`.

- [ ] **Extract the testable helper.** In `dsm/server.py`, add a module-level function just after `log = logging.getLogger(__name__)` (after line 53):

```python
def _emit_handshake_failure(err: Exception) -> None:
    """Emit the failed-handshake audit event WITHOUT the exception
    message. The human WARNING/DEBUG logs carry the detail; the netaudit
    stream (journald, enabled by --debug-net) must not, because class +
    message would let a journald reader enumerate the CN allowlist / CRL
    that the opaque WARNING deliberately hides (appsec finding)."""
    netaudit.emit(
        "handshake_end",
        role="server",
        outcome="failed",
        error=type(err).__name__,
    )
```

- [ ] **Use the helper at the emit site.** In `run_server`'s except block, replace the inline emit (lines 246-252):

```python
                netaudit.emit(
                    "handshake_end",
                    role="server",
                    outcome="failed",
                    error=err_name,
                    message=str(e),
                )
```

  with:

```python
                _emit_handshake_failure(e)
```

  (`err_name` is still used by the `log.debug(...)` calls above it, so leave that variable as-is.)

- [ ] **Run it (expect green).** `python3 -m pytest tests/test_netaudit_no_leak.py -q` — the event carries `error="CNNotAllowedError"`, no `message` key, and the secret CN string is absent from the emitted line.

- [ ] **Run the focused gate.** `python3 -m pytest tests/test_netaudit_no_leak.py tests/test_netaudit.py -q` (the schema lock in `test_netaudit.py` still passes — `"handshake_end"` is unchanged and no new event name was introduced.)

- [ ] **Report.** One line: extracted `_emit_handshake_failure` in `server.py` that emits `handshake_end` with the exception class only (drops `message=str(e)`), closing the `--debug-net` cert-auth enumeration side channel; new test asserts the message text is absent; schema lock untouched.

---

## Self-review notes (already reconciled in the plan above)

- **No placeholder language.** Every code block is concrete and derived from the read source (correct imports, names, signatures, existing error types, existing fixtures `make_test_ca`/`make_enrolled_device`/`CNAllowlist`/`_HAS_TUNCORE`/`apply_so_mark` patch).
- **Symbols verified against source:** `HandshakeError`/`HANDSHAKE_FRAME_SIZE`/`server_handshake` (handshake.py), `UDPTransport.bind/send/aclose` (transport/udp.py), `_ProxyProtocol`/`_handle_query`/`_inflight`/`_tasks`/`_schedule` (dns_proxy.py), `LockedKey32`/`mlock_slice`/`syscall_check`/`Zeroizing` (secure_memory.rs), `ARGON2_*`/`MIN_BLOB_LEN`/`TAG_LEN`/`build_aad`/`derive_argon2_key`/`PARAMS` (passphrase_store.rs), `device_attest::AttestKey`/feature `dev-soft-attest` (device_attest.rs, Cargo.toml), `netaudit.emit`/`LOGGER_NAME`/`configure` (netaudit.py), `check_user_file_permissions`/`InsecureFilePermissionsError` (path_security.py), `Config` fields (config.py).
- **Type hints** on all new Python signatures; black/88-col formatting; specific exceptions; `raise X from e` chaining used (Tasks 1, 6).
- **Rust:** no `unwrap()` outside tests; string-error convention preserved (crate does not use `thiserror` today); `zeroize` ordering fixed in `Drop`; `OsRng` already used; no new dependency (`std::sync::LazyLock` is the only new std item).
- **No existing test file is edited.** Conflicts are surfaced as FLAG FOR OWNER items (Tasks 4, 5, 6).
- **Test commands are runnable as written:** `python3 -m pytest tests/<file> -q` (system interpreter has `dsm`+`tuncore`); `cargo test --manifest-path rust/tuncore/Cargo.toml <filter>`; `maturin develop -m rust/tuncore/Cargo.toml` for rebuilds (Tasks 4, 5).
