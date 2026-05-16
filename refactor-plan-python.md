# Python Refactor Plan — DSM_V2.0

Pure planning artifact. No edits made. All hard rules from the refactoring
skill apply: every proposed change preserves observable behavior; bugs,
security tightening, perf optimizations, and API changes are flagged
separately and NOT proposed as refactors.

Scope read fully:
- All `.py` files under `dsm/` (40 files, ~3500 LOC)
- `tests/` skimmed for test→module dependency mapping; the refactor plan
  cites named tests that exercise each proposed change.

Baseline (not re-run by this pass): 253 Python tests on `main` are
reported as passing. Any refactor here would be gated on the suite
remaining green with zero changes to test files (call-site updates only,
and only for the items in §LOW that rename module-private helpers).

---

## Summary

- HIGH severity: 6 items
- MEDIUM severity: 12 items
- LOW / cosmetic: 9 items

(27 items total. Items are ordered within each tier roughly by the
amount of code they affect.)

---

## Out of scope (flagging only — bugs / security / API / design questions)

Noticed during the read pass, NOT included in any proposed refactor.
Each is one or more separate decisions for the appropriate sub-agent
(bugfixer / security-crypto / etc.).

1. **`dsm/net/dns_proxy.py:86, 122–128` — stale docstring reference.**
   The comment says "rate-limited via `_shed_log_throttle`" but the
   actual attributes are `_tasks_shed` / `_tasks_shed_last_log`. This is
   a documentation/comment fix, not a refactor. Flag for `git-docs`.

2. **`dsm/net/dns_proxy.py:181–193` — `inflight_future` lifecycle on
   exception inside the `async with self._sem:` block.** If
   `self._resolver.resolve(qname)` raises, `inflight_future.set_exception`
   runs but the `finally: del self._inflight[query_key]` may delete a
   key while other coroutines are awaiting that very future. The
   awaiters will observe the exception (correct), but the *next*
   identical query will not coalesce against the in-flight future
   (because we already deleted it) — which is the intended de-dup
   contract anyway. Probably correct; flag for `code-review` so this is
   recorded as deliberate rather than accidental.

3. **`dsm/crypto/cert.py:46` vs `dsm/crypto/crl.py:111` — strong-hash
   allowlist defined twice with the *same* set (`{"sha256","sha384",
   "sha512"}`) but only one (cert.py) goes through the
   `_check_strong_signature_hash` helper.** A real refactor would
   centralize it; doing so without behavior change is plausible but the
   error messages currently differ slightly (cert: `"only [...] are
   accepted"` listing sorted set; CRL: `"only sha256, sha384, sha512
   are accepted"` hardcoded). Either change risks shifting an
   observable log line, which `tests/test_crl.py` and `tests/test_cert.py`
   may assert. See refactor MED-3.

4. **`dsm/crypto/handshake.py:464` — `_ = handshake_hash` discards the
   server-side handshake hash that was computed for "diagnostic
   symmetry with client" (comment).** Either it's used downstream and
   the `_ =` line is dead code, or it's genuinely unused and the entire
   `handshake_hash = bytes(responder.get_handshake_hash())` assignment
   on L410 is dead computation. Flag for `code-review`.

5. **`dsm/__main__.py:212, 220` — bare `except Exception as e` around
   `load_with_passphrase`** — the underlying `KeyStore.load_with_passphrase`
   only raises `RuntimeError`, but `cryptography.exceptions` types may
   leak through the FFI boundary on a malformed blob. Narrowing here
   without losing coverage would need a manual test of every error path
   tuncore can raise out of `decrypt_from_store`. Flag for
   `error-handling-design`.

6. **`dsm/net/tunnel.py:36–56` — `_run_commands` swallows generic
   `Exception` on `strict=True` only when *not* a known
   subprocess.TimeoutExpired / CalledProcessError.** `except Exception:
   if strict: raise` — but the previous two arms already cover the only
   exceptions `subprocess.run` raises. This `except Exception` clause
   is unreachable today. Removing it is technically a refactor (dead
   code), but might be load-bearing future-proofing; flag for
   `code-review`.

7. **`dsm/crypto/handshake.py:316` — `client_addr` parameter is
   declared on `server_handshake` but never read** (its value comes
   from `msg1`'s `recv_addr`). Dead parameter; removal is an API
   change. Flag.

8. **`dsm/server.py:309` — `client_addr: list[tuple[str, int] | None] =
   [None]` uses a single-element list as a mutable cell so it can be
   captured by closure-with-write.** A `[None]` is a working pattern
   but a one-line `dataclass` (or `types.SimpleNamespace`) with an
   `addr` field would be clearer. This crosses into design taste — the
   list is part of the closure contract with `make_send_fn`'s
   `dest_addr` callable; changing it touches public-ish session shape.
   Flag for `architecture-design`.

9. **`dsm/server.py:179–181` — TCP transport recreated each iteration**
   inside the handshake retry loop; the previous transport is closed
   with `await transport_obj.aclose()` before a new `TCPTransport()` is
   constructed. This is correct behavior given `listen()` accepts once,
   but the resource hand-off contains a subtle window where shutdown
   could race a re-create; the existing loop's `if shutdown.is_set()`
   check after the inner `await` guards it. Flag for `code-review` to
   record this as deliberate.

10. **`dsm/net/forwarding.py:28` vs `dsm/core/config.py:11` vs
    `dsm/net/tunnel.py:25` — three different TUN/iface name regexes**
    (config and forwarding match the same, tunnel allows `.` extra).
    See refactor MED-4. The character-set difference is intentional per
    the comments, but the existence of duplicate patterns at three
    sites is a smell. Flag separately for clarity that this isn't a
    bug.

11. **`dsm/client.py:25` — `VPN_DNS_SERVER = "10.8.0.1"` is a hardcoded
    string repeated in `dsm/server.py:47` as `SERVER_TUN_IP`.** Single
    source of truth missing. See refactor LOW-9 — proposed as a
    rename/move; cross-flag as a design concern in case the duplication
    is deliberate (client vs server-side perspective).

12. **`dsm/net/dns.py:90`'s `_HOSTS_FILE_MAX_BYTES` is a class-level
    constant placed *after* `__init__` and `_load_hosts_file`'s
    docstring** — placement is unusual but harmless. Flag for cosmetic
    cleanup if interested.

---

## HIGH-impact refactors

### 1. `client.py` four duplicated handshake-error blocks → dispatch table or generic handler

- **File:** `dsm/client.py:148–179`
- **Change:** The `try:` block calling `client_handshake(...)` has four
  near-identical `except` arms (`CNMismatchError`, `CertRevokedError`,
  `CertAuthError`, `HandshakeError`) that each do exactly:
  ```
  log.error("<custom-prefix>: %s", e)
  netaudit.emit("handshake_end", role="client", outcome="failed",
                error="<ExceptionName>", message=str(e))
  fsm.transition(State.TEARDOWN)
  return
  ```
  Replace with a single `except (CNMismatchError, CertRevokedError,
  CertAuthError, HandshakeError) as e:` block. The error-class-specific
  log prefix becomes a small dict literal `_HANDSHAKE_ERR_LABELS = {
  CNMismatchError: "server CN check failed", ... }` looked up by
  `type(e)`. Server CN log prefix is the only piece that varies; the
  netaudit fields are derivable mechanically (`type(e).__name__`,
  `str(e)`).
- **Why:** ~30 lines down to ~10, with the FSM-teardown and emit shape
  identical to today (regression-locked by
  `tests/test_handshake_integration.py::test_client_rejects_server_wrong_cn`
  and `::test_client_pinned_to_other_ca_rejected`, which only inspect
  the `fsm.state` and the audit-stream contents — both unchanged).
- **Behavior preserved:** Each error class still produces an identical
  log line (prefix from the dict) and an identical `netaudit.emit`
  payload (error=`type(e).__name__`, message=str(e)). `fsm.transition`
  is called once per arm today and once after the consolidated arm —
  same number of FSM transitions per code path. Falling out of the
  function via `return` is identical; `AsyncExitStack` still unwinds.
- **Tests affected:**
  - `tests/test_handshake_integration.py::TestClientRejectsBadServer::test_client_rejects_server_wrong_cn`
  - `tests/test_handshake_integration.py::TestClientRejectsBadServer::test_client_pinned_to_other_ca_rejected`
  - (No call-site updates needed — these tests assert outcomes, not the
    internal try-except shape.)

### 2. `__main__.py` enroll/show-pubkey passphrase scaffolding → context manager helper

- **File:** `dsm/__main__.py:200–250` and `:266–282`
- **Change:** `_run_enroll`'s `--import` branch and `_run_show_pubkey`
  both follow an identical pattern:
  1. `passphrase = read_passphrase(...)`
  2. nested `try/except` to load keystore (and attest_store in enroll)
     with `RuntimeError` → `sys.exit(2)`
  3. `finally: wipe_passphrase(passphrase)` on the outer
  4. another nested `try/finally: keystore.unload()` (+ `attest_store.unload()`)

  Extract into a single context manager `_loaded_stores(
  config, passphrase_fd, passphrase_env_file, *,
  include_attest: bool) -> Iterator[tuple[KeyStore, AttestStore | None]]`
  that handles passphrase read → wipe → load → unload in the correct
  order with the same exit-on-RuntimeError logging.

  Similar pattern duplicated again in `dsm/client.py:75–94` and
  `dsm/server.py:99–118` — those are slightly different (no
  `sys.exit(2)`, they `return` instead), so the helper would need a
  callback or a tighter scope. Realistic plan: extract two helpers,
  one for the CLI (`exit_on_error=True`) and one for the daemon
  (`exit_on_error=False`).

- **Why:** Currently ~50 lines of nested-finally scaffolding repeated
  four times. Real load/unload semantics are non-obvious because of
  the asymmetric unload-order requirement (keystore loads first +
  unloads after attest_store on failure, but unloads LAST in the
  AsyncExitStack ordering). Centralizing means future changes to the
  passphrase lifecycle happen in one place.
- **Behavior preserved:** Exact order of load/wipe/unload preserved;
  `sys.exit(2)` codes preserved; stderr message format preserved.
- **Tests affected:**
  - `tests/test_cli.py` (calls `config_load`, doesn't invoke `_run_enroll`
    directly; safe).
  - `tests/test_keystore.py::TestKeyStorePermissionCheck` and
    `tests/test_enroll.py::*` — these test the underlying store/enroll
    primitives, not `__main__`. Safe.
  - No call-site updates required.

### 3. `session.py` lazy `from dsm.core import netaudit` imports inside hot-path functions → top-level import

- **File:** `dsm/session.py:75, 437, 507, 530`; also
  `dsm/rekey.py:193, 240`; `dsm/net/nftables.py:105, 116, 159, 174`;
  `dsm/net/tunnel.py:247, 296`
- **Change:** Convert the lazy `from dsm.core import netaudit`
  statements inside functions to a single top-level
  `from dsm.core import netaudit` per file. Today each emit() site
  does its own local import; running `grep -n "from dsm.core import
  netaudit"` finds 11 in-function imports across 5 files. There is no
  import cycle here (`dsm.core.netaudit` only depends on stdlib).
- **Why:** The lazy imports were probably added defensively but
  `dsm.core.netaudit` has no transitive deps that could circle back.
  Each in-function import is a runtime dict lookup in `sys.modules` —
  cheap, but it's clutter. More importantly, the inconsistent mix
  (some files import at top, some lazily) is a comprehensibility cost.
  Note: leaving them as-is would also be acceptable. **Open question
  for the user before executing:** is there a specific reason the lazy
  pattern was chosen, e.g. test patching that grabs the module
  pre-import? If yes, leave alone.
- **Behavior preserved:** Module import order is unchanged. `netaudit`
  is imported at module top instead of on first use — the very first
  call to any of these functions already triggered the import, so the
  observable behavior is identical (`netaudit.emit` does the same
  thing).
- **Tests affected:**
  - `tests/test_netaudit.py` (asserts emission via the logger;
    unchanged because the logger config is the same).
  - All integration tests that use `netaudit.configure(True)` to
    capture events (`tests/test_data_path_integration.py`) — unchanged.

### 4. `client.py` and `server.py` shared "post-handshake datapath setup" → helper in `session.py`

- **Files:** `dsm/client.py:274–349` and `dsm/server.py:300–386`
- **Change:** Both modules construct the same shape of state after
  the handshake completes:
  - `SequenceCounter()`, `RekeyState()`, `LivenessState()`,
    `ReassemblyBuffer()`, `tuncore.ReplayWindow()`
  - `setup_signal_handlers(shutdown)` (already done on client; server
    does it earlier in the same shape)
  - `make_send_fn(...)`, `SendScheduler(...)`, `scheduler.start()`,
    `stack.push_async_callback(scheduler.stop)`
  - Build `DataPathContext(...)`
  - Build `recv_loop` (the per-role differences are the
    `isinstance(transport, UDPTransport)` branch + the post-decrypt
    `client_addr[0] = recv_addr` server-side line)
  - `await asyncio.gather(recv_loop(), tun_send_loop(ctx),
    liveness_loop(ctx), [client-only: auto_mtu_loop(ctx, transport,
    config)])`
  - `finally: await send_session_close(ctx); fsm.transition(...)`

  Extract a `run_data_path(ctx_builder, transport, session_keys, fsm,
  config, dest_addr_fn, post_decrypt_hook=None)` that returns once the
  recv loop / gather exits. Per-role differences become two
  parameters:
  - `dest_addr_fn`: `lambda: server_addr` (client) vs `lambda:
    client_addr[0]` (server)
  - `post_decrypt_hook`: server passes a callable that updates
    `client_addr[0] = recv_addr`; client passes `None`
  - `extra_loops`: client appends `auto_mtu_loop(ctx, transport,
    config)`, server appends nothing.

- **Why:** ~75 lines of near-duplicate orchestration. The two recv
  loops are the only piece with real divergence, and that divergence
  is mechanical. This is the largest dedup opportunity in the
  codebase by line count and the one that most rewards future change
  (every new datapath state has to be added in two places today).
- **Behavior preserved:** Exact same task list to `asyncio.gather`,
  same `try/except CancelledError/finally` shape, same
  `send_session_close` call, same FSM transitions. The recv_loop
  per-role logic stays in the role-specific runtime module via the
  hook callback — no behavior moves out of role-context.
- **Tests affected:**
  - `tests/test_data_path_integration.py::*` (5 tests) — these
    construct the datapath manually using the same `make_send_fn` /
    `SendScheduler` / `DataPathContext` primitives. They never call
    `run_client` or `run_server`. Safe — no call-site updates.
  - `tests/test_auto_mtu.py::*` — patches/calls `auto_mtu_loop`
    directly; safe.
- **Caveat — this is the highest-risk refactor on the plan.** The
  shape of `client.py` / `server.py` is hand-tuned for unwind order
  (see the deep comments at `client.py:184–248` about TUN/nft/resolv
  unwind being kill-switch-safe). The extracted helper MUST NOT pull
  the AsyncExitStack into itself — the stack stays in the role
  module, only the *data-path orchestration after stack setup* moves
  into the helper. Wait for explicit approval on this one even
  within the refactor plan.

### 5. `dsm/rekey.py` four `InnerPacket` construction sites for REKEY_INIT / REKEY_ACK → small builders

- **File:** `dsm/rekey.py:69–75, 94–100, 147–153, 175–181`
- **Change:** All four sites construct an `InnerPacket(ptype=...,
  epoch_id=session_keys.epoch & 0x03, payload=...)`, pad it with
  `shaper.pad_packet(inner)`, and await `send_fn(padded, target_size)`.
  Extract a single helper:
  ```python
  async def _send_rekey_packet(
      ptype: PacketType,
      payload: bytes,
      session_keys: tuncore.SessionKeyManager,
      shaper: TrafficShaper,
      send_fn: SendFn,
  ) -> None:
      inner = InnerPacket(
          ptype=ptype,
          epoch_id=session_keys.epoch & 0x03,
          payload=payload,
      )
      padded, target_size = shaper.pad_packet(inner)
      await send_fn(padded, target_size)
  ```
  All four call sites collapse to a single line.
- **Why:** Eliminates ~16 lines of mechanical duplication. The
  `epoch_id=session_keys.epoch & 0x03` magic value appears six times
  across `session.py` and `rekey.py` (`grep -n "epoch_id=ctx.session
  _keys.epoch & 0x03\|epoch_id=session_keys.epoch & 0x03"`) — this
  centralizes 4 of them. The other 2 (in `session.py:380, 450`) are in
  KEEPALIVE and SESSION_CLOSE construction; a parallel small builder
  in `session.py` is candidate MED-7 below.
- **Behavior preserved:** Each call produces identical inner, identical
  `pad_packet` invocation, identical `send_fn` call. Padding entropy
  per-call is from `os.urandom` inside `pad_packet`, unchanged.
- **Tests affected:**
  - `tests/test_data_path_integration.py::test_rekey_roundtrip`
  - `tests/test_data_path_integration.py::test_rekey_duplicate_init_resends_cached_ack`
  - `tests/test_data_path_integration.py::test_rekey_retry_scheduler_fires_on_timeout`
  - These tests drive the rekey path via `initiate_rekey` /
    `handle_rekey_init`; the helper is module-private, no test imports
    it. Safe.

### 6. `dsm/crypto/auth_loader.py` and `dsm/crypto/enroll.py` — duplicate PEM-or-DER sniff & parse

- **Files:** `dsm/crypto/auth_loader.py:58–79` (`_load_cert_der`),
  `dsm/crypto/enroll.py:151–162` (`_load_cert_any_format`)
- **Change:** Both functions implement
  `raw.lstrip().startswith(b"-----BEGIN")` → `DeviceCert.from_pem` →
  fallback `DeviceCert.from_der`, with bespoke `EnrollError` /
  `AuthMaterialsError` wrappers around `CertError`. Move the
  detect-and-parse logic to a classmethod on `DeviceCert`:
  ```python
  @classmethod
  def from_pem_or_der(cls, raw: bytes) -> DeviceCert:
      if raw.lstrip().startswith(b"-----BEGIN"):
          return cls.from_pem(raw)
      return cls.from_der(raw)
  ```
  Both call sites become:
  ```python
  try:
      leaf = DeviceCert.from_pem_or_der(raw)
  except CertError as e:
      raise <ModuleError>(f"...{e}") from e
  ```
  The error-class-wrapping stays in each caller (different exception
  type per caller). The PEM/DER decision moves into the cert module
  where it belongs.
- **Why:** Eliminates a duplicated 8-line block, also colocates the
  sniff with the parsing functions. Currently the sniff is in two
  unrelated modules and would silently drift if either's PEM detection
  needs updating.
- **Behavior preserved:** Same sniff, same parse calls, same error
  type out of `DeviceCert` constructors. The bespoke error-wrapping at
  each call site remains — only the sniff logic moves.
- **Tests affected:**
  - `tests/test_enroll.py::*` (calls `import_signed_cert` which goes
    through `_load_cert_any_format`).
  - `tests/test_cert.py::*` (exercises `DeviceCert.from_der` /
    `from_pem` separately).
  - No call-site updates — the new classmethod is additive; existing
    `from_pem`/`from_der` are unchanged.

---

## MEDIUM-impact refactors

### MED-1. `dsm/core/config.py:_validate` is a 180-line monolithic function → split into validators

- **File:** `dsm/core/config.py:104–289`
- **Change:** `_validate(c: Config)` validates 14 distinct config
  sections (mode, IPs, ports, transport, dns, certs, role-specific,
  padding, jitter, rotation, log_level, tun_name, mtu, pmtu_interval).
  Split into private functions `_validate_mode`, `_validate_ports`,
  `_validate_dns`, `_validate_certs`, `_validate_shaping`, etc., and
  have `_validate` call each in sequence.
- **Why:** Easier to read, easier to diff when a single rule changes,
  and the helpers are unit-testable in isolation. No behavior change.
- **Behavior preserved:** Same `ValueError`/log lines, same order
  (caller of `Config(...)` sees the *first* error message — order
  matters!). The split functions are called in the SAME order they're
  written today.
- **Tests affected:**
  - `tests/test_config.py::*` (~17 cases) — each exercises a specific
    validation path. Locked in; the order of validation is asserted by
    the test for the *first* error message in some cases.

### MED-2. `dsm/core/passphrase.py:_read_noninteractive` repeats the same try/log/return-None pattern 4 times

- **File:** `dsm/core/passphrase.py:113–154`
- **Change:** Four nearly-identical `try: return _read_from_fd(fd)
  except (OSError, ...): log.warning(...); return None` arms.
  Factor each source into a `(name, callable)` tuple and iterate:
  ```python
  _SOURCES: list[tuple[str, Callable[..., bytearray]]] = [
      ("fd", _read_from_fd),
      ("file", _read_from_file),
      ("env_file", lambda: _read_from_file(env_file)),
      ("env_var", _read_from_envb),
  ]
  ```
  However this is hard to do without changing observable behavior
  because the four sources have different argument shapes (FD vs path
  vs no-arg) and the env-file's warning message includes the path
  value. Probably a smaller win: extract a `_try_read(label, fn)`
  helper that wraps each call in try/except, but keep the four
  branches.
- **Why:** Reduces repetition; current shape is ~40 lines of nested
  if/try.
- **Behavior preserved:** Each source's failure log message stays
  exactly as-is (operators may grep them). Same fallback order.
- **Tests affected:** No dedicated tests for
  `_read_noninteractive`; covered indirectly by
  `tests/test_keystore.py` and `tests/test_cli.py` smoke paths.

### MED-3. Strong-hash-name allowlist defined in two places with slightly different error messages

- **Files:** `dsm/crypto/cert.py:46` and `dsm/crypto/crl.py:111`
- **Change:** Move `_STRONG_HASH_NAMES` and the
  `_check_strong_signature_hash` helper to `dsm/crypto/cert.py` (or a
  new tiny `dsm/crypto/_sig_algs.py`) and have `crl.py` import + use
  the same helper. The duplicated assert on L111 of crl.py becomes
  `_check_strong_signature_hash(sig_alg, "CRL")` — which produces the
  cert-style error message ("only [...] are accepted").
- **Why:** Single source of truth for which signature algorithms are
  acceptable. Operators reading the error message will see the same
  format from both contexts.
- **Behavior preserved:** Same algorithm rejection. **CAVEAT:** the
  error message wording changes for CRL (from "only sha256, sha384,
  sha512 are accepted" to "only ['sha256', 'sha384', 'sha512'] are
  accepted"). Need to verify `tests/test_crl.py` doesn't assert on
  this string. If it does, defer or update the test as an explicit
  call-site fix (which would be a test modification — gated by the
  hard rule above, requires explicit approval). Wait for user
  approval before executing.
- **Tests affected:**
  - `tests/test_crl.py::*` — check whether any case asserts on the
    exact error message text. If yes, this becomes "needs approval to
    modify the test"; if no, safe.
  - `tests/test_cert.py::*` — already uses the cert-style message;
    no change.

### MED-4. Three TUN-name regexes in three modules

- **Files:** `dsm/core/config.py:11`, `dsm/net/forwarding.py:28`,
  `dsm/net/tunnel.py:25` (`_IFACE_NAME_RE` has an extra `.\-`)
- **Change:** Move `_TUN_NAME_PATTERN` to a single home (proposal:
  `dsm/core/path_security.py` or a new `dsm/core/_validators.py`).
  Keep `tunnel.py`'s broader iface regex separate if its broader
  charset is deliberate (it is — per the comment, it validates names
  loaded from a *persisted* state file and must accept whatever the
  kernel will accept, not just what dsm itself names).

  Proposal: introduce two named constants in one shared module:
  `DSM_TUN_NAME_RE` (the strict pattern used for dsm-issued names)
  and `LINUX_IFACE_NAME_RE` (the broader one for restoring persisted
  state). Both `config.py` and `forwarding.py` import the strict one;
  `tunnel.py` keeps the broader one (now named).
- **Why:** Currently three patterns risk drifting independently
  (e.g., adding IPv6 zones to one).
- **Behavior preserved:** Same regex literals.
- **Tests affected:**
  - `tests/test_config.py::test_tun_name_rejects_*` (3+ cases) —
    asserts validation behavior, not the regex literal. Safe.
  - `tests/test_tunnel_ipv6.py` — tests IPv6 restore including the
    iface-name validation. Safe (the broader pattern is unchanged).

### MED-5. `dsm/net/forwarding.py:IPForwardingManager._set` and `dsm/net/nftables.py:TcpTimestampsDisabler` — same /proc/sysctl read-write-restore pattern

- **Files:** `dsm/net/forwarding.py:53–88`,
  `dsm/net/nftables.py:60–88`
- **Change:** Both classes implement "remember the prior value of a
  /proc file, write a new value, restore on teardown" with subtly
  different shapes:
  - `IPForwardingManager` works against multiple keys (dict of
    originals) via `_set(key, value)`.
  - `TcpTimestampsDisabler` works against one fixed path with a
    single `_original` string.

  Extract `dsm/core/sysctl.py::ScopedSysctlOverride(key, value)` as a
  context manager that captures/restores any number of (key, value)
  pairs via a single API. Both managers retain their public
  apply/remove shape; their internals delegate.
- **Why:** Currently the read/write/restore code is duplicated with
  drift potential (e.g., `TcpTimestampsDisabler` doesn't log the
  attempted write only if it differs from current — but
  `_IPForwardingManager._set` only updates `self._original` when
  `current != value`, an asymmetry).
- **Behavior preserved:** Each manager's apply / remove behavior is
  preserved bit-for-bit. The asymmetry above (one always logs, one
  only on change) STAYS, because the proposed helper exposes a flag
  to control it.
- **Tests affected:** No dedicated tests for these managers;
  exercised indirectly by `test_data_path_integration` (which mocks
  out the apply via `MockTun` etc.).

### MED-6. `dsm/crypto/handshake.py:_recv` — `if isinstance(transport, UDPTransport)` branched 6 times across `_recv` and call sites

- **File:** `dsm/crypto/handshake.py:508, 524`; also at call sites
  `:183, 268, 369, 420`
- **Change:** `_recv` and several callers each branch on
  `isinstance(transport, UDPTransport)` to decide whether `recv()`
  returns `(bytes, addr)` or just `bytes`. Push the branching down
  into a tiny adapter:
  ```python
  async def _recv_one(transport) -> tuple[bytes, tuple[str, int] | None]:
      if isinstance(transport, UDPTransport):
          frame, addr = await transport.recv()
          return bytes(frame), addr
      frame = await transport.recv()
      return bytes(frame), None
  ```
  Then `_recv`'s body just calls `await asyncio.wait_for(_recv_one(...))`
  in both the `indefinite` and the retry-loop arms. The caller-side
  `if isinstance(transport, UDPTransport) and recv_addr != server_addr`
  source-pinning checks stay where they are (they're not duplication —
  they're per-message-position policy).
- **Why:** ~12 lines down to 6, and the per-arm `bytes()` coercion
  becomes a single line. `_recv` becomes much easier to read.
- **Behavior preserved:** Same blocking semantics, same timeouts, same
  return tuple shape.
- **Tests affected:**
  - `tests/test_handshake.py::TestHandshakeFraming` — tests the pad
    helpers only, not `_recv`. Safe.
  - `tests/test_handshake_integration.py::*` (full handshake over UDP
    and TCP) — locks the behavior. Safe.
  - `tests/test_handshake_retry_outage.py` — locks retry behavior.
    Safe.

### MED-7. `session.py` KEEPALIVE and SESSION_CLOSE inner-packet construction → small builder

- **Files:** `dsm/session.py:378–385, 448–454`
- **Change:** Parallel to refactor HIGH-5 (rekey builders). KEEPALIVE
  and SESSION_CLOSE both construct an InnerPacket with empty payload
  and the same `epoch_id=ctx.session_keys.epoch & 0x03`, pad it, then
  one calls `send_fn` directly (SESSION_CLOSE, bypasses scheduler) and
  the other calls `scheduler.enqueue` (KEEPALIVE). Helper:
  ```python
  def _build_control_packet(ctx, ptype) -> tuple[bytes, int]:
      inner = InnerPacket(
          ptype=ptype,
          epoch_id=ctx.session_keys.epoch & 0x03,
          payload=b"",
      )
      return ctx.shaper.pad_packet(inner)
  ```
  Each call site becomes a 2-liner: build, then either `await
  ctx.send_fn(padded, ts)` (session_close) or `ctx.scheduler.enqueue(
  padded, ts)` (keepalive).
- **Why:** Centralizes the "zero-payload control packet" idiom.
- **Behavior preserved:** Same bytes on the wire, same dispatch.
- **Tests affected:**
  - `tests/test_data_path_integration.py::test_session_close_triggers_peer_shutdown`
  - No call-site updates.

### MED-8. `dsm/net/dns.py` `_resolve_doh` and `_resolve_dot` share the same connect+pin-check+request+cleanup scaffold

- **File:** `dsm/net/dns.py:202–323`
- **Change:** Both methods (~60 lines each) do:
  1. `urlparse` + scheme/host validation
  2. `_build_dns_query`
  3. `_open_pinned_tls_connection`
  4. (per-protocol) write request + read response
  5. `_parse_dns_response` + cache
  6. cleanup via writer.close + wait_closed

  Steps 1–3, 5, 6 are identical; the difference is step 4 (HTTP/1.1
  request vs 2-byte length prefix). Extract a `_resolve_via_pinned_tls(
  reader, writer, query) -> bytes` overload per protocol kept inline,
  but the surrounding scaffold becomes a single `_resolve_with_pin(
  url, hostname, send_recv_fn) -> list[str]`.

  This is borderline — the two methods are simple enough that the
  duplication may be the clearer form. **Open question for the user:**
  do you want to dedupe DoH/DoT or leave them as parallel methods?
- **Why:** ~40 lines of duplicated scaffold (the connect/pin/close
  block is the same).
- **Behavior preserved:** Same TLS context, same pin re-verify
  belt-and-braces, same cache update.
- **Tests affected:**
  - `tests/test_dns_pinning.py` — tests ssl_context construction;
    unchanged.
  - `tests/test_dns_padding.py` — tests the query builder; unchanged.
  - No integration tests exercise live DoH/DoT (network-gated).

### MED-9. `dsm/core/passphrase.py:wipe_passphrase` + `_read_from_tty` `except BaseException` → narrow try block

- **File:** `dsm/core/passphrase.py:50–73`
- **Change:** `_read_from_tty` wraps the ENTIRE function body in
  `try: ... except BaseException: wipe_passphrase(buf); raise`. Narrow
  the try to the bytes-collection loop (L55–65); the `tcgetattr` and
  `tcsetattr` boilerplate outside the loop cannot grow the buffer and
  doesn't need the same wipe-on-exception treatment.
- **Why:** `except BaseException` is broad; narrowing the try lets the
  prefix/suffix (termios attribute capture/restore) raise without
  going through the wipe path that doesn't have anything to wipe yet.
  Note: the `except BaseException` is correct today (catches
  `KeyboardInterrupt`); the change is to narrow the *try* range, not
  to weaken the except clause.
- **Behavior preserved:** Same wipe-on-error semantics for the only
  case where `buf` has data (inside the loop). Same termios restore
  in the existing `finally`.
- **Tests affected:** No direct unit tests of `_read_from_tty`
  (interactive); covered indirectly by `tests/test_cli.py` smoke
  paths. Safe.

### MED-10. `dsm/crypto/handshake.py:_recv` parameter `indefinite: bool` is a flag-argument anti-pattern

- **File:** `dsm/crypto/handshake.py:490–554`
- **Change:** Split `_recv` into two functions:
  - `_recv_with_retry(transport, retransmit)` for the per-message
    case (3 retries with backoff)
  - `_recv_initial(transport)` for the server-side initial msg1 wait
    (single timeout, no retries)
  Both share the small `_recv_one` adapter proposed in MED-6.
- **Why:** Boolean flag-arguments that branch the entire function body
  are a textbook split-into-two refactor. Today the
  `indefinite=True` arm and the `indefinite=False` arm share no
  code beyond the protocol assertion.
- **Behavior preserved:** Each call site stays bound to the same
  retry/timeout policy.
- **Tests affected:**
  - `tests/test_handshake_retry_outage.py` (locks the retry-with-
    backoff behavior).
  - Both functions are module-private; no test imports `_recv`
    directly.

### MED-11. `dsm/crypto/cert.py:_decode_noise_static_binding_value` magic constants

- **File:** `dsm/crypto/cert.py:101–113`
- **Change:** The check
  `len(raw) != expected_total or raw[0] != _OCTET_STRING_TAG or raw[1]
  != NOISE_STATIC_PUB_LEN` works on bare byte indices. Refactor as a
  match-style check against the prefix:
  ```python
  if not raw.startswith(_OCTET_STRING_PREFIX) or len(raw) != expected_total:
      raise CertBindingError(...)
  return bytes(raw[len(_OCTET_STRING_PREFIX):])
  ```
- **Why:** Removes the two magic byte indices (0, 1) and reads as the
  inverse of `encode_noise_static_binding_value` rather than as a
  parse-by-offset.
- **Behavior preserved:** Same length check, same prefix check, same
  return value, same error wording (the error message format includes
  `{_OCTET_STRING_TAG:#04x}` — keep it).
- **Tests affected:** `tests/test_cert.py::*` (binding extension
  parsing covered). Safe.

### MED-12. `dsm/net/dns_proxy.py:_handle_query` is 80 lines and does parsing + dedup + resolve + response

- **File:** `dsm/net/dns_proxy.py:136–214`
- **Change:** Split into:
  - `_parse_query(data)` → `(qname, qtype, raw_query) | error_response`
  - `_resolve_with_dedup(qname, qtype)` → `list[str]`
  - `_build_response(query, addresses)` → wire bytes

  Then `_handle_query` orchestrates them in 15 lines instead of 80.
  The semaphore/dedup map manipulation moves into
  `_resolve_with_dedup`.
- **Why:** Currently the single function nests two `try/except` blocks
  inside a `try/finally`, with the inflight-map cleanup at the wrong
  level for the eye.
- **Behavior preserved:** Same dedup, same semaphore acquisition
  scope, same SERVFAIL on inflight-map overflow, same redaction
  behavior on debug_dns toggle.
- **Tests affected:**
  - `tests/test_dns_proxy.py::*`
  - `tests/test_dns_proxy_coalescing.py::*` — locks the dedup
    behavior. Safe — function is module-private.

---

## LOW / cosmetic

### LOW-1. `dsm/__main__.py:213, 221` — generic `Exception as e` printed verbatim

- **File:** `dsm/__main__.py:212–217, 220–225`
- **Change:** Tag the printed message with `type(e).__name__` so the
  operator sees the underlying error class:
  ```
  print(f"failed to unlock identity at {config.key_file}: "
        f"{type(e).__name__}: {e}", file=sys.stderr)
  ```
- **Why:** Same information, more discoverable when triaging.
- **Behavior preserved:** stderr text changes (this is observable!),
  so this is actually MEDIUM disguised as cosmetic — **defer until
  user approves the text shift**.
- **Tests affected:** None.

### LOW-2. `dsm/session.py:97` overflow check uses `2**64` magic

- **File:** `dsm/session.py:97`
- **Change:** Promote `_SEQ_MAX = 2**64` to a module constant just
  above `SequenceCounter`. Same number, named.
- **Why:** Self-documenting.
- **Behavior preserved:** Identical.
- **Tests affected:** None.

### LOW-3. `dsm/core/protocol.py:165` `weights = (20, 15, 12, 10, 8, 7, 6, 6, 5, 6, 5)` is a literal

- **File:** `dsm/core/protocol.py:163–175`
- **Change:** Promote to a module-level constant
  `SIZE_CLASS_WEIGHTS: tuple[int, ...] = (20, 15, ...)`. The shape
  validation (`len(weights) != len(SIZE_CLASSES)`) moves to a module-
  load-time `assert` so a mismatch is caught at import rather than at
  first call.
- **Why:** Co-locates the constants near `SIZE_CLASSES`. Avoids
  rebuilding the tuple per call.
- **Behavior preserved:** Same weights, same sampling, same fallback.
- **Tests affected:** `tests/test_protocol.py::test_pick_random_size_class`
  (if present) — exercises distribution only, not the literal. Safe.

### LOW-4. `dsm/traffic/scheduler.py:117` — `0.03 + csprng_float() * 0.04` poll-jitter magic numbers

- **File:** `dsm/traffic/scheduler.py:117`
- **Change:** Promote to module constants `_POLL_JITTER_MIN = 0.03`,
  `_POLL_JITTER_RANGE = 0.04`, with a comment explaining the 30-70 ms
  range.
- **Why:** Self-documenting.
- **Behavior preserved:** Identical.
- **Tests affected:** None.

### LOW-5. `dsm/traffic/shaper.py:179–183, 222` — `0.3`, `0.5`, `0.15`, `0.30` shaping constants

- **File:** `dsm/traffic/shaper.py:172–228`
- **Change:** Promote the shaping probabilities (`0.3 *
  chaff_rate_multiplier`, `r < 0.15`, `r < 0.30`, `0.5 + csprng_float()`)
  to module constants with names like
  `_ACTIVE_CHAFF_BASE_PROB = 0.3`, `_CHAFF_SIZE_PERTURB_UP_P = 0.15`,
  `_CHAFF_SIZE_PERTURB_DOWN_P = 0.30`, `_CHAFF_RATE_BASE = 0.5`.
- **Why:** The fingerprint-resistance behavior is sensitive to these
  numbers; naming them makes it explicit which knob is which.
- **Behavior preserved:** Identical numbers.
- **Tests affected:**
  - `tests/test_symmetric_shaping.py` (chaff size distribution locked
    in by regression test). Safe — numbers unchanged.

### LOW-6. `dsm/core/protocol.py:225` `MAX_FRAGMENTABLE_PACKET` and friends — already named, just out of order

- **File:** `dsm/core/protocol.py:181–225`
- **Change:** `MAX_FRAGMENTS = 16` is defined at L182, before
  `_PendingReassembly` (L274) needs it; `MAX_FRAGMENT_DATA` and
  `MAX_FRAGMENTABLE_PACKET` are defined at L217–224 but used in
  `fragment_ip_packet` (L227+). Constants placement is fine but the
  block has documentation-style comments that could move to a single
  block at the top. Pure code-style; possibly do not touch.
- **Why:** Module reads top-down better when constants cluster.
- **Behavior preserved:** No code moves; only comment placement.
- **Tests affected:** None.

### LOW-7. `dsm/core/fsm.py:51–52` `dict.fromkeys` would be clearer than dict comprehension with constant values

- **File:** `dsm/core/fsm.py:51–52`
- **Change:** Currently:
  ```python
  self._on_enter: dict[State, list[Callable[[], None]]] = {s: [] for s in State}
  self._on_exit: dict[State, list[Callable[[], None]]] = {s: [] for s in State}
  ```
  This is fine; `dict.fromkeys` would not be safe here because it
  shares the same list reference across keys. **No change. Listed
  here as a "did consider, intentionally not doing" item — flagged
  for explicit non-action.**

### LOW-8. `dsm/net/dns.py:79` `[bytes.fromhex(h) for h in hex_pins]` — already idiomatic, just inside `__init__`

- **File:** `dsm/net/dns.py:71–79`
- **Change:** None — comprehension is idiomatic, the loop is correct.
  Listed only because it surfaced in the checklist pass and the answer
  is "leave it alone".

### LOW-9. `dsm/client.py:25` and `dsm/server.py:47` — `VPN_DNS_SERVER` and `SERVER_TUN_IP` are both `"10.8.0.1"`

- **Files:** `dsm/client.py:25`, `dsm/server.py:47`
- **Change:** Same literal under two names. Move to a shared location
  (proposal: `dsm/net/__init__.py` or a new
  `dsm/net/_addresses.py`) under a single name, e.g.
  `SERVER_TUN_IP = "10.8.0.1"`. Both modules import it.
- **Why:** Single source of truth; today changing one would silently
  break the relationship between client's resolv.conf nameserver and
  server's TUN IP.
- **Behavior preserved:** Same literal value, same usage.
- **Tests affected:**
  - `tests/test_cli.py` — does not exercise the addresses.
  - No integration test asserts on the literal string. Safe.
- **Caveat:** This straddles "refactor" vs "design decision" — the
  *value* `"10.8.0.1"` is part of the protocol contract between
  client and server. Centralizing it is a low-risk move, but it's the
  kind of change where a deployment guide may also reference the IP
  literal. Verify before executing.

---

## Notes on what was deliberately NOT proposed

Items the checklist flagged but where the existing form is preferable:

- `dsm/core/protocol.py:OuterPacket.serialize` uses pre-sized
  `bytearray + pack_into` — this is a deliberate hot-path
  optimization (commented), do not "simplify" to a concat.
- `dsm/traffic/shaper.py:62–72` in-place EMA — same: hot-path
  optimization, explicit comment.
- `dsm/session.py:make_send_fn` returns a closure rather than a
  callable class — Python idiom is fine, no win from converting.
- `dsm/core/fsm.py:_TRANSITIONS` as a `dict[State, set[State]]` —
  could be a method dispatch but the literal is clearer at this
  scale (5 states).
- `dsm/net/transport/udp.py` and `tcp.py` — these share NO code
  surface beyond `apply_so_mark` (already factored). The class shapes
  are intentionally parallel but the semantics (datagram vs stream)
  are too different for a base class to add value.
- `dsm/session.py:_DISPATCH` packet-type dispatch table — already in
  the idiomatic form (`PacketType` enum → handler), no change.
- `dsm/server.py:_HANDSHAKE_RETRY_BACKOFF_*` constants — already
  well-named, already documented.
