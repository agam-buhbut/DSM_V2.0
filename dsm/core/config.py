from __future__ import annotations

import ipaddress
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from dsm.core._validators import DSM_TUN_NAME_RE as _TUN_NAME_PATTERN
from dsm.core.path_security import (
    InsecureFilePermissionsError,
    check_user_file_permissions,
)

CONFIG_PATH = Path("/opt/mtun/config.toml")


class ConfigError(Exception):
    """Config file is missing, malformed, or has insecure permissions."""


# Validation bounds
MIN_PORT = 1
MAX_PORT = 65535
MIN_PADDING = 64
MAX_PADDING = 1500
MAX_JITTER_MS = 1000
MIN_ROTATION_PACKETS = 100
MIN_ROTATION_SECONDS = 60
# Upper bound on rotation_packets. The Rust nonce counter is u32 (per
# epoch) and saturates at 2^32 — letting an operator configure
# rotation_packets above this means the nonce counter exhausts and the
# session shuts down before the rekey ever fires. Cap at 2^31 so the
# rekey always wins. Same number-of-orders-of-magnitude headroom is
# applied to rotation_seconds (1 year ≈ 3.1e7 s).
MAX_ROTATION_PACKETS = 1 << 31
MAX_ROTATION_SECONDS = 365 * 24 * 3600
# TUN MTU bounds. 576 is the IPv4 minimum path MTU (RFC 791). 1500 is
# standard Ethernet. Two distinct overheads matter and must not be conflated:
#   * Link overhead = IP(20) + UDP(8) = 28 B, charged against the LINK MTU
#     (it rides OUTSIDE the DSM outer packet / size class).
#   * Size-class overhead = outer header(20) + GCM tag(16) + inner header(4)
#     = 40 B, charged against the 1400-byte top SIZE_CLASS.
# So a full TUN packet of N bytes becomes an N+40 outer packet, which becomes
# an N+40+28 wire datagram. DEFAULT_TUN_MTU 1400 leaves slack for VPN-in-VPN
# / PPPoE paths; auto_mtu lowers it (and the shaper ceiling) on constrained
# links (Phase 1.7).
MIN_TUN_MTU = 576
MAX_TUN_MTU = 1500
DEFAULT_TUN_MTU = 1400


@dataclass(frozen=True, slots=True)
class Config:
    mode: Literal["client", "server"]
    server_ip: str
    server_port: int
    listen_port: int
    key_file: str
    # Device cert (PEM or DER) — issued by the internal CA, binds the
    # device's hardware-bound signing key + Noise static via the
    # noiseStaticBinding extension. Required.
    cert_file: str
    # Pinned CA root cert (PEM). Required.
    ca_root_file: str
    # Persisted attest key blob (soft-attest backend only). For TPM /
    # Keystore backends this points to a key handle, not a file.
    attest_key_file: str
    transport: Literal["udp", "tcp"] = "udp"
    dns_providers: list[str] = field(default_factory=list[str])
    dns_provider_pins: dict[str, list[str]] = field(
        default_factory=dict[str, list[str]]
    )
    # Pinned CA-root SHA-256 (64-char hex). REQUIRED for the daemon to
    # start (DSM-005): auth_loader.load_cert_materials refuses to start
    # without it, so an attacker who can overwrite the on-disk CA PEM
    # cannot substitute the trust anchor undetected. Format is validated
    # here; presence is enforced at CA-load time (not in this validator)
    # so non-daemon commands like `dsm enroll --csr-out` that never load
    # the CA aren't blocked.
    ca_root_sha256: str | None = None
    # Optional CRL file (DER or PEM).
    crl_file: str | None = None
    # When True (the default), refuse to start if either:
    #   (a) no crl_file is configured, OR
    #   (b) the configured CRL is past its ``next_update`` timestamp.
    # Default fail-closed: silent revocation-bypass is the worst kind of
    # failure for a VPN whose compromise-recovery story relies on CRL
    # distribution. Dev / lab deployments that genuinely have no CA
    # workflow can set ``crl_strict = false`` to fall back to a warning,
    # which logs and continues.
    crl_strict: bool = True
    # Client-only: subject CN we will accept on the server cert.
    expected_server_cn: str | None = None
    # Server-only: file with one allowed client subject CN per line.
    allowed_cns_file: str | None = None
    tun_name: str = "mtun0"
    log_level: Literal["debug", "info", "warning", "error"] = "info"
    padding_min: int = 128
    padding_max: int = 1400
    jitter_ms_min: int = 1
    # M-ANON-4 default bump: 50→100 ms. The wider span covers more
    # consecutive packets at line rate (10 Mbps × 100 ms = 12 packets)
    # without adding visible latency to interactive traffic. Operators
    # who care about sub-50 ms RTT for VoIP/gaming can configure
    # lower; everyone else benefits from the larger reorder window.
    jitter_ms_max: int = 100
    # ── Adaptive-envelope traffic-shaping knobs (Phase 2 / Fork 8) ────────
    # All fields are optional (backward-compatible). The defaults form a
    # coherent envelope profile; see config.example.toml for per-knob notes.
    # Per-packet latency budget: a real packet is never delayed more than this
    # many milliseconds waiting for the envelope to rise.
    envelope_latency_budget_ms: int = 1000
    # Multiplicative per-second rise cap. Must be > 1.0 (otherwise the
    # envelope cannot rise at all). Value 2.0 means the envelope can at most
    # double per second when draining a real-traffic burst.
    envelope_rise_per_s: float = 2.0
    # Exponential-decay half-life (seconds) when no real traffic is queued.
    # Controls how long the post-burst chaff tail lasts.
    envelope_fall_half_life_s: float = 4.0
    # Soft ceiling on wire rate (packets/sec). Normal chaff-fill never
    # exceeds this; only the latency-budget override may pierce it temporarily.
    envelope_ceiling_pps: int = 600
    # Per-session randomized idle floor bounds (packets/sec). The actual floor
    # is drawn uniformly from [min, max] at shaper construction and fixed for
    # the session lifetime, removing the exact-1-pps constant DSM baseline.
    envelope_idle_floor_min_pps: float = 0.5
    envelope_idle_floor_max_pps: float = 2.0
    rotation_packets: int = 5000
    rotation_seconds: int = 600
    debug_dns: bool = False
    # Structured-JSON audit stream on the `dsm.netaudit` logger.
    # When True, dsm emits one JSON event per state transition
    # (handshake start/end, nft apply/remove, TUN configure/deconfigure,
    # rekey, liveness, shutdown). Used by the two-box demo runbook for
    # capturing ground truth, and by Phase 4 pentest replays. May also
    # be enabled via the `--debug-net` CLI flag.
    debug_net: bool = False
    # When False (the default) the daemon refuses to start on the extractable
    # software attestation backend (dev-soft-attest), whose key is recoverable
    # from process memory. Set True to acknowledge and run anyway (NOT for
    # production) — startup then logs a prominent WARNING + netaudit event.
    allow_soft_attest: bool = False
    # TUN device MTU in bytes. Must satisfy MIN_TUN_MTU <= mtu <= MAX_TUN_MTU.
    # The wire-level path MTU budget is checked against this at startup.
    mtu: int = DEFAULT_TUN_MTU
    # Enable kernel Path-MTU Discovery on the UDP socket (IP_MTU_DISCOVER).
    # When True the kernel sets the DF (Don't Fragment) bit on outgoing
    # datagrams and records ICMP "frag needed" replies. `get_path_mtu()`
    # in dsm.net.transport.udp queries the current PMTU. When False the
    # kernel runs its default policy (IP_PMTUDISC_WANT).
    pmtu_discover: bool = False
    # Adaptive TUN-MTU loop. When True, a background task polls the
    # kernel-discovered path MTU every `pmtu_check_interval_s` seconds and
    # adjusts the TUN device's MTU to track it: lower-on-drop is immediate,
    # raise-toward-`mtu` is hysteresis-gated (3 consecutive stable rises)
    # to avoid flap on transient PMTU bumps. Recommended for cellular /
    # roaming clients; safe to leave False on stable wired links where
    # `mtu` is already correct.
    auto_mtu: bool = False
    pmtu_check_interval_s: float = 30.0
    config_dir: Path = field(default_factory=lambda: Path("/opt/mtun/"))

    def __post_init__(self) -> None:
        _validate(self)


def _validate_types(c: Config) -> None:
    """Phase 1.11: type-check numeric/bool fields before range validators so a
    wrong-typed TOML value (e.g. server_port = "51820") raises a readable
    ValueError instead of a cryptic TypeError from a `<=` comparison.
    """
    # The isinstance guards below look statically redundant (the dataclass
    # annotates these as ``int``/``float``), so pyright flags them — but they
    # are load-bearing: TOML supplies untyped data, so a wrong-typed value
    # (e.g. server_port = "51820") reaches here despite the annotation. The
    # ``reportUnnecessaryIsInstance`` suppression is the point of this pass.
    int_fields = (
        ("server_port", c.server_port),
        ("listen_port", c.listen_port),
        ("padding_min", c.padding_min),
        ("padding_max", c.padding_max),
        ("jitter_ms_min", c.jitter_ms_min),
        ("jitter_ms_max", c.jitter_ms_max),
        ("rotation_packets", c.rotation_packets),
        ("rotation_seconds", c.rotation_seconds),
        ("mtu", c.mtu),
        ("envelope_latency_budget_ms", c.envelope_latency_budget_ms),
        ("envelope_ceiling_pps", c.envelope_ceiling_pps),
    )
    for name, value in int_fields:
        if isinstance(
            value, bool
        ) or not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            value, int
        ):
            raise ValueError(f"{name} must be an integer, got {type(value).__name__}")
    float_fields = (
        ("pmtu_check_interval_s", c.pmtu_check_interval_s),
        ("envelope_rise_per_s", c.envelope_rise_per_s),
        ("envelope_fall_half_life_s", c.envelope_fall_half_life_s),
        ("envelope_idle_floor_min_pps", c.envelope_idle_floor_min_pps),
        ("envelope_idle_floor_max_pps", c.envelope_idle_floor_max_pps),
    )
    for name, value in float_fields:
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            value, (int, float)
        ) or isinstance(value, bool):
            raise ValueError(f"{name} must be a number, got {type(value).__name__}")


def _validate_mode(c: Config) -> None:
    if c.mode not in ("client", "server"):
        raise ValueError(f"invalid mode: {c.mode!r}")


def _validate_server_ip(c: Config) -> None:
    # server_ip must be a literal IP — the kill-switch nftables rules
    # reference it with `ip daddr <addr>` which does not accept hostnames.
    # Auto-resolution would change behavior depending on which resolver is
    # up at config-load time (and would happen before the kill switch is
    # installed, leaking the lookup), so we require an explicit IP.
    try:
        addr = ipaddress.ip_address(c.server_ip)
    except ValueError as e:
        raise ValueError(
            f"server_ip must be a literal IP, got {c.server_ip!r}. "
            f"Resolve your hostname first: `dig +short <host> | head -1`"
        ) from e
    # Phase 1.11 / OWNER DECISION: reject IPv6 until a v6 data path exists.
    # The transport binds AF_INET only, so an IPv6 endpoint passes this
    # literal check but is unusable downstream — fail loudly at config load.
    if addr.version == 6:
        raise ValueError(
            f"IPv6 server_ip {c.server_ip!r} is not supported (AF_INET-only "
            "transport; configure disables IPv6). Use an IPv4 server endpoint."
        )


def _validate_ports(c: Config) -> None:
    # server_port is always a real concrete port — clients need it to connect.
    if not (MIN_PORT <= c.server_port <= MAX_PORT):
        raise ValueError(
            f"server_port must be {MIN_PORT}-{MAX_PORT}, got {c.server_port}"
        )
    # listen_port: server-side it's the bound socket; client-side it's the
    # source port for outgoing UDP, where 0 means "let the kernel pick an
    # ephemeral port" (the standard idiom). Allow 0 only for the client.
    if c.mode == "server":
        if not (MIN_PORT <= c.listen_port <= MAX_PORT):
            raise ValueError(
                f"listen_port must be {MIN_PORT}-{MAX_PORT} in server mode, "
                f"got {c.listen_port}"
            )
    else:
        if not (0 <= c.listen_port <= MAX_PORT):
            raise ValueError(
                f"listen_port must be 0-{MAX_PORT} in client mode "
                f"(0 = ephemeral), got {c.listen_port}"
            )


def _validate_key_file(c: Config) -> None:
    if not c.key_file:
        raise ValueError("key_file must not be empty")
    if not Path(c.key_file).is_absolute():
        raise ValueError(f"key_file must be absolute, got {c.key_file!r}")


def _validate_transport(c: Config) -> None:
    if c.transport not in ("udp", "tcp"):
        raise ValueError(f"invalid transport: {c.transport!r}")


def _validate_dns(c: Config) -> None:
    if c.mode == "server" and not c.dns_providers:
        raise ValueError("server mode requires at least one dns_providers entry")

    # dns provider pins: any user-supplied provider must have SPKI pins configured.
    # The scheme is checked at config load and a typo (`http://`, `dns://`, or
    # a bare hostname) surfaces as a startup WARNING. Without this, an
    # unrecognized scheme is silently skipped at query time, leaving the
    # server with no working resolver and clients with unexplained SERVFAILs.
    # Warning rather than raising keeps backward compatibility with existing
    # test fixtures and operator configs that pass non-URL placeholders.
    for provider in c.dns_providers:
        if not (provider.startswith("https://") or provider.startswith("tls://")):
            import logging

            logging.getLogger(__name__).warning(
                "dns_provider %r has no 'https://' (DoH) or 'tls://' (DoT) "
                "scheme; it will be silently skipped at query time. Fix the "
                "config to include the scheme so this provider is actually used.",
                provider,
            )
        # Phase 1.10: provider host MUST be an IP literal. A hostname-form
        # provider triggers per-query getaddrinfo, whose unmarked UDP is
        # routed into the server's own TUN (tunnel.py ip rule), dead-looping
        # resolution. Mirror _validate_server_ip's IP-literal requirement.
        parsed_host = urlparse(provider).hostname
        if parsed_host is not None:
            try:
                ipaddress.ip_address(parsed_host)
            except ValueError as e:
                raise ValueError(
                    f"dns_provider {provider!r} host must be an IP literal, "
                    f"got {parsed_host!r}. Resolve it once offline and pin the "
                    f"IP (a hostname provider dead-loops through the TUN)."
                ) from e
        pins = c.dns_provider_pins.get(provider)
        if not pins:
            raise ValueError(
                f"dns_provider {provider!r} requires dns_provider_pins entry with "
                f"at least one SPKI SHA-256 hash"
            )
        for pin in pins:
            if len(pin) != 64:
                raise ValueError(
                    f"dns_provider_pins[{provider!r}] entry {pin!r} must be a "
                    f"64-char hex SPKI SHA-256 hash"
                )
            try:
                bytes.fromhex(pin)
            except ValueError as e:
                raise ValueError(
                    f"dns_provider_pins[{provider!r}] entry {pin!r} is not valid hex"
                ) from e


def _validate_cert_paths(c: Config) -> None:
    # cert_file / ca_root_file / attest_key_file: required, absolute paths.
    for name, value in (
        ("cert_file", c.cert_file),
        ("ca_root_file", c.ca_root_file),
        ("attest_key_file", c.attest_key_file),
    ):
        if not value:
            raise ValueError(f"{name} must not be empty")
        if not Path(value).is_absolute():
            raise ValueError(f"{name} must be absolute, got {value!r}")

    # crl_file: optional but absolute when present.
    if c.crl_file is not None:
        if not c.crl_file:
            raise ValueError("crl_file must not be empty")
        if not Path(c.crl_file).is_absolute():
            raise ValueError(f"crl_file must be absolute, got {c.crl_file!r}")


def _validate_ca_root_sha256(c: Config) -> None:
    # Format only: when set, must be 64-char hex (a SHA-256 digest).
    # Presence is REQUIRED for daemon startup but enforced at CA-load time
    # (auth_loader.load_cert_materials) rather than here, so non-daemon
    # commands (e.g. `dsm enroll --csr-out`) that never load the CA are not
    # blocked by config validation.
    if c.ca_root_sha256 is None:
        return
    if len(c.ca_root_sha256) != 64:
        raise ValueError(
            f"ca_root_sha256 must be 64 hex chars (SHA-256), "
            f"got {len(c.ca_root_sha256)}"
        )
    try:
        bytes.fromhex(c.ca_root_sha256)
    except ValueError as e:
        raise ValueError("ca_root_sha256 is not valid hex") from e


def _validate_role_specific(c: Config) -> None:
    if c.mode == "client":
        if not c.expected_server_cn:
            raise ValueError("client mode requires expected_server_cn")
    else:  # server
        if not c.allowed_cns_file:
            raise ValueError("server mode requires allowed_cns_file")
        if not Path(c.allowed_cns_file).is_absolute():
            raise ValueError(
                f"allowed_cns_file must be absolute, got {c.allowed_cns_file!r}"
            )


def _validate_padding(c: Config) -> None:
    if not (MIN_PADDING <= c.padding_min <= c.padding_max <= MAX_PADDING):
        raise ValueError(
            f"padding_min ({c.padding_min}) and padding_max ({c.padding_max}) "
            f"must satisfy {MIN_PADDING} <= min <= max <= {MAX_PADDING}"
        )


def _validate_jitter(c: Config) -> None:
    if not (0 <= c.jitter_ms_min <= c.jitter_ms_max <= MAX_JITTER_MS):
        raise ValueError(
            f"jitter_ms_min ({c.jitter_ms_min}) and jitter_ms_max ({c.jitter_ms_max}) "
            f"must satisfy 0 <= min <= max <= {MAX_JITTER_MS}"
        )


def _validate_envelope(c: Config) -> None:
    # Bounds match the Task-2.8 spec: latency_budget_ms in [10, 5000];
    # rise_per_s in (1.0, 100.0]; fall_half_life_s in (0, 60];
    # ceiling_pps in [idle_floor_max, 100000];
    # 0 < idle_floor_min <= idle_floor_max <= 1000.
    if not (10 <= c.envelope_latency_budget_ms <= 5000):
        raise ValueError(
            f"envelope_latency_budget_ms must be 10–5000 ms, "
            f"got {c.envelope_latency_budget_ms}"
        )
    if not (1.0 < c.envelope_rise_per_s <= 100.0):
        raise ValueError(
            f"envelope_rise_per_s must be > 1.0 and <= 100.0 "
            f"(must be able to rise), got {c.envelope_rise_per_s}"
        )
    if not (0.0 < c.envelope_fall_half_life_s <= 60.0):
        raise ValueError(
            f"envelope_fall_half_life_s must be in (0, 60] s, "
            f"got {c.envelope_fall_half_life_s}"
        )
    if not (
        0.0 < c.envelope_idle_floor_min_pps <= c.envelope_idle_floor_max_pps <= 1000.0
    ):
        raise ValueError(
            f"envelope_idle_floor_min_pps ({c.envelope_idle_floor_min_pps}) and "
            f"envelope_idle_floor_max_pps ({c.envelope_idle_floor_max_pps}) must "
            f"satisfy 0 < min <= max <= 1000"
        )
    if not (c.envelope_idle_floor_max_pps <= c.envelope_ceiling_pps <= 100000):
        raise ValueError(
            f"envelope_ceiling_pps must be >= envelope_idle_floor_max_pps "
            f"({c.envelope_idle_floor_max_pps}) and <= 100000, "
            f"got {c.envelope_ceiling_pps}"
        )


def _validate_rotation(c: Config) -> None:
    if c.rotation_packets < MIN_ROTATION_PACKETS:
        raise ValueError(f"rotation_packets too low: {c.rotation_packets}")
    if c.rotation_packets > MAX_ROTATION_PACKETS:
        raise ValueError(
            f"rotation_packets too high: {c.rotation_packets} "
            f"(max {MAX_ROTATION_PACKETS} — Rust nonce counter would "
            "exhaust at 2^32 before rotation fires)"
        )
    if c.rotation_seconds < MIN_ROTATION_SECONDS:
        raise ValueError(f"rotation_seconds too low: {c.rotation_seconds}")
    if c.rotation_seconds > MAX_ROTATION_SECONDS:
        raise ValueError(
            f"rotation_seconds too high: {c.rotation_seconds} "
            f"(max {MAX_ROTATION_SECONDS} = 1 year)"
        )


def _validate_log_level(c: Config) -> None:
    if c.log_level not in ("debug", "info", "warning", "error"):
        raise ValueError(f"invalid log_level: {c.log_level!r}")


def _validate_tun_name(c: Config) -> None:
    # tun_name: Linux IFNAMSIZ is 16 (including NUL), so 15 usable chars.
    # The kill-switch ruleset and MASQUERADE rule both interpolate this into
    # nftables config; restricting to alphanumeric + dash/underscore keeps the
    # interpolation site safe even if a future code path forgets to validate.
    if not _TUN_NAME_PATTERN.match(c.tun_name):
        raise ValueError(
            f"tun_name {c.tun_name!r} must be 1-15 alphanumeric/dash/underscore chars"
        )


def _validate_mtu(c: Config) -> None:
    # TUN MTU bounds — below 576 breaks IPv4 connectivity in common
    # assumptions, above 1500 overflows Ethernet without jumbo frames.
    if not (MIN_TUN_MTU <= c.mtu <= MAX_TUN_MTU):
        raise ValueError(f"mtu must be {MIN_TUN_MTU}-{MAX_TUN_MTU}, got {c.mtu}")

    # Wire-overhead sanity warning. DSM adds ~68 bytes of outer
    # IP+UDP+header+GCM tag+inner header. With Ethernet's 1500-byte MTU,
    # values above ~1400 risk silent kernel fragmentation or PMTU drops
    # on PPPoE / VPN-in-VPN paths where the link MTU is below 1500.
    if c.mtu > 1400:
        import logging

        logging.getLogger(__name__).warning(
            "configured tun mtu=%d is above the safe default 1400; "
            "wire packets will be ~%d B which may exceed link MTU on "
            "PPPoE/tunnel-in-tunnel paths. Lower to 1380 if ping works "
            "but throughput stalls.",
            c.mtu,
            c.mtu + 68,
        )


def _validate_pmtu_interval(c: Config) -> None:
    # auto_mtu polling interval. Must be strictly positive (zero would
    # tight-loop in asyncio.wait_for) and within an hour. The lower bound
    # is intentionally permissive so unit tests can drive the loop fast.
    if not (0.0 < c.pmtu_check_interval_s <= 3600.0):
        raise ValueError(
            "pmtu_check_interval_s must be in (0, 3600] s, "
            f"got {c.pmtu_check_interval_s}"
        )


# Section order is observable — Config(...) reports the FIRST error
# encountered, so reordering changes which message a test sees. Keep
# this sequence stable.
_VALIDATORS = (
    _validate_types,
    _validate_mode,
    _validate_server_ip,
    _validate_ports,
    _validate_key_file,
    _validate_transport,
    _validate_dns,
    _validate_cert_paths,
    _validate_ca_root_sha256,
    _validate_role_specific,
    _validate_padding,
    _validate_jitter,
    _validate_envelope,
    _validate_rotation,
    _validate_log_level,
    _validate_tun_name,
    _validate_mtu,
    _validate_pmtu_interval,
)


def _validate(c: Config) -> None:
    """Run every section validator in the fixed _VALIDATORS order.

    Each validator either returns or raises ``ValueError``. Order matters
    — the first failure short-circuits, so test cases that exercise one
    validation rule rely on the prior rules accepting their fixture.
    """
    for validator in _VALIDATORS:
        validator(c)


def load(path: Path | None = None) -> Config:
    """Load and validate config from TOML file.

    Config directory resolution (highest precedence first):
        1. DSM_CONFIG_DIR environment variable
        2. Parent directory of the config file path
        3. Built-in default (/opt/mtun/)
    """
    p = path or CONFIG_PATH
    # Probe existence first so a missing config produces a clear "not found"
    # rather than the permission check's "cannot lstat ... chmod 600"
    # message, which would send the operator chasing a permissions ghost.
    if not p.exists():
        raise ConfigError(f"config file not found: {p}")
    try:
        check_user_file_permissions(p)
    except InsecureFilePermissionsError as e:
        raise ConfigError(
            f"refusing to load config with insecure permissions: {e}. "
            f"config.toml pins the CA root + crl_strict; run: chmod 600 {p}"
        ) from e
    if dsm_config_dir := os.getenv("DSM_CONFIG_DIR"):
        config_dir = Path(dsm_config_dir)
    else:
        config_dir = Path(p).parent
    with open(p, "rb") as f:
        raw = tomllib.load(f)
    raw.setdefault("config_dir", config_dir)
    return Config(**raw)
