from __future__ import annotations

import ipaddress
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from dsm.core._validators import DSM_TUN_NAME_RE as _TUN_NAME_PATTERN

CONFIG_PATH = Path("/opt/mtun/config.toml")

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
# standard Ethernet; DSM's wire overhead (IP+UDP+outer header+GCM tag +
# inner header ≈ 68 B) requires TUN MTU ≤ outer_link_MTU − 68 to avoid
# path fragmentation. The default 1400 leaves slack for typical VPN-in-
# VPN or PPPoE paths.
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
        ipaddress.ip_address(c.server_ip)
    except ValueError as e:
        raise ValueError(
            f"server_ip must be a literal IP, got {c.server_ip!r}. "
            f"Resolve your hostname first: `dig +short <host> | head -1`"
        ) from e


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
    if dsm_config_dir := os.getenv("DSM_CONFIG_DIR"):
        config_dir = Path(dsm_config_dir)
    else:
        config_dir = Path(p).parent
    with open(p, "rb") as f:
        raw = tomllib.load(f)
    raw.setdefault("config_dir", config_dir)
    return Config(**raw)
