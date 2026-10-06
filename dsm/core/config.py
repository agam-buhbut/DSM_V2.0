from __future__ import annotations

import ipaddress
import logging
import os
import re
import tomllib
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, cast
from urllib.parse import urlparse

from dsm.core._validators import DSM_TUN_NAME_RE as _TUN_NAME_PATTERN
from dsm.core.path_security import (
    InsecureFilePermissionsError,
    check_user_file_permissions,
)

log = logging.getLogger(__name__)

CONFIG_PATH = Path("/opt/mtun/config.toml")


class ConfigError(Exception):
    """Config file is missing, malformed, or has insecure permissions."""


MIN_PORT = 1
MAX_PORT = 65535
MIN_PADDING = 64
MAX_PADDING = 1500
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
# Bounds on max_inflight_handshakes. Each slot is a live NoiseResponder plus a
# per-peer inbox, so an absurd pool size is a self-inflicted memory-exhaustion
# risk: refuse it above the hard cap, warn above the soft threshold.
MAX_INFLIGHT_HANDSHAKES = 4096
WARN_INFLIGHT_HANDSHAKES = 1024
# TUN MTU bounds. 576 is the IPv4 minimum path MTU (RFC 791). 1500 is
# standard Ethernet. Two distinct overheads matter and must not be conflated:
#   * Link overhead = IP(20) + UDP(8) = 28 B, charged against the LINK MTU
#     (it rides OUTSIDE the DSM outer packet / size class).
#   * Size-class overhead = outer header(20) + GCM tag(16) + inner header(4)
#     = 40 B, charged against the 1400-byte top SIZE_CLASS.
# So a full TUN packet of N bytes becomes an N+40 outer packet, which becomes
# an N+40+28 wire datagram. DEFAULT_TUN_MTU 1360 (= 1400 - 40) is the largest
# that fits one outer packet, so a full TUN packet is never split in two; it
# also leaves slack for VPN-in-VPN / PPPoE paths; auto_mtu lowers it (and the
# shaper ceiling) on constrained links (Phase 1.7).
MIN_TUN_MTU = 576
MAX_TUN_MTU = 1500
DEFAULT_TUN_MTU = 1360

# Tier shaper defaults and limits. dsm.traffic.shaper uses the same defaults,
# and the Rust core (rust/tuncore/src/shaper.rs) checks the same limits.
DEFAULT_SHAPER_TIERS_PPS: tuple[float, ...] = (10.0, 50.0, 200.0, 800.0)
DEFAULT_SHAPER_LATENCY_BUDGET_MS = 500
DEFAULT_SHAPER_DECOY_INTERVAL_S = 7200.0
DEFAULT_SHAPER_LINGER_S: tuple[float, float] = (300.0, 1800.0)
MIN_SHAPER_TIERS = 2
MAX_SHAPER_TIERS = 8
MIN_TIER_PPS = 1.0
MAX_TIER_PPS = 5000.0
MIN_SHAPER_LATENCY_BUDGET_MS = 10
MAX_SHAPER_LATENCY_BUDGET_MS = 5000
MIN_DECOY_INTERVAL_S = 300.0
MAX_DECOY_INTERVAL_S = 86400.0
MAX_LINGER_S = 7200.0
# The core's secret ranges that bound the gap at the first tier and the
# step-up point (shaper.rs: GAP_SPREAD, TIER_SCALE, STEP_UP_FRACTION). The
# first-tier rule in _validate_shaper uses them.
_MAX_GAP_SPREAD = 0.7
_MIN_TIER_SCALE = 0.8
_MIN_STEP_UP_FRACTION = 0.5
# Named in the startup error for a removed envelope_* key.
SHAPER_KEYS = (
    "shaper_tiers_pps",
    "shaper_latency_budget_ms",
    "shaper_decoy_interval_s",
    "shaper_linger_s",
)
# Removed: the tier shaper decides when every packet leaves. An old config
# that still sets them stops at startup with a clear message.
_REMOVED_JITTER_KEYS = ("jitter_ms_min", "jitter_ms_max")

# A single DNS label (RFC 1123): 1-63 chars, letters/digits/hyphen, no
# leading or trailing hyphen.
_HOSTNAME_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def _is_valid_hostname(name: str) -> bool:
    """True if ``name`` is a syntactically valid DNS hostname (RFC 1123)."""
    if not name or len(name) > 253:
        return False
    host = name[:-1] if name.endswith(".") else name  # tolerate trailing dot
    labels = host.split(".")
    return bool(labels) and all(_HOSTNAME_LABEL.match(label) for label in labels)


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
    # Tier shaper. Packets leave at a steady rate that only changes in a few
    # fixed steps; see config.example.toml for what each key does and costs.
    shaper_tiers_pps: list[float] = field(
        default_factory=lambda: list(DEFAULT_SHAPER_TIERS_PPS)
    )
    shaper_latency_budget_ms: int = DEFAULT_SHAPER_LATENCY_BUDGET_MS
    shaper_decoy_interval_s: float = DEFAULT_SHAPER_DECOY_INTERVAL_S
    shaper_linger_s: list[float] = field(
        default_factory=lambda: list(DEFAULT_SHAPER_LINGER_S)
    )
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
    # TPM-backend TCTI (the tss-esapi transport string) for the hardware
    # attest key, e.g. "device:/dev/tpmrm0". None (the default) lets the Rust
    # backend auto-resolve via the TCTI/TPM2TOOLS_TCTI env vars and finally
    # "device:/dev/tpmrm0". Only consulted on the tpm-attest build; the
    # soft-attest backend ignores it. The Rust side does the real parse — this
    # validator only catches an obviously-wrong family prefix.
    attest_tpm_tcti: str | None = None
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
    # Server only: handshake attempts the UDP acceptor validates concurrently
    # (dsm.net.handshake_acceptor), so one stalled bogus msg1 cannot starve a
    # real client. Bounds the peak NoiseResponder count and CPU.
    max_inflight_handshakes: int = 8
    config_dir: Path = field(default_factory=lambda: Path("/opt/mtun/"))

    def __post_init__(self) -> None:
        _validate(self)


def _validate_types(c: Config) -> None:
    """Type-check numeric/bool fields before range validators so a
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
        ("rotation_packets", c.rotation_packets),
        ("rotation_seconds", c.rotation_seconds),
        ("mtu", c.mtu),
        ("shaper_latency_budget_ms", c.shaper_latency_budget_ms),
        ("max_inflight_handshakes", c.max_inflight_handshakes),
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
        ("shaper_decoy_interval_s", c.shaper_decoy_interval_s),
    )
    for name, value in float_fields:
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            value, (int, float)
        ) or isinstance(value, bool):
            raise ValueError(f"{name} must be a number, got {type(value).__name__}")
    # A string or list here would reach _validate_dns and crash on .get().
    if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
        c.dns_provider_pins, dict
    ):
        raise ValueError(
            f"dns_provider_pins must be a table (a [dns_provider_pins] "
            f"section), got {type(c.dns_provider_pins).__name__}"
        )
    # A string here would be read letter by letter further on.
    if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
        c.dns_providers, list
    ) or not all(
        isinstance(p, str)  # pyright: ignore[reportUnnecessaryIsInstance]
        for p in c.dns_providers
    ):
        raise ValueError(
            'dns_providers must be a list of strings, e.g. ["https://1.1.1.1/dns-query"]'
        )


def _validate_mode(c: Config) -> None:
    if c.mode not in ("client", "server"):
        raise ValueError(f"invalid mode: {c.mode!r}")


def _validate_server_ip(c: Config) -> None:
    # A literal IPv4, or a hostname (e.g. DDNS for a home server on a dynamic
    # IP) that the client resolves once, before the kill switch is installed
    # (client._resolve_server_endpoint). That lookup leaves in the clear and is
    # not a trust anchor: the server is authenticated by Noise + cert/CN, so a
    # spoofed answer fails the handshake instead of redirecting the client.
    try:
        addr = ipaddress.ip_address(c.server_ip)
    except ValueError:
        if not _is_valid_hostname(c.server_ip):
            raise ValueError(
                f"server_ip must be a literal IPv4 address or a valid DNS "
                f"hostname, got {c.server_ip!r}"
            ) from None
        return
    # The transport binds AF_INET only, so an IPv6 endpoint would pass the
    # literal check but be unusable downstream.
    if addr.version == 6:
        raise ValueError(
            f"IPv6 server_ip {c.server_ip!r} is not supported (AF_INET-only "
            "transport). Use an IPv4 address or a hostname with an A record."
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
    if c.debug_dns:
        log.warning(
            "debug_dns is ENABLED: plaintext DNS query names will be written "
            "to logs, defeating DNS-metadata privacy. Use ONLY for local "
            "debugging and disable it in production."
        )

    # In TOML every key after a [dns_provider_pins] header belongs to that
    # table, and `dsm init` writes the table last. A setting added below it
    # would land here and be silently ignored, so refuse it. A spare or
    # mistyped pin name lands here too, so the message covers both. This runs
    # before the checks below because a misplaced `dns_providers` would
    # otherwise surface as a misleading "server mode requires dns_providers".
    stray = [key for key in c.dns_provider_pins if key not in c.dns_providers]
    if stray:
        names = ", ".join(repr(key) for key in stray)
        raise ValueError(
            f"dns_provider_pins has entries that are not in dns_providers: "
            f"{names}. If any of them is a setting, move it above the "
            f"[dns_provider_pins] section; otherwise add the provider to "
            f"dns_providers or remove the pin (names must match exactly)."
        )

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
            log.warning(
                "dns_provider %r has no 'https://' (DoH) or 'tls://' (DoT) "
                "scheme; it will be silently skipped at query time. Fix the "
                "config to include the scheme so this provider is actually used.",
                provider,
            )
        # Provider host must be an IP literal. A hostname-form
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
        # A string here would be read letter by letter below.
        if not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            pins, (list, type(None))
        ) or not all(
            isinstance(p, str)  # pyright: ignore[reportUnnecessaryIsInstance]
            for p in pins or []
        ):
            raise ValueError(
                f"dns_provider_pins[{provider!r}] must be a list of hash strings, "
                f'e.g. ["<64 hex chars>"]'
            )
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
    for name, value in (
        ("cert_file", c.cert_file),
        ("ca_root_file", c.ca_root_file),
        ("attest_key_file", c.attest_key_file),
    ):
        if not value:
            raise ValueError(f"{name} must not be empty")
        if not Path(value).is_absolute():
            raise ValueError(f"{name} must be absolute, got {value!r}")

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


def _validate_attest_tpm_tcti(c: Config) -> None:
    # Format only, and only on the lenient side: the Rust tss-esapi layer is
    # the authoritative parser. We reject an empty string (an unset TCTI must
    # be None, not "") and an obviously-wrong family prefix, so a typo surfaces
    # here instead of as an opaque tss-esapi error at enroll/start time.
    if c.attest_tpm_tcti is None:
        return
    if (
        not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
            c.attest_tpm_tcti, str
        )
        or not c.attest_tpm_tcti
    ):
        raise ValueError("attest_tpm_tcti must be a non-empty string or unset")
    allowed = ("device:", "swtpm:", "mssim:", "tabrmd:")
    if not c.attest_tpm_tcti.startswith(allowed):
        raise ValueError(
            f"attest_tpm_tcti must start with one of {allowed}, "
            f"got {c.attest_tpm_tcti!r}"
        )


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


def _number_list(name: str, value: object) -> list[float]:
    """Check a list-of-numbers key. TOML hands us untyped data, so a wrong
    type must become a readable ValueError, not a TypeError later on."""
    if not isinstance(value, (list, tuple)):
        raise ValueError(
            f"{name} must be a list of numbers, got {type(value).__name__}"
        )
    out: list[float] = []
    for item in cast(Sequence[object], value):
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            raise ValueError(
                f"{name} entries must be numbers, got {type(item).__name__}"
            )
        try:
            out.append(float(item))
        except OverflowError as e:
            # TOML integers can have any size; float() refuses one this big.
            raise ValueError(f"{name} has a number that is far too large") from e
    return out


def _validate_shaper(c: Config) -> None:
    tiers = _number_list("shaper_tiers_pps", c.shaper_tiers_pps)
    if not (MIN_SHAPER_TIERS <= len(tiers) <= MAX_SHAPER_TIERS):
        raise ValueError(
            f"shaper_tiers_pps must have {MIN_SHAPER_TIERS}-{MAX_SHAPER_TIERS} "
            f"entries, got {len(tiers)}"
        )
    if not all(MIN_TIER_PPS <= t <= MAX_TIER_PPS for t in tiers):
        raise ValueError(
            f"shaper_tiers_pps entries must be {MIN_TIER_PPS:g}-{MAX_TIER_PPS:g} "
            f"packets/s, got {tiers}"
        )
    if any(b <= a for a, b in zip(tiers, tiers[1:])):
        raise ValueError(f"shaper_tiers_pps must be strictly rising, got {tiers}")
    budget = c.shaper_latency_budget_ms
    if not (MIN_SHAPER_LATENCY_BUDGET_MS <= budget <= MAX_SHAPER_LATENCY_BUDGET_MS):
        raise ValueError(
            f"shaper_latency_budget_ms must be {MIN_SHAPER_LATENCY_BUDGET_MS}-"
            f"{MAX_SHAPER_LATENCY_BUDGET_MS} ms, got {budget}"
        )
    # The longest gap at the first tier must end before the earliest step-up
    # point, or a lone real packet could step the rate up and so move the
    # send times. The Rust core checks the same rule with the same arithmetic.
    min_tier0 = (1.0 + _MAX_GAP_SPREAD) / (
        _MIN_TIER_SCALE * _MIN_STEP_UP_FRACTION * (budget / 1000.0)
    )
    if tiers[0] <= min_tier0:
        raise ValueError(
            f"shaper_tiers_pps[0] must be above {min_tier0:g} packets/s when "
            f"shaper_latency_budget_ms is {budget}, got {tiers[0]:g}"
        )
    decoy = c.shaper_decoy_interval_s
    if not (decoy == 0 or MIN_DECOY_INTERVAL_S <= decoy <= MAX_DECOY_INTERVAL_S):
        raise ValueError(
            f"shaper_decoy_interval_s must be 0 (off) or "
            f"{MIN_DECOY_INTERVAL_S:g}-{MAX_DECOY_INTERVAL_S:g} s, got {decoy}"
        )
    linger = _number_list("shaper_linger_s", c.shaper_linger_s)
    if len(linger) != 2:
        raise ValueError(f"shaper_linger_s must be [min, max], got {linger}")
    lo, hi = linger[0], linger[1]
    if not ((lo == 0 and hi == 0) or 0 < lo <= hi <= MAX_LINGER_S):
        raise ValueError(
            f"shaper_linger_s must be [0, 0] (off) or "
            f"0 < min <= max <= {MAX_LINGER_S:g}, got {linger}"
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
        log.warning(
            "configured tun mtu=%d is above 1400; "
            "wire packets will be ~%d B which may exceed link MTU on "
            "PPPoE/tunnel-in-tunnel paths. Lower to 1380 if ping works "
            "but throughput stalls.",
            c.mtu,
            c.mtu + 68,
        )


def _validate_max_inflight_handshakes(c: Config) -> None:
    if c.max_inflight_handshakes < 1:
        raise ValueError(
            f"max_inflight_handshakes must be >= 1, got {c.max_inflight_handshakes}"
        )
    if c.max_inflight_handshakes > MAX_INFLIGHT_HANDSHAKES:
        raise ValueError(
            f"max_inflight_handshakes too high: {c.max_inflight_handshakes} "
            f"(max {MAX_INFLIGHT_HANDSHAKES} — each slot is a live NoiseResponder "
            "+ per-peer inbox; a larger pool is a memory-exhaustion footgun)"
        )
    if c.max_inflight_handshakes > WARN_INFLIGHT_HANDSHAKES:
        log.warning(
            "max_inflight_handshakes=%d is very high; each slot is a live "
            "NoiseResponder + per-peer inbox. Values in the low tens are "
            "ample for the single-admitted-session model.",
            c.max_inflight_handshakes,
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


def _validate_auto_mtu(c: Config) -> None:
    # auto_mtu adapts the TUN MTU from kernel PMTU readings, which are only
    # available when pmtu_discover sets IP_PMTUDISC_DO — get_path_mtu() returns
    # None otherwise. auto_mtu without pmtu_discover is silently inert, so warn
    # loudly rather than let an operator believe the path is adapting.
    if c.auto_mtu and not c.pmtu_discover:
        log.warning(
            "auto_mtu=true has no effect unless pmtu_discover=true is also set "
            "(kernel PMTU is unavailable without it); the TUN MTU will not "
            "adapt. Set pmtu_discover=true to enable PMTU adaptation."
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
    _validate_attest_tpm_tcti,
    _validate_role_specific,
    _validate_padding,
    _validate_shaper,
    _validate_rotation,
    _validate_log_level,
    _validate_tun_name,
    _validate_mtu,
    _validate_pmtu_interval,
    _validate_auto_mtu,
    _validate_max_inflight_handshakes,
)


def _validate(c: Config) -> None:
    """Run every section validator in the fixed _VALIDATORS order.

    Each validator either returns or raises ``ValueError``. Order matters
    — the first failure short-circuits, so test cases that exercise one
    validation rule rely on the prior rules accepting their fixture.
    """
    for validator in _VALIDATORS:
        validator(c)


def _reject_removed_keys(raw: dict[str, object]) -> None:
    """Stop with a clear message for keys that were removed (otherwise
    Config(**raw) fails with a cryptic TypeError): the adaptive envelope's
    envelope_* keys and the jitter keys."""
    old = sorted(key for key in raw if key.startswith("envelope_"))
    if old:
        raise ConfigError(
            f"config key(s) {', '.join(old)} no longer exist: the adaptive "
            f"envelope was replaced by the tier shaper. Remove them and use "
            f"{', '.join(SHAPER_KEYS)} instead (see config.example.toml)."
        )
    jitter = sorted(key for key in raw if key in _REMOVED_JITTER_KEYS)
    if jitter:
        raise ConfigError(
            f"config key(s) {', '.join(jitter)} no longer exist: the tier "
            f"shaper decides when every packet leaves, so there is no extra "
            f"random wait to set. Remove them (see config.example.toml)."
        )


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
    _reject_removed_keys(raw)
    raw.setdefault("config_dir", config_dir)
    return Config(**raw)
