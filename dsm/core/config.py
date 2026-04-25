from __future__ import annotations

import ipaddress
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

CONFIG_PATH = Path("/opt/mtun/config.toml")

# Validation bounds
MIN_PORT = 1
MAX_PORT = 65535
MIN_PADDING = 64
MAX_PADDING = 1500
MAX_JITTER_MS = 1000
MIN_ROTATION_PACKETS = 100
MIN_ROTATION_SECONDS = 60
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
    transport: Literal["udp", "tcp"] = "udp"
    dns_providers: list[str] = field(default_factory=list[str])
    dns_provider_pins: dict[str, list[str]] = field(default_factory=dict[str, list[str]])
    known_hosts_path: str | None = None
    tun_name: str = "mtun0"
    log_level: Literal["debug", "info", "warning", "error"] = "warning"
    padding_min: int = 128
    padding_max: int = 1400
    jitter_ms_min: int = 1
    jitter_ms_max: int = 50
    rotation_packets: int = 5000
    rotation_seconds: int = 600
    debug_dns: bool = False
    # When True (default), the server rejects any client whose static pubkey
    # is not in authorized_clients.json. When False AND the allowlist is empty,
    # the server accepts the first client's pubkey (TOFU) — convenience knob
    # for single-operator bootstrap. Set back to True after first connection.
    strict_client_auth: bool = True
    # TUN device MTU in bytes. Must satisfy MIN_TUN_MTU <= mtu <= MAX_TUN_MTU.
    # The wire-level path MTU budget is checked against this at startup.
    mtu: int = DEFAULT_TUN_MTU
    # Enable kernel Path-MTU Discovery on the UDP socket (IP_MTU_DISCOVER).
    # When True the kernel sets the DF (Don't Fragment) bit on outgoing
    # datagrams and records ICMP "frag needed" replies. `get_path_mtu()`
    # in dsm.net.transport.udp queries the current PMTU. When False the
    # kernel runs its default policy (IP_PMTUDISC_WANT).
    pmtu_discover: bool = False
    config_dir: Path = field(default_factory=lambda: Path("/opt/mtun/"))

    def __post_init__(self) -> None:
        _validate(self)


def _validate(c: Config) -> None:
    # mode
    if c.mode not in ("client", "server"):
        raise ValueError(f"invalid mode: {c.mode!r}")

    # server_ip
    try:
        ipaddress.ip_address(c.server_ip)
    except ValueError as e:
        raise ValueError(f"invalid server_ip: {c.server_ip!r}") from e

    # ports
    for name, val in [("server_port", c.server_port), ("listen_port", c.listen_port)]:
        if not (MIN_PORT <= val <= MAX_PORT):
            raise ValueError(f"{name} must be {MIN_PORT}-{MAX_PORT}, got {val}")

    # key_file must be a path
    if not c.key_file:
        raise ValueError("key_file must not be empty")

    # transport
    if c.transport not in ("udp", "tcp"):
        raise ValueError(f"invalid transport: {c.transport!r}")

    # dns providers
    if c.mode == "server" and not c.dns_providers:
        raise ValueError("server mode requires at least one dns_providers entry")

    # dns provider pins: any user-supplied provider must have SPKI pins configured
    for provider in c.dns_providers:
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

    # known_hosts_path (client only; optional — falls back to built-in default)
    if c.known_hosts_path is not None:
        if not c.known_hosts_path:
            raise ValueError("known_hosts_path must not be empty")
        if not Path(c.known_hosts_path).is_absolute():
            raise ValueError(
                f"known_hosts_path must be absolute, got {c.known_hosts_path!r}"
            )

    # padding
    if not (MIN_PADDING <= c.padding_min <= c.padding_max <= MAX_PADDING):
        raise ValueError(
            f"padding_min ({c.padding_min}) and padding_max ({c.padding_max}) "
            f"must satisfy {MIN_PADDING} <= min <= max <= {MAX_PADDING}"
        )

    # jitter
    if not (0 <= c.jitter_ms_min <= c.jitter_ms_max <= MAX_JITTER_MS):
        raise ValueError(
            f"jitter_ms_min ({c.jitter_ms_min}) and jitter_ms_max ({c.jitter_ms_max}) "
            f"must satisfy 0 <= min <= max <= {MAX_JITTER_MS}"
        )

    # rotation
    if c.rotation_packets < MIN_ROTATION_PACKETS:
        raise ValueError(f"rotation_packets too low: {c.rotation_packets}")
    if c.rotation_seconds < MIN_ROTATION_SECONDS:
        raise ValueError(f"rotation_seconds too low: {c.rotation_seconds}")

    # log_level
    if c.log_level not in ("debug", "info", "warning", "error"):
        raise ValueError(f"invalid log_level: {c.log_level!r}")

    # TUN MTU bounds — below 576 breaks IPv4 connectivity in common
    # assumptions, above 1500 overflows Ethernet without jumbo frames.
    if not (MIN_TUN_MTU <= c.mtu <= MAX_TUN_MTU):
        raise ValueError(
            f"mtu must be {MIN_TUN_MTU}-{MAX_TUN_MTU}, got {c.mtu}"
        )


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
