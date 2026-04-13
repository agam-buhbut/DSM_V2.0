from __future__ import annotations

import ipaddress
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


@dataclass(frozen=True, slots=True)
class Config:
    mode: Literal["client", "server", "relay"]
    server_ip: str
    server_port: int
    listen_port: int
    key_file: str
    transport: Literal["udp", "tcp"] = "udp"
    relay_addresses: list[str] = field(default_factory=list[str])
    dns_providers: list[str] = field(default_factory=list[str])
    tun_name: str = "mtun0"
    log_level: Literal["debug", "info", "warning", "error"] = "warning"
    padding_min: int = 128
    padding_max: int = 1400
    jitter_ms_min: int = 1
    jitter_ms_max: int = 50
    rotation_packets: int = 5000
    rotation_seconds: int = 600

    def __post_init__(self) -> None:
        _validate(self)


def _validate(c: Config) -> None:
    # mode
    if c.mode not in ("client", "server", "relay"):
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

    # relay addresses
    if c.mode == "relay" and not c.relay_addresses:
        raise ValueError("relay mode requires at least one relay_addresses entry")
    for addr in c.relay_addresses:
        _validate_host_port(addr, "relay_addresses")

    # dns providers
    if c.mode == "server" and not c.dns_providers:
        raise ValueError("server mode requires at least one dns_providers entry")

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


def _validate_host_port(addr: str, field_name: str) -> None:
    """Validate 'host:port' string."""
    if ":" not in addr:
        raise ValueError(f"{field_name} entry missing port: {addr!r}")
    host, port_str = addr.rsplit(":", 1)
    try:
        port = int(port_str)
    except ValueError as e:
        raise ValueError(f"{field_name} invalid port: {addr!r}") from e
    if not (MIN_PORT <= port <= MAX_PORT):
        raise ValueError(f"{field_name} port out of range: {addr!r}")
    # Validate host is an IP
    try:
        ipaddress.ip_address(host)
    except ValueError as e:
        raise ValueError(f"{field_name} invalid IP: {addr!r}") from e


def load(path: Path | None = None) -> Config:
    """Load and validate config from TOML file."""
    p = path or CONFIG_PATH
    with open(p, "rb") as f:
        raw = tomllib.load(f)
    return Config(**raw)
