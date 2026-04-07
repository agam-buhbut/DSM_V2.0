"""TUN device management for Linux.

Creates a TUN interface, configures IP/routing, and provides
async read/write for packet forwarding through the VPN tunnel.
"""

from __future__ import annotations

import asyncio
import fcntl
import logging
import os
import struct
import subprocess

log = logging.getLogger(__name__)

# ioctl constants for TUN/TAP (Linux)
TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000  # No packet info header

# VPN fwmark to prevent routing loops
FWMARK = 0x1


class TunDevice:
    """Linux TUN device for VPN packet routing."""

    def __init__(self, name: str = "mtun0") -> None:
        if len(name.encode()) > 15:
            raise ValueError(f"TUN device name too long (max 15 chars): {name!r}")
        self._name = name
        self._fd: int | None = None

    @property
    def name(self) -> str:
        return self._name

    @property
    def fd(self) -> int:
        if self._fd is None:
            raise RuntimeError("TUN device not open")
        return self._fd

    def open(self) -> None:
        """Create and open the TUN device."""
        tun_fd = os.open("/dev/net/tun", os.O_RDWR)
        # struct ifreq: 16 bytes name + 2 bytes flags + padding
        ifr = struct.pack("16sH", self._name.encode(), IFF_TUN | IFF_NO_PI)
        try:
            fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
        except OSError as e:
            os.close(tun_fd)
            raise RuntimeError(f"failed to create TUN device {self._name}: {e}")

        # Set non-blocking for asyncio
        flags = fcntl.fcntl(tun_fd, fcntl.F_GETFL)
        fcntl.fcntl(tun_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

        self._fd = tun_fd
        log.info("TUN device %s opened (fd=%d)", self._name, tun_fd)

    def configure(
        self,
        local_ip: str = "10.8.0.2",
        netmask: int = 24,
        mtu: int = 1400,
    ) -> None:
        """Configure IP address, bring up the interface, and set routing."""
        cmds = [
            ["ip", "addr", "add", f"{local_ip}/{netmask}", "dev", self._name],
            ["ip", "link", "set", self._name, "mtu", str(mtu)],
            ["ip", "link", "set", self._name, "up"],
            # Routing: use a separate table to route all traffic through TUN
            # except VPN's own traffic (marked with FWMARK)
            ["ip", "route", "add", "default", "dev", self._name, "table", "100"],
            [
                "ip",
                "rule",
                "add",
                "not",
                "fwmark",
                str(FWMARK),
                "table",
                "100",
                "priority",
                "10",
            ],
        ]
        for cmd in cmds:
            try:
                subprocess.run(cmd, check=True, capture_output=True, timeout=5)
            except subprocess.TimeoutExpired:
                log.error("cmd timed out: %s", " ".join(cmd))
                raise RuntimeError(f"TUN configure timed out: {' '.join(cmd)}")
            except subprocess.CalledProcessError as e:
                log.error("cmd failed: %s — %s", " ".join(cmd), e.stderr.decode(errors="replace"))
                raise RuntimeError(f"TUN configure failed: {' '.join(cmd)}")

        log.info("TUN %s configured: %s/%d mtu=%d", self._name, local_ip, netmask, mtu)

    def deconfigure(self) -> None:
        """Remove routing rules and bring down the interface."""
        cmds = [
            ["ip", "rule", "del", "not", "fwmark", str(FWMARK), "table", "100"],
            ["ip", "route", "del", "default", "dev", self._name, "table", "100"],
            ["ip", "link", "set", self._name, "down"],
        ]
        for cmd in cmds:
            try:
                subprocess.run(cmd, capture_output=True, timeout=5)
            except Exception:
                pass  # Best-effort cleanup

    async def read(self, bufsize: int = 2048) -> bytes:
        """Read a packet from the TUN device (async)."""
        loop = asyncio.get_running_loop()
        fut = loop.create_future()

        def _readable() -> None:
            try:
                data = os.read(self.fd, bufsize)
                if not fut.done():
                    fut.set_result(data)
            except BlockingIOError:
                pass  # Spurious wakeup
            except Exception as e:
                if not fut.done():
                    fut.set_exception(e)
            finally:
                loop.remove_reader(self.fd)

        loop.add_reader(self.fd, _readable)
        return await fut

    def write(self, data: bytes) -> int:
        """Write a packet to the TUN device (synchronous, non-blocking)."""
        return os.write(self.fd, data)

    async def awrite(self, data: bytes) -> int:
        """Write a packet to the TUN device (async, avoids blocking event loop)."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, os.write, self.fd, data)

    def close(self) -> None:
        """Close the TUN device."""
        if self._fd is not None:
            self.deconfigure()
            os.close(self._fd)
            self._fd = None
            log.info("TUN device %s closed", self._name)
