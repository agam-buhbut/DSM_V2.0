"""TUN device management for Linux.

Creates a TUN interface, configures IP/routing, and provides
async read/write for packet forwarding through the VPN tunnel.
"""

from __future__ import annotations

import asyncio
import fcntl
import json
import logging
import os
import struct
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

# ioctl constants for TUN/TAP (Linux)
TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000  # No packet info header

# VPN fwmark to prevent routing loops
FWMARK = 0x1


def _run_commands(cmds: list[list[str]], *, strict: bool = True) -> None:
    """Run a sequence of shell commands.

    Args:
        cmds: list of command argument lists
        strict: if True, raise on failure; if False, ignore errors (best-effort)
    """
    for cmd in cmds:
        try:
            subprocess.run(cmd, check=strict, capture_output=True, timeout=5)
        except subprocess.TimeoutExpired:
            if strict:
                log.error("cmd timed out: %s", " ".join(cmd))
                raise RuntimeError(f"TUN configure timed out: {' '.join(cmd)}")
        except subprocess.CalledProcessError as e:
            if strict:
                log.error("cmd failed: %s — %s", " ".join(cmd), e.stderr.decode(errors="replace"))
                raise RuntimeError(f"TUN configure failed: {' '.join(cmd)}")
        except Exception:
            if strict:
                raise


class TunDevice:
    """Linux TUN device for VPN packet routing."""

    # Path to store IPv6 per-interface state for restoration on cleanup.
    _IPV6_STATE_PATH = Path("/run/dsm/ipv6_state.json")

    def __init__(self, name: str = "mtun0") -> None:
        if len(name.encode()) > 15:
            raise ValueError(f"TUN device name too long (max 15 chars): {name!r}")
        self._name = name
        self._fd: int | None = None
        # Only set to True once configure() has fully succeeded.
        # Guards deconfigure() from restoring IPv6 state that belongs to
        # a prior crashed run rather than this process.
        self._configured = False

    @property
    def name(self) -> str:
        return self._name

    @property
    def fd(self) -> int:
        if self._fd is None:
            raise RuntimeError("TUN device not open")
        return self._fd

    def _capture_ipv6_state(self) -> dict[str, bool]:
        """Capture current IPv6 disable state for all non-TUN interfaces.

        Interface names are read from /sys/class/net (no text parsing),
        then the sysctl `net.ipv6.conf.<iface>.disable_ipv6` is read via
        the procfs path (avoids shelling out to `sysctl` per iface).
        """
        state: dict[str, bool] = {}
        try:
            net_dir = Path("/sys/class/net")
            if not net_dir.exists():
                return state
            for iface_dir in net_dir.iterdir():
                iface = iface_dir.name
                if iface == self._name:
                    continue
                sysctl_path = Path(f"/proc/sys/net/ipv6/conf/{iface}/disable_ipv6")
                try:
                    state[iface] = sysctl_path.read_text().strip() == "1"
                except OSError:
                    # Some virtual interfaces (e.g., removed between iterdir
                    # and read) or IPv6-less kernels won't have this knob.
                    continue
        except OSError as e:
            log.warning("failed to capture IPv6 state: %s", e)
        return state

    def _save_ipv6_state(self, state: dict[str, bool]) -> None:
        """Save IPv6 disable state to persistent JSON file."""
        try:
            self._IPV6_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(self._IPV6_STATE_PATH, "w") as f:
                json.dump(state, f)
            os.chmod(self._IPV6_STATE_PATH, 0o600)
            log.debug("saved IPv6 state to %s", self._IPV6_STATE_PATH)
        except Exception as e:
            log.warning("failed to save IPv6 state: %s", e)

    def _restore_ipv6_state(self) -> None:
        """Restore IPv6 disable state from persistent JSON file."""
        if not self._IPV6_STATE_PATH.exists():
            log.debug("no IPv6 state file found, skipping restore")
            return
        try:
            with open(self._IPV6_STATE_PATH, "r") as f:
                state: dict[str, bool] = json.load(f)
            cmds: list[list[str]] = []
            for iface, was_disabled in state.items():
                value = "1" if was_disabled else "0"
                cmds.append(["sysctl", "-w", f"net.ipv6.conf.{iface}.disable_ipv6={value}"])
            if cmds:
                _run_commands(cmds, strict=False)
            self._IPV6_STATE_PATH.unlink(missing_ok=True)
            log.debug("restored IPv6 state from %s", self._IPV6_STATE_PATH)
        except Exception as e:
            log.warning("failed to restore IPv6 state: %s", e)

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
        # Capture IPv6 state before disabling globally
        ipv6_state = self._capture_ipv6_state()
        self._save_ipv6_state(ipv6_state)

        cmds = [
            ["ip", "addr", "replace", f"{local_ip}/{netmask}", "dev", self._name],
            ["ip", "link", "set", self._name, "mtu", str(mtu)],
            ["ip", "link", "set", self._name, "up"],
            # Routing: use a separate table to route all traffic through TUN
            # except VPN's own traffic (marked with FWMARK)
            ["ip", "route", "replace", "default", "dev", self._name, "table", "100"],
            # Disable IPv6 on non-TUN interfaces to prevent dual-stack leaks.
            # The nftables rules also block IPv6, but disabling at sysctl level
            # prevents any IPv6 traffic from being generated in the first place.
            ["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=1"],
            ["sysctl", "-w", f"net.ipv6.conf.{self._name}.disable_ipv6=0"],
        ]
        # ip rule has no 'replace' — delete first (ignore if absent), then add
        rule_args = [
            "not", "fwmark", str(FWMARK), "table", "100", "priority", "10",
        ]
        subprocess.run(
            ["ip", "rule", "del", *rule_args],
            capture_output=True, timeout=5,
        )  # ignore errors — rule may not exist yet
        cmds.append(["ip", "rule", "add", *rule_args])

        _run_commands(cmds)
        self._configured = True

        log.info("TUN %s configured: %s/%d mtu=%d", self._name, local_ip, netmask, mtu)

    def deconfigure(self) -> None:
        """Remove routing rules and bring down the interface."""
        _run_commands(
            [
                ["ip", "rule", "del", "not", "fwmark", str(FWMARK), "table", "100"],
                ["ip", "route", "del", "default", "dev", self._name, "table", "100"],
                ["ip", "link", "set", self._name, "down"],
            ],
            strict=False,
        )
        # Only restore IPv6 state if we successfully configured in this process.
        # Without this guard we might restore a state file left behind by a
        # crashed earlier run that doesn't reflect the current host state.
        if self._configured:
            self._restore_ipv6_state()
            self._configured = False

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
        """Write a packet to the TUN device (async, avoids blocking event loop).

        TUN has a kernel-side buffer; a non-blocking write almost always
        succeeds immediately. Try the sync write first to skip the thread
        hop on the common path; only on ``EAGAIN`` do we fall back to
        the executor. This cuts per-packet latency meaningfully on the
        send-from-recv-loop hot path and avoids needless thread-pool
        churn on low-RAM targets.
        """
        try:
            return os.write(self.fd, data)
        except BlockingIOError:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, os.write, self.fd, data)

    def close(self) -> None:
        """Close the TUN device."""
        if self._fd is None:
            return
        try:
            self.deconfigure()
        finally:
            # Always close the fd, even if deconfigure raises — otherwise the
            # file descriptor leaks and the TUN device stays held by the kernel.
            os.close(self._fd)
            self._fd = None
            log.info("TUN device %s closed", self._name)
