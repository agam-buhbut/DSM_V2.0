"""Wire-parser fuzz harness: look for inputs that crash a parser with an
untyped exception (the class of bug behind the TCP framing crash).

Run directly:  python3 tests/fuzz/fuzz_parsers.py
NOT collected by pytest (no test_ functions; __main__ guard drives execution).

Targets:
  1. InnerPacket.deserialize   (dsm/core/protocol.py)
  2. Fragment.deserialize      (dsm/core/protocol.py)
  3. handle_rekey_init payload (dsm/rekey.py — pure payload slice, no I/O)
  4. handle_rekey_ack  payload (dsm/rekey.py — pure payload slice, no I/O)
  5. the TCP frame-length check (a replica of TCPTransport.recv's header parse)

The async TCP recv() path itself is covered by mocked-stream tests in
test_tcp_framing.py and test_server_malformed_frame.py.  UDP transport does
zero byte-parsing (it is a raw datagram pass-through).

A FINDING is any exception whose type is NOT in the parser's declared/typed
error set.  For the protocol and rekey targets the documented error is
ValueError.  Any
struct.error, IndexError, KeyError, UnicodeDecodeError, AttributeError, or
other type is recorded as a finding.

Bounds: ~3 000 iterations per parser → terminates in seconds.
"""

from __future__ import annotations

import random
import struct
import sys
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# Seed for reproducibility of the random corpus (not security-sensitive)
# ---------------------------------------------------------------------------
_RNG = random.Random(0xDEADBEEF)

# ---------------------------------------------------------------------------
# The accepted/expected exception types for the protocol and rekey targets.
# Any exception NOT in this set is a finding.
# ---------------------------------------------------------------------------
_EXPECTED_ERRORS: frozenset[type] = frozenset({ValueError})

# ---------------------------------------------------------------------------
# Corpus helpers
# ---------------------------------------------------------------------------

_BOUNDARY_SIZES = [
    0,
    1,
    2,
    3,
    4,
    5,
    35,
    36,
    37,
    127,
    128,
    255,
    256,
    1399,
    1400,
    1401,
    1403,
    1404,
    1405,
    65535,
    65536,
    65537,
]


def _random_bytes(n: int) -> bytes:
    return bytes(_RNG.randint(0, 255) for _ in range(n))


def _build_corpus(
    valid_examples: list[bytes],
    random_count: int = 500,
    max_random_len: int = 2048,
) -> list[bytes]:
    """Build a fuzz corpus from:
    - boundary-length random blobs
    - random-length random blobs
    - truncations of every valid example at each prefix length
    - single-bit flips of every valid example
    - oversized-field variants (4-byte BE length fields set to 2**31-1)
    """
    corpus: list[bytes] = []

    # Boundary-size random blobs
    for sz in _BOUNDARY_SIZES:
        corpus.append(_random_bytes(sz))
        corpus.append(b"\x00" * sz)
        corpus.append(b"\xff" * sz)

    # Random-length random blobs
    for _ in range(random_count):
        n = _RNG.randint(0, max_random_len)
        corpus.append(_random_bytes(n))

    # Truncations and bit-flips of valid examples
    for ex in valid_examples:
        # Every prefix length
        for cut in range(len(ex) + 1):
            corpus.append(ex[:cut])
        # Single-bit flips
        for byte_pos in range(min(len(ex), 64)):
            for bit in range(8):
                arr = bytearray(ex)
                arr[byte_pos] ^= 1 << bit
                corpus.append(bytes(arr))

    # Oversized internal length fields at offset 0, 2, 4
    for offset in (0, 2, 4):
        for big_val in (0xFFFFFFFF, 0x7FFFFFFF, 0x10000, 65536, 65537):
            for fmt in ("!I", "!H"):
                sz = struct.calcsize(fmt)
                pad = _random_bytes(max(0, offset + sz + 4))
                arr = bytearray(pad)
                if offset + sz <= len(arr):
                    struct.pack_into(
                        fmt,
                        arr,
                        offset,
                        big_val & (0xFFFFFFFF if fmt == "!I" else 0xFFFF),
                    )
                corpus.append(bytes(arr))

    return corpus


# ---------------------------------------------------------------------------
# Finding record
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    parser: str
    entry_point: str
    input_hex: str
    input_len: int
    exc_type: str
    exc_msg: str
    severity: str  # HIGH / MEDIUM / LOW


_all_findings: list[Finding] = []


def _record(
    parser: str,
    entry_point: str,
    data: bytes,
    exc: BaseException,
    severity: str = "HIGH",
) -> None:
    hex_repr = data[:32].hex()
    if len(data) > 32:
        hex_repr += f"... (+{len(data) - 32} bytes)"
    finding = Finding(
        parser=parser,
        entry_point=entry_point,
        input_hex=hex_repr,
        input_len=len(data),
        exc_type=type(exc).__name__,
        exc_msg=str(exc)[:120],
        severity=severity,
    )
    _all_findings.append(finding)


def _is_expected(exc: BaseException) -> bool:
    return type(exc) in _EXPECTED_ERRORS


# ---------------------------------------------------------------------------
# Fuzz target: InnerPacket.deserialize
# ---------------------------------------------------------------------------


def fuzz_inner_packet_deserialize(iterations: int = 3000) -> int:
    """Returns number of findings."""
    # Build a minimal valid InnerPacket as a corpus seed
    import struct as _struct

    from dsm.core.protocol import InnerPacket, PacketType

    valid: list[bytes] = []
    for ptype in list(PacketType):
        flags = 0x00  # epoch_id=0, reserved=0
        inner_len = 0
        hdr = _struct.pack("!BBH", ptype.value, flags, inner_len)
        valid.append(hdr)  # empty payload
        # With a small payload
        payload = b"\xab\xcd\xef"
        hdr_with_payload = (
            _struct.pack("!BBH", ptype.value, flags, len(payload)) + payload
        )
        valid.append(hdr_with_payload)

    corpus = _build_corpus(valid, random_count=500)
    findings_before = len(_all_findings)

    for data in corpus[:iterations]:
        try:
            InnerPacket.deserialize(data)
        except BaseException as exc:  # noqa: BLE001
            if not _is_expected(exc):
                _record(
                    "InnerPacket",
                    "dsm/core/protocol.py:InnerPacket.deserialize",
                    data,
                    exc,
                )

    return len(_all_findings) - findings_before


# ---------------------------------------------------------------------------
# Fuzz target: Fragment.deserialize
# ---------------------------------------------------------------------------


def fuzz_fragment_deserialize(iterations: int = 3000) -> int:
    import struct as _struct

    from dsm.core.protocol import MAX_FRAGMENTS, Fragment

    # Minimal valid fragment
    valid: list[bytes] = []
    for total in (1, 2, MAX_FRAGMENTS):
        for idx in range(min(total, 3)):
            hdr = _struct.pack("!HBB", 42, idx, total)
            valid.append(hdr)  # empty data
            valid.append(hdr + b"\x00" * 16)
            valid.append(hdr + b"\xab" * 100)

    # Edge: total=0, total=MAX_FRAGMENTS+1, idx>=total
    for bad in [
        _struct.pack("!HBB", 0, 0, 0),  # total=0
        _struct.pack("!HBB", 0, 0, MAX_FRAGMENTS + 1),  # total > max
        _struct.pack("!HBB", 0, 5, 3),  # idx >= total
        _struct.pack("!HBB", 0, 0, 255),  # huge total
        _struct.pack("!HBB", 0, 254, 255),  # idx=254 total=255 > MAX
    ]:
        valid.append(bad)

    corpus = _build_corpus(valid, random_count=500)
    findings_before = len(_all_findings)

    for data in corpus[:iterations]:
        try:
            Fragment.deserialize(data)
        except BaseException as exc:  # noqa: BLE001
            if not _is_expected(exc):
                _record(
                    "Fragment",
                    "dsm/core/protocol.py:Fragment.deserialize",
                    data,
                    exc,
                )

    return len(_all_findings) - findings_before


# ---------------------------------------------------------------------------
# Fuzz target: handle_rekey_init payload parser
#
# handle_rekey_init is async and requires tuncore.SessionKeyManager, FSM, etc.
# We are testing ONLY the synchronous payload-parsing slice it performs:
#   - len(payload) < REKEY_PAYLOAD_SIZE check (line 259)
#   - struct.unpack("!I", payload[:4]) (line 263)
#   - payload[4:36] slice (line 264)
# These are the ONLY bytes-parsing operations in handle_rekey_init.
# We replicate that exact slice in a pure function so we can fuzz it without
# live tuncore / asyncio context.
# ---------------------------------------------------------------------------


def fuzz_rekey_init_payload(iterations: int = 3000) -> int:
    """Fuzz the payload-parsing slice of handle_rekey_init."""
    import struct as _struct

    REKEY_PAYLOAD_SIZE = 36

    def parse_rekey_init_payload(payload: bytes) -> None:
        """Mirror of handle_rekey_init payload parsing (lines 259-264)."""
        if len(payload) < REKEY_PAYLOAD_SIZE:
            # Early return — as the real function does
            return
        new_epoch = _struct.unpack("!I", payload[:4])[0]
        remote_ephemeral_pub = payload[4:36]
        # Validate they are extractable (no further parsing beyond slice)
        _ = new_epoch
        _ = remote_ephemeral_pub

    # Valid example: 36 bytes, first 4 = epoch uint32, next 32 = pub key
    valid = [
        _struct.pack("!I", 0) + b"\x00" * 32,
        _struct.pack("!I", 1) + b"\xab" * 32,
        _struct.pack("!I", 0xFFFFFFFF) + b"\xff" * 32,
    ]

    corpus = _build_corpus(valid, random_count=500)
    findings_before = len(_all_findings)

    for data in corpus[:iterations]:
        try:
            parse_rekey_init_payload(data)
        except BaseException as exc:  # noqa: BLE001
            if not _is_expected(exc):
                _record(
                    "rekey_init_payload",
                    "dsm/rekey.py:handle_rekey_init (payload parse slice)",
                    data,
                    exc,
                )

    return len(_all_findings) - findings_before


# ---------------------------------------------------------------------------
# Fuzz target: handle_rekey_ack payload parser
#
# Same approach: replicate the synchronous bytes-parsing slice from
# handle_rekey_ack (lines 411-422):
#   - len(payload) < REKEY_PAYLOAD_SIZE check
#   - struct.unpack("!I", payload[:4])
#   - payload[4:36] slice
# ---------------------------------------------------------------------------


def fuzz_rekey_ack_payload(iterations: int = 3000) -> int:
    """Fuzz the payload-parsing slice of handle_rekey_ack."""
    import struct as _struct

    REKEY_PAYLOAD_SIZE = 36

    def parse_rekey_ack_payload(payload: bytes) -> None:
        """Mirror of handle_rekey_ack payload parsing (lines 411-422)."""
        if len(payload) < REKEY_PAYLOAD_SIZE:
            return
        ack_epoch = _struct.unpack("!I", payload[:4])[0]
        remote_ephemeral_pub = payload[4:36]
        _ = ack_epoch
        _ = remote_ephemeral_pub

    valid = [
        _struct.pack("!I", 0) + b"\x00" * 32,
        _struct.pack("!I", 2) + b"\xab" * 32,
        _struct.pack("!I", 0xFFFFFFFF) + b"\xff" * 32,
    ]

    corpus = _build_corpus(valid, random_count=500)
    findings_before = len(_all_findings)

    for data in corpus[:iterations]:
        try:
            parse_rekey_ack_payload(data)
        except BaseException as exc:  # noqa: BLE001
            if not _is_expected(exc):
                _record(
                    "rekey_ack_payload",
                    "dsm/rekey.py:handle_rekey_ack (payload parse slice)",
                    data,
                    exc,
                )

    return len(_all_findings) - findings_before


# ---------------------------------------------------------------------------
# TCPTransport recv() framing logic
#
# recv() is async and needs a real asyncio.StreamReader — cannot directly call
# with raw bytes.  However, all the byte-level parsing it does is:
#   (length,) = struct.unpack("!I", len_buf)   [len_buf is exactly 4 bytes]
#   then checks length > MAX_FRAME_SIZE / length == 0
# struct.unpack("!I", x) where x is EXACTLY 4 bytes will never raise
# struct.error (the format is fixed-size 4 bytes, input is always exactly 4).
# The only parser exposure is the frame-length bounds checks (FramingError /
# ConnectionError), both of which are in _EXPECTED_ERRORS' superclasses.
#
# We replicate the framing check logic here to confirm no crash path exists.
# ---------------------------------------------------------------------------


def fuzz_tcp_frame_length_check(iterations: int = 3000) -> int:
    """Fuzz the TCP frame-length parsing logic (no asyncio needed)."""
    import struct as _struct

    MAX_FRAME_SIZE = 65536

    # FramingError is a subclass of ValueError — in _EXPECTED_ERRORS
    # ConnectionError is NOT in _EXPECTED_ERRORS but IS a documented/typed
    # error for this parser.  Add it to the local expected set.
    local_expected: frozenset[type]
    try:
        from dsm.net.transport.tcp import FramingError

        local_expected = frozenset({ValueError, FramingError, ConnectionError})
    except ImportError:
        local_expected = frozenset({ValueError, ConnectionError})

    def parse_tcp_frame_header(four_bytes: bytes) -> None:
        """Replicate the framing check from TCPTransport.recv()._read()."""
        if len(four_bytes) != 4:
            raise ValueError(f"expected 4 bytes, got {len(four_bytes)}")
        (length,) = _struct.unpack("!I", four_bytes)
        if length > MAX_FRAME_SIZE:
            raise ValueError(f"frame length {length} exceeds max {MAX_FRAME_SIZE}")
        if length == 0:
            raise ConnectionError("zero-length frame")

    # Build a corpus of 4-byte inputs (that is ALL the parser sees)
    boundary_inputs = [
        _struct.pack("!I", 0),
        _struct.pack("!I", 1),
        _struct.pack("!I", 35),
        _struct.pack("!I", 36),
        _struct.pack("!I", 1399),
        _struct.pack("!I", 1400),
        _struct.pack("!I", 1401),
        _struct.pack("!I", 65535),
        _struct.pack("!I", 65536),
        _struct.pack("!I", 65537),
        _struct.pack("!I", 0xFFFFFFFF),
        b"\x00\x00\x00\x00",
        b"\xff\xff\xff\xff",
        b"\x00\x01\x00\x00",
    ]

    corpus: list[bytes] = list(boundary_inputs)
    for _ in range(iterations - len(boundary_inputs)):
        corpus.append(_random_bytes(4))

    findings_before = len(_all_findings)

    for data in corpus[:iterations]:
        try:
            parse_tcp_frame_header(data)
        except BaseException as exc:  # noqa: BLE001
            if type(exc) not in local_expected:
                _record(
                    "TCPTransport",
                    "dsm/net/transport/tcp.py:TCPTransport.recv (frame header)",
                    data,
                    exc,
                )

    return len(_all_findings) - findings_before


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

_TARGETS: list[tuple[str, Callable[..., int], int]] = [
    ("InnerPacket.deserialize", fuzz_inner_packet_deserialize, 3000),
    ("Fragment.deserialize", fuzz_fragment_deserialize, 3000),
    ("handle_rekey_init payload", fuzz_rekey_init_payload, 3000),
    ("handle_rekey_ack  payload", fuzz_rekey_ack_payload, 3000),
    ("TCPTransport frame header", fuzz_tcp_frame_length_check, 3000),
]


def run_all() -> dict[str, Any]:
    """Run all fuzz targets and return a results summary dict."""
    results: dict[str, Any] = {}
    for name, fn, iters in _TARGETS:
        print(f"  fuzzing {name!r} ({iters} iterations)...", end=" ", flush=True)
        count = fn(iters)
        status = f"{count} finding(s)" if count else "CLEAN"
        print(status)
        results[name] = {"iterations": iters, "new_findings": count}
    return results


if __name__ == "__main__":
    print("DSM wire-parser fuzz sweep — discovery pass")
    print("=" * 60)
    results = run_all()
    print()
    print(f"Total findings: {len(_all_findings)}")
    print()

    if _all_findings:
        print("FINDINGS:")
        print("-" * 60)
        for f in _all_findings:
            print(f"  Parser      : {f.parser}")
            print(f"  Entry point : {f.entry_point}")
            print(f"  Input (hex) : {f.input_hex}")
            print(f"  Input len   : {f.input_len}")
            print(f"  Exc type    : {f.exc_type}")
            print(f"  Exc msg     : {f.exc_msg}")
            print(f"  Severity    : {f.severity}")
            print()
    else:
        print("No findings — all parsers clean.")
    print()
    print("Per-parser iteration counts:")
    for name, r in results.items():
        iters = r["iterations"]
        new = r["new_findings"]
        print(f"  {name}: {iters} iterations, {new} new finding(s)")

    sys.exit(0 if not _all_findings else 1)
