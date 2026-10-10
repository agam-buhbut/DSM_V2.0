"""Type stubs for the tuncore native Rust extension (PyO3).

PyO3 maps `Vec<u8>` to Python `list[int]` at the FFI boundary; we declare
those returns as `bytes` here so type-checking is useful, but production
callers that hand the value to anything strict (struct.unpack_from,
hmac.compare_digest, os.write) MUST coerce with `bytes(...)`. The cost of
this small lie in the stub is one explicit wrap per call site; the
benefit is that everything downstream type-checks correctly.

EXCEPTION (H-PERF-3): ``SessionKeyManager.seal_packet``,
``SessionKeyManager.open_packet``, ``xchacha_seal`` and ``xchacha_open``
return ``PyBytes`` directly from Rust — the conversion happens
once on the Rust side instead of forcing every Python caller to allocate
again. Those stubs match reality without a coercion lie; callers may pass
the returned values straight to ``struct.unpack_from`` / ``os.write`` /
the wire serializer.
"""

class IdentityKeyPair:
    @staticmethod
    def generate() -> IdentityKeyPair: ...
    @property
    def public_key(self) -> bytes: ...
    def encrypt_to_store(self, passphrase: bytes) -> bytes: ...
    @staticmethod
    def decrypt_from_store(blob: bytes, passphrase: bytes) -> IdentityKeyPair: ...
    def zeroize(self) -> None: ...

class ReplayWindow:
    def __init__(self) -> None: ...
    def check(self, seq: int) -> bool: ...
    def update(self, seq: int) -> None: ...

class NoiseInitiator:
    def __init__(self, identity: IdentityKeyPair) -> None: ...
    def write_message_1(self) -> bytes: ...
    def read_message_2(self, msg: bytes) -> tuple[bytes, bytes]:
        """Returns ``(remote_static_pub, attest_payload)``.

        ``attest_payload`` is exactly ``HANDSHAKE_ATTEST_PAYLOAD_SIZE``
        bytes; the caller parses cert + binding signature framing.
        """
        ...

    def write_message_3(self, attest_payload: bytes) -> bytes:
        """``attest_payload`` must be exactly ``HANDSHAKE_ATTEST_PAYLOAD_SIZE`` bytes."""
        ...

    def into_transport(self) -> NoiseTransport: ...
    def get_handshake_hash(self) -> bytes: ...

class NoiseResponder:
    def __init__(self, identity: IdentityKeyPair) -> None: ...
    def read_message_1(self, msg: bytes) -> None: ...
    def write_message_2(self, attest_payload: bytes) -> bytes:
        """``attest_payload`` must be exactly ``HANDSHAKE_ATTEST_PAYLOAD_SIZE`` bytes."""
        ...

    def read_message_3(self, msg: bytes) -> tuple[bytes, bytes]:
        """Returns ``(remote_static_pub, attest_payload)``."""
        ...

    def into_transport(self) -> NoiseTransport: ...
    def get_handshake_hash(self) -> bytes: ...

class NoiseTransport:
    def encrypt(self, plaintext: bytes) -> bytes: ...
    def decrypt(self, ciphertext: bytes) -> bytes: ...

class SessionKeyManager:
    """Holds the symmetric session keys for one direction-pair.

    Constructed only via :func:`complete_bootstrap` — the safe path that
    keeps the X25519 secret scalar in mlock'd Rust heap. The earlier
    constructors (``from_handshake_hash``, ``from_bootstrap_shared_secret``)
    were removed during the audit (M4): the first derived keys from the
    PUBLIC handshake hash, the second accepted SECRET bytes through a
    Python ``bytes`` object that cannot be reliably zeroed.
    """

    def seal_packet(self, seq: int, plaintext: bytes) -> bytes:
        """Seal one wire v2 data packet; returns the whole wire packet
        (20 + len(plaintext) + 16 bytes). Raises RuntimeError when the nonce
        counter is used up (a key change is overdue)."""
        ...

    def open_packet(self, wire: bytes) -> tuple[int, bytes, bool] | None:
        """Open one wire v2 data packet: ``(seq, plaintext, used_prev)``, or
        ``None`` for anything that does not open (junk, a forgery, a replay,
        another key set's packet). Never raises on peer bytes."""
        ...

    def needs_rotation(self) -> bool: ...
    def initiate_rotation(self) -> tuple[int, bytes]: ...
    def complete_rotation_initiator(self, remote_ephemeral_pub: bytes) -> int: ...
    def abort_rotation(self) -> bool:
        """Drop a pending initiator rotation; True if one was discarded.

        Idempotent. Used on the mutual-init rekey tie-break yield path so a
        later ``initiate_rotation`` doesn't fail with "rotation already in
        progress" (DSM-003). The abandoned ephemeral secret is zeroized on
        drop; no key material crosses the FFI.
        """
        ...

    def prepare_rotation_responder(
        self, remote_ephemeral_pub: bytes, new_epoch: int
    ) -> tuple[bytes, int]: ...
    def apply_rotation_responder(self) -> int: ...
    def tick(self) -> None: ...
    @property
    def epoch(self) -> int: ...
    @property
    def send_epoch(self) -> int: ...
    @property
    def has_grace_period(self) -> bool: ...

class AttestKey:
    """Device-attestation key. Backend (soft / TPM / Keystore) is chosen at
    Rust compile time; the FFI surface is identical."""

    @staticmethod
    def generate() -> AttestKey:
        """Generate a fresh attestation keypair using the active backend."""
        ...

    def public_spki_der(self) -> bytes:
        """SubjectPublicKeyInfo DER of the verifying key. Non-secret."""
        ...

    def sign(self, msg: bytes) -> bytes:
        """Sign ``msg``. Returns ASN.1 DER ECDSA signature."""
        ...

    def encrypt_to_store(self, passphrase: bytes) -> bytes:
        """Encrypt the attest key (Argon2id + XChaCha20-Poly1305).

        Soft backend only — TPM / Keystore backends seal natively and
        will reject this call when implemented.
        """
        ...

    @staticmethod
    def decrypt_from_store(blob: bytes, passphrase: bytes) -> AttestKey:
        """Restore an attest key from a stored blob (soft backend only)."""
        ...

    def build_csr(self, cn: str, noise_static_pub: bytes) -> bytes:
        """Build a CA-ready DER CSR for this attest key.

        The PKCS#8 export of the signing scalar stays inside Rust — no
        key bytes cross the FFI boundary into Python ``bytes``-managed
        memory. ``noise_static_pub`` is the 32-byte X25519 Noise static
        embedded in the critical ``id-dsm-noiseStaticBinding`` extension.
        """
        ...

    def zeroize(self) -> None:
        """Wipe the signing scalar in place. After this call the instance
        is unusable; sign/encrypt_to_store/build_csr will operate on a
        zeroed scalar. Safe to call multiple times; idempotent."""
        ...

class BootstrapEphemeral:
    """Opaque handle holding an X25519 ephemeral keypair.

    The secret scalar lives in an mlock'd, zeroize-on-drop Rust heap
    buffer; Python only sees the matching public key. Consumed by
    :func:`complete_bootstrap`, after which :attr:`is_live` flips to
    ``False`` and a second use raises.
    """

    @staticmethod
    def generate() -> BootstrapEphemeral: ...
    @property
    def public_key_bytes(self) -> bytes: ...
    @property
    def is_live(self) -> bool: ...

class Shaper:
    """Tier shaper core for one session and one direction (Rust).

    Decides when packets leave and how big they are. Each session draws its
    own secret timing values from the OS RNG; nothing exposes them (no
    getters, nothing in ``repr``). A tier cap (``set_tier_cap``) holds the
    rate below the top tier: every climb stops at it, and a higher tier steps
    down at the next poll. ``tier()`` reads the tier in use, which is not a
    secret. Config errors raise ``ValueError``. An integer outside the range
    a call takes raises ``OverflowError``.
    """

    def __init__(
        self,
        tiers_pps: list[float],
        latency_budget_s: float,
        decoy_interval_s: float,
        linger_s: tuple[float, float],
        padding_min: int,
        padding_max: int,
        now: float,
    ) -> None: ...
    def poll(
        self, now: float, queue_len: int, oldest_wait: float, real_sent: int
    ) -> tuple[int, float]:
        """Advance to ``now``; return ``(slots_due, next_wake)``.

        Send ``slots_due`` packets now (real first, chaff for the rest) and
        poll again at ``next_wake``. ``real_sent`` counts the real packets
        sent since the previous poll.
        """
        ...

    def real_size_class(self, payload_len: int) -> int: ...
    def chaff_size_class(self) -> int: ...
    def set_size_class_ceiling(self, max_outer: int) -> None:
        """Use only size classes up to ``max_outer`` bytes (0 to 65535)."""
        ...

    def active_classes(self) -> list[int]: ...
    def set_tier_cap(self, cap: int) -> None:
        """Highest tier to use from the next poll on (0 counts as 1)."""
        ...

    def tier(self) -> int:
        """The tier in use now (0 = idle)."""
        ...

def harden_process() -> None: ...
def complete_bootstrap(
    ephemeral: BootstrapEphemeral,
    peer_public: bytes,
    is_initiator: bool,
    rotation_packets: int | None = None,
    rotation_seconds: int | None = None,
) -> SessionKeyManager:
    """Derive session keys from a bootstrap ephemeral and the peer's public key.

    Consumes ``ephemeral`` in place — a second call returns an error. The
    X25519 DH and the subsequent HKDF expansion happen entirely in Rust;
    the secret scalar never crosses the FFI boundary.

    ``rotation_packets`` / ``rotation_seconds`` override the default
    rotation thresholds (5000 / 600); jitter is always applied.
    """
    ...

def xchacha_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """XChaCha20-Poly1305 seal (the wire v2 cookie reply). ValueError for a key
    that is not 32 bytes or a nonce that is not 24 bytes."""
    ...

def xchacha_open(
    key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes
) -> bytes | None:
    """XChaCha20-Poly1305 open: the plaintext, or None when it does not open.
    Never raises on peer bytes; ValueError only for a key that is not 32
    bytes."""
    ...

# Fixed size of the attestation payload carried in Noise XX msg2 / msg3.
# Producers must pad cert + binding signature + framing to exactly this many
# bytes; receivers get exactly this many bytes back from
# ``NoiseInitiator.read_message_2`` / ``NoiseResponder.read_message_3``.
HANDSHAKE_ATTEST_PAYLOAD_SIZE: int

# True when the compiled attestation backend is the extractable software
# backend (dev-soft-attest). The daemon refuses to start on it unless
# config.allow_soft_attest is set.
ATTEST_BACKEND_IS_SOFTWARE: bool

# Padded outer packet sizes (bytes) and their draw weights. The Rust shaper
# owns them; dsm.core.protocol re-exports them.
SIZE_CLASSES: tuple[int, ...]
SIZE_CLASS_WEIGHTS: tuple[int, ...]

# Chaff size nudge: a draw below UP_P moves one class up. A draw from UP_P up
# to just below DOWN_P moves one class down.
CHAFF_PERTURB_UP_P: float
CHAFF_PERTURB_DOWN_P: float

# Longest time a rekey responder keeps the old keys while it waits for the
# peer to use the new ones (session_keys.rs PEER_CONFIRM_LIMIT_SECS).
REKEY_PEER_CONFIRM_LIMIT_SECS: int

# The wire version carried in the Noise prologue (2 since wire v2).
WIRE_VERSION: int
