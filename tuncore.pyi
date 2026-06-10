"""Type stubs for the tuncore native Rust extension (PyO3).

PyO3 maps `Vec<u8>` to Python `list[int]` at the FFI boundary; we declare
those returns as `bytes` here so type-checking is useful, but production
callers that hand the value to anything strict (struct.unpack_from,
hmac.compare_digest, os.write) MUST coerce with `bytes(...)`. The cost of
this small lie in the stub is one explicit wrap per call site; the
benefit is that everything downstream type-checks correctly.

EXCEPTION (H-PERF-3): ``SessionKeyManager.encrypt`` and
``SessionKeyManager.decrypt`` return ``PyBytes`` directly from Rust — the
hot path does the conversion once on the Rust side instead of forcing
every Python caller to allocate again. Those two stubs match reality
without a coercion lie; callers may pass the returned values straight to
``struct.unpack_from`` / ``os.write`` / the wire serializer.
"""

class IdentityKeyPair:
    @staticmethod
    def generate() -> IdentityKeyPair: ...
    @property
    def public_key(self) -> bytes: ...
    def encrypt_to_store(self, passphrase: bytes) -> bytes: ...
    @staticmethod
    def decrypt_from_store(blob: bytes, passphrase: bytes) -> IdentityKeyPair: ...
    def compute_hmac(self, context: bytes, data: bytes) -> bytes: ...
    def zeroize(self) -> None: ...

class ReplayWindow:
    def __init__(self) -> None: ...
    def check_and_update(self, seq: int) -> bool: ...
    def check(self, seq: int) -> bool: ...
    def update(self, seq: int) -> None: ...
    @property
    def max_seq(self) -> int: ...

class NonceGenerator:
    def __init__(self, epoch: int) -> None: ...
    def next(self) -> bytes: ...
    @property
    def count(self) -> int: ...
    @property
    def epoch(self) -> int: ...

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

    def encrypt(self, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes, int]: ...
    def decrypt(
        self,
        nonce: bytes,
        ciphertext: bytes,
        aad: bytes,
        seq: int,
        is_prev_epoch: bool,
    ) -> bytes: ...
    def try_decrypt_with_fallback(
        self,
        nonce: bytes,
        ciphertext: bytes,
        aad: bytes,
        seq: int,
    ) -> tuple[bytes, bool] | None:
        """M-PERF-5: non-raising decrypt with grace-period fallback.

        Returns ``(plaintext, used_prev_epoch)`` on success, ``None`` on
        auth failure. The failure path executes a constant 2 AEAD ops
        regardless of grace state so an adversary cannot infer rekey
        timing via forgery-reject latency (audit M1).
        """
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

    def complete_rotation_responder(
        self, remote_ephemeral_pub: bytes, new_epoch: int
    ) -> tuple[bytes, int]: ...
    def prepare_rotation_responder(
        self, remote_ephemeral_pub: bytes, new_epoch: int
    ) -> tuple[bytes, int]: ...
    def apply_rotation_responder(self) -> int: ...
    def tick(self) -> None: ...
    @property
    def epoch(self) -> int: ...
    @property
    def packets_sent(self) -> int: ...
    @property
    def has_grace_period(self) -> bool: ...
    @property
    def has_pending_send_swap(self) -> bool:
        """H-BUG-2/3: True between the responder's `apply_rotation_responder`
        and `tick()` promoting `pending_new_send` (GRACE_PERIOD_SECS).
        """
        ...

class AesKey:
    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes: ...
    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes: ...

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

def disable_core_dumps() -> None: ...
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

# Fixed size of the attestation payload carried in Noise XX msg2 / msg3.
# Producers must pad cert + binding signature + framing to exactly this many
# bytes; receivers get exactly this many bytes back from
# ``NoiseInitiator.read_message_2`` / ``NoiseResponder.read_message_3``.
HANDSHAKE_ATTEST_PAYLOAD_SIZE: int
