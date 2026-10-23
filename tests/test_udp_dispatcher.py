"""UDPDispatcher (multi-client spec §2.5) and the header check it uses
(§6.1): each packet goes, unopened, to the session whose keys its header
fits; a packet no session fits goes to the acceptor. Real tuncore keys from
complete_bootstrap (random, so a wrong match is 1 in 2^31 per check, as on
the wire); no sockets."""

from __future__ import annotations

import tuncore


def _pair() -> tuple[tuncore.SessionKeyManager, tuncore.SessionKeyManager]:
    """(client keys, server keys) of one session."""
    client_eph = tuncore.BootstrapEphemeral.generate()
    server_eph = tuncore.BootstrapEphemeral.generate()
    client_pub = bytes(client_eph.public_key_bytes)
    server_pub = bytes(server_eph.public_key_bytes)
    client = tuncore.complete_bootstrap(client_eph, server_pub, is_initiator=True)
    server = tuncore.complete_bootstrap(server_eph, client_pub, is_initiator=False)
    return client, server


def _rotate(
    client: tuncore.SessionKeyManager, server: tuncore.SessionKeyManager
) -> None:
    """One key change; the server keeps its old receive keys for late packets.
    The ephemeral keys come back as lists of ints, hence ``bytes()``."""
    new_epoch, client_pub = client.initiate_rotation()
    server_pub, _ = server.prepare_rotation_responder(bytes(client_pub), new_epoch)
    server.apply_rotation_responder()
    client.complete_rotation_initiator(bytes(server_pub))


def test_the_header_check_fits_only_its_own_keys() -> None:
    client, server = _pair()
    other, _ = _pair()
    wire = client.seal_packet(1, b"hello")
    assert server.header_matches(wire)
    assert not server.header_matches(other.seal_packet(1, b"hello"))
    assert not server.header_matches(server.seal_packet(1, b"other direction"))
    assert not server.header_matches(wire[:35])  # shorter than header and tag


def test_the_header_check_fits_the_previous_key_set_too() -> None:
    client, server = _pair()
    old = client.seal_packet(1, b"old keys")
    _rotate(client, server)
    new = client.seal_packet(2, b"new keys")
    assert server.header_matches(new)
    assert server.header_matches(old)


def test_the_header_check_changes_nothing() -> None:
    client, server = _pair()
    wire = client.seal_packet(1, b"hello")
    for _ in range(3):
        assert server.header_matches(wire)
    opened = server.open_packet(wire)
    assert opened is not None
    assert opened[1] == b"hello"
    assert server.open_packet(wire) is None  # opened once: now a replay
