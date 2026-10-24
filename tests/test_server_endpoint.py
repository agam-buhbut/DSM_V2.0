import asyncio
from unittest.mock import patch

import pytest

from dsm.client import _resolve_server_endpoint
from dsm.core.config import _is_valid_hostname


class TestHostnameValidation:
    @pytest.mark.parametrize(
        "name", ["home.duckdns.org", "a.b.c", "x-y.example.com", "host"]
    )
    def test_valid_hostnames(self, name):
        assert _is_valid_hostname(name)

    @pytest.mark.parametrize(
        "name", ["", "-bad.com", "bad-.com", "a..b", "x" * 64 + ".com", " sp.com"]
    )
    def test_invalid_hostnames(self, name):
        assert not _is_valid_hostname(name)


class TestResolveServerEndpoint:
    def test_ipv4_literal_returns_unchanged_without_lookup(self):
        with patch("socket.getaddrinfo") as gai:
            result = asyncio.run(_resolve_server_endpoint("192.168.1.3", 51820))
            assert result == "192.168.1.3"
            gai.assert_not_called()

    def test_hostname_resolves_to_first_a_record(self):
        # DSM's own marked lookup (dsm.net.server_lookup), not libc's.
        with (
            patch(
                "dsm.net.server_lookup.system_nameservers", return_value=["192.0.2.53"]
            ),
            patch(
                "dsm.net.server_lookup.lookup_a", return_value="203.0.113.7"
            ) as lookup,
        ):
            result = asyncio.run(_resolve_server_endpoint("home.duckdns.org", 51820))
            assert result == "203.0.113.7"
            lookup.assert_called_once_with("home.duckdns.org", ["192.0.2.53"])

    def test_unresolvable_hostname_raises_oserror(self):
        with (
            patch(
                "dsm.net.server_lookup.system_nameservers", return_value=["192.0.2.53"]
            ),
            patch("dsm.net.server_lookup.lookup_a", side_effect=OSError("no address")),
        ):
            with pytest.raises(OSError):
                asyncio.run(_resolve_server_endpoint("nope.invalid", 51820))
