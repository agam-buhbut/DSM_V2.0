import asyncio
import socket
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
        fake = [(socket.AF_INET, socket.SOCK_DGRAM, 0, "", ("203.0.113.7", 51820))]
        with patch("socket.getaddrinfo", return_value=fake) as gai:
            result = asyncio.run(_resolve_server_endpoint("home.duckdns.org", 51820))
            assert result == "203.0.113.7"
            gai.assert_called_once()

    def test_unresolvable_hostname_raises_oserror(self):
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("nxdomain")):
            with pytest.raises(OSError):
                asyncio.run(_resolve_server_endpoint("nope.invalid", 51820))
