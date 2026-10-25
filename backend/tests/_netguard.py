"""Test-only network guard: any socket connection to a non-loopback address raises.

Used by the plugin tests so that new code that tried to reach the internet (telemetry, cloud
APIs, a mis-configured URL) fails loudly instead of silently working on a connected machine.
"""

from __future__ import annotations

import ipaddress
import socket

import pytest


class NonLoopbackConnection(AssertionError):
    pass


def _is_loopback(address) -> bool:
    if not isinstance(address, tuple):  # AF_UNIX path etc.
        return True
    host = address[0]
    if host in ("localhost",):
        return True
    try:
        return ipaddress.ip_address(host.split("%")[0]).is_loopback
    except ValueError:
        return False  # an unresolved hostname: refuse rather than resolve it


@pytest.fixture(autouse=True)
def block_non_loopback(monkeypatch):
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex

    def connect(self, address):
        if not _is_loopback(address):
            raise NonLoopbackConnection(f"non-loopback connection attempted: {address!r}")
        return real_connect(self, address)

    def connect_ex(self, address):
        if not _is_loopback(address):
            raise NonLoopbackConnection(f"non-loopback connection attempted: {address!r}")
        return real_connect_ex(self, address)

    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    yield
