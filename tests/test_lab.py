import socket

import pytest

from gatekeep.lab import syslog_inject as si


def test_assert_lab_target():
    assert si.assert_lab_target("127.0.0.1") == "127.0.0.1"
    with pytest.raises(si.ScopeError):
        si.assert_lab_target("8.8.8.8")


@pytest.mark.parametrize("vector", si.SUPPORTED)
def test_build_line(vector):
    line = si.build_line(vector, "PAYLOADXYZ")
    assert line.startswith("<") and "PAYLOADXYZ" in line


def test_build_line_unsupported():
    with pytest.raises(ValueError):
        si.build_line("file.name", "x")


def test_build_payload_marker_and_vectors():
    assert si.build_payload("ssh.username", "SGABC", payload="a b") == "SGABC_a_b"
    assert si.build_payload("dns.qname", "SGABC").endswith(".lab.example")


def test_send_refuses_public_without_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network used")

    monkeypatch.setattr(socket, "create_connection", boom)
    monkeypatch.setattr(socket.socket, "sendto", boom)
    with pytest.raises(si.ScopeError):
        si.send("8.8.8.8", 514, ["x"])
