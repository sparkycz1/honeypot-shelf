"""`app.services.syslog_transport.send_syslog_sync` — the shared low-level
transport `app.audit_syslog`/`app.services.honeypot_event_syslog` both
send through. Mocks the socket/TLS layer entirely — no real network I/O
in the test environment."""

from __future__ import annotations

import socket
import ssl

from app.services.syslog_transport import SyslogProtocol, send_syslog_sync


class _FakeSocket:
    def __init__(self) -> None:
        self.sent: bytes = b""

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def __enter__(self) -> _FakeSocket:
        return self

    def __exit__(self, *exc_info: object) -> None:
        pass


class _FakeSSLContext:
    def __init__(self) -> None:
        self.minimum_version: ssl.TLSVersion | None = None
        self.wrapped_socket = _FakeSocket()

    def wrap_socket(self, sock: object, *, server_hostname: str) -> _FakeSocket:
        return self.wrapped_socket


def test_tls_send_sets_an_explicit_minimum_tls_version(monkeypatch):
    """Regression test: `ssl.create_default_context()` alone only
    *implicitly* excludes old protocol versions (whatever the local
    OpenSSL build happens to default to) — this asserts the code sets
    `minimum_version` explicitly rather than relying on that default,
    same FIPS-aligned "no weak protocol versions" stance the SSH layer
    already takes explicitly."""
    plain_socket = _FakeSocket()
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: plain_socket)

    fake_context = _FakeSSLContext()
    monkeypatch.setattr(ssl, "create_default_context", lambda: fake_context)

    send_syslog_sync("siem.example.com", 6514, SyslogProtocol.TLS, "hello")

    assert fake_context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert fake_context.wrapped_socket.sent == b"hello\n"


def test_tcp_send_uses_newline_terminated_framing_not_octet_counting(monkeypatch):
    """Regression test: this used to prefix the message with its byte
    length (RFC 6587 octet-counting) instead of terminating it with `\\n`
    (RFC 6587 non-transparent framing) — valid per the RFC, but a real
    Wazuh deployment (and every other syslog source feeding the same
    target) expected the newline-terminated form instead, so the
    octet-counted version was silently dropped: the TCP handshake
    completed fine, but the message itself never arrived."""
    plain_socket = _FakeSocket()
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: plain_socket)

    send_syslog_sync("siem.example.com", 514, SyslogProtocol.TCP, "hello")

    assert plain_socket.sent == b"hello\n"


def test_udp_send_does_not_touch_ssl_at_all(monkeypatch):
    sent: list[tuple[bytes, tuple[str, int]]] = []

    class _FakeUdpSocket:
        def settimeout(self, timeout: float) -> None:
            pass

        def sendto(self, data: bytes, addr: tuple[str, int]) -> None:
            sent.append((data, addr))

        def __enter__(self) -> _FakeUdpSocket:
            return self

        def __exit__(self, *exc_info: object) -> None:
            pass

    monkeypatch.setattr(socket, "socket", lambda *a, **k: _FakeUdpSocket())

    def _fail_if_called(*args: object, **kwargs: object) -> None:
        raise AssertionError("UDP must never touch ssl.create_default_context")

    monkeypatch.setattr(ssl, "create_default_context", _fail_if_called)

    send_syslog_sync("siem.example.com", 514, SyslogProtocol.UDP, "hi")

    assert sent == [(b"hi", ("siem.example.com", 514))]
