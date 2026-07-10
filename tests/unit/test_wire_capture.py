"""Tests for lossless capture below dnspython's message parser."""

import socket
from collections.abc import Awaitable
from typing import Any

import dns.asyncbackend
import dns.message
import dns.nameserver
import dns.rdatatype
import pytest

from src.rfc9460_checker.wire_capture import (
    MAX_DNS_TCP_FRAME_LENGTH,
    CapturingBackend,
    DNSWireCapture,
)

PEER = ("192.0.2.53", 53)


def _response_for_query(query_wire: bytes) -> bytes:
    query = dns.message.from_wire(query_wire)
    return dns.message.make_response(query).to_wire()


class FakeDatagramSocket(dns.asyncbackend.DatagramSocket):
    """Minimal datagram socket that answers the request it receives."""

    def __init__(self) -> None:
        """Initialize an empty fake datagram exchange."""
        super().__init__(socket.AF_INET, socket.SOCK_DGRAM)
        self.response = b""
        self.closed = False

    async def sendto(self, what: bytes, destination: Any, timeout: float | None) -> int:
        """Build a matching DNS response for the sent query."""
        assert destination == PEER
        self.response = _response_for_query(what)
        return len(what)

    async def recvfrom(self, size: int, timeout: float | None) -> tuple[bytes, Any]:
        """Return the prepared response and resolver address."""
        assert size >= len(self.response)
        return self.response, PEER

    async def close(self) -> None:
        """Record that the wrapper preserved socket cleanup."""
        self.closed = True

    async def getpeername(self) -> Any:
        """Return the resolver address."""
        return PEER

    async def getsockname(self) -> Any:
        """Return a stable local test address."""
        return ("192.0.2.1", 53000)

    async def getpeercert(self, timeout: float | None) -> None:
        """Return no certificate for plain DNS."""
        return None


class QueuedDatagramSocket(FakeDatagramSocket):
    """Datagram socket returning a caller-provided sequence of peers and payloads."""

    def __init__(self, responses: list[tuple[bytes, Any]]) -> None:
        """Initialize the queued datagrams in their simulated arrival order."""
        super().__init__()
        self.responses = responses

    async def recvfrom(self, size: int, timeout: float | None) -> tuple[bytes, Any]:
        """Return the next queued datagram, including intentionally unexpected peers."""
        return self.responses.pop(0)


class FakeStreamSocket(dns.asyncbackend.StreamSocket):
    """Minimal stream socket with deliberately fragmented DNS framing."""

    def __init__(self) -> None:
        """Initialize an empty fake stream exchange."""
        super().__init__(socket.AF_INET, socket.SOCK_STREAM)
        self.response = bytearray()
        self.closed = False
        self.recv_sizes: list[int] = []

    async def sendall(self, what: bytes, timeout: float | None) -> None:
        """Build a length-prefixed response for the framed query."""
        length = int.from_bytes(what[:2], "big")
        query_wire = what[2:]
        assert length == len(query_wire)
        response = _response_for_query(query_wire)
        self.response.extend(len(response).to_bytes(2, "big") + response)

    async def recv(self, size: int, timeout: float | None) -> bytes:
        """Return small chunks to exercise frame reassembly."""
        self.recv_sizes.append(size)
        # Return one byte on the first call to exercise split length prefixes.
        actual_size = 1 if len(self.recv_sizes) == 1 else min(size, 3)
        result = bytes(self.response[:actual_size])
        del self.response[:actual_size]
        return result

    async def close(self) -> None:
        """Record that the wrapper preserved socket cleanup."""
        self.closed = True

    async def getpeername(self) -> Any:
        """Return the resolver address."""
        return PEER

    async def getsockname(self) -> Any:
        """Return a stable local test address."""
        return ("192.0.2.1", 53000)

    async def getpeercert(self, timeout: float | None) -> None:
        """Return no certificate for plain DNS."""
        return None


class BulkStreamSocket(FakeStreamSocket):
    """Stream socket returning its complete queued chunk in one call."""

    async def recv(self, size: int, timeout: float | None) -> bytes:
        """Ignore the requested size to stress the capture wrapper's own buffering."""
        result = bytes(self.response)
        self.response.clear()
        return result


class FakeBackend(dns.asyncbackend.Backend):
    """Backend delegate used to verify transparent wrapping."""

    def __init__(self, dns_socket: dns.asyncbackend.Socket) -> None:
        """Initialize with the socket returned from make_socket."""
        self.dns_socket = dns_socket
        self.make_socket_args: tuple[Any, ...] | None = None
        self.slept: list[float] = []

    def name(self) -> str:
        """Return a stable backend name."""
        return "fake"

    async def make_socket(
        self,
        af: int,
        socktype: int,
        proto: int = 0,
        source: Any = None,
        destination: Any = None,
        timeout: float | None = None,
        ssl_context: Any = None,
        server_hostname: str | None = None,
    ) -> dns.asyncbackend.Socket:
        """Retain arguments and return the configured fake socket."""
        self.make_socket_args = (
            af,
            socktype,
            proto,
            source,
            destination,
            timeout,
            ssl_context,
            server_hostname,
        )
        return self.dns_socket

    def datagram_connection_required(self) -> bool:
        """Exercise delegation of the connection requirement."""
        return True

    async def sleep(self, interval: float) -> None:
        """Retain requested resolver backoffs without sleeping."""
        self.slept.append(interval)

    def get_transport_class(self) -> type[object]:
        """Return a stable fake transport class."""
        return object

    async def wait_for(self, awaitable: Awaitable[Any], timeout: float | None) -> Any:
        """Await the operation without adding a test timeout."""
        return await awaitable


@pytest.mark.asyncio
async def test_udp_capture_preserves_dnspython_query_behavior() -> None:
    """The returned message and captured datagram contain identical wire bytes."""
    dns_socket = FakeDatagramSocket()
    delegate = FakeBackend(dns_socket)
    backend = CapturingBackend(delegate)
    query = dns.message.make_query("example.com", dns.rdatatype.HTTPS)
    nameserver = dns.nameserver.Do53Nameserver(*PEER)

    response = await nameserver.async_query(
        query,
        timeout=1.0,
        source=None,
        source_port=0,
        max_size=False,
        backend=backend,
    )

    assert response.wire == dns_socket.response
    assert backend.captures == [
        DNSWireCapture("udp", PEER, dns_socket.response, query_wire=query.to_wire()),
    ]
    assert backend.evidence() == [
        {
            "sequence": 0,
            "transport": "udp",
            "peer": ["192.0.2.53", 53],
            "resolver": "192.0.2.53",
            "resolver_port": 53,
            "response_length": len(dns_socket.response),
            "response_wire": dns_socket.response,
            "query_length": len(query.to_wire()),
        }
    ]
    assert dns_socket.closed is True


@pytest.mark.asyncio
async def test_tcp_capture_reassembles_fragmented_length_prefixed_frame() -> None:
    """TCP chunk boundaries do not alter the captured DNS body or exact frame."""
    dns_socket = FakeStreamSocket()
    backend = CapturingBackend(FakeBackend(dns_socket))
    query = dns.message.make_query("example.com", dns.rdatatype.HTTPS)
    nameserver = dns.nameserver.Do53Nameserver(*PEER)

    response = await nameserver.async_query(
        query,
        timeout=1.0,
        source=None,
        source_port=0,
        max_size=True,
        backend=backend,
    )

    assert response.wire is not None
    frame = len(response.wire).to_bytes(2, "big") + response.wire
    assert backend.captures == [
        DNSWireCapture("tcp", PEER, response.wire, frame, query.to_wire()),
    ]
    assert backend.evidence()[0]["tcp_frame_wire"] == frame
    assert backend.evidence()[0]["tcp_frame_length"] == len(frame)
    assert dns_socket.recv_sizes[0] == 2
    assert dns_socket.closed is True


@pytest.mark.asyncio
async def test_stream_wrapper_captures_multiple_frames_and_keeps_partial_tail() -> None:
    """Every complete frame is emitted once; an incomplete frame is not fabricated."""
    first = b"one"
    second = b"two!"
    partial = b"partial"
    stream = FakeStreamSocket()
    stream.response = bytearray(
        len(first).to_bytes(2, "big")
        + first
        + len(second).to_bytes(2, "big")
        + second
        + (len(partial) + 1).to_bytes(2, "big")
        + partial
    )
    backend = CapturingBackend(FakeBackend(stream))
    wrapped = await backend.make_socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
        destination=PEER,
    )

    while stream.response:
        await wrapped.recv(65535, 1.0)  # type: ignore[attr-defined]

    assert [capture.response_wire for capture in backend.captures] == [first, second]


@pytest.mark.asyncio
async def test_malformed_datagram_survives_a_later_parser_failure() -> None:
    """Capture happens before dnspython can reject a malformed DNS message."""
    malformed = b"too short"
    dns_socket = FakeDatagramSocket()
    dns_socket.response = malformed
    backend = CapturingBackend(FakeBackend(dns_socket))
    wrapped = await backend.make_socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
        destination=PEER,
    )

    wire, _ = await wrapped.recvfrom(65535, 1.0)  # type: ignore[attr-defined]
    with pytest.raises(dns.message.ShortHeader):
        dns.message.from_wire(wire)

    assert backend.captures[0].response_wire == malformed


@pytest.mark.asyncio
async def test_udp_capture_filters_unexpected_peers_before_retention() -> None:
    """Datagrams from another source remain delegated but never consume capture slots."""
    unexpected_peer = ("198.51.100.53", 53)
    dns_socket = QueuedDatagramSocket(
        [
            (b"unexpected", unexpected_peer),
            (b"expected", PEER),
        ]
    )
    backend = CapturingBackend(FakeBackend(dns_socket))
    wrapped = await backend.make_socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
        destination=PEER,
    )

    unexpected = await wrapped.recvfrom(65535, 1.0)  # type: ignore[attr-defined]
    assert unexpected == (b"unexpected", unexpected_peer)
    assert await wrapped.recvfrom(65535, 1.0) == (b"expected", PEER)  # type: ignore[attr-defined]

    assert [capture.response_wire for capture in backend.captures] == [b"expected"]
    assert backend.capture_metadata()["filtered_datagram_count"] == 1


@pytest.mark.asyncio
async def test_udp_capture_ring_retains_the_latest_response() -> None:
    """Same-peer wrong-ID traffic cannot grow storage or evict the final response."""
    payloads = [b"wrong-id-1", b"wrong-id-2", b"wrong-id-3", b"accepted"]
    dns_socket = QueuedDatagramSocket([(payload, PEER) for payload in payloads])
    backend = CapturingBackend(FakeBackend(dns_socket), max_captures=2)
    wrapped = await backend.make_socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
        destination=PEER,
    )

    for _ in payloads:
        await wrapped.recvfrom(65535, 1.0)  # type: ignore[attr-defined]

    assert [capture.response_wire for capture in backend.captures] == [
        b"wrong-id-3",
        b"accepted",
    ]
    assert backend.capture_metadata() == {
        "retained_capture_count": 2,
        "max_capture_count": 2,
        "dropped_capture_count": 2,
        "filtered_datagram_count": 0,
        "oversized_datagram_count": 0,
        "discarded_stream_buffer_count": 0,
    }


@pytest.mark.asyncio
async def test_oversized_udp_datagram_is_not_copied_into_capture_storage() -> None:
    """A backend violating recvfrom's 65535-byte contract cannot defeat the bound."""
    dns_socket = QueuedDatagramSocket([(b"x" * 65536, PEER)])
    backend = CapturingBackend(FakeBackend(dns_socket))
    wrapped = await backend.make_socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
        destination=PEER,
    )

    wire, _ = await wrapped.recvfrom(65535, 1.0)  # type: ignore[attr-defined]

    assert len(wire) == 65536
    assert backend.captures == []
    assert backend.capture_metadata()["oversized_datagram_count"] == 1
    assert backend.capture_metadata()["dropped_capture_count"] == 1


@pytest.mark.asyncio
async def test_tcp_partial_frame_buffer_is_bounded_by_the_protocol_length() -> None:
    """Even an oversized delegate chunk leaves at most one incomplete DNS frame buffered."""
    stream = BulkStreamSocket()
    stream.response = bytearray(b"\xff\xff" + b"x" * (MAX_DNS_TCP_FRAME_LENGTH - 3))
    backend = CapturingBackend(FakeBackend(stream))
    wrapped = await backend.make_socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
        destination=PEER,
    )

    await wrapped.recv(65535, 1.0)  # type: ignore[attr-defined]

    assert backend.captures == []
    assert len(wrapped._received) == MAX_DNS_TCP_FRAME_LENGTH - 1  # type: ignore[attr-defined]
    stream.response = bytearray(b"x")
    await wrapped.recv(65535, 1.0)  # type: ignore[attr-defined]
    assert len(backend.captures[0].response_wire) == 65535
    assert len(wrapped._received) == 0  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_backend_and_socket_operations_are_delegated() -> None:
    """Wrapping does not alter backend identity, waits, socket metadata, or cleanup."""
    dns_socket = FakeDatagramSocket()
    delegate = FakeBackend(dns_socket)
    backend = CapturingBackend(delegate)

    assert backend.name() == "fake"
    assert backend.datagram_connection_required() is True
    assert backend.get_transport_class() is object
    await backend.sleep(0.25)
    assert delegate.slept == [0.25]

    async def value() -> str:
        return "complete"

    assert await backend.wait_for(value(), 1.0) == "complete"
    wrapped = await backend.make_socket(
        socket.AF_INET,
        socket.SOCK_DGRAM,
        17,
        ("0.0.0.0", 0),
        PEER,
        1.0,
    )
    assert delegate.make_socket_args == (
        socket.AF_INET,
        socket.SOCK_DGRAM,
        17,
        ("0.0.0.0", 0),
        PEER,
        1.0,
        None,
        None,
    )
    assert await wrapped.getpeername() == PEER
    assert await wrapped.getsockname() == ("192.0.2.1", 53000)
    assert await wrapped.getpeercert(1.0) is None
    async with wrapped:
        pass
    assert dns_socket.closed is True


def test_capture_evidence_handles_ipv6_and_clear() -> None:
    """IPv6 sockaddr details remain intact and captures can be reused explicitly."""
    backend = CapturingBackend(FakeBackend(FakeDatagramSocket()))
    backend.captures.append(
        DNSWireCapture(
            transport="udp",
            peer=("2001:db8::53", 5353, 7, 9),
            response_wire=b"dns",
        )
    )

    assert backend.evidence()[0]["peer"] == ["2001:db8::53", 5353, 7, 9]
    assert backend.evidence()[0]["resolver"] == "2001:db8::53"
    assert backend.evidence()[0]["resolver_port"] == 5353
    backend.clear()
    assert backend.captures == []


def test_default_backend_selection_is_lazy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Synchronous checker construction does not require an active event loop."""

    def fail_if_called() -> dns.asyncbackend.Backend:
        raise AssertionError("default backend was selected eagerly")

    monkeypatch.setattr(dns.asyncbackend, "get_default_backend", fail_if_called)

    backend = CapturingBackend()

    assert backend.backend is None
    assert backend.captures == []
