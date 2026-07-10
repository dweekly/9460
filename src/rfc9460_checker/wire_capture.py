"""Lossless DNS response capture for dnspython's asynchronous resolver.

dnspython normally parses a response before returning it to the resolver.  A
malformed SVCB or HTTPS RDATA value can therefore be rejected before callers
can inspect the bytes that caused the failure.  ``CapturingBackend`` wraps an
existing async backend at the socket boundary, where UDP datagrams and DNS over
TCP frames are still opaque bytes.

The wrapper delegates all I/O unchanged.  Create one instance per resolution
when captures must be associated with a single query; a shared instance keeps a
single arrival-ordered capture list across all of its sockets.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Any, Callable, Literal, Protocol, cast  # noqa: TYP001

import dns.asyncbackend
import dns.exception
import dns.inet
from dns.asyncbackend import (  # type: ignore[attr-defined]
    Backend,
    DatagramSocket,
    Socket,
    StreamSocket,
)

Transport = Literal["udp", "tcp"]
MAX_DNS_MESSAGE_LENGTH = 65535
MAX_DNS_TCP_FRAME_LENGTH = MAX_DNS_MESSAGE_LENGTH + 2
DEFAULT_MAX_CAPTURES = 32


class _SocketDelegate(Protocol):
    family: int
    type: int

    async def close(self) -> None: ...

    async def getpeername(self) -> Any: ...

    async def getsockname(self) -> Any: ...

    async def getpeercert(self, timeout: float | None) -> Any: ...


class _DatagramSocketDelegate(_SocketDelegate, Protocol):
    async def sendto(self, what: bytes, destination: Any, timeout: float | None) -> Any: ...

    async def recvfrom(self, size: int, timeout: float | None) -> Any: ...


class _StreamSocketDelegate(_SocketDelegate, Protocol):
    async def sendall(self, what: bytes, timeout: float | None) -> Any: ...

    async def recv(self, size: int, timeout: float | None) -> bytes: ...


class _BackendDelegate(Protocol):
    def name(self) -> str: ...

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
    ) -> Socket: ...

    def datagram_connection_required(self) -> bool: ...

    async def sleep(self, interval: float) -> None: ...

    def get_transport_class(self) -> Any: ...

    async def wait_for(self, awaitable: Any, timeout: float | None) -> Any: ...


def _peer_evidence(peer: Any) -> tuple[Any, str | None, int | None]:
    """Return a JSON-safe peer plus conventional resolver host and port."""
    if isinstance(peer, tuple):
        peer_value: Any = list(peer)
        resolver = peer[0] if peer and isinstance(peer[0], str) else None
        resolver_port = (
            peer[1]
            if len(peer) > 1 and isinstance(peer[1], int) and not isinstance(peer[1], bool)
            else None
        )
        return peer_value, resolver, resolver_port
    if isinstance(peer, list):
        resolver = peer[0] if peer and isinstance(peer[0], str) else None
        resolver_port = (
            peer[1]
            if len(peer) > 1 and isinstance(peer[1], int) and not isinstance(peer[1], bool)
            else None
        )
        return list(peer), resolver, resolver_port
    if peer is None or isinstance(peer, str | int | float | bool):
        return peer, peer if isinstance(peer, str) else None, None
    return str(peer), None, None


def _peer_matches(family: int, peer: Any, destination: Any) -> bool:
    """Match a received datagram peer using dnspython-compatible sockaddr rules."""
    if destination is None:
        return True
    if not isinstance(peer, (tuple, list)) or not isinstance(destination, (tuple, list)):
        return bool(peer == destination)
    if len(peer) < 2 or len(destination) < 2:
        return False
    try:
        peer_address = dns.inet.inet_pton(family, peer[0])
        destination_address = dns.inet.inet_pton(family, destination[0])
    except NotImplementedError:
        return bool(peer == destination)
    except dns.exception.SyntaxError, TypeError, ValueError:
        return False
    trailing_matches = tuple(peer[1:]) == tuple(destination[1:])
    if peer_address == destination_address and trailing_matches:
        return True
    try:
        return bool(dns.inet.is_multicast(destination[0]) and trailing_matches)
    except dns.exception.SyntaxError, TypeError, ValueError:
        return False


@dataclass(frozen=True, slots=True)
class DNSWireCapture:
    """One complete response received from a DNS resolver."""

    transport: Transport
    peer: Any
    response_wire: bytes
    tcp_frame_wire: bytes | None = None
    query_wire: bytes | None = None

    def evidence(self, *, sequence: int | None = None) -> dict[str, Any]:
        """Return attachable evidence while retaining byte values losslessly."""
        peer, resolver, resolver_port = _peer_evidence(self.peer)
        result: dict[str, Any] = {
            "transport": self.transport,
            "peer": peer,
            "resolver": resolver,
            "resolver_port": resolver_port,
            "response_length": len(self.response_wire),
            "response_wire": self.response_wire,
        }
        if sequence is not None:
            result["sequence"] = sequence
        if self.tcp_frame_wire is not None:
            result["tcp_frame_length"] = len(self.tcp_frame_wire)
            result["tcp_frame_wire"] = self.tcp_frame_wire
        if self.query_wire is not None:
            result["query_length"] = len(self.query_wire)
        return result


class _SocketMixin:
    """Delegate socket metadata and lifetime operations unchanged."""

    _socket: _SocketDelegate

    async def close(self) -> None:
        await self._socket.close()

    async def getpeername(self) -> Any:
        return await self._socket.getpeername()

    async def getsockname(self) -> Any:
        return await self._socket.getsockname()

    async def getpeercert(self, timeout: float | None) -> Any:
        return await self._socket.getpeercert(timeout)


class _CapturingDatagramSocket(_SocketMixin, DatagramSocket):
    def __init__(
        self,
        wrapped: DatagramSocket,
        destination: Any,
        retain_capture: Callable[[DNSWireCapture], None],
        note_filtered: Callable[[], None],
        note_oversized: Callable[[], None],
    ) -> None:
        super().__init__(wrapped.family, wrapped.type)
        self._socket = cast(_SocketDelegate, wrapped)
        self._datagram_socket = cast(_DatagramSocketDelegate, wrapped)
        self._destination = destination
        self._retain_capture = retain_capture
        self._note_filtered = note_filtered
        self._note_oversized = note_oversized
        self._query_wire: bytes | None = None

    async def sendto(self, what: bytes, destination: Any, timeout: float | None) -> Any:
        if destination is not None:
            self._destination = destination
        self._query_wire = bytes(what) if len(what) <= MAX_DNS_MESSAGE_LENGTH else None
        return await self._datagram_socket.sendto(what, destination, timeout)

    async def recvfrom(self, size: int, timeout: float | None) -> Any:
        result = await self._datagram_socket.recvfrom(size, timeout)
        wire, peer = result
        if not _peer_matches(self.family, peer, self._destination):
            self._note_filtered()
            return result
        if len(wire) > MAX_DNS_MESSAGE_LENGTH:
            self._note_oversized()
            return result
        self._retain_capture(
            DNSWireCapture(
                transport="udp",
                peer=peer,
                response_wire=bytes(wire),
                query_wire=self._query_wire,
            )
        )
        return result


class _CapturingStreamSocket(_SocketMixin, StreamSocket):
    def __init__(
        self,
        wrapped: StreamSocket,
        retain_capture: Callable[[DNSWireCapture], None],
        note_stream_discard: Callable[[], None],
        peer: Any,
    ) -> None:
        super().__init__(wrapped.family, wrapped.type)
        self._socket = cast(_SocketDelegate, wrapped)
        self._stream_socket = cast(_StreamSocketDelegate, wrapped)
        self._retain_capture = retain_capture
        self._note_stream_discard = note_stream_discard
        self._peer = peer
        self._received = bytearray()
        self._query_wire: bytes | None = None

    async def sendall(self, what: bytes, timeout: float | None) -> Any:
        if len(what) >= 2 and int.from_bytes(what[:2], "big") == len(what) - 2:
            query_wire = what[2:]
            self._query_wire = (
                bytes(query_wire) if len(query_wire) <= MAX_DNS_MESSAGE_LENGTH else None
            )
        return await self._stream_socket.sendall(what, timeout)

    async def recv(self, size: int, timeout: float | None) -> bytes:
        data = await self._stream_socket.recv(size, timeout)
        if data:
            self._feed_received(data)
        return data

    def _feed_received(self, data: bytes) -> None:
        """Consume chunks without letting the frame assembly buffer grow unbounded."""
        cursor = 0
        while cursor < len(data):
            available = MAX_DNS_TCP_FRAME_LENGTH - len(self._received)
            if available <= 0:
                # A two-octet DNS length can never require a larger buffer.  If
                # this invariant is violated, discard capture state but leave
                # the delegated stream and returned bytes untouched.
                self._received.clear()
                self._note_stream_discard()
                available = MAX_DNS_TCP_FRAME_LENGTH
            end = min(cursor + available, len(data))
            self._received.extend(data[cursor:end])
            cursor = end
            self._capture_complete_frames()

    def _capture_complete_frames(self) -> None:
        while len(self._received) >= 2:
            message_length = struct.unpack_from("!H", self._received)[0]
            frame_length = message_length + 2
            if len(self._received) < frame_length:
                return
            frame = bytes(self._received[:frame_length])
            del self._received[:frame_length]
            self._retain_capture(
                DNSWireCapture(
                    transport="tcp",
                    peer=self._peer,
                    response_wire=frame[2:],
                    tcp_frame_wire=frame,
                    query_wire=self._query_wire,
                )
            )


class CapturingBackend(Backend):
    """Wrap a dnspython backend and retain exact received DNS messages."""

    def __init__(
        self,
        backend: Backend | None = None,
        *,
        max_captures: int = DEFAULT_MAX_CAPTURES,
    ) -> None:
        """Initialize with an explicit delegate or lazily use the active default."""
        if max_captures <= 0:
            raise ValueError("max_captures must be positive")
        self.backend = backend
        self.max_captures = max_captures
        self.captures: list[DNSWireCapture] = []
        self.dropped_capture_count = 0
        self.filtered_datagram_count = 0
        self.oversized_datagram_count = 0
        self.discarded_stream_buffer_count = 0

    def _retain_capture(self, capture: DNSWireCapture) -> None:
        """Retain the newest bounded capture window in arrival order."""
        while len(self.captures) >= self.max_captures:
            self.captures.pop(0)
            self.dropped_capture_count += 1
        self.captures.append(capture)

    def _note_filtered_datagram(self) -> None:
        self.filtered_datagram_count += 1

    def _note_oversized_datagram(self) -> None:
        self.oversized_datagram_count += 1
        self.dropped_capture_count += 1

    def _note_stream_discard(self) -> None:
        self.discarded_stream_buffer_count += 1
        self.dropped_capture_count += 1

    def _delegate(self) -> _BackendDelegate:
        if self.backend is None:
            # Backend sniffing requires an active async-library context.  Delay
            # it so checkers can be constructed by ordinary synchronous code.
            self.backend = dns.asyncbackend.get_default_backend()
        return cast(_BackendDelegate, self.backend)

    def name(self) -> str:
        """Return the delegate's name so backend selection remains transparent."""
        return self._delegate().name()

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
    ) -> Socket:
        """Create and wrap a delegate socket of the requested kind."""
        wrapped = await self._delegate().make_socket(
            af,
            socktype,
            proto,
            source,
            destination,
            timeout,
            ssl_context,
            server_hostname,
        )
        if socktype == socket.SOCK_DGRAM:
            return _CapturingDatagramSocket(
                cast(DatagramSocket, wrapped),
                destination,
                self._retain_capture,
                self._note_filtered_datagram,
                self._note_oversized_datagram,
            )
        if socktype == socket.SOCK_STREAM:
            return _CapturingStreamSocket(
                cast(StreamSocket, wrapped),
                self._retain_capture,
                self._note_stream_discard,
                destination,
            )
        return wrapped

    def datagram_connection_required(self) -> bool:
        """Preserve the delegate's datagram connection requirements."""
        return bool(self._delegate().datagram_connection_required())

    async def sleep(self, interval: float) -> None:
        """Delegate resolver backoff sleeps."""
        await self._delegate().sleep(interval)

    def get_transport_class(self) -> Any:
        """Return the delegate's transport class."""
        return self._delegate().get_transport_class()

    async def wait_for(self, awaitable: Any, timeout: float | None) -> Any:
        """Delegate timeout handling without changing its semantics."""
        return await self._delegate().wait_for(awaitable, timeout)

    def clear(self) -> None:
        """Discard captures retained by this wrapper."""
        self.captures.clear()
        self.dropped_capture_count = 0
        self.filtered_datagram_count = 0
        self.oversized_datagram_count = 0
        self.discarded_stream_buffer_count = 0

    def capture_metadata(self) -> dict[str, int]:
        """Return bounded-retention and early-filter counters."""
        return {
            "retained_capture_count": len(self.captures),
            "max_capture_count": self.max_captures,
            "dropped_capture_count": self.dropped_capture_count,
            "filtered_datagram_count": self.filtered_datagram_count,
            "oversized_datagram_count": self.oversized_datagram_count,
            "discarded_stream_buffer_count": self.discarded_stream_buffer_count,
        }

    def evidence(self) -> list[dict[str, Any]]:
        """Return captures in arrival order as attachable observation fields."""
        return [capture.evidence(sequence=index) for index, capture in enumerate(self.captures)]
