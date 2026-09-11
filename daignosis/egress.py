from __future__ import annotations

import socket
import threading

ALLOWED = frozenset({"127.0.0.1", "::1", "localhost"})


class EgressGuard:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.cloud_ai_calls = 0
        self.egress_bytes = 0
        self.blocked = 0
        self.dns_events = 0
        self.last_blocked: str | None = None
        self.active = False
        self._orig_connect = None
        self._orig_create = None
        self._feeds: set[str] = set()

    def allow(self, host: str) -> None:
        with self.lock:
            if host:
                self._feeds.add(str(host))

    def _is_allowed(self, host: str) -> bool:
        return host in ALLOWED or host in self._feeds

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "inference_mode": "LOCAL",
                "cloud_ai_calls": self.cloud_ai_calls,
                "dns_events_processed": self.dns_events,
                "external_data_transmitted_bytes": self.egress_bytes,
                "blocked_attempts": self.blocked,
                "last_blocked": self.last_blocked,
                "airgap": self.active,
            }

    def bump_events(self, n: int = 1) -> None:
        with self.lock:
            self.dns_events += n

    def note_blocked(self, host: str, nbytes: int = 0) -> None:
        with self.lock:
            self.blocked += 1
            self.egress_bytes += nbytes
            self.last_blocked = host

    def install(self) -> None:
        if self.active:
            return
        guard = self
        self._orig_connect = socket.socket.connect
        self._orig_create = socket.create_connection

        def connect(sock, address):
            host = address[0] if isinstance(address, tuple) else address
            if not guard._is_allowed(str(host)):
                guard.note_blocked(str(host))
                raise PermissionError(f"egress blocked: {host}")
            return guard._orig_connect(sock, address)

        def create_connection(address, *args, **kwargs):
            host = address[0]
            if not guard._is_allowed(str(host)):
                guard.note_blocked(str(host))
                raise PermissionError(f"egress blocked: {host}")
            return guard._orig_create(address, *args, **kwargs)

        socket.socket.connect = connect  # type: ignore[method-assign]
        socket.create_connection = create_connection  # type: ignore[assignment]
        self.active = True

    def restore(self) -> None:
        if not self.active:
            return
        if self._orig_connect is not None:
            socket.socket.connect = self._orig_connect  # type: ignore[method-assign]
        if self._orig_create is not None:
            socket.create_connection = self._orig_create  # type: ignore[assignment]
        self.active = False


GUARD = EgressGuard()
