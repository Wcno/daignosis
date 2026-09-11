from __future__ import annotations

import time

from sentinel_dns.models import DnsEvent

BEACON_DOMAIN = "xjs83kavqpwm.xyz"
BEACON_HOSTS = [
    "190.14.213.60",
    "190.14.212.86",
    "190.14.204.18",
    "190.14.206.133",
    "190.14.197.98",
]
TYPO_DOMAIN = "micros0ft.com"


class Scenario:
    def __init__(self, beacon_at: float = 45.0, degrade_at: float = 90.0) -> None:
        self.t0 = time.monotonic()
        self.beacon_at = beacon_at
        self.degrade_at = degrade_at
        self._last_beacon = 0.0
        self._typo_done = False
        self._burst_done = False

    def elapsed(self) -> float:
        return time.monotonic() - self.t0

    def beacon_on(self) -> bool:
        return self.elapsed() >= self.beacon_at

    def degrade_on(self) -> bool:
        return self.elapsed() >= self.degrade_at

    def due_events(self, now_wall: float) -> list[DnsEvent]:
        out: list[DnsEvent] = []
        elapsed = self.elapsed()
        if self.beacon_on() and not self._burst_done:
            self._burst_done = True
            self._last_beacon = elapsed
            for ip in BEACON_HOSTS:
                for k in range(6):
                    out.append(
                        DnsEvent(
                            ts=now_wall - (5 - k) * 6.0,
                            ts_raw="injected",
                            client_ip=ip,
                            port=53000 + k,
                            qname=BEACON_DOMAIN,
                            qtype="A",
                            flags="+",
                            server="172.19.1.2",
                            injected=True,
                            rcode="NOERROR",
                            latency_ms=41.0,
                        )
                    )
        elif self.beacon_on() and elapsed - self._last_beacon >= 6.0:
            self._last_beacon = elapsed
            for ip in BEACON_HOSTS:
                out.append(
                    DnsEvent(
                        ts=now_wall,
                        ts_raw="injected",
                        client_ip=ip,
                        port=53000,
                        qname=BEACON_DOMAIN,
                        qtype="A",
                        flags="+",
                        server="172.19.1.2",
                        injected=True,
                        rcode="NOERROR",
                        latency_ms=41.0,
                    )
                )
        if self.beacon_on() and not self._typo_done and elapsed >= self.beacon_at + 8:
            self._typo_done = True
            out.append(
                DnsEvent(
                    ts=now_wall,
                    ts_raw="injected",
                    client_ip=BEACON_HOSTS[0],
                    port=53001,
                    qname=TYPO_DOMAIN,
                    qtype="A",
                    flags="+",
                    server="172.19.1.2",
                    injected=True,
                    rcode="NXDOMAIN",
                    latency_ms=33.0,
                )
            )
        return out
