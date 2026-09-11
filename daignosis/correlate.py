from __future__ import annotations

import re
import time
from collections import deque
from dataclasses import dataclass
from typing import Any

from daignosis.models import Incident

CORRELATION_WINDOW_S = 120.0
MIN_HOSTS = 2
MIN_EVENTS = 3
COOLDOWN_S = 300.0

_INTERVAL_RE = re.compile(r"~([0-9.]+)\s*s")


@dataclass
class Campaign:
    ts: float
    domain: str
    site: str
    customer: str
    hosts: list[str]
    kinds: list[str]
    n_events: int
    repeated_seconds: float | None = None
    concluded: bool = False

    @property
    def n_hosts(self) -> int:
        return len(self.hosts)

    def brief(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "site": self.site,
            "customer": self.customer,
            "affected_hosts": self.hosts[:32],
            "signal_types": self.kinds,
            "events_observed": self.n_events,
            "hosts_affected": self.n_hosts,
            "repeat_interval_seconds": self.repeated_seconds,
            "window_seconds": CORRELATION_WINDOW_S,
        }


def template_campaign(c: Campaign) -> tuple[str, str]:
    site = f"{c.site} ({c.customer})" if c.customer else c.site
    if c.n_hosts >= 2 and c.repeated_seconds:
        verdict = (
            f"Likely coordinated campaign, not isolated events: {c.n_hosts} internal hosts queried "
            f"{c.domain} at a steady ~{c.repeated_seconds:.0f}s cadence ({c.n_events} events in a "
            f"{CORRELATION_WINDOW_S:.0f}s window). Site: {site}. Pattern is consistent with a shared "
            f"infection, not independent endpoint behavior."
        )
        rec = (
            f"Isolate all {c.n_hosts} affected hosts, sinkhole {c.domain} at DNS, "
            f"and sweep for C2 artifacts on the whole site."
        )
    elif c.n_hosts >= 2:
        verdict = (
            f"{c.n_hosts} internal hosts produced {c.n_events} suspicious events against "
            f"{c.domain} inside one window. Site: {site}. Correlation across endpoints indicates "
            f"a common origin rather than isolated false positives."
        )
        rec = "Hunt the affected hosts as one group; correlated scope nips lateral movement early."
    else:
        verdict = (
            f"Activity limited to a single host ({c.domain}, {site}); correlation does not "
            f"indicate a campaign across endpoints."
        )
        rec = "Investigate the single endpoint and keep watching for propagation."
    return verdict, rec


class Correlator:
    def __init__(
        self,
        window_s: float = CORRELATION_WINDOW_S,
        min_hosts: int = MIN_HOSTS,
        min_events: int = MIN_EVENTS,
        cooldown_s: float = COOLDOWN_S,
    ) -> None:
        self.window_s = window_s
        self.min_hosts = min_hosts
        self.min_events = min_events
        self.cooldown_s = cooldown_s
        self._events: deque[Incident] = deque()
        self._cooldown: dict[str, float] = {}
        self.campaigns: list[Campaign] = []

    def add(self, inc: Incident) -> None:
        self._events.append(inc)

    def _trim(self, now: float) -> None:
        while self._events and now - self._events[0].ts > self.window_s:
            self._events.popleft()

    @staticmethod
    def _repeat_period(incs: list[Incident]) -> float | None:
        for inc in incs:
            for s in inc.signals:
                m = _INTERVAL_RE.search(s)
                if m:
                    try:
                        return float(m.group(1))
                    except ValueError:
                        pass
        return None

    def poll(self, now: float | None = None) -> list[Campaign]:
        now = now or time.time()
        self._trim(now)
        groups: dict[tuple[str, str], list[Incident]] = {}
        for inc in self._events:
            key = (inc.domain, inc.site)
            groups.setdefault(key, []).append(inc)

        out: list[Campaign] = []
        for (domain, site), incs in groups.items():
            key = f"{domain}|{site}"
            last = self._cooldown.get(key, -1e9)
            if now - last < self.cooldown_s:
                continue
            hosts = sorted({h for inc in incs for h in inc.affected_hosts})
            if len(incs) < self.min_events or len(hosts) < self.min_hosts:
                continue
            campaign = Campaign(
                ts=now,
                domain=domain,
                site=site,
                customer=incs[0].customer,
                hosts=hosts,
                kinds=sorted({inc.kind for inc in incs}),
                n_events=len(incs),
                repeated_seconds=self._repeat_period(incs),
            )
            self._cooldown[key] = now
            self.campaigns.append(campaign)
            out.append(campaign)
        return out