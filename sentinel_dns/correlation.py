from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from sentinel_dns.models import DnsEvent, Finding, Incident
from sentinel_dns.risk import aggregate


@dataclass
class _CampaignWindow:
    opened_at: float
    customer: str
    site: str
    domain: str
    hosts: set[str] = field(default_factory=set)
    findings: dict[str, Finding] = field(default_factory=dict)
    emitted: bool = False


class CampaignCorrelator:
    """Builds one Security Incident from related detector Findings."""

    def __init__(
        self,
        window_seconds: float = 60.0,
        min_hosts: int = 3,
        min_finding_types: int = 2,
    ) -> None:
        self.window_seconds = window_seconds
        self.min_hosts = min_hosts
        self.min_finding_types = min_finding_types
        self._windows: dict[tuple[str, str], _CampaignWindow] = {}
        self._nxdomain: dict[str, deque[float]] = {}

    def observe(self, event: DnsEvent) -> None:
        if not event.site or event.rcode != "NXDOMAIN":
            return
        queries = self._nxdomain.setdefault(event.site, deque())
        queries.append(event.ts)
        cutoff = event.ts - self.window_seconds
        while queries and queries[0] < cutoff:
            queries.popleft()

    def feed(self, event: DnsEvent, findings: list[Finding]) -> Incident | None:
        self.observe(event)
        if not findings or not event.site or not event.etld1:
            return None
        key = (event.site, event.etld1)
        window = self._windows.get(key)
        if window is None or event.ts - window.opened_at > self.window_seconds:
            window = _CampaignWindow(
                opened_at=event.ts,
                customer=event.customer,
                site=event.site,
                domain=event.etld1,
            )
            self._windows[key] = window
        window.hosts.add(event.client_ip)
        for finding in findings:
            previous = window.findings.get(finding.kind)
            if previous is None or finding.score > previous.score:
                window.findings[finding.kind] = finding
        if window.emitted:
            return None
        if len(window.hosts) < self.min_hosts or len(window.findings) < self.min_finding_types:
            return None
        incident = aggregate(
            event.ts,
            window.domain,
            list(window.findings.values()),
            sorted(window.hosts),
            window.customer,
            window.site,
        )
        if incident is None:
            return None
        incident.kind = "coordinated_malware_campaign"
        incident.signals.append(
            f"Correlated {len(window.findings)} finding types across {len(window.hosts)} hosts in 60s"
        )
        nxdomain_count = len(self._nxdomain.get(event.site, ()))
        if nxdomain_count:
            incident.signals.append(f"NXDOMAIN spike: {nxdomain_count} queries in 60s")
        window.emitted = True
        return incident
