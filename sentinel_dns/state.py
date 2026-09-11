from __future__ import annotations

import threading
import time
from collections import deque

from sentinel_dns.egress import GUARD
from sentinel_dns.models import Incident


class AppState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.started = time.time()
        self.processed = 0
        self.injected = 0
        self.window = deque()
        self.recent = deque(maxlen=40)
        self.findings: list[dict] = []
        self.incidents: list[Incident] = []
        self.alerts: list[dict] = []
        self.qoe: dict[str, dict] = {}
        self.qvac_ready = False
        self.qvac_error: str | None = None
        self.source = "synthetic"

    def note_batch(self, n: int, injected: int, sample: list[dict]) -> None:
        now = time.time()
        with self.lock:
            self.processed += n
            self.injected += injected
            self.window.append((now, n))
            while self.window and now - self.window[0][0] > 2.0:
                self.window.popleft()
            for row in sample:
                self.recent.appendleft(row)
        GUARD.bump_events(n)

    def qps(self) -> float:
        with self.lock:
            if not self.window:
                return 0.0
            span = self.window[-1][0] - self.window[0][0]
            total = sum(n for _, n in self.window)
        return total / span if span > 0 else 0.0

    def add_findings(self, event: dict, findings: list[dict]) -> None:
        with self.lock:
            self.findings.insert(0, {"event": event, "findings": findings})
            del self.findings[80:]

    def add_incident(self, inc: Incident) -> None:
        with self.lock:
            self.incidents.insert(0, inc)
            del self.incidents[80:]

    def set_qoe(self, snap: dict) -> None:
        with self.lock:
            self.qoe[snap["site"]] = snap

    def snapshot(self) -> dict:
        with self.lock:
            findings = list(self.findings)[:20]
            incidents = [
                {
                    "ts": i.ts,
                    "domain": i.domain,
                    "kind": i.kind,
                    "risk_score": i.risk_score,
                    "severity": i.severity,
                    "signals": i.signals,
                    "affected_hosts": i.affected_hosts,
                    "customer": i.customer,
                    "site": i.site,
                    "explanation": i.explanation,
                    "recommended_action": i.recommended_action,
                    "confidence": i.confidence,
                    "qvac_used": i.qvac_used,
                    "wazuh_sent": i.wazuh_sent,
                }
                for i in self.incidents[:15]
            ]
            qoe = list(self.qoe.values())
            recent = list(self.recent)
            processed = self.processed
            injected = self.injected
            source = self.source
            qvac_ready = self.qvac_ready
            qvac_error = self.qvac_error
        return {
            "processed": processed,
            "injected": injected,
            "qps": round(self.qps(), 1),
            "uptime_s": round(time.time() - self.started, 1),
            "source": source,
            "recent": recent,
            "findings": findings,
            "incidents": incidents,
            "qoe": qoe,
            "alerts": self.alerts[:10] if False else [],
            "qvac": {"ready": qvac_ready, "error": qvac_error},
            "sovereignty": GUARD.snapshot(),
        }
