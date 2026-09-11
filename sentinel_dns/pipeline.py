from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path

from sentinel_dns.clickhouse import MetricSink
from sentinel_dns.correlation import CampaignCorrelator
from sentinel_dns.detect import DetectorBank
from sentinel_dns.features import extract
from sentinel_dns.inject import Scenario
from sentinel_dns.models import DnsEvent, Incident
from sentinel_dns.overlay import Overlay
from sentinel_dns.qoe import QoeEngine
from sentinel_dns.qvac_explain import Explainer, qoe_template
from sentinel_dns.state import AppState
from sentinel_dns.wazuh import format_alert
from sentinel_dns.webhook import WazuhWebhook

SITE_CAPACITY = {
    "Panama-East": 400.0,
    "Panama-West": 350.0,
    "Bogota-DC": 280.0,
    "San-Salvador": 200.0,
    "Guatemala-City": 220.0,
    "Edge-Other": 150.0,
}


class Pipeline:
    def __init__(
        self,
        state: AppState,
        explainer: Explainer,
        sink: MetricSink,
        webhook: WazuhWebhook,
        batch_size: int = 512,
        inject_scenario: bool = True,
    ) -> None:
        self.state = state
        self.explainer = explainer
        self.sink = sink
        self.webhook = webhook
        self.batch_size = batch_size
        self.inject_scenario = inject_scenario
        self.overlay = Overlay()
        self.detectors = DetectorBank()
        self.correlator = CampaignCorrelator()
        self.qoe = QoeEngine()
        self.scenario = Scenario()
        self._last_qoe_explain: dict[str, str] = {}
        self.stop = False
        self._pace_qps = 420.0
        self._pace_t0 = time.monotonic()
        self._pace_n = 0

    def _emit_incident(self, inc: Incident) -> None:
        if not inc.qvac_used:
            return
        alert = format_alert(inc)
        inc.wazuh_sent = self.webhook.deliver(alert)
        self.state.add_incident(inc)
        self.sink.write_incident(
            {
                "ts": inc.ts,
                "domain": inc.domain,
                "kind": inc.kind,
                "risk_score": inc.risk_score,
                "severity": inc.severity,
                "site": inc.site,
                "customer": inc.customer,
                "explanation": inc.explanation,
            }
        )

    def _on_explained(self, inc: Incident) -> None:
        self._emit_incident(inc)

    def _on_qoe_explained(self, snap: dict) -> None:
        self.state.set_qoe(snap)
        self.sink.write_qoe(snap)

    def _on_qvac_error(self, message: str) -> None:
        self.state.qvac_error = message

    def _normalize_for_legacy_source(self, ev: DnsEvent) -> None:
        if not ev.site:
            self.overlay.enrich(ev)

    def process_event(self, ev: DnsEvent) -> Incident | None:
        self._normalize_for_legacy_source(ev)
        feats = extract(ev)
        findings = self.detectors.feed(ev, feats)
        cap = SITE_CAPACITY.get(ev.site, 150.0)
        self.qoe.feed(ev.site, ev.customer, ev.zone, ev.latency_ms, ev.rcode == "NXDOMAIN", ev.timeout, cap)
        if not findings:
            self.correlator.feed(ev, findings)
            return None
        self.state.add_findings(
            {
                "ts": ev.ts,
                "domain": ev.etld1 or ev.qname,
                "host": ev.client_ip,
                "site": ev.site,
                "customer": ev.customer,
            },
            [{"kind": finding.kind, "score": round(finding.score, 3), "detail": finding.detail} for finding in findings],
        )
        return self.correlator.feed(ev, findings)

    def _flush_qoe(self) -> None:
        for snap in self.qoe.flush_due():
            status = snap["qoe_status"]
            prev = self._last_qoe_explain.get(snap["site"])
            snap["narrative"] = qoe_template(snap)
            self.state.set_qoe(snap)
            self.sink.write_qoe(snap)
            if status != "ok" and prev != status:
                self._last_qoe_explain[snap["site"]] = status
            elif status == "ok":
                self._last_qoe_explain[snap["site"]] = "ok"

    def run(self, source: Iterator[DnsEvent]) -> None:
        self.explainer.start(self._on_explained, self._on_qoe_explained, self._on_qvac_error)
        batch: list[DnsEvent] = []
        last_batch_flush = time.monotonic()
        last_sleep_check = time.monotonic()
        try:
            while not self.stop:
                if self.inject_scenario and self.scenario.degrade_on():
                    self.overlay.degrade("Panama-East")
                if self.inject_scenario:
                    for extra in self.scenario.due_events(time.time()):
                        batch.append(extra)
                        if len(batch) >= self.batch_size:
                            self._flush_batch(batch)
                            batch = []
                try:
                    ev = next(source)
                except StopIteration:
                    if batch:
                        self._flush_batch(batch)
                        batch = []
                        last_batch_flush = time.monotonic()
                    if getattr(source, "live", False):
                        continue
                    break
                batch.append(ev)
                now = time.monotonic()
                if len(batch) >= self.batch_size or now - last_batch_flush >= 0.25:
                    self._flush_batch(batch)
                    batch = []
                    last_batch_flush = now
                if now - last_sleep_check > 0.25:
                    last_sleep_check = now
                    time.sleep(0.001)
        except KeyboardInterrupt:
            self.stop = True
        finally:
            if batch:
                self._flush_batch(batch)
            self.explainer.stop()
            close = getattr(source, "close", None)
            if close:
                close()

    def _flush_batch(self, batch: list[DnsEvent]) -> None:
        sample = []
        injected = 0
        pending: list[Incident] = []
        for ev in batch:
            if ev.injected:
                injected += 1
            inc = self.process_event(ev)
            if inc is not None:
                pending.append(inc)
            if len(sample) < 8:
                sample.append(
                    {
                        "qname": ev.qname,
                        "ip": ev.client_ip,
                        "site": ev.site,
                        "qtype": ev.qtype,
                        "rcode": ev.rcode,
                        "latency_ms": round(ev.latency_ms, 1),
                        "injected": ev.injected,
                    }
                )
        self.state.note_batch(len(batch), injected, sample)
        now = time.monotonic()
        if now - self._pace_t0 >= 1.0:
            self._pace_n = 0
            self._pace_t0 = now
        self._pace_n += len(batch)
        ahead = self._pace_n / self._pace_qps - (now - self._pace_t0)
        if ahead > 0:
            time.sleep(ahead)
        for inc in pending:
            self.explainer.submit_incident(inc)
        self._flush_qoe()
        self.state.qvac_ready = self.explainer.ready
        self.state.qvac_error = self.explainer.error


def open_source(data: Path | None, preferred: str | None) -> Iterator[DnsEvent]:
    from sentinel_dns.replay import iter_bind_dir, iter_synthetic

    if data and data.exists():
        return iter_bind_dir(data, preferred)
    return iter_synthetic()
