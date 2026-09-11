from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path

from sentinel_dns.clickhouse import MetricSink
from sentinel_dns.detect import DetectorBank
from sentinel_dns.features import extract
from sentinel_dns.inject import Scenario
from sentinel_dns.models import DnsEvent, Incident
from sentinel_dns.overlay import Overlay, lookup_site
from sentinel_dns.qoe import QoeEngine
from sentinel_dns.qvac_explain import Explainer, qoe_template, template_explain
from sentinel_dns.risk import aggregate
from sentinel_dns.state import AppState
from sentinel_dns.wazuh import format_alert

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
        batch_size: int = 512,
    ) -> None:
        self.state = state
        self.explainer = explainer
        self.sink = sink
        self.batch_size = batch_size
        self.overlay = Overlay()
        self.detectors = DetectorBank()
        self.qoe = QoeEngine()
        self.scenario = Scenario()
        self._cooldown: dict[tuple[str, str], float] = {}
        self._last_qoe_explain: dict[str, str] = {}
        self.stop = False
        self._pace_qps = 420.0
        self._pace_t0 = time.monotonic()
        self._pace_n = 0

    def _emit_incident(self, inc: Incident) -> None:
        if not inc.explanation:
            expl, rec = template_explain(inc)
            inc.explanation = expl
            inc.recommended_action = rec
        alert = format_alert(inc)
        inc.wazuh_sent = True
        self.state.add_incident(inc, alert)
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

    def process_event(self, ev: DnsEvent) -> Incident | None:
        self.overlay.enrich(ev)
        feats = extract(ev)
        findings = self.detectors.feed(ev, feats)
        cap = SITE_CAPACITY.get(ev.site, 150.0)
        self.qoe.feed(ev.site, ev.customer, ev.zone, ev.latency_ms, ev.rcode == "NXDOMAIN", ev.timeout, cap)
        if not findings:
            return None
        hosts = self.detectors.affected(ev.etld1)
        inc = aggregate(ev.ts, ev.etld1 or ev.qname, findings, hosts, ev.customer, ev.site)
        if inc is None:
            return None
        key = (inc.kind, inc.domain)
        now = time.monotonic()
        last = self._cooldown.get(key, 0.0)
        if now - last < 45.0:
            return None
        self._cooldown[key] = now
        return inc

    def _flush_qoe(self) -> None:
        for snap in self.qoe.flush_due():
            status = snap["qoe_status"]
            prev = self._last_qoe_explain.get(snap["site"])
            snap["narrative"] = qoe_template(snap)
            self.state.set_qoe(snap)
            self.sink.write_qoe(snap)
            if status != "ok" and prev != status:
                self._last_qoe_explain[snap["site"]] = status
                self.explainer.submit_qoe(snap)
            elif status == "ok":
                self._last_qoe_explain[snap["site"]] = "ok"

    def run(self, source: Iterator[DnsEvent]) -> None:
        self.explainer.start(self._on_explained, self._on_qoe_explained)
        batch: list[DnsEvent] = []
        last_sleep_check = time.monotonic()
        try:
            while not self.stop:
                if self.scenario.degrade_on():
                    self.overlay.degrade("Panama-East")
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
                    time.sleep(0.05)
                    if self.stop:
                        break
                    continue
                batch.append(ev)
                if len(batch) >= self.batch_size:
                    self._flush_batch(batch)
                    batch = []
                now = time.monotonic()
                if now - last_sleep_check > 0.25:
                    last_sleep_check = now
                    time.sleep(0.001)
        except KeyboardInterrupt:
            self.stop = True
        finally:
            if batch:
                self._flush_batch(batch)
            self.explainer.stop()

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
            expl, rec = template_explain(inc)
            inc.explanation = expl
            inc.recommended_action = rec
            self.explainer.submit_incident(inc)
        self._flush_qoe()
        self.state.qvac_ready = self.explainer.ready
        self.state.qvac_error = self.explainer.error


def open_source(data: Path | None, preferred: str | None) -> Iterator[DnsEvent]:
    from sentinel_dns.replay import iter_bind_dir, iter_synthetic

    if data and data.exists():
        return iter_bind_dir(data, preferred)
    return iter_synthetic()
