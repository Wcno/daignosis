from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path

from daignosis.clickhouse import MetricSink
from daignosis.correlate import Campaign, Correlator
from daignosis.detect import DetectorBank
from daignosis.features import extract
from daignosis.inject import Scenario
from daignosis.models import DnsEvent, Incident
from daignosis.overlay import Overlay, lookup_site
from daignosis.qoe import QoeEngine
from daignosis.qvac_explain import Explainer, qoe_template, template_explain
from daignosis.risk import _severity, aggregate
from daignosis.state import AppState
from daignosis.wazuh import WazuhWebhook, format_alert

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
        wazuh_endpoint: str | None = None,
    ) -> None:
        self.state = state
        self.explainer = explainer
        self.sink = sink
        self.batch_size = batch_size
        self.wazuh = WazuhWebhook(wazuh_endpoint)
        self.overlay = Overlay()
        self.detectors = DetectorBank()
        self.qoe = QoeEngine()
        self.scenario = Scenario()
        self.correlator = Correlator()
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
        delivered = self.wazuh.send(alert)
        # With no endpoint, the contract is still emitted to the local console.
        inc.wazuh_sent = delivered or not self.wazuh.configured
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

    def _on_case_explained(
        self,
        campaign: Campaign,
        explanation: str,
        recommended_action: str,
        qvac_used: bool,
    ) -> None:
        score = 55.0 + min(30.0, campaign.n_hosts * 6.0) + min(20.0, campaign.n_events * 3.0)
        if campaign.repeated_seconds:
            score += 15.0
        if campaign.concluded:
            score += 10.0
        risk = int(min(100, round(score)))
        signals = [
            f"{campaign.n_hosts} internal hosts on the same domain/site",
            f"{campaign.n_events} corroborating events in one window",
        ]
        if campaign.repeated_seconds:
            signals.append(f"steady ~{campaign.repeated_seconds:.0f}s cadence")
        inc = Incident(
            ts=campaign.ts,
            domain=campaign.domain,
            kind="coordinated_campaign",
            risk_score=risk,
            severity=_severity(risk),
            signals=signals,
            affected_hosts=campaign.hosts,
            customer=campaign.customer,
            site=campaign.site,
            explanation=explanation,
            recommended_action=recommended_action,
            qvac_used=qvac_used,
        )
        self._emit_incident(inc)
        self.state.add_case(
            {
                "ts": inc.ts,
                "domain": inc.domain,
                "site": inc.site,
                "hosts": campaign.n_hosts,
                "events": campaign.n_events,
                "risk_score": inc.risk_score,
                "severity": inc.severity,
                "explanation": inc.explanation,
                "recommended_action": inc.recommended_action,
                "qvac_used": inc.qvac_used,
            }
        )

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
        self.explainer.start(self._on_explained, self._on_qoe_explained, self._on_case_explained)
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
        for inc in pending:
            self.correlator.add(inc)
        for campaign in self.correlator.poll(time.time()):
            self.explainer.submit_case(campaign)
        self._flush_qoe()
        self.state.qvac_ready = self.explainer.ready
        self.state.qvac_error = self.explainer.error


def open_source(data: Path | None, preferred: str | None) -> Iterator[DnsEvent]:
    from daignosis.replay import iter_bind_dir, iter_synthetic

    if data and data.exists():
        return iter_bind_dir(data, preferred)
    return iter_synthetic()
