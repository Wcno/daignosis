from __future__ import annotations

import math
import time
from dataclasses import dataclass, field


def _clamp(x: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, x))


class Ewma:
    def __init__(self, alpha: float = 0.05) -> None:
        self.alpha = alpha
        self.mean: float | None = None
        self.var = 0.0

    def update(self, x: float) -> None:
        if self.mean is None:
            self.mean = x
            return
        delta = x - self.mean
        self.mean += self.alpha * delta
        self.var = (1 - self.alpha) * (self.var + self.alpha * delta * delta)

    def z(self, x: float) -> float:
        if self.mean is None:
            return 0.0
        return (x - self.mean) / math.sqrt(self.var + 1e-6)


@dataclass
class SiteWindow:
    customer: str
    site: str
    zone: str
    capacity_qps: float
    n: int = 0
    lat_sum: float = 0.0
    nx: int = 0
    timeouts: int = 0
    lat: Ewma = field(default_factory=Ewma)
    nxr: Ewma = field(default_factory=Ewma)
    tor: Ewma = field(default_factory=Ewma)
    qps_ewma: Ewma = field(default_factory=Ewma)
    degraded_since: float | None = None
    affected_queries: int = 0
    last_status: str = "ok"
    last_flush: float = 0.0


def _component_latency(ms: float) -> float:
    if ms <= 25:
        return 100.0
    if ms >= 150:
        return 0.0
    return _clamp(100.0 * (150 - ms) / 125.0)


def _component_rate(p: float, good: float, bad: float) -> float:
    if p <= good:
        return 100.0
    if p >= bad:
        return 0.0
    return _clamp(100.0 * (bad - p) / (bad - good))


def _component_z(z: float, good: float = 1.0, bad: float = 3.0) -> float:
    if z != z:  # NaN
        return 100.0
    if z <= good:
        return 100.0
    if z >= bad:
        return 0.0
    return _clamp(100.0 * (bad - z) / (bad - good))


class QoeEngine:
    def __init__(self, flush_every: float = 5.0) -> None:
        self.flush_every = flush_every
        self.sites: dict[str, SiteWindow] = {}

    def _site(self, customer: str, site: str, zone: str, capacity: float) -> SiteWindow:
        row = self.sites.get(site)
        if row is None:
            row = SiteWindow(customer=customer, site=site, zone=zone, capacity_qps=capacity)
            self.sites[site] = row
        return row

    def feed(self, site: str, customer: str, zone: str, latency_ms: float, nx: bool, timeout: bool, capacity: float) -> None:
        row = self._site(customer, site, zone, capacity)
        row.n += 1
        row.lat_sum += latency_ms
        row.nx += int(nx)
        row.timeouts += int(timeout)

    def flush_due(self, now: float | None = None) -> list[dict]:
        now = now or time.time()
        out = []
        for row in self.sites.values():
            if row.n == 0:
                if now - row.last_flush >= self.flush_every and row.last_flush:
                    continue
                continue
            if row.last_flush and now - row.last_flush < self.flush_every:
                continue
            if row.last_flush:
                dt = max(now - row.last_flush, self.flush_every, 1e-3)
            else:
                dt = max(self.flush_every, 1e-3)
            qps = row.n / dt
            avg_lat = row.lat_sum / row.n
            nx_rate = row.nx / row.n
            to_rate = row.timeouts / row.n
            sat = qps / max(row.capacity_qps, 1.0)
            row.lat.update(avg_lat)
            row.nxr.update(nx_rate)
            row.tor.update(to_rate)
            row.qps_ewma.update(qps)
            lat_z = row.lat.z(avg_lat)
            nx_z = row.nxr.z(nx_rate)
            to_z = row.tor.z(to_rate)
            sat_z = row.qps_ewma.z(qps)
            lat_s = min(_component_latency(avg_lat), _component_z(lat_z))
            nx_s = min(_component_rate(nx_rate, 0.04, 0.20), _component_z(nx_z))
            to_s = min(_component_rate(to_rate, 0.01, 0.08), _component_z(to_z))
            sat_fixed = _clamp(100.0 * (1.0 - max(0.0, sat - 0.7) / 0.3))
            sat_s = min(sat_fixed, _component_z(sat_z))
            qoe = 0.40 * lat_s + 0.25 * nx_s + 0.20 * to_s + 0.15 * sat_s
            if qoe >= 80:
                status = "ok"
            elif qoe >= 60:
                status = "degraded"
            else:
                status = "critical"
            parts = {
                "latency": (lat_s, lat_z, avg_lat, row.lat.mean),
                "nxdomain": (nx_s, nx_z, nx_rate, row.nxr.mean),
                "timeout": (to_s, to_z, to_rate, row.tor.mean),
                "saturation": (sat_s, sat_z, sat, row.qps_ewma.mean),
            }
            cause = min(parts.items(), key=lambda kv: kv[1][0])[0]
            if status in {"degraded", "critical"}:
                if row.degraded_since is None:
                    row.degraded_since = now
                row.affected_queries += row.n
            else:
                row.degraded_since = None
                row.affected_queries = 0
            duration = (now - row.degraded_since) if row.degraded_since else 0.0
            snapshot = {
                "ts": now,
                "customer": row.customer,
                "site": row.site,
                "zone": row.zone,
                "avg_dns_latency": round(avg_lat, 2),
                "nxdomain_rate": round(nx_rate, 4),
                "timeout_rate": round(to_rate, 4),
                "qps": round(qps, 1),
                "qoe_score": round(qoe, 1),
                "qoe_status": status,
                "root_cause": cause,
                "latency_z": round(lat_z, 2),
                "nxdomain_z": round(nx_z, 2),
                "timeout_z": round(to_z, 2),
                "saturation_z": round(sat_z, 2),
                "baseline_latency": round(row.lat.mean or avg_lat, 2),
                "affected_queries": row.affected_queries,
                "degraded_seconds": round(duration, 1),
                "components": {
                    "latency": round(lat_s, 1),
                    "nxdomain": round(nx_s, 1),
                    "timeout": round(to_s, 1),
                    "saturation": round(sat_s, 1),
                },
            }
            row.n = 0
            row.lat_sum = 0.0
            row.nx = 0
            row.timeouts = 0
            row.last_flush = now
            row.last_status = status
            out.append(snapshot)
        return out
