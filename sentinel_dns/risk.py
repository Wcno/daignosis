from __future__ import annotations

from sentinel_dns.models import Finding, Incident


def _severity(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


def aggregate(
    ts: float,
    domain: str,
    findings: list[Finding],
    hosts: list[str],
    customer: str,
    site: str,
) -> Incident | None:
    if not findings:
        return None
    by = {f.kind: f for f in findings}
    score = 0.0
    signals: list[str] = []
    if "dga" in by:
        score += 50.0 * by["dga"].score
        signals.append(f"DGA probability {by['dga'].score * 100:.0f}%")
        ent = by["dga"].detail.get("entropy")
        if ent:
            signals.append(f"High domain entropy {ent}")
    if "beacon" in by:
        score += 30.0 * by["beacon"].score
        period = by["beacon"].detail.get("period_seconds")
        signals.append(f"Query interval ~{period}s")
    if "tunnel" in by:
        score += 25.0 * by["tunnel"].score
        signals.append("DNS tunneling features")
    if "typosquat" in by:
        score += 22.0
        signals.append(f"Looks like {by['typosquat'].detail.get('brand')}")
    n_hosts = len(hosts)
    if n_hosts >= 3:
        score += min(15.0, n_hosts * 2.5)
        signals.append(f"{n_hosts} internal hosts affected")
    risk = int(min(100, round(score)))
    if risk < 45:
        return None
    kind = max(findings, key=lambda f: f.score).kind
    if "beacon" in by and "dga" in by:
        kind = "possible_c2_beaconing"
    elif "tunnel" in by:
        kind = "dns_tunneling"
    elif "typosquat" in by:
        kind = "typosquatting"
    elif "dga" in by:
        kind = "dga"
    return Incident(
        ts=ts,
        domain=domain,
        kind=kind,
        risk_score=risk,
        severity=_severity(risk),
        signals=signals,
        affected_hosts=hosts[:64],
        customer=customer,
        site=site,
    )
