from __future__ import annotations

import json
from datetime import datetime, timezone

from sentinel_dns.models import Incident


def format_alert(inc: Incident) -> dict:
    ts = datetime.fromtimestamp(inc.ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"
    level = {"critical": 12, "high": 10, "medium": 7, "low": 4}.get(inc.severity, 7)
    groups = ["sentinel-dns", inc.kind.replace("possible_", "")]
    return {
        "timestamp": ts,
        "rule": {
            "level": level,
            "description": f"Sentinel-DNS: {inc.kind} risk {inc.risk_score}",
            "id": "100001",
            "groups": groups,
            "mitre": {
                "id": ["T1071.004", "T1568.002"],
                "tactic": ["Command and Control"],
            },
        },
        "decoder": {"name": "sentinel-dns"},
        "location": "sentinel-dns",
        "agent": {"id": "000", "name": "sentinel-dns"},
        "data": {
            "srcip": inc.affected_hosts[0] if inc.affected_hosts else "",
            "dns.question.name": inc.domain,
            "risk_score": inc.risk_score,
            "severity": inc.severity,
            "confidence": inc.confidence,
            "incident_type": inc.kind,
            "affected_hosts": inc.affected_hosts,
            "customer": inc.customer,
            "site": inc.site,
            "signals": inc.signals,
            "explanation": inc.explanation,
            "recommended_action": inc.recommended_action,
            "qvac_used": inc.qvac_used,
        },
        "full_log": json.dumps(
            {
                "source": "sentinel-dns",
                "severity": inc.severity,
                "risk_score": inc.risk_score,
                "domain": inc.domain,
                "incident_type": inc.kind,
                "confidence": inc.confidence,
                "affected_hosts": len(inc.affected_hosts),
                "explanation": inc.explanation,
            },
            ensure_ascii=False,
        ),
    }
