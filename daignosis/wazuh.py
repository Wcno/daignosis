from __future__ import annotations

import json
from datetime import datetime, timezone
from urllib.error import URLError
from urllib.request import Request, urlopen

from daignosis.models import Incident
from daignosis.egress import ALLOWED


def format_alert(inc: Incident) -> dict:
    ts = datetime.fromtimestamp(inc.ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+0000"
    level = {"critical": 12, "high": 10, "medium": 7, "low": 4}.get(inc.severity, 7)
    groups = ["daignosis", inc.kind.replace("possible_", "")]
    return {
        "timestamp": ts,
        "rule": {
            "level": level,
            "description": f"dAIgnosis: {inc.kind} risk {inc.risk_score}",
            "id": "100001",
            "groups": groups,
            "mitre": {
                "id": ["T1071.004", "T1568.002"],
                "tactic": ["Command and Control"],
            },
        },
        "decoder": {"name": "daignosis"},
        "location": "daignosis",
        "agent": {"id": "000", "name": "daignosis"},
        "data": {
            "srcip": inc.affected_hosts[0] if inc.affected_hosts else "",
            "dns.question.name": inc.domain,
            "risk_score": inc.risk_score,
            "severity": inc.severity,
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
                "source": "daignosis",
                "severity": inc.severity,
                "risk_score": inc.risk_score,
                "domain": inc.domain,
                "incident_type": inc.kind,
                "affected_hosts": len(inc.affected_hosts),
                "explanation": inc.explanation,
            },
            ensure_ascii=False,
        ),
    }


class WazuhWebhook:
    """Deliver the Wazuh-compatible alert to a local manager or relay."""

    def __init__(self, endpoint: str | None, timeout: float = 0.8) -> None:
        self.endpoint = endpoint.rstrip("/") if endpoint else None
        self.timeout = timeout
        self.last_error: str | None = None
        if self.endpoint:
            from urllib.parse import urlparse

            host = urlparse(self.endpoint).hostname or ""
            if host not in ALLOWED:
                raise PermissionError(f"Wazuh endpoint must be local: {host}")

    @property
    def configured(self) -> bool:
        return self.endpoint is not None

    def send(self, alert: dict) -> bool:
        if not self.endpoint:
            return False
        try:
            body = json.dumps(alert, ensure_ascii=False).encode("utf-8")
            req = Request(
                self.endpoint,
                data=body,
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urlopen(req, timeout=self.timeout) as response:
                if not 200 <= response.status < 300:
                    self.last_error = f"HTTP {response.status}"
                    return False
            self.last_error = None
            return True
        except (URLError, TimeoutError, OSError, PermissionError) as exc:
            self.last_error = str(exc)
            return False
