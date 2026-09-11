from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class DnsEvent:
    ts: float
    ts_raw: str
    client_ip: str
    port: int
    qname: str
    qtype: str
    flags: str
    server: str
    customer: str = ""
    site: str = ""
    zone: str = ""
    latency_ms: float = 0.0
    rcode: str = "NOERROR"
    timeout: bool = False
    injected: bool = False
    etld1: str = ""
    sld: str = ""


@dataclass(slots=True)
class Finding:
    kind: str
    score: float
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Incident:
    ts: float
    domain: str
    kind: str
    risk_score: int
    severity: str
    signals: list[str]
    affected_hosts: list[str]
    customer: str
    site: str
    explanation: str = ""
    recommended_action: str = ""
    confidence: str = ""
    qvac_used: bool = False
    wazuh_sent: bool = False
