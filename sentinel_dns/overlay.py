from __future__ import annotations

import ipaddress
import json
import random
from pathlib import Path

from sentinel_dns.etld import etld1
from sentinel_dns.models import DnsEvent

_CFG = Path(__file__).resolve().parent / "config" / "sites.json"


def _load() -> tuple[list[tuple[ipaddress._BaseNetwork, dict]], dict]:
    raw = json.loads(_CFG.read_text(encoding="utf-8"))
    prefixes = []
    for row in raw["prefixes"]:
        prefixes.append((ipaddress.ip_network(row["prefix"]), row))
    return prefixes, raw["default"]


PREFIXES, DEFAULT = _load()


def lookup_site(ip: str) -> dict:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return DEFAULT
    for net, row in PREFIXES:
        if addr in net:
            return row
    return DEFAULT


class Overlay:
    def __init__(self, rng: random.Random | None = None) -> None:
        self.rng = rng or random.Random(2026)
        self.degraded: set[str] = set()

    def degrade(self, site: str) -> None:
        self.degraded.add(site)

    def enrich(self, ev: DnsEvent) -> DnsEvent:
        meta = lookup_site(ev.client_ip)
        ev.customer = meta["customer"]
        ev.site = meta["site"]
        ev.zone = meta["zone"]
        root, sld = etld1(ev.qname)
        ev.etld1 = root
        ev.sld = sld
        mean = float(meta["latency_ms"])
        if ev.site in self.degraded:
            mean = 96.0
        ev.latency_ms = max(4.0, self.rng.gauss(mean, mean * 0.12))
        nx_p = float(meta["nxdomain_p"])
        to_p = float(meta["timeout_p"])
        roll = self.rng.random()
        if ev.injected:
            pass
        elif roll < to_p:
            ev.timeout = True
            ev.rcode = "SERVFAIL"
            ev.latency_ms = mean * 4
        elif roll < to_p + nx_p:
            ev.rcode = "NXDOMAIN"
        else:
            ev.rcode = "NOERROR"
        return ev
