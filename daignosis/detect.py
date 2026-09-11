from __future__ import annotations

import json
from collections import OrderedDict, deque
from pathlib import Path

from daignosis.models import DnsEvent, Finding

_BRANDS = json.loads(
    (Path(__file__).resolve().parent / "config" / "brands.json").read_text(encoding="utf-8")
)["brands"]

SUSPECT_TLD = frozenset(
    {"xyz", "top", "click", "work", "rest", "surf", "tk", "ml", "ga", "cf", "gq", "info", "biz", "zip"}
)

HOMO = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "@": "a",
    }
)


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            ins, delete, sub = cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + (ca != cb)
            cur.append(min(ins, delete, sub))
        prev = cur
    return prev[-1]


def dga_score(feats: dict, ev: DnsEvent) -> float:
    if ev.qname.endswith(".arpa") or ev.qtype == "PTR":
        return 0.0
    sld = ev.sld
    if not sld or len(sld) < 6:
        return 0.0
    score = 0.0
    if feats["entropy"] >= 3.5:
        score += 0.28
    if feats["entropy"] >= 4.0:
        score += 0.17
    if feats["sld_len"] >= 12:
        score += 0.18
    if feats["digit_ratio"] >= 0.2:
        score += 0.12
    if feats["vowel_ratio"] <= 0.22:
        score += 0.15
    tld = ev.etld1.split(".")[-1] if ev.etld1 else ""
    if tld in SUSPECT_TLD:
        score += 0.18
    if feats["max_label"] >= 32:
        score += 0.1
    return min(1.0, score)


def typosquat(ev: DnsEvent) -> Finding | None:
    candidate = ev.etld1
    if not candidate or candidate.endswith(".arpa"):
        return None
    norm = candidate.translate(HOMO)
    for brand in _BRANDS:
        if candidate == brand:
            return None
        bnorm = brand.translate(HOMO)
        if norm == bnorm and candidate != brand:
            return Finding(
                "typosquat",
                0.95,
                {"brand": brand, "distance": 0, "domain": candidate, "homoglyph": True},
            )
        if abs(len(norm) - len(bnorm)) > 2:
            continue
        dist = levenshtein(norm, bnorm)
        if 0 < dist <= 2:
            return Finding(
                "typosquat",
                0.9,
                {"brand": brand, "distance": dist, "domain": candidate},
            )
        clab = candidate.split(".")[0]
        blab = brand.split(".")[0]
        if clab.startswith(blab) and len(clab) - len(blab) <= 8 and len(clab) > len(blab) + 2:
            if any(x in clab for x in ("login", "secure", "auth", "verify", "account")):
                return Finding(
                    "typosquat",
                    0.75,
                    {"brand": brand, "distance": dist, "domain": candidate},
                )
    return None


class _LruDeques:
    def __init__(self, maxlen: int, max_keys: int) -> None:
        self.maxlen = maxlen
        self.max_keys = max_keys
        self.data: OrderedDict = OrderedDict()

    def add(self, key, value) -> deque:
        if key in self.data:
            self.data.move_to_end(key)
        else:
            if len(self.data) >= self.max_keys:
                self.data.popitem(last=False)
            self.data[key] = deque(maxlen=self.maxlen)
        dq = self.data[key]
        dq.append(value)
        return dq


class DetectorBank:
    def __init__(self) -> None:
        self.beacons = _LruDeques(16, 50000)
        self.subs = _LruDeques(64, 20000)
        self.hosts: OrderedDict[str, set[str]] = OrderedDict()
        self._host_cap = 20000

    def _hosts(self, domain: str, ip: str) -> list[str]:
        if domain in self.hosts:
            self.hosts.move_to_end(domain)
        else:
            if len(self.hosts) >= self._host_cap:
                self.hosts.popitem(last=False)
            self.hosts[domain] = set()
        bucket = self.hosts[domain]
        if len(bucket) < 256:
            bucket.add(ip)
        return list(bucket)

    def feed(self, ev: DnsEvent, feats: dict) -> list[Finding]:
        out: list[Finding] = []
        ds = dga_score(feats, ev)
        if ds >= 0.55:
            out.append(
                Finding(
                    "dga",
                    ds,
                    {
                        "entropy": round(feats["entropy"], 3),
                        "sld_len": feats["sld_len"],
                        "vowel_ratio": round(feats["vowel_ratio"], 3),
                    },
                )
            )
        typo = typosquat(ev)
        if typo:
            out.append(typo)

        if feats["max_label"] >= 40 or (
            feats["label_depth"] >= 4 and feats["entropy"] >= 3.8
        ):
            out.append(
                Finding(
                    "tunnel",
                    min(1.0, feats["max_label"] / 80.0 + feats["entropy"] / 8.0),
                    {"max_label": feats["max_label"], "depth": feats["label_depth"]},
                )
            )
        if ev.qtype == "TXT" and ev.etld1:
            key = (ev.client_ip, ev.etld1)
            dq = self.beacons.add(("txt",) + key, ev.ts)
            if len(dq) >= 8:
                span = dq[-1] - dq[0]
                if span > 0 and len(dq) / span >= 2.0:
                    out.append(Finding("tunnel", 0.7, {"txt_rate": round(len(dq) / span, 2)}))

        if ev.etld1 and not ev.qname.endswith(".arpa"):
            labels = ev.qname.split(".")
            if len(labels) > 2:
                sub_dq = self.subs.add(ev.etld1, labels[0])
                if len(set(sub_dq)) >= 24:
                    out.append(
                        Finding(
                            "tunnel",
                            0.65,
                            {"unique_subs": len(set(sub_dq)), "apex": ev.etld1},
                        )
                    )

        key = (ev.client_ip, ev.etld1)
        times = self.beacons.add(key, ev.ts)
        if len(times) >= 6:
            intervals = [times[i] - times[i - 1] for i in range(1, len(times))]
            mean = sum(intervals) / len(intervals)
            if 2.0 <= mean <= 180.0:
                var = sum((x - mean) ** 2 for x in intervals) / len(intervals)
                cv = (var ** 0.5) / mean if mean else 1.0
                if cv < 0.18:
                    out.append(
                        Finding(
                            "beacon",
                            max(0.55, 1.0 - cv * 4),
                            {
                                "period_seconds": round(mean, 2),
                                "cv": round(cv, 3),
                                "samples": len(times),
                            },
                        )
                    )

        if ev.etld1:
            self._hosts(ev.etld1, ev.client_ip)
        return out

    def affected(self, domain: str) -> list[str]:
        return list(self.hosts.get(domain, ()))
