from __future__ import annotations

import math
from collections import Counter

from daignosis.models import DnsEvent

VOWELS = set("aeiou")


def shannon(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    counts = Counter(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract(ev: DnsEvent) -> dict:
    sld = ev.sld or ev.qname
    labels = [p for p in ev.qname.split(".") if p]
    digits = sum(ch.isdigit() for ch in sld)
    vowels = sum(ch in VOWELS for ch in sld)
    n = max(len(sld), 1)
    max_label = max((len(p) for p in labels), default=0)
    return {
        "entropy": shannon(sld),
        "sld_len": len(sld),
        "digit_ratio": digits / n,
        "vowel_ratio": vowels / n,
        "label_depth": max(len(labels) - 2, 0),
        "max_label": max_label,
        "qtype": ev.qtype,
        "nx": ev.rcode == "NXDOMAIN",
        "timeout": ev.timeout,
    }
