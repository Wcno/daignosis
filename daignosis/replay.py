from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path

from daignosis.models import DnsEvent
from daignosis.parse import parse_line

BENIGN = [
    "www.apple.com",
    "officeclient.microsoft.com",
    "clients4.google.com",
    "settings-win.data.microsoft.com",
    "gue1-spclient.spotify.com",
    "i.ytimg.com",
    "pop.gmail.com",
    "time.windows.com",
    "teams.cloud.microsoft",
    "static.ui.com",
]

SYN_IPS = [
    "190.14.210.102",
    "190.102.56.90",
    "200.12.212.138",
    "181.119.219.3",
    "38.108.33.34",
]


def iter_bind_file(path: Path) -> Iterator[DnsEvent]:
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            ev = parse_line(line)
            if ev is not None:
                yield ev


def iter_bind_dir(root: Path, preferred: str | None = "queries.0") -> Iterator[DnsEvent]:
    if root.is_file():
        yield from iter_bind_file(root)
        return
    files = sorted(root.glob("queries.*"), key=lambda p: p.name)
    files = [p for p in files if p.is_file() and not p.name.startswith("._")]
    if preferred:
        first = [p for p in files if p.name == preferred]
        rest = [p for p in files if p.name != preferred]
        files = first + rest
    for path in files:
        yield from iter_bind_file(path)


def iter_synthetic(qps: float = 280.0) -> Iterator[DnsEvent]:
    interval = 1.0 / max(qps, 1.0)
    i = 0
    while True:
        ts = time.time()
        ip = SYN_IPS[i % len(SYN_IPS)]
        qname = BENIGN[i % len(BENIGN)]
        yield DnsEvent(
            ts=ts,
            ts_raw="synthetic",
            client_ip=ip,
            port=40000 + (i % 20000),
            qname=qname,
            qtype="A",
            flags="+",
            server="172.19.1.2",
        )
        i += 1
        time.sleep(interval)
