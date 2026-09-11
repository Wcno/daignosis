from __future__ import annotations

import re
from datetime import datetime

from sentinel_dns.models import DnsEvent

LINE_RE = re.compile(
    r"^(?P<ts>\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"queries:\s+info:\s+client\s+@\S+\s+"
    r"(?P<ip>[0-9a-fA-F:.]+)#(?P<port>\d+)\s+"
    r"\((?P<name>[^)]+)\):\s+query:\s+"
    r"(?P<qname>\S+)\s+IN\s+(?P<qtype>\S+)\s+"
    r"(?P<flags>\S+)\s+\((?P<server>[^)]+)\)"
)

_TS_FMT = "%d-%b-%Y %H:%M:%S.%f"


def parse_line(line: str) -> DnsEvent | None:
    m = LINE_RE.match(line.rstrip("\n\r"))
    if not m:
        return None
    ts_raw = m.group("ts")
    try:
        ts = datetime.strptime(ts_raw, _TS_FMT).timestamp()
    except ValueError:
        return None
    qname = m.group("qname").rstrip(".").lower()
    return DnsEvent(
        ts=ts,
        ts_raw=ts_raw,
        client_ip=m.group("ip"),
        port=int(m.group("port")),
        qname=qname,
        qtype=m.group("qtype"),
        flags=m.group("flags"),
        server=m.group("server"),
    )
