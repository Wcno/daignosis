from __future__ import annotations

import json
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from daignosis.egress import ALLOWED


class MetricSink:
    def __init__(self, url: str = "http://127.0.0.1:8123", var_dir: Path | None = None) -> None:
        self.url = url.rstrip("/")
        self.var_dir = var_dir or Path("var")
        self.var_dir.mkdir(parents=True, exist_ok=True)
        self.qoe_path = self.var_dir / "qoe.jsonl"
        self.inc_path = self.var_dir / "incidents.jsonl"
        self.live = False
        self._ensure_tables()

    def _ensure_tables(self) -> None:
        ddl = [
            (
                "CREATE TABLE IF NOT EXISTS qoe_metrics ("
                "ts DateTime64(3), customer LowCardinality(String), site LowCardinality(String), "
                "zone LowCardinality(String), avg_dns_latency Float64, nxdomain_rate Float64, "
                "timeout_rate Float64, qps Float64, qoe_score Float64, qoe_status LowCardinality(String), "
                "root_cause String, affected_queries UInt64, degraded_seconds Float64) "
                "ENGINE = MergeTree ORDER BY (site, ts)"
            ),
            (
                "CREATE TABLE IF NOT EXISTS dns_incidents ("
                "ts DateTime64(3), domain String, kind LowCardinality(String), risk_score UInt8, "
                "severity LowCardinality(String), site String, customer String, explanation String) "
                "ENGINE = MergeTree ORDER BY (ts, domain)"
            ),
        ]
        for stmt in ddl:
            if not self._http(stmt):
                self.live = False
                return
        self.live = True

    def _http(self, body: str) -> bool:
        try:
            req = Request(self.url + "/?query=", data=body.encode("utf-8"), method="POST")
            with urlopen(req, timeout=0.4) as resp:
                return 200 <= resp.status < 300
        except (URLError, TimeoutError, OSError, PermissionError):
            return False

    def write_qoe(self, row: dict) -> None:
        line = json.dumps(row, ensure_ascii=False, default=str)
        with self.qoe_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        if self.live:
            payload = {k: row[k] for k in row if k != "components"}
            self._http("INSERT INTO qoe_metrics FORMAT JSONEachRow\n" + json.dumps(payload))

    def write_incident(self, row: dict) -> None:
        line = json.dumps(row, ensure_ascii=False, default=str)
        with self.inc_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        if self.live:
            self._http("INSERT INTO dns_incidents FORMAT JSONEachRow\n" + json.dumps(row))


def assert_local_url(url: str) -> None:
    from urllib.parse import urlparse

    host = urlparse(url).hostname or ""
    if host not in ALLOWED:
        raise PermissionError(f"sink host not local: {host}")
