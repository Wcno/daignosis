from __future__ import annotations

import json
import time
from collections.abc import Iterator
from datetime import datetime
from typing import Any

from daignosis.models import DnsEvent
from daignosis.parse import parse_line

_TS_FMT = "%d-%b-%Y %H:%M:%S.%f"


def _norm(value: Any) -> str:
    return str(value or "").strip().rstrip(".").lower()


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _parse_ts(obj: dict[str, Any]) -> tuple[float, str]:
    raw = obj.get("ts_raw") or obj.get("timestamp") or obj.get("ts") or ""
    ts = _to_float(obj.get("ts"), 0.0)
    text = str(raw).strip()
    if ts <= 0 and text:
        for parser in (datetime.fromisoformat,):
            try:
                dt = parser(text.replace("Z", "+00:00"))
                return dt.timestamp(), text
            except (ValueError, TypeError):
                pass
        try:
            return datetime.strptime(text, _TS_FMT).timestamp(), text
        except (ValueError, TypeError):
            pass
        return time.time(), text
    return (ts if ts > 0 else time.time()), text


def json_to_event(obj: dict[str, Any]) -> DnsEvent | None:
    qname = _norm(obj.get("qname") or obj.get("query") or obj.get("domain") or obj.get("name"))
    if not qname:
        return None
    ts, ts_raw = _parse_ts(obj)
    return DnsEvent(
        ts=ts,
        ts_raw=ts_raw,
        client_ip=_norm(obj.get("client_ip") or obj.get("ip") or obj.get("src_ip")),
        port=_to_int(obj.get("port")),
        qname=qname,
        qtype=_norm(obj.get("qtype") or obj.get("type") or "A"),
        flags=_norm(obj.get("flags") or "+"),
        server=_norm(obj.get("server") or obj.get("resolver")),
        customer=str(obj.get("customer") or "").strip(),
        site=str(obj.get("site") or "").strip(),
        zone=str(obj.get("zone") or "").strip(),
        latency_ms=_to_float(obj.get("latency_ms") or obj.get("latency")),
        rcode=_norm(obj.get("rcode") or "NOERROR").upper(),
        timeout=bool(obj.get("timeout")),
    )


def message_to_event(raw: str | bytes | None) -> DnsEvent | None:
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")
    text = raw.strip()
    if not text:
        return None
    ev = parse_line(text)
    if ev is not None:
        return ev
    try:
        obj = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    return json_to_event(obj)


def iter_kafka_stream(messages: Iterator[str | bytes | None]) -> Iterator[DnsEvent]:
    for raw in messages:
        ev = message_to_event(raw)
        if ev is not None:
            yield ev


def iter_kafka(
    bootstrap: str,
    topics: list[str],
    group: str = "daignosis",
    auto_offset_reset: str = "earliest",
    poll_s: float = 1.0,
) -> Iterator[DnsEvent]:
    try:
        from confluent_kafka import Consumer
        from confluent_kafka.cimpl import KafkaError
    except ImportError as exc:
        raise RuntimeError(
            "Kafka source requires 'confluent-kafka'. Install with: pip install -r requirements-kafka.txt"
        ) from exc

    conf = {
        "bootstrap.servers": bootstrap,
        "group.id": group,
        "auto.offset.reset": auto_offset_reset,
        "enable.auto.commit": True,
        "session.timeout.ms": 10000,
        "client.id": "daignosis-agent",
    }
    consumer = Consumer(conf)
    try:
        consumer.subscribe(topics)
        while True:
            msgs = consumer.consume(num_messages=512, timeout=poll_s)
            if not msgs:
                time.sleep(0.05)
                continue
            for msg in msgs:
                if msg.error() and msg.error().code() != KafkaError._PARTITION_EOF:
                    continue
                ev = message_to_event(msg.value())
                if ev is not None:
                    yield ev
    except KeyboardInterrupt:
        pass
    finally:
        consumer.close()