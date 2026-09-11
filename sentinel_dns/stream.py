from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import asdict

from sentinel_dns.models import DnsEvent

TOPIC = "dns.telemetry.v1"
CONSUMER_GROUP = "sentinel-dns"


def encode_event(event: DnsEvent) -> bytes:
    return json.dumps(
        {"schema_version": 1, "event": asdict(event)},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def decode_event(raw: bytes) -> DnsEvent:
    payload = json.loads(raw.decode("utf-8"))
    if payload.get("schema_version") != 1:
        raise ValueError("unsupported DNS telemetry schema version")
    event = payload.get("event")
    if not isinstance(event, dict):
        raise ValueError("DNS telemetry event is missing")
    return DnsEvent(**event)


def _kafka_classes():
    try:
        from kafka import KafkaConsumer, KafkaProducer
    except ImportError as exc:
        raise RuntimeError("Kafka support requires kafka-python") from exc
    return KafkaConsumer, KafkaProducer


class KafkaPublisher:
    def __init__(self, bootstrap_servers: str, topic: str = TOPIC) -> None:
        _, producer_class = _kafka_classes()
        self.topic = topic
        self._producer = producer_class(
            bootstrap_servers=bootstrap_servers,
            value_serializer=encode_event,
            acks="all",
            retries=3,
        )

    def publish(self, event: DnsEvent) -> None:
        self._producer.send(self.topic, event).get(timeout=10)

    def close(self) -> None:
        self._producer.flush(timeout=10)
        self._producer.close(timeout=10)


class KafkaEventSource(Iterator[DnsEvent]):
    def __init__(
        self,
        bootstrap_servers: str,
        topic: str = TOPIC,
        group_id: str = CONSUMER_GROUP,
    ) -> None:
        consumer_class, _ = _kafka_classes()
        self._consumer = consumer_class(
            topic,
            bootstrap_servers=bootstrap_servers,
            group_id=group_id,
            auto_offset_reset="latest",
            enable_auto_commit=True,
            value_deserializer=decode_event,
        )
        self._messages = iter(self._consumer)

    def __iter__(self) -> KafkaEventSource:
        return self

    def __next__(self) -> DnsEvent:
        return next(self._messages).value

    def close(self) -> None:
        self._consumer.close()
