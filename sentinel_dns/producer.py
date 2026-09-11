from __future__ import annotations

import time
from collections.abc import Iterator

from sentinel_dns.inject import Scenario
from sentinel_dns.models import DnsEvent
from sentinel_dns.overlay import Overlay
from sentinel_dns.stream import KafkaPublisher


class DemoProducer:
    """Publishes normalized benign traffic and the deterministic campaign to Kafka."""

    def __init__(self, publisher: KafkaPublisher, source: Iterator[DnsEvent], qps: float = 420.0) -> None:
        self.publisher = publisher
        self.source = source
        self.qps = qps
        self.overlay = Overlay()
        self.scenario = Scenario()
        self._paced_at = time.monotonic()
        self._paced_count = 0

    def run(self) -> None:
        try:
            while True:
                if self.scenario.degrade_on():
                    self.overlay.degrade("Panama-East")
                for event in self.scenario.due_events(time.time()):
                    self._publish(event)
                try:
                    event = next(self.source)
                except StopIteration:
                    return
                self._publish(event)
        except KeyboardInterrupt:
            return
        finally:
            self.publisher.close()

    def _publish(self, event: DnsEvent) -> None:
        self.overlay.enrich(event)
        self.publisher.publish(event)
        self._paced_count += 1
        now = time.monotonic()
        elapsed = now - self._paced_at
        if elapsed >= 1.0:
            self._paced_at = now
            self._paced_count = 0
            return
        ahead = self._paced_count / self.qps - elapsed
        if ahead > 0:
            time.sleep(ahead)
