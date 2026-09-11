import unittest
from pathlib import Path

from daignosis.kafka_source import iter_kafka_stream, json_to_event, message_to_event

SAMPLE = Path(__file__).resolve().parent / "fixtures" / "queries.sample"


class MessageTests(unittest.TestCase):
    def test_bind_line_message(self):
        line = SAMPLE.read_text(encoding="utf-8").splitlines()[0]
        ev = message_to_event(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.qname, "www.apple.com")
        self.assertEqual(ev.client_ip, "190.102.59.241")

    def test_json_message_mapping(self):
        raw = (
            '{"qname":"xjs83kavqpwm.xyz","client_ip":"190.14.210.102","qtype":"A",'
            '"rcode":"NXDOMAIN","latency_ms":12.5,"site":"Panama-East",'
            '"customer":"TelcoCo","server":"172.19.1.2","ts":1700000000.0}'
        )
        ev = message_to_event(raw)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.qname, "xjs83kavqpwm.xyz")
        self.assertEqual(ev.client_ip, "190.14.210.102")
        self.assertEqual(ev.rcode, "NXDOMAIN")
        self.assertEqual(ev.latency_ms, 12.5)
        self.assertEqual(ev.site, "Panama-East")
        self.assertEqual(ev.customer, "TelcoCo")
        self.assertGreater(ev.ts, 0)

    def test_json_bytes_message(self):
        ev = message_to_event(b'{"qname":"a.b.xyz","qtype":"TXT"}')
        self.assertIsNotNone(ev)
        self.assertEqual(ev.qname, "a.b.xyz")

    def test_json_missing_qname_returns_none(self):
        self.assertIsNone(json_to_event({"latency": 5}))
        self.assertIsNone(message_to_event('{"not_a_name":1}'))

    def test_garbage_returns_none(self):
        self.assertIsNone(message_to_event("not a bind line"))
        self.assertIsNone(message_to_event(None))


class StreamTests(unittest.TestCase):
    def test_stream_filters_invalid(self):
        src = iter_kafka_stream(
            iter(
                [
                    '{"qname":"evil.xyz","client_ip":"10.0.0.1"}',
                    "garbage",
                    None,
                ]
            )
        )
        events = list(src)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].qname, "evil.xyz")


if __name__ == "__main__":
    unittest.main()