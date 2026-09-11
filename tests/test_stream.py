import unittest

from sentinel_dns.models import DnsEvent
from sentinel_dns.stream import assert_local_bootstrap, decode_event, encode_event


class StreamContractTests(unittest.TestCase):
    def test_versioned_event_round_trips_normalized_dns_attributes(self):
        original = DnsEvent(
            ts=1000.25,
            ts_raw="synthetic",
            client_ip="190.14.213.60",
            port=53000,
            qname="xjs83kavqpwm.xyz",
            qtype="A",
            flags="+",
            server="172.19.1.2",
            customer="Hospital Nacional",
            site="Panama-East",
            zone="PA-EAST",
            latency_ms=41.0,
            rcode="NXDOMAIN",
            timeout=False,
            injected=True,
            etld1="xjs83kavqpwm.xyz",
            sld="xjs83kavqpwm",
        )

        decoded = decode_event(encode_event(original))

        self.assertEqual(decoded, original)

    def test_rejects_non_local_kafka_broker(self):
        with self.assertRaises(PermissionError):
            assert_local_bootstrap("kafka.example.com:9092")


if __name__ == "__main__":
    unittest.main()
