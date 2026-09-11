import unittest

from daignosis.detect import DetectorBank, dga_score, typosquat
from daignosis.features import extract
from daignosis.models import DnsEvent
from daignosis.overlay import Overlay
from daignosis.risk import aggregate


def ev(qname: str, ip: str = "190.14.213.60", ts: float = 1000.0) -> DnsEvent:
    row = DnsEvent(
        ts=ts,
        ts_raw="t",
        client_ip=ip,
        port=1,
        qname=qname,
        qtype="A",
        flags="+",
        server="172.19.1.2",
    )
    return Overlay(rng=__import__("random").Random(1)).enrich(row)


class DetectTests(unittest.TestCase):
    def test_apple_not_dga(self):
        e = ev("www.apple.com")
        self.assertLess(dga_score(extract(e), e), 0.4)

    def test_injected_is_dga(self):
        e = ev("xjs83kavqpwm.xyz")
        self.assertGreaterEqual(dga_score(extract(e), e), 0.55)

    def test_typosquat_homoglyph(self):
        e = ev("micros0ft.com")
        f = typosquat(e)
        self.assertIsNotNone(f)
        self.assertEqual(f.kind, "typosquat")

    def test_beacon_and_campaign_risk(self):
        bank = DetectorBank()
        domain = "xjs83kavqpwm.xyz"
        hosts = [f"190.14.213.{i}" for i in range(60, 65)]
        last = None
        for k in range(6):
            for ip in hosts:
                e = ev(domain, ip=ip, ts=1000 + k * 6)
                last = bank.feed(e, extract(e))
        self.assertTrue(any(f.kind == "beacon" for f in last))
        inc = aggregate(1000, domain, last, bank.affected(domain), "Hospital Nacional", "Panama-East")
        self.assertIsNotNone(inc)
        self.assertGreaterEqual(inc.risk_score, 70)
        self.assertEqual(inc.kind, "possible_c2_beaconing")


if __name__ == "__main__":
    unittest.main()
