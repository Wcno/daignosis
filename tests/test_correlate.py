import unittest

from daignosis.correlate import Campaign, Correlator, template_campaign
from daignosis.models import Incident
from daignosis.risk import _severity


def _inc(domain: str, site: str, host: str, kind: str = "dga", ts: float = 1000.0) -> Incident:
    risk = 60
    return Incident(
        ts=ts,
        domain=domain,
        kind=kind,
        risk_score=risk,
        severity=_severity(risk),
        signals=["probable"],
        affected_hosts=[host],
        customer="TelcoCo",
        site=site,
    )


class CorrelatorTests(unittest.TestCase):
    def test_groups_across_hosts_into_campaign(self):
        corr = Correlator(window_s=120, min_hosts=2, min_events=3)
        hosts = ["10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14"]
        for i, host in enumerate(hosts):
            corr.add(_inc("xjs83kavqpwm.xyz", "Panama-East", host, ts=1000.0 + i * 6))
        campaigns = corr.poll(1060.0)
        self.assertEqual(len(campaigns), 1)
        c = campaigns[0]
        self.assertEqual(c.domain, "xjs83kavqpwm.xyz")
        self.assertEqual(c.n_events, 4)
        self.assertGreaterEqual(c.n_hosts, 2)
        self.assertEqual(c.site, "Panama-East")

    def test_cooldown_prevents_duplicate(self):
        corr = Correlator(window_s=120, min_hosts=2, min_events=3, cooldown_s=300)
        for i in range(3):
            corr.add(_inc("c2.example.net", "Bogota-DC", f"10.0.1.{i}", ts=1000.0 + i))
        self.assertEqual(len(corr.poll(1010.0)), 1)
        self.assertEqual(len(corr.poll(1015.0)), 0)

    def test_not_enough_signal_no_campaign(self):
        corr = Correlator(min_hosts=2, min_events=3)
        corr.add(_inc("x.xyz", "P", "10.0.0.1", ts=1000.0))
        corr.add(_inc("x.xyz", "P", "10.0.0.2", ts=1001.0))
        self.assertEqual(corr.poll(1010.0), [])


class TemplateTests(unittest.TestCase):
    def _camp(self, hosts: int, events: int, repeated) -> Campaign:
        return Campaign(
            ts=1000.0,
            domain="d.xyz",
            site="S",
            customer="C",
            hosts=[f"10.0.0.{i}" for i in range(hosts)],
            kinds=["dga"],
            n_events=events,
            repeated_seconds=repeated,
        )

    def test_campaign_verdict(self):
        expl, _ = template_campaign(self._camp(5, 8, 6.0))
        self.assertIn("coordinated campaign", expl.lower())

    def test_single_host_verdict(self):
        expl, _ = template_campaign(self._camp(1, 2, None))
        self.assertIn("single host", expl.lower())


if __name__ == "__main__":
    unittest.main()