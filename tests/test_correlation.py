import unittest

from sentinel_dns.correlation import CampaignCorrelator
from sentinel_dns.models import DnsEvent, Finding


class CampaignCorrelationTests(unittest.TestCase):
    def test_emits_one_incident_for_shared_indicator_across_three_hosts(self):
        correlator = CampaignCorrelator(window_seconds=60.0, min_hosts=3, min_finding_types=2)
        findings = [Finding("dga", 0.9), Finding("beacon", 0.9)]

        incidents = []
        for index, host in enumerate(("190.14.213.60", "190.14.212.86", "190.14.204.18")):
            event = DnsEvent(
                ts=1000.0 + index,
                ts_raw="synthetic",
                client_ip=host,
                port=53000,
                qname="xjs83kavqpwm.xyz",
                qtype="A",
                flags="+",
                server="172.19.1.2",
                customer="Hospital Nacional",
                site="Panama-East",
                zone="PA-EAST",
                etld1="xjs83kavqpwm.xyz",
            )
            incident = correlator.feed(event, findings)
            if incident:
                incidents.append(incident)

        self.assertEqual(len(incidents), 1)
        incident = incidents[0]
        self.assertEqual(incident.kind, "coordinated_malware_campaign")
        self.assertEqual(incident.site, "Panama-East")
        self.assertEqual(incident.domain, "xjs83kavqpwm.xyz")
        self.assertEqual(len(incident.affected_hosts), 3)

    def test_adds_site_nxdomain_spike_to_campaign_evidence(self):
        correlator = CampaignCorrelator(window_seconds=60.0, min_hosts=3, min_finding_types=2)
        for index in range(4):
            correlator.feed(
                DnsEvent(
                    ts=1000.0 + index,
                    ts_raw="synthetic",
                    client_ip="190.14.213.60",
                    port=54000 + index,
                    qname=f"missing-{index}.demo.invalid",
                    qtype="A",
                    flags="+",
                    server="172.19.1.2",
                    site="Panama-East",
                    rcode="NXDOMAIN",
                ),
                [],
            )
        incident = None
        for index, host in enumerate(("190.14.213.60", "190.14.212.86", "190.14.204.18")):
            incident = correlator.feed(
                DnsEvent(
                    ts=1010.0 + index,
                    ts_raw="synthetic",
                    client_ip=host,
                    port=53000,
                    qname="xjs83kavqpwm.xyz",
                    qtype="A",
                    flags="+",
                    server="172.19.1.2",
                    customer="Hospital Nacional",
                    site="Panama-East",
                    zone="PA-EAST",
                    etld1="xjs83kavqpwm.xyz",
                ),
                [Finding("dga", 0.9), Finding("beacon", 0.9)],
            )

        self.assertIsNotNone(incident)
        self.assertIn("NXDOMAIN spike: 4 queries in 60s", incident.signals)

    def test_does_not_emit_for_one_host_or_one_finding_type(self):
        correlator = CampaignCorrelator(window_seconds=60.0, min_hosts=3, min_finding_types=2)
        event = DnsEvent(
            ts=1000.0,
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
            etld1="xjs83kavqpwm.xyz",
        )

        self.assertIsNone(correlator.feed(event, [Finding("dga", 0.9)]))


if __name__ == "__main__":
    unittest.main()
