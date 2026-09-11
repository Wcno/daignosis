import unittest
from pathlib import Path

from sentinel_dns.models import Incident
from sentinel_dns.qvac_explain import Explainer


class QvacFailureBoundaryTests(unittest.TestCase):
    def test_unavailable_qvac_withholds_security_incident(self):
        emitted = []
        errors = []
        explainer = Explainer(cache_dir=Path("/tmp/qvac-test"), enabled=False)
        explainer.start(emitted.append, lambda _: None, errors.append)
        explainer.submit_incident(
            Incident(
                ts=1.0,
                domain="xjs83kavqpwm.xyz",
                kind="coordinated_malware_campaign",
                risk_score=90,
                severity="critical",
                signals=["DGA", "Beacon"],
                affected_hosts=["190.14.213.60", "190.14.212.86", "190.14.204.18"],
                customer="Hospital Nacional",
                site="Panama-East",
            )
        )

        self.assertEqual(emitted, [])
        self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
