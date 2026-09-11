import socket
import unittest

from daignosis.egress import GUARD
from daignosis.wazuh import format_alert
from daignosis.models import Incident


class EgressTests(unittest.TestCase):
    def tearDown(self):
        GUARD.restore()

    def test_blocks_public(self):
        GUARD.install()
        with self.assertRaises(PermissionError):
            socket.create_connection(("1.1.1.1", 443), timeout=0.2)

    def test_wazuh_json_shape(self):
        inc = Incident(
            ts=1.0,
            domain="xjs83kavqpwm.xyz",
            kind="possible_c2_beaconing",
            risk_score=92,
            severity="critical",
            signals=["DGA"],
            affected_hosts=["190.14.213.60"],
            customer="Hospital Nacional",
            site="Panama-East",
            explanation="Possible C2",
            recommended_action="Investigate",
        )
        alert = format_alert(inc)
        self.assertEqual(alert["decoder"]["name"], "daignosis")
        self.assertGreaterEqual(alert["rule"]["level"], 12)
        self.assertIn("daignosis", alert["rule"]["groups"])
        self.assertEqual(alert["data"]["dns.question.name"], "xjs83kavqpwm.xyz")


if __name__ == "__main__":
    unittest.main()
