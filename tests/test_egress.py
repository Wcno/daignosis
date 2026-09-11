import socket
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from daignosis.egress import GUARD
from daignosis.wazuh import WazuhWebhook, format_alert
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

    def test_wazuh_webhook_delivers_local_alert(self):
        received = []

        class Receiver(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(self.rfile.read(int(self.headers["Content-Length"])))
                self.send_response(202)
                self.end_headers()

            def log_message(self, fmt, *args):
                return

        server = HTTPServer(("127.0.0.1", 0), Receiver)
        thread = threading.Thread(target=server.handle_request)
        thread.start()
        try:
            hook = WazuhWebhook(f"http://127.0.0.1:{server.server_port}/alerts")
            self.assertTrue(hook.send({"rule": {"id": "100001"}}))
            thread.join(timeout=1)
            self.assertEqual(received, [b'{"rule": {"id": "100001"}}'])
        finally:
            server.server_close()

    def test_wazuh_webhook_rejects_public_endpoint(self):
        with self.assertRaises(PermissionError):
            WazuhWebhook("https://example.com/wazuh")


if __name__ == "__main__":
    unittest.main()
