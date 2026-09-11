import threading
import unittest

from sentinel_dns.server import serve
from sentinel_dns.state import AppState
from sentinel_dns.webhook import WazuhWebhook


class WazuhWebhookTests(unittest.TestCase):
    def test_delivers_wazuh_compatible_alert_to_local_receiver(self):
        state = AppState()
        httpd = serve(state, "127.0.0.1", 0)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            port = httpd.server_address[1]
            delivered = WazuhWebhook(f"http://127.0.0.1:{port}/ingest/wazuh").deliver(
                {"decoder": {"name": "sentinel-dns"}, "data": {"site": "Panama-East"}}
            )
        finally:
            httpd.shutdown()
            thread.join()
            httpd.server_close()

        self.assertTrue(delivered)
        self.assertEqual(state.alerts[0]["data"]["site"], "Panama-East")


if __name__ == "__main__":
    unittest.main()
