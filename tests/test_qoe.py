import unittest

from sentinel_dns.qoe import QoeEngine


class QoeTests(unittest.TestCase):
    def test_latency_is_root_cause(self):
        eng = QoeEngine(flush_every=0.0)
        for _ in range(40):
            eng.feed("Panama-East", "Hospital Nacional", "PA-EAST", 22.0, False, False, 400)
        first = eng.flush_due(1000)[0]
        self.assertGreaterEqual(first["qoe_score"], 80)
        for _ in range(40):
            eng.feed("Panama-East", "Hospital Nacional", "PA-EAST", 96.0, False, False, 400)
        second = eng.flush_due(1005)[0]
        self.assertEqual(second["root_cause"], "latency")
        self.assertLess(second["qoe_score"], first["qoe_score"])


if __name__ == "__main__":
    unittest.main()
