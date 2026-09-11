import unittest

from daignosis.qoe import QoeEngine


class AdaptiveBaselineTests(unittest.TestCase):
    def test_deviation_from_site_baseline_drives_score(self):
        eng = QoeEngine(flush_every=0.0)
        now = 0.0
        for _ in range(15):
            for _ in range(40):
                eng.feed("Panama-East", "Hospital Nacional", "PA-EAST", 5.0, False, False, 400)
            now += 5.0
            eng.flush_due(now)
        for _ in range(40):
            eng.feed("Panama-East", "Hospital Nacional", "PA-EAST", 40.0, False, False, 400)
        now += 5.0
        snap = eng.flush_due(now)[0]
        fixed_for_40ms = 100.0 * (150.0 - 40.0) / 125.0
        self.assertLess(snap["components"]["latency"], fixed_for_40ms)
        self.assertGreater(snap["latency_z"], 1.0)


if __name__ == "__main__":
    unittest.main()