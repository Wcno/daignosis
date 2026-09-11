import unittest
from pathlib import Path

from daignosis.parse import parse_line

SAMPLE = Path(__file__).resolve().parent / "fixtures" / "queries.sample"


class ParseTests(unittest.TestCase):
    def test_apple_line(self):
        line = SAMPLE.read_text(encoding="utf-8").splitlines()[0]
        ev = parse_line(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.qname, "www.apple.com")
        self.assertEqual(ev.client_ip, "190.102.59.241")
        self.assertEqual(ev.qtype, "A")
        self.assertGreater(ev.ts, 0)

    def test_garbage(self):
        self.assertIsNone(parse_line("not a bind line"))


if __name__ == "__main__":
    unittest.main()
