import tempfile
import unittest
from pathlib import Path

from daignosis.clickhouse import MetricSink
from daignosis.models import Incident
from daignosis.pipeline import Pipeline
from daignosis.qvac_explain import Explainer
from daignosis.risk import _severity
from daignosis.state import AppState


def _inc(host: str, ts: float) -> Incident:
    return Incident(
        ts=ts,
        domain="xjs83kavqpwm.xyz",
        kind="possible_c2_beaconing",
        risk_score=70,
        severity=_severity(70),
        signals=["Query interval ~6s"],
        affected_hosts=[host],
        customer="TelcoCo",
        site="Panama-East",
    )


class CorrelationIntegrationTests(unittest.TestCase):
    def test_campaign_flows_to_state_and_wazuh(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            state = AppState()
            explainer = Explainer(cache_dir=tmp / "cache", enabled=False)
            sink = MetricSink(url="http://127.0.0.1:8123", var_dir=tmp / "var")
            pipe = Pipeline(state=state, explainer=explainer, sink=sink)

            hosts = ["10.0.0.11", "10.0.0.12", "10.0.0.13"]
            for i, host in enumerate(hosts):
                pipe.correlator.add(_inc(host, ts=1000.0 + i * 6))

            campaigns = pipe.correlator.poll(1060.0)
            self.assertEqual(len(campaigns), 1)

            pipe.explainer.start(pipe._on_explained, pipe._on_qoe_explained, pipe._on_case_explained)
            pipe.explainer.submit_case(campaigns[0])

            self.assertEqual(len(state.cases), 1)
            case = state.cases[0]
            self.assertEqual(case["domain"], "xjs83kavqpwm.xyz")
            self.assertEqual(case["hosts"], 3)
            self.assertIn("coordinated", case["explanation"].lower())

            self.assertEqual(state.incidents[0].kind, "coordinated_campaign")
            self.assertFalse(state.incidents[0].qvac_used)
            self.assertGreaterEqual(state.incidents[0].risk_score, 85)

            self.assertEqual(state.alerts[0]["full_log"].count("daignosis"), 1)


if __name__ == "__main__":
    unittest.main()