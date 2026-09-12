import json
import tempfile
import unittest
from pathlib import Path

from src.engine import assess, assess_event, metrics
from src.loader import load_events
from src.models import ClosureEvidence
from src.remediation import validate_closure
from src.reporting import render_markdown


class EngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = load_events("data/synthetic_events.json")
        cls.findings = assess(cls.events)

    def test_findings_created(self):
        self.assertGreaterEqual(len(self.findings), 4)

    def test_sorted_by_risk(self):
        scores = [f.risk_score for f in self.findings]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_scores_bounded(self):
        self.assertTrue(all(0 <= f.risk_score <= 100 for f in self.findings))

    def test_ids_deterministic(self):
        self.assertEqual(assess_event(self.events[0]).finding_id, assess_event(self.events[0]).finding_id)

    def test_attack_mapping_present(self):
        self.assertTrue(all(f.attack_techniques and f.attack_techniques[0].startswith("T1021") for f in self.findings))

    def test_metrics(self):
        m = metrics(self.findings)
        self.assertEqual(m["total_findings"], len(self.findings))
        self.assertGreaterEqual(m["unique_destination_hosts"], 1)

    def test_report_contains_context(self):
        report = render_markdown(self.findings)
        self.assertIn("MITRE ATT&CK", report)
        self.assertIn("T1021", report)

    def test_duplicate_rejected(self):
        raw = json.loads(Path("data/synthetic_events.json").read_text())
        raw.append(raw[0])
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"; p.write_text(json.dumps(raw))
            with self.assertRaises(ValueError):
                load_events(p)

    def test_invalid_boolean_rejected(self):
        raw = json.loads(Path("data/synthetic_events.json").read_text())
        raw[0]["success"] = "true"
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "events.json"; p.write_text(json.dumps(raw))
            with self.assertRaises(ValueError):
                load_events(p)

    def test_valid_closure(self):
        ev = ClosureEvidence("LM-1", "owner", "CHG-1", "restricted SMB", True, True, True, True)
        self.assertEqual(validate_closure(ev)[0], "validated")

    def test_failed_retest_invalidates_closure(self):
        ev = ClosureEvidence("LM-1", "owner", "CHG-1", "restricted SMB", True, True, True, False)
        self.assertEqual(validate_closure(ev)[0], "invalid_closure")

    def test_missing_evidence_blocks_closure(self):
        ev = ClosureEvidence("LM-1", "", "CHG-1", "restricted SMB", True, True, False, False)
        self.assertEqual(validate_closure(ev)[0], "needs_evidence")


if __name__ == "__main__":
    unittest.main()
