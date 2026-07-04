"""Stdlib-only tests for SlotSettleGate (20+ cases)."""

import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from SlotSettleGate.cli import main, sample_packet
from SlotSettleGate.engine import AuditLogger, evaluate_packet


class TestSlotSettleGate(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.original_cwd = os.getcwd()
        os.chdir(self.test_dir)

    def tearDown(self):
        os.chdir(self.original_cwd)
        shutil.rmtree(self.test_dir)

    def test_01_authorized_packet(self):
        result = evaluate_packet(sample_packet("authorized"))
        self.assertEqual(result["verdict"], "authorized")

    def test_02_review_packet(self):
        packet = sample_packet("authorized")
        packet["settlement"]["compliance_score"] = 0.92
        result = evaluate_packet(packet)
        self.assertEqual(result["verdict"], "review")

    def test_03_vetoed_execution_outside_slot(self):
        packet = sample_packet("authorized")
        packet["slot"]["execution_unix"] = packet["slot"]["slot_end_unix"] + 1
        result = evaluate_packet(packet)
        self.assertEqual(result["verdict"], "vetoed")

    def test_04_vetoed_missing_reauth(self):
        packet = sample_packet("authorized")
        packet["slot"]["reauth_required"] = True
        packet["slot"]["reauth_granted"] = False
        result = evaluate_packet(packet)
        self.assertEqual(result["verdict"], "vetoed")

    def test_05_vetoed_invalid_auth_hash(self):
        packet = sample_packet("authorized")
        packet["slot"]["authorization_hash"] = "not-a-hash"
        result = evaluate_packet(packet)
        self.assertEqual(result["verdict"], "vetoed")

    def test_06_vetoed_rules_quorum_fail(self):
        packet = sample_packet("authorized")
        packet["settlement"]["rules_passed"] = 2
        result = evaluate_packet(packet)
        self.assertEqual(result["verdict"], "vetoed")

    def test_07_review_partial_rules(self):
        packet = sample_packet("authorized")
        packet["settlement"]["rules_passed"] = 3
        result = evaluate_packet(packet)
        self.assertEqual(result["verdict"], "review")

    def test_08_vetoed_low_compliance(self):
        packet = sample_packet("authorized")
        packet["settlement"]["compliance_score"] = 0.7
        result = evaluate_packet(packet)
        self.assertEqual(result["verdict"], "vetoed")

    def test_09_vetoed_risk_above_threshold(self):
        packet = sample_packet("authorized")
        packet["veto_escrow"]["risk_score"] = 0.85
        result = evaluate_packet(packet)
        self.assertEqual(result["verdict"], "vetoed")

    def test_10_review_risk_near_threshold(self):
        packet = sample_packet("authorized")
        packet["veto_escrow"]["risk_score"] = 0.65
        result = evaluate_packet(packet)
        self.assertEqual(result["verdict"], "review")

    def test_11_vetoed_interrupt_requested(self):
        packet = sample_packet("authorized")
        packet["veto_escrow"]["interrupt_requested"] = True
        result = evaluate_packet(packet)
        self.assertEqual(result["verdict"], "vetoed")

    def test_12_vetoed_escrow_inactive(self):
        packet = sample_packet("authorized")
        packet["veto_escrow"]["escrow_active"] = False
        result = evaluate_packet(packet)
        self.assertEqual(result["verdict"], "vetoed")

    def test_13_vetoed_invalid_packet_type(self):
        result = evaluate_packet("bad")
        self.assertEqual(result["verdict"], "vetoed")

    def test_14_deterministic_repeat(self):
        packet = sample_packet("authorized")
        self.assertEqual(evaluate_packet(packet), evaluate_packet(packet))

    def test_15_vetoed_slot_window_exceeds_duration(self):
        packet = sample_packet("authorized")
        packet["slot"]["slot_end_unix"] = packet["slot"]["slot_start_unix"] + 1000
        packet["slot"]["duration_limit_sec"] = 300
        result = evaluate_packet(packet)
        self.assertEqual(result["verdict"], "vetoed")

    def test_16_vetoed_negative_amount(self):
        packet = sample_packet("authorized")
        packet["settlement"]["amount_usd"] = -1.0
        result = evaluate_packet(packet)
        self.assertEqual(result["verdict"], "vetoed")

    def test_17_audit_logger_append_and_verify(self):
        logger = AuditLogger("ledger.json")
        packet = sample_packet("authorized")
        result = evaluate_packet(packet)
        logger.append(packet, result, "2026-07-04T00:00:00+00:00")
        logger.append(packet, result, "2026-07-04T00:00:01+00:00")
        self.assertTrue(logger.verify_chain())

    def test_18_audit_tamper_detection(self):
        logger = AuditLogger("ledger.json")
        packet = sample_packet("authorized")
        result = evaluate_packet(packet)
        logger.append(packet, result, "2026-07-04T00:00:00+00:00")
        entries = logger.load_log()
        entries[0]["verdict"] = "vetoed"
        with open("ledger.json", "w", encoding="utf-8") as handle:
            json.dump(entries, handle)
        self.assertFalse(logger.verify_chain())

    def test_19_cli_sample(self):
        code = main(["sample", "--out", "examples"])
        self.assertEqual(code, 0)
        self.assertTrue(os.path.exists("examples/authorized.json"))

    def test_20_cli_evaluate_and_report(self):
        main(["sample", "--out", "examples"])
        code = main(["evaluate", "--input", "examples/authorized.json", "--output", "out.json"])
        self.assertEqual(code, 0)
        with open("out.json", encoding="utf-8") as handle:
            payload = json.load(handle)
        self.assertEqual(payload["result"]["verdict"], "authorized")
        code = main(["report", "--input", "out.json", "--out", "out.md"])
        self.assertEqual(code, 0)
        with open("out.md", encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("AUTHORIZED", text)

    def test_21_three_sample_verdicts(self):
        self.assertEqual(evaluate_packet(sample_packet("authorized"))["verdict"], "authorized")
        review = sample_packet("review")
        self.assertEqual(evaluate_packet(review)["verdict"], "review")
        self.assertEqual(evaluate_packet(sample_packet("vetoed"))["verdict"], "vetoed")


if __name__ == "__main__":
    unittest.main()