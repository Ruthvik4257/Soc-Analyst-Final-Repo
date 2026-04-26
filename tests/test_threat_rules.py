import unittest

from server.threat_rules import (
    DECISION_BLOCK,
    DECISION_FALSE_POSITIVE,
    DECISION_ESCALATE,
    validate_decision,
)


class ThreatRulesTestCase(unittest.TestCase):
    def test_auth_bruteforce_recommends_block(self):
        logs = []
        for idx in range(6):
            logs.append(
                {
                    "raw": "failed login invalid password from 203.0.113.5",
                    "fields": {
                        "timestamp": f"2026-04-26T10:00:0{idx}Z",
                        "src_ip": "203.0.113.5",
                        "event": "failed login",
                    },
                }
            )
        result = validate_decision({"type": "brute_force"}, logs)
        self.assertIn(result.recommended_decision, (DECISION_BLOCK, DECISION_ESCALATE))
        self.assertGreater(result.score, 0.3)

    def test_benign_impossible_travel_context_false_positive(self):
        logs = [
            {
                "raw": "user login from trusted vpn zscaler corporate vpn",
                "fields": {"timestamp": "2026-04-26T10:00:00Z", "event": "login"},
            }
        ]
        result = validate_decision({"type": "impossible_travel"}, logs)
        self.assertEqual(result.recommended_decision, DECISION_FALSE_POSITIVE)

    def test_cloud_high_risk_escalates_or_blocks(self):
        logs = [
            {
                "raw": "CreateAccessKey success for user bob",
                "fields": {"event": "CreateAccessKey", "src_ip": "198.51.100.66"},
            },
            {
                "raw": "StopLogging called on trail prod-main",
                "fields": {"event": "StopLogging", "src_ip": "198.51.100.66"},
            },
        ]
        result = validate_decision({"type": "cloud_alert"}, logs)
        self.assertIn(result.recommended_decision, (DECISION_ESCALATE, DECISION_BLOCK))
        self.assertGreater(result.confidence, 0.4)


if __name__ == "__main__":
    unittest.main()
