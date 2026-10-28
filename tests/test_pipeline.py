"""
Unit and Integration Tests for AI Pipeline, Validation, and Risk Scoring.
"""

import unittest
from ml.predict import (
    validate_event,
    calculate_risk_score,
    classify_threat_category,
    analyze_security_event,
    FEATURES
)


class TestAIPipeline(unittest.TestCase):

    def test_event_schema_validation(self):
        valid_input = {
            "login_attempts": 10,
            "failed_attempts": 5,
            "request_count": 200,
            "file_access_count": 10,
            "data_transfer_mb": 150.0,
            "unusual_location": 1,
            "unusual_time": 0,
            "privilege_level": 2
        }
        cleaned = validate_event(valid_input)
        self.assertEqual(cleaned["login_attempts"], 10)
        self.assertEqual(cleaned["failed_attempts"], 5)

        # Logical correction test: failed_attempts > login_attempts
        invalid_attempts = valid_input.copy()
        invalid_attempts["failed_attempts"] = 25
        invalid_attempts["login_attempts"] = 10
        corrected = validate_event(invalid_attempts)
        self.assertGreaterEqual(corrected["login_attempts"], corrected["failed_attempts"])

    def test_missing_feature_raises_error(self):
        incomplete = {"login_attempts": 5}
        with self.assertRaises(ValueError):
            validate_event(incomplete)

    def test_risk_scoring_and_severity_tiers(self):
        # 1. Low risk event
        normal_event = {
            "login_attempts": 1,
            "failed_attempts": 0,
            "request_count": 20,
            "file_access_count": 2,
            "data_transfer_mb": 10.0,
            "unusual_location": 0,
            "unusual_time": 0,
            "privilege_level": 1
        }
        risk, severity, _ = calculate_risk_score(normal_event, threat_probability=0.05, is_anomaly=False)
        self.assertLess(risk, 30)
        self.assertEqual(severity, "LOW")

        # 2. Critical threat event
        attack_event = {
            "login_attempts": 20,
            "failed_attempts": 18,
            "request_count": 800,
            "file_access_count": 30,
            "data_transfer_mb": 900.0,
            "unusual_location": 1,
            "unusual_time": 1,
            "privilege_level": 3
        }
        risk, severity, _ = calculate_risk_score(attack_event, threat_probability=0.99, is_anomaly=True)
        self.assertGreaterEqual(risk, 80)
        self.assertEqual(severity, "CRITICAL")

    def test_threat_taxonomy_classification(self):
        brute_force_event = {
            "login_attempts": 15,
            "failed_attempts": 12,
            "request_count": 250,
            "file_access_count": 2,
            "data_transfer_mb": 20.0,
            "unusual_location": 1,
            "unusual_time": 1,
            "privilege_level": 1
        }
        category = classify_threat_category(brute_force_event, prediction=1, is_anomaly=True, risk_score=90)
        self.assertEqual(category, "Brute Force Credential Attack")

    def test_end_to_end_analysis(self):
        sample = {
            "login_attempts": 2,
            "failed_attempts": 0,
            "request_count": 30,
            "file_access_count": 3,
            "data_transfer_mb": 15.0,
            "unusual_location": 0,
            "unusual_time": 0,
            "privilege_level": 1
        }
        result = analyze_security_event(sample)
        self.assertIn("risk_score", result)
        self.assertIn("severity", result)
        self.assertIn("threat_probability", result)
        self.assertIn("feature_contributions", result)


if __name__ == "__main__":
    unittest.main()
