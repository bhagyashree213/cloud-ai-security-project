"""
Unit Tests for the Five Scikit-Learn Classification Models & Benchmarks.
Tests training, evaluation, pipeline construction, and inference across:
  1. Decision Tree Classifier
  2. Random Forest Classifier
  3. Logistic Regression
  4. Support Vector Machine (SVM)
  5. Gradient Boosting Classifier
"""

import unittest
from pathlib import Path
import pandas as pd
import numpy as np

from ml.preprocess import load_cybersecurity_dataset, FEATURES, TARGET_COLUMN
from ml.train_and_compare import get_five_candidate_models, evaluate_on_test_set
from ml.predict import analyze_security_event, validate_event


class TestFiveModels(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.X, cls.y, cls.df = load_cybersecurity_dataset()
        cls.X_train = cls.X.iloc[:800]
        cls.y_train = cls.y.iloc[:800]
        cls.X_test = cls.X.iloc[800:1000]
        cls.y_test = cls.y.iloc[800:1000]

    def test_five_candidate_models_exist(self):
        models = get_five_candidate_models()
        self.assertEqual(len(models), 5)
        expected_names = {
            "Decision Tree Classifier",
            "Random Forest Classifier",
            "Logistic Regression",
            "Support Vector Machine (SVM)",
            "Gradient Boosting Classifier"
        }
        self.assertEqual(set(models.keys()), expected_names)

    def test_all_five_models_train_and_evaluate(self):
        models = get_five_candidate_models()
        results = evaluate_on_test_set(models, self.X_train, self.X_test, self.y_train, self.y_test)

        self.assertEqual(len(results), 5)
        for name, r in results.items():
            self.assertIn("accuracy", r)
            self.assertIn("precision", r)
            self.assertIn("recall", r)
            self.assertIn("f1_score", r)
            self.assertIn("training_time_sec", r)
            self.assertIn("confusion_matrix", r)

            # Check valid score ranges
            self.assertGreaterEqual(r["accuracy"], 0.70)
            self.assertLessEqual(r["accuracy"], 1.0)
            self.assertGreaterEqual(r["f1_score"], 0.70)
            self.assertLessEqual(r["f1_score"], 1.0)
            self.assertGreater(r["training_time_sec"], 0.0)

    def test_normal_and_threat_event_inference(self):
        normal_sample = {
            "login_attempts": 1,
            "failed_attempts": 0,
            "request_count": 25,
            "file_access_count": 2,
            "data_transfer_mb": 12.0,
            "unusual_location": 0,
            "unusual_time": 0,
            "privilege_level": 1
        }
        normal_res = analyze_security_event(normal_sample)
        self.assertEqual(normal_res["prediction"], 0)
        self.assertLess(normal_res["threat_probability"], 0.5)
        self.assertIn(normal_res["severity"], ["LOW", "MEDIUM"])

        threat_sample = {
            "login_attempts": 25,
            "failed_attempts": 22,
            "request_count": 600,
            "file_access_count": 35,
            "data_transfer_mb": 750.0,
            "unusual_location": 1,
            "unusual_time": 1,
            "privilege_level": 3
        }
        threat_res = analyze_security_event(threat_sample)
        self.assertEqual(threat_res["prediction"], 1)
        self.assertGreater(threat_res["threat_probability"], 0.8)
        self.assertIn(threat_res["severity"], ["HIGH", "CRITICAL"])

    def test_invalid_input_and_missing_features(self):
        missing_input = {"login_attempts": 5}
        with self.assertRaises(ValueError):
            validate_event(missing_input)

        non_numeric_input = {
            "login_attempts": "not_a_number",
            "failed_attempts": 0,
            "request_count": 10,
            "file_access_count": 1,
            "data_transfer_mb": 5.0,
            "unusual_location": 0,
            "unusual_time": 0,
            "privilege_level": 1
        }
        with self.assertRaises(ValueError):
            validate_event(non_numeric_input)


if __name__ == "__main__":
    unittest.main()
