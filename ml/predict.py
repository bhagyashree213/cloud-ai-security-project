"""
Core AI Inference and Risk-Scoring Engine for CloudSentinel.
Provides:
  - Model loading and bundle unpacking (supports {"model": estimator, "features": [...]})
  - Strict input validation and feature ordering for the 8 standard security features
  - Calibrated threat probability prediction (Supervised Classifier)
  - Unsupervised anomaly detection and scoring (Isolation Forest)
  - Centralized composite Risk Scoring (0–100) and severity classification
  - Deterministic 6-category Threat Taxonomy attribution
  - Forensic feature contribution explainability and model consensus analysis
"""

from pathlib import Path
import sys
from typing import Dict, Any, Tuple, Optional, List
import joblib
import numpy as np
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

MODEL_DIR = BASE_DIR / "models"
DEFAULT_THREAT_MODEL_PATH = MODEL_DIR / "threat_model.pkl"
DEFAULT_ANOMALY_MODEL_PATH = MODEL_DIR / "anomaly_model.pkl"

# Exact 8 Standard Cybersecurity Telemetry Features
FEATURES: List[str] = [
    "login_attempts",
    "failed_attempts",
    "request_count",
    "file_access_count",
    "data_transfer_mb",
    "unusual_location",
    "unusual_time",
    "privilege_level",
]

# Standard 6-Category Threat Taxonomy
THREAT_CATEGORIES = [
    "Normal Activity",
    "Brute Force Credential Attack",
    "Data Exfiltration / Insider Threat",
    "DDoS / Request Flooding",
    "Privileged Account Anomaly",
    "Suspicious Security Activity"
]

# Normal User Population Baseline Medians (for explainability calculations)
FEATURE_BASELINES: Dict[str, float] = {
    "login_attempts": 2.0,
    "failed_attempts": 0.0,
    "request_count": 35.0,
    "file_access_count": 3.0,
    "data_transfer_mb": 15.0,
    "unusual_location": 0.0,
    "unusual_time": 0.0,
    "privilege_level": 1.0,
}


def load_model_bundle(model_path: Path) -> Tuple[Any, List[str]]:
    """
    Safely loads a joblib model bundle and extracts the underlying estimator.
    Handles both dictionary bundles {"model": estimator, "features": [...]} and raw estimators.
    Attaches detected model name as an internal attribute for human-readable display.
    """
    if not model_path.exists():
        raise FileNotFoundError(f"Model file not found at: {model_path}")

    bundle = joblib.load(model_path)
    if isinstance(bundle, dict):
        estimator = bundle.get("model", bundle)
        features = bundle.get("features", FEATURES)
        model_name = bundle.get("model_name")
    else:
        estimator = bundle
        features = FEATURES
        model_name = None

    if model_name:
        try:
            setattr(estimator, "_display_model_name", model_name)
        except Exception:
            pass

    return estimator, features


def get_model_display_name(estimator: Any, fallback: str = "Classifier") -> str:
    """Extracts clean human-readable name from estimator or pipeline."""
    if hasattr(estimator, "_display_model_name") and estimator._display_model_name:
        return str(estimator._display_model_name)
    if hasattr(estimator, "named_steps"):
        clf = estimator.named_steps.get("clf", estimator.named_steps.get("classifier"))
        if clf:
            if hasattr(clf, "estimator"):
                return type(clf.estimator).__name__
            return type(clf).__name__
    return getattr(estimator, "__class__", type(estimator)).__name__



def validate_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates input security event schema and coerces values into required numerical types.
    Enforces feature ordering and logical bounds (failed_attempts <= login_attempts).
    Raises ValueError on invalid or missing features.
    """
    cleaned: Dict[str, Any] = {}
    for feat in FEATURES:
        if feat not in event:
            raise ValueError(f"Missing required security feature: '{feat}'")
        try:
            if feat == "data_transfer_mb":
                cleaned[feat] = max(0.0, float(event[feat]))
            else:
                cleaned[feat] = max(0, int(event[feat]))
        except (ValueError, TypeError):
            raise ValueError(f"Feature '{feat}' must be a valid numerical value.")

    # Logical validation: failed attempts cannot exceed total login attempts
    if cleaned["failed_attempts"] > cleaned["login_attempts"]:
        cleaned["login_attempts"] = cleaned["failed_attempts"]

    # Binary flags validation (0 or 1)
    cleaned["unusual_location"] = 1 if cleaned["unusual_location"] else 0
    cleaned["unusual_time"] = 1 if cleaned["unusual_time"] else 0

    # Privilege level validation (0 to 3)
    cleaned["privilege_level"] = min(3, max(0, cleaned["privilege_level"]))

    return cleaned


def calculate_risk_score(
    event: Dict[str, Any],
    threat_probability: float,
    is_anomaly: bool,
    anomaly_score: float = 0.0
) -> Tuple[int, str, Dict[str, float]]:
    """
    Calculates composite Risk Score (0-100) using the centralized formula:
      - 50% Supervised Model Confidence (Threat Probability * 50)
      - 20% Unsupervised Anomaly Indicator (20 if Anomaly, normalized score)
      - 30% Domain Behavioral Heuristics (Failed logins, location, time, data volume, privilege)

    Operational Severity Classification:
      0  - 29: LOW
      30 - 59: MEDIUM
      60 - 79: HIGH
      80 - 100: CRITICAL

    Returns: (risk_score, severity, factor_contributions)
    """
    # 1. Supervised Model Component (0 to 50 pts)
    supervised_pts = min(50.0, max(0.0, float(threat_probability) * 50.0))

    # 2. Unsupervised Anomaly Component (0 to 20 pts)
    if is_anomaly:
        anomaly_pts = 16.0 + min(4.0, max(0.0, float(anomaly_score) * 4.0))
    else:
        anomaly_pts = 0.0

    # 3. Domain Heuristic Risk Indicators (0 to 30 pts)
    heuristic_pts = 0.0
    failed_attempts = event["failed_attempts"]
    login_attempts = event["login_attempts"]
    request_count = event["request_count"]
    data_transfer_mb = event["data_transfer_mb"]
    unusual_location = event["unusual_location"]
    unusual_time = event["unusual_time"]
    privilege_level = event["privilege_level"]

    # Failed authentication burst (credential stuffing)
    if failed_attempts >= 3:
        heuristic_pts += min(10.0, (failed_attempts - 2) * 2.0)

    # Location anomaly
    if unusual_location:
        heuristic_pts += 6.0

    # Temporal anomaly (off-hours access)
    if unusual_time:
        heuristic_pts += 4.0

    # High request frequency (DoS / scraping)
    if request_count >= 300:
        heuristic_pts += min(5.0, (request_count - 300) / 150.0 * 2.0)

    # High data volume egress (exfiltration)
    if data_transfer_mb >= 300.0:
        heuristic_pts += min(5.0, (data_transfer_mb - 300.0) / 200.0 * 2.0)

    # High-privilege account targeted or off-hours
    if privilege_level >= 2 and (unusual_location or unusual_time or failed_attempts > 0):
        heuristic_pts += 5.0

    capped_heuristics = min(30.0, heuristic_pts)
    raw_risk = supervised_pts + anomaly_pts + capped_heuristics
    risk_score = int(round(max(0.0, min(100.0, raw_risk))))

    # Standard Severity Classification
    if risk_score >= 80:
        severity = "CRITICAL"
    elif risk_score >= 60:
        severity = "HIGH"
    elif risk_score >= 30:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    factors = {
        "supervised_probability_contribution": round(supervised_pts, 1),
        "unsupervised_anomaly_contribution": round(anomaly_pts, 1),
        "heuristic_indicators_contribution": round(capped_heuristics, 1)
    }

    return risk_score, severity, factors


def classify_threat_category(
    event: Dict[str, Any],
    prediction: int,
    is_anomaly: bool,
    risk_score: int
) -> str:
    """
    Assigns threat taxonomy category based on behavioral evidence and telemetry characteristics.
    Uses the exact 6 standardized categories across the platform.
    """
    if prediction == 0 and not is_anomaly and risk_score < 30:
        return "Normal Activity"

    if event["failed_attempts"] >= 5 and event["login_attempts"] >= 7:
        return "Brute Force Credential Attack"

    if event["data_transfer_mb"] >= 350.0 and event["file_access_count"] >= 15:
        return "Data Exfiltration / Insider Threat"

    if event["request_count"] >= 500:
        return "DDoS / Request Flooding"

    if event["privilege_level"] >= 2 and (event["unusual_location"] or event["unusual_time"]):
        return "Privileged Account Anomaly"

    if prediction == 1 or is_anomaly:
        return "Suspicious Security Activity"

    return "Normal Activity"


def compute_feature_contributions(event: Dict[str, Any]) -> Dict[str, float]:
    """
    Calculates normalized percentage contribution for each feature relative to baseline.
    Assists security analysts in forensic root-cause analysis.
    """
    contributions: Dict[str, float] = {}
    for feat in FEATURES:
        val = event[feat]
        base = FEATURE_BASELINES[feat]
        if feat in ("unusual_location", "unusual_time"):
            contributions[feat] = 100.0 if val == 1 else 0.0
        elif feat == "privilege_level":
            contributions[feat] = round((val / 3.0) * 100.0, 1)
        else:
            diff = max(0.0, val - base)
            contributions[feat] = round(min(100.0, (diff / (base * 3.0 + 1.0)) * 100.0), 1)
    return contributions


def analyze_security_event(
    event_data: Dict[str, Any],
    threat_model_path: Optional[Path] = None,
    anomaly_model_path: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Unified end-to-end security analysis pipeline:
      1. Validates and coerces input event telemetry
      2. Executes supervised threat classifier (Random Forest)
      3. Executes unsupervised anomaly detector (Isolation Forest)
      4. Calculates composite 0–100 risk score and operational severity
      5. Maps event to standard 6-category threat taxonomy
      6. Computes forensic feature risk contributions and model consensus notes
    """
    validated = validate_event(event_data)
    X = pd.DataFrame([validated], columns=FEATURES)

    t_path = threat_model_path or DEFAULT_THREAT_MODEL_PATH
    a_path = anomaly_model_path or DEFAULT_ANOMALY_MODEL_PATH

    threat_model, _ = load_model_bundle(t_path)
    anomaly_model, _ = load_model_bundle(a_path)

    # 1. Supervised Prediction & Probability
    prediction = int(threat_model.predict(X)[0])
    if hasattr(threat_model, "predict_proba"):
        probs = threat_model.predict_proba(X)[0]
        classes = list(threat_model.classes_)
        probability = float(probs[classes.index(1)]) if 1 in classes else float(prediction)
    elif hasattr(threat_model, "decision_function"):
        df_val = threat_model.decision_function(X)[0]
        probability = float(1.0 / (1.0 + np.exp(-df_val)))
    else:
        probability = float(prediction)

    # 2. Unsupervised Anomaly Prediction (-1 is anomaly, 1 is inlier)
    raw_anomaly_pred = anomaly_model.predict(X)[0]
    is_anomaly = bool(raw_anomaly_pred == -1)

    if hasattr(anomaly_model, "decision_function"):
        anomaly_score = float(-anomaly_model.decision_function(X)[0])
    else:
        anomaly_score = 1.0 if is_anomaly else 0.0

    # 3. Composite Risk Scoring & Severity
    risk_score, severity, risk_factors = calculate_risk_score(
        validated, probability, is_anomaly, anomaly_score
    )

    # 4. Standard Threat Taxonomy
    threat_type = classify_threat_category(validated, prediction, is_anomaly, risk_score)

    # 5. Explainability & Model Concordance
    feature_contributions = compute_feature_contributions(validated)

    if prediction == 1 and not is_anomaly:
        disagreement_note = "Supervised classifier flagged threat signature; anomaly detector evaluated within population variance."
    elif prediction == 0 and is_anomaly:
        disagreement_note = "Zero-day / novelty alert: Unsupervised model detected abnormal behavioral deviation not recognized by classifier."
    else:
        disagreement_note = "Supervised classifier and unsupervised detector agree on event classification."

    model_name = get_model_display_name(threat_model, "Random Forest Classifier")
    anomaly_model_name = get_model_display_name(anomaly_model, "Isolation Forest")

    return {
        "event": validated,
        "prediction": prediction,
        "threat_status": "THREAT DETECTED" if prediction == 1 else "NORMAL",
        "threat_probability": round(probability, 4),
        "is_anomaly": is_anomaly,
        "anomaly_status": "ANOMALY DETECTED" if is_anomaly else "NORMAL BEHAVIOR",
        "anomaly_score": round(anomaly_score, 4),
        "risk_score": risk_score,
        "severity": severity,
        "threat_type": threat_type,
        "model_used": model_name,
        "anomaly_model_used": anomaly_model_name,
        "risk_factors": risk_factors,
        "feature_contributions": feature_contributions,
        "disagreement_note": disagreement_note
    }


if __name__ == "__main__":
    sample_event = {
        "login_attempts": 12,
        "failed_attempts": 10,
        "request_count": 450,
        "file_access_count": 18,
        "data_transfer_mb": 520.0,
        "unusual_location": 1,
        "unusual_time": 1,
        "privilege_level": 3
    }
    result = analyze_security_event(sample_event)
    print("=== Centralized Threat Analysis Result ===")
    for k, v in result.items():
        print(f"  {k}: {v}")
