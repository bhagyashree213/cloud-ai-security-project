"""
Security Monitoring and Event Ingestion Module for CloudSentinel.
Provides:
  1. Safe, read-only authorized HTTP endpoint health and security header checks.
  2. Batch security event ingestion from CSV/JSON with schema validation.
  3. Real-time simulated security event streaming for academic viva demonstrations.
"""

from pathlib import Path
import sys
import time
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
import requests
import pandas as pd

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from ml.predict import analyze_security_event, FEATURES
from database.database import save_event, log_audit


def check_authorized_endpoint(target_url: str) -> Dict[str, Any]:
    """
    Performs a safe, read-only HTTP health check and security header inspection
    against an authorized website or local endpoint that the user owns or has permission to test.
    Never executes destructive scans, exploits, or brute-force tests.
    """
    target = target_url.strip()
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target

    start_time = time.time()
    try:
        response = requests.get(target, timeout=5, headers={"User-Agent": "CloudSentinel-HealthMonitor/1.0"})
        latency_ms = round((time.time() - start_time) * 1000, 2)
        headers = response.headers

        # Check defensive security headers
        sec_headers = {
            "Strict-Transport-Security": "Strict-Transport-Security" in headers,
            "X-Frame-Options": "X-Frame-Options" in headers,
            "X-Content-Type-Options": "X-Content-Type-Options" in headers,
            "Content-Security-Policy": "Content-Security-Policy" in headers,
        }
        missing_headers = [h for h, present in sec_headers.items() if not present]

        return {
            "success": True,
            "url": target,
            "status_code": response.status_code,
            "latency_ms": latency_ms,
            "server": headers.get("Server", "Unknown"),
            "security_headers": sec_headers,
            "missing_headers": missing_headers,
            "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "disclaimer": "Safe, read-only health & header evaluation. Does not prove internal application security."
        }
    except requests.exceptions.RequestException as e:
        latency_ms = round((time.time() - start_time) * 1000, 2)
        return {
            "success": False,
            "url": target,
            "error": str(e),
            "latency_ms": latency_ms,
            "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "disclaimer": "Endpoint could not be reached or request timed out."
        }


def import_security_events_file(
    file_bytes_or_buffer,
    filename: str,
    user_id: Optional[int] = None,
    username: str = "System"
) -> Dict[str, Any]:
    """
    Imports and analyzes security events from an uploaded CSV or JSON file.
    Validates schema against model features and saves predictions into the unified database.
    """
    errors = []
    analyzed_count = 0
    threats_count = 0
    high_critical_alerts = 0

    try:
        if filename.endswith(".csv"):
            df = pd.read_csv(file_bytes_or_buffer)
        elif filename.endswith(".json"):
            df = pd.read_json(file_bytes_or_buffer)
        else:
            return {"success": False, "error": "Unsupported file format. Please upload CSV or JSON."}
    except Exception as e:
        return {"success": False, "error": f"Failed to parse file: {str(e)}"}

    # Check for missing features
    missing_cols = [f for f in FEATURES if f not in df.columns]
    if missing_cols:
        return {
            "success": False,
            "error": f"Missing required feature columns: {', '.join(missing_cols)}"
        }

    for idx, row in df.iterrows():
        try:
            event = {f: row[f] for f in FEATURES}
            analysis = analyze_security_event(event)

            log_id = save_event(
                event=analysis["event"],
                probability=analysis["threat_probability"],
                anomaly=analysis["is_anomaly"],
                risk=analysis["risk_score"],
                severity=analysis["severity"],
                threat_type=analysis["threat_type"],
                user_id=user_id,
                source=f"Import ({filename})",
                model_used=analysis["model_used"],
                anomaly_model_used=analysis["anomaly_model_used"],
                contributing_factors=analysis["risk_factors"]
            )

            analyzed_count += 1
            if analysis["prediction"] == 1 or analysis["is_anomaly"]:
                threats_count += 1
            if analysis["severity"] in ("HIGH", "CRITICAL"):
                high_critical_alerts += 1

        except Exception as e:
            errors.append(f"Row {idx+1}: {str(e)}")

    log_audit(
        user_id=user_id,
        username=username,
        action="EVENT_BATCH_IMPORT",
        details=f"Imported {analyzed_count} events from {filename} ({threats_count} threats, {high_critical_alerts} alerts)"
    )

    return {
        "success": True,
        "total_analyzed": analyzed_count,
        "threats_detected": threats_count,
        "high_critical_alerts": high_critical_alerts,
        "errors": errors[:10]  # Return sample of errors if any
    }


def generate_demonstration_event(profile: str = "mixed") -> Dict[str, Any]:
    """
    Generates a realistic simulated telemetry payload for a specified demonstration profile.
    Profiles: 'normal', 'brute_force', 'data_exfiltration', 'ddos', 'privilege_anomaly', 'mixed'.
    """
    import numpy as np

    if profile == "mixed":
        chosen_profile = np.random.choice(
            ["normal", "brute_force", "data_exfiltration", "ddos", "privilege_anomaly"],
            p=[0.55, 0.15, 0.12, 0.12, 0.06]
        )
    else:
        chosen_profile = profile

    if chosen_profile == "brute_force":
        login_attempts = int(np.random.randint(10, 28))
        failed_attempts = int(np.random.randint(login_attempts - 2, login_attempts + 1))
        request_count = int(np.random.randint(180, 420))
        file_access_count = int(np.random.randint(1, 6))
        data_transfer_mb = round(float(np.random.uniform(8.0, 45.0)), 2)
        unusual_location = 1
        unusual_time = int(np.random.choice([0, 1], p=[0.2, 0.8]))
        privilege_level = 1
        source = "Simulated Stream (Brute Force)"

    elif chosen_profile == "data_exfiltration":
        login_attempts = int(np.random.randint(1, 3))
        failed_attempts = 0
        request_count = int(np.random.randint(300, 700))
        file_access_count = int(np.random.randint(28, 65))
        data_transfer_mb = round(float(np.random.uniform(450.0, 1500.0)), 2)
        unusual_location = int(np.random.choice([0, 1], p=[0.4, 0.6]))
        unusual_time = 1
        privilege_level = int(np.random.choice([2, 3]))
        source = "Simulated Stream (Data Exfiltration)"

    elif chosen_profile == "ddos":
        login_attempts = int(np.random.randint(6, 16))
        failed_attempts = int(np.random.randint(2, 6))
        request_count = int(np.random.randint(700, 2000))
        file_access_count = int(np.random.randint(10, 25))
        data_transfer_mb = round(float(np.random.uniform(250.0, 850.0)), 2)
        unusual_location = 1
        unusual_time = 0
        privilege_level = 1
        source = "Simulated Stream (DDoS Flood)"

    elif chosen_profile == "privilege_anomaly":
        login_attempts = int(np.random.randint(2, 5))
        failed_attempts = int(np.random.randint(1, 3))
        request_count = int(np.random.randint(160, 380))
        file_access_count = int(np.random.randint(18, 40))
        data_transfer_mb = round(float(np.random.uniform(120.0, 380.0)), 2)
        unusual_location = 1
        unusual_time = 1
        privilege_level = 3
        source = "Simulated Stream (Privilege Escalation)"

    else:  # normal
        login_attempts = int(np.random.choice([1, 2, 3], p=[0.75, 0.20, 0.05]))
        failed_attempts = int(np.random.choice([0, 1], p=[0.92, 0.08]))
        if failed_attempts > login_attempts:
            failed_attempts = 0
        request_count = int(np.random.randint(15, 60))
        file_access_count = int(np.random.randint(1, 6))
        data_transfer_mb = round(float(np.random.uniform(5.0, 35.0)), 2)
        unusual_location = 0
        unusual_time = 0
        privilege_level = 1
        source = "Simulated Stream (Normal User)"

    event = {
        "login_attempts": login_attempts,
        "failed_attempts": failed_attempts,
        "request_count": request_count,
        "file_access_count": file_access_count,
        "data_transfer_mb": data_transfer_mb,
        "unusual_location": unusual_location,
        "unusual_time": unusual_time,
        "privilege_level": privilege_level,
    }
    return {"event": event, "source": source, "profile": chosen_profile}


def process_live_simulation_tick(profile: str = "mixed", user_id: Optional[int] = None) -> Dict[str, Any]:
    """Generates a simulated event, runs AI analysis, and saves to database."""
    item = generate_demonstration_event(profile)
    analysis = analyze_security_event(item["event"])

    log_id = save_event(
        event=analysis["event"],
        probability=analysis["threat_probability"],
        anomaly=analysis["is_anomaly"],
        risk=analysis["risk_score"],
        severity=analysis["severity"],
        threat_type=analysis["threat_type"],
        user_id=user_id,
        source=item["source"],
        model_used=analysis["model_used"],
        anomaly_model_used=analysis["anomaly_model_used"],
        contributing_factors=analysis["risk_factors"]
    )

    analysis["log_id"] = log_id
    analysis["simulation_source"] = item["source"]
    return analysis
