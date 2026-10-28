"""
Data Preprocessing and Feature Engineering Module for CloudSentinel.
Defines:
  - Standardized 8 cybersecurity telemetry features and their domain meanings
  - Target variable definition ('threat': 0 = Normal, 1 = Potential Threat)
  - Dataset loading and validation with class balance reporting
  - Leak-free scikit-learn preprocessing pipelines (StandardScaler for linear/kernel models)
"""

from pathlib import Path
import sys
from typing import Tuple, Dict, Any, List
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

DATA_DIR = BASE_DIR / "data"
BENCHMARK_DATASET_PATH = DATA_DIR / "security_logs_benchmark.csv"
SEED_DATASET_PATH = DATA_DIR / "security_logs.csv"

# Exact 8 Telemetry Features
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

TARGET_COLUMN: str = "threat"

# Detailed Domain Explanations for Academic Viva & UI Tooltips
FEATURE_METADATA: Dict[str, Dict[str, Any]] = {
    "login_attempts": {
        "name": "Total Login Attempts",
        "type": "Numerical (Integer)",
        "unit": "Count",
        "description": "Total number of authentication attempts initiated within the observation window.",
        "security_significance": "Spikes indicate automated credential guessing, brute force, or credential stuffing attacks.",
        "baseline_normal": "1 to 3 attempts"
    },
    "failed_attempts": {
        "name": "Failed Login Attempts",
        "type": "Numerical (Integer)",
        "unit": "Count",
        "description": "Count of unsuccessful password or multi-factor authentication challenges.",
        "security_significance": "Key indicator of dictionary attacks or brute force when failed_attempts closely tracks login_attempts.",
        "baseline_normal": "0 to 1 failures"
    },
    "request_count": {
        "name": "HTTP Request Velocity",
        "type": "Numerical (Integer)",
        "unit": "Requests",
        "description": "Total volume of HTTP/HTTPS requests dispatched to server endpoints.",
        "security_significance": "Anomalous high volumes indicate Application-Layer DDoS, web scraping, or automated API fuzzing.",
        "baseline_normal": "15 to 60 requests"
    },
    "file_access_count": {
        "name": "Sensitive Files Accessed",
        "type": "Numerical (Integer)",
        "unit": "Files",
        "description": "Count of system files, confidential directories, or document assets queried.",
        "security_significance": "Excessive reads signify directory traversal, configuration reconnaissance, or internal file harvesting.",
        "baseline_normal": "1 to 5 files"
    },
    "data_transfer_mb": {
        "name": "Egress Data Volume",
        "type": "Numerical (Float)",
        "unit": "Megabytes (MB)",
        "description": "Total network payload size transferred outbound from the target system.",
        "security_significance": "Large egress spikes indicate unauthorized database exfiltration, archive exfiltration, or staging.",
        "baseline_normal": "5.0 to 35.0 MB"
    },
    "unusual_location": {
        "name": "Geographic / Subnet Anomaly",
        "type": "Categorical / Binary (0 or 1)",
        "unit": "Flag",
        "description": "1 if request originated from an unrecognized IP range, foreign ASN, or VPN/Tor exit node; 0 if trusted.",
        "security_significance": "Geographic distance anomalies suggest credential compromise or proxy-based remote attacker interaction.",
        "baseline_normal": "0 (Trusted known subnet)"
    },
    "unusual_time": {
        "name": "Temporal Access Window",
        "type": "Categorical / Binary (0 or 1)",
        "unit": "Flag",
        "description": "1 if activity occurred during non-business off-hours (e.g. 11:00 PM – 05:00 AM); 0 during working hours.",
        "security_significance": "Attackers frequently conduct stealth operations off-hours to avoid real-time human SOC detection.",
        "baseline_normal": "0 (Normal operating hours)"
    },
    "privilege_level": {
        "name": "Account Authorization Tier",
        "type": "Ordinal (0 to 3)",
        "unit": "Level",
        "description": "Privilege scope of the targeted account: 0=Guest, 1=Standard User, 2=Supervisor/Staff, 3=Root/Admin.",
        "security_significance": "High-privilege accounts (Levels 2 and 3) represent critical crown jewels; anomalies trigger elevated risk.",
        "baseline_normal": "Level 1 (Standard User)"
    }
}


def load_cybersecurity_dataset(dataset_path: Path = None) -> Tuple[pd.DataFrame, pd.Series, pd.DataFrame]:
    """
    Loads and validates the labeled cybersecurity dataset.
    Prioritizes benchmark dataset (1,200 events) or falls back to seed dataset.
    Returns: (X, y, full_df)
    """
    if dataset_path and Path(dataset_path).exists():
        target_path = Path(dataset_path)
    elif BENCHMARK_DATASET_PATH.exists():
        target_path = BENCHMARK_DATASET_PATH
    elif SEED_DATASET_PATH.exists():
        target_path = SEED_DATASET_PATH
    else:
        raise FileNotFoundError(
            f"No cybersecurity dataset found at {BENCHMARK_DATASET_PATH} or {SEED_DATASET_PATH}"
        )

    df = pd.read_csv(target_path)

    # Validate required columns
    missing_features = [col for col in FEATURES if col not in df.columns]
    if missing_features:
        raise ValueError(f"Dataset missing required feature columns: {missing_features}")

    if TARGET_COLUMN not in df.columns:
        raise ValueError(f"Target column '{TARGET_COLUMN}' not found in dataset.")

    # Data cleaning and type enforcement
    cleaned_df = df.copy()
    for col in FEATURES:
        if col == "data_transfer_mb":
            cleaned_df[col] = pd.to_numeric(cleaned_df[col], errors="coerce").fillna(0.0).clip(lower=0.0)
        else:
            cleaned_df[col] = pd.to_numeric(cleaned_df[col], errors="coerce").fillna(0).astype(int).clip(lower=0)

    # Validate target
    cleaned_df[TARGET_COLUMN] = pd.to_numeric(cleaned_df[TARGET_COLUMN], errors="coerce").fillna(0).astype(int)

    X = cleaned_df[FEATURES]
    y = cleaned_df[TARGET_COLUMN]

    return X, y, cleaned_df


def create_model_pipeline(classifier, scale_features: bool = True) -> Pipeline:
    """
    Wraps an estimator in a scikit-learn Pipeline with optional StandardScaler.
    Prevents data leakage by fitting transformers strictly during training folds.
    """
    if scale_features:
        return Pipeline([
            ("scaler", StandardScaler()),
            ("classifier", classifier)
        ])
    return Pipeline([
        ("classifier", classifier)
    ])


def print_dataset_summary():
    """Diagnostic utility printing feature breakdown and target distribution."""
    X, y, df = load_cybersecurity_dataset()
    print("=" * 60)
    print("CLOUDSENTINEL CYBERSECURITY DATASET SUMMARY")
    print("=" * 60)
    print(f"Total Events: {len(df)}")
    print(f"Target Distribution:\n{y.value_counts(normalize=True).map(lambda n: f'{n:.1%}')}")
    print("\nFeature Summary:")
    print(X.describe().T[["mean", "std", "min", "50%", "max"]])


if __name__ == "__main__":
    print_dataset_summary()