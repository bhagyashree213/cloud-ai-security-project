"""
CloudSentinel — Standalone Unsupervised Anomaly Detection Training Script.
Trains an Isolation Forest anomaly pipeline on cybersecurity telemetry data.
"""

from pathlib import Path
import sys
import time
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from ml.preprocess import load_cybersecurity_dataset, FEATURES

MODEL_DIR = BASE_DIR / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)
MODEL_PATH = MODEL_DIR / "anomaly_model.pkl"


def train_anomaly_model():
    print("=" * 60)
    print("TRAINING ISOLATION FOREST ANOMALY PIPELINE")
    print("=" * 60)

    X, y, df = load_cybersecurity_dataset()
    print(f"[+] Loaded dataset: {len(df)} samples across {len(FEATURES)} features.")

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", IsolationForest(
            n_estimators=100,
            contamination=0.30,
            random_state=42
        ))
    ])

    start_time = time.time()
    pipeline.fit(X)
    duration = round(time.time() - start_time, 4)

    joblib.dump({
        "model": pipeline,
        "features": FEATURES,
        "model_name": "Isolation Forest",
        "contamination": 0.30,
        "training_time_sec": duration,
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }, MODEL_PATH)

    print(f"[+] Anomaly pipeline successfully trained in {duration}s!")
    print(f"[+] Model saved to: {MODEL_PATH}")


if __name__ == "__main__":
    train_anomaly_model()