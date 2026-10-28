"""
CloudSentinel — Standalone Supervised Threat Model Training Script.
Trains the Random Forest classification pipeline on the benchmark security dataset,
evaluates on a stratified test split, and saves the trained pipeline artifact to models/threat_model.pkl.
"""

from pathlib import Path
import sys
import time
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, f1_score, recall_score, precision_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from ml.preprocess import load_cybersecurity_dataset, FEATURES, TARGET_COLUMN

MODEL_DIR = BASE_DIR / "models"
MODEL_DIR.mkdir(parents=True, exist_ok=True)
MODEL_PATH = MODEL_DIR / "threat_model.pkl"


def train_single_model():
    print("=" * 60)
    print("TRAINING SUPERVISED THREAT CLASSIFICATION PIPELINE")
    print("=" * 60)

    # 1. Load full benchmark dataset
    X, y, df = load_cybersecurity_dataset()
    print(f"[+] Loaded dataset: {len(df)} samples across {len(FEATURES)} features.")

    # 2. Stratified train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # 3. Create leak-free pipeline (StandardScaler + RandomForestClassifier)
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=100,
            max_depth=12,
            min_samples_split=4,
            random_state=42
        ))
    ])

    # 4. Train pipeline
    start_time = time.time()
    pipeline.fit(X_train, y_train)
    duration = round(time.time() - start_time, 4)

    # 5. Evaluate on unseen test set
    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    rec = recall_score(y_test, y_pred, zero_division=0)
    prec = precision_score(y_test, y_pred, zero_division=0)

    print(f"\n[+] Training completed in {duration}s")
    print(f"    Accuracy:  {acc:.2%}")
    print(f"    Precision: {prec:.2%}")
    print(f"    Recall:    {rec:.2%}")
    print(f"    F1-Score:  {f1:.2%}")
    print("\nClassification Report:\n", classification_report(y_test, y_pred))

    # 6. Save model bundle
    joblib.dump({
        "model": pipeline,
        "features": FEATURES,
        "model_name": "Random Forest Classifier",
        "metrics": {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "training_time_sec": duration
        },
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }, MODEL_PATH)

    print(f"[+] Pipeline artifact safely saved to: {MODEL_PATH}")


if __name__ == "__main__":
    train_single_model()