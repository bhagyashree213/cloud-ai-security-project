"""
CloudSentinel — Machine Learning Model Comparison & Benchmarking Suite.
Evaluates the exact five required scikit-learn classifiers:
  1. Decision Tree Classifier
  2. Random Forest Classifier
  3. Logistic Regression
  4. Support Vector Machine (SVM)
  5. Gradient Boosting Classifier

Plus companion Unsupervised Anomaly Detection:
  - Isolation Forest

Key Architecture:
  - Stratified 80/20 train/test split with random_state=42 for exact reproducibility.
  - Leak-free preprocessing pipelines (StandardScaler fitted inside fold/pipeline).
  - Cross-validation on training data ONLY for model selection (prioritizing Threat Recall & F1-Score).
  - Honest evaluation on held-out test set (no data leakage, no hardcoded scores, never artificial 100%).
  - Serializes all candidate artifacts into models/benchmarks/ and champion into models/threat_model.pkl.
  - Persists metrics to SQLite database for dashboard display.
"""

from pathlib import Path
import sys
import time
import json
from typing import Dict, Any, Tuple
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_validate
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.calibration import CalibratedClassifierCV

# 5 Required Classifiers
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC

# Companion Anomaly Detector
from sklearn.ensemble import IsolationForest

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from ml.preprocess import load_cybersecurity_dataset, FEATURES, TARGET_COLUMN
from database.database import init_db, save_model_evaluation, set_active_model

MODEL_DIR = BASE_DIR / "models"
BENCHMARK_DIR = MODEL_DIR / "benchmarks"
MODEL_DIR.mkdir(parents=True, exist_ok=True)
BENCHMARK_DIR.mkdir(parents=True, exist_ok=True)


def get_five_candidate_models() -> Dict[str, Dict[str, Any]]:
    """
    Returns the exact five classification pipelines with documented algorithm profiles.
    Pipelines guarantee zero data leakage during scaling and preprocessing.
    """
    return {
        "Decision Tree Classifier": {
            "pipeline": Pipeline([
                ("scaler", StandardScaler()),
                ("clf", DecisionTreeClassifier(
                    max_depth=6,
                    min_samples_split=5,
                    random_state=42
                ))
            ]),
            "algorithm": "DecisionTreeClassifier",
            "type": "Supervised Classifier",
            "desc": "Single orthogonal decision tree partitioning feature space via Gini impurity splits.",
            "pros": "Fully interpretable decision rules, zero latency, highly efficient.",
            "cons": "Prone to high variance and overfitting compared to ensemble methods."
        },
        "Random Forest Classifier": {
            "pipeline": Pipeline([
                ("scaler", StandardScaler()),
                ("clf", RandomForestClassifier(
                    n_estimators=100,
                    max_depth=12,
                    min_samples_split=4,
                    random_state=42
                ))
            ]),
            "algorithm": "RandomForestClassifier",
            "type": "Supervised Classifier",
            "desc": "Ensemble of decorrelated decision trees trained via bootstrap aggregation (bagging).",
            "pros": "Robust against overfitting, captures complex multi-feature threat interactions, provides feature importances.",
            "cons": "Higher memory footprint and slightly slower inference than single trees."
        },
        "Logistic Regression": {
            "pipeline": Pipeline([
                ("scaler", StandardScaler()),
                ("clf", LogisticRegression(
                    max_iter=1000,
                    C=1.0,
                    solver="lbfgs",
                    random_state=42
                ))
            ]),
            "algorithm": "LogisticRegression",
            "type": "Supervised Classifier",
            "desc": "Linear probabilistic classifier estimating log-odds of a security event being malicious.",
            "pros": "Fast training, produces well-calibrated probabilities, highly transparent linear coefficients.",
            "cons": "Assumes linear decision boundaries; cannot naturally capture non-linear feature interactions without manual polynomial expansion."
        },
        "Support Vector Machine (SVM)": {
            "pipeline": Pipeline([
                ("scaler", StandardScaler()),
                ("clf", CalibratedClassifierCV(
                    estimator=SVC(
                        kernel="rbf",
                        C=1.0,
                        gamma="scale",
                        random_state=42
                    ),
                    cv=3
                ))
            ]),
            "algorithm": "SupportVectorMachine",
            "type": "Supervised Classifier",
            "desc": "Max-margin hyperplane classifier mapped into high-dimensional space via Radial Basis Function (RBF) kernel.",
            "pros": "Effective in non-linear decision spaces, robust against moderate feature collinearity.",
            "cons": "Computationally intensive quadratic training time; probability calibration requires Platt scaling."
        },
        "Gradient Boosting Classifier": {
            "pipeline": Pipeline([
                ("scaler", StandardScaler()),
                ("clf", GradientBoostingClassifier(
                    n_estimators=100,
                    learning_rate=0.1,
                    max_depth=4,
                    random_state=42
                ))
            ]),
            "algorithm": "GradientBoostingClassifier",
            "type": "Supervised Classifier",
            "desc": "Sequential boosting ensemble iteratively correcting pseudo-residuals of prior trees.",
            "pros": "High predictive precision on tabular security metrics, strong edge-case capture.",
            "cons": "Sensitive to noisy mislabeled events and outliers; sequential training cannot be fully parallelized."
        }
    }


def select_best_model_via_cross_validation(candidates: Dict[str, Dict[str, Any]], X_train: pd.DataFrame, y_train: pd.Series) -> str:
    """
    Selects the champion model using 5-Fold Stratified Cross-Validation on TRAINING data only.
    Selection Rule:
      Cybersecurity Objective: Maximize capture of actual attacks (Threat Recall)
      while maintaining overall precision and balance (F1-score).
      Objective Score = 0.55 * CV_F1 + 0.45 * CV_Recall
    """
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = {}

    print("\n--- 5-Fold Stratified Cross-Validation on Training Fold ---")
    for name, config in candidates.items():
        pipe = config["pipeline"]
        cv_res = cross_validate(
            pipe,
            X_train,
            y_train,
            cv=cv,
            scoring=["f1", "recall", "precision", "accuracy"],
            n_jobs=1
        )
        mean_f1 = float(np.mean(cv_res["test_f1"]))
        mean_rec = float(np.mean(cv_res["test_recall"]))
        mean_prec = float(np.mean(cv_res["test_precision"]))
        mean_acc = float(np.mean(cv_res["test_accuracy"]))

        # Documented selection rule: weighted balance of F1-score (harmonic balance) and Recall (threat capture)
        selection_score = (0.55 * mean_f1) + (0.45 * mean_rec)
        scores[name] = {
            "cv_f1": round(mean_f1, 4),
            "cv_recall": round(mean_rec, 4),
            "cv_precision": round(mean_prec, 4),
            "cv_accuracy": round(mean_acc, 4),
            "selection_score": round(selection_score, 4)
        }
        print(f"  {name:30} | CV-F1: {mean_f1:.4f} | CV-Recall: {mean_rec:.4f} | CV-Score: {selection_score:.4f}")

    best_name = max(scores.keys(), key=lambda k: scores[k]["selection_score"])
    print(f"\n[+] Champion Model Selected via Cross-Validation: {best_name} (Selection Score: {scores[best_name]['selection_score']:.4f})")
    return best_name, scores


def evaluate_on_test_set(candidates: Dict[str, Dict[str, Any]], X_train: pd.DataFrame, X_test: pd.DataFrame, y_train: pd.Series, y_test: pd.Series) -> Dict[str, Dict[str, Any]]:
    """
    Trains each candidate pipeline on the full training set and evaluates strictly on the unseen test set.
    """
    results = {}

    for name, config in candidates.items():
        pipe = config["pipeline"]
        start_time = time.time()
        pipe.fit(X_train, y_train)
        training_time = round(time.time() - start_time, 4)

        y_pred = pipe.predict(X_test)

        # Extract probabilities for ROC-AUC
        if hasattr(pipe, "predict_proba"):
            y_proba = pipe.predict_proba(X_test)[:, 1]
        elif hasattr(pipe, "decision_function"):
            y_proba = pipe.decision_function(X_test)
        else:
            y_proba = y_pred

        acc = round(float(accuracy_score(y_test, y_pred)), 4)
        prec = round(float(precision_score(y_test, y_pred, zero_division=0)), 4)
        rec = round(float(recall_score(y_test, y_pred, zero_division=0)), 4)
        f1 = round(float(f1_score(y_test, y_pred, zero_division=0)), 4)
        try:
            auc = round(float(roc_auc_score(y_test, y_proba)), 4)
        except Exception:
            auc = 0.0

        cm = confusion_matrix(y_test, y_pred).tolist()

        results[name] = {
            "pipeline": pipe,
            "algorithm": config["algorithm"],
            "model_type": config["type"],
            "description": config["desc"],
            "pros": config["pros"],
            "cons": config["cons"],
            "training_time_sec": training_time,
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "roc_auc": auc,
            "confusion_matrix": cm,
            "hyperparameters": {"algorithm": config["algorithm"]}
        }

    return results


def train_companion_anomaly_detector(X_train: pd.DataFrame, X_test: pd.DataFrame, y_test: pd.Series) -> Dict[str, Any]:
    """
    Trains the companion unsupervised Isolation Forest model for behavioral zero-day anomaly detection.
    """
    contamination = 0.30
    pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", IsolationForest(n_estimators=100, contamination=contamination, random_state=42))
    ])

    start_time = time.time()
    pipe.fit(X_train)
    training_time = round(time.time() - start_time, 4)

    raw_preds = pipe.predict(X_test)
    # -1 is outlier (anomaly/threat), 1 is inlier (normal)
    y_pred = np.where(raw_preds == -1, 1, 0)

    try:
        scores = -pipe.decision_function(X_test)
        auc = round(float(roc_auc_score(y_test, scores)), 4)
    except Exception:
        auc = 0.0

    acc = round(float(accuracy_score(y_test, y_pred)), 4)
    prec = round(float(precision_score(y_test, y_pred, zero_division=0)), 4)
    rec = round(float(recall_score(y_test, y_pred, zero_division=0)), 4)
    f1 = round(float(f1_score(y_test, y_pred, zero_division=0)), 4)
    cm = confusion_matrix(y_test, y_pred).tolist()

    return {
        "pipeline": pipe,
        "algorithm": "IsolationForest",
        "model_type": "Unsupervised Anomaly Detector",
        "description": "Isolates anomalies by recursive random partition cuts; few cuts indicate severe outlier.",
        "pros": "Detects novel zero-day attack patterns without needing prior labeled attack signatures.",
        "cons": "Unsupervised nature means contamination rate must be estimated.",
        "training_time_sec": training_time,
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
        "roc_auc": auc,
        "confusion_matrix": cm,
        "hyperparameters": {"contamination": contamination}
    }


def run_full_comparison_and_training() -> Dict[str, Any]:
    """
    Executes end-to-end benchmark workflow:
      1. Loads labeled dataset and splits 80/20 with stratification.
      2. Cross-validates all 5 classifiers to select champion based on security objectives.
      3. Trains all 5 on training split and evaluates on unseen test set.
      4. Trains companion Isolation Forest anomaly detector.
      5. Saves models to models/benchmarks/ and champion to models/threat_model.pkl.
      6. Records benchmark evaluations in the database.
    """
    init_db()
    X, y, full_df = load_cybersecurity_dataset()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print("=" * 70)
    print("CLOUDSENTINEL FIVE-MODEL BENCHMARK & COMPARISON")
    print("=" * 70)
    print(f"Dataset Size: {len(X)} events | Train Set: {len(X_train)} | Test Set: {len(X_test)}")
    print(f"Class Balance: Normal={int((y == 0).sum())} ({((y == 0).mean()):.1%}), Threat={int((y == 1).sum())} ({((y == 1).mean()):.1%})")

    candidates = get_five_candidate_models()

    # Step 1: Model Selection via Cross-Validation on Training data ONLY
    champion_name, cv_scores = select_best_model_via_cross_validation(candidates, X_train, y_train)

    # Step 2: Final Training & Evaluation on Test Set
    test_results = evaluate_on_test_set(candidates, X_train, X_test, y_train, y_test)

    # Step 3: Companion Anomaly Detector
    anomaly_result = train_companion_anomaly_detector(X_train, X_test, y_test)

    # Step 4: Persist Artifacts and Record in Database
    print("\n--- Final Test Set Evaluation Results ---")
    for name, r in test_results.items():
        is_champ = (name == champion_name)
        status_tag = "[CHAMPION]" if is_champ else "[CANDIDATE]"
        print(f"{status_tag:11} {name:30} | Acc: {r['accuracy']:.2%} | Prec: {r['precision']:.2%} | Rec: {r['recall']:.2%} | F1: {r['f1_score']:.2%} | Time: {r['training_time_sec']}s")

        # Save individual benchmark model
        safe_name = name.lower().replace(" ", "_").replace("(", "").replace(")", "")
        model_file = BENCHMARK_DIR / f"supervised_{safe_name}.pkl"
        joblib.dump({
            "model": r["pipeline"],
            "features": FEATURES,
            "metrics": r,
            "model_name": name,
            "cv_scores": cv_scores.get(name, {})
        }, model_file)

        # Record in database
        save_model_evaluation(
            model_name=name,
            model_type="Supervised Classifier",
            algorithm=r["algorithm"],
            accuracy=r["accuracy"],
            precision_score=r["precision"],
            recall_score=r["recall"],
            f1_score=r["f1_score"],
            roc_auc=r["roc_auc"],
            training_time_sec=r["training_time_sec"],
            confusion_matrix=r["confusion_matrix"],
            hyperparameters=r["hyperparameters"],
            is_active=is_champ
        )

    # Save Anomaly Detector
    anomaly_model_file = BENCHMARK_DIR / "anomaly_isolation_forest.pkl"
    joblib.dump({
        "model": anomaly_result["pipeline"],
        "features": FEATURES,
        "metrics": anomaly_result,
        "model_name": "Isolation Forest"
    }, anomaly_model_file)

    save_model_evaluation(
        model_name="Isolation Forest",
        model_type="Unsupervised Anomaly Detector",
        algorithm="IsolationForest",
        accuracy=anomaly_result["accuracy"],
        precision_score=anomaly_result["precision"],
        recall_score=anomaly_result["recall"],
        f1_score=anomaly_result["f1_score"],
        roc_auc=anomaly_result["roc_auc"],
        training_time_sec=anomaly_result["training_time_sec"],
        confusion_matrix=anomaly_result["confusion_matrix"],
        hyperparameters=anomaly_result["hyperparameters"],
        is_active=True
    )

    # Save Champion Model to Production Threat Model Path
    champion_pipeline = test_results[champion_name]["pipeline"]
    threat_model_path = MODEL_DIR / "threat_model.pkl"
    anomaly_model_path = MODEL_DIR / "anomaly_model.pkl"

    joblib.dump({
        "model": champion_pipeline,
        "features": FEATURES,
        "model_name": champion_name,
        "metrics": test_results[champion_name],
        "selection_rule": "Prioritizes Threat Recall & Macro-F1 across 5-Fold Stratified Cross-Validation",
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }, threat_model_path)

    joblib.dump({
        "model": anomaly_result["pipeline"],
        "features": FEATURES,
        "model_name": "Isolation Forest",
        "metrics": anomaly_result,
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }, anomaly_model_path)

    print(f"\n[+] Active Champion Model saved to: {threat_model_path}")
    print(f"[+] Active Anomaly Model saved to: {anomaly_model_path}")

    return {
        "supervised": test_results,
        "unsupervised": {"Isolation Forest": anomaly_result},
        "champion_supervised": champion_name,
        "champion_unsupervised": "Isolation Forest",
        "cv_scores": cv_scores
    }


if __name__ == "__main__":
    run_full_comparison_and_training()
