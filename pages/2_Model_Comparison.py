"""
CloudSentinel — Page 2: AI Model Comparison & Benchmark Lab
Evaluates and compares the five required scikit-learn classifiers:
  1. Decision Tree Classifier
  2. Random Forest Classifier
  3. Logistic Regression
  4. Support Vector Machine (SVM)
  5. Gradient Boosting Classifier

Plus companion Unsupervised Anomaly Detection:
  - Isolation Forest

Displays:
  - Comparison table for all 5 models
  - Accuracy comparison bar chart
  - Grouped Precision, Recall, and F1-Score chart
  - Confusion matrix inspector with TN, FP, FN, TP explanation
  - Champion model identification according to documented selection rule
"""

from pathlib import Path
import sys
import json
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from auth import require_auth, get_current_user
from database.database import init_db, fetch_model_evaluations, log_audit
from ml.train_and_compare import run_full_comparison_and_training
from ui_helpers import (
    apply_custom_styles,
    render_sidebar_user_profile,
    get_plotly_layout
)

st.set_page_config(
    page_title="Model Comparison — CloudSentinel",
    page_icon="🧠",
    layout="wide"
)

init_db()
apply_custom_styles()
render_sidebar_user_profile()

require_auth()
current_user = get_current_user() or {}

st.markdown(
    """
    <div style="border-bottom: 1px solid #1e293b; padding-bottom: 0.8rem; margin-bottom: 1.5rem;">
        <h1 style="color:#f8fafc; margin:0; font-size: 2.1rem;">🧠 Five Machine Learning Models Comparison & Benchmark</h1>
        <p style="color:#94a3b8; margin:0; font-size: 0.95rem;">
            Comparative Evaluation of 5 Scikit-Learn Classifiers • Cross-Validation Selection • Security Metrics (Accuracy, Precision, Recall, F1)
        </p>
    </div>
    """,
    unsafe_allow_html=True
)

# Fetch stored evaluations from database
evals = fetch_model_evaluations()

# Action bar for retraining
col_head1, col_head2 = st.columns([3, 1])
with col_head1:
    st.caption("Active Champion Model is preserved in `models/threat_model.pkl` for host telemetry classification.")
with col_head2:
    if st.button("🔄 RETRAIN & RE-BENCHMARK ALL 5 MODELS", use_container_width=True):
        with st.spinner("Executing 5-fold cross-validation, training 5 models & updating benchmark database..."):
            results = run_full_comparison_and_training()
            log_audit(
                user_id=current_user.get("id"),
                username=current_user.get("username", "User"),
                action="MODEL_RETRAIN_BENCHMARK",
                details=f"Retrained 5 models. Supervised Champion: {results['champion_supervised']}"
            )
            st.success("All five models trained and benchmark database updated!")
            st.rerun()

if not evals:
    st.warning("No model evaluations recorded in the database yet. Click below to initialize the benchmark suite:")
    if st.button("🚀 Run Initial Benchmark Suite Now"):
        with st.spinner("Running 5-model benchmark suite..."):
            run_full_comparison_and_training()
            st.rerun()
    st.stop()

df_eval = pd.DataFrame(evals)

# Filter for the 5 required supervised classifiers
ALLOWED_SUPERVISED = [
    "Random Forest Classifier",
    "Gradient Boosting Classifier",
    "Support Vector Machine (SVM)",
    "Logistic Regression",
    "Decision Tree Classifier"
]

supervised_df = df_eval[df_eval["model_type"] == "Supervised Classifier"].copy()
if not supervised_df.empty:
    # Filter to the 5 required models and keep the latest run of each
    filtered_sup = supervised_df[supervised_df["model_name"].isin(ALLOWED_SUPERVISED)]
    if not filtered_sup.empty:
        supervised_df = filtered_sup.drop_duplicates(subset=["model_name"], keep="first")
    else:
        supervised_df = supervised_df.drop_duplicates(subset=["model_name"], keep="first")
else:
    supervised_df = df_eval.copy().drop_duplicates(subset=["model_name"], keep="first")

# Identify champion model
champ_row = supervised_df[supervised_df["is_active"] == 1]
if not champ_row.empty:
    best_row = champ_row.iloc[0]
else:
    # Fallback to model with highest F1 then Recall
    best_row = supervised_df.sort_values(by=["f1_score", "recall_score"], ascending=False).iloc[0]

# =====================================================================
# 1. CHAMPION MODEL SELECTION BANNER
# =====================================================================
st.markdown("### 🏆 Best-Performing Model Selection")

with st.container(border=True):
    b_col1, b_col2 = st.columns([1.5, 1])
    with b_col1:
        st.markdown(
            f"""
            <div style="border-left: 5px solid #38bdf8; padding-left: 14px;">
                <span style="font-size:0.8rem; text-transform:uppercase; color:#38bdf8; font-weight:700; letter-spacing:0.05em;">Selected Production Champion</span>
                <h2 style="color:#f8fafc; margin: 4px 0 8px 0; font-size: 1.8rem;">{best_row['model_name']}</h2>
                <p style="color:#94a3b8; font-size:0.95rem; margin-bottom:8px;">
                    <b>Algorithm:</b> <code>{best_row['algorithm']}</code> • <b>Persistence Path:</b> <code>models/threat_model.pkl</code>
                </p>
                <p style="color:#cbd5e1; font-size:0.92rem; line-height:1.5;">
                    <b>Selection Basis:</b> Selected via 5-fold cross-validation on training data. Achieved {best_row['recall_score']:.1%} Threat Recall and {best_row['f1_score']:.1%} F1-Score with sub-second inference latency.
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )

    with b_col2:
        st.markdown("##### Held-Out Test Set Metrics")
        m1, m2 = st.columns(2)
        m1.metric("Accuracy", f"{best_row['accuracy']:.2%}")
        m2.metric("Precision", f"{best_row['precision_score']:.2%}")
        m3, m4 = st.columns(2)
        m3.metric("Recall (Sensitivity)", f"{best_row['recall_score']:.2%}")
        m4.metric("F1-Score", f"{best_row['f1_score']:.2%}")
        st.caption(f"⏱️ Training Latency: {best_row.get('training_time_sec', 0):.4f}s • ROC-AUC: {best_row.get('roc_auc', 0):.2%}")

st.markdown("<br/>", unsafe_allow_html=True)

# =====================================================================
# 2. COMPARISON TABLE FOR ALL FIVE MODELS
# =====================================================================
st.subheader("📊 Five Models Benchmark Comparison Table")
st.caption("All models evaluated on the identical stratified test set partition (20% holdout):")

display_cols = [
    "model_name", "algorithm", "accuracy", "precision_score",
    "recall_score", "f1_score", "roc_auc", "training_time_sec", "is_active"
]
avail_cols = [c for c in display_cols if c in supervised_df.columns]

# Format metrics nicely for presentation
formatted_df = supervised_df[avail_cols].copy()
formatted_df.rename(columns={
    "model_name": "Model Name",
    "algorithm": "Algorithm",
    "accuracy": "Accuracy",
    "precision_score": "Precision",
    "recall_score": "Recall",
    "f1_score": "F1-Score",
    "roc_auc": "ROC-AUC",
    "training_time_sec": "Train Time (s)",
    "is_active": "Selected Champion"
}, inplace=True)

st.dataframe(
    formatted_df.style.format({
        "Accuracy": "{:.2%}",
        "Precision": "{:.2%}",
        "Recall": "{:.2%}",
        "F1-Score": "{:.2%}",
        "ROC-AUC": "{:.2%}",
        "Train Time (s)": "{:.4f}s",
        "Selected Champion": lambda x: "🏆 Champion" if x == 1 else "Candidate"
    }),
    use_container_width=True,
    hide_index=True
)

st.markdown("<br/>", unsafe_allow_html=True)

# =====================================================================
# 3. PERFORMANCE CHARTS
# =====================================================================
st.subheader("📈 Visual Performance Comparisons")

ch1, ch2 = st.columns(2)

with ch1:
    st.markdown("##### 1. Accuracy Comparison Across Five Models")
    acc_df = supervised_df.copy()
    acc_df["Accuracy (%)"] = acc_df["accuracy"] * 100.0
    fig_acc = px.bar(
        acc_df,
        x="model_name",
        y="Accuracy (%)",
        labels={"model_name": "Model", "Accuracy (%)": "Accuracy (%)"},
        color="Accuracy (%)",
        color_continuous_scale="Blues",
        text=acc_df["Accuracy (%)"].map(lambda x: f"{x:.1f}%")
    )
    fig_acc.update_layout(get_plotly_layout(height=340))
    fig_acc.update_yaxes(range=[85, 102])
    st.plotly_chart(fig_acc, use_container_width=True)

with ch2:
    st.markdown("##### 2. Precision, Recall & F1-Score Comparison")
    melted_metrics = supervised_df.melt(
        id_vars=["model_name"],
        value_vars=["precision_score", "recall_score", "f1_score"],
        var_name="Metric",
        value_name="Score"
    )
    metric_labels = {
        "precision_score": "Precision",
        "recall_score": "Recall",
        "f1_score": "F1-Score"
    }
    melted_metrics["Metric"] = melted_metrics["Metric"].map(metric_labels)

    fig_prf = px.bar(
        melted_metrics,
        x="model_name",
        y="Score",
        color="Metric",
        barmode="group",
        labels={"model_name": "Model", "Score": "Score (0.0 to 1.0)"},
        color_discrete_map={
            "Precision": "#38bdf8",
            "Recall": "#f59e0b",
            "F1-Score": "#10b981"
        }
    )
    fig_prf.update_layout(get_plotly_layout(height=340))
    fig_prf.update_yaxes(range=[0.85, 1.02])
    st.plotly_chart(fig_prf, use_container_width=True)

# Training Latency Chart
st.markdown("##### 3. Model Training Latency (Seconds)")
fig_time = px.bar(
    supervised_df,
    x="model_name",
    y="training_time_sec",
    labels={"model_name": "Model", "training_time_sec": "Training Time (Seconds)"},
    color="training_time_sec",
    color_continuous_scale="Purples",
    text=supervised_df["training_time_sec"].map(lambda x: f"{x:.4f}s")
)
fig_time.update_layout(get_plotly_layout(height=280))
st.plotly_chart(fig_time, use_container_width=True)

st.markdown("<br/>", unsafe_allow_html=True)

# =====================================================================
# 4. CONFUSION MATRIX INSPECTOR
# =====================================================================
st.subheader("🔍 Interactive Confusion Matrix Inspector")
st.caption("Inspect the classification matrix breakdown for the selected best model or compare any candidate:")

sel_model_name = st.selectbox(
    "Select Model to Inspect Confusion Matrix",
    supervised_df["model_name"].tolist(),
    index=int(supervised_df["model_name"].tolist().index(best_row["model_name"])) if best_row["model_name"] in supervised_df["model_name"].tolist() else 0
)

sel_eval_row = supervised_df[supervised_df["model_name"] == sel_model_name].iloc[0]
cm_raw = sel_eval_row.get("confusion_matrix")

if cm_raw:
    try:
        cm = json.loads(cm_raw) if isinstance(cm_raw, str) else cm_raw
        tn, fp = int(cm[0][0]), int(cm[0][1])
        fn, tp = int(cm[1][0]), int(cm[1][1])

        cm_c1, cm_c2 = st.columns([1.2, 1.8])

        with cm_c1:
            cm_df = pd.DataFrame(
                [[tn, fp], [fn, tp]],
                index=["Actual Normal (0)", "Actual Threat (1)"],
                columns=["Predicted Normal (0)", "Predicted Threat (1)"]
            )
            st.table(cm_df)

        with cm_c2:
            st.markdown(f"#### Matrix Breakdown for `{sel_model_name}`")
            st.write(f"✅ **True Negatives (TN):** `{tn}` events — Normal user traffic correctly recognized and allowed.")
            st.write(f"⚠️ **False Positives (FP):** `{fp}` events — Benign user traffic incorrectly flagged as threats (benign false alarms).")
            st.write(f"🚨 **False Negatives (FN):** `{fn}` events — **Dangerous missed cyberattacks** (critical in security).")
            st.write(f"🛡️ **True Positives (TP):** `{tp}` events — Real cyberattacks accurately detected and intercepted.")

    except Exception as e:
        st.error(f"Error parsing confusion matrix: {e}")


