"""
CloudSentinel — Page 4: Executive Reports & Security Compliance Analytics
Aggregates forensic telemetry from real website assessments, security headers compliance,
threat intelligence alerts, and ML benchmark performance baselines.
"""

from pathlib import Path
import sys
import io
from datetime import datetime
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from auth import require_auth, get_current_user
from database.database import (
    init_db,
    fetch_website_assessments,
    get_system_kpis,
    log_audit
)
from aws_s3 import upload_bytes_to_s3
from ui_helpers import (
    apply_custom_styles,
    render_sidebar_user_profile,
    get_plotly_layout
)

st.set_page_config(
    page_title="Executive Reports — CloudSentinel",
    page_icon="📊",
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
        <h1 style="color:#f8fafc; margin:0; font-size: 2.1rem;">📊 Executive Reports & Security Intelligence</h1>
        <p style="color:#94a3b8; margin:0; font-size: 0.95rem;">
            Real Website Security Posture • Threat Reputation Intelligence • Defensive Headers Compliance • ML Benchmarks
        </p>
    </div>
    """,
    unsafe_allow_html=True
)

kpis = get_system_kpis()
assessments = fetch_website_assessments(limit=250)

# -------------------------------------------------------------
# 1. EXECUTIVE KPI CARDS
# -------------------------------------------------------------
st.subheader("Executive Website Security Posture")
m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Total Website Scans", kpis.get("total_website_assessments", len(assessments)))
m2.metric("Potentially Malicious", kpis.get("malicious_websites", 0), delta_color="inverse")
m3.metric("No Threat Detected", kpis.get("clean_websites", 0))
m4.metric("Unable to Determine", kpis.get("undetermined_websites", 0))
m5.metric("Open / New Alerts", kpis.get("open_alerts", 0), delta_color="inverse")

st.markdown("<br/>", unsafe_allow_html=True)

# -------------------------------------------------------------
# 2. VISUAL ANALYTICS SECTION
# -------------------------------------------------------------
st.subheader("Website Threat & Configuration Visualizations")

if assessments:
    df_wa = pd.DataFrame(assessments)
    v1, v2 = st.columns(2)

    with v1:
        st.markdown("##### Website Assessment Outcomes Distribution")
        res_counts = df_wa["assessment_result"].value_counts().reset_index()
        res_counts.columns = ["Result", "Count"]

        color_map = {
            "Potentially Malicious": "#ef4444",
            "No Threat Detected by Available Sources": "#10b981",
            "Unable to Determine": "#94a3b8"
        }

        fig_pie = px.pie(
            res_counts,
            values="Count",
            names="Result",
            color="Result",
            color_discrete_map=color_map,
            hole=0.45
        )
        fig_pie.update_layout(get_plotly_layout(height=320))
        st.plotly_chart(fig_pie, use_container_width=True)

    with v2:
        st.markdown("##### Alert Triage Status Breakdown")
        stat_counts = df_wa["alert_status"].value_counts().reset_index()
        stat_counts.columns = ["Status", "Count"]

        stat_colors = {
            "NEW": "#ef4444",
            "OPEN": "#ef4444",
            "INVESTIGATING": "#f59e0b",
            "RESOLVED": "#10b981"
        }

        fig_bar = px.bar(
            stat_counts,
            x="Status",
            y="Count",
            color="Status",
            color_discrete_map=stat_colors
        )
        fig_bar.update_layout(get_plotly_layout(height=320))
        st.plotly_chart(fig_bar, use_container_width=True)
else:
    st.info("No website assessments recorded yet. Run website checks to populate visualization charts.")

st.markdown("---")

# -------------------------------------------------------------
# 4. EXPORT & S3 CLOUD ARCHIVAL
# -------------------------------------------------------------
st.subheader("📤 Export Executive Security Reports")

if assessments:
    df_exp = pd.DataFrame(assessments)
    drop_cols = [c for c in ["findings_json", "virustotal_stats", "findings", "virustotal"] if c in df_exp.columns]
    df_exp = df_exp.drop(columns=drop_cols)

    csv_buf = io.StringIO()
    df_exp.to_csv(csv_buf, index=False)
    csv_bytes = csv_buf.getvalue().encode("utf-8")

    e1, e2 = st.columns([1, 1])
    with e1:
        st.download_button(
            "📥 Download Executive Report (CSV)",
            data=csv_bytes,
            file_name=f"cloudsentinel_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True
        )
    with e2:
        if st.button("☁️ Archive Executive Report to AWS S3", use_container_width=True):
            filename = f"executive_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            res = upload_bytes_to_s3(csv_bytes, filename=filename, prefix="reports", content_type="text/csv")
            if not res.get("success"):
                st.error(f"❌ Failed to archive report: {res.get('error', 'Unknown error')}")
            else:
                s3_loc = res.get("s3_uri") or res.get("s3_url", "S3 Storage")
                if res.get("simulated"):
                    st.info(f"💾 Saved to Local S3 Simulation: `{s3_loc}`")
                else:
                    st.success(f"☁️ Archived to Amazon S3: `{s3_loc}`")
