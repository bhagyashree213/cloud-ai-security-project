"""
CloudSentinel — Page 3: Security Logs & Incident Alert Management
Displays and manages security incident alerts and triage lifecycle:
NEW -> INVESTIGATING -> RESOLVED, with CSV export and S3 archival.
"""

from pathlib import Path
import sys
import io
import json
from datetime import datetime
import pandas as pd
import streamlit as st

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from auth import require_auth, get_current_user
from database.database import (
    init_db,
    fetch_alerts,
    update_alert_status,
    get_alert_history,
    log_audit,
    sanitize_for_csv
)
from aws_s3 import upload_bytes_to_s3, get_s3_status
from ui_helpers import (
    apply_custom_styles,
    render_sidebar_user_profile,
    severity_badge,
    status_badge
)

st.set_page_config(
    page_title="Security Logs & Alerts — CloudSentinel",
    page_icon="📜",
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
        <h1 style="color:#f8fafc; margin:0; font-size: 2.1rem;">📜 Security Logs & Alerts</h1>
    </div>
    """,
    unsafe_allow_html=True
)

all_alerts = [al for al in fetch_alerts() if al.get("source") != "Test Suite"]
new_alerts = len([al for al in all_alerts if al["status"] in ("NEW", "OPEN")])
inv_alerts = len([al for al in all_alerts if al["status"] == "INVESTIGATING"])
res_alerts = len([al for al in all_alerts if al["status"] == "RESOLVED"])

k1, k2, k3, k4 = st.columns(4)
k1.metric("Recent Incident Alerts", len(all_alerts))
k2.metric("New / Open Alerts", new_alerts, delta_color="inverse")
k3.metric("Under Investigation", inv_alerts)
k4.metric("Resolved Incidents", res_alerts)

st.markdown("<br/>", unsafe_allow_html=True)

with st.container(border=True):
    st.markdown("##### 🔍 Alert Filters")
    af1, af2, af3, af4 = st.columns([1, 1, 1.5, 0.8])
    with af1:
        a_stat_filter = st.selectbox("Status Filter", ["ALL", "NEW", "INVESTIGATING", "RESOLVED"], key="al_stat_filter")
    with af2:
        a_sev_filter = st.selectbox("Severity Filter", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"], key="al_sev_filter")
    with af3:
        a_search = st.text_input("Search Alert", placeholder="Search by message, domain, or assignee...", key="al_search_box")
    with af4:
        a_limit = st.selectbox("Max Alerts", [5, 10, 25, 50], index=1, key="al_limit_box")

filtered_alerts = [
    al for al in fetch_alerts(
        status=None if a_stat_filter == "ALL" else a_stat_filter,
        severity=None if a_sev_filter == "ALL" else a_sev_filter,
        search=a_search if a_search.strip() else None,
        limit=a_limit
    ) if al.get("source") != "Test Suite"
]

if filtered_alerts:
    df_export = pd.DataFrame(filtered_alerts)
    csv_buf = io.StringIO()
    df_export.to_csv(csv_buf, index=False)
    csv_bytes = csv_buf.getvalue().encode("utf-8")

    col_count, col_dl, col_s3 = st.columns([2, 1, 1])
    with col_count:
        st.write(f"Showing **{len(filtered_alerts)}** recent incident alerts")
    with col_dl:
        st.download_button(
            "📥 Export CSV",
            data=csv_bytes,
            file_name=f"security_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            use_container_width=True
        )
    with col_s3:
        if st.button("☁️ Archive to S3", use_container_width=True):
            filename = f"security_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            res = upload_bytes_to_s3(csv_bytes, filename=filename, prefix="logs", content_type="text/csv")
            if not res.get("success"):
                st.error(f"❌ Failed to archive alerts: {res.get('error', 'Unknown error')}")
            else:
                s3_loc = res.get("s3_uri") or res.get("s3_url", "S3 Storage")
                if res.get("simulated"):
                    st.info(f"💾 Saved to Local S3 Simulation: `{s3_loc}`")
                else:
                    st.success(f"☁️ Successfully archived to Amazon S3: `{s3_loc}`")
else:
    st.write("Showing **0** incident alerts")

st.markdown("<br/>", unsafe_allow_html=True)

if not filtered_alerts:
    st.info("No incident alerts matching your current filter criteria.")
else:
    for al in filtered_alerts:
        al_id = al["id"]
        sev = al["severity"]
        curr_status = "NEW" if al["status"] == "OPEN" else al["status"]
        border_c = "#ef4444" if sev in ("CRITICAL", "HIGH") else "#eab308"

        with st.container(border=True):
            ah1, ah2 = st.columns([3, 1])
            with ah1:
                st.markdown(
                    f"### Alert #{al_id}: {al.get('threat_type', 'Website Alert')} <span style='font-size:0.8rem; padding:3px 8px; border-radius:4px; background:{border_c}; color:#fff;'>{sev}</span>",
                    unsafe_allow_html=True
                )
                st.write(f"**Message:** {al['message']}")
            with ah2:
                st_col = "#ef4444" if curr_status == "NEW" else ("#f59e0b" if curr_status == "INVESTIGATING" else "#10b981")
                st.markdown(
                    f"<div style='text-align:right;'><span style='font-size:1.1rem; font-weight:700; color:{st_col};'>● {curr_status}</span><br/><span style='font-size:0.8rem; color:#94a3b8;'>Created: {al['created_at']}</span></div>",
                    unsafe_allow_html=True
                )

            # Alert Details
            d1, d2, d3, d4 = st.columns(4)
            d1.write(f"**Source Target:** `{al.get('domain') or al.get('ip_address', 'N/A')}`")
            d2.write(f"**Detection Source:** {al.get('source', 'Website Threat Checker')}")
            d3.write(f"**Assigned Reviewer:** `{al.get('assigned_to', 'Unassigned')}`")
            d4.write(f"**Assessment:** {al.get('assessment_result', 'N/A')}")

            # Triage Controls
            st.markdown("---")
            tc1, tc2, tc3 = st.columns([1.2, 2, 1])
            with tc1:
                target_st = st.selectbox(
                    "Update Status",
                    ["NEW", "INVESTIGATING", "RESOLVED"],
                    index=["NEW", "INVESTIGATING", "RESOLVED"].index(curr_status) if curr_status in ["NEW", "INVESTIGATING", "RESOLVED"] else 0,
                    key=f"triage_st_{al_id}"
                )
            with tc2:
                target_note = st.text_input("Triage Notes", placeholder="e.g. False positive confirmed / Escalated to SOC", key=f"triage_note_{al_id}")
            with tc3:
                st.write("")
                st.write("")
                if st.button("Apply", key=f"apply_btn_{al_id}", use_container_width=True):
                    update_alert_status(
                        alert_id=al_id,
                        new_status=target_st,
                        changed_by=current_user.get("username", "Analyst"),
                        notes=target_note
                    )
                    st.success(f"Alert #{al_id} updated to {target_st}!")
                    st.rerun()

            # History Timeline
            hist = get_alert_history(al_id)
            if hist:
                with st.expander(f"📜 View Lifecycle Audit Trail ({len(hist)} events)", expanded=False):
                    for h in hist:
                        st.write(f"- `{h['timestamp']}` by **{h['changed_by']}**: `{h['old_status']}` ➔ `{h['new_status']}` | *{h.get('notes', 'No notes')}*")
