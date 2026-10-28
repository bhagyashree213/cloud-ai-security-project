"""
CloudSentinel — Page 7: Administrator Command & System Management
Administrative RBAC user management, tamper-evident audit logging, database backups, and S3 sync.
"""

from pathlib import Path
import sys
import os
import pandas as pd
import streamlit as st

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from auth import require_auth, get_current_user
from database.database import (
    init_db,
    get_all_users,
    update_user_role,
    toggle_user_status,
    delete_user,
    fetch_audit_logs,
    backup_database,
    get_system_kpis,
    log_audit
)
from aws_s3 import upload_file_to_s3, get_s3_status
from ui_helpers import apply_custom_styles, render_sidebar_user_profile

st.set_page_config(
    page_title="Admin Management — CloudSentinel",
    page_icon="🛡️",
    layout="wide"
)

init_db()
apply_custom_styles()
render_sidebar_user_profile()

require_auth()
current_user = get_current_user() or {}

# Strict Server-Side Role Enforcement
if current_user.get("role") != "Administrator":
    st.error("⛔ Access Denied: You do not possess the required Administrator privileges to access this console.")
    st.info("Please log in with an Administrator account or consult the System Administrator.")
    st.stop()

st.markdown(
    """
    <div style="border-bottom: 1px solid #1e293b; padding-bottom: 0.8rem; margin-bottom: 1.5rem;">
        <h1 style="color:#f8fafc; margin:0; font-size: 2.1rem;">🛡️ Administrator Command & System Management</h1>
        <p style="color:#94a3b8; margin:0; font-size: 0.95rem;">
            Role-Based Access Control • Tamper-Evident Audit Logging • Database Snapshot & Cloud S3 Archival
        </p>
    </div>
    """,
    unsafe_allow_html=True
)

tab_users, tab_audit, tab_backup, tab_health = st.tabs([
    "👥 User RBAC Management",
    "📜 Audit Logs Explorer",
    "💾 Database Backups & S3 Sync",
    "☁️ Cloud & System Diagnostics"
])

# -------------------------------------------------------------
# TAB 1: User RBAC Management
# -------------------------------------------------------------
with tab_users:
    st.subheader("Registered User Accounts & Access Control")
    users = get_all_users()
    df_users = pd.DataFrame(users)

    if not df_users.empty:
        st.dataframe(
            df_users[["id", "name", "username", "email", "role", "is_active", "created_at"]],
            use_container_width=True,
            hide_index=True
        )

        st.markdown("---")
        st.markdown("##### Modify User Role or Account Status")
        u_col1, u_col2, u_col3 = st.columns(3)

        user_options = {u["id"]: f"{u['name']} (@{u['username']}) — {u['role']}" for u in users}

        with u_col1:
            target_user_id = st.selectbox(
                "Select User Account",
                options=list(user_options.keys()),
                format_func=lambda x: user_options[x]
            )

        target_user = next((u for u in users if u["id"] == target_user_id), None)

        with u_col2:
            new_role = st.selectbox(
                "Assign Role",
                ["Security Analyst", "Alert Reviewer", "User / Demonstrator", "Administrator"],
                index=["Security Analyst", "Alert Reviewer", "User / Demonstrator", "Administrator"].index(target_user["role"]) if target_user else 0
            )

        with u_col3:
            st.write("")
            st.write("")
            if st.button("💾 UPDATE USER ROLE", use_container_width=True):
                if target_user["username"] == current_user["username"] and new_role != "Administrator":
                    st.error("You cannot demote your own current Administrator account.")
                else:
                    success = update_user_role(
                        user_id=target_user_id,
                        new_role=new_role,
                        admin_username=current_user.get("username", "Admin")
                    )
                    if success:
                        st.success(f"Updated role for {target_user['name']} to {new_role}!")
                        st.rerun()
                    else:
                        st.error("Failed to update user role.")

        st.markdown("##### Account Active Status & Deletion")
        st_col1, st_col2, st_col3 = st.columns([1.5, 1, 1])
        with st_col1:
            st.write(f"Current status for **{target_user['name']}**: {'🟢 Active' if target_user['is_active'] else '🔴 Deactivated'}")
        with st_col2:
            if target_user["username"] == current_user["username"]:
                st.caption("Cannot modify your own active account.")
            else:
                toggle_action = "Deactivate" if target_user["is_active"] else "Activate"
                if st.button(f"{toggle_action} Account", use_container_width=True):
                    toggle_user_status(
                        user_id=target_user_id,
                        is_active=(not target_user["is_active"]),
                        admin_username=current_user.get("username", "Admin")
                    )
                    st.success(f"Account status updated!")
                    st.rerun()
        with st_col3:
            if target_user["username"] == current_user["username"]:
                st.caption("Cannot delete your own active account.")
            else:
                if st.button("🗑️ Delete User", use_container_width=True, type="secondary"):
                    try:
                        delete_user(target_user_id, current_user.get("username", "Admin"))
                        st.success(f"Deleted user account @{target_user['username']}!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed to delete user: {e}")

# -------------------------------------------------------------
# TAB 2: Audit Logs Explorer
# -------------------------------------------------------------
with tab_audit:
    st.subheader("Tamper-Evident System Audit Trail")
    st.caption("All security-relevant actions (logins, role changes, alert triage, model retraining, S3 sync) are immutably logged.")

    a_col1, a_col2 = st.columns([1, 2])
    with a_col1:
        action_filter = st.selectbox(
            "Filter by Action Type",
            ["ALL", "USER_ROLE_CHANGE", "USER_STATUS_CHANGE", "ALERT_STATUS_CHANGE", "ALERT_ASSIGNMENT", "MODEL_RETRAIN_BENCHMARK", "EVENT_BATCH_IMPORT", "S3_LOG_ARCHIVE", "S3_REPORT_ARCHIVE"]
        )
    with a_col2:
        audit_limit = st.selectbox("Maximum Log Records", [50, 100, 250, 500], index=1)

    audit_logs = fetch_audit_logs(
        limit=audit_limit,
        action=None if action_filter == "ALL" else action_filter
    )

    if audit_logs:
        df_audit = pd.DataFrame(audit_logs)
        st.dataframe(
            df_audit[["id", "timestamp", "username", "action", "details", "ip_address"]],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("No audit logs matching criteria.")

# -------------------------------------------------------------
# TAB 3: Database Backups & S3 Sync
# -------------------------------------------------------------
with tab_backup:
    st.subheader("Database Snapshot & Cloud S3 Archival")
    st.markdown("Create transactional snapshot backups of `database/security.db` and securely archive to Amazon S3.")

    bk_col1, bk_col2 = st.columns(2)

    with bk_col1:
        if st.button("📸 CREATE LOCAL DATABASE SNAPSHOT", use_container_width=True):
            with st.spinner("Generating SQLite online transaction snapshot..."):
                backup_path = backup_database()
                if backup_path:
                    st.success(f"Snapshot created successfully: `{backup_path.name}` ({backup_path.stat().st_size / 1024:.1f} KB)")
                    log_audit(
                        user_id=current_user.get("id"),
                        username=current_user.get("username", "Admin"),
                        action="LOCAL_DB_BACKUP",
                        details=f"Created database snapshot {backup_path.name}"
                    )
                else:
                    st.info("Cloud Mode active: Database backups are managed via Amazon RDS Automated Snapshots.")

    with bk_col2:
        s3_stat = get_s3_status()
        s3_btn_label = f"☁️ SYNC BACKUPS TO S3 (s3://{s3_stat.get('bucket', 'cloudsentinel')}/backups/)"
        if st.button(s3_btn_label, use_container_width=True):
            with st.spinner("Uploading snapshots to S3..."):
                backups_dir = BASE_DIR / "database" / "backups"
                db_files = list(backups_dir.glob("*.db"))
                if not db_files:
                    # Create one first
                    fresh = backup_database()
                    if fresh:
                        db_files = [fresh]

                if db_files:
                    latest_backup = max(db_files, key=lambda p: p.stat().st_mtime)
                    res = upload_file_to_s3(
                        local_path=latest_backup,
                        prefix="backups",
                        content_type="application/x-sqlite3"
                    )
                    if res.get("success"):
                        st.success(f"Successfully archived to S3: {res.get('s3_uri')}")
                        log_audit(
                            user_id=current_user.get("id"),
                            username=current_user.get("username", "Admin"),
                            action="S3_BACKUP_SYNC",
                            details=f"Uploaded {latest_backup.name} to {res.get('s3_uri')}"
                        )
                    else:
                        st.error(f"S3 Upload failed: {res.get('error')}")
                else:
                    st.warning("No local backups found to sync.")

    st.markdown("---")
    st.markdown("##### Existing Local Backups in `database/backups/`")
    backups_dir = BASE_DIR / "database" / "backups"
    if backups_dir.exists():
        backup_list = []
        for f in backups_dir.glob("*.db"):
            backup_list.append({
                "Filename": f.name,
                "Size (KB)": round(f.stat().st_size / 1024, 2),
                "Last Modified": pd.to_datetime(f.stat().st_mtime, unit="s").strftime("%Y-%m-%d %H:%M:%S")
            })
        if backup_list:
            st.dataframe(pd.DataFrame(backup_list), use_container_width=True, hide_index=True)
        else:
            st.info("No snapshot backups currently exist in `database/backups/`.")
    else:
        st.info("Backups directory has not been created yet.")

# -------------------------------------------------------------
# TAB 4: Cloud & System Diagnostics
# -------------------------------------------------------------
with tab_health:
    st.subheader("Infrastructure Health & Diagnostics")
    kpis = get_system_kpis()

    h1, h2, h3 = st.columns(3)
    with h1:
        st.markdown("##### Database Engine")
        st.write(f"**Mode:** `{kpis['db_mode']}`")
        st.write(f"**Target:** `{kpis['db_target']}`")
        st.write(f"**Cloud DB:** {'Yes (Amazon RDS)' if kpis['is_cloud_db'] else 'No (Local SQLite WAL)'}")

    with h2:
        st.markdown("##### AWS Cloud Storage")
        s3_stat = get_s3_status()
        st.write(f"**Configured:** {'Yes' if s3_stat['configured'] else 'No (Simulation Mode)'}")
        st.write(f"**Bucket:** `{s3_stat.get('bucket', 'N/A')}`")
        st.write(f"**Region:** `{s3_stat.get('region', 'N/A')}`")
        st.write(f"**Status:** {s3_stat.get('message')}")

    with h3:
        st.markdown("##### AI Model Persistence")
        threat_pkl = BASE_DIR / "models" / "threat_model.pkl"
        anomaly_pkl = BASE_DIR / "models" / "anomaly_model.pkl"
        st.write(f"**Threat Model:** {'🟢 Active' if threat_pkl.exists() else '🔴 Missing'}")
        st.write(f"**Anomaly Model:** {'🟢 Active' if anomaly_pkl.exists() else '🔴 Missing'}")
        bench_dir = BASE_DIR / "models" / "benchmarks"
        bench_count = len(list(bench_dir.glob("*.pkl"))) if bench_dir.exists() else 0
        st.write(f"**Benchmark Models:** {bench_count} models stored in `models/benchmarks/`")
