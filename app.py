"""
CloudSentinel — Cloud-Based AI Security and Threat Detection System
Main Application Entrypoint, User Role Gateway, and Operational Command Dashboard.
Suitable for MCA Academic Project Demonstration & Viva Defense.
"""

from pathlib import Path
import sys
import pandas as pd
import streamlit as st
import plotly.express as px

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from database.database import (
    init_db,
    has_admin_user,
    setup_initial_admin,
    get_system_kpis,
    fetch_website_assessments,
    save_website_assessment,
    fetch_alerts,
    fetch_model_evaluations
)
from auth import (
    authenticate_user,
    register_user,
    get_current_user,
    is_authenticated,
    logout_user,
    hash_password
)
from ui_helpers import (
    apply_custom_styles,
    render_sidebar_user_profile,
    get_plotly_layout
)
from aws_s3 import get_s3_status
from website_checker import analyze_website_security

# Configure Streamlit Page
st.set_page_config(
    page_title="CloudSentinel — AI Website Security & Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize authoritative database schema
init_db()
apply_custom_styles()

# Check authentication state
current_user = get_current_user()

# =====================================================================
# FIRST-RUN SETUP WIZARD (If database has no Administrator)
# =====================================================================
if not has_admin_user():
    st.markdown("<h1 style='text-align:center;color:#38bdf8'>🛡️ CloudSentinel Initial Setup</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align:center;color:#94a3b8'>No system administrator found. Bootstrap your initial administrator account below.</p>", unsafe_allow_html=True)

    _, col, _ = st.columns([1, 1.6, 1])
    with col:
        with st.form("bootstrap_admin_form"):
            st.subheader("Create Initial Administrator")
            st.info("This first-run wizard initializes the primary root Administrator for your viva demonstration.")
            admin_name = st.text_input("Full Name", value="System Administrator")
            admin_username = st.text_input("Admin Username", value="admin")
            admin_email = st.text_input("Admin Email Address", value="admin@cloudsentinel.local")
            admin_pass = st.text_input("Admin Password (min 8 chars)", type="password", value="Admin@123")
            admin_confirm = st.text_input("Confirm Password", type="password", value="Admin@123")

            submitted = st.form_submit_button("🚀 INITIALIZE CLOUDSENTINEL SYSTEM", use_container_width=True)
            if submitted:
                if not admin_name or not admin_username or not admin_email or not admin_pass:
                    st.error("Please fill in all fields.")
                elif len(admin_pass) < 8:
                    st.error("Password must be at least 8 characters long.")
                elif admin_pass != admin_confirm:
                    st.error("Passwords do not match.")
                else:
                    pw_hash, salt = hash_password(admin_pass)
                    if setup_initial_admin(admin_name, admin_username, admin_email, pw_hash, salt):
                        st.success("Administrator account initialized! Please log in below.")
                        st.rerun()
                    else:
                        st.error("Failed to initialize administrator.")
    st.stop()


# =====================================================================
# PUBLIC LOGIN / REGISTRATION GATEWAY WITH 1-CLICK DEMO ACCESS
# =====================================================================
if not is_authenticated():
    render_sidebar_user_profile()

    st.markdown(
        """
        <div style="text-align:center; margin-top: 1rem; margin-bottom: 1.5rem;">
            <h1 style="color:#38bdf8; font-size: 2.8rem; margin-bottom: 0.2rem;">🛡️ CloudSentinel</h1>
            <p style="color:#94a3b8; font-size: 1.15rem; max-width: 750px; margin: 0 auto;">
                Cloud-Based AI Website Security & Threat Detection System
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    _, center_col, _ = st.columns([1, 1.5, 1])

    with center_col:
        # Quick Demo Login Shortcut
        with st.container(border=True):
            st.markdown("##### ⚡ Quick Role Access")
            st.caption("Select a role to sign in immediately:")
            demo_c1, demo_c2, demo_c3 = st.columns(3)

            with demo_c1:
                if st.button("🎭 Demonstrator", use_container_width=True, help="Log in as Demonstrator"):
                    st.session_state.user = {
                        "id": 1,
                        "name": "Project Demonstrator",
                        "username": "demo",
                        "email": "demo@cloudsentinel.local",
                        "role": "User / Demonstrator"
                    }
                    st.rerun()

            with demo_c2:
                if st.button("🔍 Security Analyst", use_container_width=True, help="Log in as Security Analyst"):
                    st.session_state.user = {
                        "id": 2,
                        "name": "Security Analyst",
                        "username": "analyst",
                        "email": "analyst@cloudsentinel.local",
                        "role": "Security Analyst"
                    }
                    st.rerun()

            with demo_c3:
                if st.button("🛡️ Admin / Reviewer", use_container_width=True, help="Log in as Administrator / Alert Reviewer"):
                    st.session_state.user = {
                        "id": 4,
                        "name": "System Administrator",
                        "username": "admin",
                        "email": "admin@cloudsentinel.local",
                        "role": "Administrator"
                    }
                    st.rerun()

        st.markdown("<br/>", unsafe_allow_html=True)

        login_tab, register_tab = st.tabs(["🔐 Sign In with Credentials", "📝 Register New Account"])

        with login_tab:
            st.subheader("Credential Access")
            login_id = st.text_input("Username or Email Address", key="login_id")
            login_pw = st.text_input("Password", type="password", key="login_pw")

            if st.button("Sign In to CloudSentinel", use_container_width=True):
                if not login_id.strip() or not login_pw:
                    st.warning("Please enter your username/email and password.")
                else:
                    user_dict = authenticate_user(login_id, login_pw)
                    if user_dict:
                        st.session_state.user = user_dict
                        st.session_state.logged_in_user = user_dict["name"]
                        st.success(f"Welcome back, {user_dict['name']}!")
                        st.rerun()
                    else:
                        st.error("Invalid credentials. Please verify your username and password.")

            st.caption("Default Admin: `admin` / `admin123` • Analyst: `analyst` / `analyst123` • Demo: `demo` / `demo123`")

        with register_tab:
            st.subheader("Register Account")
            reg_name = st.text_input("Full Name", key="reg_name")
            reg_user = st.text_input("Username", key="reg_user")
            reg_email = st.text_input("Email Address", key="reg_email")
            reg_pw = st.text_input("Password (min 8 chars)", type="password", key="reg_pw")
            reg_confirm = st.text_input("Confirm Password", type="password", key="reg_confirm")

            if st.button("Create Account", use_container_width=True):
                success, msg = register_user(
                    name=reg_name,
                    username=reg_user,
                    email=reg_email,
                    password=reg_pw,
                    confirm_password=reg_confirm,
                    is_public_registration=True
                )
                if success:
                    st.success(msg)
                else:
                    st.error(msg)

    st.stop()


# =====================================================================
# AUTHENTICATED USER COMMAND DASHBOARD
# =====================================================================
render_sidebar_user_profile()

current_user = get_current_user() or {}
role = current_user.get("role", "Security Analyst")

st.markdown(
    f"""
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 1.5rem; border-bottom: 1px solid #1e293b; padding-bottom: 0.8rem;">
        <div>
            <h1 style="color:#f8fafc; margin:0; font-size: 2.1rem;">🛡️ CloudSentinel SOC Command Center</h1>
            <p style="color:#94a3b8; margin:0; font-size: 0.95rem;">
                Real-Time AI Website Security & Threat Detection Platform
            </p>
        </div>
        <div style="text-align:right;">
            <span style="font-size:0.85rem; color:#64748b;">Active Role:</span><br/>
            <strong style="color:#38bdf8; font-size: 1.1rem;">{current_user.get('name')}</strong>
            <span style="font-size: 0.85rem; color:#94a3b8;">({role})</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

# Role description banner with quick 1-click role switcher
with st.container(border=True):
    r1, r2 = st.columns([1.5, 2.5])
    with r1:
        st.markdown(f"**Current Role:** `{role}`")
        role_notes = {
            "User / Demonstrator": "General user with access to website threat inspections.",
            "Security Analyst": "Conducts deep forensic audits, evaluates TLS certificates, and investigates alerts.",
            "Administrator": "Full administrative control over incident alerts and system settings."
        }
        st.caption(role_notes.get(role, "Active session user."))
    with r2:
        st.markdown("<span style='font-size:0.85rem; color:#94a3b8;'>Switch Role:</span>", unsafe_allow_html=True)
        sw1, sw2, sw3 = st.columns(3)
        with sw1:
            if st.button("🎭 Demonstrator", key="sw_demo", use_container_width=True):
                st.session_state.user["role"] = "User / Demonstrator"
                st.session_state.user["name"] = "Project Demonstrator"
                st.rerun()
        with sw2:
            if st.button("🔍 Security Analyst", key="sw_analyst", use_container_width=True):
                st.session_state.user["role"] = "Security Analyst"
                st.session_state.user["name"] = "Security Analyst"
                st.rerun()
        with sw3:
            if st.button("🛡️ Administrator", key="sw_admin", use_container_width=True):
                st.session_state.user["role"] = "Administrator"
                st.session_state.user["name"] = "System Administrator"
                st.rerun()

# Real database KPIs
kpis = get_system_kpis()
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total Website Scans", kpis.get("total_website_assessments", 0))
c2.metric("Potentially Malicious", kpis.get("malicious_websites", 0), delta_color="inverse")
c3.metric("No Threat Detected", kpis.get("clean_websites", 0))
c4.metric("Unable to Determine", kpis.get("undetermined_websites", 0))
c5.metric("Open / New Alerts", kpis.get("open_alerts", 0), delta_color="inverse")

st.markdown("<br/>", unsafe_allow_html=True)

# Quick navigation shortcuts to all 5 multi-page modules
st.markdown("##### 🚀 CloudSentinel System Workspaces")
nav_cols = st.columns(5)
with nav_cols[0]:
    st.page_link("pages/1_Website_Threat_Checker.py", label="🌐 Website Threat Checker", use_container_width=True)
with nav_cols[1]:
    st.page_link("pages/2_Model_Comparison.py", label="🧠 5 ML Models Benchmark", use_container_width=True)
with nav_cols[2]:
    st.page_link("pages/3_Security_Logs.py", label="📜 Assessments & Alerts", use_container_width=True)
with nav_cols[3]:
    st.page_link("pages/4_Reports.py", label="📊 Executive Reports", use_container_width=True)
with nav_cols[4]:
    st.page_link("pages/5_Admin_Management.py", label="⚙️ Admin & Audit Logs", use_container_width=True)

st.markdown("<br/>", unsafe_allow_html=True)

# Main Application Tabs
tab_scan_launcher, tab_assessments = st.tabs([
    "🚀 Quick Website Threat Scan",
    "📜 Recent Website Assessments"
])

# =====================================================================
# TAB 1: Quick Website Threat Scan Launcher
# =====================================================================
with tab_scan_launcher:
    st.subheader("Direct Website Threat Inspection")
    st.caption("Enter a public domain or URL to execute safe, read-only defensive checks (SSRF protected):")

    with st.container(border=True):
        col_in, col_act = st.columns([3.5, 1])
        with col_in:
            quick_target = st.text_input(
                "Target Website URL or Domain",
                value="https://example.com",
                placeholder="e.g. https://example.com, github.com, or cloudflare.com",
                key="home_target_input"
            )
        with col_act:
            st.write("")
            st.write("")
            run_check = st.button("🚀 Check Website", use_container_width=True, type="primary", key="home_scan_btn")

    if run_check:
        with st.spinner(f"Performing safe, read-only security checks on {quick_target}..."):
            result = analyze_website_security(quick_target)
            st.session_state["home_quick_result"] = result
            try:
                save_website_assessment(result, user=current_user.get("username", "Analyst"))
            except Exception:
                pass

    if "home_quick_result" in st.session_state:
        qr = st.session_state["home_quick_result"]
        q_res = qr.get("overall_assessment", "Unable to Determine")
        q_sum = qr.get("summary", "")
        q_ev = qr.get("evidence", {})
        q_items = q_ev.get("items", [])

        color_map = {
            "Potentially Malicious": ("#ef4444", "🚨"),
            "No Threat Detected by Available Sources": ("#10b981", "✅"),
            "Unable to Determine": ("#94a3b8", "⚠️")
        }
        res_color, res_icon = color_map.get(q_res, ("#94a3b8", "ℹ️"))

        st.markdown(
            f"""
            <div style="background-color:#111e38; border: 1px solid #1e3a5f; border-left: 6px solid {res_color}; border-radius: 8px; padding: 16px; margin: 1rem 0;">
                <h3 style="color:{res_color}; margin:0; font-size: 1.6rem;">{res_icon} {q_res}</h3>
                <p style="color:#cbd5e1; margin:6px 0 0 0; font-size: 0.95rem;"><b>Summary:</b> {q_sum}</p>
            </div>
            """,
            unsafe_allow_html=True
        )

        with st.expander("🔍 Observed Evidence Breakdown", expanded=True):
            if q_items:
                for it in q_items:
                    st.write(f"- {it}")
            st.page_link("pages/1_Website_Threat_Checker.py", label="👉 Open Full Forensics & Security Headers Audit in Website Threat Checker", use_container_width=False)

# =====================================================================
# TAB 2: Recent Website Assessments Table
# =====================================================================
with tab_assessments:
    st.subheader("Recent Real Website Threat Assessments")
    recent_wa = fetch_website_assessments(limit=8)

    if not recent_wa:
        st.info("No website assessments recorded yet. Use the scan launcher above to assess a website.")
    else:
        wa_df = pd.DataFrame(recent_wa)
        disp_cols = ["id", "domain", "ip_address", "assessment_result", "alert_status", "tls_status", "headers_status", "created_at"]
        avail_wa = [c for c in disp_cols if c in wa_df.columns]
        st.dataframe(wa_df[avail_wa], use_container_width=True, hide_index=True)
