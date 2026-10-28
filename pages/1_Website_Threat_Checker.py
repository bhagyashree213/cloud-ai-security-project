"""
CloudSentinel — Page 1: Website Threat Checker
The primary workflow of CloudSentinel:
  1. User enters a public website URL or domain and clicks 'Check Website'.
  2. Performs safe, read-only checks for HTTPS/TLS, certificate validity, security headers, and available threat reputation.
  3. Integrates VirusTotal API v3 using an API key from Streamlit secrets or environment variables.
     Retrieves existing reports first, requests a fresh scan if needed and permitted, respects API quotas, and never fabricates results.
  4. Shows a clear result: 'Potentially Malicious', 'No Threat Detected by Available Sources', or 'Unable to Determine'.
     Explains the evidence behind the assessment.
  5. Automatically saves each website assessment, timestamp, findings, source, and alert status in SQLite.
  6. Displays previous assessments directly on this page and links to Security Logs and Reports.
"""

from pathlib import Path
import sys
import json
import pandas as pd
import streamlit as st

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from auth import require_auth, get_current_user
from database.database import (
    init_db,
    save_website_assessment,
    fetch_website_assessments,
    log_audit
)
from website_checker import analyze_website_security
from ui_helpers import apply_custom_styles, render_sidebar_user_profile

st.set_page_config(
    page_title="Website Threat Checker — CloudSentinel",
    page_icon="🌐",
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
        <h1 style="color:#f8fafc; margin:0; font-size: 2.1rem;">🌐 Website Threat & Security Header Checker</h1>
        <p style="color:#94a3b8; margin:0; font-size: 0.95rem;">
            Real Website Security Assessment • TLS/SSL Certificate Verification • Defensive Security Headers • VirusTotal v3 Reputation
        </p>
    </div>
    """,
    unsafe_allow_html=True
)

tab_scanner, tab_history = st.tabs([
    "🔍 Scan Website / Domain",
    "📜 Previous Website Assessments"
])

# =====================================================================
# TAB 1: Real Website Threat Checker
# =====================================================================
with tab_scanner:
    with st.container(border=True):
        st.markdown("##### 🔍 Enter Target Public Website or Domain")
        col_url, col_btn = st.columns([3.5, 1])
        with col_url:
            target_url_input = st.text_input(
                "Public Website URL or Domain Name",
                value="https://example.com",
                placeholder="e.g. https://example.com, github.com, or cloudflare.com",
                help="Enter a public domain or HTTP/HTTPS URL. Internal and private network addresses will be blocked by SSRF defenses.",
                key="target_url_input"
            )
        with col_btn:
            st.write("")
            st.write("")
            scan_clicked = st.button("🚀 Check Website", use_container_width=True, type="primary")

    # Sample presets for quick demonstration
    st.markdown(
        """
        <div style="display:flex; gap:10px; align-items:center; margin-bottom:1.2rem; flex-wrap:wrap;">
            <span style="font-size:0.85rem; color:#94a3b8; font-weight:600;">Demonstration Presets:</span>
            <span style="font-size:0.8rem; background:#111e38; border:1px solid #1e3a5f; padding:4px 10px; border-radius:6px; color:#38bdf8;">
                <b>Clean Site:</b> https://example.com
            </span>
            <span style="font-size:0.8rem; background:#111e38; border:1px solid #1e3a5f; padding:4px 10px; border-radius:6px; color:#f87171;">
                <b>SSRF Localhost Block:</b> http://127.0.0.1
            </span>
            <span style="font-size:0.8rem; background:#111e38; border:1px solid #1e3a5f; padding:4px 10px; border-radius:6px; color:#f87171;">
                <b>SSRF Cloud Metadata Block:</b> http://169.254.169.254
            </span>
        </div>
        """,
        unsafe_allow_html=True
    )

    if scan_clicked:
        with st.spinner(f"Performing safe, read-only security checks on {target_url_input}..."):
            report = analyze_website_security(target_url_input)
            st.session_state["active_website_report"] = report

            # Automatically persist assessment to SQLite database
            try:
                saved_id = save_website_assessment(
                    report,
                    user=current_user.get("username", "Analyst")
                )
                report["saved_id"] = saved_id
            except Exception as e:
                st.warning(f"Note: Could not persist assessment to database: {e}")

    # Display Assessment Results
    if "active_website_report" in st.session_state:
        rep = st.session_state["active_website_report"]
        overall = rep.get("overall_assessment", "Unable to Determine")
        summary = rep.get("summary", "")
        evidence = rep.get("evidence", {})
        evidence_items = evidence.get("items", [])
        tls_info = rep.get("tls_info", {})
        http_info = rep.get("http_info", {})
        rep_info = rep.get("reputation_info", {})
        hostname = rep.get("hostname", "Target")
        resolved_ips = rep.get("resolved_ips", [])
        saved_id = rep.get("saved_id")

        # Color mapping for the 3 explicit categories
        color_map = {
            "Potentially Malicious": ("#ef4444", "🚨"),
            "No Threat Detected by Available Sources": ("#10b981", "✅"),
            "Unable to Determine": ("#94a3b8", "⚠️")
        }
        res_color, res_icon = color_map.get(overall, ("#94a3b8", "ℹ️"))

        st.markdown("---")
        st.subheader("🎯 Real Website Security Assessment Result")

        # Main Assessment Banner
        st.markdown(
            f"""
            <div style="background-color:#111e38; border: 1px solid #1e3a5f; border-left: 6px solid {res_color}; border-radius: 8px; padding: 18px; margin-bottom: 1.5rem;">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap;">
                    <div>
                        <span style="font-size:0.85rem; color:#94a3b8; text-transform:uppercase; letter-spacing:0.05em; font-weight:700;">
                            Objective Security Assessment Result
                        </span>
                        <h2 style="color:{res_color}; margin: 4px 0 6px 0; font-size: 2rem;">{res_icon} {overall}</h2>
                        <p style="color:#cbd5e1; font-size: 0.98rem; margin:0; line-height:1.5;">
                            <b>Target:</b> <code>{rep.get('sanitized_url', target_url_input)}</code> • <b>Domain:</b> <code>{hostname}</code>
                            {f' • <b>Record ID:</b> #{saved_id}' if saved_id else ''}
                        </p>
                    </div>
                    <div style="text-align:right;">
                        <span style="font-size:0.85rem; color:#94a3b8;">Assessment Timestamp</span><br/>
                        <strong style="color:#f8fafc; font-size:0.95rem;">{rep.get('checked_at')}</strong>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # Evidence Summary Box
        st.markdown("### 📝 Evidence Behind Assessment")
        with st.container(border=True):
            st.markdown(f"**Primary Finding:** {summary}")
            st.markdown("##### Detailed Observed Evidence:")
            if evidence_items:
                for item in evidence_items:
                    st.write(f"- {item}")
            else:
                st.write("- No specific evidence observations recorded.")

            st.caption(f"**Sources Inspected:** {', '.join(evidence.get('sources_checked', ['DNS', 'TLS', 'Headers', 'VirusTotal']))}")

        st.markdown("<br/>", unsafe_allow_html=True)

        # 4 Granular Forensic Cards
        fc1, fc2 = st.columns(2)

        with fc1:
            # 1. TLS/SSL Card
            with st.container(border=True):
                st.markdown("#### 🔐 TLS / SSL Certificate Forensics")
                if tls_info.get("https_available") and tls_info.get("cert_valid"):
                    days = tls_info.get("days_remaining", 0)
                    st.success(f"✅ HTTPS Accessible • Valid for **{days} more days**")
                    st.write(f"**Subject Common Name:** `{tls_info.get('subject_cn', 'N/A')}`")
                    st.write(f"**Certificate Authority (CA):** `{tls_info.get('issuer', 'N/A')}`")
                    st.write(f"**Expiration Date:** `{tls_info.get('expires_at', 'N/A')}`")
                    st.write(f"**Negotiated TLS Protocol:** `{tls_info.get('tls_version', 'TLSv1.3')}`")
                elif tls_info.get("is_expired"):
                    days_rem = tls_info.get("days_remaining")
                    exp_text = f" ({abs(days_rem)} days ago)" if days_rem is not None else ""
                    st.error(f"🚨 **Certificate is EXPIRED**{exp_text}")
                    st.write(f"**Issuer:** `{tls_info.get('issuer', 'N/A')}`")
                    st.write(f"**Verification Error:** `{tls_info.get('error', 'Expired')}`")
                elif not tls_info.get("https_available"):
                    st.warning("⚠️ HTTPS Connection Unavailable on standard port 443.")
                    if tls_info.get("error"):
                        st.caption(f"Error detail: {tls_info.get('error')}")
                else:
                    st.error(f"❌ Certificate Validation Failed: {tls_info.get('error', 'Untrusted')}")

            # 2. VirusTotal Reputation Card
            with st.container(border=True):
                st.markdown("#### 🌐 VirusTotal v3 Threat Intelligence")
                if rep_info.get("available"):
                    mal = rep_info.get("malicious_count", 0)
                    susp = rep_info.get("suspicious_count", 0)
                    harmless = rep_info.get("harmless_count", 0)
                    rep_score = rep_info.get("reputation_score", 0)

                    vt1, vt2, vt3, vt4 = st.columns(4)
                    vt1.metric("Malicious", mal, delta_color="inverse")
                    vt2.metric("Suspicious", susp, delta_color="inverse")
                    vt3.metric("Clean / Harmless", harmless)
                    vt4.metric("Community Score", rep_score)

                    if mal > 0:
                        st.error(f"🚨 **Known Threat Alert:** Flagged malicious by {mal} security vendor(s).")
                        engs = rep_info.get("engine_results", {})
                        if engs:
                            st.write("**Flagging Engines:**")
                            for eng, verdict in engs.items():
                                st.write(f"- `{eng}`: **{verdict}**")
                    else:
                        st.success(f"✅ Verified Clean: 0 threat detections across {mal + susp + harmless} security engines.")

                    cats = rep_info.get("categories", [])
                    if cats:
                        st.caption(f"**Observed Categories:** {', '.join(cats)}")
                    st.caption(f"Scan Status: `{rep_info.get('status', 'Completed')}` • Source: VirusTotal v3 API")
                else:
                    st.info(f"ℹ️ {rep_info.get('message', 'Reputation check unavailable.')}")
                    st.caption("Tip: Store `VIRUSTOTAL_API_KEY` in Streamlit secrets or environment variables to enable live domain and URL reputation lookups.")

        with fc2:
            # 3. HTTP Security Headers Card
            with st.container(border=True):
                st.markdown("#### 🛡️ Defensive HTTP Security Headers Audit")
                if http_info.get("success"):
                    found = http_info.get("headers_found", {})
                    missing = http_info.get("missing_headers", [])

                    st.markdown(f"**Audit Score: {len(found)}/6 Recommended Defensive Headers Present**")
                    st.progress(len(found) / 6.0)

                    st.markdown("##### Present Headers:")
                    if found:
                        for h_name, h_data in found.items():
                            st.write(f"✅ **{h_name}**: `{h_data.get('value', 'Active')}`")
                    else:
                        st.write("*(None of the 6 standard defensive headers were observed)*")

                    if missing:
                        with st.expander("⚠️ View Missing Headers and Risk Implications", expanded=False):
                            for m in missing:
                                st.markdown(f"- **{m['name']}** (`{m['header']}`) — *{m['description']}*")
                else:
                    st.warning(f"HTTP audit unavailable: {http_info.get('error', 'Unreachable')}")

            # 4. Network Resolution & SSRF Forensics Card
            with st.container(border=True):
                st.markdown("#### 📡 Network Resolution & SSRF Forensics")
                st.write(f"**Resolved Public IP(s):** `{', '.join(resolved_ips) if resolved_ips else 'None'}`")
                st.write(f"**HTTP Server Header:** `{http_info.get('server', 'Hidden / Undisclosed')}`")
                st.write(f"**Network Latency:** `{http_info.get('latency_ms', 'N/A')} ms`")
                st.write(f"**HTTP Response Code:** `{http_info.get('status_code', 'N/A')}`")
                st.caption("All resolved IPs validated against loopback (127.0.0.0/8), RFC 1918 private subnets, and cloud metadata (169.254.169.254).")

# =====================================================================
# TAB 2: Historical Website Assessments (From SQLite)
# =====================================================================
with tab_history:
    st.subheader("📜 Previous Website Assessments")
    st.caption("Stored assessment records from the SQLite database:")

    h_col1, h_col2, h_col3 = st.columns([1, 1, 2])
    with h_col1:
        f_result = st.selectbox(
            "Filter by Assessment Result",
            ["ALL", "Potentially Malicious", "No Threat Detected by Available Sources", "Unable to Determine"],
            key="hist_filter_res"
        )
    with h_col2:
        f_status = st.selectbox(
            "Filter by Alert Status",
            ["ALL", "NEW", "INVESTIGATING", "RESOLVED"],
            key="hist_filter_stat"
        )
    with h_col3:
        f_search = st.text_input("Search Domain or IP", placeholder="e.g. example.com", key="hist_search")

    assessments = fetch_website_assessments(
        limit=50,
        result_filter=None if f_result == "ALL" else f_result,
        status_filter=None if f_status == "ALL" else f_status,
        search=f_search if f_search.strip() else None
    )

    if not assessments:
        st.info("No stored website assessments matching the selected filters.")
    else:
        st.write(f"Displaying **{len(assessments)}** historical website assessment records:")
        for a in assessments:
            a_id = a["id"]
            domain = a["domain"]
            res = a["assessment_result"]
            stat = a["alert_status"]
            created = a["created_at"]
            summary = a.get("evidence_summary", "")

            border = "#ef4444" if res == "Potentially Malicious" else ("#10b981" if res == "No Threat Detected by Available Sources" else "#94a3b8")

            with st.container(border=True):
                r1, r2 = st.columns([3, 1])
                with r1:
                    st.markdown(f"### #{a_id}: `{domain}` — <span style='color:{border}; font-weight:700;'>{res}</span>", unsafe_allow_html=True)
                    st.write(f"**Evidence:** {summary}")
                    st.caption(f"IP: `{a.get('ip_address', 'N/A')}` • TLS: `{a.get('tls_status', 'N/A')}` • Headers: `{a.get('headers_status', 'N/A')}`")
                with r2:
                    st.markdown(f"<div style='text-align:right;'><b>Alert Status:</b> <code>{stat}</code><br/><span style='font-size:0.8rem; color:#94a3b8;'>Scanned: {created}</span></div>", unsafe_allow_html=True)
