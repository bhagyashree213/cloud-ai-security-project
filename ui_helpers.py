"""
UI/UX Design Helpers for CloudSentinel.
Provides professional cybersecurity styling (navy/slate/blue theme),
consistent KPI metric cards, status badges, and Plotly visualization formatting.
"""

import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from typing import Optional, Dict, Any


CYBER_CSS = """
<style>
    /* Cybersecurity Navy & Blue Accent Theme */
    .stApp {
        background-color: #0b1120;
        color: #f1f5f9;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    }
    
    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #070d19;
        border-right: 1px solid #1e293b;
    }
    
    /* Metric Cards */
    div[data-testid="stMetric"] {
        background-color: #111e38;
        border: 1px solid #1e3a5f;
        border-radius: 8px;
        padding: 14px 18px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
    }
    div[data-testid="stMetricLabel"] p {
        color: #94a3b8 !important;
        font-weight: 500;
        font-size: 0.88rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    div[data-testid="stMetricValue"] div {
        color: #38bdf8 !important;
        font-weight: 700;
    }

    /* Primary and Secondary Buttons */
    .stButton > button {
        background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
        color: #ffffff;
        font-weight: 600;
        border: none;
        border-radius: 6px;
        padding: 0.5rem 1rem;
        transition: all 0.2s ease-in-out;
    }
    .stButton > button:hover {
        background: linear-gradient(135deg, #38bdf8 0%, #0284c7 100%);
        box-shadow: 0 0 12px rgba(56, 189, 248, 0.4);
        color: #ffffff;
    }

    /* Status Badges */
    .badge {
        display: inline-block;
        padding: 0.25rem 0.65rem;
        font-size: 0.8rem;
        font-weight: 700;
        border-radius: 9999px;
        text-transform: uppercase;
        letter-spacing: 0.04em;
    }
    .badge-critical { background-color: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }
    .badge-high { background-color: rgba(249, 115, 22, 0.2); color: #f97316; border: 1px solid #f97316; }
    .badge-medium { background-color: rgba(234, 179, 8, 0.2); color: #eab308; border: 1px solid #eab308; }
    .badge-low { background-color: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid #10b981; }
    .badge-open { background-color: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #f87171; }
    .badge-investigating { background-color: rgba(234, 179, 8, 0.2); color: #fbbf24; border: 1px solid #fbbf24; }
    .badge-resolved { background-color: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #34d399; }

    /* Tables & DataFrames */
    div[data-testid="stDataFrame"] {
        border: 1px solid #1e293b;
        border-radius: 6px;
    }

    /* Form Containers */
    div[data-testid="stForm"] {
        background-color: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 20px;
    }
</style>
"""

def apply_custom_styles():
    """Injects custom cyber CSS styling into the current Streamlit page."""
    st.markdown(CYBER_CSS, unsafe_allow_html=True)


def render_sidebar_user_profile():
    """Renders user info, role badge, quick links, and logout button in the sidebar."""
    from auth import get_current_user, logout_user

    user = get_current_user()
    with st.sidebar:
        st.markdown(
            """
            <div style="text-align: center; margin-bottom: 1.2rem;">
                <span style="font-size: 2.2rem;">🛡️</span>
                <h3 style="margin: 0; color: #38bdf8; font-size: 1.3rem;">CloudSentinel</h3>
                <p style="margin: 0; color: #64748b; font-size: 0.78rem;">AI Threat Detection System</p>
            </div>
            """,
            unsafe_allow_html=True
        )

        if user:
            role = user.get("role", "Security Analyst")
            role_colors = {
                "Administrator": "#ec4899",
                "Alert Reviewer": "#8b5cf6",
                "Security Analyst": "#0ea5e9",
                "User / Demonstrator": "#10b981"
            }
            color = role_colors.get(role, "#0ea5e9")

            st.markdown(
                f"""
                <div style="background-color: #111e38; border: 1px solid #1e3a5f; border-radius: 8px; padding: 12px; margin-bottom: 1rem;">
                    <div style="font-size: 0.75rem; color: #94a3b8; text-transform: uppercase;">Active Session</div>
                    <div style="font-weight: 700; color: #f8fafc; font-size: 1rem;">{user.get('name', 'User')}</div>
                    <div style="font-size: 0.8rem; color: #64748b; margin-bottom: 6px;">@{user.get('username', 'user')}</div>
                    <span style="background-color: rgba(56, 189, 248, 0.15); color: {color}; border: 1px solid {color}; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600;">
                        {role}
                    </span>
                </div>
                """,
                unsafe_allow_html=True
            )

            if st.button("🔒 Log Out", use_container_width=True):
                logout_user()
                st.rerun()

            st.markdown("---")
            st.markdown("<p style='font-size: 0.75rem; color: #64748b; text-align: center;'>CloudSentinel Security Platform v2.0</p>", unsafe_allow_html=True)


def severity_badge(severity: str) -> str:
    """Returns HTML for a colored severity badge."""
    sev = str(severity).upper()
    css_class = f"badge-{sev.lower()}" if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "badge-low"
    return f'<span class="badge {css_class}">{sev}</span>'


def status_badge(status: str) -> str:
    """Returns HTML for a colored alert status badge."""
    stat = str(status).upper()
    if stat in ("NEW", "OPEN"):
        css_class = "badge-open"
    elif stat == "INVESTIGATING":
        css_class = "badge-investigating"
    elif stat == "RESOLVED":
        css_class = "badge-resolved"
    else:
        css_class = "badge-low"
    return f'<span class="badge {css_class}">{stat}</span>'


def get_plotly_layout(title: str = "", height: Optional[int] = None, **kwargs) -> Dict[str, Any]:
    """Returns a dark cybersecurity layout theme for Plotly charts."""
    layout: Dict[str, Any] = {
        "title": {"text": title, "font": {"color": "#f8fafc", "size": 15}},
        "paper_bgcolor": "#0f172a",
        "plot_bgcolor": "#0f172a",
        "font": {"color": "#94a3b8", "family": "Segoe UI, sans-serif"},
        "xaxis": {
            "gridcolor": "#1e293b",
            "zerolinecolor": "#1e293b",
            "tickfont": {"color": "#94a3b8"}
        },
        "yaxis": {
            "gridcolor": "#1e293b",
            "zerolinecolor": "#1e293b",
            "tickfont": {"color": "#94a3b8"}
        },
        "margin": {"l": 40, "r": 20, "t": 40, "b": 40}
    }
    if height is not None:
        layout["height"] = height
    layout.update(kwargs)
    return layout

