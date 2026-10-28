"""
Authentication and Role-Based Access Control (RBAC) Module for CloudSentinel.
Provides secure password hashing (bcrypt with legacy PBKDF2 backwards-compatibility),
session management, and server-side role validation.
"""

from pathlib import Path
import sys
import hmac
import hashlib
from typing import Optional, Dict, Any, List, Tuple
import bcrypt
import streamlit as st

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from database.database import (
    get_db,
    log_audit,
    has_admin_user,
    setup_initial_admin
)

# Supported system roles in hierarchical privilege order
ROLES = ["User / Demonstrator", "Security Analyst", "Alert Reviewer", "Administrator"]

# Role permissions mapping (granular server-side authorization)
ROLE_PERMISSIONS = {
    "User / Demonstrator": {
        "can_view_demo_dashboard": True,
        "can_view_logs": True,
        "can_view_reports": True,
        "can_submit_events": True,  # Sandbox demonstration testing permitted
        "can_edit_alerts": False,
        "can_train_models": False,
        "can_manage_users": False,
        "can_view_audit_logs": False,
        "can_configure_monitoring": False,
    },
    "Security Analyst": {
        "can_view_demo_dashboard": True,
        "can_view_logs": True,
        "can_view_reports": True,
        "can_submit_events": True,
        "can_edit_alerts": False,
        "can_train_models": False,
        "can_manage_users": False,
        "can_view_audit_logs": False,
        "can_configure_monitoring": True,
    },
    "Alert Reviewer": {
        "can_view_demo_dashboard": True,
        "can_view_logs": True,
        "can_view_reports": True,
        "can_submit_events": True,
        "can_edit_alerts": True,
        "can_train_models": False,
        "can_manage_users": False,
        "can_view_audit_logs": True,
        "can_configure_monitoring": True,
    },
    "Administrator": {
        "can_view_demo_dashboard": True,
        "can_view_logs": True,
        "can_view_reports": True,
        "can_submit_events": True,
        "can_edit_alerts": True,
        "can_train_models": True,
        "can_manage_users": True,
        "can_view_audit_logs": True,
        "can_configure_monitoring": True,
    },
}


def hash_password(password: str) -> Tuple[str, str]:
    """Hashes a password using bcrypt. Returns (hash, salt_str)."""
    salt = bcrypt.gensalt(rounds=12)
    pw_hash = bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")
    return pw_hash, salt.decode("utf-8")


def verify_password(password: str, stored_hash: str, salt: Optional[str] = None) -> bool:
    """Verifies a plaintext password against a stored hash (bcrypt or legacy PBKDF2)."""
    if not stored_hash or not password:
        return False

    # Check for bcrypt hash prefix ($2a$, $2b$, $2y$)
    if stored_hash.startswith("$2a$") or stored_hash.startswith("$2b$") or stored_hash.startswith("$2y$"):
        try:
            return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
        except Exception:
            return False

    # Backwards compatibility check for legacy PBKDF2 hex hash
    if salt:
        try:
            calc_hash = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                bytes.fromhex(salt),
                200000
            ).hex()
            return hmac.compare_digest(calc_hash, stored_hash)
        except Exception:
            return False

    return False


def authenticate_user(identifier: str, password: str) -> Optional[Dict[str, Any]]:
    """Authenticates a user via email or username. Returns user dictionary if valid."""
    identifier_clean = identifier.strip().lower()
    if not identifier_clean or not password:
        return None

    with get_db() as conn:
        row = conn.execute("""
            SELECT id, username, name, email, password_hash, salt, role, is_active
            FROM users
            WHERE (LOWER(email) = ? OR LOWER(username) = ?) AND is_active = 1
        """, (identifier_clean, identifier_clean)).fetchone()

    if not row:
        return None

    user_dict = dict(row)
    if verify_password(password, user_dict["password_hash"], user_dict["salt"]):
        del user_dict["password_hash"]
        del user_dict["salt"]
        return user_dict

    return None


def register_user(
    name: str,
    username: str,
    email: str,
    password: str,
    confirm_password: str,
    role: str = "Security Analyst",
    is_public_registration: bool = True
) -> Tuple[bool, str]:
    """
    Validates and registers a new user.
    Security Rule: Public registration automatically enforces lowest non-admin role.
    """
    name = name.strip()
    username = username.strip().lower()
    email = email.strip().lower()

    if not name or not username or not email or not password:
        return False, "All fields are required."

    if len(username) < 3 or not username.replace("_", "").isalnum():
        return False, "Username must be at least 3 characters and contain only letters, numbers, or underscores."

    if "@" not in email or "." not in email.split("@")[-1]:
        return False, "Please enter a valid email address."

    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    if password != confirm_password:
        return False, "Passwords do not match."

    # Enforce security rule: Public registration must never grant elevated privileges
    if is_public_registration:
        assigned_role = "Security Analyst"
    else:
        assigned_role = role if role in ROLES else "Security Analyst"

    pw_hash, salt = hash_password(password)

    try:
        with get_db() as conn:
            cursor = conn.execute("""
                INSERT INTO users (username, name, email, password_hash, salt, role, is_active)
                VALUES (?, ?, ?, ?, ?, ?, 1)
            """, (username, name, email, pw_hash, salt, assigned_role))
            new_id = cursor.lastrowid

        log_audit(
            user_id=new_id,
            username=username,
            action="USER_REGISTRATION",
            details=f"New user registered with role '{assigned_role}'"
        )
        return True, "Account created successfully! You can now log in."
    except Exception as e:
        err_str = str(e).lower()
        if "unique" in err_str:
            if "username" in err_str:
                return False, "Username is already taken. Please choose another."
            return False, "An account with this email address already exists."
        return False, f"Registration failed: {str(e)}"


def get_current_user() -> Optional[Dict[str, Any]]:
    """Retrieves the currently logged-in user from Streamlit session state."""
    if "user" in st.session_state and st.session_state.user:
        return st.session_state.user
    return None


def is_authenticated() -> bool:
    """Returns True if a user is currently logged in and active."""
    user = get_current_user()
    return user is not None and user.get("id") is not None


def check_permission(permission_key: str) -> bool:
    """Server-side permission check for the logged-in user's role."""
    user = get_current_user()
    if not user:
        return False
    role = user.get("role", "Security Analyst")
    return ROLE_PERMISSIONS.get(role, {}).get(permission_key, False)


def require_auth(allowed_roles: Optional[List[str]] = None) -> bool:
    """
    Enforces authentication and optional role restrictions on a page.
    Stops page execution and shows an error banner if unauthorized.
    """
    if not is_authenticated():
        st.warning("⚠️ Access Denied: Please log in to view this page.")
        st.stop()
        return False

    user = get_current_user()
    user_role = user.get("role", "Security Analyst")

    if allowed_roles and user_role not in allowed_roles:
        st.error(
            f"🚫 Unauthorized: Role '{user_role}' does not have permission to access this resource. "
            f"Required role(s): {', '.join(allowed_roles)}"
        )
        st.stop()
        return False

    return True


def logout_user():
    """Clears all authentication and user session state variables."""
    user = get_current_user()
    if user:
        log_audit(
            user_id=user.get("id"),
            username=user.get("username", "unknown"),
            action="USER_LOGOUT",
            details="User logged out"
        )
    for key in ["user", "logged_in_user", "auth_token", "current_role"]:
        if key in st.session_state:
            del st.session_state[key]
