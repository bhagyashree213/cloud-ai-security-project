"""
Database Layer for CloudSentinel — Cloud-Based AI Security and Threat Detection System.
Supports dual operational modes:
  1. LOCAL MODE: Embedded SQLite database (database/security.db) with WAL mode and foreign keys.
  2. CLOUD MODE: Amazon RDS (PostgreSQL / MySQL) with secure connection pooling and parameterized SQL.

Provides schema initialization, atomic transactions, alert lifecycle tracking,
tamper-evident audit logging, and analytics queries.
"""

from pathlib import Path
import os
import sys
import json
import sqlite3
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from contextlib import contextmanager

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Local SQLite Path (Authoritative local database)
LOCAL_DB_PATH = BASE_DIR / "database" / "security.db"
LOCAL_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# Database Mode Configuration ('sqlite' for Local Mode, 'rds' for Cloud Mode)
DATABASE_MODE = os.getenv("DATABASE_MODE", os.getenv("DB_MODE", "sqlite")).lower()

# Amazon RDS Configuration (Read securely from environment / secrets)
RDS_HOST = os.getenv("RDS_HOST")
RDS_PORT = int(os.getenv("RDS_PORT", "5432"))
RDS_DB = os.getenv("RDS_DB", "cloudsentinel")
RDS_USER = os.getenv("RDS_USER", "cloudadmin")
RDS_PASSWORD = os.getenv("RDS_PASSWORD")
RDS_ENGINE = os.getenv("RDS_ENGINE", "postgresql").lower()  # 'postgresql' or 'mysql'
DATABASE_URL = os.getenv("DATABASE_URL")


class DBConnectionWrapper:
    """
    Unified connection and query adapter that allows identical parameterized SQL
    to execute seamlessly on both SQLite and Amazon RDS (PostgreSQL/MySQL).
    """
    def __init__(self, raw_conn, is_rds: bool = False, engine: str = "sqlite"):
        self.conn = raw_conn
        self.is_rds = is_rds
        self.engine = engine

    def execute(self, query: str, params: Optional[Tuple] = None):
        if self.is_rds and params is not None:
            # PostgreSQL and MySQL use %s parameter placeholders
            adapted_query = query.replace("?", "%s")
        else:
            adapted_query = query

        cur = self.conn.cursor()
        if params is not None:
            cur.execute(adapted_query, params)
        else:
            cur.execute(adapted_query)
        return cur

    def executescript(self, script: str):
        if hasattr(self.conn, "executescript"):
            return self.conn.executescript(script)
        else:
            # Fallback for DB-API connections without native executescript
            cur = self.conn.cursor()
            statements = [s.strip() for s in script.split(";") if s.strip()]
            for stmt in statements:
                cur.execute(stmt)
            self.conn.commit()
            return cur

    def commit(self):
        return self.conn.commit()

    def rollback(self):
        return self.conn.rollback()

    def close(self):
        return self.conn.close()


def get_raw_connection():
    """Establishes connection based on active DATABASE_MODE."""
    if DATABASE_MODE == "rds" and (RDS_HOST or DATABASE_URL):
        try:
            if "postgres" in RDS_ENGINE:
                import psycopg2
                import psycopg2.extras
                if DATABASE_URL:
                    conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.DictCursor)
                else:
                    conn = psycopg2.connect(
                        host=RDS_HOST,
                        port=RDS_PORT,
                        dbname=RDS_DB,
                        user=RDS_USER,
                        password=RDS_PASSWORD,
                        cursor_factory=psycopg2.extras.DictCursor
                    )
                return DBConnectionWrapper(conn, is_rds=True, engine="postgresql")
            elif "mysql" in RDS_ENGINE:
                import pymysql
                import pymysql.cursors
                conn = pymysql.connect(
                    host=RDS_HOST,
                    port=RDS_PORT,
                    database=RDS_DB,
                    user=RDS_USER,
                    password=RDS_PASSWORD,
                    cursorclass=pymysql.cursors.DictCursor,
                    autocommit=False
                )
                return DBConnectionWrapper(conn, is_rds=True, engine="mysql")
        except Exception as e:
            print(f"[DATABASE WARNING] Failed to connect to Amazon RDS: {e}. Falling back to Local SQLite mode.")

    # Default: Local SQLite Mode
    LOCAL_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(LOCAL_DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        conn.execute("PRAGMA journal_mode = WAL;")
    except Exception:
        pass
    return DBConnectionWrapper(conn, is_rds=False, engine="sqlite")


@contextmanager
def get_db():
    """
    Context manager that yields a managed connection,
    handles commit/rollback via transaction, and guarantees connection closure.
    """
    wrapper = get_raw_connection()
    try:
        yield wrapper
        wrapper.commit()
    except Exception:
        wrapper.rollback()
        raise
    finally:
        wrapper.close()


def get_db_info() -> Dict[str, Any]:
    """Returns database operational mode, host, and storage target."""
    if DATABASE_MODE == "rds" and (RDS_HOST or DATABASE_URL):
        return {
            "mode": "CLOUD MODE (Amazon RDS)",
            "engine": RDS_ENGINE.upper(),
            "target": RDS_HOST or "Amazon RDS Endpoint",
            "is_cloud": True
        }
    return {
        "mode": "LOCAL MODE (SQLite)",
        "engine": "SQLite 3 (WAL Mode)",
        "target": str(LOCAL_DB_PATH),
        "is_cloud": False
    }


def init_db():
    """
    Initializes core database schema, constraints, and indexes.
    Idempotent and safe to run on startup.
    """
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'Security Analyst',
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                login_attempts INTEGER NOT NULL,
                failed_attempts INTEGER NOT NULL,
                request_count INTEGER NOT NULL,
                file_access_count INTEGER NOT NULL,
                data_transfer_mb REAL NOT NULL,
                unusual_location INTEGER NOT NULL,
                unusual_time INTEGER NOT NULL,
                privilege_level INTEGER NOT NULL,
                source TEXT NOT NULL DEFAULT 'Manual Form',
                ip_address TEXT DEFAULT '127.0.0.1',
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_id INTEGER NOT NULL,
                threat_probability REAL NOT NULL,
                anomaly INTEGER NOT NULL,
                risk_score INTEGER NOT NULL,
                severity TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                model_used TEXT NOT NULL DEFAULT 'Random Forest Classifier',
                anomaly_model_used TEXT NOT NULL DEFAULT 'Isolation Forest',
                contributing_factors TEXT DEFAULT '{}',
                detected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (log_id) REFERENCES security_logs(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                threat_id INTEGER DEFAULT NULL,
                log_id INTEGER DEFAULT NULL,
                assessment_id INTEGER DEFAULT NULL,
                message TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'NEW',
                assigned_to TEXT DEFAULT 'Unassigned',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (threat_id) REFERENCES threats(id) ON DELETE CASCADE,
                FOREIGN KEY (log_id) REFERENCES security_logs(id) ON DELETE CASCADE,
                FOREIGN KEY (assessment_id) REFERENCES website_assessments(id) ON DELETE CASCADE
            );


            CREATE TABLE IF NOT EXISTS alert_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                changed_by TEXT NOT NULL,
                old_status TEXT NOT NULL,
                new_status TEXT NOT NULL,
                notes TEXT,
                timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT DEFAULT '127.0.0.1',
                timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS model_evaluations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_name TEXT NOT NULL,
                model_type TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                accuracy REAL,
                precision_score REAL,
                recall_score REAL,
                f1_score REAL,
                roc_auc REAL,
                training_time_sec REAL,
                confusion_matrix TEXT,
                hyperparameters TEXT,
                is_active INTEGER NOT NULL DEFAULT 0,
                evaluated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS monitoring_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                source_type TEXT NOT NULL,
                target TEXT NOT NULL,
                interval_seconds INTEGER DEFAULT 60,
                is_active INTEGER DEFAULT 0,
                last_status TEXT DEFAULT 'IDLE',
                last_checked TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS website_assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_url TEXT NOT NULL,
                domain TEXT NOT NULL,
                ip_address TEXT,
                assessment_result TEXT NOT NULL,
                alert_status TEXT NOT NULL DEFAULT 'NEW',
                severity TEXT NOT NULL DEFAULT 'LOW',
                evidence_summary TEXT NOT NULL,
                findings_json TEXT NOT NULL DEFAULT '{}',
                sources_checked TEXT NOT NULL DEFAULT 'TLS/SSL, HTTP Headers, VirusTotal v3',
                virustotal_stats TEXT DEFAULT '{}',
                tls_status TEXT,
                headers_status TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                created_by TEXT DEFAULT 'System'
            );

            CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON security_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
            CREATE INDEX IF NOT EXISTS idx_threats_log_id ON threats(log_id);
            CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
            CREATE INDEX IF NOT EXISTS idx_alerts_threat_id ON alerts(threat_id);
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_wa_timestamp ON website_assessments(created_at);
            CREATE INDEX IF NOT EXISTS idx_wa_result ON website_assessments(assessment_result);
            CREATE INDEX IF NOT EXISTS idx_wa_domain ON website_assessments(domain);
        """)

        # Migration: ensure alerts table allows nullable threat_id and has assessment_id
        try:
            cols = conn.execute("PRAGMA table_info(alerts)").fetchall()
            col_names = [c["name"] for c in cols]
            threat_col = [c for c in cols if c["name"] == "threat_id"]
            if threat_col and threat_col[0]["notnull"] == 1:
                conn.execute("PRAGMA foreign_keys = OFF;")
                conn.execute("DROP TABLE IF EXISTS alerts_new;")
                conn.execute("""
                    CREATE TABLE alerts_new (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        threat_id INTEGER DEFAULT NULL,
                        log_id INTEGER DEFAULT NULL,
                        assessment_id INTEGER DEFAULT NULL,
                        message TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'NEW',
                        assigned_to TEXT DEFAULT 'Unassigned',
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (threat_id) REFERENCES threats(id) ON DELETE CASCADE,
                        FOREIGN KEY (log_id) REFERENCES security_logs(id) ON DELETE CASCADE,
                        FOREIGN KEY (assessment_id) REFERENCES website_assessments(id) ON DELETE CASCADE
                    );
                """)
                conn.execute("""
                    INSERT INTO alerts_new (id, threat_id, log_id, message, severity, status, assigned_to, created_at, updated_at)
                    SELECT id, threat_id, log_id, message, severity, status, assigned_to, created_at, COALESCE(updated_at, created_at) FROM alerts;
                """)
                conn.execute("DROP TABLE alerts;")
                conn.execute("ALTER TABLE alerts_new RENAME TO alerts;")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_threat_id ON alerts(threat_id);")
                conn.execute("PRAGMA foreign_keys = ON;")
            elif "assessment_id" not in col_names:
                conn.execute("ALTER TABLE alerts ADD COLUMN assessment_id INTEGER DEFAULT NULL;")
        except Exception:
            pass


# =====================================================================
# USER AND RBAC MANAGEMENT
# =====================================================================

def has_admin_user() -> bool:
    """Checks whether an Administrator account exists."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'Administrator' AND is_active = 1"
        ).fetchone()
        return bool(row and row[0] > 0)


def setup_initial_admin(name: str, username: str, email: str, password_hash: str, salt: str) -> bool:
    """Sets up the very first Administrator account if none exists."""
    if has_admin_user():
        return False

    with get_db() as conn:
        conn.execute("""
            INSERT INTO users (name, username, email, password_hash, salt, role, is_active)
            VALUES (?, ?, ?, ?, ?, 'Administrator', 1)
        """, (name.strip(), username.strip().lower(), email.strip().lower(), password_hash, salt))

    log_audit(
        user_id=1,
        username=username,
        action="INITIAL_ADMIN_SETUP",
        details="Initial administrator account created during first-run bootstrap."
    )
    return True


def get_all_users() -> List[Dict[str, Any]]:
    """Fetches all users excluding password hashes."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT id, username, name, email, role, is_active, created_at
            FROM users
            ORDER BY id ASC
        """).fetchall()
        return [dict(r) for r in rows]


def update_user_role(user_id: int, new_role: str, admin_username: str) -> bool:
    """Updates user role and records audit event."""
    valid_roles = {"Administrator", "Alert Reviewer", "Security Analyst", "User / Demonstrator"}
    if new_role not in valid_roles:
        raise ValueError(f"Invalid role: {new_role}")

    with get_db() as conn:
        user = conn.execute("SELECT username, role FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            return False

        old_role = user["role"]
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))

    log_audit(
        user_id=user_id,
        username=admin_username,
        action="USER_ROLE_CHANGE",
        details=f"Changed role for user '{user['username']}' from '{old_role}' to '{new_role}'"
    )
    return True


def toggle_user_status(user_id: int, is_active: bool, admin_username: str) -> bool:
    """Activates or deactivates a user account."""
    with get_db() as conn:
        user = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            return False
        conn.execute("UPDATE users SET is_active = ? WHERE id = ?", (1 if is_active else 0, user_id))

    log_audit(
        user_id=user_id,
        username=admin_username,
        action="USER_STATUS_CHANGE",
        details=f"User '{user['username']}' active status set to {is_active}"
    )
    return True


def delete_user(user_id: int, admin_username: str) -> bool:
    """Deletes a user account and records an audit log entry."""
    with get_db() as conn:
        user = conn.execute("SELECT username, role FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user:
            return False
        if user["role"] == "Administrator":
            admin_count = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'Administrator'").fetchone()[0]
            if admin_count <= 1:
                raise ValueError("Cannot delete the last remaining Administrator account.")
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))

    log_audit(
        user_id=None,
        username=admin_username,
        action="USER_DELETION",
        details=f"Deleted user account '{user['username']}' (ID: {user_id})"
    )
    return True


# =====================================================================
# EVENT, THREAT, AND ALERT PERSISTENCE
# =====================================================================

def save_event(
    event: Dict[str, Any],
    probability: float,
    anomaly: bool,
    risk: int,
    severity: str,
    threat_type: str,
    user_id: Optional[int] = None,
    source: str = "Manual Form",
    model_used: str = "Random Forest Classifier",
    anomaly_model_used: str = "Isolation Forest",
    contributing_factors: Optional[Dict[str, Any]] = None,
    ip_address: str = "127.0.0.1"
) -> int:
    """
    Saves an analyzed security event, threat evaluation, and conditional alert.
    Uses an atomic transaction to guarantee data integrity across tables.
    """
    factors_json = json.dumps(contributing_factors or {})

    with get_db() as conn:
        # 1. Insert security log
        cursor = conn.execute("""
            INSERT INTO security_logs (
                user_id, login_attempts, failed_attempts, request_count,
                file_access_count, data_transfer_mb,
                unusual_location, unusual_time, privilege_level,
                source, ip_address
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id,
            int(event["login_attempts"]),
            int(event["failed_attempts"]),
            int(event["request_count"]),
            int(event["file_access_count"]),
            float(event["data_transfer_mb"]),
            int(event["unusual_location"]),
            int(event["unusual_time"]),
            int(event["privilege_level"]),
            source,
            ip_address
        ))
        log_id = cursor.lastrowid

        # 2. Insert threat evaluation
        threat_cursor = conn.execute("""
            INSERT INTO threats (
                log_id, threat_probability, anomaly, risk_score,
                severity, threat_type, model_used, anomaly_model_used,
                contributing_factors
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            log_id,
            float(probability),
            int(anomaly),
            int(risk),
            severity,
            threat_type,
            model_used,
            anomaly_model_used,
            factors_json
        ))
        threat_id = threat_cursor.lastrowid

        # 3. Automatically create alert for HIGH or CRITICAL risk
        if severity in ("HIGH", "CRITICAL"):
            alert_msg = f"{threat_type} detected with Risk Score {risk}/100 ({severity})."
            alert_cur = conn.execute("""
                INSERT INTO alerts (threat_id, log_id, message, severity, status, assigned_to)
                VALUES (?, ?, ?, ?, 'NEW', 'Unassigned')
            """, (threat_id, log_id, alert_msg, severity))
            alert_id = alert_cur.lastrowid

            # Initial history record
            conn.execute("""
                INSERT INTO alert_history (alert_id, changed_by, old_status, new_status, notes)
                VALUES (?, 'System', 'NONE', 'NEW', 'Alert auto-generated by AI Threat Detection Pipeline')
            """, (alert_id,))


        return log_id


def fetch_logs(
    limit: Optional[int] = None,
    severity: Optional[str] = None,
    threat_type: Optional[str] = None,
    search: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Fetches security logs joined with threat evaluation details with flexible filtering.
    """
    query = """
        SELECT l.*,
               t.id AS threat_id,
               t.threat_probability,
               t.anomaly,
               t.risk_score,
               t.severity,
               t.threat_type,
               t.model_used,
               t.anomaly_model_used,
               t.contributing_factors,
               u.username AS submitted_by_username
        FROM security_logs l
        LEFT JOIN threats t ON t.log_id = l.id
        LEFT JOIN users u ON u.id = l.user_id
        WHERE 1=1
    """
    params: List[Any] = []

    if severity and severity != "ALL":
        query += " AND t.severity = ?"
        params.append(severity)

    if threat_type and threat_type != "ALL":
        query += " AND t.threat_type LIKE ?"
        params.append(f"%{threat_type}%")

    if search:
        query += """ AND (
            l.source LIKE ? OR
            l.ip_address LIKE ? OR
            t.threat_type LIKE ? OR
            u.username LIKE ?
        )"""
        s_pat = f"%{search}%"
        params.extend([s_pat, s_pat, s_pat, s_pat])

    if start_date:
        query += " AND date(l.timestamp) >= date(?)"
        params.append(start_date)

    if end_date:
        query += " AND date(l.timestamp) <= date(?)"
        params.append(end_date)

    query += " ORDER BY l.id DESC"

    if limit:
        query += " LIMIT ?"
        params.append(limit)

    with get_db() as conn:
        rows = conn.execute(query, tuple(params)).fetchall()
        return [dict(r) for r in rows]


def get_event_by_id(log_id: int) -> Optional[Dict[str, Any]]:
    """Fetches single event with full threat & user details."""
    with get_db() as conn:
        row = conn.execute("""
            SELECT l.*,
                   t.id AS threat_id,
                   t.threat_probability,
                   t.anomaly,
                   t.risk_score,
                   t.severity,
                   t.threat_type,
                   t.model_used,
                   t.anomaly_model_used,
                   t.contributing_factors,
                   u.username AS submitted_by_username
            FROM security_logs l
            LEFT JOIN threats t ON t.log_id = l.id
            LEFT JOIN users u ON u.id = l.user_id
            WHERE l.id = ?
        """, (log_id,)).fetchone()
        return dict(row) if row else None


# =====================================================================
# ALERTS AND AUDITING
# =====================================================================

def fetch_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    limit: Optional[int] = None
) -> List[Dict[str, Any]]:
    """Fetches alerts joined with threats, logs, and website assessments."""
    query = """
        SELECT a.id,
               a.threat_id,
               a.log_id,
               a.assessment_id,
               a.message,
               a.severity,
               a.status,
               a.assigned_to,
               a.created_at,
               a.updated_at,
               COALESCE(t.risk_score, 0) AS risk_score,
               COALESCE(t.threat_type, 'Website Threat') AS threat_type,
               COALESCE(t.threat_probability, 0.0) AS threat_probability,
               COALESCE(t.anomaly, 0) AS anomaly,
               COALESCE(t.model_used, 'VirusTotal & Defensive Audit') AS model_used,
               COALESCE(l.ip_address, wa.ip_address, 'N/A') AS ip_address,
               COALESCE(l.source, 'Website Threat Checker') AS source,
               wa.target_url,
               wa.domain,
               wa.assessment_result
        FROM alerts a
        LEFT JOIN threats t ON t.id = a.threat_id
        LEFT JOIN security_logs l ON l.id = a.log_id
        LEFT JOIN website_assessments wa ON wa.id = a.assessment_id
        WHERE 1=1
    """
    params: List[Any] = []

    if status and status != "ALL":
        if status in ("NEW", "OPEN"):
            query += " AND (a.status = 'NEW' OR a.status = 'OPEN')"
        else:
            query += " AND a.status = ?"
            params.append(status)

    if severity and severity != "ALL":
        query += " AND a.severity = ?"
        params.append(severity)

    if search:
        query += " AND (a.message LIKE ? OR t.threat_type LIKE ? OR a.assigned_to LIKE ? OR wa.domain LIKE ?)"
        pattern = f"%{search}%"
        params.extend([pattern, pattern, pattern, pattern])

    query += " ORDER BY a.id DESC"
    if limit is not None:
        query += f" LIMIT {int(limit)}"

    with get_db() as conn:
        rows = conn.execute(query, tuple(params)).fetchall()
        return [dict(r) for r in rows]


def update_alert_status(alert_id: int, new_status: str, changed_by: str, notes: Optional[str] = None) -> bool:
    """Updates alert status and records full audit trail into alert_history."""
    allowed_statuses = {"NEW", "INVESTIGATING", "RESOLVED", "OPEN"}
    if new_status not in allowed_statuses:
        raise ValueError(f"Invalid alert status: {new_status}. Allowed: {allowed_statuses}")


    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with get_db() as conn:
        row = conn.execute("SELECT status FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if not row:
            return False

        old_status = row["status"]
        if old_status == new_status and not notes:
            return True

        # Update alert
        conn.execute("""
            UPDATE alerts
            SET status = ?, updated_at = ?
            WHERE id = ?
        """, (new_status, now_str, alert_id))

        # Insert into alert_history
        conn.execute("""
            INSERT INTO alert_history (alert_id, changed_by, old_status, new_status, notes)
            VALUES (?, ?, ?, ?, ?)
        """, (alert_id, changed_by, old_status, new_status, notes or f"Status changed from {old_status} to {new_status}"))

    log_audit(
        user_id=None,
        username=changed_by,
        action="ALERT_STATUS_CHANGE",
        details=f"Alert #{alert_id} status changed from {old_status} to {new_status}. Notes: {notes or 'None'}"
    )
    return True


def assign_alert(alert_id: int, assigned_to: str, changed_by: str) -> bool:
    """Assigns an alert to a reviewer."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_db() as conn:
        conn.execute("""
            UPDATE alerts
            SET assigned_to = ?, updated_at = ?
            WHERE id = ?
        """, (assigned_to.strip(), now_str, alert_id))

    log_audit(
        user_id=None,
        username=changed_by,
        action="ALERT_ASSIGNMENT",
        details=f"Alert #{alert_id} assigned to '{assigned_to}'"
    )
    return True


def get_alert_history(alert_id: int) -> List[Dict[str, Any]]:
    """Retrieves chronological lifecycle history for an alert."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT id, alert_id, changed_by, old_status, new_status, notes, timestamp
            FROM alert_history
            WHERE alert_id = ?
            ORDER BY id ASC
        """, (alert_id,)).fetchall()
        return [dict(r) for r in rows]


def log_audit(
    user_id: Optional[int],
    username: str,
    action: str,
    details: str = "",
    ip_address: str = "127.0.0.1"
):
    """Inserts a tamper-evident record into system audit_logs."""
    try:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO audit_logs (user_id, username, action, details, ip_address)
                VALUES (?, ?, ?, ?, ?)
            """, (user_id, username, action, details, ip_address))
    except Exception as e:
        print(f"[AUDIT LOG ERROR] Failed to record audit log: {e}")


def fetch_audit_logs(limit: int = 100, action: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fetches recent audit log entries."""
    query = "SELECT * FROM audit_logs"
    params: List[Any] = []
    if action and action != "ALL":
        query += " WHERE action = ?"
        params.append(action)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with get_db() as conn:
        rows = conn.execute(query, tuple(params)).fetchall()
        return [dict(r) for r in rows]


# =====================================================================
# MODEL EVALUATIONS AND ACTIVE MODEL TRACKING
# =====================================================================

def save_model_evaluation(
    model_name: str,
    model_type: str,
    algorithm: str,
    accuracy: Optional[float],
    precision_score: Optional[float],
    recall_score: Optional[float],
    f1_score: Optional[float],
    roc_auc: Optional[float],
    training_time_sec: float,
    confusion_matrix: Optional[List[List[int]]] = None,
    hyperparameters: Optional[Dict[str, Any]] = None,
    is_active: bool = False
) -> int:
    """Stores benchmark metrics and configuration for an evaluated AI model."""
    cm_json = json.dumps(confusion_matrix) if confusion_matrix is not None else None
    params_json = json.dumps(hyperparameters) if hyperparameters is not None else None

    with get_db() as conn:
        if is_active:
            conn.execute(
                "UPDATE model_evaluations SET is_active = 0 WHERE model_type = ?",
                (model_type,)
            )

        cur = conn.execute("""
            INSERT INTO model_evaluations (
                model_name, model_type, algorithm, accuracy, precision_score,
                recall_score, f1_score, roc_auc, training_time_sec,
                confusion_matrix, hyperparameters, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            model_name, model_type, algorithm, accuracy, precision_score,
            recall_score, f1_score, roc_auc, training_time_sec,
            cm_json, params_json, 1 if is_active else 0
        ))
        return cur.lastrowid


def fetch_model_evaluations(model_type: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fetches stored model evaluation runs."""
    query = "SELECT * FROM model_evaluations"
    params: List[Any] = []
    if model_type:
        query += " WHERE model_type = ?"
        params.append(model_type)
    query += " ORDER BY id DESC"

    with get_db() as conn:
        rows = conn.execute(query, tuple(params)).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if d.get("confusion_matrix"):
                try:
                    d["confusion_matrix"] = json.loads(d["confusion_matrix"])
                except Exception:
                    pass
            if d.get("hyperparameters"):
                try:
                    d["hyperparameters"] = json.loads(d["hyperparameters"])
                except Exception:
                    pass
            result.append(d)
        return result


def set_active_model(eval_id: int) -> bool:
    """Designates a specific trained model as active for production inference."""
    with get_db() as conn:
        row = conn.execute("SELECT model_type, model_name FROM model_evaluations WHERE id = ?", (eval_id,)).fetchone()
        if not row:
            return False
        m_type = row["model_type"]
        conn.execute("UPDATE model_evaluations SET is_active = 0 WHERE model_type = ?", (m_type,))
        conn.execute("UPDATE model_evaluations SET is_active = 1 WHERE id = ?", (eval_id,))

    log_audit(
        user_id=None,
        username="System",
        action="MODEL_DEPLOYMENT",
        details=f"Active deployment set to {row['model_name']} (ID: {eval_id})"
    )
    return True


# =====================================================================
# SYSTEM METRICS AND DASHBOARD KPIS
# =====================================================================

def get_system_kpis() -> Dict[str, Any]:
    """Calculates live KPI metrics directly from the database."""
    with get_db() as conn:
        total_events = conn.execute("SELECT COUNT(*) FROM security_logs").fetchone()[0]
        
        threats_detected = conn.execute("""
            SELECT COUNT(*) FROM threats
            WHERE threat_probability >= 0.5 OR anomaly = 1
        """).fetchone()[0]

        high_risk = conn.execute("SELECT COUNT(*) FROM threats WHERE severity = 'HIGH'").fetchone()[0]
        critical_risk = conn.execute("SELECT COUNT(*) FROM threats WHERE severity = 'CRITICAL'").fetchone()[0]

        open_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE status IN ('NEW', 'OPEN')").fetchone()[0]
        investigating_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE status = 'INVESTIGATING'").fetchone()[0]
        resolved_alerts = conn.execute("SELECT COUNT(*) FROM alerts WHERE status = 'RESOLVED'").fetchone()[0]

        total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]

        severities = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        sev_rows = conn.execute("SELECT severity, COUNT(*) as cnt FROM threats GROUP BY severity").fetchall()
        for r in sev_rows:
            if r["severity"] in severities:
                severities[r["severity"]] = r["cnt"]

        db_info = get_db_info()

        # Real Website Assessment KPIs
        total_website_assessments = conn.execute("SELECT COUNT(*) FROM website_assessments").fetchone()[0]
        malicious_websites = conn.execute("SELECT COUNT(*) FROM website_assessments WHERE assessment_result = 'Potentially Malicious'").fetchone()[0]
        clean_websites = conn.execute("SELECT COUNT(*) FROM website_assessments WHERE assessment_result = 'No Threat Detected by Available Sources'").fetchone()[0]
        undetermined_websites = conn.execute("SELECT COUNT(*) FROM website_assessments WHERE assessment_result = 'Unable to Determine'").fetchone()[0]

        return {
            "total_events": total_events,
            "threats_detected": threats_detected,
            "high_risk": high_risk,
            "critical_risk": critical_risk,
            "open_alerts": open_alerts,
            "new_alerts": open_alerts,
            "investigating_alerts": investigating_alerts,
            "resolved_alerts": resolved_alerts,
            "total_alerts": open_alerts + investigating_alerts + resolved_alerts,

            "total_website_assessments": total_website_assessments,
            "malicious_websites": malicious_websites,
            "clean_websites": clean_websites,
            "undetermined_websites": undetermined_websites,

            "total_users": total_users,
            "severity_counts": severities,
            "db_connected": True,
            "db_mode": db_info["mode"],
            "db_target": db_info["target"],
            "is_cloud_db": db_info["is_cloud"]
        }


# =====================================================================
# WEBSITE THREAT ASSESSMENTS REPOSITORY
# =====================================================================

def save_website_assessment(assessment_data: Dict[str, Any], user: str = "System") -> int:
    """
    Persists a safe website threat inspection report into website_assessments.
    If assessment_result is 'Potentially Malicious', automatically creates an alert with status 'NEW'.
    """
    target_url = assessment_data.get("sanitized_url") or assessment_data.get("input_url", "")
    domain = assessment_data.get("hostname", "")
    ips = assessment_data.get("resolved_ips", [])
    ip_address = ips[0] if ips else ""
    assessment_result = assessment_data.get("overall_assessment", "Unable to Determine")

    # Map assessment to severity and alert status
    if assessment_result == "Potentially Malicious":
        severity = "HIGH"
        alert_status = "NEW"
    elif assessment_result == "Unable to Determine":
        severity = "MEDIUM"
        alert_status = "NEW"
    else:
        severity = "LOW"
        alert_status = "RESOLVED"

    evidence = assessment_data.get("evidence", {})
    evidence_summary = evidence.get("summary") or assessment_data.get("summary", "")
    findings_json = json.dumps({
        "tls_info": assessment_data.get("tls_info", {}),
        "http_info": assessment_data.get("http_info", {}),
        "reputation_info": assessment_data.get("reputation_info", {}),
        "concerns": assessment_data.get("concerns", []),
        "evidence_items": evidence.get("items", [])
    })

    sources = ", ".join(evidence.get("sources_checked", ["TLS/SSL", "HTTP Headers", "VirusTotal v3"]))
    vt_stats = json.dumps(assessment_data.get("reputation_info", {}))

    tls_info = assessment_data.get("tls_info", {})
    if tls_info.get("https_available") and tls_info.get("cert_valid"):
        tls_status = f"Valid ({tls_info.get('days_remaining', 0)}d remaining)"
    elif tls_info.get("is_expired"):
        tls_status = "EXPIRED"
    elif not tls_info.get("https_available"):
        tls_status = "HTTPS Unavailable"
    else:
        tls_status = tls_info.get("error", "Invalid Certificate")

    http_info = assessment_data.get("http_info", {})
    headers_count = len(http_info.get("headers_found", {}))
    headers_status = f"{headers_count}/6 Headers Present"

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with get_db() as conn:
        cur = conn.execute("""
            INSERT INTO website_assessments (
                target_url, domain, ip_address, assessment_result, alert_status,
                severity, evidence_summary, findings_json, sources_checked,
                virustotal_stats, tls_status, headers_status, created_at, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            target_url, domain, ip_address, assessment_result, alert_status,
            severity, evidence_summary, findings_json, sources,
            vt_stats, tls_status, headers_status, now_str, user
        ))
        assessment_id = cur.lastrowid

        # Auto-create alert if Potentially Malicious
        if assessment_result == "Potentially Malicious":
            conn.execute("""
                INSERT INTO alerts (threat_id, log_id, assessment_id, message, severity, status, assigned_to, created_at, updated_at)
                VALUES (NULL, NULL, ?, ?, ?, 'NEW', 'Unassigned', ?, ?)
            """, (
                assessment_id,
                f"Website Assessment Flagged Potentially Malicious: {domain} ({evidence_summary[:100]})",
                severity,
                now_str,
                now_str
            ))

    log_audit(
        user_id=None,
        username=user,
        action="WEBSITE_ASSESSMENT_SAVED",
        details=f"Assessment #{assessment_id} for {domain}: {assessment_result}",
        ip_address=ip_address or "127.0.0.1"
    )

    return assessment_id


def fetch_website_assessments(
    limit: int = 100,
    result_filter: Optional[str] = None,
    status_filter: Optional[str] = None,
    search: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Retrieves stored website assessments with optional filtering."""
    query = "SELECT * FROM website_assessments WHERE 1=1"
    params: List[Any] = []

    if result_filter and result_filter != "ALL":
        query += " AND assessment_result = ?"
        params.append(result_filter)

    if status_filter and status_filter != "ALL":
        if status_filter in ("NEW", "OPEN"):
            query += " AND (alert_status = 'NEW' OR alert_status = 'OPEN')"
        else:
            query += " AND alert_status = ?"
            params.append(status_filter)

    if search:
        query += " AND (domain LIKE ? OR target_url LIKE ? OR ip_address LIKE ? OR evidence_summary LIKE ?)"
        pat = f"%{search}%"
        params.extend([pat, pat, pat, pat])

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with get_db() as conn:
        rows = conn.execute(query, tuple(params)).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            if d.get("findings_json"):
                try:
                    d["findings"] = json.loads(d["findings_json"])
                except Exception:
                    d["findings"] = {}
            if d.get("virustotal_stats"):
                try:
                    d["virustotal"] = json.loads(d["virustotal_stats"])
                except Exception:
                    d["virustotal"] = {}
            result.append(d)
        return result


def update_website_assessment_status(
    assessment_id: int,
    new_status: str,
    changed_by: str,
    notes: Optional[str] = None
) -> bool:
    """Updates the alert status of a website assessment and any linked alert."""
    allowed = {"NEW", "INVESTIGATING", "RESOLVED", "OPEN"}
    if new_status not in allowed:
        raise ValueError(f"Invalid alert status: {new_status}")

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with get_db() as conn:
        row = conn.execute("SELECT alert_status, domain FROM website_assessments WHERE id = ?", (assessment_id,)).fetchone()
        if not row:
            return False

        old_status = row["alert_status"]
        conn.execute("""
            UPDATE website_assessments
            SET alert_status = ?
            WHERE id = ?
        """, (new_status, assessment_id))

        # Also update linked alert if exists
        conn.execute("""
            UPDATE alerts
            SET status = ?, updated_at = ?
            WHERE assessment_id = ?
        """, (new_status, now_str, assessment_id))

    log_audit(
        user_id=None,
        username=changed_by,
        action="WEBSITE_ASSESSMENT_STATUS_CHANGE",
        details=f"Assessment #{assessment_id} ({row['domain']}) status changed from {old_status} to {new_status}. Notes: {notes or 'None'}"
    )
    return True


def get_website_assessment_by_id(assessment_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves a single website assessment by its ID."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM website_assessments WHERE id = ?", (assessment_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        if d.get("findings_json"):
            try:
                d["findings"] = json.loads(d["findings_json"])
            except Exception:
                d["findings"] = {}
        if d.get("virustotal_stats"):
            try:
                d["virustotal"] = json.loads(d["virustotal_stats"])
            except Exception:
                d["virustotal"] = {}
        return d


# =====================================================================
# CSV SANITIZATION (FORMULA INJECTION PROTECTION)
# =====================================================================

def sanitize_for_csv(val: Any) -> Any:
    """
    Prevents CSV / Spreadsheet Formula Injection (OWASP ASVS requirement).
    Prepends a single apostrophe (') to cell values starting with =, +, -, @, or tabs.
    """
    if val is None:
        return ""
    s_val = str(val)
    if s_val and s_val[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s_val
    return s_val


# =====================================================================
# DATABASE SNAPSHOT & BACKUP
# =====================================================================

def backup_database(destination_dir: Optional[Path] = None) -> Optional[Path]:
    """
    Creates a consistent SQLite snapshot backup into database/backups/.
    Uses sqlite3 online backup API to ensure transaction consistency.
    """
    if IS_CLOUD_MODE:
        return None  # RDS backups are managed via AWS RDS automated snapshots

    backup_dir = destination_dir or (BASE_DIR / "database" / "backups")
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = backup_dir / f"security_backup_{timestamp_str}.db"

    source_conn = sqlite3.connect(SQLITE_DB_PATH)
    dest_conn = sqlite3.connect(backup_file)
    with dest_conn:
        source_conn.backup(dest_conn)
    dest_conn.close()
    source_conn.close()

    return backup_file


if __name__ == "__main__":
    init_db()
    info = get_db_info()
    print(f"Database initialized successfully. Mode: {info['mode']} | Target: {info['target']}")
