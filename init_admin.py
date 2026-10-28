"""
Administrative Account Bootstrap Utility for CloudSentinel.
Can be run via CLI to initialize or reset the system administrator credentials.
"""

import sys
import argparse
import getpass
from database.database import init_db, get_connection, log_audit, has_admin_user
from auth import hash_password

def setup_admin(name: str, username: str, email: str, password: str, force: bool = False):
    init_db()
    name = name.strip()
    username = username.strip().lower()
    email = email.strip().lower()

    if len(password) < 8:
        print("[-] Error: Password must be at least 8 characters long.")
        return False

    with get_connection() as conn:
        existing = conn.execute(
            "SELECT id, username, role FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?",
            (username, email)
        ).fetchone()

        pw_hash, salt = hash_password(password)

        if existing:
            if not force:
                print(f"[!] User with username '{username}' or email '{email}' already exists (Role: {existing['role']}).")
                print("    Use --force to reset their password and ensure Administrator privileges.")
                return False
            else:
                conn.execute("""
                    UPDATE users
                    SET password_hash = ?, salt = ?, role = 'Administrator', is_active = 1
                    WHERE id = ?
                """, (pw_hash, salt, existing["id"]))
                print(f"[+] Successfully updated existing user '{username}' to Administrator with new password.")
                log_audit(
                    user_id=existing["id"],
                    username="CLI_BOOTSTRAP",
                    action="ADMIN_PASSWORD_RESET",
                    details=f"Admin password reset via CLI for user '{username}'",
                    conn=conn
                )
                return True
        else:
            cur = conn.execute("""
                INSERT INTO users (username, name, email, password_hash, salt, role, is_active)
                VALUES (?, ?, ?, ?, ?, 'Administrator', 1)
            """, (username, name, email, pw_hash, salt))
            admin_id = cur.lastrowid
            print(f"[+] Successfully created new Administrator: '{username}' (ID: {admin_id})")
            log_audit(
                user_id=admin_id,
                username="CLI_BOOTSTRAP",
                action="INITIAL_ADMIN_CREATED",
                details=f"Admin credentials configured via CLI for user '{username}'",
                conn=conn
            )
            return True

def main():
    parser = argparse.ArgumentParser(description="CloudSentinel Administrator Bootstrap Utility")
    parser.add_argument("--username", help="Administrator username", default=None)
    parser.add_argument("--name", help="Administrator full name", default=None)
    parser.add_argument("--email", help="Administrator email address", default=None)
    parser.add_argument("--password", help="Administrator password", default=None)
    parser.add_argument("--force", action="store_true", help="Force update if user already exists")

    args = parser.parse_args()

    if args.username and args.email and args.password:
        name = args.name or args.username.capitalize()
        setup_admin(name, args.username, args.email, args.password, force=args.force)
    else:
        print("=== CloudSentinel Administrator Setup ===")
        username = input("Enter admin username: ").strip()
        name = input("Enter admin full name: ").strip()
        email = input("Enter admin email: ").strip()
        password = getpass.getpass("Enter admin password (min 8 chars): ").strip()
        confirm = getpass.getpass("Confirm admin password: ").strip()

        if password != confirm:
            print("[-] Error: Passwords do not match.")
            sys.exit(1)

        setup_admin(name, username, email, password, force=args.force)

if __name__ == "__main__":
    main()
