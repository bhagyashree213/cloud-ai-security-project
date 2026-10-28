"""
Unit and Integration Tests for CloudSentinel Authentication & RBAC.
"""

import unittest
from auth import (
    hash_password,
    verify_password,
    authenticate_user,
    register_user,
    ROLES,
    ROLE_PERMISSIONS
)
from database.database import init_db, delete_user


class TestAuthAndRBAC(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()

    def test_bcrypt_hashing_and_verification(self):
        password = "TestPassword@123"
        pw_hash, salt = hash_password(password)
        self.assertTrue(pw_hash.startswith("$2b$") or pw_hash.startswith("$2a$"))
        self.assertTrue(verify_password(password, pw_hash, salt))
        self.assertFalse(verify_password("WrongPassword!", pw_hash, salt))

    def test_legacy_pbkdf2_hash_compatibility(self):
        # Sample hash compatibility verification
        import hashlib
        salt_hex = "5660e6f86dbf374b699ceed9cf977a1d"
        raw_pw = "SampleLegacyPass123"
        legacy_hash = hashlib.pbkdf2_hmac("sha256", raw_pw.encode(), bytes.fromhex(salt_hex), 200000).hex()

        self.assertTrue(verify_password(raw_pw, legacy_hash, salt=salt_hex))
        self.assertFalse(verify_password("InvalidPassword", legacy_hash, salt=salt_hex))

    def test_public_registration_role_enforcement(self):
        import uuid
        unique_id = uuid.uuid4().hex[:8]
        u_name = f"user_{unique_id}"
        u_email = f"{u_name}@cloudsentinel.local"

        # Security Rule: Public registration must never allow Administrator role directly
        success, msg = register_user(
            name="Test Public Analyst",
            username=u_name,
            email=u_email,
            password="SecurePassword@123",
            confirm_password="SecurePassword@123",
            role="Administrator",  # Attempting privilege escalation
            is_public_registration=True
        )
        self.assertTrue(success, f"Registration failed: {msg}")

        # Verify role in DB is Security Analyst, NOT Administrator
        user = authenticate_user(u_name, "SecurePassword@123")
        self.assertIsNotNone(user)
        self.assertEqual(user["role"], "Security Analyst")

        # Cleanup test user after verification
        delete_user(user["id"], "TestRunner")

    def test_password_length_validation(self):
        success, msg = register_user(
            name="Short Pass User",
            username="shortpass",
            email="short@test.local",
            password="short",
            confirm_password="short",
            is_public_registration=True
        )
        self.assertFalse(success)
        self.assertIn("8 characters", msg)

    def test_role_permissions_matrix(self):
        self.assertTrue(ROLE_PERMISSIONS["Administrator"]["can_train_models"])
        self.assertTrue(ROLE_PERMISSIONS["Administrator"]["can_manage_users"])
        self.assertFalse(ROLE_PERMISSIONS["Security Analyst"]["can_train_models"])
        self.assertFalse(ROLE_PERMISSIONS["Security Analyst"]["can_edit_alerts"])
        self.assertTrue(ROLE_PERMISSIONS["Alert Reviewer"]["can_edit_alerts"])


if __name__ == "__main__":
    unittest.main()
