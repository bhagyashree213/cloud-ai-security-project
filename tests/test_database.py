"""
Unit and Integration Tests for CloudSentinel Database Operations.
"""

import unittest
from database.database import (
    init_db,
    get_db,
    save_event,
    fetch_logs,
    fetch_alerts,
    update_alert_status,
    get_alert_history,
    log_audit,
    fetch_audit_logs,
    get_system_kpis
)


class TestDatabaseOperations(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()

    def test_database_connection_and_wal(self):
        with get_db() as conn:
            cur = conn.execute("PRAGMA journal_mode;")
            mode = cur.fetchone()[0]
            self.assertEqual(mode.lower(), "wal")

    def test_save_event_and_atomic_alert_trigger(self):
        event = {
            "login_attempts": 15,
            "failed_attempts": 12,
            "request_count": 450,
            "file_access_count": 20,
            "data_transfer_mb": 650.0,
            "unusual_location": 1,
            "unusual_time": 1,
            "privilege_level": 3
        }

        # Saving a CRITICAL severity event should automatically create an alert
        log_id = save_event(
            event=event,
            probability=0.98,
            anomaly=True,
            risk=95,
            severity="CRITICAL",
            threat_type="Brute Force Credential Attack",
            source="Test Case",
            ip_address="192.168.1.100"
        )
        self.assertIsInstance(log_id, int)
        self.assertGreater(log_id, 0)

        # Verify event in logs
        logs = fetch_logs(limit=5, search="192.168.1.100")
        self.assertTrue(any(l["id"] == log_id for l in logs))

        # Verify alert was created
        alerts = fetch_alerts(status="OPEN")
        matching = [a for a in alerts if a["log_id"] == log_id]
        self.assertTrue(len(matching) > 0)
        alert_id = matching[0]["id"]

        # Verify status update and history tracking
        updated = update_alert_status(
            alert_id=alert_id,
            new_status="INVESTIGATING",
            changed_by="TestAnalyst",
            notes="Testing status transition"
        )
        self.assertTrue(updated)

        history = get_alert_history(alert_id)
        self.assertTrue(any(h["new_status"] == "INVESTIGATING" for h in history))

    def test_audit_log_recording(self):
        log_audit(
            user_id=1,
            username="test_admin",
            action="UNIT_TEST_ACTION",
            details="Verifying audit trail recording"
        )
        audits = fetch_audit_logs(limit=10, action="UNIT_TEST_ACTION")
        self.assertTrue(len(audits) > 0)
        self.assertEqual(audits[0]["username"], "test_admin")

    def test_system_kpis_calculation(self):
        kpis = get_system_kpis()
        self.assertIn("total_events", kpis)
        self.assertIn("threats_detected", kpis)
        self.assertIn("open_alerts", kpis)
        self.assertIn("total_website_assessments", kpis)
        self.assertGreaterEqual(kpis["total_events"], 1)

    def test_website_assessment_persistence_and_alerts(self):
        from database.database import (
            save_website_assessment,
            fetch_website_assessments,
            update_website_assessment_status
        )

        mock_report = {
            "input_url": "https://malicious-test-example.com",
            "sanitized_url": "https://malicious-test-example.com",
            "hostname": "malicious-test-example.com",
            "resolved_ips": ["198.51.100.99"],
            "overall_assessment": "Potentially Malicious",
            "summary": "Flagged by 3 security engines on VirusTotal",
            "evidence": {
                "summary": "Flagged by 3 security engines on VirusTotal",
                "items": ["VirusTotal engine alert: 3 engines flagged malicious"],
                "sources_checked": ["VirusTotal v3", "TLS Handshake"]
            },
            "tls_info": {"https_available": True, "cert_valid": True, "days_remaining": 45},
            "http_info": {"success": True, "headers_found": {}},
            "reputation_info": {"available": True, "malicious_count": 3}
        }

        # 1. Save assessment
        wa_id = save_website_assessment(mock_report, user="UnitTester")
        self.assertIsInstance(wa_id, int)
        self.assertGreater(wa_id, 0)

        # 2. Fetch assessments
        records = fetch_website_assessments(limit=10, search="malicious-test-example.com")
        self.assertTrue(len(records) > 0)
        rec = records[0]
        self.assertEqual(rec["domain"], "malicious-test-example.com")
        self.assertEqual(rec["assessment_result"], "Potentially Malicious")
        self.assertEqual(rec["alert_status"], "NEW")

        # 3. Verify auto-created alert in alerts table
        alerts = fetch_alerts(search="malicious-test-example.com")
        self.assertTrue(len(alerts) > 0)
        alert = alerts[0]
        self.assertEqual(alert["severity"], "HIGH")
        self.assertEqual(alert["status"], "NEW")

        # 4. Update status to RESOLVED
        updated = update_website_assessment_status(
            assessment_id=wa_id,
            new_status="RESOLVED",
            changed_by="UnitTester",
            notes="False positive verified"
        )
        self.assertTrue(updated)

        # Verify updated status
        updated_records = fetch_website_assessments(limit=5, search="malicious-test-example.com")
        self.assertEqual(updated_records[0]["alert_status"], "RESOLVED")


if __name__ == "__main__":
    unittest.main()
