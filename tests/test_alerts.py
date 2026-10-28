"""
Unit and Integration Tests for Alert Lifecycles and Triage Workflows.
Tests alert generation for HIGH and CRITICAL risks, status progression,
assignment, and lifecycle audit history.
"""

import unittest
from database.database import (
    init_db,
    save_event,
    fetch_alerts,
    update_alert_status,
    assign_alert,
    get_alert_history
)


class TestAlerts(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()

    def test_alert_generation_on_critical_severity(self):
        sample_crit = {
            "login_attempts": 20,
            "failed_attempts": 18,
            "request_count": 800,
            "file_access_count": 25,
            "data_transfer_mb": 500.0,
            "unusual_location": 1,
            "unusual_time": 1,
            "privilege_level": 3
        }
        log_id = save_event(
            event=sample_crit,
            probability=0.97,
            anomaly=True,
            risk=92,
            severity="CRITICAL",
            threat_type="Brute Force Credential Attack",
            source="Test Suite",
            ip_address="192.168.10.99"
        )
        self.assertGreater(log_id, 0)

        # Confirm alert was auto-created
        alerts = fetch_alerts(status="OPEN")
        matching = [a for a in alerts if a["log_id"] == log_id]
        self.assertGreaterEqual(len(matching), 1)
        alert_id = matching[0]["id"]
        self.assertEqual(matching[0]["severity"], "CRITICAL")

        # Test transition to INVESTIGATING
        updated = update_alert_status(
            alert_id=alert_id,
            new_status="INVESTIGATING",
            changed_by="TestAnalyst",
            notes="Active investigation in progress"
        )
        self.assertTrue(updated)

        # Test assignment
        assigned = assign_alert(
            alert_id=alert_id,
            assigned_to="SeniorAnalyst",
            changed_by="TestAnalyst"
        )
        self.assertTrue(assigned)

        # Test transition to RESOLVED
        resolved = update_alert_status(
            alert_id=alert_id,
            new_status="RESOLVED",
            changed_by="SeniorAnalyst",
            notes="Host contained and incident mitigated"
        )
        self.assertTrue(resolved)

        # Verify audit history
        history = get_alert_history(alert_id)
        statuses = [h["new_status"] for h in history]
        self.assertTrue("NEW" in statuses or "OPEN" in statuses)
        self.assertIn("INVESTIGATING", statuses)
        self.assertIn("RESOLVED", statuses)



if __name__ == "__main__":
    unittest.main()
