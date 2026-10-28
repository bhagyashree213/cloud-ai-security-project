"""
Unit Tests for CloudSentinel AWS S3 Integration and Local Simulation Mode.
"""

import unittest
from pathlib import Path
from aws_s3 import (
    get_s3_status,
    upload_bytes_to_s3,
    upload_file_to_s3,
    ALLOWED_PREFIXES
)


class TestAWSS3Integration(unittest.TestCase):

    def test_allowed_s3_prefixes(self):
        expected = {"datasets", "logs", "reports", "backups"}
        self.assertEqual(ALLOWED_PREFIXES, expected)

    def test_s3_status_detection(self):
        status = get_s3_status()
        self.assertIn("configured", status)
        self.assertIn("bucket", status)
        self.assertIn("message", status)

    def test_upload_bytes_to_s3_or_simulation(self):
        data = b"test,threat,probability\n1,0,0.05"
        res = upload_bytes_to_s3(
            file_bytes=data,
            filename="unit_test_log.csv",
            prefix="logs",
            content_type="text/csv"
        )
        self.assertTrue(res.get("success"), f"Upload failed: {res}")
        self.assertIn("s3_uri", res)
        self.assertTrue("logs/" in res["s3_uri"])

    def test_invalid_prefix_rejection(self):
        data = b"malicious data"
        res = upload_bytes_to_s3(
            file_bytes=data,
            filename="exploit.bin",
            prefix="unauthorized_prefix"
        )
        self.assertFalse(res.get("success"))
        self.assertIn("Invalid S3 prefix", res.get("error", ""))

    def test_upload_missing_file_error(self):
        fake_path = Path("non_existent_file_12345.csv")
        res = upload_file_to_s3(
            local_path=fake_path,
            prefix="reports"
        )
        self.assertFalse(res.get("success"))
        self.assertIn("does not exist", res.get("error", ""))

    def test_upload_bytes_redundant_prefix_and_nested_dirs(self):
        data = b"col1,col2\nval1,val2"
        # Test that passing 'reports/nested_sub/report.csv' does not create reports/reports/ and creates parent dir safely
        res = upload_bytes_to_s3(
            file_bytes=data,
            filename="reports/nested_sub/test_report.csv",
            prefix="reports",
            content_type="text/csv"
        )
        self.assertTrue(res.get("success"), f"Upload failed: {res}")
        # Ensure redundant 'reports/reports/' is not present
        if res.get("simulated"):
            local_path = res.get("local_path", "")
            self.assertNotIn("reports\\reports\\", local_path)
            self.assertNotIn("reports/reports/", local_path)
            self.assertTrue(Path(local_path).is_file())


if __name__ == "__main__":
    unittest.main()
