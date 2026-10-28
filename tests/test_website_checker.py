"""
Unit Tests for the Website Threat Checker Module.
Tests URL parsing, SSRF defense, IP filtering, TLS certificate inspection,
and graceful handling of unreachable or forbidden endpoints.
"""

import unittest
from website_checker import (
    sanitize_and_parse_url,
    is_safe_public_ip,
    resolve_hostname_safely,
    analyze_website_security,
    check_domain_reputation_optional
)


class TestWebsiteChecker(unittest.TestCase):

    def test_url_sanitization_and_parsing(self):
        # Bare domain
        valid, url, host, port, err = sanitize_and_parse_url("example.com")
        self.assertTrue(valid)
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 443)
        self.assertTrue(url.startswith("https://"))

        # Explicit HTTP URL
        valid, url, host, port, err = sanitize_and_parse_url("http://example.com:8080/path")
        self.assertTrue(valid)
        self.assertEqual(host, "example.com")
        self.assertEqual(port, 8080)
        self.assertTrue(url.startswith("http://"))

        # Empty string
        valid, _, _, _, err = sanitize_and_parse_url("")
        self.assertFalse(valid)
        self.assertIn("cannot be empty", err)

        # Prohibited schemes
        for scheme in ["ftp://ftp.example.com", "file:///etc/passwd", "gopher://evil.com"]:
            valid, _, _, _, err = sanitize_and_parse_url(scheme)
            self.assertFalse(valid)
            self.assertIn("Only HTTP and HTTPS", err)

    def test_ssrf_ip_filtering(self):
        # Loopback
        is_safe, msg = is_safe_public_ip("127.0.0.1")
        self.assertFalse(is_safe)
        self.assertIn("loopback", msg.lower())

        # Private RFC 1918
        for priv_ip in ["10.0.0.1", "172.16.0.1", "192.168.1.1"]:
            is_safe, msg = is_safe_public_ip(priv_ip)
            self.assertFalse(is_safe)
            self.assertIn("private", msg.lower())

        # Cloud Metadata IP
        is_safe, msg = is_safe_public_ip("169.254.169.254")
        self.assertFalse(is_safe)
        self.assertIn("cloud metadata", msg.lower())

        # Safe public IP (e.g. Cloudflare DNS)
        is_safe, msg = is_safe_public_ip("1.1.1.1")
        self.assertTrue(is_safe)

    def test_ssrf_hostname_resolution_blocks_forbidden(self):
        # Localhost name
        safe, ips, err = resolve_hostname_safely("localhost")
        self.assertFalse(safe)
        self.assertIn("prohibited", err.lower())

        # Internal domain names
        safe, ips, err = resolve_hostname_safely("mycompany.internal")
        self.assertFalse(safe)
        self.assertIn("internal", err.lower())

    def test_reputation_unconfigured_behavior(self):
        # Verifies that when no API key is provided, the function gracefully explains it rather than inventing a result
        rep = check_domain_reputation_optional("example.com")
        self.assertIn("source", rep)
        self.assertIn("message", rep)
        # Should not fabricate engine counts if unavailable
        if not rep.get("available"):
            self.assertIn("unavailable", rep["message"].lower())

    def test_analyze_website_security_on_ssrf_attempt(self):
        res = analyze_website_security("http://127.0.0.1")
        self.assertFalse(res["success"])
        self.assertEqual(res["error_type"], "SSRF_DEFENSE_BLOCKED")

        res_meta = analyze_website_security("http://169.254.169.254")
        self.assertFalse(res_meta["success"])
        self.assertEqual(res_meta["error_type"], "SSRF_DEFENSE_BLOCKED")

    def test_analyze_website_security_on_valid_domain(self):
        res = analyze_website_security("https://example.com")
        self.assertTrue(res["success"])
        self.assertIn("overall_assessment", res)
        # Must be strictly one of the 3 required outcomes
        self.assertIn(res["overall_assessment"], [
            "Potentially Malicious",
            "No Threat Detected by Available Sources",
            "Unable to Determine"
        ])
        self.assertIn("tls_info", res)
        self.assertIn("http_info", res)
        self.assertIn("evidence", res)
        self.assertIn("summary", res["evidence"])
        self.assertIn("items", res["evidence"])
        self.assertIn("sources_checked", res["evidence"])


if __name__ == "__main__":
    unittest.main()
