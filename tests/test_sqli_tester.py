"""
Test: SQL Injection Tester
"""

import sys
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
from urllib.parse import urlparse, parse_qs

TEST_DIR = Path(__file__).resolve().parent
BASE_DIR = TEST_DIR.parent
sys.path.insert(0, str(BASE_DIR))

import importlib.util
spec = importlib.util.spec_from_file_location(
    "sqli_tester",
    BASE_DIR / "02-webapp" / "sqli_tester.py",
)
sqli = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sqli)

normalize_url = sqli.normalize_url
get_params = sqli.get_params
inject_params = sqli.inject_params
_sqli_error_test = sqli.test_error_based


class TestSQLiTester(unittest.TestCase):
    """Test SQL injection tester functions."""

    def test_normalize_url_no_scheme(self):
        """URL tanpa scheme ditambahkan http://."""
        normalized, parsed = normalize_url("example.com/page?id=1")
        self.assertEqual(normalized, "http://example.com/page?id=1")

    def test_normalize_url_https(self):
        """URL HTTPS tetap dipertahankan."""
        normalized, parsed = normalize_url("https://example.com/page?id=1")
        self.assertTrue(normalized.startswith("https://"))

    def test_normalize_url_with_scheme(self):
        """URL dengan http:// tidak diubah."""
        normalized, parsed = normalize_url("http://example.com/page?id=1")
        self.assertEqual(normalized, "http://example.com/page?id=1")

    def test_get_params_single(self):
        """Ekstrak satu parameter dari URL."""
        params = get_params("http://target.com/page?id=1")
        self.assertIn("id", params)
        self.assertEqual(params["id"], ["1"])

    def test_get_params_multiple(self):
        """Ekstrak banyak parameter dari URL."""
        params = get_params("http://target.com/search?q=test&page=1&sort=asc")
        self.assertEqual(len(params), 3)
        self.assertEqual(params["q"], ["test"])
        self.assertEqual(params["page"], ["1"])
        self.assertEqual(params["sort"], ["asc"])

    def test_get_params_empty(self):
        """URL tanpa parameter return dict kosong."""
        params = get_params("http://target.com/page")
        self.assertEqual(params, {})

    def test_get_params_duplicate(self):
        """Parameter duplikat menjadi list."""
        params = get_params("http://target.com/page?color=red&color=blue")
        self.assertEqual(params["color"], ["red", "blue"])

    def test_inject_params_simple(self):
        """Injeksi parameter ke URL."""
        url = "http://target.com/page?id=1"
        test_params = {"id": "1'"}
        result = inject_params(url, test_params)
        self.assertIn("id=1%27", result)

    def test_inject_params_multiple(self):
        """Injeksi beberapa parameter."""
        url = "http://target.com/search?q=test&page=1"
        test_params = {"q": "test'", "page": "1 OR 1=1"}
        result = inject_params(url, test_params)
        self.assertIn("q=test%27", result)
        self.assertIn("page=1+OR+1%3D1", result)

    def test_inject_params_ipv4(self):
        """Injeksi pada URL IPv4."""
        url = "http://192.168.1.1/admin?id=1"
        test_params = {"id": "1' OR '1'='1"}
        result = inject_params(url, test_params)
        self.assertIn("192.168.1.1", result)
        self.assertIn("id=1%27+OR+%271%27%3D%271", result)

    @patch("requests.Session")
    def test_error_based_detection(self, mock_session_class):
        """Deteksi error-based SQLi dengan mock response."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        mock_resp = MagicMock()
        mock_resp.text = "You have an error in your SQL syntax; check the manual"
        mock_session.get.return_value = mock_resp

        url = "http://target.com/page?id=1"
        params = {"id": ["1"]}
        findings = _sqli_error_test(mock_session, url, params)

    def test_url_parse_edge_cases(self):
        """Test parsing URL edge cases."""
        for url in [
            "https://localhost:8443/app",
            "http://127.0.0.1:8080/test",
            "https://sub.example.co.uk/path?x=1",
        ]:
            normalized, parsed = normalize_url(url)
            self.assertTrue(parsed.scheme in ("http", "https"))

    def test_payload_injection_position(self):
        """Verifikasi payload disisipkan ke parameter yang tepat."""
        url = "http://target.com/page?user=admin&id=100"
        payload = "1' OR '1'='1"
        test_params = {"user": "admin", "id": "100" + payload}
        result = inject_params(url, test_params)
        self.assertIn("user=admin", result)
        self.assertIn("id=100", result)
        self.assertIn("1%27+OR+%271%27%3D%271", result)

    def test_inject_params_https_retained(self):
        """Injeksi parameter mempertahankan HTTPS scheme."""
        url = "https://secure.site.com/api?token=abc"
        test_params = {"token": "abc' OR 1=1--"}
        result = inject_params(url, test_params)
        self.assertTrue(result.startswith("https://"))


if __name__ == "__main__":
    unittest.main()
