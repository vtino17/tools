"""
Test: LFI Tester
"""

import sys
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path

TEST_DIR = Path(__file__).resolve().parent
BASE_DIR = TEST_DIR.parent
sys.path.insert(0, str(BASE_DIR))

import importlib.util
spec = importlib.util.spec_from_file_location(
    "lfi_tester",
    BASE_DIR / "04-exploitation" / "lfi_tester.py",
)
lfi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lfi)


class TestLFITester(unittest.TestCase):
    """Test LFI tester payloads and detection."""

    def test_linux_payloads_exist(self):
        """Payload Linux tidak kosong."""
        self.assertGreater(len(lfi.PAYLOADS_LINUX), 0)
        self.assertIn("../../../../../../etc/passwd", lfi.PAYLOADS_LINUX)

    def test_windows_payloads_exist(self):
        """Payload Windows tidak kosong."""
        self.assertGreater(len(lfi.PAYLOADS_WINDOWS), 0)

    def test_wrapper_payloads(self):
        """Payload PHP wrapper ada di daftar."""
        wrappers = [p for p in lfi.PAYLOADS_LINUX if "php://filter" in p]
        self.assertGreater(len(wrappers), 0)

    def test_detect_linux_root_entry(self):
        """Pattern deteksi mendeteksi /etc/passwd."""
        pattern, desc = lfi.DETECT_LINUX[0]
        import re
        content = "root:x:0:0:root:/root:/bin/bash\n"
        self.assertIsNotNone(re.search(pattern, content))

    def test_detect_linux_user_list(self):
        """Pattern deteksi baris user /etc/passwd."""
        pattern, desc = lfi.DETECT_LINUX[1]
        import re
        content = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        self.assertIsNotNone(re.search(pattern, content))

    def test_detect_windows_win_ini(self):
        """Pattern deteksi windows/win.ini."""
        pattern, desc = lfi.DETECT_WINDOWS[0]
        import re
        content = "[fonts]\nsystem=dejavu\n"
        self.assertIsNotNone(re.search(pattern, content))

    def test_detect_base64(self):
        """Pattern deteksi base64 root entry."""
        pattern, desc = lfi.DETECT_BASE64[0]
        import re
        content = "root:x:0:0:root:/root:/bin/bash\n"
        self.assertIsNotNone(re.search(pattern, content))

    def test_path_traversal_depth(self):
        """Payload traversal memiliki cukup '../'."""
        traversal_count = sum(1 for p in lfi.PAYLOADS_LINUX if "../" * 5 in p)
        self.assertGreater(traversal_count, 0)

    def test_double_encode_payloads(self):
        """Double-encoded payloads exist."""
        self.assertGreater(len(lfi.DOUBLE_ENCODE_LINUX), 0)

    def test_rfi_payloads_exist(self):
        """RFI payloads exist."""
        self.assertGreater(len(lfi.RFI_PAYLOADS), 0)
        self.assertTrue(any("http://" in p or "https://" in p for p in lfi.RFI_PAYLOADS))

    @patch("requests.Session")
    def test_lfi_scan_detection_mock(self, mock_session_class):
        """Response mock terdeteksi sebagai LFI."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        import re
        mock_resp = MagicMock()
        mock_resp.text = "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\n"
        mock_resp.status_code = 200
        mock_session.get.return_value = mock_resp

        pattern, desc = lfi.DETECT_LINUX[0]
        self.assertIsNotNone(re.search(pattern, mock_resp.text))
        self.assertIn("root entry", desc)

    @patch("requests.Session")
    def test_lfi_response_windows_detection(self, mock_session_class):
        """Response windows/win.ini terdeteksi."""
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        import re
        mock_resp = MagicMock()
        mock_resp.text = "[fonts]\nsystem=test\n[extensions]\n"
        mock_resp.status_code = 200
        mock_session.get.return_value = mock_resp

        pattern, desc = lfi.DETECT_WINDOWS[0]
        self.assertIsNotNone(re.search(pattern, mock_resp.text))
        self.assertIn("win.ini", desc)

    def test_url_parameter_injection_params(self):
        """Parameter LFI disisipkan ke query URL."""
        import urllib.parse
        param = "file"
        payload = "../../../../../../etc/passwd"
        full_url = "http://target.com/index.php"
        constructed = full_url + "?" + param + "=" + urllib.parse.quote(payload, safe="")
        self.assertIn("file=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd", constructed)

    def test_raw_url_injection(self):
        """Raw URL injection dengan traversal."""
        import urllib.parse
        url = "http://target.com/index.php"
        param = "page"
        payload = "../../../../../../etc/passwd"
        full_url = url + ("&" if "?" in url else "?") + param + "=" + urllib.parse.quote(payload, safe="")
        self.assertIn("page=..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd", full_url)


if __name__ == "__main__":
    unittest.main()
