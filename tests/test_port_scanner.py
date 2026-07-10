"""
Test: Port Scanner
"""

import sys
import unittest
from unittest.mock import patch
from pathlib import Path

TEST_DIR = Path(__file__).resolve().parent
BASE_DIR = TEST_DIR.parent
sys.path.insert(0, str(BASE_DIR))

import importlib.util
spec = importlib.util.spec_from_file_location(
    "port_scanner",
    BASE_DIR / "01-network" / "port_scanner.py",
)
port_scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(port_scanner)


class TestPortScanner(unittest.TestCase):
    """Test core port scanner functions tanpa actual network."""

    @patch("socket.socket")
    def test_scan_port_open(self, mock_socket):
        """Port terbuka -> connect_ex return 0"""
        inst = mock_socket.return_value
        inst.connect_ex.return_value = 0
        result = port_scanner.scan_port("127.0.0.1", 80)
        self.assertTrue(result)

    @patch("socket.socket")
    def test_scan_port_closed(self, mock_socket):
        """Port tertutup -> connect_ex return nonzero"""
        inst = mock_socket.return_value
        inst.connect_ex.return_value = 1
        result = port_scanner.scan_port("127.0.0.1", 80)
        self.assertFalse(result)

    def test_get_common_service_known(self):
        """Service lookup untuk port terkenal."""
        self.assertEqual(port_scanner.get_common_service(22), "SSH")
        self.assertEqual(port_scanner.get_common_service(80), "HTTP")
        self.assertEqual(port_scanner.get_common_service(443), "HTTPS")
        self.assertEqual(port_scanner.get_common_service(3306), "MySQL")

    def test_get_common_service_unknown(self):
        """Port yang tidak dikenal return 'Unknown'."""
        self.assertEqual(port_scanner.get_common_service(9999), "Unknown")


if __name__ == "__main__":
    unittest.main()
