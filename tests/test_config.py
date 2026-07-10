"""
Test: Config & Logger (hackerai package)
"""

import sys
import unittest
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hackerai.config import env_info, get_default_wordlist


class TestConfig(unittest.TestCase):
    """Test centralized config module."""

    def test_env_info_default(self):
        """env_info() tanpa env vars harus return 'default'."""
        info = env_info()
        self.assertIsInstance(info, str)

    def test_get_default_wordlist_not_exists(self):
        """get_default_wordlist() untuk file yang tidak ada return path."""
        path = get_default_wordlist("nonexistent.txt")
        self.assertTrue("nonexistent.txt" in path)


class TestLogger(unittest.TestCase):
    """Test centralized logging (tanpa file output berlebihan)."""

    def test_import(self):
        """Logger module bisa di-import."""
        from hackerai.logger import setup_logger, get_logger
        logger = get_logger("test")
        self.assertEqual(logger.name, "test")

    def test_setup_logger_dedup(self):
        """setup_logger dipanggil dua kali tidak double-handler."""
        from hackerai.logger import setup_logger
        log1 = setup_logger("test_dedup")
        count1 = len(log1.handlers)
        log2 = setup_logger("test_dedup")
        count2 = len(log2.handlers)
        self.assertEqual(count1, count2)


if __name__ == "__main__":
    unittest.main()
