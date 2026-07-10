"""
Test: Hash Cracker
"""

import sys
import hashlib
import unittest
from pathlib import Path

TEST_DIR = Path(__file__).resolve().parent
BASE_DIR = TEST_DIR.parent
sys.path.insert(0, str(BASE_DIR))

import importlib.util

spec = importlib.util.spec_from_file_location(
    "hash_cracker",
    BASE_DIR / "03-password" / "hash_cracker.py",
)
hash_cracker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hash_cracker)


class TestHashCracker(unittest.TestCase):
    """Test hash cracker dengan known hash values."""

    @classmethod
    def setUpClass(cls):
        cls.wordlist = TEST_DIR / "fixtures" / "wordlist_test.txt"
        cls.wordlist.parent.mkdir(parents=True, exist_ok=True)
        cls.wordlist.write_text("password\nadmin123\nhello\nsecret\n123456\ntest\n")

    def test_crack_md5_found(self):
        """MD5 'password' harus ketemu"""
        h = hashlib.md5(b"password").hexdigest()
        result, count = hash_cracker.crack_hash(h, "md5", str(self.wordlist))
        self.assertEqual(result, "password")

    def test_crack_md5_not_found(self):
        """Hash yang tidak ada di wordlist harus return None"""
        h = hashlib.md5(b"nonexistent").hexdigest()
        result, count = hash_cracker.crack_hash(h, "md5", str(self.wordlist))
        self.assertIsNone(result)

    def test_crack_sha1_found(self):
        """SHA1 'hello' harus ketemu"""
        h = hashlib.sha1(b"hello").hexdigest()
        result, count = hash_cracker.crack_hash(h, "sha1", str(self.wordlist))
        self.assertEqual(result, "hello")

    def test_crack_sha256_found(self):
        """SHA256 'test' harus ketemu"""
        h = hashlib.sha256(b"test").hexdigest()
        result, count = hash_cracker.crack_hash(h, "sha256", str(self.wordlist))
        self.assertEqual(result, "test")

    def test_hash_string_md5(self):
        """hash_string('password', 'md5') harus sesuai."""
        result = hash_cracker.hash_string("password", "md5")
        expected = hashlib.md5(b"password").hexdigest()
        self.assertEqual(result, expected)

    def test_identify_hash(self):
        """identify_hash berdasarkan panjang."""
        md5 = hashlib.md5(b"test").hexdigest()
        self.assertIn("md5", hash_cracker.identify_hash(md5).lower())
        sha1 = hashlib.sha1(b"test").hexdigest()
        self.assertEqual(hash_cracker.identify_hash(sha1), "sha1")

    def test_generate_rules(self):
        """generate_rules harus return list mutations."""
        rules = hash_cracker.generate_rules("Test123")
        self.assertIn("test123", rules)
        self.assertIn("TEST123", rules)
        self.assertIn("Test123!", rules)
        self.assertIn("321tseT", rules)  # reversed

    @classmethod
    def tearDownClass(cls):
        if cls.wordlist.exists():
            cls.wordlist.unlink()
            cls.wordlist.parent.rmdir()


if __name__ == "__main__":
    unittest.main()
