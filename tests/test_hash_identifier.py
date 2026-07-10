"""
Test: Hash Identifier
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
    "hash_identifier",
    BASE_DIR / "03-password" / "hash_identifier.py",
)
hi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hi)

identify_hash = hi.identify_hash


class TestHashIdentifier(unittest.TestCase):
    """Test hash type identification."""

    def test_identify_md5(self):
        """32-char hex string -> terdeteksi MD5."""
        h = hashlib.md5(b"test").hexdigest()
        results = identify_hash(h)
        names = [r["name"] for r in results]
        self.assertIn("MD5", names)

    def test_identify_sha1(self):
        """40-char hex string -> terdeteksi SHA1."""
        h = hashlib.sha1(b"test").hexdigest()
        results = identify_hash(h)
        names = [r["name"] for r in results]
        self.assertIn("SHA1", names)

    def test_identify_sha256(self):
        """64-char hex string -> terdeteksi SHA-256."""
        h = hashlib.sha256(b"test").hexdigest()
        results = identify_hash(h)
        names = [r["name"] for r in results]
        self.assertIn("SHA256", names)

    def test_identify_sha512(self):
        """128-char hex string -> terdeteksi SHA-512."""
        h = hashlib.sha512(b"test").hexdigest()
        results = identify_hash(h)
        names = [r["name"] for r in results]
        self.assertIn("SHA512", names)

    def test_identify_bcrypt(self):
        """$2a$ prefix -> terdeteksi bcrypt."""
        h = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
        results = identify_hash(h)
        names = [r["name"] for r in results]
        bcrypt_found = any("bcrypt" in n.lower() for n in names)
        self.assertTrue(bcrypt_found)

    def test_identify_ntlm(self):
        """32-char hex -> NTLM terdeteksi (bersama MD5)."""
        h = "aad3b435b51404eeaad3b435b51404ee"
        results = identify_hash(h)
        names = [r["name"] for r in results]
        self.assertIn("NTLM", names)

    def test_identify_unknown(self):
        """String acak pendek -> return empty list."""
        results = identify_hash("not-a-hash")
        self.assertEqual(results, [])

    def test_identify_empty(self):
        """String kosong -> return empty list."""
        results = identify_hash("")
        self.assertEqual(results, [])

    def test_identify_crc32(self):
        """8-char hex -> CRC32."""
        h = "aabbccdd"
        results = identify_hash(h)
        names = [r["name"] for r in results]
        self.assertIn("CRC32", names)

    def test_identify_sha384(self):
        """96-char hex -> SHA384."""
        h = hashlib.sha384(b"test").hexdigest()
        results = identify_hash(h)
        names = [r["name"] for r in results]
        self.assertIn("SHA384", names)

    def test_identify_sha224(self):
        """56-char hex -> SHA224."""
        h = hashlib.sha224(b"test").hexdigest()
        results = identify_hash(h)
        names = [r["name"] for r in results]
        self.assertIn("SHA224", names)

    def test_identify_sha512crypt(self):
        """$6$ prefix -> SHA-512 crypt."""
        h = "$6$rounds=5000$usesomesillystri$D4IrlXatmP7rx3P3InaxBeoomnAihCKRVQP22JZ6EY47Wc6BkroIuUUBOov1i.S5KPgErtP/EN5mcO.ChWQW21"
        results = identify_hash(h)
        names = [r["name"] for r in results]
        self.assertIn("SHAcrypt SHA-512", names)

    def test_identify_sha256crypt(self):
        """$5$ prefix -> SHA-256 crypt."""
        h = "$5$rounds=5000$usesomesillystri$KqJWpanXZHKq2BOB43TSaYhEWsQ1Lr5QNyPCDH/Tp.6"
        results = identify_hash(h)
        names = [r["name"] for r in results]
        self.assertIn("SHAcrypt SHA-256", names)


if __name__ == "__main__":
    unittest.main()
