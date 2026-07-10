"""
Test: Password Generator
"""

import sys
import unittest
from pathlib import Path

TEST_DIR = Path(__file__).resolve().parent
BASE_DIR = TEST_DIR.parent
sys.path.insert(0, str(BASE_DIR))

import importlib.util

spec = importlib.util.spec_from_file_location(
    "password_generator",
    BASE_DIR / "03-password" / "password_generator.py",
)
pg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pg)

generate_password = pg.generate_password
check_strength = pg.check_strength


class TestPasswordGenerator(unittest.TestCase):
    """Test password generation & strength checking."""

    def test_generate_length(self):
        """Password harus sesuai panjang yang diminta."""
        for length in [8, 12, 16, 32]:
            pw = generate_password(length, True, True, True, True, False)
            self.assertEqual(len(pw), length)

    def test_generate_contains_uppercase(self):
        """use_upper=True harus ada huruf besar."""
        pw = generate_password(16, True, True, True, True, False)
        self.assertTrue(any(c.isupper() for c in pw))

    def test_generate_contains_lowercase(self):
        """use_lower=True harus ada huruf kecil."""
        pw = generate_password(16, True, True, True, True, False)
        self.assertTrue(any(c.islower() for c in pw))

    def test_generate_contains_digit(self):
        """use_digits=True harus ada angka."""
        pw = generate_password(16, True, True, True, True, False)
        self.assertTrue(any(c.isdigit() for c in pw))

    def test_generate_no_symbols(self):
        """use_symbols=False, password hanya huruf+digit."""
        pw = generate_password(16, True, True, True, False, False)
        self.assertTrue(pw.isalnum())

    def test_generate_no_upper(self):
        """use_upper=False, password tanpa huruf besar."""
        pw = generate_password(16, False, True, True, True, False)
        self.assertTrue(
            not any(c.isupper() for c in pw)
            or all(c.islower() or c.isdigit() or not c.isalpha() for c in pw)
        )

    def test_strength_weak(self):
        """'1234' harus 'SANGAT LEMAH' atau 'LEMAH'."""
        score, feedback, entropy, strength = check_strength("1234")
        self.assertIn(strength, ["SANGAT LEMAH", "LEMAH"])

    def test_strength_strong(self):
        """Password panjang + variasi harus 'KUAT'/'SANGAT KUAT'."""
        score, feedback, entropy, strength = check_strength("A7$k9mX!qR2#vB8nLp@1")
        self.assertIn(strength, ["KUAT", "SANGAT KUAT"])

    def test_strength_common_password(self):
        """Password umum seperti 'password' harus sangat rendah."""
        score, feedback, entropy, strength = check_strength("password")
        self.assertEqual(score, 0)

    def test_strength_empty(self):
        """Password kosong return score 0 dan list feedback."""
        result = check_strength("")
        # empty password returns (0, ["Password kosong"]) — 2-tuple
        self.assertEqual(result[0], 0)
        self.assertIn("kosong", result[1][0].lower())


if __name__ == "__main__":
    unittest.main()
