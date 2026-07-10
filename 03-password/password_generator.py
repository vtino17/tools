#!/usr/bin/env python3
"""
Password Generator & Strength Checker
Generate strong passwords dan cek kekuatan password.
Usage: python password_generator.py -l 16 -c 20
"""

import argparse
import string
import random
import re
import sys
import math
import hashlib

COMMON_PASSWORDS = {
    "password",
    "123456",
    "12345678",
    "qwerty",
    "abc123",
    "monkey",
    "master",
    "dragon",
    "111111",
    "baseball",
    "iloveyou",
    "trustno1",
    "sunshine",
    "ashley",
    "football",
    "shadow",
    "batman",
    "access",
    "hello",
    "charlie",
    "donald",
    "password1",
    "qwerty123",
    "letmein",
    "welcome",
    "admin",
    "admin123",
    "root",
    "toor",
    "pass",
    "test",
    "guest",
    "info",
    "mysql",
    "user",
    "administrator",
    "oracle",
    "ftp",
    "pi",
    "puppet",
    "ansible",
    "ec2-user",
    "vagrant",
    "azureuser",
    "admin@123",
    "P@ssw0rd",
    "P@ssword1",
}


def generate_password(length, use_upper, use_lower, use_digits, use_symbols, exclude_ambiguous):
    chars = ""
    required = []

    if use_lower:
        pool = string.ascii_lowercase
        if exclude_ambiguous:
            pool = pool.replace("l", "").replace("o", "")
        chars += pool
        required.append(random.choice(pool))

    if use_upper:
        pool = string.ascii_uppercase
        if exclude_ambiguous:
            pool = pool.replace("I", "").replace("O", "")
        chars += pool
        required.append(random.choice(pool))

    if use_digits:
        pool = string.digits
        if exclude_ambiguous:
            pool = pool.replace("0", "").replace("1", "")
        chars += pool
        required.append(random.choice(pool))

    if use_symbols:
        pool = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        chars += pool
        required.append(random.choice(pool))

    if not chars:
        print("[!] Tidak ada character set yang dipilih")
        sys.exit(1)

    # Ensure at least one of each required type
    password = required[:]
    password += [random.choice(chars) for _ in range(length - len(required))]
    random.shuffle(password)
    return "".join(password)


def check_strength(password):
    score = 0
    feedback = []

    if not password:
        return 0, ["Password kosong"]

    length = len(password)
    if length >= 16:
        score += 3
    elif length >= 12:
        score += 2
    elif length >= 8:
        score += 1
    else:
        feedback.append(f"Terlalu pendek ({length} chars), minimal 12")

    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]", password))

    variety = sum([has_lower, has_upper, has_digit, has_symbol])
    score += variety

    if variety < 3:
        feedback.append("Tambahkan lebih banyak variasi karakter")

    # Check for common passwords
    if password.lower() in COMMON_PASSWORDS or password.lower() in [
        p.lower() for p in COMMON_PASSWORDS
    ]:
        score = 0
        feedback.append("Password ada di daftar password umum (sangat lemah)")

    # Check for repeated chars
    if re.search(r"(.)\1{2,}", password):
        score -= 1
        feedback.append("Mengandung karakter berulang")

    # Check for sequences
    for i in range(len(password) - 2):
        if ord(password[i]) == ord(password[i + 1]) - 1 == ord(password[i + 2]) - 2:
            score -= 1
            feedback.append("Mengandung sekuens karakter (abc, 123, dll)")
            break

    # Calculate entropy
    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_symbol:
        pool_size += 32
    entropy = length * (math.log2(pool_size) if pool_size > 0 else 0)

    if entropy < 40:
        strength = "SANGAT LEMAH"
    elif entropy < 60:
        strength = "LEMAH"
    elif entropy < 80:
        strength = "SEDANG"
    elif entropy < 100:
        strength = "KUAT"
    else:
        strength = "SANGAT KUAT"

    return min(max(score, 0), 6), feedback, entropy, strength


def main():
    parser = argparse.ArgumentParser(description="Password Generator & Strength Checker")
    parser.add_argument("-l", "--length", type=int, default=16, help="Password length")
    parser.add_argument(
        "-c", "--count", type=int, default=1, help="Number of passwords to generate"
    )
    parser.add_argument("--no-upper", action="store_true")
    parser.add_argument("--no-lower", action="store_true")
    parser.add_argument("--no-digits", action="store_true")
    parser.add_argument("--no-symbols", action="store_true")
    parser.add_argument("--exclude-ambiguous", action="store_true", help="Exclude 0O1lI")
    parser.add_argument("--check", help="Cek kekuatan password")
    args = parser.parse_args()

    if args.check:
        print(f"[*] Checking password strength...")
        print("-" * 60)
        score, feedback, entropy, strength = check_strength(args.check)
        print(f"Password: {'*' * len(args.check)}")
        print(f"Length: {len(args.check)}")
        print(f"Entropy: {entropy:.1f} bits")
        print(f"Strength: {strength} (score: {score}/6)")
        if feedback:
            print("Feedback:")
            for f in feedback:
                print(f"  - {f}")
        print(f"\nSHA256: {hashlib.sha256(args.check.encode()).hexdigest()}")
        return

    print(f"[*] Generating {args.count} password(s) of length {args.length}")
    print("-" * 60)
    for i in range(args.count):
        pwd = generate_password(
            args.length,
            not args.no_upper,
            not args.no_lower,
            not args.no_digits,
            not args.no_symbols,
            args.exclude_ambiguous,
        )
        score, _, entropy, strength = check_strength(pwd)
        print(f"{i+1:3}. {pwd}  [Strength: {strength}, {entropy:.0f} bits]")


if __name__ == "__main__":
    main()
