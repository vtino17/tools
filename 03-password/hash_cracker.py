#!/usr/bin/env python3
"""
Hash Cracker - Multi-algorithm hash cracking
Mendukung MD5, SHA1, SHA256, SHA512, NTLM.
Usage: python hash_cracker.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -t md5 -w wordlist.txt
"""
import hashlib
import argparse
import sys
import binascii


SUPPORTED_HASHES = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "ntlm"]


def hash_string(password, hash_type):
    if hash_type == "md5":
        return hashlib.md5(password.encode()).hexdigest()
    elif hash_type == "sha1":
        return hashlib.sha1(password.encode()).hexdigest()
    elif hash_type == "sha224":
        return hashlib.sha224(password.encode()).hexdigest()
    elif hash_type == "sha256":
        return hashlib.sha256(password.encode()).hexdigest()
    elif hash_type == "sha384":
        return hashlib.sha384(password.encode()).hexdigest()
    elif hash_type == "sha512":
        return hashlib.sha512(password.encode()).hexdigest()
    elif hash_type == "ntlm":
        return hashlib.new("md4", password.encode("utf-16le")).hexdigest()
    return None


def identify_hash(hash_str):
    """Identify hash type by length"""
    length = len(hash_str)
    return {
        32: "md5/ntlm",
        40: "sha1",
        56: "sha224",
        64: "sha256",
        96: "sha384",
        128: "sha512",
    }.get(length, "unknown")


def crack_hash(target_hash, hash_type, wordlist_path, rules=False):
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            count = 0
            for line in f:
                password = line.rstrip("\n")
                if not password:
                    continue
                count += 1

                candidates = [password]
                if rules:
                    candidates.extend(generate_rules(password))

                for cand in candidates:
                    hashed = hash_string(cand, hash_type)
                    if hashed and hashed.lower() == target_hash.lower():
                        return cand, count
                if count % 10000 == 0:
                    print(f"\r[*] Tried {count} passwords...", end="", flush=True)
    except FileNotFoundError:
        print(f"[!] Wordlist tidak ditemukan: {wordlist_path}")
        return None, 0
    except KeyboardInterrupt:
        print("\n[!] Dihentikan oleh user")
    return None, count


def generate_rules(password):
    """Generate simple password mutations"""
    rules = []
    rules.append(password.lower())
    rules.append(password.upper())
    rules.append(password.capitalize())
    rules.append(password + "1")
    rules.append(password + "123")
    rules.append(password + "!")
    rules.append(password + "2024")
    rules.append(password + "2025")
    rules.append("1" + password)
    rules.append(password[::-1])
    return list(set(rules))


def main():
    parser = argparse.ArgumentParser(description="Hash Cracker")
    parser.add_argument("-H", "--hash", required=True, help="Hash untuk di-crack")
    parser.add_argument("-t", "--type", choices=SUPPORTED_HASHES, help="Tipe hash")
    parser.add_argument("-w", "--wordlist", required=True, help="Path ke wordlist")
    parser.add_argument("-r", "--rules", action="store_true", help="Aktifkan rule-based mutations")
    args = parser.parse_args()

    if not args.type:
        guess = identify_hash(args.hash)
        print(f"[*] Hash length {len(args.hash)} -> kemungkinan tipe: {guess}")
        print(f"[!] Harap tentukan tipe hash secara eksplisit dengan -t")
        sys.exit(1)

    print(f"[*] Target hash: {args.hash}")
    print(f"[*] Hash type: {args.type}")
    print(f"[*] Wordlist: {args.wordlist}")
    print(f"[*] Rules: {'ON' if args.rules else 'OFF'}")
    print("-" * 60)

    result, count = crack_hash(args.hash, args.type, args.wordlist, args.rules)
    print()
    if result:
        print(f"[+] PASSWORD DITEMUKAN: {result}")
        print(f"[+] Setelah {count} percobaan")
    else:
        print(f"[-] Password tidak ditemukan dalam wordlist ({count} percobaan)")


if __name__ == "__main__":
    main()

