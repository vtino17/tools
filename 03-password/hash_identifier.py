#!/usr/bin/env python3
"""Hash Type Identifier - Deteksi jenis hash berdasarkan pola dan panjang karakter.

Penggunaan:
    python hash_identifier.py --hash "5f4dcc3b5aa765d61d8327deb882cf99"
    python hash_identifier.py --hash "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
    python hash_identifier.py --file hashes.txt
"""

import argparse
import re
import sys
from collections import OrderedDict

HASH_PATTERNS = OrderedDict(
    [
        (
            "MD5",
            {
                "regex": r"^[a-fA-F0-9]{32}$",
                "confidence": "certain",
                "desc": "Message Digest 5 - 128 bit, umum digunakan untuk checksum dan password lama",
            },
        ),
        (
            "NTLM",
            {
                "regex": r"^[a-fA-F0-9]{32}$",
                "confidence": "certain",
                "desc": "NT LAN Manager - digunakan Windows untuk autentikasi, format sama dengan MD5",
            },
        ),
        (
            "SHA1",
            {
                "regex": r"^[a-fA-F0-9]{40}$",
                "confidence": "certain",
                "desc": "Secure Hash Algorithm 1 - 160 bit, sudah tidak direkomendasikan",
            },
        ),
        (
            "SHA224",
            {
                "regex": r"^[a-fA-F0-9]{56}$",
                "confidence": "certain",
                "desc": "SHA-2 family 224 bit",
            },
        ),
        (
            "SHA256",
            {
                "regex": r"^[a-fA-F0-9]{64}$",
                "confidence": "certain",
                "desc": "SHA-2 family 256 bit, banyak digunakan untuk integritas data",
            },
        ),
        (
            "SHA384",
            {
                "regex": r"^[a-fA-F0-9]{96}$",
                "confidence": "certain",
                "desc": "SHA-2 family 384 bit",
            },
        ),
        (
            "SHA512",
            {
                "regex": r"^[a-fA-F0-9]{128}$",
                "confidence": "certain",
                "desc": "SHA-2 family 512 bit",
            },
        ),
        (
            "RIPEMD-160",
            {
                "regex": r"^[a-fA-F0-9]{40}$",
                "confidence": "likely",
                "desc": "RACE Integrity Primitives Evaluation Message Digest 160 bit (alternatif SHA1)",
            },
        ),
        (
            "Whirlpool",
            {
                "regex": r"^[a-fA-F0-9]{128}$",
                "confidence": "likely",
                "desc": "Whirlpool hash - 512 bit, output 128 hex chars (alternatif SHA512)",
            },
        ),
        (
            "CRC32",
            {
                "regex": r"^[a-fA-F0-9]{8}$",
                "confidence": "certain",
                "desc": "Cyclic Redundancy Check 32 bit, bukan hash kriptografis",
            },
        ),
        (
            "LM",
            {
                "regex": r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$",
                "confidence": "certain",
                "desc": "LAN Manager - hash Windows lawas, format dua bagian dipisah colon",
            },
        ),
        (
            "MySQL3.x",
            {
                "regex": r"^\*[a-fA-F0-9]{40}$",
                "confidence": "certain",
                "desc": "MySQL 3.x/4.x password hash - diawali asterisk + 40 hex",
            },
        ),
        (
            "MySQL5",
            {
                "regex": r"^\$mysql\$",
                "confidence": "certain",
                "desc": "MySQL 5.x password hash dengan prefix $mysql$",
            },
        ),
        (
            "bcrypt",
            {
                "regex": r"^\$2[aby]\$\d{1,2}\$[./A-Za-z0-9]{53}$",
                "confidence": "certain",
                "desc": "Blowfish-based crypt - diawali $2a$, $2b$, atau $2y$",
            },
        ),
        (
            "bcrypt (generic)",
            {
                "regex": r"^\$2[aby]\$",
                "confidence": "likely",
                "desc": "Blowfish-based crypt - terdeteksi dari prefix $2a$/$2b$/$2y$",
            },
        ),
        (
            "SHAcrypt SHA-256",
            {
                "regex": r"^\$5\$",
                "confidence": "certain",
                "desc": "SHA-256 crypt format Unix/Linux - diawali $5$",
            },
        ),
        (
            "SHAcrypt SHA-512",
            {
                "regex": r"^\$6\$",
                "confidence": "certain",
                "desc": "SHA-512 crypt format Unix/Linux - diawali $6$",
            },
        ),
        (
            "Argon2",
            {
                "regex": r"^\$argon2",
                "confidence": "certain",
                "desc": "Argon2 - pemenang Password Hashing Competition 2015",
            },
        ),
    ]
)


def identify_hash(hash_str: str) -> list[dict]:
    """Identifikasi jenis hash dari string yang diberikan."""
    if not hash_str:
        return []

    hash_str = hash_str.strip()
    results = []

    for name, info in HASH_PATTERNS.items():
        if re.match(info["regex"], hash_str):
            results.append(
                {
                    "name": name,
                    "confidence": info["confidence"],
                    "description": info["desc"],
                }
            )

    if len(results) > 1 and any(r["name"] == "bcrypt (generic)" for r in results):
        results = [r for r in results if r["name"] != "bcrypt (generic)"]

    if len(results) > 1 and any(r["name"] == "RIPEMD-160" for r in results):
        if any(r["name"] == "SHA1" for r in results) and len(hash_str) == 40:
            pass

    if len(results) > 1 and any(r["name"] == "Whirlpool" for r in results):
        if any(r["name"] == "SHA512" for r in results) and len(hash_str) == 128:
            pass

    return results


def print_result(hash_str: str, results: list[dict]) -> None:
    """Tampilkan hasil identifikasi dengan format rapi."""
    print(f"\n[*] Input hash: {hash_str[:80]}{'...' if len(hash_str) > 80 else ''}")
    print(f"[*] Panjang   : {len(hash_str)} karakter")
    print("-" * 60)

    if not results:
        print("[!] Gagal mengidentifikasi jenis hash.")
        print("[*] Coba periksa kembali format hash yang dimasukkan.")
        print("[*] Pastikan tidak ada whitespace/spasi di awal/akhir hash.")
        return

    for i, result in enumerate(results, 1):
        confidence_tag = {
            "certain": "[+]",
            "likely": "[~]",
            "possible": "[?]",
        }.get(result["confidence"], "[?]")

        print(f"\n{confidence_tag} [{i}] {result['name']}")
        print(f"    Keyakinan : {result['confidence'].upper()}")
        print(f"    Deskripsi : {result['description']}")


def main():
    parser = argparse.ArgumentParser(
        description="Hash Type Identifier - Deteksi jenis hash berdasarkan pola",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  python hash_identifier.py --hash "5f4dcc3b5aa765d61d8327deb882cf99"
  python hash_identifier.py --hash "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
  python hash_identifier.py --file hashes.txt
        """,
    )

    parser.add_argument(
        "--hash",
        "-H",
        type=str,
        default=None,
        help="Hash string yang akan diidentifikasi",
    )
    parser.add_argument(
        "--file",
        "-f",
        type=str,
        default=None,
        help="File berisi daftar hash (satu per baris) untuk bulk identification",
    )

    args = parser.parse_args()

    if not args.hash and not args.file:
        parser.print_help()
        print("\n[!] Error: Harap masukkan --hash atau --file")
        sys.exit(1)

    if args.hash:
        results = identify_hash(args.hash)
        print_result(args.hash, results)

    if args.file:
        try:
            with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
                lines = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] Error: File '{args.file}' tidak ditemukan.")
            sys.exit(1)

        print(f"\n[*] Bulk Identification - {len(lines)} hash dari {args.file}")
        print("=" * 60)

        for idx, line in enumerate(lines, 1):
            results = identify_hash(line)
            print(f"\n--- Baris {idx} ---")
            print_result(line, results)


if __name__ == "__main__":
    main()
