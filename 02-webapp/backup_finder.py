#!/usr/bin/env python3
"""
Backup File Scanner

Memindai target website untuk file backup, file sisa (leftover), dan file
konfigurasi yang mungkin terekspos. Menggunakan HEAD request untuk
kecepatan, lalu GET untuk verifikasi.

Usage:
    python backup_finder.py -u https://target.com
    python backup_finder.py -u https://target.com --threads 20
    python backup_finder.py -u https://target.com -f wordlist.txt
    python backup_finder.py -u https://target.com -e .php,.asp,.zip,.sql
"""

import argparse
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    sys.exit("[!] Modul 'requests' tidak terinstall. Jalankan: pip install requests")

try:
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

# ═══════════════════════════════
# DEFAULT BACKUP EXTENSIONS
# ═══════════════════════════════

BACKUP_EXTENSIONS = [
    ".bak", ".old", ".backup", ".swp", ".swo", ".save", ".orig", ".tmp",
    ".txt", ".zip", ".tar.gz", ".tar", ".gz", ".sql", ".7z", ".rar",
    ".tgz", ".bz2", ".xz", ".log", ".dump", ".export", ".csv",
]

# ═══════════════════════════════
# FILE NAMING PATTERNS
# ═══════════════════════════════

NAMING_PATTERNS = [
    "{name}~",                    # index.php~
    ".{name}.swp",                # .index.php.swp
    "copy of {name}",             # Copy of index.php
    "{name}(1)",                  # index.php(1)
    "{name}(2)",
    "{name}.{ext}~",
    "{name} copy",
    "{name} - copy",
    "{name} - backup",
    "{name} - old",
    "{name}_backup",
    "{name}_old",
    "{name}_copy",
    "backup_{name}",
    "old_{name}",
    "copy_of_{name}",
    "{name}.{ext}.bak",
    "{name}.{ext}.old",
    "{name}.{ext}.backup",
    "{name}.{ext}.orig",
    "{name}.{ext}.save",
    "{name}.{ext}.tmp",
    "{name}.{ext}.swp",
]

# ═══════════════════════════════
# DEFAULT PAGES TO CHECK
# ═══════════════════════════════

DEFAULT_PAGES = [
    "index.php", "index.html", "index.asp", "index.aspx", "index.jsp",
    "config.php", "wp-config.php", "configuration.php", "settings.php",
    "database.php", "db.php", "admin.php", "login.php", "header.php",
    "footer.php", "functions.php", "style.css", "app.js", "main.js",
    ".env", "docker-compose.yml", "Dockerfile",
]

# ═══════════════════════════════
# HEADERS
# ═══════════════════════════════

def _get_headers():
    return {
        "User-Agent": "Mozilla/5.0 (compatible; BackupScanner/1.0)",
        "Accept": "*/*",
        "Connection": "close",
    }


# ═══════════════════════════════
# CORE FUNCTIONS
# ═══════════════════════════════

def _build_url(base, path):
    base = base.rstrip("/")
    path = path.lstrip("/")
    return f"{base}/{path}"


def _check_url(url, timeout=10, session=None):
    """Cek URL dengan HEAD dulu, lalu GET."""
    s = session or requests.Session()
    s.headers.update(_get_headers())
    try:
        head = s.head(url, timeout=timeout, verify=False, allow_redirects=False)
        if head.status_code == 200:
            return url, head.status_code, int(head.headers.get("Content-Length", 0))
        elif head.status_code in (301, 302):
            loc = head.headers.get("Location", "")
            return url, head.status_code, 0
        elif head.status_code == 403:
            return url, 403, 0
    except RequestException:
        pass

    try:
        get = s.get(url, timeout=timeout, verify=False, allow_redirects=False, stream=True)
        get.close()
        cl = int(get.headers.get("Content-Length", 0))
        if get.status_code == 200 and cl > 0:
            return url, get.status_code, cl
        return url, get.status_code, 0
    except RequestException:
        return None


def generate_targets(base_url, pages, extensions):
    """Hasilkan semua URL yang akan diuji."""
    targets = []

    for page in pages:
        p = Path(page)
        stem = p.stem
        ext = p.suffix
        name_no_ext = stem

        # Tambahkan backup extensions
        for bext in extensions:
            targets.append(f"{page}{bext}")

        # Tambahkan naming patterns
        for pattern in NAMING_PATTERNS:
            candidate = pattern.replace("{name}", name_no_ext)
            if "{ext}" in candidate:
                candidate = candidate.replace("{ext}", ext.lstrip("."))
            # Jangan duplikasi dengan pola extension
            if not any(candidate.endswith(e) for e in extensions):
                targets.append(candidate)

    # Dedup
    seen = set()
    unique = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


# ═══════════════════════════════
# MAIN
# ═══════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Backup File Scanner - Menemukan file backup dan sisa di target",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  python backup_finder.py -u https://target.com
  python backup_finder.py -u https://target.com --threads 20 -e .php,.asp
  python backup_finder.py -u https://target.com -f pages.txt
  python backup_finder.py -u https://target.com/subdir/ -e .zip,.sql,.bak
        """,
    )
    parser.add_argument("-u", "--url", required=True, help="URL target (contoh: https://target.com)")
    parser.add_argument("-f", "--file", dest="wordlist", help="File wordlist halaman yang akan dicek")
    parser.add_argument("-e", "--extensions", default=".bak,.old,.backup,.swp,.save,.orig,.tmp,.zip,.sql,.txt,.tar.gz,.7z,.rar",
                        help="Ekstensi backup yang dicek (dipisah koma, default: umum)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Jumlah thread paralel (default: 10)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout per request dalam detik (default: 10)")
    parser.add_argument("--all", action="store_true", help="Tambahkan pola naming kompleks (lebih banyak request)")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")
    timeout = args.timeout
    threads = min(args.threads, 50)

    extensions = [e.strip() for e in args.extensions.split(",") if e.strip()]
    if not extensions:
        extensions = BACKUP_EXTENSIONS

    if args.wordlist:
        try:
            with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                pages = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            print(f"[+] Loaded {len(pages)} halaman dari wordlist: {args.wordlist}")
        except FileNotFoundError:
            print(f"[!] File wordlist tidak ditemukan: {args.wordlist}")
            sys.exit(1)
    else:
        pages = DEFAULT_PAGES

    print(r"""
╔╗ ┌─┐┌─┐┬┌─┬ ╦┌─┐  ╔═╗┬┌┐┌┌┬┐┌─┐┬─┐
╠╩╗├─┤│  ├┴┐║ ║├─┘  ╠╣ ││││ ││├┤ ├┬┘
╚═╝┴ ┴└─┘┴ ┴╚═╝┴    ╚  ┴┘└┘─┴┘└─┘┴└─  v1.0
""")

    print(f"\n[*] Target: {base_url}")
    print(f"[*] Extensions: {', '.join(extensions)}")
    print(f"[*] Halaman dasar: {len(pages)}")
    print(f"[*] Threads: {threads}")

    targets = generate_targets(base_url, pages, extensions)

    if args.all:
        print(f"[*] Mode --all: menggunakan pola naming tambahan")

    print(f"[*] Total URL yang akan diuji: {len(targets)}")
    print("\n[*] Memulai scanning...\n")

    session = requests.Session()
    found = []
    tested = 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(_check_url, _build_url(base_url, t), timeout, session): t
            for t in targets
        }
        for future in as_completed(futures):
            tested += 1
            result = future.result()
            if result:
                url_found, status, size = result
                if status == 200 and size > 0:
                    found.append((url_found, status, size))
                    print(f"[+] DITEMUKAN: {url_found} ({size} bytes)")
                elif status == 403:
                    found.append((url_found, status, 0))
                    print(f"[*] FORBIDDEN: {url_found} (403)")

            if tested % 100 == 0:
                print(f"[*] Progress: {tested}/{len(targets)} diuji...")

    print(f"\n{'=' * 60}")
    print(f"  HASIL SCAN")
    print(f"{'=' * 60}")

    if found:
        print(f"\n[+] Total file ditemukan: {len(found)}")
        print(f"\n{'URL':<70} {'Status':<8} {'Size'}")
        print("-" * 90)
        for url_found, status, size in found:
            size_str = f"{size:,} B" if size > 0 else "-"
            print(f"{url_found:<70} {status:<8} {size_str}")
    else:
        print("\n[-] Tidak ada file backup yang ditemukan.")

    print(f"\n[*] Total URL diuji: {tested}")
    print(f"[*] File ditemukan: {len(found)}")


if __name__ == "__main__":
    main()
