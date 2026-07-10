#!/usr/bin/env python3
"""
Git/DVCS Exposure Scanner

Memindai target website untuk file version control (Git, SVN) dan file
sensitif yang terekspos. Mendeteksi content pattern spesifik untuk
memastikan file benar-benar ada dan valid.

Usage:
    python git_exposure.py -u https://target.com
    python git_exposure.py -u https://target.com --wordlist extra_paths.txt
    python git_exposure.py -u https://target.com --threads 5 --timeout 5
"""

import argparse
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

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
# DEFAULT PATHS & CONTENT PATTERNS
# ═══════════════════════════════

DEFAULT_CHECKS = [
    # Git exposed
    {
        "path": ".git/HEAD",
        "category": "Git",
        "severity": "CRITICAL",
        "description": "Repository Git terekspos",
        "pattern": r"ref:\s*refs/heads/",
    },
    {
        "path": ".git/config",
        "category": "Git",
        "severity": "CRITICAL",
        "description": "Konfigurasi Git terekspos",
        "pattern": r"\[core\]|\[remote",
    },
    {
        "path": ".git/index",
        "category": "Git",
        "severity": "CRITICAL",
        "description": "Index Git terekspos (binary, cek size)",
        "pattern": None,
    },
    {
        "path": ".git/description",
        "category": "Git",
        "severity": "MEDIUM",
        "description": "Deskripsi repo Git",
        "pattern": None,
    },
    # SVN exposed
    {
        "path": ".svn/entries",
        "category": "SVN",
        "severity": "CRITICAL",
        "description": "Metadata SVN terekspos",
        "pattern": r"\d{2,4}-\d{2}-\d{2}|\bdir\b|\bfile\b",
    },
    {
        "path": ".svn/wc.db",
        "category": "SVN",
        "severity": "CRITICAL",
        "description": "Database SVN workcopy (SQLite)",
        "pattern": None,
    },
    # macOS
    {
        "path": ".DS_Store",
        "category": "macOS",
        "severity": "LOW",
        "description": "File metadata macOS",
        "pattern": None,
    },
    # Environment / Secrets
    {
        "path": ".env",
        "category": "Secrets",
        "severity": "CRITICAL",
        "description": "Environment variables terekspos",
        "pattern": r"[A-Z_]+=.+",
    },
    {
        "path": ".env.backup",
        "category": "Secrets",
        "severity": "CRITICAL",
        "description": "Backup .env terekspos",
        "pattern": r"[A-Z_]+=.+",
    },
    {
        "path": ".env.example",
        "category": "Secrets",
        "severity": "LOW",
        "description": "Contoh environment file",
        "pattern": r"[A-Z_]+=.+",
    },
    {
        "path": ".env.local",
        "category": "Secrets",
        "severity": "CRITICAL",
        "description": "Local env terekspos",
        "pattern": r"[A-Z_]+=.+",
    },
    {
        "path": ".env.production",
        "category": "Secrets",
        "severity": "CRITICAL",
        "description": "Production env terekspos",
        "pattern": r"[A-Z_]+=.+",
    },
    {
        "path": ".env.development",
        "category": "Secrets",
        "severity": "MEDIUM",
        "description": "Development env",
        "pattern": r"[A-Z_]+=.+",
    },
    # Apache
    {
        "path": ".htaccess",
        "category": "Apache",
        "severity": "MEDIUM",
        "description": "File konfigurasi Apache .htaccess",
        "pattern": r"RewriteEngine|RewriteRule|Order\s|Deny\s|Allow\s|<IfModule",
    },
    {
        "path": ".htpasswd",
        "category": "Apache",
        "severity": "CRITICAL",
        "description": "File password Apache",
        "pattern": r"(^|:)\$2[aby]\$|^\w+:",
    },
    # WordPress
    {
        "path": "wp-config.php.bak",
        "category": "WordPress",
        "severity": "CRITICAL",
        "description": "Backup wp-config.php",
        "pattern": r"DB_NAME|DB_USER|DB_PASSWORD|AUTH_KEY",
    },
    {
        "path": "wp-config.php~",
        "category": "WordPress",
        "severity": "CRITICAL",
        "description": "Backup editor wp-config.php",
        "pattern": r"DB_NAME|DB_USER|DB_PASSWORD|AUTH_KEY",
    },
    {
        "path": "wp-config.php.old",
        "category": "WordPress",
        "severity": "CRITICAL",
        "description": "Versi lama wp-config.php",
        "pattern": r"DB_NAME|DB_USER|DB_PASSWORD|AUTH_KEY",
    },
    # Umum
    {
        "path": "config.php.bak",
        "category": "Konfigurasi",
        "severity": "CRITICAL",
        "description": "Backup config.php",
        "pattern": None,
    },
    {
        "path": "config.php~",
        "category": "Konfigurasi",
        "severity": "CRITICAL",
        "description": "Backup editor config.php",
        "pattern": None,
    },
    {
        "path": "phpinfo.php",
        "category": "Information Disclosure",
        "severity": "MEDIUM",
        "description": "PHP info page",
        "pattern": r"PHP Version|phpinfo\(\)|PHP License",
    },
    {
        "path": "info.php",
        "category": "Information Disclosure",
        "severity": "MEDIUM",
        "description": "PHP info page",
        "pattern": r"PHP Version|phpinfo\(\)",
    },
    # Server status
    {
        "path": "server-status",
        "category": "Information Disclosure",
        "severity": "HIGH",
        "description": "Apache server-status",
        "pattern": r"Server Version|Server MPM|Current Time|Restart Time|Parent Server|Server Uptime|server-status",
    },
    {
        "path": "server-info",
        "category": "Information Disclosure",
        "severity": "HIGH",
        "description": "Apache server-info",
        "pattern": r"Server Version|Server Built|Module Name|Server Root",
    },
    # Cross-domain policies
    {
        "path": "crossdomain.xml",
        "category": "Policies",
        "severity": "LOW",
        "description": "Flash cross-domain policy",
        "pattern": r"cross-domain-policy|allow-access-from",
    },
    {
        "path": "clientaccesspolicy.xml",
        "category": "Policies",
        "severity": "LOW",
        "description": "Silverlight client access policy",
        "pattern": r"access-policy|cross-domain-access",
    },
    # Robots & Sitemap
    {
        "path": "robots.txt",
        "category": "Crawl",
        "severity": "INFO",
        "description": "File robots.txt",
        "pattern": r"User-agent|Disallow|Allow|Sitemap",
    },
    {
        "path": "sitemap.xml",
        "category": "Crawl",
        "severity": "INFO",
        "description": "Sitemap XML",
        "pattern": r"<urlset|<sitemapindex|<\?xml",
    },
    {
        "path": "sitemap.xml.gz",
        "category": "Crawl",
        "severity": "INFO",
        "description": "Sitemap terkompresi",
        "pattern": None,
    },
    # IIS / ASP.NET
    {
        "path": "web.config",
        "category": "IIS",
        "severity": "MEDIUM",
        "description": "Konfigurasi IIS/ASP.NET",
        "pattern": r"<configuration>|<connectionStrings>|<appSettings",
    },
    # Package managers
    {
        "path": "package.json",
        "category": "Dev",
        "severity": "LOW",
        "description": "Node.js package.json",
        "pattern": r'"name"\s*:\s*"|"dependencies"\s*:|"devDependencies"',
    },
    {
        "path": "package-lock.json",
        "category": "Dev",
        "severity": "LOW",
        "description": "Node.js lockfile",
        "pattern": None,
    },
    {
        "path": "composer.json",
        "category": "Dev",
        "severity": "LOW",
        "description": "PHP Composer manifest",
        "pattern": r'"require"\s*:|\"name\"\s*:|"autoload"',
    },
    {
        "path": "composer.lock",
        "category": "Dev",
        "severity": "LOW",
        "description": "PHP Composer lockfile",
        "pattern": None,
    },
    {
        "path": "Gemfile",
        "category": "Dev",
        "severity": "LOW",
        "description": "Ruby Gemfile",
        "pattern": r"(gem|source)\s",
    },
    {
        "path": "Gemfile.lock",
        "category": "Dev",
        "severity": "LOW",
        "description": "Ruby Gemfile lock",
        "pattern": None,
    },
    {
        "path": "requirements.txt",
        "category": "Dev",
        "severity": "LOW",
        "description": "Python requirements",
        "pattern": None,
    },
    {
        "path": "Pipfile",
        "category": "Dev",
        "severity": "LOW",
        "description": "Python Pipfile",
        "pattern": None,
    },
    {
        "path": "Pipfile.lock",
        "category": "Dev",
        "severity": "LOW",
        "description": "Python Pipfile lock",
        "pattern": None,
    },
    {
        "path": "yarn.lock",
        "category": "Dev",
        "severity": "LOW",
        "description": "Yarn lockfile",
        "pattern": None,
    },
    # Docker
    {
        "path": "Dockerfile",
        "category": "Docker",
        "severity": "MEDIUM",
        "description": "Dockerfile terekspos",
        "pattern": r"FROM\s+|RUN\s+|CMD\s+|ENTRYPOINT",
    },
    {
        "path": "docker-compose.yml",
        "category": "Docker",
        "severity": "MEDIUM",
        "description": "Docker Compose config",
        "pattern": r"services:|version:|image:",
    },
    {
        "path": "docker-compose.yaml",
        "category": "Docker",
        "severity": "MEDIUM",
        "description": "Docker Compose config",
        "pattern": r"services:|version:|image:",
    },
    {
        "path": ".dockerignore",
        "category": "Docker",
        "severity": "LOW",
        "description": "Docker ignore file",
        "pattern": None,
    },
    # CI/CD
    {
        "path": ".travis.yml",
        "category": "CI/CD",
        "severity": "MEDIUM",
        "description": "Travis CI config",
        "pattern": r"language:|script:|deploy:|before_script:",
    },
    {
        "path": "Jenkinsfile",
        "category": "CI/CD",
        "severity": "MEDIUM",
        "description": "Jenkins pipeline",
        "pattern": r"pipeline\s*\{|agent\s|stage\s*\(",
    },
    {
        "path": ".gitlab-ci.yml",
        "category": "CI/CD",
        "severity": "MEDIUM",
        "description": "GitLab CI config",
        "pattern": r"stages:|image:|script:|before_script:",
    },
    {
        "path": ".github/workflows",
        "category": "CI/CD",
        "severity": "MEDIUM",
        "description": "GitHub Actions workflows (directory)",
        "pattern": None,
    },
    {
        "path": ".circleci/config.yml",
        "category": "CI/CD",
        "severity": "MEDIUM",
        "description": "CircleCI config",
        "pattern": None,
    },
    # Git attributes / ignore
    {
        "path": ".gitignore",
        "category": "Git",
        "severity": "LOW",
        "description": "Git ignore file",
        "pattern": None,
    },
    {
        "path": ".gitattributes",
        "category": "Git",
        "severity": "LOW",
        "description": "Git attributes",
        "pattern": None,
    },
    # Mercurial
    {
        "path": ".hg/store",
        "category": "Mercurial",
        "severity": "CRITICAL",
        "description": "Repository Mercurial terekspos",
        "pattern": None,
    },
    # Bazaar
    {
        "path": ".bzr/README",
        "category": "Bazaar",
        "severity": "CRITICAL",
        "description": "Repository Bazaar terekspos",
        "pattern": None,
    },
    # IDE / Editor
    {
        "path": ".vscode/settings.json",
        "category": "IDE",
        "severity": "LOW",
        "description": "VS Code settings",
        "pattern": None,
    },
    {
        "path": ".idea/workspace.xml",
        "category": "IDE",
        "severity": "LOW",
        "description": "JetBrains workspace",
        "pattern": None,
    },
]


# ═══════════════════════════════
# HELPERS
# ═══════════════════════════════


def _get_headers():
    return {
        "User-Agent": "Mozilla/5.0 (compatible; GitExposureScan/1.0)",
        "Accept": "*/*",
        "Connection": "close",
    }


def _check_path(base_url, check, timeout=10):
    """Cek satu path, cocokkan pattern konten jika ada."""
    path = check["path"]
    url = f"{base_url.rstrip('/')}/{path}"

    try:
        resp = requests.get(
            url,
            headers=_get_headers(),
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
    except RequestException:
        return None

    content_type = resp.headers.get("Content-Type", "").lower()

    # Redirect ke login/home bukan temuan valid
    if resp.status_code in (301, 302):
        loc = resp.headers.get("Location", "")
        if "login" in loc.lower() or loc.rstrip("/") == base_url.rstrip("/"):
            return None

    # Hanya proses 200
    if resp.status_code != 200:
        return None

    text = resp.text
    clen = len(resp.content)

    # HTML responses untuk file sensitif: skip
    if "text/html" in content_type and check["category"] != "Crawl":
        # Beberapa file bisa HTML valid (seperti phpinfo, server-status)
        if check["path"] not in ("phpinfo.php", "info.php", "server-status", "server-info"):
            if clen > 0:
                return None

    # Cocokkan pattern konten bila ada
    pattern = check.get("pattern")
    if pattern:
        if not re.search(pattern, text):
            return None

    # Pattern None tapi size = 0: skip
    if (
        pattern is None
        and clen == 0
        and check["path"] not in ("robots.txt", ".gitignore", ".gitattributes")
    ):
        return None

    return {
        "url": url,
        "path": check["path"],
        "category": check["category"],
        "severity": check["severity"],
        "description": check["description"],
        "size": clen,
        "content_type": content_type,
    }


# ═══════════════════════════════
# MAIN
# ═══════════════════════════════


def main():
    parser = argparse.ArgumentParser(
        description="Git/DVCS Exposure Scanner - Deteksi file sensitif terekspos",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  python git_exposure.py -u https://target.com
  python git_exposure.py -u https://target.com --wordlist extra_paths.txt
  python git_exposure.py -u https://target.com --threads 5 --timeout 5
        """,
    )
    parser.add_argument(
        "-u", "--url", required=True, help="URL target (contoh: https://target.com)"
    )
    parser.add_argument("-w", "--wordlist", help="File wordlist path tambahan (satu per baris)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Thread paralel (default: 5)")
    parser.add_argument("--timeout", type=int, default=8, help="Timeout request (default: 8 detik)")
    parser.add_argument(
        "--include-low", action="store_true", help="Tampilkan temuan severity INFO/LOW"
    )
    args = parser.parse_args()

    base_url = args.url.rstrip("/")
    timeout = args.timeout
    threads = min(args.threads, 15)

    print(r"""
╔═╗┬┌┬┐╔═╗═╗ ╦╔═╗╔═╗╔═╗╦ ╦╦═╗╔═╗
║ ╦│ │ ║╣ ╔╩╦╝╠═╝║ ║╚═╗║ ║╠╦╝║╣
╚═╝┴ ┴ ╚═╝╩ ╚═╩  ╚═╝╚═╝╚═╝╩╚═╚═╝  v1.0
""")

    print(f"\n[*] Target: {base_url}")
    print(f"[*] Karakteristik unik: mendeteksi file dengan content pattern")

    checks = list(DEFAULT_CHECKS)

    if args.wordlist:
        try:
            with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        checks.append(
                            {
                                "path": line,
                                "category": "Custom",
                                "severity": "INFO",
                                "description": f"Custom: {line}",
                                "pattern": None,
                            }
                        )
            print(f"[+] Loaded {sum(1 for c in checks if c['category'] == 'Custom')} custom paths")
        except FileNotFoundError:
            print(f"[!] Wordlist tidak ditemukan: {args.wordlist}")
            sys.exit(1)

    print(f"[*] Total paths yang diuji: {len(checks)}")
    print(f"[*] Threads: {threads}")
    print("\n[*] Memulai scanning...\n")

    found = []
    tested = 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_check_path, base_url, c, timeout): c for c in checks}
        for future in as_completed(futures):
            tested += 1
            result = future.result()
            if result:
                found.append(result)
                sev = result["severity"]
                icon = (
                    "[!] " if sev in ("CRITICAL", "HIGH") else "[+] " if sev == "MEDIUM" else "[*] "
                )
                print(
                    f"{icon}{sev:<10} {result['path']:<35} - {result['description']} ({result['size']:,} bytes)"
                )

    print(f"\n{'=' * 70}")
    print(f"  RINGKASAN TEMUAN")
    print(f"{'=' * 70}")

    if found:
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        found.sort(key=lambda x: (sev_order.get(x["severity"], 99), x["path"]))

        shown = 0
        for r in found:
            if r["severity"] in ("LOW", "INFO") and not args.include_low:
                continue
            shown += 1
            sev = r["severity"]
            marker = "[!]" if sev in ("CRITICAL", "HIGH") else "[+]" if sev == "MEDIUM" else "[*]"
            print(f"{marker} [{sev:<10}] {r['url']}")
            print(f"      {r['description']} - {r['size']:,} bytes, type: {r['content_type']}")

        total_low = sum(1 for r in found if r["severity"] in ("LOW", "INFO"))
        if total_low > 0 and not args.include_low:
            print(
                f"\n[*] {total_low} temuan LOW/INFO disembunyikan (gunakan --include-low untuk menampilkan)"
            )

        print(f"\n  CRITICAL: {sum(1 for r in found if r['severity'] == 'CRITICAL')}")
        print(f"  HIGH:     {sum(1 for r in found if r['severity'] == 'HIGH')}")
        print(f"  MEDIUM:   {sum(1 for r in found if r['severity'] == 'MEDIUM')}")
        print(f"  LOW/INFO: {total_low}")
        print(f"  TOTAL:    {len(found)}")
    else:
        print("\n[-] Tidak ada file sensitif yang ditemukan.")

    print(f"\n[*] Selesai. {tested} paths diuji.")


if __name__ == "__main__":
    main()
