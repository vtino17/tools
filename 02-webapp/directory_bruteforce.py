#!/usr/bin/env python3
"""
Directory Bruteforcer - Hidden directory/file discovery
Menemukan direktori dan file tersembunyi di web server.
Usage: python directory_bruteforce.py -u http://target.com -w wordlist.txt
"""

import requests
import argparse
import sys
import concurrent.futures
from collections import OrderedDict

DEFAULT_PATHS = [
    "admin",
    "administrator",
    "login",
    "wp-admin",
    "wp-login.php",
    "dashboard",
    "panel",
    "controlpanel",
    "cpanel",
    "phpmyadmin",
    "admin.php",
    "admin.html",
    "admin.asp",
    "admin.aspx",
    "admin.jsp",
    "login.php",
    "login.html",
    "login.asp",
    "login.aspx",
    "user",
    "users",
    "account",
    "accounts",
    "profile",
    "profiles",
    "config",
    "configuration",
    "settings",
    "setup",
    "install",
    "backup",
    "backups",
    "bak",
    "old",
    "new",
    "temp",
    "tmp",
    "test",
    "testing",
    "dev",
    "development",
    "staging",
    "stg",
    "api",
    "api/v1",
    "api/v2",
    "v1",
    "v2",
    "rest",
    "docs",
    "doc",
    "documentation",
    "help",
    "readme",
    "README",
    "robots.txt",
    "sitemap.xml",
    "crossdomain.xml",
    "favicon.ico",
    ".htaccess",
    ".htpasswd",
    ".git",
    ".git/HEAD",
    ".git/config",
    ".env",
    "env",
    "environment",
    "wp-config.php",
    "config.php",
    "web.config",
    "database.yml",
    "database.php",
    "db.php",
    "phpinfo.php",
    "info.php",
    "test.php",
    "debug.php",
    "server-status",
    "server-info",
    ".well-known",
    ".well-known/security.txt",
    "uploads",
    "upload",
    "files",
    "file",
    "media",
    "images",
    "img",
    "css",
    "js",
    "scripts",
    "static",
    "assets",
    "public",
    "private",
    "secret",
    "secrets",
    "hidden",
    "internal",
    "private",
    "confidential",
    "logs",
    "log",
    "log.txt",
    "error.log",
    "access.log",
    "debug.log",
    "cgi-bin",
    "cgi",
    "scripts",
    "bin",
    "shell",
    "cmd",
    "exec",
    "console",
    "terminal",
    "manage",
    "management",
    "manager",
    "register",
    "signup",
    "join",
    "create",
    "new",
    "search",
    "find",
    "query",
    "browse",
    "data",
    "database",
    "db",
    "sql",
    "mysql",
    "postgres",
    "xmlrpc.php",
    "rpc",
    "soap",
    "wsdl",
    "swagger",
    "swagger.json",
    "swagger.yaml",
    "openapi.json",
    "graphql",
    "graphiql",
    "playground",
    "monitor",
    "health",
    "healthcheck",
    "ping",
    "alive",
    "status",
    "metrics",
    "stats",
    "statistics",
    "analytics",
]


def check_path(session, base_url, path, timeout=5):
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        r = session.get(url, timeout=timeout, allow_redirects=False, verify=False)
        if r.status_code not in [404]:
            return (url, r.status_code, len(r.text), r.headers.get("Content-Type", ""))
    except requests.exceptions.RequestException:
        return None
    return None


def main():
    parser = argparse.ArgumentParser(description="Directory/File Bruteforcer")
    parser.add_argument("-u", "--url", required=True, help="Base URL")
    parser.add_argument("-w", "--wordlist", help="Wordlist file path")
    parser.add_argument("-t", "--threads", type=int, default=30, help="Thread count")
    parser.add_argument("-e", "--extensions", help="Comma-separated extensions (e.g. php,html,asp)")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout")
    args = parser.parse_args()

    requests.packages.urllib3.disable_warnings()

    if args.wordlist:
        try:
            with open(args.wordlist, "r") as f:
                paths = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"[!] File tidak ditemukan: {args.wordlist}")
            sys.exit(1)
    else:
        paths = DEFAULT_PATHS

    # Add extensions
    if args.extensions:
        exts = [e.strip() for e in args.extensions.split(",")]
        new_paths = list(paths)
        for path in paths:
            if "." not in path:
                for ext in exts:
                    new_paths.append(f"{path}.{ext}")
        paths = new_paths

    print(f"[*] Target: {args.url}")
    print(f"[*] Wordlist size: {len(paths)}")
    print(f"[*] Threads: {args.threads}")
    print("-" * 80)
    print(f"{'URL':<50}{'Status':<10}{'Size':<10}{'Type'}")
    print("-" * 80)

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 Security-Scanner"})

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_path = {
            executor.submit(check_path, session, args.url, path, args.timeout): path
            for path in paths
        }
        for future in concurrent.futures.as_completed(future_to_path):
            result = future.result()
            if result:
                url, status, size, ctype = result
                color = "\033[92m" if status in [200, 301, 302] else "\033[93m"
                reset = "\033[0m"
                print(f"{url:<50}{color}{status:<10}{reset}{size:<10}{ctype[:30]}")
                found.append({"url": url, "status": status, "size": size})

    print("-" * 80)
    print(f"[+] Selesai. {len(found)} paths ditemukan.")


if __name__ == "__main__":
    main()
