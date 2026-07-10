#!/usr/bin/env python3
"""
Cookie Security Analyzer - Audit HTTP cookies for security misconfigurations.
Usage: python cookie_analyzer.py --url https://target.com
       python cookie_analyzer.py --url https://target.com --headers
"""

import argparse
import base64
import json
import re
import sys
from datetime import datetime

import requests


SESSION_COOKIE_NAMES = {
    "sessionid", "phpsessid", "jsessionid", "asp.net_sessionid",
    "sid", "authsid", "ssid", "laravel_session", "ci_session",
    "cfid", "cftoken", "connect.sid", "od_sess", "csrf_token",
    "django_sessid", "cake", "sails.sid", "wordpress_logged_in_",
    "wp-settings-", "wordpress_sec_",
}

CRITICAL_FLAGS = {"HttpOnly", "Secure"}
IMPORTANT_FLAGS = {"SameSite"}


def normalize_url(url):
    parsed = __import__("urllib.parse").urlparse(url)
    if not parsed.scheme:
        url = "http://" + url
    return url


def fetch_cookies(url):
    headers = {
        "User-Agent": "CookieAnalyzer/1.0",
        "Accept": "text/html,application/xhtml+xml",
    }
    response = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
    return response


def detect_jwt(value):
    jwt_pattern = re.compile(r"^eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.?[A-Za-z0-9\-_]*$")
    if not jwt_pattern.match(value):
        return None

    parts = value.split(".")
    result = {}
    try:
        for idx, label in [(0, "header"), (1, "payload")]:
            decoded = base64.urlsafe_b64decode(parts[idx] + "==")
            result[label] = json.loads(decoded)
    except Exception:
        result["header"] = {"error": "decode failed"}

    return result


def score_cookie(cookie, session_names):
    issues = []

    if cookie.secure is not True:
        issues.append(("CRITICAL", "Missing Secure flag — cookie sent over HTTP → MITM risk"))
    if cookie.has_nonstandard_attr("httponly") and not getattr(cookie, "httponly", False):
        pass
    if hasattr(cookie, "_rest") and "HttpOnly" not in str(cookie._rest):
        issues.append(("CRITICAL", "Missing HttpOnly flag — accessible via JavaScript → XSS risk"))
    if not cookie.get_nonstandard_attr("SameSite"):
        issues.append(("HIGH", "Missing SameSite flag — no CSRF protection"))

    has_samesite = cookie._rest.get("SameSite") if hasattr(cookie, "_rest") else None
    raw_cookie_str = str(cookie).lower() if hasattr(cookie, "__str__") else ""
    if "samesite" not in raw_cookie_str:
        pass

    name_lower = cookie.name.lower()
    for sname in session_names:
        if sname in name_lower:
            flags_present = set()
            if cookie.secure:
                flags_present.add("Secure")
            cs_rest = getattr(cookie, "_rest", {})
            if cs_rest.get("HttpOnly"):
                flags_present.add("HttpOnly")
            if cs_rest.get("SameSite"):
                flags_present.add("SameSite")

            missing_critical = CRITICAL_FLAGS - flags_present
            for f in missing_critical:
                issues.append(("CRITICAL", f"Session cookie missing {f} flag"))

            if "SameSite" not in flags_present:
                issues.append(("HIGH", "Session cookie lacks SameSite → CSRF risk"))
            break

    expires = None
    for attr in ["expires", "max-age"]:
        val = getattr(cookie, attr, None) or cookie._rest.get(attr.capitalize(), None)
        if val:
            expires = val
            break

    if not expires and any(sname in name_lower for sname in session_names):
        pass
    elif expires:
        try:
            if isinstance(expires, (int, float)):
                max_days = expires / 86400
                if max_days > 30:
                    issues.append(("INFO", f"Long-lived cookie: {int(max_days)} days"))
        except Exception:
            pass

    cookie_len = len(cookie.value)
    if cookie_len > 4096:
        issues.append(("WARN", f"Cookie value exceeds browser limit ({cookie_len} bytes)"))

    cookie.domain = getattr(cookie, "domain", "") or ""
    domain = cookie.domain.lower().lstrip(".")
    if domain and re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
        issues.append(("WARN", "Domain set to IP address — cookies not portable"))
    if not domain:
        issues.append(("INFO", "No Domain set — cookie scoped to origin host only"))

    return issues


def parse_samesite(cookie):
    if hasattr(cookie, "_rest"):
        val = cookie._rest.get("SameSite", "")
        if val:
            return val
    return "Not Set"


def parse_raw_cookie_attr(cookie_str):
    flags = {"HttpOnly": "No", "Secure": "No", "SameSite": "Not Set"}
    lower = cookie_str.lower()
    if "httponly" in lower:
        flags["HttpOnly"] = "Yes"
    if "secure" in lower:
        flags["Secure"] = "Yes"

    m = re.search(r"samesite\s*=\s*(\w+)", lower)
    if m:
        flags["SameSite"] = m.group(1).capitalize()

    expires = "Session"
    m_exp = re.search(r"expires\s*=\s*([^;]+)", lower, re.IGNORECASE)
    if m_exp:
        expires = m_exp.group(1).strip()
    m_max = re.search(r"max-age\s*=\s*(\d+)", lower)
    if m_max:
        expires = m_max.group(1) + "s"

    flags["Expires"] = expires
    return flags


def analyze_cookies(response, session_names):
    results = []
    raw_cookies = response.headers.get("Set-Cookie") or response.headers.get("set-cookie") or ""
    set_cookie_headers = []

    for header_name, header_val in response.raw._original_response.headers.get_all("Set-Cookie"):
        set_cookie_headers.append(header_val)

    if not set_cookie_headers:
        raw_val = response.headers.get("Set-Cookie") or response.headers.get("set-cookie")
        if raw_val:
            set_cookie_headers = [raw_val]

    for idx, cookie in enumerate(response.cookies):
        raw_hdr = set_cookie_headers[idx] if idx < len(set_cookie_headers) else ""
        flags = parse_raw_cookie_attr(raw_hdr)

        entry = {
            "name": cookie.name,
            "value_preview": cookie.value[:80] + ("..." if len(cookie.value) > 80 else ""),
            "value_length": len(cookie.value),
            "secure": flags["Secure"],
            "http_only": flags["HttpOnly"],
            "same_site": flags["SameSite"],
            "domain": cookie.domain or "(host-only)",
            "expires": flags["Expires"],
            "is_session": any(sn in cookie.name.lower() for sn in session_names),
            "issues": [],
            "raw_header": raw_hdr,
        }

        is_session = any(sn in cookie.name.lower() for sn in session_names)
        if is_session:
            if flags["Secure"] == "No":
                entry["issues"].append(("CRITICAL", "Session cookie missing Secure → MITM risk"))
            if flags["HttpOnly"] == "No":
                entry["issues"].append(("CRITICAL", "Session cookie missing HttpOnly → XSS risk"))
            if flags["SameSite"] == "Not Set":
                entry["issues"].append(("HIGH", "Session cookie missing SameSite → CSRF risk"))

        if flags["Secure"] == "No":
            entry["issues"].append(("CRITICAL", "Missing Secure flag → MITM risk"))
        if flags["HttpOnly"] == "No":
            entry["issues"].append(("CRITICAL", "Missing HttpOnly flag → XSS risk"))
        if flags["SameSite"] == "Not Set":
            entry["issues"].append(("HIGH", "Missing SameSite flag → CSRF risk"))

        if len(cookie.value) > 4096:
            entry["issues"].append(("WARN", f"Oversized cookie ({len(cookie.value)} bytes)"))

        cookie.domain_val = getattr(cookie, "domain", "") or ""
        if cookie.domain_val and re.match(r"^\d+\.\d+\.\d+\.\d+$", cookie.domain_val):
            entry["issues"].append(("WARN", "Domain set to IP address"))

        jwt_info = detect_jwt(cookie.value)
        if jwt_info:
            entry["jwt"] = jwt_info

        results.append(entry)

    return results, set_cookie_headers


def print_report(results, set_cookie_headers, show_headers):
    if not results:
        print("[*] No cookies found.")
        return

    print("\n" + "=" * 80)
    print("  COOKIE SECURITY AUDIT REPORT")
    print("=" * 80)

    total_critical = sum(1 for r in results for i in r["issues"] if i[0] == "CRITICAL")
    total_high = sum(1 for r in results for i in r["issues"] if i[0] == "HIGH")
    total_warn = sum(1 for r in results for i in r["issues"] if i[0] == "WARN")

    print(f"\n  Cookies found: {len(results)}")
    print(f"  Critical issues: {total_critical}")
    print(f"  High issues:     {total_high}")
    print(f"  Warnings:        {total_warn}")

    for idx, cookie in enumerate(results, 1):
        print(f"\n{'─' * 80}")
        print(f"  [{idx}] {cookie['name']}")
        print(f"      Value preview : {cookie['value_preview']}")
        print(f"      Value length  : {cookie['value_length']} bytes")
        print(f"      Secure        : {cookie['secure']}")
        print(f"      HttpOnly      : {cookie['http_only']}")
        print(f"      SameSite      : {cookie['same_site']}")
        print(f"      Domain        : {cookie['domain']}")
        print(f"      Expires       : {cookie['expires']}")
        print(f"      Session Cookie: {'Yes' if cookie['is_session'] else 'No'}")

        if cookie["issues"]:
            print(f"      ── Issues ──")
            for severity, desc in cookie["issues"]:
                tag = {"CRITICAL": "!!", "HIGH": "!!", "WARN": "! ", "INFO": "  "}.get(severity, "  ")
                print(f"      [{tag}] [{severity}] {desc}")

        if cookie.get("jwt"):
            print(f"      ── JWT Detected ──")
            jwt = cookie["jwt"]
            if "header" in jwt:
                print(f"      Header  : {json.dumps(jwt['header'], indent=18)}")
            if "payload" in jwt:
                payload_str = json.dumps(jwt["payload"], indent=18)
                for line in payload_str.split("\n"):
                    print(f"      Payload : {line}")

    if show_headers and set_cookie_headers:
        print(f"\n{'─' * 80}")
        print("  RAW SET-COOKIE HEADERS")
        print(f"{'─' * 80}")
        for hdr in set_cookie_headers:
            print(f"  {hdr}")

    print(f"\n{'─' * 80}")
    print("  RECOMMENDATIONS")
    print(f"{'─' * 80}")
    if total_critical > 0:
        print("  [!] Add Secure + HttpOnly flags to all session cookies")
    if total_high > 0:
        print("  [!] Set SameSite=Lax or Strict on all cookies")
    print("  [*] Use __Host- prefix for cookies requiring Secure+Path=/+no Domain")
    print("  [*] Consider upgrading session tokens to JWT with short expiry")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Cookie Security Analyzer - Audit cookies for security issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cookie_analyzer.py --url https://example.com
  python cookie_analyzer.py --url https://example.com --headers
        """,
    )
    parser.add_argument("--url", "-u", required=True, help="Target URL")
    parser.add_argument("--headers", action="store_true", help="Show raw Set-Cookie headers")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout (seconds)")

    args = parser.parse_args()

    url = normalize_url(args.url)

    print(f"[*] Fetching cookies from: {url}")
    try:
        response = fetch_cookies(url)
    except requests.exceptions.RequestException as e:
        print(f"[!] Connection failed: {e}")
        sys.exit(1)

    session_names = SESSION_COOKIE_NAMES
    results, set_cookie_headers = analyze_cookies(response, session_names)

    print_report(results, set_cookie_headers, args.headers)


if __name__ == "__main__":
    main()
