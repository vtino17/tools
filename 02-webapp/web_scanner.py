#!/usr/bin/env python3
"""
Web Application Scanner - Comprehensive security scanner
Scanning multi-aspek untuk kerentanan web umum.
Usage: python web_scanner.py -u http://target.com
"""
import requests
import argparse
import sys
import re
from urllib.parse import urlparse, urljoin


SENSITIVE_PATHS = [
    "/.git/HEAD", "/.git/config", "/.gitignore", "/.svn/entries",
    "/.env", "/.DS_Store", "/wp-config.php.bak", "/config.php.bak",
    "/web.config", "/robots.txt", "/.htaccess", "/.htpasswd",
    "/phpinfo.php", "/info.php", "/server-status", "/server-info",
    "/crossdomain.xml", "/.well-known/security.txt", "/elmah.axd",
    "/web.config.bak", "/database.yml", "/database.php",
    "/.backup", "/backup.sql", "/dump.sql", "/db.sql", "/data.sql",
    "/admin.php", "/administrator/", "/phpmyadmin/", "/adminer.php",
    "/cpanel/", "/plesk/", "/webmail/", "/mail/", "/roundcube/",
    "/api/", "/graphql", "/swagger.json", "/v1/", "/v2/",
    "/.dockerenv", "/Dockerfile", "/docker-compose.yml",
    "/wp-json/", "/wp-includes/", "/wp-content/", "/xmlrpc.php",
    "/login/", "/admin/", "/panel/", "/dashboard/",
    "/uploads/", "/upload/", "/files/", "/media/",
    "/cgi-bin/", "/scripts/", "/bin/",
    "/shell.php", "/cmd.php", "/backdoor.php", "/c99.php", "/r57.php",
    "/config.json", "/package.json", "/composer.json", "/Gemfile",
    "/Makefile", "/Gruntfile.js", "/Gulpfile.js",
]

SECURITY_HEADERS = {
    "X-Frame-Options": "Clickjacking",
    "X-Content-Type-Options": "MIME-sniffing",
    "Content-Security-Policy": "XSS (CSP)",
    "Strict-Transport-Security": "HSTS",
    "X-XSS-Protection": "XSS Filter",
    "Referrer-Policy": "Referrer leak",
    "Permissions-Policy": "Browser features",
    "X-Permitted-Cross-Domain-Policies": "Flash/PDF cross-domain",
}

COMMON_PORTS = {
    80: "HTTP", 443: "HTTPS", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    8000: "HTTP-Dev", 8888: "HTTP-Alt", 3000: "NodeJS", 5000: "Flask",
    9000: "PHP-FPM", 9090: "Cockpit", 81: "HTTP-Alt", 82: "HTTP-Alt",
    8008: "HTTP-Alt", 8081: "HTTP-Alt", 8088: "HTTP-Alt", 8880: "HTTP-Alt",
}


def normalize_url(url):
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "http://" + url
        parsed = urlparse(url)
    if not parsed.netloc:
        return None
    return url


def check_security_headers(headers):
    issues = []
    for header, desc in SECURITY_HEADERS.items():
        if header not in headers:
            issues.append(f"Missing: {header} ({desc})")
    return issues


def check_server_info(headers):
    info = []
    server = headers.get("Server", "")
    powered = headers.get("X-Powered-By", "")
    if server:
        info.append(f"Server: {server}")
    if powered:
        info.append(f"X-Powered-By: {powered}")
    aspnet = headers.get("X-AspNet-Version", "")
    if aspnet:
        info.append(f"ASP.NET Version: {aspnet}")
    return info


def check_sensitive_files(session, base_url):
    findings = []
    for path in SENSITIVE_PATHS:
        url = urljoin(base_url, path)
        try:
            r = session.get(url, timeout=5, allow_redirects=False, verify=False)
            if r.status_code == 200 and len(r.text) > 0 and "Not Found" not in r.text[:500]:
                if path == "/robots.txt":
                    findings.append({"path": path, "status": 200, "info": "Disallowed paths", "data": r.text[:500]})
                elif "/.git/" in path or "/.env" in path or "/backup" in path or "config" in path.lower():
                    findings.append({"path": path, "status": 200, "info": "SENSITIVE FILE", "data": r.text[:500]})
                else:
                    findings.append({"path": path, "status": 200, "info": "Exposed", "data": ""})
        except requests.exceptions.RequestException:
            continue
    return findings


def check_cookie_security(headers):
    issues = []
    set_cookie = headers.get("Set-Cookie", "")
    if set_cookie:
        if "Secure" not in set_cookie:
            issues.append("Cookie missing Secure flag")
        if "HttpOnly" not in set_cookie:
            issues.append("Cookie missing HttpOnly flag")
        if "SameSite" not in set_cookie:
            issues.append("Cookie missing SameSite attribute")
    return issues


def check_cors(headers):
    aco = headers.get("Access-Control-Allow-Origin", "")
    if aco == "*":
        return "CORS: Access-Control-Allow-Origin: * (Permissive)"
    if aco and aco != "null":
        return f"CORS: Reflected origin ({aco})"
    return None


def main():
    parser = argparse.ArgumentParser(description="Web Application Security Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--no-files", action="store_true", help="Skip sensitive file scan")
    args = parser.parse_args()

    requests.packages.urllib3.disable_warnings()
    base_url = normalize_url(args.url)
    if not base_url:
        print("[!] URL tidak valid")
        sys.exit(1)

    print(f"[*] Target: {base_url}")
    print("=" * 60)

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Security-Audit)"})

    # Fetch homepage
    try:
        r = session.get(base_url, timeout=10, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"[!] Tidak dapat terhubung: {e}")
        sys.exit(1)

    print(f"\n[INFO] Homepage: HTTP {r.status_code} ({len(r.text)} bytes)")
    print(f"[INFO] Server: {r.headers.get('Server', 'hidden')}")
    print(f"[INFO] Powered-By: {r.headers.get('X-Powered-By', 'hidden')}")

    # Security headers
    print("\n[*] Security Headers:")
    issues = check_security_headers(r.headers)
    if issues:
        for issue in issues:
            print(f"  [!] {issue}")
    else:
        print("  [+] All major security headers present")

    # Server info leak
    print("\n[*] Server Information Disclosure:")
    info = check_server_info(r.headers)
    if info:
        for i in info:
            print(f"  [!] {i}")
    else:
        print("  [+] Server info hidden")

    # CORS check
    cors = check_cors(r.headers)
    if cors:
        print(f"\n[!] CORS Issue: {cors}")

    # Cookies
    print("\n[*] Cookie Security:")
    cookie_issues = check_cookie_security(r.headers)
    if cookie_issues:
        for issue in cookie_issues:
            print(f"  [!] {issue}")
    else:
        print("  [+] No obvious cookie issues")

    # Sensitive files
    if not args.no_files:
        print("\n[*] Scanning sensitive files/directories...")
        findings = check_sensitive_files(session, base_url)
        if findings:
            for f in findings:
                severity = "[!]" if f["info"] == "SENSITIVE FILE" else "[+]"
                print(f"  {severity} {f['path']} -> HTTP {f['status']} ({f['info']})")
                if f["data"]:
                    print(f"      Preview: {f['data'][:200].strip()[:100]}")
        else:
            print("  [+] No sensitive files found")

    # Form analysis
    print("\n[*] Forms Analysis:")
    forms = re.findall(r"<form.*?</form>", r.text, re.IGNORECASE | re.DOTALL)
    print(f"  [+] {len(forms)} forms found")
    for i, form in enumerate(forms[:5]):
        action = re.search(r'action=["\']?([^"\'\s>]+)', form, re.IGNORECASE)
        method = re.search(r'method=["\']?([^"\'\s>]+)', form, re.IGNORECASE)
        print(f"  Form {i+1}: action={action.group(1) if action else 'current'} method={method.group(1) if method else 'GET'}")

    print("\n" + "=" * 60)
    print("[*] Scan complete.")


if __name__ == "__main__":
    main()

