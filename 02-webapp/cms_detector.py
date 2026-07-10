#!/usr/bin/env python3
"""
CMS Detector - Identifies CMS and its version
Mendeteksi Content Management System yang digunakan website.
Usage: python cms_detector.py -u http://target.com
"""

import requests
import argparse
import re
import sys

CMS_SIGNATURES = {
    "WordPress": [
        r"/wp-content/",
        r"/wp-includes/",
        r"/wp-json/",
        r"wp-login\.php",
        r"<meta name=\"generator\" content=\"WordPress",
    ],
    "Joomla": [
        r"/administrator/",
        r"com_content",
        r"<meta name=\"generator\" content=\"Joomla",
    ],
    "Drupal": [
        r"/sites/default/files/",
        r"/misc/drupal\.js",
        r"Drupal\.settings",
        r"<meta name=\"generator\" content=\"Drupal",
    ],
    "Magento": [
        r"/skin/frontend/",
        r"Mage\.Cookies",
        r"magento",
    ],
    "Shopify": [
        r"cdn\.shopify\.com",
        r"shopify-features",
    ],
    "PrestaShop": [
        r"prestashop",
        r"/modules/",
    ],
    "OpenCart": [
        r"catalog/view/javascript",
        r"opencart",
    ],
    "Laravel": [
        r"laravel",
        r"XSRF-TOKEN",
        r"_token",
    ],
    "Django": [
        r"csrfmiddlewaretoken",
        r"__admin",
    ],
    "ASP.NET": [
        r"__VIEWSTATE",
        r"__EVENTVALIDATION",
        r"aspnetForm",
    ],
    "PHP": [
        r"PHPSESSID",
        r"\?PHPSESSID=",
    ],
    "Tomcat": [
        r"Apache Tomcat",
        r"JSESSIONID",
    ],
    "IIS": [
        r"X-Powered-By: ASP\.NET",
        r"X-AspNet-Version",
    ],
    "Express.js": [
        r"X-Powered-By: Express",
    ],
    "Nginx": [
        r"Server: nginx",
    ],
    "Apache": [
        r"Server: Apache",
    ],
    "Cloudflare": [
        r"cloudflare",
        r"cf-ray",
        r"__cfduid",
    ],
    "jQuery": [
        r"jquery[-\.min]*\.js",
    ],
    "Bootstrap": [
        r"bootstrap[-\.min]*\.css",
        r"bootstrap[-\.min]*\.js",
    ],
    "React": [
        r"react\.production\.min\.js",
        r"react-dom",
    ],
    "Vue.js": [
        r"vue\.runtime",
    ],
    "Angular": [
        r"angular\.min\.js",
        r"ng-version",
    ],
}


def detect_cms(session, base_url, html, headers):
    found = {}
    checks = [
        ("Generator meta", "meta"),
        ("Headers", "header"),
        ("Path signatures", "path"),
        ("Script src", "script"),
    ]

    for cms, patterns in CMS_SIGNATURES.items():
        score = 0
        evidence = []

        # Check meta tags
        meta_match = re.search(
            r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)', html, re.IGNORECASE
        )
        if meta_match and cms.lower() in meta_match.group(1).lower():
            score += 5
            evidence.append(f"Generator: {meta_match.group(1)}")

        # Check headers
        for h, v in headers.items():
            for pattern in patterns:
                if re.search(pattern, f"{h}: {v}", re.IGNORECASE):
                    score += 2
                    evidence.append(f"Header: {h}: {v}")

        # Check HTML body
        for pattern in patterns:
            if re.search(pattern, html, re.IGNORECASE):
                score += 1
                evidence.append(f"Match: {pattern[:50]}")

        if score > 0:
            found[cms] = {"score": score, "evidence": evidence}

    return found


def extract_version(html, pattern):
    match = re.search(pattern, html, re.IGNORECASE)
    if match:
        return match.group(1)
    return None


def main():
    parser = argparse.ArgumentParser(description="CMS and Technology Detector")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    args = parser.parse_args()

    if not args.url.startswith("http"):
        args.url = "http://" + args.url

    print(f"[*] Target: {args.url}")
    print("=" * 60)

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    try:
        r = session.get(args.url, timeout=10, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

    print(f"[+] Status: {r.status_code}")
    print(f"[+] Size: {len(r.text)} bytes\n")

    found = detect_cms(session, args.url, r.text, r.headers)

    print("[*] Detected Technologies:")
    if not found:
        print("  [-] Tidak terdeteksi teknologi spesifik")
    else:
        sorted_found = sorted(found.items(), key=lambda x: x[1]["score"], reverse=True)
        for tech, data in sorted_found:
            print(f"  [+] {tech} (score: {data['score']})")
            for ev in data["evidence"][:3]:
                print(f"      - {ev}")

    # Try extract versions
    print("\n[*] Version Detection:")
    wp_version = extract_version(r.text, r"wp-includes/js/wp-emoji-release\.min\.js\?ver=([0-9.]+)")
    if wp_version:
        print(f"  WordPress version: {wp_version}")

    jquery_version = extract_version(r.text, r"jquery[/-]([0-9.]+)(\.min)?\.js")
    if jquery_version:
        print(f"  jQuery version: {jquery_version}")

    bootstrap_version = extract_version(r.text, r"bootstrap[/-]([0-9.]+)(\.min)?\.(css|js)")
    if bootstrap_version:
        print(f"  Bootstrap version: {bootstrap_version}")

    print("\n[*] Done.")


if __name__ == "__main__":
    main()
