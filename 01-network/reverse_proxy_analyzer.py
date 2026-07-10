#!/usr/bin/env python3
"""Reverse Proxy & CDN Analyzer - Deteksi CDN dan reverse proxy di balik suatu website.

Menganalisis HTTP response headers untuk mendeteksi keberadaan:
- Cloudflare, AWS CloudFront, Akamai, Fastly, Varnish
- Nginx, HAProxy, Imperva/Incapsula, Sucuri
- Google Cloud CDN, Azure CDN
- Deteksi overlap WAF (mod_security + Cloudflare, dsb.)

Penggunaan:
    python reverse_proxy_analyzer.py --target https://example.com
    python reverse_proxy_analyzer.py --target http://192.168.1.10
"""

import argparse
import socket
import ssl
import sys
import urllib.parse
import urllib.request
from collections import OrderedDict


CDN_SIGNATURES = OrderedDict([
    ("Cloudflare", {
        "headers": {
            "cf-ray": "Cloudflare Ray ID (identitas request unik)",
            "cf-cache-status": "Status cache Cloudflare (HIT/MISS/EXPIRED)",
            "cf-connecting-ip": "IP asli pengguna di balik Cloudflare",
        },
        "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
        "server": "cloudflare",
        "description": "Cloudflare CDN/WAF - melindungi dari DDoS dan menyediakan caching global",
    }),
    ("AWS CloudFront", {
        "headers": {
            "x-amz-cf-id": "CloudFront request ID",
            "x-amz-cf-pop": "CloudFront Point of Presence (edge location)",
        },
        "cookies": [],
        "server": "cloudfront",
        "description": "Amazon CloudFront CDN - edge caching dari AWS global network",
    }),
    ("Akamai", {
        "headers": {
            "x-akamai-transformed": "Akamai content transformation status",
            "x-akamai-request-id": "Akamai request identifier",
            "x-akamai-staging": "Akamai staging environment flag",
            "x-true-client-ip": "Client IP behind Akamai (umum)",
        },
        "cookies": ["akaalb_"],
        "server": "akamai",
        "description": "Akamai CDN - salah satu CDN tertua dan terbesar di dunia",
    }),
    ("Fastly", {
        "headers": {
            "x-served-by": "Fastly edge server yang melayani request",
            "x-cache": "Fastly cache status (HIT/MISS)",
            "x-cache-hits": "Jumlah cache hits Fastly",
            "x-timer": "Fastly timing header",
        },
        "cookies": [],
        "server": None,
        "description": "Fastly CDN - edge cloud platform dengan VCL configuration",
    }),
    ("Varnish", {
        "headers": {
            "x-varnish": "Varnish cache ID / status",
        },
        "cookies": [],
        "server": None,
        "via_pattern": r"varnish",
        "description": "Varnish Cache - HTTP accelerator/reverse proxy open source",
    }),
    ("Nginx", {
        "headers": {
            "x-proxy-cache": "Nginx proxy cache status (umum)",
            "x-accel-expires": "Nginx X-Accel internal header",
        },
        "cookies": [],
        "server": "nginx",
        "description": "Nginx - web server sekaligus reverse proxy populer",
    }),
    ("HAProxy", {
        "headers": {},
        "cookies": [],
        "server": "haproxy",
        "description": "HAProxy - load balancer dan reverse proxy TCP/HTTP",
    }),
    ("Imperva / Incapsula", {
        "headers": {
            "x-iinfo": "Imperva/Incapsula request info",
            "x-cdn": "Imperva CDN identifier",
            "x-request-info": "Imperva request metadata",
        },
        "cookies": ["incap_ses_", "visid_incap_", "nlbi_"],
        "server": None,
        "description": "Imperva/Incapsula - WAF dan CDN enterprise security",
    }),
    ("Sucuri", {
        "headers": {
            "x-sucuri-id": "Sucuri firewall request ID",
            "x-sucuri-cache": "Sucuri cache status",
            "x-sucuri-block": "Sucuri block reason (jika diblok)",
        },
        "cookies": ["sucuri_cloudproxy"],
        "server": "sucuri",
        "description": "Sucuri - Website firewall dan CDN security",
    }),
    ("Google Cloud CDN", {
        "headers": {},
        "cookies": [],
        "server": "google frontend",
        "description": "Google Cloud CDN - edge caching via Google infrastructure",
    }),
    ("Azure CDN / Front Door", {
        "headers": {
            "x-azure-ref": "Azure CDN/Front Door reference ID",
            "x-azure-requestchain": "Azure Front Door request chain",
            "x-azure-fdid": "Azure Front Door instance ID",
        },
        "cookies": ["x-ms-edge-ref"],
        "server": None,
        "description": "Microsoft Azure CDN & Front Door - edge delivery + WAF",
    }),
])

WAF_OVERLAP_CHECKS = {
    "mod_security": {
        "headers": {
            "x-mod-security": "ModSecurity ID",
        },
        "server_pattern": r"mod_security",
    },
    "Wordfence": {
        "headers": {
            "x-wordfence": "Wordfence request marker",
            "wf-cf": "Wordfence Cloudflare integration",
        },
    },
    "AWS WAF": {
        "headers": {
            "x-amzn-waf": "AWS WAF request marker",
        },
    },
}


def make_request(url: str, timeout: int = 10) -> dict:
    """Lakukan HTTP request dan ambil semua response metadata."""
    result = {
        "url": url,
        "status_code": None,
        "headers": {},
        "server_header": None,
        "cookies": {},
        "via_header": None,
        "x_forwarded_for": None,
        "x_forwarded_proto": None,
        "error": None,
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            url,
            method="GET",
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                              "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            },
        )

        https_handler = urllib.request.HTTPSHandler(context=ctx)
        opener = urllib.request.build_opener(https_handler)

        response = opener.open(req, timeout=timeout)
        result["status_code"] = response.status

        headers_lower = {}
        for key, val in response.getheaders():
            headers_lower[key.lower()] = val
            result["headers"][key.lower()] = val

        result["server_header"] = headers_lower.get("server", "")
        result["via_header"] = headers_lower.get("via", "")
        result["x_forwarded_for"] = headers_lower.get("x-forwarded-for", "")
        result["x_forwarded_proto"] = headers_lower.get("x-forwarded-proto", "")

        set_cookie = headers_lower.get("set-cookie", "")
        if set_cookie:
            for part in set_cookie.split(";"):
                part = part.strip()
                if "=" in part:
                    key, val = part.split("=", 1)
                    result["cookies"][key.lower()] = val

    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        for key, val in e.headers.items():
            result["headers"][key.lower()] = val
        result["server_header"] = e.headers.get("Server", "")
        result["via_header"] = e.headers.get("Via", "")
        result["x_forwarded_for"] = e.headers.get("X-Forwarded-For", "")
    except urllib.error.URLError as e:
        result["error"] = f"URL Error: {e.reason}"
    except (socket.timeout, TimeoutError):
        result["error"] = "Connection timeout"
    except ssl.SSLError as e:
        result["error"] = f"SSL Error: {e}"
    except Exception as e:
        result["error"] = f"Error: {e}"

    return result


def detect_cdn(response: dict) -> list[dict]:
    """Deteksi CDN/reverse proxy berdasarkan response headers."""
    findings = []

    headers_lower = {k.lower(): v.lower() for k, v in response["headers"].items()}
    server_lower = response["server_header"].lower()
    via_lower = response["via_header"].lower()
    cookies = list(response["cookies"].keys())

    for name, sig in CDN_SIGNATURES.items():
        evidence = []
        confidence = "possible"

        for header_key, header_desc in sig["headers"].items():
            if header_key in headers_lower:
                evidence.append(f"{header_key}: {response['headers'][header_key]} ({header_desc})")
                confidence = "certain"

        for cookie_name in sig["cookies"]:
            matching = [c for c in cookies if c.startswith(cookie_name.lower().replace("_", ""))
                        or cookie_name.lower() in c]
            if matching:
                evidence.append(f"Cookie: {matching[0]} (signature {cookie_name})")
                if confidence != "certain":
                    confidence = "likely"

        if sig["server"] and sig["server"] in server_lower:
            evidence.append(f"Server header: {response['server_header']}")
            if confidence == "possible":
                confidence = "likely"

        if "via_pattern" in sig:
            import re
            if re.search(sig["via_pattern"], via_lower):
                evidence.append(f"Via header: {response['via_header']}")
                if confidence == "possible":
                    confidence = "likely"

        if evidence:
            findings.append({
                "name": name,
                "confidence": confidence,
                "description": sig["description"],
                "evidence": evidence,
            })

    if response["x_forwarded_for"]:
        has_reverse_proxy = any(
            f["name"] in ["Nginx", "HAProxy", "Varnish", "Cloudflare", "Fastly"]
            for f in findings
        )
        if not has_reverse_proxy:
            findings.append({
                "name": "Reverse Proxy (Generik)",
                "confidence": "likely",
                "description": "Reverse proxy tidak dikenal - terdeteksi dari X-Forwarded-For header",
                "evidence": [f"X-Forwarded-For: {response['x_forwarded_for']}"],
            })

    return findings


def detect_waf_overlap(response: dict, cdn_findings: list[dict]) -> list[dict]:
    """Deteksi overlap WAF dengan CDN yang sudah terdeteksi."""
    waf_findings = []

    headers_lower = {k.lower(): v.lower() for k, v in response["headers"].items()}
    server_lower = response["server_header"].lower()

    for name, sig in WAF_OVERLAP_CHECKS.items():
        evidence = []
        for header_key, header_desc in sig["headers"].items():
            if header_key in headers_lower:
                evidence.append(f"{header_key}: {response['headers'][header_key]} ({header_desc})")

        if "server_pattern" in sig:
            import re
            if re.search(sig["server_pattern"], server_lower):
                evidence.append(f"Server header: {response['server_header']}")

        if evidence:
            cdn_names = [f["name"] for f in cdn_findings]
            overlap_info = ""
            if "Cloudflare" in cdn_names and name == "mod_security":
                overlap_info = " (mungkin berada di belakang Cloudflare)"
            if "Cloudflare" in cdn_names and name == "Wordfence":
                overlap_info = " (Wordfence + Cloudflare integration terdeteksi)"

            waf_findings.append({
                "name": name + overlap_info,
                "confidence": "certain" if len(evidence) >= 2 else "likely",
                "evidence": evidence,
            })

    return waf_findings


def print_banner(target: str) -> None:
    print("=" * 60)
    print("  Reverse Proxy & CDN Analyzer")
    print("=" * 60)


def print_http_info(response: dict) -> None:
    print(f"\n[*] Target       : {response['url']}")
    print(f"[*] Status Code  : {response['status_code']}")
    print(f"[*] Server       : {response['server_header'] or '(tidak diketahui)'}")
    if response["via_header"]:
        print(f"[*] Via          : {response['via_header']}")
    if response["x_forwarded_for"]:
        print(f"[*] X-Forwarded-For: {response['x_forwarded_for']}")
    if response["x_forwarded_proto"]:
        print(f"[*] X-Forwarded-Proto: {response['x_forwarded_proto']}")


def print_findings(findings: list[dict], title: str) -> None:
    if not findings:
        print(f"\n[-] {title}: Tidak terdeteksi")
        return

    print(f"\n[+] {title} Terdeteksi:")
    for i, finding in enumerate(findings, 1):
        conf_tag = {
            "certain": "[+]",
            "likely": "[~]",
            "possible": "[?]",
        }.get(finding["confidence"], "[?]")

        print(f"\n  {conf_tag} [{i}] {finding['name']}")
        print(f"      Keyakinan : {finding['confidence'].upper()}")
        if "description" in finding:
            print(f"      Deskripsi : {finding['description']}")
        print(f"      Evidence  :")
        for ev in finding["evidence"]:
            print(f"        - {ev}")


def print_summary(cdn_findings: list[dict], waf_findings: list[dict]) -> None:
    print("\n" + "=" * 60)
    print("  Ringkasan Analisis")
    print("=" * 60)

    if cdn_findings:
        names = [f["name"] for f in cdn_findings]
        print(f"\n[+] CDN / Reverse Proxy : {', '.join(names)}")

        confidences = set(f["confidence"] for f in cdn_findings)
        if "certain" in confidences:
            print("[+] Status              : Terkonfirmasi (signature header ditemukan)")
        elif "likely" in confidences:
            print("[~] Status              : Kemungkinan besar (indikasi kuat)")
        else:
            print("[?] Status              : Mungkin (indikasi lemah)")
    else:
        print("\n[-] CDN / Reverse Proxy : Tidak terdeteksi")
        print("[*] Kemungkinan         : Origin server langsung, atau CDN custom")

    if waf_findings:
        waf_names = [f["name"] for f in waf_findings]
        print(f"[+] WAF Deteksi         : {', '.join(waf_names)}")

    print()


def main():
    parser = argparse.ArgumentParser(
        description="Reverse Proxy & CDN Analyzer - Deteksi CDN/proxy di balik website",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  python reverse_proxy_analyzer.py --target https://example.com
  python reverse_proxy_analyzer.py --target http://192.168.1.10:8080
        """,
    )

    parser.add_argument(
        "--target", "-t",
        type=str,
        required=True,
        help="URL target (contoh: https://example.com)",
    )

    args = parser.parse_args()

    if not args.target.startswith(("http://", "https://")):
        args.target = "https://" + args.target
        print(f"[*] Auto-correct URL: {args.target}")

    print_banner(args.target)

    print(f"\n[*] Mengirim request ke {args.target} ...")
    response = make_request(args.target)

    if response["error"]:
        print(f"\n[!] Gagal: {response['error']}")
        sys.exit(1)

    print_http_info(response)

    cdn_findings = detect_cdn(response)
    print_findings(cdn_findings, "CDN / Reverse Proxy")

    waf_findings = detect_waf_overlap(response, cdn_findings)
    print_findings(waf_findings, "WAF Overlap")

    print_summary(cdn_findings, waf_findings)


if __name__ == "__main__":
    main()
