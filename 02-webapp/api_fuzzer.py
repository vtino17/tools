#!/usr/bin/env python3
"""
API Endpoint Fuzzer (REST & GraphQL)

Fuzzer untuk API endpoint REST dan GraphQL. Mendukung OpenAPI spec parsing,
GraphQL introspection, fuzzing method, deteksi overposting, rate limiting,
verbose errors, dan insecure methods.

Usage:
    python api_fuzzer.py -u https://api.target.com
    python api_fuzzer.py -u https://api.target.com --spec openapi.json
    python api_fuzzer.py -u https://api.target.com/graphql --graphql
    python api_fuzzer.py -u https://api.target.com --graphql --threads 5
"""

import argparse
import json
import re
import sys
import urllib.parse
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
# COMMON API ENDPOINTS WORDLIST
# ═══════════════════════════════

COMMON_API_ENDPOINTS = [
    # Generic REST
    "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
    "/api/v1/users", "/api/v1/users/1", "/api/v1/users/admin",
    "/api/v1/me", "/api/v1/profile", "/api/v1/account",
    "/api/v1/auth/login", "/api/v1/auth/register", "/api/v1/auth/token",
    "/api/v1/admin", "/api/v1/admin/users", "/api/v1/admin/config",
    "/api/v1/products", "/api/v1/products/1", "/api/v1/items",
    "/api/v1/orders", "/api/v1/orders/1", "/api/v1/cart",
    "/api/v1/posts", "/api/v1/posts/1", "/api/v1/comments",
    "/api/v1/settings", "/api/v1/config", "/api/v1/health",
    "/api/v1/status", "/api/v1/ping", "/api/v1/version",
    "/api/v1/files", "/api/v1/uploads", "/api/v1/search",
    "/api/users", "/api/users/1", "/api/auth", "/api/login",
    "/api/admin", "/api/config", "/api/health", "/api/status",

    # Common platform paths
    "/rest/api/", "/services/rest/", "/webservice/rest/",
    "/graphql", "/gql", "/query", "/v1/graphql", "/v2/graphql",
    "/api/graphql", "/api/gql",

    # Swagger / OpenAPI
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api-docs.json", "/api/docs", "/docs/api",
    "/swagger-ui.html", "/swagger/index.html",

    # Specific framework paths
    "/.well-known/openid-configuration",
    "/oauth2/token", "/oauth2/authorize",
    "/.env", "/debug/vars", "/metrics",
]

# ═══════════════════════════════
# HTTP METHODS TO TEST
# ═══════════════════════════════

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

# ═══════════════════════════════
# OVERPOSTING TEST BODIES
# ═══════════════════════════════

OVERPOSTING_PAYLOADS = [
    {"role": "admin", "isAdmin": True, "is_admin": True},
    {"role": "superadmin", "admin": True, "superuser": True},
    {"price": 0, "discount": 999999, "balance": 99999},
    {"verified": True, "email_verified": True, "2fa_enabled": False},
    {"plan": "enterprise", "tier": "unlimited", "subscription": "lifetime"},
]

# ═══════════════════════════════
# GRAPHQL INTROSPECTION QUERY
# ═══════════════════════════════

GRAPHQL_INTROSPECTION = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind name description
      fields { name description args { name type { name kind ofType { name kind } } } }
      inputFields { name description type { name kind ofType { name kind } } }
    }
  }
}
""".strip()

GRAPHQL_DEPTH_TEST = """
query DepthTest {
  q1: __typename
  l1 { l2 { l3 { l4 { l5 { l6 { l7 { l8 { l9 { l10 { __typename } } } } } } } } }
}
""".strip()

GRAPHQL_COST_TEST = """
query AliasesTest {
  a1: __typename
  a2: __typename
  a3: __typename
  ...f1 ...f2 ...f3
}
fragment f1 on Query { a4: __typename a5: __typename a6: __typename a7: __typename a8: __typename }
fragment f2 on Query { a9: __typename a10: __typename a11: __typename a12: __typename a13: __typename }
fragment f3 on Query { a14: __typename a15: __typename a16: __typename a17: __typename a18: __typename }
""".strip()

GRAPHQL_FIELD_SUGGESTION_TEST = """
query { usr { name } }
""".strip()

GRAPHQL_BATCHING_TEST = [
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
    {"query": "{ __typename }"},
]


# ═══════════════════════════════
# HELPER
# ═══════════════════════════════

def _get_headers(content_type="application/json"):
    return {
        "User-Agent": "Mozilla/5.0 (compatible; APIFuzzer/1.0)",
        "Accept": "application/json, */*",
        "Content-Type": content_type,
        "Connection": "close",
    }


def _build_url(base, path):
    base = base.rstrip("/")
    path = path.lstrip("/")
    return f"{base}/{path}"


# ═══════════════════════════════
# OPENAPI / REST FUZZING
# ═══════════════════════════════

def load_openapi_spec(url_or_path, timeout=10):
    """Coba load OpenAPI spec dari URL atau file lokal."""
    if url_or_path.startswith("http://") or url_or_path.startswith("https://"):
        try:
            resp = requests.get(url_or_path, headers=_get_headers(), timeout=timeout, verify=False)
            if resp.status_code == 200:
                try:
                    return resp.json()
                except ValueError:
                    try:
                        import yaml
                        return yaml.safe_load(resp.text)
                    except Exception:
                        print("[!] Gagal parse OpenAPI spec (JSON/YAML).")
                        return None
        except RequestException:
            print("[!] Gagal fetch OpenAPI spec dari URL.")
            return None
    else:
        try:
            with open(url_or_path, "r", encoding="utf-8") as f:
                raw = f.read()
            try:
                return json.loads(raw)
            except ValueError:
                try:
                    import yaml
                    return yaml.safe_load(raw)
                except Exception:
                    print("[!] Gagal parse OpenAPI spec (JSON/YAML).")
                    return None
        except FileNotFoundError:
            print(f"[!] File tidak ditemukan: {url_or_path}")
            return None
        except Exception as e:
            print(f"[!] Error membaca spec: {e}")
            return None


def extract_endpoints_from_spec(spec, base_url):
    """Ekstrak path + method dari OpenAPI spec."""
    endpoints = []
    paths = spec.get("paths", {})
    servers = spec.get("servers", [])
    if servers:
        base_url = servers[0].get("url", base_url).rstrip("/")

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method in methods:
            if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
                full_path = f"{base_url}{path}"
                endpoints.append((full_path, method.upper()))
    return endpoints


def fuzz_rest_endpoint(url, method, timeout=10):
    """Fuzz satu REST endpoint dengan satu method dan analisis hasil."""

    findings = []
    headers = _get_headers()
    headers_no_auth = {k: v for k, v in headers.items()}

    try:
        if method in ("POST", "PUT", "PATCH"):
            resp = requests.request(method, url, headers=headers,
                                    json={"test": "fuzzer"}, timeout=timeout, verify=False)
        else:
            resp = requests.request(method, url, headers=headers, timeout=timeout, verify=False)
    except RequestException:
        return findings

    status = resp.status_code
    body = resp.text[:2000]
    body_lower = body.lower()
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    # Missing auth?
    if status == 200 and method in ("GET", "POST"):
        # Jika respons mengandung data sensitif tanpa token
        sensitive_keys = ["password", "token", "secret", "apikey", "credit_card", "ssn"]
        has_sensitive = any(k in body_lower for k in sensitive_keys)
        if has_sensitive:
            findings.append({
                "type": "missing_auth",
                "severity": "CRITICAL",
                "endpoint": url,
                "method": method,
                "description": f"Endpoint {method} mengembalikan data sensitif TANPA autentikasi",
                "evidence": "Data sensitif dalam respons 200",
            })
        else:
            # Mungkin endpoint tanpa auth, tapi berisi user data
            data_keys = ["user", "users", "data", "result", "id", "name", "email"]
            if any(k in body_lower for k in data_keys):
                findings.append({
                    "type": "potential_no_auth",
                    "severity": "HIGH",
                    "endpoint": url,
                    "method": method,
                    "description": f"Endpoint {method} mungkin dapat diakses tanpa auth",
                    "evidence": f"Status {status}, data ditemukan",
                })

    # Verbose errors
    error_patterns = [
        (r"stack\s*trace|stacktrace|traceback", "Stack trace dalam respons"),
        (r"ORA-\d+|SQLSTATE|PostgreSQL query failed", "Database error terlihat"),
        (r"exception\s+in|uncaught\s+exception|thrown\s+in", "Exception terlihat"),
        (r"Warning:\s+|Fatal error:|Notice:\s+", "PHP error terlihat"),
        (r"System\.\w+Exception|at\s+\w+\.\w+\(.*\)\s+in\s+", ".NET error terlihat"),
        (r"File\s+\".+\.\w+\"\s*,\s*line\s+\d+", "Path file & line number terlihat"),
        (r"DEBUG", "Debug flag terlihat"),
    ]
    for pattern, desc in error_patterns:
        if re.search(pattern, body, re.IGNORECASE):
            findings.append({
                "type": "verbose_error",
                "severity": "MEDIUM",
                "endpoint": url,
                "method": method,
                "description": f"Verbose error: {desc}",
                "evidence": re.search(pattern, body, re.IGNORECASE).group(0)[:100],
            })

    # Insecure methods
    if method == "OPTIONS":
        allow = resp.headers.get("Allow", resp.headers.get("allow", ""))
        dangerous = ["PUT", "DELETE", "TRACE", "CONNECT"]
        for dm in dangerous:
            if dm.upper() in allow.upper():
                findings.append({
                    "type": "insecure_method",
                    "severity": "LOW",
                    "endpoint": url,
                    "method": "OPTIONS",
                    "description": f"Method {dm} diizinkan via OPTIONS",
                    "evidence": f"Allow: {allow}",
                })

    # Rate limiting check
    rl_headers = ["x-ratelimit-limit", "x-rate-limit-limit", "ratelimit-limit",
                  "x-ratelimit-remaining", "retry-after"]
    has_rl = any(h in headers_lower for h in rl_headers)
    if status == 429:
        findings.append({
            "type": "rate_limiting",
            "severity": "INFO",
            "endpoint": url,
            "method": method,
            "description": "Rate limiting terdeteksi (HTTP 429)",
            "evidence": "Status 429 Too Many Requests",
        })
    elif status == 200 and not has_rl:
        pass  # tidak bisa memastikan tanpa rate limiting header

    return findings


def fuzz_overposting(base_url, timeout=10):
    """Uji overposting / mass assignment pada endpoint."""
    findings = []
    endpoints_to_test = [
        "/api/v1/users", "/api/v1/users/1", "/api/users", "/api/users/1",
        "/api/v1/me", "/api/v1/profile", "/api/v1/account",
        "/api/v1/auth/register", "/api/v1/auth/signup",
    ]

    for ep in endpoints_to_test:
        url = _build_url(base_url, ep)
        for payload in OVERPOSTING_PAYLOADS:
            try:
                resp = requests.post(url, headers=_get_headers(), json=payload, timeout=timeout, verify=False)
                if resp.status_code in (200, 201):
                    findings.append({
                        "type": "overposting",
                        "severity": "HIGH",
                        "endpoint": url,
                        "method": "POST",
                        "description": f"Endpoint menerima field tidak terduga: {list(payload.keys())}",
                        "evidence": f"Status {resp.status_code}",
                    })
                    break
            except RequestException:
                pass

    return findings


# ═══════════════════════════════
# GRAPHQL FUZZING
# ═══════════════════════════════

def graphql_introspection(url, timeout=10):
    """Jalankan GraphQL introspection query."""
    try:
        resp = requests.post(url, headers=_get_headers(),
                             json={"query": GRAPHQL_INTROSPECTION},
                             timeout=timeout, verify=False)
        if resp.status_code == 200:
            data = resp.json()
            if "data" in data and data["data"].get("__schema"):
                return data["data"]["__schema"]
    except (RequestException, ValueError, KeyError):
        pass
    return None


def graphql_depth_test(url, timeout=10):
    """Uji apakah GraphQL membatasi query depth."""
    try:
        resp = requests.post(url, headers=_get_headers(),
                             json={"query": GRAPHQL_DEPTH_TEST},
                             timeout=timeout, verify=False)
        if resp.status_code == 200:
            if "error" not in resp.json():
                return True  # depth tidak dibatasi
        return False
    except (RequestException, ValueError):
        return None


def graphql_cost_test(url, timeout=10):
    """Uji query cost/complexity limit."""
    try:
        resp = requests.post(url, headers=_get_headers(),
                             json={"query": GRAPHQL_COST_TEST},
                             timeout=timeout, verify=False)
        if resp.status_code == 200:
            if "error" not in resp.json():
                return True  # cost tidak dibatasi
        return False
    except (RequestException, ValueError):
        return None


def graphql_field_suggestion_test(url, timeout=10):
    """Uji field suggestion (bisa leak schema)."""
    try:
        resp = requests.post(url, headers=_get_headers(),
                             json={"query": GRAPHQL_FIELD_SUGGESTION_TEST},
                             timeout=timeout, verify=False)
        if resp.status_code == 200:
            data = resp.json()
            if "errors" in data:
                for err in data["errors"]:
                    msg = err.get("message", "")
                    if "Did you mean" in msg or "Cannot query field" in msg:
                        return True, msg[:200]
        return False, None
    except (RequestException, ValueError):
        return None, None


def graphql_batching_test(url, timeout=10):
    """Uji apakah GraphQL menerima batched queries."""
    try:
        resp = requests.post(url, headers=_get_headers(),
                             json=GRAPHQL_BATCHING_TEST,
                             timeout=timeout, verify=False)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list) and len(data) == 3:
                return True
        return False
    except (RequestException, ValueError):
        return None


def graphql_debug_mode(url, timeout=10):
    """Cek apakah GraphQL mengembalikan debug/trace info."""
    try:
        resp = requests.post(url, headers=_get_headers(),
                             json={"query": "{ __typenam }"},
                             timeout=timeout, verify=False)
        body = resp.text.lower()
        debug_indicators = ["stacktrace", "traceback", "exception", "debug",
                            "extensions", "locations"]
        for di in debug_indicators:
            if di in body:
                return True, di
        return False, None
    except (RequestException, ValueError):
        return None, None


# ═══════════════════════════════
# MAIN
# ═══════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="API Endpoint Fuzzer - Fuzz REST & GraphQL endpoints",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  python api_fuzzer.py -u https://api.target.com
  python api_fuzzer.py -u https://api.target.com --spec openapi.json
  python api_fuzzer.py -u https://api.target.com/graphql --graphql
  python api_fuzzer.py -u https://api.target.com --graphql --threads 5
        """,
    )
    parser.add_argument("-u", "--url", required=True, help="URL target API base (contoh: https://api.target.com)")
    parser.add_argument("--spec", help="Path atau URL ke OpenAPI/Swagger spec (JSON/YAML)")
    parser.add_argument("--graphql", action="store_true", help="Aktifkan fuzzing GraphQL")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Thread paralel (default: 5)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout request (default: 10)")
    parser.add_argument("--no-overposting", action="store_true", help="Skip uji overposting")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")
    timeout = args.timeout
    threads = min(args.threads, 20)

    print(r"""
╔═╗╔═╗╦  ╔═╗╦ ╦╔═╗╔═╗╔═╗╦═╗
╠═╣╠═╝║  ╠╣ ║ ║╔═╝║╣ ║╣ ╠╦╝
╩ ╩╩  ╩  ╚  ╚═╝╩  ╚═╝╚═╝╩╚═  v1.0
""")

    print(f"\n[*] Target: {base_url}")
    print(f"[*] Threads: {threads}")

    all_findings = []

    # ═══════ OPENAPI SPEC
    endpoints = []
    if args.spec:
        print(f"\n[*] Memuat OpenAPI spec: {args.spec}")
        spec = load_openapi_spec(args.spec, timeout)
        if spec:
            endpoints = extract_endpoints_from_spec(spec, base_url)
            print(f"[+] {len(endpoints)} endpoint dari spec ditemukan")
        else:
            print("[!] Gagal memuat spec, fallback ke wordlist umum.")

    if not endpoints:
        endpoints = [(f"{base_url}{ep}", "GET") for ep in COMMON_API_ENDPOINTS]
        # Tambahkan juga variasi method
        expanded = []
        for ep_url, _ in endpoints:
            for method in HTTP_METHODS:
                expanded.append((ep_url, method))
        endpoints = expanded
        print(f"[+] {len(endpoints)} endpoint dari wordlist untuk fuzzing")

    # ═══════ REST FUZZING
    print(f"\n[1] REST API FUZZING ({len(endpoints)} requests)\n" + "=" * 60)

    tested = 0
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(fuzz_rest_endpoint, ep, method, timeout): (ep, method)
                   for ep, method in endpoints}
        for future in as_completed(futures):
            tested += 1
            result = future.result()
            if result:
                all_findings.extend(result)
                for f in result:
                    sev = f["severity"]
                    icon = "[!]" if sev in ("CRITICAL", "HIGH") else "[+]" if sev == "MEDIUM" else "[*]"
                    print(f"{icon} [{sev}] {f['method']:6} {f['endpoint'][:80]}")
                    print(f"      {f['description']}")
                    if f.get("evidence"):
                        print(f"      Evidence: {f['evidence'][:120]}")
            if tested % 50 == 0:
                print(f"[*] Progress: {tested}/{len(endpoints)} diuji...")

    # ═══════ OVERPOSTING
    if not args.no_overposting:
        print(f"\n[2] OVERPOSTING TEST\n" + "=" * 60)
        overpost_findings = fuzz_overposting(base_url, timeout)
        if overpost_findings:
            for f in overpost_findings:
                all_findings.append(f)
                print(f"[!] [{f['severity']}] {f['endpoint']} - {f['description']}")
        else:
            print("[-] Tidak ada celah overposting yang terdeteksi.")

    # ═══════ GRAPHQL
    if args.graphql:
        print(f"\n[3] GRAPHQL FUZZING\n" + "=" * 60)
        gql_url = base_url if "/graphql" in base_url else _build_url(base_url, "/graphql")
        print(f"[*] GraphQL endpoint: {gql_url}")

        # Introspection
        print("\n[*] Mencoba GraphQL introspection...")
        schema = graphql_introspection(gql_url, timeout)
        if schema:
            query_type = schema.get("queryType", {}).get("name", "?")
            mutation_type = schema.get("mutationType", {})
            types_count = len(schema.get("types", []))
            print(f"[!] [CRITICAL] GraphQL Introspection AKTIF!")
            print(f"    Query type: {query_type}")
            if mutation_type:
                print(f"    Mutation type: {mutation_type.get('name', '?')}")
            print(f"    Total types: {types_count}")
            all_findings.append({
                "type": "graphql_introspection",
                "severity": "CRITICAL",
                "endpoint": gql_url,
                "method": "POST",
                "description": f"GraphQL introspection terbuka ({types_count} types)",
                "evidence": f"Query type: {query_type}",
            })
        else:
            print("[-] Introspection tidak aktif atau diblokir.")

        # Depth limit test
        print("\n[*] Menguji query depth limit...")
        depth_result = graphql_depth_test(gql_url, timeout)
        if depth_result:
            print("[!] [HIGH] GraphQL tidak membatasi query depth!")
            print("    Attacker bisa melakukan deeply nested query DoS.")
            all_findings.append({
                "type": "graphql_depth",
                "severity": "HIGH",
                "endpoint": gql_url,
                "method": "POST",
                "description": "Query depth TIDAK dibatasi (depth 10 diterima)",
                "evidence": "Deeply nested query berhasil",
            })
        elif depth_result is False:
            print("[+] Query depth limit diterapkan (aman).")

        # Cost limit
        print("\n[*] Menguji query cost/complexity limit...")
        cost_result = graphql_cost_test(gql_url, timeout)
        if cost_result:
            print("[!] [HIGH] GraphQL tidak membatasi query cost!")
            all_findings.append({
                "type": "graphql_cost",
                "severity": "HIGH",
                "endpoint": gql_url,
                "method": "POST",
                "description": "Query cost/complexity TIDAK dibatasi",
                "evidence": "Multi-fragment aliased query berhasil",
            })
        elif cost_result is False:
            print("[+] Query cost limit diterapkan (aman).")

        # Field suggestion
        print("\n[*] Menguji field suggestion...")
        suggest_result, suggest_msg = graphql_field_suggestion_test(gql_url, timeout)
        if suggest_result:
            print(f"[+] [MEDIUM] Field suggestion AKTIF: {suggest_msg}")
            all_findings.append({
                "type": "graphql_suggestion",
                "severity": "MEDIUM",
                "endpoint": gql_url,
                "method": "POST",
                "description": "Field suggestions dapat membantu enumerasi schema",
                "evidence": suggest_msg,
            })
        else:
            print("[-] Field suggestion tidak aktif.")

        # Batching
        print("\n[*] Menguji query batching...")
        batch_result = graphql_batching_test(gql_url, timeout)
        if batch_result:
            print("[+] [MEDIUM] GraphQL menerima batched queries (mungkin abuse untuk brute force).")
            all_findings.append({
                "type": "graphql_batching",
                "severity": "MEDIUM",
                "endpoint": gql_url,
                "method": "POST",
                "description": "Query batching diizinkan",
                "evidence": "3 batched queries berhasil",
            })
        else:
            print("[-] Batching tidak diizinkan.")

        # Debug mode
        print("\n[*] Mengecek debug/trace info...")
        debug_result, debug_info = graphql_debug_mode(gql_url, timeout)
        if debug_result:
            print(f"[!] [HIGH] GraphQL debug mode AKTIF! ({debug_info})")
            all_findings.append({
                "type": "graphql_debug",
                "severity": "HIGH",
                "endpoint": gql_url,
                "method": "POST",
                "description": f"GraphQL mengembalikan debug info",
                "evidence": f"Trace mengandung '{debug_info}'",
            })
        else:
            print("[-] Tidak ada debug info yang bocor.")

    # ═══════ SUMMARY
    print(f"\n{'=' * 60}")
    print(f"  RINGKASAN TEMUAN")
    print(f"{'=' * 60}")

    if all_findings:
        by_severity = {}
        for f in all_findings:
            sev = f["severity"]
            by_severity.setdefault(sev, []).append(f)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            items = by_severity.get(sev, [])
            if items:
                print(f"\n  {sev}: {len(items)} temuan")
                for item in items:
                    print(f"    - [{item['type']}] {item['description'][:100]}")

        print(f"\n  Total temuan: {len(all_findings)}")
        print(f"  CRITICAL: {len(by_severity.get('CRITICAL', []))}")
        print(f"  HIGH:     {len(by_severity.get('HIGH', []))}")
        print(f"  MEDIUM:   {len(by_severity.get('MEDIUM', []))}")
    else:
        print("\n[-] Tidak ada temuan keamanan yang terdeteksi.")

    print(f"\n[*] Selesai. {tested} endpoint diuji.")


if __name__ == "__main__":
    main()
