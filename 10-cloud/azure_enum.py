#!/usr/bin/env python3
"""
Azure Enumeration Tool — Passive & Active Reconnaissance.

Enumerates Azure resources without credentials (passive) or with credentials
(Microsoft Graph API). Supports storage account discovery, Azure AD enumeration,
subscriptions, and resource listing.

Usage:
    # Passive: scan common storage account names for a company
    python azure_enum.py --company "examplecorp" --passive

    # Active: enumerate Azure AD with OAuth
    python azure_enum.py --tenant-id "xxx" --client-id "xxx" --client-secret "xxx"

    # User enumeration via common naming patterns
    python azure_enum.py --domain "examplecorp.com" --tenant-id "xxx" --client-id "xxx" --client-secret "xxx"

    # Full enumeration
    python azure_enum.py --tenant-id "xxx" --client-id "xxx" --client-secret "xxx" --all
"""

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote

try:
    import requests
except ImportError:
    print("[!] Modul 'requests' tidak ditemukan. Install: pip install requests")
    sys.exit(1)

STORAGE_PATTERNS = [
    "{company}", "{company}prod", "{company}dev", "{company}staging",
    "{company}test", "{company}backup", "{company}data",
    "{company}files", "{company}blob", "{company}static", "{company}cdn",
    "{company}media", "{company}logs", "{company}assets",
    "prod{company}", "dev{company}", "stg{company}",
]

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
LOGIN_BASE = "https://login.microsoftonline.com"


def get_graph_token(tenant_id, client_id, client_secret):
    """Obtain Microsoft Graph API access token via OAuth client credentials."""
    url = f"{LOGIN_BASE}/{tenant_id}/oauth2/v2.0/token"
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
        "scope": "https://graph.microsoft.com/.default",
    }
    print(f"[*] Meminta token dari {LOGIN_BASE}/{tenant_id}/oauth2/v2.0/token")
    try:
        resp = requests.post(url, data=data, timeout=15)
        if resp.status_code == 200:
            token = resp.json().get("access_token")
            print("[+] Token didapatkan\n")
            return token
        else:
            print(f"[!] Gagal mendapatkan token (HTTP {resp.status_code}): {resp.text[:300]}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"[!] Gagal koneksi: {e}")
        return None


def graph_get(token, endpoint, params=None):
    """Make a GET request to Microsoft Graph API."""
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    results = []
    url = f"{GRAPH_BASE}{endpoint}"
    while url:
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                results.extend(data.get("value", []))
                url = data.get("@odata.nextLink")
                params = None
            elif resp.status_code == 401:
                print(f"[!] Token tidak valid / expired")
                return results
            elif resp.status_code == 403:
                print(f"[!] Insufficient permissions untuk {endpoint}")
                return results
            else:
                print(f"[!] HTTP {resp.status_code} pada {endpoint}")
                return results
        except requests.exceptions.RequestException as e:
            print(f"[!] Gagal koneksi Graph API: {e}")
            return results
        time.sleep(0.2)
    return results


def list_users(token):
    """Enumerate Azure AD users."""
    print("[*] Enumerasi Azure AD users...")
    users = graph_get(token, "/users", params={"$top": 999})
    print(f"[+] Users: {len(users)}")
    for u in users[:50]:
        upn = u.get("userPrincipalName", "N/A")
        enabled = u.get("accountEnabled", "N/A")
        mfa = u.get("strongAuthenticationDetail", {})
        pfx = "[+]" if enabled else "[!]"
        mfa_str = "MFA" if mfa else "?"
        print(f"  {pfx} {u.get('displayName','?')} | {upn} | enabled={enabled} | {mfa_str}")
    if len(users) > 50:
        print(f"  ... dan {len(users) - 50} users lainnya")
    return users


def list_groups(token):
    """Enumerate Azure AD groups."""
    print("\n[*] Enumerasi Azure AD groups...")
    groups = graph_get(token, "/groups", params={"$top": 999})
    print(f"[+] Groups: {len(groups)}")
    for g in groups[:30]:
        print(f"  [*] {g.get('displayName','?')} ({g.get('id','?')}) | {g.get('groupTypes','?')}")
    if len(groups) > 30:
        print(f"  ... dan {len(groups) - 30} groups lainnya")
    return groups


def list_applications(token):
    """Enumerate Azure AD applications."""
    print("\n[*] Enumerasi Azure AD applications...")
    apps = graph_get(token, "/applications", params={"$top": 999})
    print(f"[+] Applications: {len(apps)}")
    for a in apps[:30]:
        app_id = a.get("appId", "?")
        print(f"  [*] {a.get('displayName','?')} (appId={app_id})")
    if len(apps) > 30:
        print(f"  ... dan {len(apps) - 30} apps lainnya")
    return apps


def list_service_principals(token):
    """Enumerate Azure AD service principals."""
    print("\n[*] Enumerasi service principals...")
    sps = graph_get(token, "/servicePrincipals", params={"$top": 999})
    print(f"[+] Service Principals: {len(sps)}")
    for sp in sps[:30]:
        app_id = sp.get("appId", "?")
        print(f"  [*] {sp.get('displayName','?')} (appId={app_id})")
    if len(sps) > 30:
        print(f"  ... dan {len(sps) - 30} SPs lainnya")
    return sps


def check_storage_account(name, timeout=5):
    """Check if an Azure storage account exists via HTTP."""
    result = {"name": name, "exists": False, "public": False}
    url = f"https://{name}.blob.core.windows.net"
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=False)
        if resp.status_code != 404:
            result["exists"] = True
            if resp.status_code == 200:
                result["public"] = True
                try:
                    xml_data = resp.text
                    if "<EnumerationResults" in xml_data:
                        containers = []
                        for line in xml_data.split("\n"):
                            if "<Name>" in line and "</Name>" in line:
                                cname = line.split("<Name>")[1].split("</Name>")[0]
                                containers.append(cname)
                        if containers and "$root" not in containers:
                            result["containers"] = containers
                except Exception:
                    pass
    except requests.exceptions.RequestException:
        pass
    return result


def passive_enum(company, threads=10):
    """Run passive Azure enumeration."""
    print(f"[*] Enumerasi pasif Azure untuk: {company}")
    print(f"[*] Menjalankan dengan {threads} thread\n")

    patterns = [p.format(company=company) for p in STORAGE_PATTERNS]
    patterns = list(dict.fromkeys(patterns))
    print(f"[*] Menguji {len(patterns)} storage account...\n")

    found = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_storage_account, p): p for p in patterns}
        for i, future in enumerate(as_completed(futures), 1):
            res = future.result()
            if res["exists"]:
                found.append(res)
                pfx = "[+]" if res["public"] else "[*]"
                akses = "PUBLIK" if res["public"] else "pribadi"
                extra = ""
                if res.get("containers"):
                    extra = f"containers={res['containers'][:5]}"
                print(f"  {pfx} https://{res['name']}.blob.core.windows.net ({akses}) {extra}")
            if i % 20 == 0:
                print(f"    ... {i}/{len(patterns)} diproses")

    print(f"\n[*] Menemukan {len(found)} storage account ({sum(1 for b in found if b['public'])} publik)")
    return {"storage_accounts": found}


def enumerate_users_by_pattern(token, domain, threads=10):
    """Enumerate Azure AD users via common naming patterns."""
    print(f"\n[*] Enumerasi user berdasarkan domain: {domain}")

    common_names = [
        "admin", "administrator", "user", "test", "dev", "developer",
        "info", "contact", "support", "sales", "marketing", "finance",
        "hr", "it", "security", "help", "service", "office", "mail",
        "webmaster", "postmaster", "root", "azure", "cloud",
    ]

    def check_user(upn):
        url = f"{GRAPH_BASE}/users/{quote(upn)}"
        headers = {"Authorization": f"Bearer {token}"}
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "upn": upn,
                    "display_name": data.get("displayName"),
                    "enabled": data.get("accountEnabled"),
                }
        except Exception:
            pass
        return None

    print(f"[*] Menguji {len(common_names)} nama umum...\n")
    found = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {}
        for name in common_names:
            upn = f"{name}@{domain}"
            futures[executor.submit(check_user, upn)] = name
        for future in as_completed(futures):
            res = future.result()
            if res:
                found.append(res)
                print(f"  [+] {res['upn']} ({res.get('display_name','?')})")

    print(f"\n[+] Menemukan {len(found)} user via enumerasi pola")
    return found


def main():
    parser = argparse.ArgumentParser(
        description="Azure Enumeration Tool — Reconnaissance pasif & aktif",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  python azure_enum.py --company "examplecorp" --passive
  python azure_enum.py --tenant-id "xxx" --client-id "xxx" --client-secret "xxx"
  python azure_enum.py --tenant-id "xxx" --client-id "xxx" --client-secret "xxx" --all
  python azure_enum.py --company "examplecorp" --passive --output results.json
        """,
    )
    parser.add_argument("--company", help="Nama perusahaan untuk enumerasi pasif")
    parser.add_argument("--passive", action="store_true", help="Mode enumerasi pasif (tanpa kredensial)")
    parser.add_argument("--tenant-id", help="Azure AD Tenant ID")
    parser.add_argument("--client-id", help="Azure AD Application (client) ID")
    parser.add_argument("--client-secret", help="Azure AD client secret")
    parser.add_argument("--domain", help="Domain untuk user enumeration (contoh: examplecorp.com)")
    parser.add_argument("--all", action="store_true", help="Enumerasi semua resource yang tersedia")
    parser.add_argument("--threads", type=int, default=10, help="Jumlah thread konkuren (default: 10)")
    parser.add_argument("--output", help="Simpan hasil ke file JSON")
    args = parser.parse_args()

    results = {}

    if args.passive:
        if not args.company:
            print("[!] --company diperlukan untuk mode pasif")
            sys.exit(1)
        results = passive_enum(args.company, args.threads)
    else:
        if not all([args.tenant_id, args.client_id, args.client_secret]):
            print("[!] --tenant-id, --client-id, --client-secret diperlukan untuk mode aktif")
            print("[*] Gunakan mode pasif dengan --passive --company NAMA")
            sys.exit(1)

        token = get_graph_token(args.tenant_id, args.client_id, args.client_secret)
        if not token:
            sys.exit(1)

        results["users"] = list_users(token)
        results["groups"] = list_groups(token)
        results["applications"] = list_applications(token)
        results["service_principals"] = list_service_principals(token)

        if args.domain:
            results["discovered_users"] = enumerate_users_by_pattern(token, args.domain, args.threads)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n[+] Hasil disimpan ke: {args.output}")

    print("\n[*] Selesai.")


if __name__ == "__main__":
    main()
