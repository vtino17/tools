#!/usr/bin/env python3
"""
GCP Enumeration Tool — Passive & Active Reconnaissance.

Enumerates GCP resources without credentials (passive) or with credentials
(service account key JSON). Supports GCS bucket discovery, Cloud Run service
enumeration, IAM roles, Compute Engine VMs, Cloud SQL instances.

Usage:
    # Passive: scan common GCS bucket names for a company
    python gcp_enum.py --company "examplecorp" --passive

    # Active with service account key
    python gcp_enum.py --service-account-key "sa-key.json"

    # Organization-level enumeration
    python gcp_enum.py --service-account-key "sa-key.json" --org-id "123456789012"

    # Full enumeration
    python gcp_enum.py --service-account-key "sa-key.json" --all
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

GOOGLE_API_AVAILABLE = False
try:
    from googleapiclient import discovery
    from google.oauth2 import service_account

    GOOGLE_API_AVAILABLE = True
except ImportError:
    pass

GCS_PATTERNS = [
    "{company}",
    "{company}-prod",
    "{company}-dev",
    "{company}-staging",
    "{company}-test",
    "{company}-backup",
    "{company}-data",
    "{company}-assets",
    "{company}-static",
    "{company}-media",
    "{company}-logs",
    "{company}-files",
    "{company}-images",
    "{company}-terraform",
    "{company}-config",
    "{company}-build",
    "prod-{company}",
    "dev-{company}",
    "staging-{company}",
]

GCP_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
TOKEN_URI = "https://oauth2.googleapis.com/token"
GCS_BASE = "https://storage.googleapis.com"
CLOUD_RUN_BASE = "https://{region}-run.googleapis.com"


def get_access_token(key_path):
    """Obtain GCP access token from service account key."""
    try:
        with open(key_path, "r") as f:
            sa_info = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"[!] Gagal membaca service account key: {e}")
        return None

    print(f"[*] Service account: {sa_info.get('client_email', '?')}")
    print(f"[*] Project: {sa_info.get('project_id', '?')}\n")

    from jwt import JWT
    import jwt as jwtt
    import jwt

    from datetime import datetime, timedelta, timezone

    try:
        import jwt
    except ImportError:
        jwt = None

    if jwt is None:
        try:
            import PyJWT as jwt
        except ImportError:
            print("[!] PyJWT tidak ditemukan. Mencoba dengan google-auth...")
            if GOOGLE_API_AVAILABLE:
                creds = service_account.Credentials.from_service_account_file(
                    key_path, scopes=GCP_SCOPES
                )
                creds.refresh(requests.Request())
                return creds.token
            print("[!] Install: pip install pyjwt google-api-python-client google-auth")
            return None

    now = int(time.time())
    assertion = {
        "iss": sa_info["client_email"],
        "scope": " ".join(GCP_SCOPES),
        "aud": TOKEN_URI,
        "exp": now + 3600,
        "iat": now,
    }
    private_key = sa_info["private_key"]
    try:
        signed = jwt.encode(assertion, private_key, algorithm="RS256")
    except Exception as e:
        print(f"[!] Gagal sign JWT: {e}")
        return None

    try:
        resp = requests.post(
            TOKEN_URI,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": signed,
            },
            timeout=15,
        )
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


def gcp_get(token, url, params=None):
    """Make authenticated GET request to GCP API."""
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    results = []
    while url:
        try:
            resp = requests.get(url, headers=headers, params=params, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                if "items" in data:
                    results.extend(data["items"])
                if "projects" in data:
                    results.extend(data["projects"])
                if "instances" in data:
                    results.extend(data.get("instances", []))
                if "buckets" in data:
                    results.extend(data.get("buckets", []))
                url = data.get("nextPageToken")
                if url and not url.startswith("http"):
                    if params:
                        params["pageToken"] = url
                    else:
                        params = {"pageToken": url}
                    url_components = resp.request.url.split("?")[0]
                    url = url_components
                elif not url or url == resp.request.url:
                    url = None
                else:
                    url = None
            elif resp.status_code == 401:
                print(f"[!] Token tidak valid / expired")
                return results
            elif resp.status_code == 403:
                print(f"[!] Insufficient permissions untuk endpoint")
                return results
            else:
                print(f"[!] HTTP {resp.status_code} pada API call")
                return results
        except requests.exceptions.RequestException as e:
            print(f"[!] Gagal koneksi: {e}")
            return results
        time.sleep(0.3)
    return results


def list_projects(token):
    """List GCP projects."""
    print("[*] Enumerasi GCP projects...")
    projects = gcp_get(token, "https://cloudresourcemanager.googleapis.com/v1/projects")
    print(f"[+] Projects: {len(projects)}")
    for p in projects[:30]:
        p_id = p.get("projectId", "?")
        lifecycle = p.get("lifecycleState", "?")
        print(f"  [*] {p.get('name', '?')} (id={p_id}, state={lifecycle})")
    return projects


def list_iam_roles(token, project_id):
    """List IAM roles/policies for a project."""
    print(f"\n[*] Enumerasi IAM untuk project: {project_id}")
    try:
        url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}:getIamPolicy"
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        resp = requests.post(url, headers=headers, json={}, timeout=30)
        if resp.status_code == 200:
            bindings = resp.json().get("bindings", [])
            print(f"[+] IAM bindings: {len(bindings)}")
            for b in bindings:
                role = b.get("role", "?")
                members = b.get("members", [])
                pfx = "[!]" if "admin" in role.lower() else "[*]"
                print(f"  {pfx} {role}: {len(members)} members")
                for m in members[:5]:
                    print(f"      {m}")
                if len(members) > 5:
                    print(f"      ... dan {len(members) - 5} lainnya")
            return bindings
        else:
            print(f"[!] HTTP {resp.status_code}")
    except Exception as e:
        print(f"[!] Gagal enumerasi IAM: {e}")
    return []


def list_compute_instances(token, project_id, zone="us-central1-a"):
    """List Compute Engine VM instances."""
    print(f"\n[*] Enumerasi Compute Engine untuk project: {project_id}")
    try:
        url = (
            f"https://compute.googleapis.com/compute/v1/projects/{project_id}/aggregated/instances"
        )
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            data = resp.json()
            count = 0
            for zone_key, zone_data in data.get("items", {}).items():
                instances = zone_data.get("instances", [])
                for inst in instances:
                    count += 1
                    name = inst.get("name", "?")
                    status = inst.get("status", "?")
                    tags = inst.get("tags", {}).get("items", [])
                    nat_ip = None
                    for iface in inst.get("networkInterfaces", []):
                        for ac in iface.get("accessConfigs", []):
                            nat_ip = ac.get("natIP")
                    pfx = "[!]" if nat_ip else "[*]"
                    ip_str = nat_ip or "Tidak"
                    print(f"  {pfx} {name} | {status} | public_ip={ip_str} | tags={tags}")
            print(f"[+] Total instances: {count}")
            return count
        else:
            print(f"[!] HTTP {resp.status_code}")
    except Exception as e:
        print(f"[!] Gagal enumerasi Compute: {e}")
    return 0


def list_gcs_buckets(token, project_id):
    """List Cloud Storage buckets for a project."""
    print(f"\n[*] Enumerasi GCS buckets untuk project: {project_id}")
    try:
        url = f"https://storage.googleapis.com/storage/v1/b?project={project_id}"
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            items = resp.json().get("items", [])
            print(f"[+] GCS Buckets: {len(items)}")
            for b in items:
                name = b.get("name", "?")
                location = b.get("location", "?")
                try:
                    pub_resp = requests.get(f"{GCS_BASE}/{name}", timeout=5, allow_redirects=False)
                    public = (
                        pub_resp.status_code in (200, 403)
                        and "<ListBucketResult" in pub_resp.text[:200]
                    )
                except Exception:
                    public = False
                pfx = "[!]" if public else "[*]"
                print(f"  {pfx} gs://{name} (location={location}, public={public})")
            return items
        elif resp.status_code == 404:
            print("[-] Tidak ada GCS buckets atau insufficient permissions")
        else:
            print(f"[!] HTTP {resp.status_code}")
    except Exception as e:
        print(f"[!] Gagal enumerasi GCS: {e}")
    return []


def list_cloud_sql(token, project_id):
    """List Cloud SQL instances."""
    print(f"\n[*] Enumerasi Cloud SQL untuk project: {project_id}")
    try:
        url = f"https://sqladmin.googleapis.com/v1/projects/{project_id}/instances"
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            items = resp.json().get("items", [])
            print(f"[+] Cloud SQL Instances: {len(items)}")
            for inst in items:
                name = inst.get("name", "?")
                db_ver = inst.get("databaseVersion", "?")
                state = inst.get("state", "?")
                pub = False
                for ip in inst.get("ipAddresses", []):
                    if ip.get("type") == "PRIMARY":
                        pub = True
                pfx = "[!]" if pub else "[+]"
                print(f"  {pfx} {name} ({db_ver}) | {state} | public_ip={pub}")
            return items
        else:
            print(f"[!] HTTP {resp.status_code}")
    except Exception as e:
        print(f"[!] Gagal enumerasi Cloud SQL: {e}")
    return []


def check_gcs_bucket(name, timeout=5):
    """Check if a GCS bucket exists via public HTTP."""
    result = {"name": name, "exists": False, "public": False}
    url = f"{GCS_BASE}/{name}"
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=False)
        if resp.status_code != 404:
            result["exists"] = True
            if resp.status_code == 200 and "<ListBucketResult" in resp.text[:300]:
                result["public"] = True
    except requests.exceptions.RequestException:
        pass
    return result


def passive_enum(company, threads=10):
    """Run passive GCP enumeration."""
    print(f"[*] Enumerasi pasif GCP untuk: {company}")
    print(f"[*] Menjalankan dengan {threads} thread\n")

    patterns = [p.format(company=company) for p in GCS_PATTERNS]
    patterns = list(dict.fromkeys(patterns))
    print(f"[*] Menguji {len(patterns)} nama bucket GCS...\n")

    found = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_gcs_bucket, p): p for p in patterns}
        for i, future in enumerate(as_completed(futures), 1):
            res = future.result()
            if res["exists"]:
                found.append(res)
                pfx = "[+]" if res["public"] else "[*]"
                akses = "PUBLIK" if res["public"] else "pribadi"
                print(f"  {pfx} gs://{res['name']} ({akses})")
            if i % 20 == 0:
                print(f"    ... {i}/{len(patterns)} diproses")

    public_count = sum(1 for b in found if b["public"])
    print(f"\n[*] Menemukan {len(found)} bucket GCS ({public_count} publik)")

    return {"buckets": found}


def main():
    parser = argparse.ArgumentParser(
        description="GCP Enumeration Tool — Reconnaissance pasif & aktif",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  python gcp_enum.py --company "examplecorp" --passive
  python gcp_enum.py --service-account-key "sa-key.json"
  python gcp_enum.py --service-account-key "sa-key.json" --org-id "123456789012"
  python gcp_enum.py --company "examplecorp" --passive --output results.json
        """,
    )
    parser.add_argument("--company", help="Nama perusahaan untuk enumerasi pasif")
    parser.add_argument(
        "--passive", action="store_true", help="Mode enumerasi pasif (tanpa kredensial)"
    )
    parser.add_argument("--service-account-key", help="Path ke file JSON service account key GCP")
    parser.add_argument("--org-id", help="GCP Organization ID")
    parser.add_argument("--all", action="store_true", help="Enumerasi semua resource")
    parser.add_argument("--project", help="GCP project ID spesifik")
    parser.add_argument("--threads", type=int, default=10, help="Jumlah thread (default: 10)")
    parser.add_argument("--output", help="Simpan hasil ke file JSON")
    args = parser.parse_args()

    results = {}

    if args.passive:
        if not args.company:
            print("[!] --company diperlukan untuk mode pasif")
            sys.exit(1)
        results = passive_enum(args.company, args.threads)
    else:
        if not args.service_account_key:
            print("[!] --service-account-key diperlukan untuk mode aktif")
            print("[*] Gunakan mode pasif dengan --passive --company NAMA")
            sys.exit(1)

        token = get_access_token(args.service_account_key)
        if not token:
            sys.exit(1)

        projects = list_projects(token)
        results["projects"] = projects

        for p in projects:
            pid = p.get("projectId")
            if not pid:
                continue
            if args.project and args.project != pid:
                continue

            print(f"\n{'='*60}")
            print(f"  Project: {p.get('name', pid)} ({pid})")
            print(f"{'='*60}")

            results.setdefault("iam", {})[pid] = list_iam_roles(token, pid)
            list_compute_instances(token, pid)
            results.setdefault("gcs", {})[pid] = list_gcs_buckets(token, pid)
            list_cloud_sql(token, pid)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n[+] Hasil disimpan ke: {args.output}")

    print("\n[*] Selesai.")


if __name__ == "__main__":
    main()
