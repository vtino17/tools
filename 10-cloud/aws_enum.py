#!/usr/bin/env python3
"""
AWS Enumeration Tool — Passive & Active Reconnaissance.

Enumerates AWS resources without credentials (passive) or with credentials
(boto3 active mode). Supports S3 bucket scanning, CloudFront discovery, IAM,
EC2, RDS, Lambda enumeration.

Usage:
    # Passive: scan common S3 bucket names for a company
    python aws_enum.py --company "examplecorp" --passive

    # Active: full enumeration with AWS profile
    python aws_enum.py --profile "default" --service all

    # Active: specific service with access keys
    python aws_enum.py --access-key AKIAxxx --secret-key xxx --service s3

    # Bucket fuzzing with wordlist
    python aws_enum.py --company "examplecorp" --passive --bucket-wordlist wordlist.txt
"""

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    print("[!] Modul 'requests' tidak ditemukan. Install: pip install requests")
    sys.exit(1)

BOTO3_AVAILABLE = False
try:
    import boto3
    BOTO3_AVAILABLE = True
except ImportError:
    pass

BUCKET_PATTERNS = [
    "{company}", "{company}-prod", "{company}-dev", "{company}-staging",
    "{company}-test", "{company}-backup", "{company}-logs", "{company}-data",
    "{company}-assets", "{company}-static", "{company}-media", "{company}-cdn",
    "{company}-files", "{company}-images", "{company}-upload", "{company}-public",
    "{company}-private", "{company}-config", "{company}-terraform",
    "{company}-cloudformation", "{company}-artifacts", "{company}-build",
    "{company}-release", "{company}-db-backup", "{company}-db-backups",
    "{company}-www", "{company}-web", "{company}-app", "{company}-api",
    "prod-{company}", "dev-{company}", "staging-{company}",
]

REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-central-2",
    "ap-southeast-1", "ap-southeast-2", "ap-southeast-3",
    "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
    "ap-south-1", "ap-south-2", "sa-east-1",
    "ca-central-1", "me-south-1", "me-central-1",
    "af-south-1", "il-central-1",
]


def check_s3_bucket(bucket_name, timeout=5):
    """Check if an S3 bucket exists and determine its access level."""
    result = {"name": bucket_name, "exists": False, "public": False, "region": None}
    url = f"https://{bucket_name}.s3.amazonaws.com"
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=False)
        result["exists"] = True
        result["region"] = resp.headers.get("x-amz-bucket-region", "us-east-1")
        if resp.status_code in (200, 403):
            try:
                pub = requests.get(
                    f"https://{bucket_name}.s3.amazonaws.com/?acl",
                    timeout=timeout,
                )
                result["public"] = pub.status_code == 200
            except requests.exceptions.RequestException:
                pass
        elif resp.status_code == 404:
            result["exists"] = False
    except requests.exceptions.RequestException:
        pass

    if not result["exists"]:
        for region in REGIONS[:5]:
            try:
                url2 = f"https://{bucket_name}.s3.{region}.amazonaws.com"
                resp2 = requests.get(url2, timeout=timeout, allow_redirects=False)
                if resp2.status_code != 404:
                    result["exists"] = True
                    result["region"] = region
                    if resp2.status_code == 200:
                        result["public"] = True
                    break
            except requests.exceptions.RequestException:
                pass
    return result


def check_cloudfront(company, timeout=5):
    """Check for common CloudFront distribution patterns."""
    results = []
    patterns = [
        f"d123456.cloudfront.net",
        f"{company}.cloudfront.net",
    ]
    for pattern in patterns:
        try:
            resp = requests.head(f"https://{pattern}", timeout=timeout, allow_redirects=True)
            if resp.status_code < 500:
                results.append({"domain": pattern, "status": resp.status_code})
        except requests.exceptions.RequestException:
            pass
    return results


def passive_enum(company, wordlist=None, threads=10):
    """Run passive AWS enumeration (no credentials)."""
    print(f"[*] Enumerasi pasif AWS untuk: {company}")
    print(f"[*] Menjalankan dengan {threads} thread\n")

    if wordlist:
        try:
            with open(wordlist, "r") as f:
                prefixes = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] File wordlist tidak ditemukan: {wordlist}")
            sys.exit(1)
        patterns = []
        for p in prefixes:
            patterns.append(f"{p}-{company}")
            patterns.append(f"{company}-{p}")
    else:
        patterns = [p.format(company=company) for p in BUCKET_PATTERNS]

    patterns = list(dict.fromkeys(patterns))
    print(f"[*] Menguji {len(patterns)} pola bucket S3...\n")

    found = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_s3_bucket, b): b for b in patterns}
        for i, future in enumerate(as_completed(futures), 1):
            res = future.result()
            if res["exists"]:
                found.append(res)
                pfx = "[+]" if res["public"] else "[*]"
                akses = "PUBLIK" if res["public"] else "pribadi"
                print(f"  {pfx} s3://{res['name']} ({akses}, region: {res['region'] or '?'})")
            if i % 50 == 0:
                print(f"    ... {i}/{len(patterns)} diproses")

    print(f"\n[*] Menemukan {len(found)} bucket S3 ({sum(1 for b in found if b['public'])} publik)")

    print("\n[*] Memeriksa CloudFront...")
    cf_results = check_cloudfront(company)
    if cf_results:
        print(f"[+] Menemukan {len(cf_results)} distribusi CloudFront:")
        for r in cf_results:
            print(f"  [*] https://{r['domain']} (HTTP {r['status']})")
    else:
        print("[-] Tidak menemukan distribusi CloudFront yang umum")

    return {"buckets": found, "cloudfront": cf_results}


def active_enum_s3(session, region="us-east-1"):
    """Enumerate S3 buckets using boto3."""
    print(f"\n--- Enumerasi S3 ({region}) ---")
    try:
        s3 = session.client("s3", region_name=region)
        buckets = s3.list_buckets()
        print(f"[+] Total bucket: {len(buckets['Buckets'])}")
        for b in buckets["Buckets"]:
            name = b["Name"]
            try:
                acl = s3.get_bucket_acl(Bucket=name)
                public = any(
                    g.get("URI") in (
                        "http://acs.amazonaws.com/groups/global/AllUsers",
                        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                    )
                    for g in acl["Grants"]
                )
                versioning = s3.get_bucket_versioning(Bucket=name)
                encrypted = True
                try:
                    s3.get_bucket_encryption(Bucket=name)
                except Exception:
                    encrypted = False
                pfx = "[!]" if public else "[+]"
                v_status = "Ya" if versioning.get("Status") else "Tidak"
                print(f"  {pfx} {name} (public={public}, versioning={v_status}, encrypted={encrypted})")
            except Exception as e:
                print(f"  [*] {name} (tidak bisa membaca ACL: {e})")
    except Exception as e:
        print(f"[!] Gagal enumerasi S3: {e}")


def active_enum_iam(session):
    """Enumerate IAM users, roles, and policies using boto3."""
    print("\n--- Enumerasi IAM ---")
    try:
        iam = session.client("iam")
        users = iam.list_users()
        print(f"\n[+] IAM Users: {len(users['Users'])}")
        for u in users["Users"]:
            has_mfa = False
            try:
                mfa = iam.list_mfa_devices(UserName=u["UserName"])
                has_mfa = len(mfa["MFADevices"]) > 0
            except Exception:
                pass
            pfx = "[+]" if has_mfa else "[!]"
            print(f"  {pfx} {u['UserName']} (MFA={'Ya' if has_mfa else 'Tidak'})")

        roles = iam.list_roles()
        print(f"\n[+] IAM Roles: {len(roles['Roles'])}")
        for r in roles["Roles"]:
            admin = False
            try:
                attached = iam.list_attached_role_policies(RoleName=r["RoleName"])
                admin = any("AdministratorAccess" in p["PolicyName"] for p in attached["AttachedPolicies"])
            except Exception:
                pass
            pfx = "[!]" if admin else "[*]"
            print(f"  {pfx} {r['RoleName']} (admin={admin})")

        policies = iam.list_policies(Scope="Local")
        print(f"\n[*] IAM Policies (custom): {len(policies['Policies'])}")
        for p in list(policies["Policies"])[:20]:
            print(f"  [*] {p['PolicyName']}")
        if len(policies["Policies"]) > 20:
            print(f"  ... dan {len(policies['Policies']) - 20} lainnya")
    except Exception as e:
        print(f"[!] Gagal enumerasi IAM: {e}")


def active_enum_ec2(session, region="us-east-1"):
    """Enumerate EC2 instances using boto3."""
    print(f"\n--- Enumerasi EC2 ({region}) ---")
    try:
        ec2 = session.client("ec2", region_name=region)
        instances = ec2.describe_instances()
        count = sum(len(r["Instances"]) for r in instances["Reservations"])
        print(f"[+] EC2 Instances: {count}")
        for res in instances["Reservations"]:
            for inst in res["Instances"]:
                name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), "N/A")
                pub_ip = inst.get("PublicIpAddress", "Tidak")
                sg = [g["GroupName"] for g in inst.get("SecurityGroups", [])]
                pfx = "[!]" if pub_ip != "Tidak" else "[*]"
                print(f"  {pfx} {name} ({inst['InstanceId']}) | {inst['State']['Name']} | public_ip={pub_ip} | SG={sg}")
    except Exception as e:
        print(f"[!] Gagal enumerasi EC2: {e}")


def active_enum_rds(session, region="us-east-1"):
    """Enumerate RDS databases using boto3."""
    print(f"\n--- Enumerasi RDS ({region}) ---")
    try:
        rds = session.client("rds", region_name=region)
        instances = rds.describe_db_instances()
        print(f"[+] RDS Instances: {len(instances['DBInstances'])}")
        for db in instances["DBInstances"]:
            pub = db.get("PubliclyAccessible", False)
            encrypted = db.get("StorageEncrypted", False)
            pfx = "[!]" if pub else "[+]"
            print(f"  {pfx} {db['DBInstanceIdentifier']} ({db['Engine']} {db.get('EngineVersion','?')}) | public={pub} | encrypted={encrypted}")
    except Exception as e:
        print(f"[!] Gagal enumerasi RDS: {e}")


def active_enum_lambda(session, region="us-east-1"):
    """Enumerate Lambda functions using boto3."""
    print(f"\n--- Enumerasi Lambda ({region}) ---")
    try:
        lbd = session.client("lambda", region_name=region)
        functions = lbd.list_functions()
        print(f"[+] Lambda Functions: {len(functions['Functions'])}")
        for f in functions["Functions"]:
            vpc = "vpc" if f.get("VpcConfig", {}).get("VpcId") else "no-vpc"
            env_vars = list(f.get("Environment", {}).get("Variables", {}).keys())
            has_secrets = any("SECRET" in k.upper() or "PASSWORD" in k.upper() or "KEY" in k.upper() for k in env_vars)
            pfx = "[!]" if has_secrets else "[*]"
            print(f"  {pfx} {f['FunctionName']} ({f['Runtime']}) | {vpc} | env_has_secrets={has_secrets}")
    except Exception as e:
        print(f"[!] Gagal enumerasi Lambda: {e}")


def active_enum(session, service, region):
    """Run active enumeration with boto3 session."""
    print(f"[*] Enumerasi aktif AWS (service={service}, region={region})\n")
    services = {
        "s3": lambda s, r: active_enum_s3(s, r),
        "iam": lambda s, r: active_enum_iam(s),
        "ec2": lambda s, r: active_enum_ec2(s, r),
        "rds": lambda s, r: active_enum_rds(s, r),
        "lambda": lambda s, r: active_enum_lambda(s, r),
    }
    if service == "all":
        for svc_name, svc_fn in services.items():
            try:
                svc_fn(session, region)
            except Exception as e:
                print(f"[!] Gagal enumerasi {svc_name}: {e}")
    elif service in services:
        services[service](session, region)
    else:
        print(f"[!] Service '{service}' tidak dikenal. Pilihan: {', '.join(services.keys())}, all")


def main():
    parser = argparse.ArgumentParser(
        description="AWS Enumeration Tool — Reconnaissance pasif & aktif",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  python aws_enum.py --company "examplecorp" --passive
  python aws_enum.py --profile "default" --service all
  python aws_enum.py --access-key AKIAxxx --secret-key xxx --service s3
  python aws_enum.py --company "examplecorp" --passive --bucket-wordlist buckets.txt
  python aws_enum.py --company "examplecorp" --passive --output results.json
        """,
    )
    parser.add_argument("--company", help="Nama perusahaan untuk enumerasi pasif")
    parser.add_argument("--passive", action="store_true", help="Mode enumerasi pasif (tanpa kredensial)")
    parser.add_argument("--profile", help="AWS profile (dari ~/.aws/credentials)")
    parser.add_argument("--access-key", help="AWS Access Key ID")
    parser.add_argument("--secret-key", help="AWS Secret Access Key")
    parser.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    parser.add_argument("--service", default="all", help="Service untuk enumerasi: s3|iam|ec2|rds|lambda|all")
    parser.add_argument("--bucket-wordlist", help="Wordlist untuk fuzzing nama bucket")
    parser.add_argument("--threads", type=int, default=10, help="Jumlah thread konkuren (default: 10)")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout HTTP (detik, default: 5)")
    parser.add_argument("--output", help="Simpan hasil ke file JSON")
    args = parser.parse_args()

    results = {}

    if args.passive:
        if not args.company:
            print("[!] --company diperlukan untuk mode pasif")
            sys.exit(1)
        results = passive_enum(args.company, args.bucket_wordlist, args.threads)
    else:
        if not BOTO3_AVAILABLE:
            print("[!] Modul 'boto3' tidak ditemukan. Install: pip install boto3")
            print("[*] Gunakan mode pasif dengan --passive --company NAMA")
            sys.exit(1)

        if args.profile:
            session = boto3.Session(profile_name=args.profile, region_name=args.region)
            print(f"[*] Menggunakan AWS profile: {args.profile}")
        elif args.access_key and args.secret_key:
            session = boto3.Session(
                aws_access_key_id=args.access_key,
                aws_secret_access_key=args.secret_key,
                region_name=args.region,
            )
            print(f"[*] Menggunakan access key: {args.access_key[:8]}...")
        else:
            session = boto3.Session(region_name=args.region)
            print("[*] Menggunakan kredensial default boto3")

        try:
            sts = session.client("sts")
            identity = sts.get_caller_identity()
            print(f"[+] Authenticated: {identity['Arn']}\n")
        except Exception as e:
            print(f"[!] Gagal autentikasi: {e}")
            sys.exit(1)

        results = {"identity": identity["Arn"]}
        active_enum(session, args.service, args.region)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n[+] Hasil disimpan ke: {args.output}")

    print("\n[*] Selesai.")


if __name__ == "__main__":
    main()
