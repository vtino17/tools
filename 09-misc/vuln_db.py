#!/usr/bin/env python3
"""
Vulnerability Database Lookup - Local CVE/CWE database
Database lokal untuk lookup vulnerability.
Usage: python vuln_db.py -s Apache -v 2.4.49
"""
import argparse
import sys
import json


LOCAL_VULN_DB = {
    "Apache 2.4.49": {
        "cve": "CVE-2021-41773",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Path traversal and remote code execution flaw",
        "type": "Path Traversal, RCE",
    },
    "Apache 2.4.50": {
        "cve": "CVE-2021-42013",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Path traversal and remote code execution",
        "type": "Path Traversal, RCE",
    },
    "Log4j": {
        "cve": "CVE-2021-44228",
        "cvss": 10.0,
        "severity": "Critical",
        "description": "Remote code execution via JNDI lookup",
        "type": "RCE",
    },
    "OpenSSL 1.0.1": {
        "cve": "CVE-2014-0160",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Heartbleed - information disclosure",
        "type": "Information Disclosure",
    },
    "WordPress 5.0": {
        "cve": "CVE-2019-8942",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Remote code execution via image metadata",
        "type": "RCE",
    },
    "Drupal 7": {
        "cve": "CVE-2018-7600",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Drupalgeddon - remote code execution",
        "type": "RCE",
    },
    "Shellshock": {
        "cve": "CVE-2014-6271",
        "cvss": 10.0,
        "severity": "Critical",
        "description": "Bash remote code execution",
        "type": "RCE",
    },
    "EternalBlue": {
        "cve": "CVE-2017-0144",
        "cvss": 8.1,
        "severity": "High",
        "description": "SMB remote code execution",
        "type": "RCE",
    },
    "BlueKeep": {
        "cve": "CVE-2019-0708",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Windows RDP remote code execution",
        "type": "RCE",
    },
    "ProxyLogon": {
        "cve": "CVE-2021-26855",
        "cvss": 10.0,
        "severity": "Critical",
        "description": "Microsoft Exchange Server SSRF",
        "type": "SSRF, RCE",
    },
    "Spring4Shell": {
        "cve": "CVE-2022-22965",
        "cvss": 9.8,
        "severity": "Critical",
        "description": "Spring framework RCE",
        "type": "RCE",
    },
}


def search_db(query):
    """Search local database"""
    results = []
    query_lower = query.lower()
    for key, vuln in LOCAL_VULN_DB.items():
        if query_lower in key.lower() or query_lower in vuln.get("cve", "").lower():
            results.append({"name": key, **vuln})
    return results


def get_by_cve(cve_id):
    """Get vuln by CVE ID"""
    for key, vuln in LOCAL_VULN_DB.items():
        if vuln.get("cve", "").upper() == cve_id.upper():
            return {"name": key, **vuln}
    return None


def main():
    parser = argparse.ArgumentParser(description="Local Vulnerability Database")
    parser.add_argument("-s", "--search", help="Search by software name")
    parser.add_argument("-c", "--cve", help="Search by CVE ID")
    parser.add_argument("-l", "--list", action="store_true", help="List all")
    args = parser.parse_args()

    print("=" * 70)
    print("LOCAL VULNERABILITY DATABASE")
    print("=" * 70)

    if args.list:
        for key, vuln in LOCAL_VULN_DB.items():
            print(f"\n  [{vuln.get('severity', 'N/A'):<8}] {key}")
            print(f"    CVE: {vuln.get('cve')}")
            print(f"    CVSS: {vuln.get('cvss')}")
            print(f"    Type: {vuln.get('type')}")
            print(f"    {vuln.get('description')}")
        return

    if args.cve:
        vuln = get_by_cve(args.cve)
        if vuln:
            print(f"\n[+] Found: {vuln['name']}")
            print(f"    CVE: {vuln.get('cve')}")
            print(f"    CVSS: {vuln.get('cvss')} ({vuln.get('severity')})")
            print(f"    Type: {vuln.get('type')}")
            print(f"    Description: {vuln.get('description')}")
        else:
            print(f"[!] CVE {args.cve} not found in local DB")
            print(f"[*] Try: https://nvd.nist.gov/vuln/detail/{args.cve}")
        return

    if args.search:
        results = search_db(args.search)
        if results:
            for vuln in results:
                print(f"\n[+] {vuln['name']}")
                print(f"    CVE: {vuln.get('cve')}")
                print(f"    CVSS: {vuln.get('cvss')} ({vuln.get('severity')})")
                print(f"    Type: {vuln.get('type')}")
                print(f"    {vuln.get('description')}")
        else:
            print(f"[-] No results for: {args.search}")
            print("[*] Try online: https://nvd.nist.gov")
        return

    parser.print_help()


if __name__ == "__main__":
    main()

