#!/usr/bin/env python3
"""
Subdomain Enumerator - DNS-based subdomain discovery
Enumerasi subdomain menggunakan wordlist + DNS resolution.
Usage: python subdomain_enum.py -d example.com -w subdomains.txt
"""

import socket
import argparse
import concurrent.futures
import sys

DEFAULT_WORDLIST = [
    "www",
    "mail",
    "ftp",
    "smtp",
    "pop",
    "pop3",
    "imap",
    "webmail",
    "email",
    "cpanel",
    "whm",
    "autodiscover",
    "autoconfig",
    "ns",
    "ns1",
    "ns2",
    "ns3",
    "ns4",
    "dns",
    "dns1",
    "dns2",
    "mx",
    "mx1",
    "mx2",
    "blog",
    "dev",
    "demo",
    "test",
    "staging",
    "stage",
    "pre",
    "preview",
    "api",
    "api2",
    "api3",
    "v1",
    "v2",
    "cdn",
    "cloud",
    "app",
    "apps",
    "admin",
    "administrator",
    "panel",
    "dashboard",
    "portal",
    "cms",
    "wp",
    "wordpress",
    "joomla",
    "drupal",
    "magento",
    "shop",
    "store",
    "secure",
    "ssl",
    "vpn",
    "remote",
    "gw",
    "gateway",
    "proxy",
    "lb",
    "backup",
    "bak",
    "old",
    "new",
    "beta",
    "alpha",
    "git",
    "gitlab",
    "github",
    "bitbucket",
    "svn",
    "jenkins",
    "ci",
    "cd",
    "build",
    "jenkins",
    "jira",
    "confluence",
    "wiki",
    "kb",
    "help",
    "support",
    "docs",
    "dev1",
    "dev2",
    "qa",
    "uat",
    "prod",
    "production",
    "sandbox",
    "lab",
    "m",
    "mobile",
    "wap",
    "web",
    "www2",
    "ww1",
    "home",
    "intranet",
    "internal",
    "private",
    "corp",
    "corporate",
    "main",
    "www1",
    "cms1",
    "db",
    "database",
    "mysql",
    "postgres",
    "mongo",
    "redis",
    "elastic",
    "ldap",
    "auth",
    "sso",
    "login",
    "account",
    "accounts",
    "user",
    "users",
    "files",
    "file",
    "share",
    "shared",
    "download",
    "downloads",
    "upload",
    "img",
    "images",
    "image",
    "static",
    "assets",
    "media",
    "video",
    "videos",
    "crm",
    "erp",
    "hr",
    "finance",
    "sales",
    "marketing",
    "ops",
    "monitor",
    "nagios",
    "zabbix",
    "grafana",
    "prometheus",
    "kibana",
    "log",
    "logs",
    "logstash",
    "fluentd",
    "splunk",
    "stg",
    "preprod",
    "demo1",
    "test1",
    "qa1",
    "uat1",
    "sandbox1",
    "staging1",
    "stage1",
    "pre1",
    "preview1",
    "demo2",
    "test2",
    "qa2",
]


def resolve_subdomain(subdomain, domain):
    full_domain = f"{subdomain}.{domain}"
    try:
        ip = socket.gethostbyname(full_domain)
        return (full_domain, ip)
    except (socket.gaierror, socket.error):
        return None


def load_wordlist(file_path):
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        return []


def main():
    parser = argparse.ArgumentParser(description="Subdomain Enumerator")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-w", "--wordlist", help="Wordlist file path")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Thread count")
    args = parser.parse_args()

    if args.wordlist:
        wordlist = load_wordlist(args.wordlist)
        if not wordlist:
            print(f"[!] Wordlist kosong, menggunakan default")
            wordlist = DEFAULT_WORDLIST
    else:
        print("[*] Tidak ada wordlist, menggunakan default")
        wordlist = DEFAULT_WORDLIST

    print(f"[*] Target domain: {args.domain}")
    print(f"[*] Wordlist size: {len(wordlist)}")
    print(f"[*] Threads: {args.threads}")
    print("-" * 60)

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_sub = {
            executor.submit(resolve_subdomain, sub, args.domain): sub for sub in wordlist
        }
        for future in concurrent.futures.as_completed(future_to_sub):
            result = future.result()
            if result:
                found.append(result)
                print(f"[+] {result[0]:<40} -> {result[1]}")

    print("-" * 60)
    print(f"[+] Selesai. {len(found)} subdomain ditemukan.")


if __name__ == "__main__":
    main()
