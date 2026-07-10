#!/usr/bin/env python3
"""
OSINT Tool - Multi-source Open Source Intelligence gathering
Mengumpulkan informasi dari berbagai sumber publik.
Usage: python osint_tool.py -t target.com
"""
import socket
import requests
import argparse
import sys
import re
import json
from urllib.parse import urlparse


def whois_lookup(domain):
    """Simple whois lookup"""
    try:
        r = requests.get(f"https://www.whoisxmlapi.com/whoisserver/WhoisService",
                         params={"domainName": domain, "outputFormat": "JSON"},
                         timeout=10)
    except:
        pass
    return None


def dns_records(domain):
    """Get DNS records"""
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
    results = {}
    for rtype in record_types:
        try:
            import subprocess
            result = subprocess.run(
                ["nslookup", "-type=" + rtype, domain],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                results[rtype] = result.stdout
        except:
            pass
    return results


def get_ip_info(ip):
    """Get IP geolocation info"""
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return None


def get_http_headers(url):
    """Get HTTP headers"""
    try:
        r = requests.head(url, timeout=10, allow_redirects=True, verify=False)
        return dict(r.headers)
    except:
        return None


def extract_emails(text):
    """Extract email addresses from text"""
    return list(set(re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text)))


def extract_links(html):
    """Extract all links from HTML"""
    return list(set(re.findall(r'href=["\']?([^"\'\s<>]+)', html, re.IGNORECASE)))


def shodan_search(api_key, query):
    """Search Shodan (requires API key)"""
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/search",
                         params={"key": api_key, "query": query}, timeout=15)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return None


def virustotal_report(api_key, target):
    """Get VirusTotal report"""
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/{target}",
                         headers={"x-apikey": api_key}, timeout=15)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return None


def wayback_lookup(domain):
    """Get historical data from Wayback Machine"""
    try:
        r = requests.get(f"http://web.archive.org/cdx/search/cdx",
                         params={"url": domain + "/*", "output": "json", "limit": 20},
                         timeout=15)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return None


def main():
    parser = argparse.ArgumentParser(description="OSINT Gathering Tool")
    parser.add_argument("-t", "--target", required=True, help="Target domain/IP/URL")
    parser.add_argument("--shodan-key", help="Shodan API key")
    parser.add_argument("--vt-key", help="VirusTotal API key")
    args = parser.parse_args()

    target = args.target
    print(f"[*] OSINT Target: {target}")
    print("=" * 70)

    # Determine type
    is_ip = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target)
    is_url = target.startswith("http")

    if is_url:
        parsed = urlparse(target)
        domain = parsed.netloc
    elif is_ip:
        domain = None
    else:
        domain = target

    # IP Resolution
    if domain:
        try:
            ip = socket.gethostbyname(domain)
            print(f"[+] IP Address: {ip}")
        except:
            ip = None
            print(f"[!] Cannot resolve {domain}")
    else:
        ip = target

    # IP Geolocation
    if ip:
        print(f"\n[*] IP Geolocation:")
        info = get_ip_info(ip)
        if info:
            if info.get("status") == "success":
                print(f"    Country: {info.get('country')}")
                print(f"    Region: {info.get('regionName')}")
                print(f"    City: {info.get('city')}")
                print(f"    ISP: {info.get('isp')}")
                print(f"    Org: {info.get('org')}")
                print(f"    Lat/Lon: {info.get('lat')}, {info.get('lon')}")
                print(f"    Timezone: {info.get('timezone')}")

    # HTTP Headers
    url_to_check = target if is_url else f"http://{target}"
    print(f"\n[*] HTTP Headers ({url_to_check}):")
    headers = get_http_headers(url_to_check)
    if headers:
        for k, v in headers.items():
            print(f"    {k}: {v}")

    # Wayback Machine
    if domain:
        print(f"\n[*] Wayback Machine (historical data):")
        wb = wayback_lookup(domain)
        if wb and len(wb) > 1:
            for entry in wb[1:6]:
                timestamp = entry[1]
                original = entry[2]
                print(f"    [{timestamp}] {original}")
                print(f"             https://web.archive.org/web/{timestamp}/{original}")

    # Shodan
    if args.shodan_key and domain:
        print(f"\n[*] Shodan Search:")
        shodan = shodan_search(args.shodan_key, f"hostname:{domain}")
        if shodan and "matches" in shodan:
            print(f"    Found {shodan.get('total', 0)} matches")
            for m in shodan["matches"][:5]:
                print(f"    - {m.get('ip_str')}:{m.get('port')} - {m.get('product', 'unknown')}")

    print("=" * 70)
    print("[*] OSINT gathering complete")


if __name__ == "__main__":
    main()

