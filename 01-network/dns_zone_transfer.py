#!/usr/bin/env python3
"""
DNS Zone Transfer (AXFR) Tester & Subdomain Brute-force Tool.

Melakukan pengujian zone transfer AXFR pada nameserver domain target.
Jika zone transfer gagal, fallback ke brute-force enumerasi subdomain
menggunakan wordlist bawaan dan reverse DNS lookup.

Usage:
    python dns_zone_transfer.py --domain example.com
    python dns_zone_transfer.py --domain example.com --nameserver ns1.example.com
    python dns_zone_transfer.py --domain example.com --wordlist subdomains.txt
"""

import argparse
import socket
import sys
from collections import defaultdict

try:
    import dns.resolver
    import dns.query
    import dns.zone
    import dns.rdatatype
    import dns.reversename
    import dns.exception
except ImportError:
    print("[!] Modul 'dnspython' tidak ditemukan.")
    print("[!] Install dengan: pip install dnspython")
    sys.exit(1)

DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "admin", "dev", "test", "staging",
    "webmail", "remote", "blog", "shop", "api", "cdn", "m",
    "mobile", "portal", "vpn", "ns1", "ns2", "dns", "dns1",
    "dns2", "smtp", "pop", "pop3", "imap", "ldap", "mysql",
    "db", "sql", "oracle", "secure", "ssl", "auth", "login",
    "gateway", "proxy", "firewall", "monitor", "status", "uptime",
    "wiki", "docs", "support", "help", "apps", "cloud", "files",
    "backup", "intranet",
]


def log_info(msg: str) -> None:
    print(f"[*] {msg}")


def log_success(msg: str) -> None:
    print(f"[+] {msg}")


def log_error(msg: str) -> None:
    print(f"[!] {msg}")


def get_nameservers(domain: str) -> list[str]:
    log_info(f"Mencari nameserver untuk domain: {domain}")
    try:
        answers = dns.resolver.resolve(domain, "NS")
        ns_list = sorted(str(r.target).rstrip(".") for r in answers)
        log_success(f"Ditemukan {len(ns_list)} nameserver: {', '.join(ns_list)}")
        return ns_list
    except dns.exception.DNSException as e:
        log_error(f"Gagal mengambil NS record: {e}")
        return []


def resolve_nameserver_ips(ns_list: list[str]) -> list[tuple[str, str]]:
    results = []
    for ns in ns_list:
        try:
            answers = dns.resolver.resolve(ns, "A")
            for r in answers:
                results.append((ns, str(r.address)))
                log_info(f"  {ns} -> {r.address}")
        except dns.exception.DNSException:
            log_error(f"  Gagal resolve IP untuk {ns}")
    return results


def attempt_zone_transfer(domain: str, ns_ip: str, ns_name: str) -> dict[str, list[str]] | None:
    log_info(f"Mencoba zone transfer dari {ns_name} ({ns_ip})...")
    try:
        xfr = dns.query.xfr(ns_ip, domain, timeout=10)
        zone = dns.zone.from_xfr(xfr)
        if zone is None:
            log_error(f"  Zone transfer gagal (None response)")
            return None

        records: dict[str, list[str]] = defaultdict(list)
        for name, node in zone.nodes.items():
            for rdset in node.rdatasets:
                rtype = dns.rdatatype.to_text(rdset.rdtype)
                for rdata in rdset:
                    records[rtype].append(f"{name} -> {rdata}")

        log_success(f"  Zone transfer BERHASIL! {sum(len(v) for v in records.values())} record ditemukan.")
        return dict(records)
    except dns.exception.DNSException as e:
        log_error(f"  Zone transfer gagal: {e}")
        return None
    except Exception as e:
        log_error(f"  Zone transfer gagal (exception): {e}")
        return None


def brute_force_subdomains(domain: str, wordlist: list[str]) -> dict[str, list[str]]:
    log_info(f"Memulai brute-force subdomain ({len(wordlist)} kata)...")
    records: dict[str, list[str]] = defaultdict(list)
    count = 0

    for sub in wordlist:
        fqdn = f"{sub}.{domain}"
        try:
            answers = dns.resolver.resolve(fqdn, "A", lifetime=2)
            for r in answers:
                records["A"].append(f"{fqdn} -> {r.address}")
                count += 1
        except dns.exception.DNSException:
            pass

    if count > 0:
        log_success(f"Ditemukan {count} subdomain via brute-force")
    else:
        log_info("Tidak ada subdomain ditemukan via brute-force")
    return dict(records)


def reverse_dns_lookup(domain: str) -> dict[str, list[str]]:
    log_info("Melakukan reverse DNS lookup untuk pola umum...")
    records: dict[str, list[str]] = defaultdict(list)

    prefixes = ["mail", "www", "ftp", "smtp", "pop", "imap", "ns1", "ns2", "mx"]
    for prefix in prefixes:
        fqdn = f"{prefix}.{domain}"
        try:
            answers = dns.resolver.resolve(fqdn, "A", lifetime=2)
            for r in answers:
                try:
                    rev_name = dns.reversename.from_address(str(r.address))
                    ptr = dns.resolver.resolve(rev_name, "PTR", lifetime=2)
                    for p in ptr:
                        records["PTR"].append(f"{r.address} -> {p.target}")
                except dns.exception.DNSException:
                    records["PTR"].append(f"{r.address} -> (no PTR)")
        except dns.exception.DNSException:
            pass

    if records:
        log_success(f"Reverse DNS: {sum(len(v) for v in records.values())} record ditemukan")
    return dict(records)


def get_standard_records(domain: str) -> dict[str, list[str]]:
    log_info("Mengambil record DNS standar (A, MX, NS, TXT, SOA, CNAME)...")
    records: dict[str, list[str]] = defaultdict(list)
    rtypes = ["A", "MX", "NS", "TXT", "SOA", "CNAME"]

    for rtype in rtypes:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=3)
            for r in answers:
                records[rtype].append(str(r))
        except dns.exception.DNSException:
            records[rtype].append("(tidak ditemukan)")

    return dict(records)


def display_records(records: dict[str, list[str]], title: str = "Hasil") -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")
    if not records:
        print("  (tidak ada record)")
        return

    for rtype in ["A", "AAAA", "MX", "CNAME", "NS", "SOA", "TXT", "PTR", "SRV", "HINFO"]:
        if rtype not in records:
            continue
        print(f"\n  [{rtype}]")
        for entry in records[rtype]:
            print(f"    {entry}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="DNS Zone Transfer Tester & Subdomain Brute-force",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  %(prog)s --domain example.com
  %(prog)s --domain example.com --nameserver ns1.example.com
  %(prog)s --domain example.com --wordlist wordlist.txt
        """,
    )
    parser.add_argument("--domain", "-d", required=True, help="Domain target")
    parser.add_argument("--nameserver", "-n", help="Nameserver spesifik (auto-discover jika kosong)")
    parser.add_argument("--wordlist", "-w", help="File wordlist subdomain (opsional)")
    parser.add_argument("--no-brute", action="store_true", help="Lewati brute-force subdomain")
    parser.add_argument("--no-reverse", action="store_true", help="Lewati reverse DNS lookup")
    args = parser.parse_args()

    domain = args.domain.strip(".").lower()
    all_records: dict[str, list[str]] = defaultdict(list)

    if args.nameserver:
        ns_list = [args.nameserver]
    else:
        ns_list = get_nameservers(domain)

    if not ns_list:
        log_error("Tidak dapat menemukan nameserver. Pastikan domain valid.")
        sys.exit(1)

    ns_with_ips = resolve_nameserver_ips(ns_list)

    zone_transferred = False
    if ns_with_ips:
        for ns_name, ns_ip in ns_with_ips:
            zone_records = attempt_zone_transfer(domain, ns_ip, ns_name)
            if zone_records:
                for rtype, entries in zone_records.items():
                    all_records[rtype].extend(entries)
                zone_transferred = True
                break

    if not zone_transferred:
        log_info("Zone transfer gagal. Jatuh ke metode fallback.")

    standard = get_standard_records(domain)
    for rtype, entries in standard.items():
        if rtype not in all_records or all_records[rtype] == ["(tidak ditemukan)"]:
            all_records[rtype] = entries

    if not zone_transferred and not args.no_brute:
        wordlist = DEFAULT_WORDLIST
        if args.wordlist:
            try:
                with open(args.wordlist, encoding="utf-8") as f:
                    wordlist = [line.strip() for line in f if line.strip()]
                log_info(f"Loaded {len(wordlist)} subdomain dari {args.wordlist}")
            except FileNotFoundError:
                log_error(f"File wordlist tidak ditemukan: {args.wordlist}")

        bruted = brute_force_subdomains(domain, wordlist)
        for rtype, entries in bruted.items():
            all_records[rtype].extend(entries)

    if not args.no_reverse:
        rev_records = reverse_dns_lookup(domain)
        for rtype, entries in rev_records.items():
            all_records[rtype].extend(entries)

    display_records(dict(all_records), f"Hasil Enumerasi DNS: {domain}")

    discovered = [
        e for rtype in ["A", "AAAA", "MX", "CNAME", "NS", "SOA", "TXT", "PTR"]
        for e in all_records.get(rtype, [])
        if e not in ("(tidak ditemukan)",)
    ]
    print(f"\n[+] Total record ditemukan: {len(discovered)}")


if __name__ == "__main__":
    main()
