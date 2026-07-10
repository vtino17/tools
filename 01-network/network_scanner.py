#!/usr/bin/env python3
"""
Network Scanner - ARP-based host discovery
Pemindai jaringan untuk menemukan host aktif dalam subnet.
Usage: python network_scanner.py -t 192.168.1.0/24
"""
import scapy.all as scapy
import argparse
import sys
import ipaddress


def scan_network(target):
    try:
        arp_request = scapy.ARP(pdst=target)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

        clients = []
        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            clients.append(client_dict)
        return clients
    except PermissionError:
        print("[!] Butuh akses admin/root untuk raw sockets")
        return []
    except Exception as e:
        print(f"[!] Error: {e}")
        return []


def display(clients):
    print("\n" + "=" * 60)
    print(f"{'IP Address':<20}{'MAC Address':<20}")
    print("=" * 60)
    for client in clients:
        print(f"{client['ip']:<20}{client['mac']:<20}")
    print("=" * 60)
    print(f"[+] Total host aktif: {len(clients)}")


def main():
    parser = argparse.ArgumentParser(description="Network Host Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target subnet (e.g. 192.168.1.0/24)")
    args = parser.parse_args()

    try:
        ipaddress.ip_network(args.target, strict=False)
    except ValueError:
        print(f"[!] Target tidak valid: {args.target}")
        sys.exit(1)

    print(f"[*] Scanning network: {args.target}")
    clients = scan_network(args.target)
    display(clients)


if __name__ == "__main__":
    main()

