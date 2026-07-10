#!/usr/bin/env python3
"""
Network Discovery - Multi-protocol network discovery
Mendeteksi host dan layanan di jaringan.
Usage: python network_discovery.py -t 192.168.1.0/24
"""
import argparse
import sys
import socket
import ipaddress
import concurrent.futures
import time


def ping_host(ip, timeout=1):
    """Check if host is alive using TCP probe"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((str(ip), 80))
        sock.close()
        if result == 0:
            return True
    except:
        pass

    # Try other common ports
    for port in [22, 443, 8080, 3389, 445]:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((str(ip), port))
            sock.close()
            if result == 0:
                return True
        except:
            pass

    return False


def scan_ports_on_host(ip, ports, timeout=1):
    """Quick port scan on host"""
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((str(ip), port))
            sock.close()
            if result == 0:
                open_ports.append(port)
        except:
            pass
    return (ip, open_ports)


def discover_network(target, threads=50, scan_ports_flag=False, port_range=None):
    """Discover hosts in network"""
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as e:
        print(f"[!] Invalid target: {e}")
        return

    print(f"[*] Network: {network}")
    print(f"[*] Total hosts: {network.num_addresses}")
    if network.num_addresses > 1024:
        print("[!] WARNING: Large network, this may take a while")
    print("-" * 60)

    hosts = list(network.hosts())
    if network.num_addresses > 256:
        # Limit to first 256 for /24 networks
        hosts = hosts[:256]

    print(f"[*] Scanning {len(hosts)} hosts...")
    alive = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_ip = {executor.submit(ping_host, ip): ip for ip in hosts}
        completed = 0
        for future in concurrent.futures.as_completed(future_to_ip):
            completed += 1
            ip = future_to_ip[future]
            try:
                if future.result():
                    alive.append(ip)
                    print(f"[+] {ip} is UP")
            except:
                pass
            if completed % 10 == 0:
                print(f"[*] Progress: {completed}/{len(hosts)}", end="\r")

    print(f"\n[+] Found {len(alive)} alive hosts")
    print("=" * 60)

    if scan_ports_flag and alive:
        ports = port_range or [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080]
        print(f"\n[*] Scanning common ports on {len(alive)} hosts...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_ip = {executor.submit(scan_ports_on_host, ip, ports): ip for ip in alive}
            for future in concurrent.futures.as_completed(future_to_ip):
                ip, open_ports = future.result()
                if open_ports:
                    print(f"  {ip}: {open_ports}")


def main():
    parser = argparse.ArgumentParser(description="Network Discovery")
    parser.add_argument("-t", "--target", required=True, help="Target (e.g. 192.168.1.0/24 or single IP)")
    parser.add_argument("--threads", type=int, default=50, help="Thread count")
    parser.add_argument("--ports", action="store_true", help="Scan common ports on discovered hosts")
    parser.add_argument("-p", "--port-range", help="Comma-separated port list")
    args = parser.parse_args()

    port_range = None
    if args.port_range:
        port_range = [int(p) for p in args.port_range.split(",")]

    discover_network(args.target, args.threads, args.ports, port_range)


if __name__ == "__main__":
    main()

