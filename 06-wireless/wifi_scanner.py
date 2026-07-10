#!/usr/bin/env python3
"""
WiFi Scanner - Scan wireless networks (Linux only, requires root)
Menggunakan scapy untuk scan WiFi networks dan client probing.
Usage: sudo python wifi_scanner.py -i wlan0
"""

import argparse
import sys
import time


def check_root():
    import os

    if os.name != "posix" or os.geteuid() != 0:
        print("[!] WiFi scanning requires root privileges on Linux")
        print("[!] Run with: sudo python wifi_scanner.py")
        return False
    return True


def scan_wireless(interface, duration=30):
    """Scan for wireless networks using scapy"""
    try:
        from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Elt
    except ImportError:
        print("[!] scapy not installed. Run: pip install scapy")
        return

    networks = {}
    clients = set()

    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            ssid = ""
            rssi = -100
            try:
                ssid = pkt[Dot11Elt].info.decode("utf-8", errors="ignore")
            except:
                pass
            try:
                rssi = pkt.dBm_AntSignal
            except:
                pass
            bssid = pkt[Dot11].addr2
            if bssid not in networks:
                networks[bssid] = {
                    "ssid": ssid or "<hidden>",
                    "rssi": rssi,
                    "channel": freq_to_channel(pkt[Dot11Beacon].network_stats().get("channel", 0)),
                }
        elif pkt.haslayer(Dot11ProbeReq):
            client = pkt[Dot11].addr2
            if client:
                clients.add(client)

    def freq_to_channel(freq):
        if freq == 0:
            return 0
        return (freq - 2407) // 5

    print(f"[*] Scanning on {interface} for {duration} seconds...")
    try:
        sniff(iface=interface, prn=packet_handler, timeout=duration, store=False)
    except KeyboardInterrupt:
        pass

    print(f"\n[+] Found {len(networks)} networks:")
    print("-" * 70)
    print(f"{'BSSID':<20}{'SSID':<35}{'Signal':<10}{'Channel'}")
    print("-" * 70)
    for bssid, info in sorted(networks.items(), key=lambda x: x[1]["rssi"], reverse=True):
        print(f"{bssid:<20}{info['ssid'][:33]:<35}{info['rssi']} dBm{'':<3}{info['channel']}")

    print(f"\n[+] Probing clients: {len(clients)}")
    for c in list(clients)[:20]:
        print(f"    {c}")


def main():
    parser = argparse.ArgumentParser(description="WiFi Network Scanner")
    parser.add_argument("-i", "--interface", help="Wireless interface (e.g. wlan0)")
    parser.add_argument("-d", "--duration", type=int, default=30, help="Scan duration in seconds")
    args = parser.parse_args()

    if not check_root():
        return

    if not args.interface:
        print("[*] Available interfaces:")
        try:
            from scapy.all import get_if_list

            for iface in get_if_list():
                print(f"    {iface}")
        except:
            pass
        sys.exit(1)

    scan_wireless(args.interface, args.duration)


if __name__ == "__main__":
    main()
