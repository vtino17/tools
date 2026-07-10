#!/usr/bin/env python3
"""
Packet Sniffer - Network packet capture and analysis
Sniffing paket jaringan dengan filter dan save to PCAP.
Usage: sudo python packet_sniffer.py -i eth0 -f "tcp port 80" -c 100
"""

import argparse
import sys
import os
import time
from datetime import datetime


def check_root():
    if os.name == "posix" and os.geteuid() != 0:
        print("[!] Packet sniffing requires root privileges")
        return False
    if os.name == "nt":
        try:
            import ctypes

            if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                print("[!] Packet sniffing requires Administrator privileges on Windows")
                return False
        except:
            pass
    return True


def parse_pcap_path(output):
    if not output:
        return f"capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
    return output


def write_pcap_header(f):
    """Write PCAP file header"""
    f.write(b"\xd4\xc3\xb2\xa1")  # Magic number
    f.write(b"\x02\x00\x04\x00")  # Version 2.4
    f.write(b"\x00\x00\x00\x00")  # Timezone
    f.write(b"\x00\x00\x00\x00")  # Sigfigs
    f.write(b"\xff\xff\x00\x00")  # Snaplen
    f.write(b"\x01\x00\x00\x00")  # Network (Ethernet)


def write_pcap_packet(f, data):
    """Write packet to PCAP"""
    ts_sec = int(time.time())
    ts_usec = int((time.time() % 1) * 1000000)
    f.write(ts_sec.to_bytes(4, "little"))
    f.write(ts_usec.to_bytes(4, "little"))
    f.write(len(data).to_bytes(4, "little"))
    f.write(len(data).to_bytes(4, "little"))
    f.write(data)


def sniff_packets(interface, filter_str, count, output, show_payload=False, protocols_only=None):
    try:
        from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Ether
    except ImportError:
        print("[!] scapy not installed. Run: pip install scapy")
        return

    packets_captured = 0
    pcap_file = None

    if output:
        pcap_path = parse_pcap_path(output)
        pcap_file = open(pcap_path, "wb")
        write_pcap_header(pcap_file)
        print(f"[*] Saving to: {pcap_path}")

    protocol_count = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}

    def handle_packet(pkt):
        nonlocal packets_captured
        packets_captured += 1

        if pcap_file:
            try:
                write_pcap_packet(pcap_file, bytes(pkt))
            except:
                pass

        info = ""
        if pkt.haslayer(IP):
            ip = pkt[IP]
            src = ip.src
            dst = ip.dst
            proto = "Other"
            sport = ""
            dport = ""

            if pkt.haslayer(TCP):
                proto = "TCP"
                tcp = pkt[TCP]
                sport = tcp.sport
                dport = tcp.dport
            elif pkt.haslayer(UDP):
                proto = "UDP"
                udp = pkt[UDP]
                sport = udp.sport
                dport = udp.dport
            elif pkt.haslayer(ICMP):
                proto = "ICMP"

            protocol_count[proto] = protocol_count.get(proto, 0) + 1

            info = f"{src}:{sport}" if sport else src
            info += f" -> {dst}:{dport}" if dport else f" -> {dst}"
            info += f" [{proto}]"

            if show_payload and pkt.haslayer(Raw):
                payload = pkt[Raw].load
                info += f" | Payload: {payload[:50]!r}"
        else:
            info = "Non-IP packet"

        if not protocols_only or info.find(protocols_only) != -1:
            print(f"[{packets_captured:5}] {info}")

    print(f"[*] Sniffing on {interface} (filter: {filter_str or 'none'})")
    print(f"[*] Limit: {count if count else 'unlimited'}")
    print("-" * 70)

    try:
        sniff(iface=interface, prn=handle_packet, filter=filter_str, count=count, store=False)
    except KeyboardInterrupt:
        print("\n[!] Stopped by user")
    except Exception as e:
        print(f"[!] Error: {e}")

    if pcap_file:
        pcap_file.close()

    print("-" * 70)
    print(f"[+] Captured {packets_captured} packets")
    for proto, cnt in protocol_count.items():
        if cnt > 0:
            print(f"    {proto}: {cnt}")


def main():
    parser = argparse.ArgumentParser(description="Network Packet Sniffer")
    parser.add_argument("-i", "--interface", required=True, help="Network interface")
    parser.add_argument("-f", "--filter", help="BPF filter (e.g. 'tcp port 80')")
    parser.add_argument(
        "-c", "--count", type=int, default=0, help="Number of packets (0=unlimited)"
    )
    parser.add_argument("-o", "--output", help="Save to PCAP file")
    parser.add_argument("-p", "--payload", action="store_true", help="Show payload")
    parser.add_argument("--proto", help="Show only specific protocol")
    args = parser.parse_args()

    if not check_root():
        sys.exit(1)

    sniff_packets(args.interface, args.filter, args.count, args.output, args.payload, args.proto)


if __name__ == "__main__":
    main()
