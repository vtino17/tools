#!/usr/bin/env python3
"""
Banner Grabber - Service identification via banner
Mengambil banner layanan untuk identifikasi versi.
Usage: python banner_grabber.py -t 192.168.1.1 -p 80
"""
import socket
import argparse
import sys


PROBES = {
    21: b"",
    22: b"SSH-2.0-OpenSSH\r\n",
    23: b"\r\n",
    25: b"EHLO test\r\n",
    53: b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01",
    80: b"GET / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n",
    110: b"",
    111: b"",
    135: b"",
    139: b"",
    143: b"",
    443: b"GET / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n",
    445: b"",
    993: b"",
    995: b"",
    1433: b"",
    3306: b"",
    3389: b"",
    8080: b"GET / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n",
}


def grab_banner(target, port, timeout=3):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        probe = PROBES.get(port, b"\r\n")
        if probe:
            sock.send(probe)

        banner = b""
        try:
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                banner += data
                if len(banner) > 8192:
                    break
        except socket.timeout:
            pass

        sock.close()
        return banner.decode("utf-8", errors="ignore").strip()
    except Exception as e:
        return f"Error: {e}"


def main():
    parser = argparse.ArgumentParser(description="Service Banner Grabber")
    parser.add_argument("-t", "--target", required=True, help="Target host/IP")
    parser.add_argument("-p", "--port", type=int, required=True, help="Target port")
    args = parser.parse_args()

    print(f"[*] Grabbing banner from {args.target}:{args.port}")
    print("-" * 60)
    banner = grab_banner(args.target, args.port)
    print(banner if banner else "[!] Tidak ada banner yang diterima")
    print("-" * 60)


if __name__ == "__main__":
    main()

