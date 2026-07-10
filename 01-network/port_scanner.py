#!/usr/bin/env python3
"""
Port Scanner - Multi-threaded TCP port scanner
Pemindai port cepat dengan banner grabbing.
Usage: python port_scanner.py -t 192.168.1.1 -p 1-1000
"""

import socket
import argparse
import threading
import queue
import sys
from datetime import datetime

# Lock for print synchronization
print_lock = threading.Lock()


def grab_banner(sock):
    try:
        sock.settimeout(2)
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        return banner[:200] if banner else "No banner"
    except:
        return ""


def scan_port(target, port, grab_banner_flag=False):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            with print_lock:
                service = get_common_service(port)
                line = f"[+] Port {port:<6} OPEN   ({service})"
                if grab_banner_flag:
                    banner = grab_banner(sock)
                    if banner:
                        line += f"\n    |_ Banner: {banner}"
                print(line)
            sock.close()
            return True
        sock.close()
    except socket.gaierror:
        pass
    except socket.error:
        pass
    return False


def get_common_service(port):
    services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        135: "MS-RPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP-Proxy",
        8443: "HTTPS-Alt",
        27017: "MongoDB",
    }
    return services.get(port, "Unknown")


def worker(target, port_queue, grab_banner_flag, results):
    while not port_queue.empty():
        port = port_queue.get()
        if scan_port(target, port, grab_banner_flag):
            results.append(port)
        port_queue.task_done()


def main():
    parser = argparse.ArgumentParser(description="Multi-threaded Port Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target host/IP")
    parser.add_argument(
        "-p", "--ports", default="1-1024", help="Port range (e.g. 1-1000) or single port"
    )
    parser.add_argument("--threads", type=int, default=100, help="Thread count")
    parser.add_argument("-b", "--banner", action="store_true", help="Enable banner grabbing")
    args = parser.parse_args()

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[!] Tidak dapat resolve hostname: {args.target}")
        sys.exit(1)

    port_queue = queue.Queue()
    if "-" in args.ports:
        start, end = map(int, args.ports.split("-"))
        for p in range(start, end + 1):
            port_queue.put(p)
    elif "," in args.ports:
        for p in map(int, args.ports.split(",")):
            port_queue.put(p)
    else:
        port_queue.put(int(args.ports))

    print(f"[*] Mulai scan: {target_ip}")
    print(f"[*] Port range: {args.ports}")
    print(f"[*] Threads: {args.threads}")
    print(f"[*] Start: {datetime.now()}")
    print("-" * 60)

    results = []
    threads = []
    for _ in range(min(args.threads, port_queue.qsize())):
        t = threading.Thread(target=worker, args=(target_ip, port_queue, args.banner, results))
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("-" * 60)
    print(f"[+] Selesai. {len(results)} port terbuka ditemukan.")
    print(f"[*] End: {datetime.now()}")


if __name__ == "__main__":
    main()
