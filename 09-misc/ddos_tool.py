#!/usr/bin/env python3
"""
Stress Test Tool (Authorized Load Testing Only)
HTTP/HTTPS load tester - Authorized stress test only.
Usage: python ddos_tool.py -u http://target.com -c 50 -d 30
"""

import argparse
import sys
import time
import threading
import requests
import random


def stress_test(url, num_threads, duration, method, headers, body):
    """HTTP stress testing"""
    end_time = time.time() + duration
    request_count = [0]
    success_count = [0]
    error_count = [0]

    session = requests.Session()
    session.headers.update(headers)
    session.verify = False

    def worker():
        while time.time() < end_time:
            try:
                if method == "GET":
                    r = session.get(url, timeout=5)
                else:
                    r = session.post(url, data=body, timeout=5)
                request_count[0] += 1
                if 200 <= r.status_code < 400:
                    success_count[0] += 1
                else:
                    error_count[0] += 1
            except requests.exceptions.RequestException:
                error_count[0] += 1

    print(f"[*] Starting stress test")
    print(f"    URL: {url}")
    print(f"    Threads: {num_threads}")
    print(f"    Duration: {duration}s")
    print(f"    Method: {method}")
    print("=" * 60)

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    # Progress bar
    start_time = time.time()
    while time.time() < end_time:
        elapsed = time.time() - start_time
        print(
            f"\r[*] {elapsed:.0f}s elapsed | Requests: {request_count[0]} | Success: {success_count[0]} | Errors: {error_count[0]}",
            end="",
            flush=True,
        )
        time.sleep(1)

    print("\n")
    elapsed = time.time() - start_time
    print("=" * 60)
    print(f"[+] Test complete")
    print(f"    Total requests: {request_count[0]}")
    print(f"    Successful: {success_count[0]}")
    print(f"    Errors: {error_count[0]}")
    print(f"    Duration: {elapsed:.1f}s")
    if elapsed > 0:
        print(f"    RPS: {request_count[0] / elapsed:.1f}")


def main():
    parser = argparse.ArgumentParser(description="HTTP Load Tester (Authorized Use)")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-c", "--concurrent", type=int, default=50, help="Concurrent threads")
    parser.add_argument("-d", "--duration", type=int, default=30, help="Duration in seconds")
    parser.add_argument("-m", "--method", choices=["GET", "POST"], default="GET")
    parser.add_argument("-H", "--header", action="append", help="Custom header 'Key: Value'")
    parser.add_argument("-b", "--body", help="POST body")
    args = parser.parse_args()

    if not args.url.startswith("http"):
        args.url = "http://" + args.url

    headers = {"User-Agent": "Mozilla/5.0"}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

    print("[!] WARNING: Hanya untuk AUTHORIZED load testing")
    print("[!] Unauthorized denial of service adalah tindakan kriminal")
    confirm = input("[?] Lanjutkan? (yes/no): ")
    if confirm.lower() != "yes":
        print("Aborted")
        sys.exit(0)

    requests.packages.urllib3.disable_warnings()
    stress_test(args.url, args.concurrent, args.duration, args.method, headers, args.body)


if __name__ == "__main__":
    main()
