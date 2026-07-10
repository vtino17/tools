#!/usr/bin/env python3
"""
SMB Enumerator & Scanner.

Memeriksa ketersediaan port SMB (445), mendeteksi versi SMB,
mencoba enumerasi share, null session, dan status SMB signing.

Mendukung autentikasi guest/anonymous dan kredensial khusus.
Cross-platform: menggunakan smbclient di Linux / net view di Windows,
dengan fallback pure-Python socket.

Usage:
    python smb_scanner.py --target 192.168.1.10
    python smb_scanner.py --target 192.168.1.10 --username admin --password P@ssw0rd
    python smb_scanner.py --target 192.168.1.0/24 --no-null
    python smb_scanner.py --target 192.168.1.10 --no-null
"""

import argparse
import ipaddress
import os
import re
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def log_info(msg: str) -> None:
    print(f"[*] {msg}")


def log_success(msg: str) -> None:
    print(f"[+] {msg}")


def log_error(msg: str) -> None:
    print(f"[!] {msg}")


def log_warn(msg: str) -> None:
    print(f"[-] {msg}")


def check_port(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def detect_smb_version_socket(host: str, timeout: float = 5.0) -> str | None:
    """Deteksi versi SMB menggunakan raw socket (SMB negotiate request)."""
    try:
        sock = socket.create_connection((host, 445), timeout=timeout)
        sock.settimeout(timeout)

        smb_negotiate = bytes(
            [
                0x00,
                0x00,
                0x00,
                0x54,
                0xFF,
                0x53,
                0x4D,
                0x42,
                0x72,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x01,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0xFF,
                0xFE,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x26,
                0x02,
                0x50,
                0x43,
                0x20,
                0x4E,
                0x45,
                0x54,
                0x57,
                0x4F,
                0x52,
                0x4B,
                0x20,
                0x50,
                0x52,
                0x4F,
                0x47,
                0x52,
                0x41,
                0x4D,
                0x20,
                0x31,
                0x2E,
                0x30,
                0x00,
                0x02,
                0x4D,
                0x49,
                0x43,
                0x52,
                0x4F,
                0x53,
                0x4F,
                0x46,
                0x54,
                0x20,
                0x4E,
                0x45,
                0x54,
                0x57,
                0x4F,
                0x52,
                0x4B,
                0x53,
                0x20,
                0x31,
                0x2E,
                0x30,
                0x33,
                0x00,
                0x02,
                0x4C,
                0x41,
                0x4E,
                0x4D,
                0x41,
                0x4E,
                0x31,
                0x2E,
                0x30,
                0x00,
            ]
        )

        sock.send(smb_negotiate)
        data = sock.recv(4096)
        sock.close()

        dialect_index = struct.unpack_from("<H", data, 36)[0]

        versions = {
            0: "PC NETWORK PROGRAM 1.0",
            1: "LANMAN 1.0",
            2: "Windows for Workgroups 3.1a",
            3: "LM1.2X002",
            4: "LANMAN2.1",
            5: "NT LM 0.12 (SMBv1)",
            6: "SMB v2.002 (SMBv2)",
            7: "SMB v2.??? (SMBv2)",
            8: "SMB v2.??? (SMBv2.x)",
            9: "SMB v2.1",
            10: "SMB v3.0",
            11: "SMB v3.02 (SMBv3)",
            12: "SMB v3.1.1",
        }
        return versions.get(dialect_index, f"Dialect index: {dialect_index}")
    except Exception as e:
        return f"Gagal deteksi: {e}"


def detect_smb_version_nmap(host: str) -> str | None:
    """Deteksi versi SMB menggunakan nmap NSE smb-protocols."""
    try:
        script = "smb-protocols" if os.name == "nt" else "'smb-protocols'"
        if os.name == "nt":
            cmd = ["nmap", "-p", "445", "--script", "smb-protocols", "-Pn", host]
        else:
            cmd = ["nmap", "-p", "445", "--script", "smb-protocols", "-Pn", host]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout

        match = re.search(r"(\|.*?smb-protocols.*?(?:\n\|.*?)+)", output, re.DOTALL)
        if match:
            return match.group(1).strip()
        return None
    except Exception:
        return None


def test_null_session(host: str) -> bool:
    """Uji null session access via smbclient atau net use."""
    log_info(f"Menguji null session pada {host}...")

    if os.name == "nt":
        cmd = f'net use \\\\{host}\\IPC$ "" /user:"" 2>&1'
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            if "success" in result.stdout.lower() or "berhasil" in result.stdout.lower():
                log_success(f"Null session BERHASIL pada {host}")
                subprocess.run(
                    f"net use \\\\{host}\\IPC$ /delete /y",
                    shell=True,
                    capture_output=True,
                    timeout=5,
                )
                return True
        except Exception:
            pass

    try:
        result = subprocess.run(
            ["smbclient", "-N", "-L", f"//{host}", "-g"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        output = result.stdout + result.stderr
        if "NT_STATUS" not in output and "Error" not in output:
            log_success(f"Null session BERHASIL pada {host}")
            return True
        elif "NT_STATUS_ACCESS_DENIED" in output:
            log_warn(f"Null session ditolak (ACCESS_DENIED) pada {host}")
            return False
    except FileNotFoundError:
        log_warn("smbclient tidak tersedia, melewati null session test")
    except Exception:
        pass

    log_warn(f"Null session GAGAL pada {host}")
    return False


def list_shares_smbclient(host: str, username: str = "", password: str = "") -> list[str]:
    """Enumerasi share SMB menggunakan smbclient."""
    shares = []

    if username:
        log_info(f"Mencoba enumerasi share dengan kredensial {username}...")
        cmd = ["smbclient", "-L", f"//{host}", "-U", f"{username}%{password}", "-g"]
    else:
        log_info("Mencoba enumerasi share anonymous...")
        cmd = ["smbclient", "-N", "-L", f"//{host}", "-g"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        for line in (result.stdout + result.stderr).splitlines():
            if line.startswith("Disk|"):
                parts = line.split("|")
                if len(parts) >= 2:
                    share = parts[1]
                    comment = parts[2] if len(parts) > 2 else ""
                    entry = share
                    if comment:
                        entry += f"  ({comment})"
                    shares.append(entry)
    except FileNotFoundError:
        log_warn("smbclient tidak ditemukan di PATH")
    except Exception as e:
        log_warn(f"Error enumerasi share: {e}")

    return shares


def list_shares_netview(host: str, username: str = "", password: str = "") -> list[str]:
    """Enumerasi share SMB menggunakan net view (Windows)."""
    shares = []
    cmd = f"net view \\\\{host}"
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        lines = result.stdout.splitlines()
        in_shares = False
        for line in lines:
            line = line.strip()
            if "---" in line or "Share name" in line.lower():
                in_shares = True
                continue
            if in_shares and line and not line.startswith("The command"):
                parts = line.split()
                if parts:
                    shares.append(parts[0])
    except Exception as e:
        log_warn(f"Error net view: {e}")
    return shares


def check_smb_signing(host: str) -> str:
    """Periksa status SMB signing via nmap smb2-security-mode."""
    try:
        result = subprocess.run(
            ["nmap", "-p", "445", "--script", "smb2-security-mode", "-Pn", host],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout
        signing = []
        for line in output.splitlines():
            if "signing" in line.lower():
                signing.append(line.strip())
        return "\n".join(signing) if signing else "Tidak dapat mendeteksi status signing"
    except Exception:
        return "Tidak dapat memeriksa (nmap tidak tersedia)"


def scan_single_host(host: str, args: argparse.Namespace) -> dict:
    """Pindai satu host SMB dan kembalikan hasilnya."""
    result = {
        "host": host,
        "online": False,
        "shares": [],
        "version": None,
        "null_session": False,
        "signing": "",
    }

    log_info(f"Memindai {host}...")
    result["online"] = check_port(host, 445)

    if not result["online"]:
        return result

    log_success(f"Port 445 terbuka pada {host}")

    result["version"] = detect_smb_version_socket(host)
    log_info(f"Versi SMB: {result['version']}")

    if not args.no_null:
        result["null_session"] = test_null_session(host)

    if os.name == "nt":
        shares = list_shares_netview(host, args.username or "", args.password or "")
    else:
        shares = list_shares_smbclient(host, args.username or "", args.password or "")

    if args.username:
        auth_shares = list_shares_smbclient(host, args.username, args.password)
        for s in auth_shares:
            if s not in shares:
                shares.append(f"(auth) {s}")

    result["shares"] = shares
    if shares:
        log_success(f"Ditemukan {len(shares)} share")

    if shares:
        result["signing"] = check_smb_signing(host)

    return result


def expand_targets(target: str) -> list[str]:
    """Expand target menjadi list IP jika diberikan sebagai subnet."""
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses > 1:
            hosts = [str(h) for h in net.hosts()]
            log_info(f"Subnet terdeteksi: {target} ({len(hosts)} host)")
            return hosts
    except ValueError:
        pass
    return [target]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SMB Enumerator & Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  %(prog)s --target 192.168.1.10
  %(prog)s --target 192.168.1.0/24
  %(prog)s --target 192.168.1.10 --username admin --password P@ssw0rd
  %(prog)s --target 192.168.1.10 --no-null
        """,
    )
    parser.add_argument(
        "--target",
        "-t",
        required=True,
        help="Target IP, hostname, atau subnet (e.g. 192.168.1.0/24)",
    )
    parser.add_argument("--username", "-u", help="Username SMB")
    parser.add_argument("--password", "-p", help="Password SMB")
    parser.add_argument("--no-null", action="store_true", help="Lewati null session test")
    parser.add_argument(
        "--threads", type=int, default=10, help="Jumlah thread paralel (default: 10)"
    )
    parser.add_argument("--timeout", type=float, default=5.0, help="Timeout koneksi (default: 5s)")
    args = parser.parse_args()

    targets = expand_targets(args.target)
    results = []

    if len(targets) == 1:
        result = scan_single_host(targets[0], args)
        results.append(result)
    else:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(scan_single_host, t, args): t for t in targets}
            for future in as_completed(futures):
                results.append(future.result())

    online_hosts = [r for r in results if r["online"]]

    print(f"\n{'=' * 60}")
    print(f"  HASIL ENUMERASI SMB")
    print(f"{'=' * 60}")
    print(f"  Target dipindai  : {len(targets)}")
    print(f"  Host online      : {len(online_hosts)}")
    print(f"{'=' * 60}")

    for r in online_hosts:
        print(f"\n  [HOST] {r['host']}")
        print(f"    Versi SMB     : {r['version']}")
        print(f"    Null Session  : {'TERBUKA' if r['null_session'] else 'Tertutup'}")

        if r["shares"]:
            print(f"    Share ({len(r['shares'])}):")
            for share in r["shares"]:
                print(f"      - {share}")
        else:
            print(f"    Share         : (tidak dapat dienumerasi)")

        if r["signing"]:
            print(f"    SMB Signing   :")
            for line in r["signing"].splitlines():
                print(f"      {line.strip()}")

    offline = [r for r in results if not r["online"]]
    if offline and len(targets) > 1:
        print(f"\n  [OFFLINE] {len(offline)} host")
        for r in offline[:10]:
            print(f"    - {r['host']}")
        if len(offline) > 10:
            print(f"    ... dan {len(offline) - 10} lainnya")


if __name__ == "__main__":
    main()
