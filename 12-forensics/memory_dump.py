#!/usr/bin/env python3
"""
Memory Dump Tool - Akuisisi & Analisis Memori
Usage:
  memory_dump.py --mode dump --pid 1234 --output mem.dmp
  memory_dump.py --mode analyze --output mem.dmp
  memory_dump.py --mode strings --output mem.dmp --size 6
  memory_dump.py --mode dump --output full.dmp
"""

import argparse
import os
import re
import struct
import sys
import subprocess
import platform
from datetime import datetime

OS_NAME = platform.system()

BANNER = """
╔══════════════════════════════════════════════╗
║         MEMORY DUMP TOOL v1.0                ║
║    Akuisisi & Analisis Memori Forensik       ║
╚══════════════════════════════════════════════╝
"""


def get_process_list():
    """Ambil daftar proses yang berjalan."""
    processes = []
    try:
        if OS_NAME == "Windows":
            try:
                import ctypes
                from ctypes import wintypes
                kernel32 = ctypes.windll.kernel32
                psapi = ctypes.windll.psapi

                h_process_snap = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
                if h_process_snap == -1:
                    raise OSError("CreateToolhelp32Snapshot gagal")

                class PROCESSENTRY32(ctypes.Structure):
                    _fields_ = [
                        ("dwSize", wintypes.DWORD),
                        ("cntUsage", wintypes.DWORD),
                        ("th32ProcessID", wintypes.DWORD),
                        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                        ("th32ModuleID", wintypes.DWORD),
                        ("cntThreads", wintypes.DWORD),
                        ("th32ParentProcessID", wintypes.DWORD),
                        ("pcPriClassBase", ctypes.c_long),
                        ("dwFlags", wintypes.DWORD),
                        ("szExeFile", ctypes.c_char * 260),
                    ]

                pe32 = PROCESSENTRY32()
                pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)

                if kernel32.Process32First(h_process_snap, ctypes.byref(pe32)):
                    while True:
                        name = pe32.szExeFile.decode("utf-8", errors="replace")
                        processes.append((pe32.th32ProcessID, name, pe32.cntThreads, pe32.th32ParentProcessID))
                        if not kernel32.Process32Next(h_process_snap, ctypes.byref(pe32)):
                            break

                kernel32.CloseHandle(h_process_snap)

                for i, (pid, name, threads, ppid) in enumerate(processes):
                    try:
                        h_process = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)
                        if h_process:
                            pmc = ctypes.c_ulonglong()
                            pmc2 = ctypes.c_ulonglong()
                            if psapi.GetProcessMemoryInfo(h_process, ctypes.byref(pmc), ctypes.sizeof(pmc)):
                                mem_bytes = pmc.value
                            else:
                                mem_bytes = 0
                            kernel32.CloseHandle(h_process)
                        else:
                            mem_bytes = 0
                    except Exception:
                        mem_bytes = 0
                    processes[i] = (pid, name, threads, ppid, mem_bytes)

            except ImportError:
                result = subprocess.run(
                    'Get-Process | Select-Object Id, ProcessName, Threads, @{N="MemMB";E={[math]::Round($_.WorkingSet64/1MB,2)}}',
                    shell=True, capture_output=True, text=True,
                    executable="powershell.exe",
                )
                for line in result.stdout.strip().split("\n"):
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[0].isdigit():
                        pid = int(parts[0])
                        name = parts[1]
                        processes.append((pid, name, 0, 0, 0))
        else:
            result = subprocess.run(
                ["ps", "-eo", "pid,comm,rss"],
                capture_output=True, text=True,
            )
            for line in result.stdout.strip().split("\n")[1:]:
                parts = line.strip().split(None, 2)
                if len(parts) >= 2:
                    try:
                        pid = int(parts[0])
                        name = parts[1]
                        rss = int(parts[2]) * 1024 if len(parts) >= 3 else 0
                        processes.append((pid, name, 0, pid, rss))
                    except ValueError:
                        continue
    except Exception as e:
        print(f"[!] Gagal mengambil daftar proses: {e}")
    return processes


def dump_process_windows(pid, output_file):
    """Dump memori proses di Windows menggunakan comsvcs.dll atau procdump."""
    print(f"[*] Mencoba dump proses PID={pid} di Windows...")

    dump_path = output_file or f"memory_pid{pid}_{datetime.now():%Y%m%d_%H%M%S}.dmp"

    if os.path.exists(dump_path):
        os.remove(dump_path)

    try:
        cmd = f'rundll32.exe C:\\Windows\\System32\\comsvcs.dll,MiniDump {pid} "{os.path.abspath(dump_path)}" full'
        print(f"[*] Menjalankan: {cmd}")
        subprocess.run(cmd, shell=True, timeout=60)
        if os.path.exists(dump_path) and os.path.getsize(dump_path) > 0:
            print(f"[+] Dump berhasil: {dump_path} ({os.path.getsize(dump_path)} bytes)")
            return dump_path
    except Exception as e:
        print(f"[!] comsvcs.dll gagal: {e}")

    for procdump_path in [
        os.path.expandvars(r"%SystemRoot%\System32\procdump.exe"),
        "procdump.exe",
        "procdump64.exe",
    ]:
        try:
            cmd = f'"{procdump_path}" -accepteula -ma {pid} "{os.path.abspath(dump_path)}"'
            print(f"[*] Mencoba Procdump: {cmd}")
            subprocess.run(cmd, shell=True, timeout=120)
            if os.path.exists(dump_path) and os.path.getsize(dump_path) > 0:
                print(f"[+] Dump berhasil via Procdump: {dump_path} ({os.path.getsize(dump_path)} bytes)")
                return dump_path
        except Exception as e:
            print(f"[!] Procdump gagal: {e}")

    print("[!] Gagal dump memori di Windows. Pastikan menjalankan sebagai Administrator.")
    print("[!] Alternatif: gunakan ProcDump, Process Explorer, atau FTK Imager secara manual.")
    return None


def dump_memory_linux(output_file):
    """Dump memori penuh di Linux menggunakan /dev/mem, /proc/kcore, atau instruksi LiME."""
    dump_path = output_file or f"memory_full_{datetime.now():%Y%m%d_%H%M%S}.dmp"
    print(f"[*] Mencoba dump memori penuh di Linux...")

    if os.path.exists("/dev/mem") and os.access("/dev/mem", os.R_OK):
        try:
            print("[*] Mencoba /dev/mem...")
            with open("/dev/mem", "rb") as src:
                with open(dump_path, "wb") as dst:
                    chunk = 1024 * 1024 * 64
                    copied = 0
                    while True:
                        data = src.read(chunk)
                        if not data:
                            break
                        dst.write(data)
                        copied += len(data)
                        print(f"\r[*] Terbaca: {copied / (1024**2):.1f} MB", end="", flush=True)
                    print()
            if os.path.getsize(dump_path) > 0:
                print(f"[+] Dump berhasil via /dev/mem: {dump_path} ({os.path.getsize(dump_path)} bytes)")
                return dump_path
        except Exception as e:
            print(f"\n[!] /dev/mem gagal: {e}")

    if os.path.exists("/proc/kcore"):
        print("[*] /proc/kcore tersedia tetapi dalam format ELF.")
        print("[*] Ekstrak dengan: dd if=/proc/kcore of=mem.dmp bs=4096 conv=noerror,sync")
        print("[!] /proc/kcore tidak bisa dibaca langsung — perlu alat kernel.")

    print("\n[!] Instruksi dump memori Linux:")
    print("    1. Kompilasi LiME (Linux Memory Extractor):")
    print("       git clone https://github.com/504ensicsLabs/LiME.git")
    print("       cd LiME/src && make")
    print("    2. Load kernel module:")
    print("       sudo insmod lime-*.ko path=mem.dmp format=raw")
    return None


def analyze_processes():
    """Analisis proses berjalan — cari indikasi injeksi dan proses tersembunyi."""
    print("\n[*] Menganalisis proses yang berjalan...")
    processes = get_process_list()

    if not processes:
        print("[!] Tidak dapat mengambil daftar proses.")
        return

    print(f"[*] Total proses terdeteksi: {len(processes)}")
    print(f"\n{'PID':>8} {'Nama':<30} {'Threads':>8} {'Memori':>14} {'Indikator'}")
    print("-" * 90)

    suspicious_names = [
        "mimikatz", "procmon", "procdump", "cuckoo", "vmwaretray",
        "vboxservice", "vboxtray", "splunk", "wireshark", "dumpcap",
        "netcat", "nc.exe", "ncat", "certutil", "bitsadmin",
        "rundll32", "regsvr32", "mshta", "cscript", "wscript",
    ]

    suspicious_parents = [
        "wmiprvse", "svchost", "services",
    ]

    for entry in processes:
        pid, name, threads, ppid = entry[:4]
        mem = entry[4] if len(entry) >= 5 else 0

        indicators = []

        name_lower = name.lower() if name else ""
        if name_lower in suspicious_names:
            indicators.append("SUSPICIOUS_NAME")

        if " " in name and ".exe" not in name_lower:
            indicators.append("WEIRD_NAME")

        mem_mb = mem / (1024 * 1024) if mem > 0 else 0
        if mem_mb > 500 and pid != 4:
            indicators.append(f"HIGH_MEM({mem_mb:.0f}MB)")

        indicator_str = " | ".join(indicators) if indicators else "-"
        if indicators:
            print(f"{pid:>8} {name:<30} {threads:>8} {mem_mb:>10.1f} MB [{indicator_str}]")

    print("\n[*] Mencari proses tersembunyi...")
    if OS_NAME == "Windows":
        try:
            result = subprocess.run(
                'Get-Process | Measure-Object | Select-Object -ExpandProperty Count',
                shell=True, capture_output=True, text=True,
                executable="powershell.exe",
            )
            ps_count = int(result.stdout.strip())
            ctypes_count = len(processes)
            print(f"[*] PowerShell: {ps_count} proses  |  ToolHelp32: {ctypes_count} proses")
            if abs(ps_count - ctypes_count) > 3:
                print(f"[!] Perbedaan jumlah proses terdeteksi! Kemungkinan rootkit aktif.")
        except Exception:
            pass

    print(f"\n[+] Analisis proses selesai.")


def extract_strings(filepath, min_length=6):
    """Ekstrak string ASCII dan Unicode dari file dump memori."""
    print(f"\n[*] Mengekstrak string dari: {filepath}")
    print(f"[*] Panjang minimum string: {min_length} karakter")

    if not os.path.exists(filepath):
        print(f"[!] File tidak ditemukan: {filepath}")
        return

    file_size = os.path.getsize(filepath)
    print(f"[*] Ukuran file: {file_size:,} bytes ({file_size / (1024**2):.1f} MB)")

    ascii_pattern = re.compile(rb"[\x20-\x7E]{%d,}" % min_length)
    unicode_pattern = re.compile(
        rb"(?:[\x20-\x7E]\x00){%d,}" % min_length
    )

    strings_found = []

    try:
        chunk_size = 1024 * 1024 * 64
        offset = 0
        print("[*] Memindai string ASCII...")

        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                for match in ascii_pattern.finditer(chunk):
                    s = match.group().decode("ascii", errors="replace")
                    strings_found.append((offset + match.start(), "ASCII", s))
                offset += len(chunk)
                progress = min(100, (offset / file_size) * 100)
                print(f"\r[*] Progress: {progress:.1f}%", end="", flush=True)

        print()

        offset = 0
        print("[*] Memindai string Unicode (UTF-16LE)...")
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                for match in unicode_pattern.finditer(chunk):
                    raw = match.group()
                    try:
                        s = raw.decode("utf-16-le", errors="replace")
                        if len(s) >= min_length and all(
                            c == "\x00" or 0x20 <= ord(c) <= 0x7E or ord(c) > 0x7F
                            for c in s
                        ):
                            strings_found.append((offset + match.start(), "UTF16", s))
                    except Exception:
                        pass
                offset += len(chunk)
                progress = min(100, (offset / file_size) * 100)
                print(f"\r[*] Progress: {progress:.1f}%", end="", flush=True)
        print()

    except Exception as e:
        print(f"\n[!] Gagal membaca file: {e}")
        return

    print(f"\n[+] Total string ditemukan: {len(strings_found)}")

    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    url_pattern = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
    email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    path_pattern = re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*")

    interesting = []
    for offset, enc, s in strings_found:
        if any([
            ip_pattern.search(s),
            url_pattern.search(s),
            email_pattern.search(s),
            "password" in s.lower(),
            "username" in s.lower(),
            "login" in s.lower(),
            "cmd.exe" in s.lower(),
            "powershell" in s.lower(),
            "http" in s.lower(),
            "registry" in s.lower(),
            "rundll32" in s.lower(),
            path_pattern.search(s),
        ]):
            interesting.append((offset, enc, s))

    if interesting:
        print(f"\n[*] String mencurigakan/penting ({len(interesting)} item):")
        for off, enc, s in interesting[:200]:
            print(f"    0x{off:08X} [{enc:5s}] {s[:120]}")
        if len(interesting) > 200:
            print(f"    ... dan {len(interesting) - 200} lainnya")

    print(f"\n[+] Ekstraksi string selesai.")


def analyze_dump(filepath):
    """Analisis file memory dump — header, proses, DLL."""
    print(f"\n[*] Menganalisis memory dump: {filepath}")

    if not os.path.exists(filepath):
        print(f"[!] File tidak ditemukan: {filepath}")
        return

    fs = os.path.getsize(filepath)
    print(f"[*] Ukuran: {fs:,} bytes ({fs / (1024**2):.1f} MB)")

    try:
        with open(filepath, "rb") as f:
            header = f.read(32)
    except Exception as e:
        print(f"[!] Gagal membaca file: {e}")
        return

    print(f"[*] Header (hex): {header[:32].hex(' ')}")

    if header[:4] == b"DMP\x00":
        print("[+] Format: Windows Minidump")
        if b"MDMP" in header[:32]:
            print("[+] Tipe: Full Memory Dump (MDMP)")
        else:
            print("[*] Tipe: Mini/Partial Dump")
    elif header[:4] == b"\x7fELF":
        print("[+] Format: ELF (Linux /proc/kcore atau LiME)")
    elif header[:4] == b"PAGED":
        print("[+] Format: Windows PAGEDUMP")
    elif header[:4] == b"DUMP":
        print("[+] Format: Windows Crash Dump")
    elif header[:2] == b"MZ":
        print("[*] File executable Windows (MZ header) — bukan memory dump")
    else:
        sig = header[:4].hex().upper()
        print(f"[*] Signature tidak dikenal: {sig}")
        print("[*] Mungkin raw memory dump — melanjutkan analisis string...")

    if b"proc" in header.lower() or b"wind" in header.lower():
        extract_strings(filepath, min_length=8)
    else:
        print("[*] Gunakan --mode strings untuk ekstraksi string dari dump ini.")

    print(f"\n[+] Analisis dump selesai.")


def main():
    parser = argparse.ArgumentParser(
        description="Memory Dump Tool — Akuisisi & Analisis Memori Forensik",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  %(prog)s --mode dump --pid 1234 --output mem.dmp
  %(prog)s --mode analyze --output mem.dmp
  %(prog)s --mode strings --output mem.dmp --size 8
  %(prog)s --mode analyze               (analisis proses berjalan)
        """,
    )
    parser.add_argument("--mode", choices=["dump", "analyze", "strings"], required=True,
                        help="Mode operasi: dump (akuisisi), analyze (analisis), strings (ekstrak string)")
    parser.add_argument("--pid", type=int, default=0,
                        help="PID proses untuk dump (hanya mode dump)")
    parser.add_argument("--output", type=str, default="",
                        help="Path file output (dump / input untuk analyze & strings)")
    parser.add_argument("--size", type=int, default=6,
                        help="Panjang minimum string (default: 6, mode strings)")

    args = parser.parse_args()

    print(BANNER)
    print(f"[*] Sistem Operasi: {OS_NAME}")
    print(f"[*] Mode: {args.mode}")
    print(f"[*] Waktu: {datetime.now():%Y-%m-%d %H:%M:%S}")

    if args.mode == "dump":
        if OS_NAME == "Windows":
            if args.pid > 0:
                dump_process_windows(args.pid, args.output)
            else:
                print("[!] Gunakan --pid <PID> untuk dump proses di Windows.")
                print("[*] Menampilkan daftar proses...")
                procs = get_process_list()
                if procs:
                    print(f"\n{'PID':>8} {'Nama':<35} {'Threads':>8} {'Mem(MB)':>10}")
                    print("-" * 70)
                    for entry in procs[:50]:
                        pid, name, threads = entry[:3]
                        mem = entry[4] if len(entry) >= 5 else 0
                        mem_mb = mem / (1024 * 1024) if mem > 0 else 0
                        print(f"{pid:>8} {name:<35} {threads:>8} {mem_mb:>10.1f}")
                    if len(procs) > 50:
                        print(f"    ... dan {len(procs) - 50} lainnya")
        else:
            dump_memory_linux(args.output)

    elif args.mode == "analyze":
        if args.output and os.path.exists(args.output):
            analyze_dump(args.output)
        else:
            analyze_processes()

    elif args.mode == "strings":
        if not args.output:
            print("[!] Gunakan --output <file_dump> untuk mengekstrak string.")
            sys.exit(1)
        extract_strings(args.output, min_length=args.size)


if __name__ == "__main__":
    main()
