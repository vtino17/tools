#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HackerAI Tools - Master Launcher
Menu interaktif untuk menjalankan seluruh tools hacking yang tersedia.
Usage: python hackerai.py  or  python hackerai.py --list
"""

import io
import os
import sys
import subprocess
import importlib

# Fix Windows cp1252 console — force UTF-8 for stdout/stderr
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except AttributeError:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

try:
    from colorama import init, Fore, Style

    init(autoreset=True)
    C = Fore
    S = Style
except ImportError:

    class _NoColor:
        def __getattr__(self, name):
            return ""

    C = _NoColor()
    S = _NoColor()

CATEGORY_NAMES = {
    "01-network": "Network Recon",
    "02-webapp": "Web Application Security",
    "03-password": "Password & Bruteforce",
    "04-exploitation": "Exploitation",
    "05-osint": "OSINT",
    "06-wireless": "Wireless & Sniffing",
    "07-spoofing": "Spoofing & MITM",
    "08-postexploit": "Post-Exploitation",
    "09-misc": "Miscellaneous",
    "10-cloud": "Cloud Security",
    "11-containers": "Container Security",
    "12-forensics": "Forensics",
    "13-tunnel": "Tunneling",
}

TOOLS = {
    "1": {
        "name": "Network Scanner (ARP)",
        "category": "01-network",
        "file": "network_scanner.py",
        "needs_root": True,
        "deps": ["scapy"],
    },
    "2": {
        "name": "Port Scanner",
        "category": "01-network",
        "file": "port_scanner.py",
        "needs_root": False,
    },
    "3": {
        "name": "Subdomain Enumerator",
        "category": "01-network",
        "file": "subdomain_enum.py",
        "needs_root": False,
    },
    "4": {
        "name": "Banner Grabber",
        "category": "01-network",
        "file": "banner_grabber.py",
        "needs_root": False,
    },
    "5": {
        "name": "DNS Zone Transfer",
        "category": "01-network",
        "file": "dns_zone_transfer.py",
        "needs_root": False,
        "deps": ["dnspython"],
    },
    "6": {
        "name": "SMB Scanner",
        "category": "01-network",
        "file": "smb_scanner.py",
        "needs_root": False,
    },
    "7": {
        "name": "SNMP Scanner",
        "category": "01-network",
        "file": "snmp_scanner.py",
        "needs_root": False,
    },
    "8": {
        "name": "LDAP Scanner",
        "category": "01-network",
        "file": "ldap_scanner.py",
        "needs_root": False,
    },
    "9": {
        "name": "Reverse Proxy Analyzer",
        "category": "01-network",
        "file": "reverse_proxy_analyzer.py",
        "needs_root": False,
    },
    "10": {
        "name": "Web Application Scanner",
        "category": "02-webapp",
        "file": "web_scanner.py",
        "needs_root": False,
    },
    "11": {
        "name": "SQL Injection Tester",
        "category": "02-webapp",
        "file": "sqli_tester.py",
        "needs_root": False,
    },
    "12": {
        "name": "XSS Scanner",
        "category": "02-webapp",
        "file": "xss_scanner.py",
        "needs_root": False,
    },
    "13": {
        "name": "Directory Bruteforcer",
        "category": "02-webapp",
        "file": "directory_bruteforce.py",
        "needs_root": False,
    },
    "14": {
        "name": "CMS Detector",
        "category": "02-webapp",
        "file": "cms_detector.py",
        "needs_root": False,
    },
    "15": {
        "name": "WordPress Scanner",
        "category": "02-webapp",
        "file": "wordpress_scanner.py",
        "needs_root": False,
    },
    "16": {
        "name": "Backup File Finder",
        "category": "02-webapp",
        "file": "backup_finder.py",
        "needs_root": False,
    },
    "17": {
        "name": "Git/Config Exposure",
        "category": "02-webapp",
        "file": "git_exposure.py",
        "needs_root": False,
    },
    "18": {
        "name": "API Fuzzer",
        "category": "02-webapp",
        "file": "api_fuzzer.py",
        "needs_root": False,
    },
    "19": {
        "name": "Cookie Analyzer",
        "category": "02-webapp",
        "file": "cookie_analyzer.py",
        "needs_root": False,
    },
    "20": {
        "name": "Hash Cracker",
        "category": "03-password",
        "file": "hash_cracker.py",
        "needs_root": False,
    },
    "21": {
        "name": "Hash Identifier",
        "category": "03-password",
        "file": "hash_identifier.py",
        "needs_root": False,
    },
    "22": {
        "name": "HTTP Login Bruteforcer",
        "category": "03-password",
        "file": "http_bruteforce.py",
        "needs_root": False,
    },
    "23": {
        "name": "SSH Bruteforcer",
        "category": "03-password",
        "file": "ssh_bruteforce.py",
        "needs_root": False,
        "deps": ["paramiko"],
    },
    "24": {
        "name": "FTP Bruteforcer",
        "category": "03-password",
        "file": "ftp_bruteforce.py",
        "needs_root": False,
    },
    "25": {
        "name": "RDP Bruteforcer",
        "category": "03-password",
        "file": "rdp_bruteforce.py",
        "needs_root": False,
    },
    "26": {
        "name": "Password Generator",
        "category": "03-password",
        "file": "password_generator.py",
        "needs_root": False,
    },
    "27": {
        "name": "Reverse Shell Listener",
        "category": "04-exploitation",
        "file": "listener.py",
        "needs_root": False,
    },
    "28": {
        "name": "msfvenom Helper",
        "category": "04-exploitation",
        "file": "msfvenom_helper.py",
        "needs_root": False,
    },
    "29": {
        "name": "Payload Generator",
        "category": "04-exploitation",
        "file": "payload_generator.py",
        "needs_root": False,
    },
    "30": {
        "name": "Shellcode Encoder",
        "category": "04-exploitation",
        "file": "shellcode_encoder.py",
        "needs_root": False,
    },
    "31": {
        "name": "CVE Finder",
        "category": "04-exploitation",
        "file": "cve_finder.py",
        "needs_root": False,
    },
    "32": {
        "name": "Exploit Finder",
        "category": "04-exploitation",
        "file": "exploit_finder.py",
        "needs_root": False,
    },
    "33": {
        "name": "Persistence Helper",
        "category": "04-exploitation",
        "file": "persistence.py",
        "needs_root": False,
    },
    "34": {
        "name": "LFI/RFI Tester",
        "category": "04-exploitation",
        "file": "lfi_tester.py",
        "needs_root": False,
    },
    "35": {
        "name": "Command Injection",
        "category": "04-exploitation",
        "file": "command_injection.py",
        "needs_root": False,
    },
    "36": {
        "name": "SSTI Scanner",
        "category": "04-exploitation",
        "file": "ssti_scanner.py",
        "needs_root": False,
    },
    "37": {
        "name": "XXE Tester",
        "category": "04-exploitation",
        "file": "xxe_tester.py",
        "needs_root": False,
    },
    "38": {
        "name": "File Upload Tester",
        "category": "04-exploitation",
        "file": "file_upload_tester.py",
        "needs_root": False,
    },
    "39": {
        "name": "CORS Tester",
        "category": "04-exploitation",
        "file": "cors_tester.py",
        "needs_root": False,
    },
    "40": {
        "name": "IDOR Tester",
        "category": "04-exploitation",
        "file": "idor_tester.py",
        "needs_root": False,
    },
    "41": {
        "name": "CSRF Tester",
        "category": "04-exploitation",
        "file": "csrf_tester.py",
        "needs_root": False,
    },
    "42": {
        "name": "JWT Analyzer",
        "category": "04-exploitation",
        "file": "jwt_analyzer.py",
        "needs_root": False,
    },
    "43": {
        "name": "WAF Detector",
        "category": "04-exploitation",
        "file": "waf_detector.py",
        "needs_root": False,
    },
    "44": {
        "name": "Web Shell Generator",
        "category": "04-exploitation",
        "file": "web_shell_generator.py",
        "needs_root": False,
    },
    "45": {
        "name": "OSINT Tool",
        "category": "05-osint",
        "file": "osint_tool.py",
        "needs_root": False,
    },
    "46": {
        "name": "Email Harvester",
        "category": "05-osint",
        "file": "email_harvester.py",
        "needs_root": False,
    },
    "47": {
        "name": "Username Finder",
        "category": "05-osint",
        "file": "username_finder.py",
        "needs_root": False,
    },
    "48": {
        "name": "Google Dorker",
        "category": "05-osint",
        "file": "google_dorker.py",
        "needs_root": False,
    },
    "49": {
        "name": "WiFi Scanner",
        "category": "06-wireless",
        "file": "wifi_scanner.py",
        "needs_root": True,
        "deps": ["scapy"],
    },
    "50": {
        "name": "WiFi Deauth",
        "category": "06-wireless",
        "file": "wifi_deauth.py",
        "needs_root": True,
        "deps": ["scapy"],
        "dangerous": True,
    },
    "51": {
        "name": "WiFi Cracker",
        "category": "06-wireless",
        "file": "wifi_cracker.py",
        "needs_root": True,
        "deps": ["scapy"],
    },
    "52": {
        "name": "Packet Sniffer",
        "category": "06-wireless",
        "file": "packet_sniffer.py",
        "needs_root": True,
        "deps": ["scapy"],
    },
    "53": {
        "name": "Bluetooth Scanner",
        "category": "06-wireless",
        "file": "bluetooth_scanner.py",
        "needs_root": False,
    },
    "54": {
        "name": "ARP Spoofer",
        "category": "07-spoofing",
        "file": "arp_spoofer.py",
        "needs_root": True,
        "deps": ["scapy"],
        "dangerous": True,
    },
    "55": {
        "name": "DNS Spoofer",
        "category": "07-spoofing",
        "file": "dns_spoofer.py",
        "needs_root": True,
        "deps": ["scapy"],
        "dangerous": True,
    },
    "56": {
        "name": "DHCP Spoofer",
        "category": "07-spoofing",
        "file": "dhcp_spoofer.py",
        "needs_root": True,
        "deps": ["scapy"],
        "dangerous": True,
    },
    "57": {
        "name": "NetCut (ARP Disrupt)",
        "category": "07-spoofing",
        "file": "netcut.py",
        "needs_root": True,
        "deps": ["scapy"],
        "dangerous": True,
    },
    "58": {
        "name": "Windows Privesc",
        "category": "08-postexploit",
        "file": "win_privesc.py",
        "needs_root": False,
    },
    "59": {
        "name": "Linux Privesc",
        "category": "08-postexploit",
        "file": "lin_privesc.py",
        "needs_root": False,
    },
    "60": {
        "name": "Kernel Exploit Suggester",
        "category": "08-postexploit",
        "file": "kernel_exploit_checker.py",
        "needs_root": False,
    },
    "61": {
        "name": "Keylogger",
        "category": "08-postexploit",
        "file": "keylogger.py",
        "needs_root": False,
        "deps": ["pynput"],
        "dangerous": True,
    },
    "62": {
        "name": "Screenshot Tool",
        "category": "08-postexploit",
        "file": "screenshot.py",
        "needs_root": False,
    },
    "63": {
        "name": "Credential Harvester",
        "category": "08-postexploit",
        "file": "credential_harvester.py",
        "needs_root": False,
    },
    "64": {
        "name": "Log Cleaner",
        "category": "08-postexploit",
        "file": "log_cleaner.py",
        "needs_root": False,
        "dangerous": True,
    },
    "65": {
        "name": "DLL Hijack Finder",
        "category": "08-postexploit",
        "file": "dll_hijacker.py",
        "needs_root": False,
    },
    "66": {
        "name": "Network Discovery",
        "category": "09-misc",
        "file": "network_discovery.py",
        "needs_root": False,
    },
    "67": {
        "name": "HTTP Fuzzer",
        "category": "09-misc",
        "file": "http_fuzzer.py",
        "needs_root": False,
    },
    "68": {
        "name": "SSL/TLS Scanner",
        "category": "09-misc",
        "file": "ssl_scanner.py",
        "needs_root": False,
    },
    "69": {
        "name": "Steganography",
        "category": "09-misc",
        "file": "steganography.py",
        "needs_root": False,
    },
    "70": {
        "name": "Steganography Detector",
        "category": "09-misc",
        "file": "stego_detector.py",
        "needs_root": False,
    },
    "71": {
        "name": "Load Tester",
        "category": "09-misc",
        "file": "ddos_tool.py",
        "needs_root": False,
        "dangerous": True,
    },
    "72": {"name": "AWS Enum", "category": "10-cloud", "file": "aws_enum.py", "needs_root": False},
    "73": {
        "name": "Azure Enum",
        "category": "10-cloud",
        "file": "azure_enum.py",
        "needs_root": False,
    },
    "74": {"name": "GCP Enum", "category": "10-cloud", "file": "gcp_enum.py", "needs_root": False},
    "75": {
        "name": "Docker Enum",
        "category": "11-containers",
        "file": "docker_enum.py",
        "needs_root": False,
    },
    "76": {
        "name": "Kubernetes Enum",
        "category": "11-containers",
        "file": "k8s_enum.py",
        "needs_root": False,
    },
    "77": {
        "name": "Memory Dump/Analysis",
        "category": "12-forensics",
        "file": "memory_dump.py",
        "needs_root": False,
    },
    "78": {
        "name": "Disk Analyzer",
        "category": "12-forensics",
        "file": "disk_analyzer.py",
        "needs_root": False,
    },
    "79": {
        "name": "Registry Reader",
        "category": "12-forensics",
        "file": "registry_reader.py",
        "needs_root": False,
    },
    "80": {
        "name": "Port Forwarder",
        "category": "13-tunnel",
        "file": "port_forward.py",
        "needs_root": False,
    },
    "81": {
        "name": "DNS Tunnel",
        "category": "13-tunnel",
        "file": "dns_tunnel.py",
        "needs_root": True,
        "deps": ["dnspython"],
    },
    "82": {
        "name": "ICMP Tunnel",
        "category": "13-tunnel",
        "file": "icmp_tunnel.py",
        "needs_root": True,
    },
    "83": {
        "name": "MAC Changer",
        "category": "06-wireless",
        "file": "mac_changer.py",
        "needs_root": True,
    },
    "84": {
        "name": "Report Generator",
        "category": "09-misc",
        "file": "report_generator.py",
        "needs_root": False,
    },
}

CONSENT_FILE = os.path.join(BASE_DIR, ".consent_accepted")

DISCLAIMER = """\
======================================================================
  [!] PERINGATAN - BACA DENGAN SEKSAMA SEBELUM MELANJUTKAN
======================================================================

Alat ini HANYA boleh digunakan untuk:
  • CTF (Capture The Flag) competitions
  • Bug Bounty programs yang SUDAH disetujui
  • Penetration testing pada sistem MILIK SENDIRI
  • Lab environment / virtual machine pribadi
  • Educational research pada sistem yang ANDA miliki

DILARANG KERAS menggunakan alat ini untuk:
  • Menyerang sistem tanpa izin tertulis
  • Aktivitas ilegal atau melanggar hukum
  • Merusak sistem orang lain
  • Pencurian data / credential

Penggunaan alat ini SEPENUHNYA tanggung jawab ANDA.
Developer tidak bertanggung jawab atas penyalahgunaan.

======================================================================
"""

CATEGORY_MENU_KEYS = sorted(set(t["category"] for t in TOOLS.values()))


def show_disclaimer():
    print(C.YELLOW + DISCLAIMER + S.RESET_ALL)
    while True:
        try:
            answer = input("Ketik 'SETUJU' untuk melanjutkan: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[!] Dibatalkan.")
            sys.exit(0)
        if answer == "SETUJU":
            print(C.GREEN + "[OK] Anda telah menyetujui ketentuan penggunaan.\n" + S.RESET_ALL)
            return True
        else:
            print(C.RED + "[!] Anda harus mengetik 'SETUJU' untuk melanjutukan.\n" + S.RESET_ALL)


def is_admin():
    if os.name == "nt":
        try:
            import ctypes

            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False


def check_deps(tool):
    missing = []
    for dep in tool.get("deps", []):
        if dep == "scapy":
            dep_name = "scapy"
        elif dep == "dnspython":
            dep_name = "dns"
        elif dep == "paramiko":
            dep_name = "paramiko"
        elif dep == "pynput":
            dep_name = "pynput"
        else:
            dep_name = dep
        try:
            importlib.import_module(dep_name)
        except ImportError:
            missing.append(dep)
    return missing


def list_tools():
    print(C.CYAN + "\n  HACKERAI TOOLS - Full List (84 tools, 13 categories)\n" + S.RESET_ALL)
    for cat in sorted(CATEGORY_MENU_KEYS):
        cat_tools = [(tid, t) for tid, t in TOOLS.items() if t["category"] == cat]
        print(C.YELLOW + f"\n  [{cat}] {CATEGORY_NAMES.get(cat, cat)}" + S.RESET_ALL)
        for tid, t in cat_tools:
            root = C.RED + " [ROOT]" + S.RESET_ALL if t.get("needs_root") else ""
            dang = C.RED + " [!]" + S.RESET_ALL if t.get("dangerous") else ""
            print(f"   {tid:>3}. {t['name']}{root}{dang}")


def show_main_menu():
    print()
    print(C.CYAN + "=" * 65)
    print("  HACKERAI TOOLS - MASTER LAUNCHER v2.0")
    print("  84 tools · 13 categories")
    print("=" * 65 + S.RESET_ALL)
    for i, cat in enumerate(CATEGORY_MENU_KEYS, 1):
        count = sum(1 for t in TOOLS.values() if t["category"] == cat)
        print(f"  {C.GREEN}{i:>2}{S.RESET_ALL}. {CATEGORY_NAMES.get(cat, cat)} ({count} tools)")
    print(f"\n  {C.YELLOW} L{S.RESET_ALL}. List semua tools")
    print(f"  {C.YELLOW} D{S.RESET_ALL}. Check dependencies")
    print(f"  {C.YELLOW} W{S.RESET_ALL}. Web Dashboard (port 8080)")
    print(f"  {C.CYAN}  0{S.RESET_ALL}. Exit")
    print(C.CYAN + "=" * 65 + S.RESET_ALL)


def show_category_menu(category):
    cat_tools = [(tid, t) for tid, t in TOOLS.items() if t["category"] == category]
    print()
    print(C.CYAN + f"\n  [{category}] {CATEGORY_NAMES.get(category, category)}" + S.RESET_ALL)
    print("-" * 60)
    for tid, t in cat_tools:
        root = C.RED + " [ROOT]" + S.RESET_ALL if t.get("needs_root") else ""
        dang = C.RED + " [!]" + S.RESET_ALL if t.get("dangerous") else ""
        missing = check_deps(t)
        dep_warn = C.YELLOW + f" [missing: {','.join(missing)}]" + S.RESET_ALL if missing else ""
        print(f"  {C.GREEN}{tid:>3}{S.RESET_ALL}. {t['name']}{root}{dang}{dep_warn}")
    print("-" * 60)
    print(f"  {C.YELLOW} B{S.RESET_ALL}. Kembali ke menu utama")
    print(f"  {C.CYAN} 0{S.RESET_ALL}. Exit")


def run_tool(tool_id):
    if tool_id not in TOOLS:
        print(C.RED + f"[!] Invalid selection: {tool_id}" + S.RESET_ALL)
        return

    tool = TOOLS[tool_id]
    tool_path = os.path.join(BASE_DIR, tool["category"], tool["file"])

    if not os.path.exists(tool_path):
        print(C.RED + f"[!] Tool tidak ditemukan: {tool_path}" + S.RESET_ALL)
        return

    missing = check_deps(tool)
    if missing:
        print(C.YELLOW + f"[!] Missing dependencies: {', '.join(missing)}" + S.RESET_ALL)
        print(C.YELLOW + f"    Install: pip install {' '.join(missing)}" + S.RESET_ALL)

    if tool.get("dangerous"):
        print()
        print(C.RED + "!" * 60)
        print(f"  [!] DANGER: {tool['name']}")
        print("!" * 60)
        print("  Tool ini dapat menyebabkan kerusakan pada sistem target!")
        print("  HANYA gunakan pada sistem yang ANDA miliki.")
        print()
        try:
            confirm = input("  Ketik 'LANJUT' untuk menjalankan: ").strip()
        except (EOFError, KeyboardInterrupt):
            print(C.RED + "\n[!] Dibatalkan." + S.RESET_ALL)
            return
        if confirm != "LANJUT":
            print(C.RED + "[!] Dibatalkan." + S.RESET_ALL)
            return
        print()

    if tool.get("needs_root") and not is_admin():
        print(C.RED + "[!] Tool ini memerlukan akses Administrator/Root!" + S.RESET_ALL)
        print(C.RED + "[!] Jalankan ulang terminal sebagai Administrator/Root." + S.RESET_ALL)
        return

    print(C.GREEN + f"\n[+] Menjalankan: {tool['name']}" + S.RESET_ALL)
    print(f"[*] Path: {tool_path}")
    print("-" * 70)

    try:
        subprocess.run([sys.executable, tool_path], cwd=os.path.dirname(tool_path))
    except KeyboardInterrupt:
        print(C.RED + f"\n[!] Tool dihentikan oleh user." + S.RESET_ALL)
    except Exception as e:
        print(C.RED + f"[!] Error: {e}" + S.RESET_ALL)

    print("-" * 70)
    print(C.GREEN + "[*] Selesai." + S.RESET_ALL)


def check_all_deps():
    print(C.CYAN + "\n[*] Memeriksa dependencies..." + S.RESET_ALL)
    all_ok = True
    all_deps = set()
    for t in TOOLS.values():
        for d in t.get("deps", []):
            all_deps.add(d)
    for dep in sorted(all_deps):
        try:
            if dep == "scapy":
                importlib.import_module("scapy")
            elif dep == "dnspython":
                importlib.import_module("dns")
            elif dep == "paramiko":
                importlib.import_module("paramiko")
            elif dep == "pynput":
                importlib.import_module("pynput")
            else:
                importlib.import_module(dep)
            print(C.GREEN + f"  [v] {dep} - OK" + S.RESET_ALL)
        except ImportError:
            print(C.RED + f"  [x] {dep} - MISSING (pip install {dep})" + S.RESET_ALL)
            all_ok = False
    if all_ok:
        print(C.GREEN + "\n[v] Semua dependencies terinstall!" + S.RESET_ALL)
    else:
        print(
            C.YELLOW
            + "\n[!] Ada dependencies yang hilang. Install dengan: pip install -r requirements.txt"
            + S.RESET_ALL
        )


def start_web_dashboard():
    webapp = os.path.join(BASE_DIR, "webapp", "app.py")
    if not os.path.exists(webapp):
        print(C.RED + "[!] webapp/app.py tidak ditemukan!" + S.RESET_ALL)
        return
    print(C.GREEN + "[+] Menjalankan Web Dashboard..." + S.RESET_ALL)
    try:
        subprocess.run([sys.executable, webapp])
    except KeyboardInterrupt:
        print(C.RED + "\n[!] Dashboard dihentikan." + S.RESET_ALL)


def main():
    if "--list" in sys.argv or "-l" in sys.argv:
        list_tools()
        return

    show_disclaimer()

    while True:
        show_main_menu()
        try:
            choice = input(C.CYAN + "\n[*] Pilih: " + S.RESET_ALL).strip()
        except (EOFError, KeyboardInterrupt):
            print(C.RED + "\n[!] Keluar." + S.RESET_ALL)
            break

        if choice == "0":
            print(C.GREEN + "[*] Sampai jumpa!" + S.RESET_ALL)
            break
        elif choice == "":
            continue
        elif choice.upper() == "L":
            list_tools()
        elif choice.upper() == "D":
            check_all_deps()
        elif choice.upper() == "W":
            start_web_dashboard()
        elif choice.isdigit() and int(choice) <= len(CATEGORY_MENU_KEYS):
            cat_idx = int(choice) - 1
            category = CATEGORY_MENU_KEYS[cat_idx]
            while True:
                show_category_menu(category)
                try:
                    sub_choice = input(C.CYAN + "\n[*] Pilih tool: " + S.RESET_ALL).strip()
                except (EOFError, KeyboardInterrupt):
                    break
                if sub_choice == "0":
                    print(C.GREEN + "[*] Sampai jumpa!" + S.RESET_ALL)
                    return
                elif sub_choice.upper() == "B":
                    break
                elif sub_choice == "":
                    continue
                elif sub_choice in TOOLS:
                    run_tool(sub_choice)
                else:
                    print(C.RED + f"[!] Pilihan tidak valid: {sub_choice}" + S.RESET_ALL)
        elif choice in TOOLS:
            run_tool(choice)
        else:
            print(C.RED + f"[!] Pilihan tidak valid: {choice}" + S.RESET_ALL)


if __name__ == "__main__":
    main()
