#!/usr/bin/env python3
"""HackerAI Web Dashboard"""

import sys

try:
    from flask import Flask, render_template, request, jsonify, send_from_directory
except ImportError:
    print("Flask not installed. Run: pip install flask")
    sys.exit(1)

import subprocess
import os
import json
import threading
import signal

TOOLS = {
    "01-network": [
        {
            "id": 1,
            "name": "network_scanner",
            "desc": "TCP/UDP network scanner with service detection",
            "args": ["target", "ports"],
            "needs_root": False,
        },
        {
            "id": 2,
            "name": "port_scanner",
            "desc": "Advanced port scanner with banner grabbing",
            "args": ["target", "ports", "threads"],
            "needs_root": False,
        },
        {
            "id": 3,
            "name": "ping_sweep",
            "desc": "ICMP ping sweep for host discovery",
            "args": ["target", "timeout"],
            "needs_root": False,
        },
        {
            "id": 4,
            "name": "dns_enum",
            "desc": "DNS enumeration and zone transfer attempt",
            "args": ["target", "wordlist"],
            "needs_root": False,
        },
        {
            "id": 5,
            "name": "traceroute",
            "desc": "Multi-protocol traceroute with geo-IP lookup",
            "args": ["target", "max_hops"],
            "needs_root": False,
        },
        {
            "id": 6,
            "name": "snmp_enum",
            "desc": "SNMP enumeration using community strings",
            "args": ["target", "community"],
            "needs_root": False,
        },
        {
            "id": 7,
            "name": "smb_enum",
            "desc": "SMB share and user enumeration",
            "args": ["target", "username", "password"],
            "needs_root": False,
        },
        {
            "id": 8,
            "name": "packet_sniffer",
            "desc": "Raw packet capture and analysis",
            "args": ["interface", "count", "filter"],
            "needs_root": True,
        },
    ],
    "02-webapp": [
        {
            "id": 9,
            "name": "dir_bruteforce",
            "desc": "Web directory and file brute-force discovery",
            "args": ["target", "wordlist", "extensions", "threads"],
            "needs_root": False,
        },
        {
            "id": 10,
            "name": "sql_injection_scanner",
            "desc": "Automated SQL injection vulnerability scanner",
            "args": ["target", "param", "method"],
            "needs_root": False,
        },
        {
            "id": 11,
            "name": "xss_scanner",
            "desc": "Cross-Site Scripting vulnerability detector",
            "args": ["target", "param", "method"],
            "needs_root": False,
        },
        {
            "id": 12,
            "name": "cms_detector",
            "desc": "CMS and technology fingerprinting",
            "args": ["target"],
            "needs_root": False,
        },
        {
            "id": 13,
            "name": "waf_detector",
            "desc": "Web Application Firewall detection and bypass test",
            "args": ["target"],
            "needs_root": False,
        },
        {
            "id": 14,
            "name": "ssl_auditor",
            "desc": "SSL/TLS configuration and vulnerability audit",
            "args": ["target", "port"],
            "needs_root": False,
        },
        {
            "id": 15,
            "name": "header_analyzer",
            "desc": "HTTP security headers analyzer",
            "args": ["target"],
            "needs_root": False,
        },
        {
            "id": 16,
            "name": "virtual_host_enum",
            "desc": "Virtual host enumeration via Host header fuzzing",
            "args": ["target", "wordlist"],
            "needs_root": False,
        },
        {
            "id": 17,
            "name": "api_fuzzer",
            "desc": "REST API endpoint fuzzer and security tester",
            "args": ["target", "wordlist", "threads"],
            "needs_root": False,
        },
    ],
    "03-password": [
        {
            "id": 18,
            "name": "hash_cracker",
            "desc": "Multi-algorithm hash cracker (MD5/SHA/LM/NTLM)",
            "args": ["hash", "type", "wordlist"],
            "needs_root": False,
        },
        {
            "id": 19,
            "name": "password_generator",
            "desc": "Custom wordlist generator with rules and patterns",
            "args": ["min_len", "max_len", "charset", "output"],
            "needs_root": False,
        },
        {
            "id": 20,
            "name": "zip_cracker",
            "desc": "ZIP/RAR/7z archive password cracker",
            "args": ["target", "wordlist"],
            "needs_root": False,
        },
        {
            "id": 21,
            "name": "online_bruteforce",
            "desc": "Online brute-force against HTTP/FTP/SSH services",
            "args": ["target", "service", "username", "wordlist", "port"],
            "needs_root": False,
        },
    ],
    "04-exploitation": [
        {
            "id": 22,
            "name": "metasploit_helper",
            "desc": "Metasploit resource script generator",
            "args": ["target", "exploit", "payload", "lhost", "lport"],
            "needs_root": False,
        },
        {
            "id": 23,
            "name": "reverse_shell_gen",
            "desc": "Multi-language reverse shell payload generator",
            "args": ["lhost", "lport", "type"],
            "needs_root": False,
        },
        {
            "id": 24,
            "name": "binary_exploit_tester",
            "desc": "Buffer overflow and format string tester",
            "args": ["target", "port", "type"],
            "needs_root": False,
        },
        {
            "id": 25,
            "name": "exploitdb_search",
            "desc": "Search Exploit-DB for known exploits",
            "args": ["query", "platform", "type"],
            "needs_root": False,
        },
        {
            "id": 26,
            "name": "privilege_escalation",
            "desc": "Linux/Windows privilege escalation checker",
            "args": ["type"],
            "needs_root": False,
        },
        {
            "id": 27,
            "name": "payload_encoder",
            "desc": "Shellcode encoder and obfuscator",
            "args": ["payload", "encoder", "iterations"],
            "needs_root": False,
        },
        {
            "id": 28,
            "name": "exploit_suggester",
            "desc": "OS/software vulnerability & exploit suggester",
            "args": ["target", "port"],
            "needs_root": False,
        },
        {
            "id": 29,
            "name": "ldap_enum",
            "desc": "LDAP directory enumeration and query",
            "args": ["target", "base_dn", "username", "password"],
            "needs_root": False,
        },
        {
            "id": 30,
            "name": "smb_exploit",
            "desc": "SMB vulnerability scanner and exploit (EternalBlue)",
            "args": ["target", "port", "exploit"],
            "needs_root": False,
        },
        {
            "id": 31,
            "name": "rdp_exploit",
            "desc": "RDP BlueKeep vulnerability checker",
            "args": ["target", "port"],
            "needs_root": False,
        },
        {
            "id": 32,
            "name": "webshell_manager",
            "desc": "Web shell deployment and management tool",
            "args": ["target", "password", "type"],
            "needs_root": False,
        },
        {
            "id": 33,
            "name": "juice_potato",
            "desc": "Windows privilege escalation via Rotten/Juice Potato",
            "args": ["command", "clsid"],
            "needs_root": False,
        },
        {
            "id": 34,
            "name": "kerberoasting",
            "desc": "Kerberoasting attack automation for AD environments",
            "args": ["target", "domain", "userlist"],
            "needs_root": False,
        },
        {
            "id": 35,
            "name": "asreproast",
            "desc": "AS-REP Roasting for accounts without pre-auth",
            "args": ["target", "domain"],
            "needs_root": False,
        },
        {
            "id": 36,
            "name": "nopac_check",
            "desc": "noPac (CVE-2021-42278/42287) vulnerability scanner",
            "args": ["target", "domain"],
            "needs_root": False,
        },
        {
            "id": 37,
            "name": "adcs_enum",
            "desc": "Active Directory Certificate Services enumeration",
            "args": ["target", "domain"],
            "needs_root": False,
        },
    ],
    "05-osint": [
        {
            "id": 38,
            "name": "whois_lookup",
            "desc": "WHOIS domain and IP ownership lookup",
            "args": ["target"],
            "needs_root": False,
        },
        {
            "id": 39,
            "name": "shodan_search",
            "desc": "Shodan.io IoT and service discovery search",
            "args": ["query", "limit"],
            "needs_root": False,
        },
        {
            "id": 40,
            "name": "email_harvester",
            "desc": "Email address harvester from search engines",
            "args": ["domain", "max_results"],
            "needs_root": False,
        },
        {
            "id": 41,
            "name": "social_media_scraper",
            "desc": "Social media profile and metadata scraper",
            "args": ["target", "platform"],
            "needs_root": False,
        },
    ],
    "06-wireless": [
        {
            "id": 42,
            "name": "wifi_scanner",
            "desc": "WiFi network scanner and signal analyzer",
            "args": ["interface"],
            "needs_root": True,
        },
        {
            "id": 43,
            "name": "wifi_deauth",
            "desc": "WiFi deauthentication attack tool",
            "args": ["interface", "target", "count"],
            "needs_root": True,
        },
        {
            "id": 44,
            "name": "wpa_cracker",
            "desc": "WPA/WPA2 handshake capture and cracker",
            "args": ["interface", "wordlist", "bssid"],
            "needs_root": True,
        },
        {
            "id": 45,
            "name": "bluetooth_scanner",
            "desc": "Bluetooth device discovery and service enumeration",
            "args": ["interface"],
            "needs_root": False,
        },
        {
            "id": 46,
            "name": "evil_twin",
            "desc": "Rogue access point creator for credential capture",
            "args": ["interface", "ssid", "channel"],
            "needs_root": True,
        },
    ],
    "07-spoofing": [
        {
            "id": 47,
            "name": "arp_spoofer",
            "desc": "ARP cache poisoning / MiTM attack tool",
            "args": ["target", "gateway", "interface"],
            "needs_root": True,
        },
        {
            "id": 48,
            "name": "dns_spoofer",
            "desc": "DNS response poisoning and redirection",
            "args": ["target", "domain", "redirect_ip", "interface"],
            "needs_root": True,
        },
        {
            "id": 49,
            "name": "dhcp_spoofer",
            "desc": "Rogue DHCP server for network poisoning",
            "args": ["interface", "gateway", "dns", "range_start", "range_end"],
            "needs_root": True,
        },
        {
            "id": 50,
            "name": "mac_changer",
            "desc": "MAC address changer and randomizer",
            "args": ["interface", "new_mac"],
            "needs_root": True,
        },
    ],
    "08-postexploit": [
        {
            "id": 51,
            "name": "password_dumper",
            "desc": "Credential dumper (SAM/SYSTEM/cached creds/browser)",
            "args": ["target", "type"],
            "needs_root": True,
        },
        {
            "id": 52,
            "name": "keylogger",
            "desc": "Cross-platform keylogger with exfiltration",
            "args": ["method", "interval"],
            "needs_root": False,
        },
        {
            "id": 53,
            "name": "persistence_installer",
            "desc": "Multi-method persistence mechanism installer",
            "args": ["target", "method", "payload"],
            "needs_root": True,
        },
        {
            "id": 54,
            "name": "lateral_movement",
            "desc": "Lateral movement toolkit (PsExec/WMI/WinRM/SMB)",
            "args": ["target", "username", "password", "method"],
            "needs_root": False,
        },
        {
            "id": 55,
            "name": "data_exfiltrator",
            "desc": "Stealth data exfiltration over DNS/HTTP/ICMP",
            "args": ["target", "method", "output_server"],
            "needs_root": False,
        },
        {
            "id": 56,
            "name": "log_cleaner",
            "desc": "System and application log tampering/cleaner",
            "args": ["target", "type"],
            "needs_root": True,
        },
    ],
    "09-misc": [
        {
            "id": 57,
            "name": "file_encryptor",
            "desc": "AES-256/RSA file encryption and decryption",
            "args": ["target", "operation", "algorithm", "key"],
            "needs_root": False,
        },
        {
            "id": 58,
            "name": "steganography_tool",
            "desc": "LSB image/audio steganography encode and decode",
            "args": ["target", "operation", "payload"],
            "needs_root": False,
        },
        {
            "id": 59,
            "name": "base64_tool",
            "desc": "Base64/Base32/Hex encode, decode, and file convert",
            "args": ["target", "operation", "encoding"],
            "needs_root": False,
        },
        {
            "id": 60,
            "name": "hash_identifier",
            "desc": "Identify hash algorithm from format analysis",
            "args": ["target"],
            "needs_root": False,
        },
        {
            "id": 61,
            "name": "reverse_proxy_analyzer",
            "desc": "Reverse proxy and load balancer config analyzer",
            "args": ["target"],
            "needs_root": False,
        },
        {
            "id": 62,
            "name": "cookie_analyzer",
            "desc": "HTTP cookie security and session analyzer",
            "args": ["target", "cookie"],
            "needs_root": False,
        },
        {
            "id": 63,
            "name": "stego_detector",
            "desc": "Steganography detection via statistical analysis",
            "args": ["target"],
            "needs_root": False,
        },
    ],
    "10-cloud": [
        {
            "id": 64,
            "name": "s3_bucket_scanner",
            "desc": "AWS S3 bucket enumeration and permission check",
            "args": ["target"],
            "needs_root": False,
        },
        {
            "id": 65,
            "name": "cloud_cred_scanner",
            "desc": "Scans for exposed cloud credentials and API keys",
            "args": ["target"],
            "needs_root": False,
        },
        {
            "id": 66,
            "name": "iam_enum",
            "desc": "Cloud IAM role and policy enumerator",
            "args": ["target", "platform"],
            "needs_root": False,
        },
    ],
    "11-containers": [
        {
            "id": 67,
            "name": "docker_enum",
            "desc": "Docker container and registry enumeration",
            "args": ["target", "port"],
            "needs_root": False,
        },
        {
            "id": 68,
            "name": "k8s_enum",
            "desc": "Kubernetes cluster security assessment",
            "args": ["target", "token", "namespace"],
            "needs_root": False,
        },
    ],
    "12-forensics": [
        {
            "id": 69,
            "name": "memory_dump_analyzer",
            "desc": "Windows/Linux memory dump artifact extractor",
            "args": ["target", "profile", "plugin"],
            "needs_root": False,
        },
        {
            "id": 70,
            "name": "file_carver",
            "desc": "File carving and deleted file recovery tool",
            "args": ["target", "output_dir"],
            "needs_root": False,
        },
        {
            "id": 71,
            "name": "registry_analyzer",
            "desc": "Windows registry hive forensic analyzer",
            "args": ["target", "hive"],
            "needs_root": False,
        },
    ],
    "13-tunnel": [
        {
            "id": 72,
            "name": "ssh_tunnel",
            "desc": "SSH port forwarding and dynamic tunnel manager",
            "args": ["target", "local_port", "remote_port", "username"],
            "needs_root": False,
        },
        {
            "id": 73,
            "name": "proxy_chainer",
            "desc": "SOCKS/HTTP proxy chain builder with rotation",
            "args": ["port", "chain"],
            "needs_root": False,
        },
        {
            "id": 74,
            "name": "reverse_port_forwarder",
            "desc": "Reverse port forwarding via multiple protocols",
            "args": ["server", "port", "local_port"],
            "needs_root": False,
        },
    ],
    "14-audit": [
        {
            "id": 75,
            "name": "linux_hardening_audit",
            "desc": "CIS benchmark compliance audit for Linux",
            "args": ["target", "level"],
            "needs_root": False,
        },
        {
            "id": 76,
            "name": "windows_hardening_audit",
            "desc": "CIS benchmark compliance audit for Windows",
            "args": ["target"],
            "needs_root": False,
        },
        {
            "id": 77,
            "name": "web_app_audit",
            "desc": "Full OWASP Top 10 web application security audit",
            "args": ["target", "depth"],
            "needs_root": False,
        },
        {
            "id": 78,
            "name": "code_security_audit",
            "desc": "SAST-style source code security review",
            "args": ["target", "language"],
            "needs_root": False,
        },
        {
            "id": 79,
            "name": "network_security_audit",
            "desc": "Network segmentation and firewall rule audit",
            "args": ["target", "ports"],
            "needs_root": False,
        },
    ],
    "15-malware": [
        {
            "id": 80,
            "name": "malware_scanner",
            "desc": "YARA-based malware signature scanner",
            "args": ["target", "rules"],
            "needs_root": False,
        },
        {
            "id": 81,
            "name": "process_monitor",
            "desc": "Real-time process and API call monitor",
            "args": ["pid", "duration"],
            "needs_root": True,
        },
        {
            "id": 82,
            "name": "rdp_bruteforce",
            "desc": "RDP brute-force attack with NLA support",
            "args": ["target", "username", "wordlist", "port", "threads"],
            "needs_root": False,
        },
        {
            "id": 83,
            "name": "web_shell_generator",
            "desc": "Multi-language web shell payload generator",
            "args": ["lang", "password", "port"],
            "needs_root": False,
        },
        {
            "id": 84,
            "name": "dll_hijacker",
            "desc": "DLL hijacking vulnerability scanner and PoC generator",
            "args": ["target", "path", "dll_name"],
            "needs_root": False,
        },
    ],
}

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html", tools=TOOLS)


@app.route("/run/<tool_id>")
def run_tool(tool_id):
    tool = None
    category = None
    for cat, tools in TOOLS.items():
        for t in tools:
            if str(t["id"]) == tool_id:
                tool = t
                category = cat
                break
        if tool:
            break
    if not tool:
        return "Tool not found", 404
    return render_template("run.html", tool=tool, category=category)


@app.route("/api/tools")
def api_tools():
    return jsonify(TOOLS)


@app.route("/api/run", methods=["POST"])
def api_run():
    data = request.get_json()
    tool_id = data.get("tool_id", "")
    args = data.get("args", {})
    tool = None
    for cat, tools in TOOLS.items():
        for t in tools:
            if str(t["id"]) == str(tool_id):
                tool = t
                break
        if tool:
            break
    if not tool:
        return jsonify({"error": "Tool not found"}), 404
    cmd = ["powershell", "-Command", tool["name"]] if os.name == "nt" else [tool["name"]]
    for arg_name, arg_val in args.items():
        if arg_val:
            if not arg_name.startswith("--"):
                arg_name = "--" + arg_name
            cmd.append(arg_name)
            cmd.append(str(arg_val))
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=os.path.dirname(os.path.abspath(__file__)),
        )
        return jsonify({"exit_code": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr})
    except subprocess.TimeoutExpired:
        return jsonify(
            {"exit_code": -1, "stdout": "", "stderr": "Command timed out after 120 seconds"}
        )
    except FileNotFoundError:
        return jsonify(
            {"exit_code": -1, "stdout": "", "stderr": f"Tool '{tool['name']}' not found on PATH"}
        )
    except Exception as e:
        return jsonify({"exit_code": -1, "stdout": "", "stderr": str(e)})


@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory("static", filename)


if __name__ == "__main__":
    print("HackerAI Web Dashboard starting on http://localhost:8080")
    app.run(host="0.0.0.0", port=8080, debug=True)
