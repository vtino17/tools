<div align="center">

# HackerAI Tools Collection

**85+ hacking & penetration testing tools — 13 categories — one CLI**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-22AA55?style=flat-square)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/vtino17/tools?style=flat-square&logo=github)](https://github.com/vtino17/tools/stargazers)
[![Last commit](https://img.shields.io/github/last-commit/vtino17/tools?style=flat-square)](https://github.com/vtino17/tools/commits)
[![CI](https://img.shields.io/github/actions/workflow/status/vtino17/tools/qa.yml?style=flat-square&label=CI)](https://github.com/vtino17/tools/actions)
[![Code style](https://img.shields.io/badge/code%20style-black-000000?style=flat-square)](https://github.com/psf/black)

</div>

A comprehensive collection of **85+ Python-based security tools** covering network reconnaissance, web application testing, exploitation, OSINT, wireless, cloud security, forensics, and more — all accessible through a single unified CLI launcher.

---

## Quick Start

```bash
# Clone & install
git clone https://github.com/vtino17/tools.git
cd tools
pip install -r requirements.txt

# Interactive menu (13 categories)
python hackerai.py

# List all tools
python hackerai.py --list

# Web dashboard
python hackerai.py  →  press W  →  http://localhost:8080
```

---

## Features

- **85+ tools** across network, web, exploitation, OSINT, wireless, cloud, containers, forensics & more
- **Unified launcher** — `hackerai.py` with categorized sub-menus
- **Direct mode** — run any tool standalone for scripting/automation
- **Web dashboard** — graphical UI for tool management
- **Custom wordlists** — common passwords, subdomains, usernames
- **Report templates** — HTML & Markdown pentest report templates
- **Cross-platform** — Windows & Linux with privilege detection

---

## Tool Categories

| # | Category | Tools | Description |
|---|----------|-------|-------------|
| 01 | [Network Recon](01-network/) | 9 | ARP discovery, port scan, DNS, SMB, SNMP, LDAP |
| 02 | [Web Security](02-webapp/) | 10 | SQLi, XSS, directory brute, CMS detect, API fuzz |
| 03 | [Password & Bruteforce](03-password/) | 7 | Hash cracker/identifier, HTTP/SSH/FTP/RDP brute |
| 04 | [Exploitation](04-exploitation/) | 18 | Reverse shell, payload gen, CVE search, LFI, SSTI, XXE |
| 05 | [OSINT](05-osint/) | 4 | Multi-source OSINT, email harvest, username search, dorking |
| 06 | [Wireless](06-wireless/) | 6 | WiFi scan/deauth/crack, Bluetooth LE, packet sniff |
| 07 | [Spoofing & MITM](07-spoofing/) | 4 | ARP/DNS/DHCP spoof, network disrupt |
| 08 | [Post-Exploitation](08-postexploit/) | 8 | Win/Lin privesc, keylogger, cred harvester, log cleaner |
| 09 | [Miscellaneous](09-misc/) | 7 | Steganography, HTTP fuzz, SSL scan, report generator |
| 10 | [Cloud Security](10-cloud/) | 3 | AWS/Azure/GCP enumeration |
| 11 | [Container Security](11-containers/) | 2 | Docker & Kubernetes enumeration |
| 12 | [Forensics](12-forensics/) | 3 | Memory dump, disk analyzer, registry parser |
| 13 | [Tunneling](13-tunnel/) | 3 | TCP forward, DNS tunnel, ICMP tunnel |
| | **OCySec OSINT** | 1 | Standalone OSINT framework (email, username, phone, domain, IP) |

---

## Usage

### Interactive Mode
```bash
python hackerai.py
```
Shows a categorized menu → select category → select tool → configure options.

### Direct Mode (for automation)
```bash
python 01-network/port_scanner.py -t 192.168.1.1 -p 1-1000
python 02-webapp/sqli_tester.py -u "http://target.com/page?id=1"
python 03-password/hash_cracker.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -t md5 -w wordlist.txt
```

### Web Dashboard
```bash
python hackerai.py  →  press W
```
Opens a browser dashboard at `http://localhost:8080`.

---

## Privileged Tools

Some tools require root/admin access:

**Linux:** `sudo python <tool>.py`

**Windows:** Run CMD/PowerShell as Administrator

| Category | Tools |
|----------|-------|
| Network | network_scanner, packet_sniffer, mac_changer |
| Wireless | wifi_scanner, wifi_deauth, wifi_cracker |
| Spoofing | arp_spoofer, dns_spoofer, dhcp_spoofer, netcut |
| Tunneling | icmp_tunnel, dns_tunnel |

---

## Dependencies

```bash
pip install -r requirements.txt
```

Core packages: `scapy`, `requests`, `paramiko`, `beautifulsoup4`, `Pillow`, `pynput`, `cryptography`

---

## Tips

1. **Always get authorization** before testing any system
2. **Use VPN/proxy** during testing for anonymity
3. **Update wordlists** from SecLists for better results
4. **Combine tools** — recon first, then targeted exploitation
5. **Backup data** before running exploits

---

## Project Structure

```
tools/
├── 01-network/          Network scanning & reconnaissance
├── 02-webapp/           Web application security testing
├── 03-password/         Password cracking & bruteforce
├── 04-exploitation/     Exploitation & payload generation
├── 05-osint/            Open Source Intelligence
├── 06-wireless/         Wireless & packet analysis
├── 07-spoofing/         ARP/DNS/MITM attacks
├── 08-postexploit/      Post-exploitation & privesc
├── 09-misc/             Miscellaneous tools
├── 10-cloud/            Cloud security enumeration
├── 11-containers/       Container & K8s security
├── 12-forensics/        Digital forensics tools
├── 13-tunnel/           Tunneling & data exfiltration
├── hackerai.py          Master launcher
├── hackerai/            Launcher modules
├── ocysint/             Standalone OSINT framework
├── wordlists/           Custom wordlists
├── reports/templates/   Pentest report templates
├── tests/               Test suite
└── requirements.txt     Python dependencies
```

---

## Legal Disclaimer

These tools are intended for:
- Authorized penetration testing
- Security education & research
- CTF competitions
- Bug bounty programs

**Unauthorized use is illegal.** Always obtain written permission before testing any system you do not own.

---

<div align="center">

**Built for learning, testing, and defensive security operations.**

[Report Bug](https://github.com/vtino17/tools/issues) · [Request Feature](https://github.com/vtino17/tools/issues) · [Contribute](https://github.com/vtino17/tools)

</div>
