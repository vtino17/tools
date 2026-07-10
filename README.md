# HackerAI Tools Collection

Koleksi lengkap **85 tools** hacking dan penetration testing yang ditulis dalam Python. Mencakup **13 kategori**: network scanning, web application security, exploitation, OSINT, wireless, spoofing, post-exploitation, cloud security, container security, forensics, tunneling, dan lain-lain.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run master menu (interactive with sub-menu)
python hackerai.py

# List semua 84 tools
python hackerai.py --list

# Check dependencies
python hackerai.py  (lalu pilih D)

# Web Dashboard
python hackerai.py  (lalu pilih W)  →  browse http://localhost:8080
```

## Struktur Folder

```
tools-hacking/
 01-network/        - Network scanning & reconnaissance (8 tools)
 02-webapp/         - Web application security testing (10 tools)
 03-password/       - Password cracking & bruteforce (5 tools)
 04-exploitation/   - Exploitation & payload generation (17 tools)
 05-osint/          - Open Source Intelligence (4 tools)
 06-wireless/       - Wireless & packet analysis (5 tools)
 07-spoofing/       - ARP/DNS/MITM attacks (4 tools)
 08-postexploit/    - Post-exploitation & privesc (7 tools)
 09-misc/           - Miscellaneous tools (6 tools)
 10-cloud/          - Cloud security enumeration (3 tools) ⭐NEW
 11-containers/     - Container & K8s security (2 tools) ⭐NEW
 12-forensics/      - Digital forensics tools (3 tools) ⭐NEW
 13-tunnel/         - Tunneling & data exfil (3 tools) ⭐NEW
 wordlists/         - Custom wordlists (common, subdomains, passwords, users)
 reports/templates/ - Pentest report templates (HTML & Markdown)
 hackerai.py        - Master launcher (77+ tools)
 requirements.txt   - Python dependencies
```

## Daftar Tools (85 tools)

### 01 - Network Recon (9 tools)
- **network_scanner.py** - ARP-based host discovery pada subnet
- **port_scanner.py** - Multi-threaded TCP port scanner dengan banner grabbing
- **subdomain_enum.py** - DNS-based subdomain enumerator
- **banner_grabber.py** - Service version detection via banner
- **dns_zone_transfer.py** - DNS AXFR zone transfer tester
- **smb_scanner.py** - SMB enumeration & share listing
- **snmp_scanner.py** - SNMP community string brute + info extraction
- **ldap_scanner.py** - LDAP enumeration & anonymous bind
- **reverse_proxy_analyzer.py** - CDN & reverse proxy detector ⭐

### 02 - Web Application Security (10 tools)
- **web_scanner.py** - Comprehensive web security scanner
- **sqli_tester.py** - SQL injection detection (error-based & time-based)
- **xss_scanner.py** - XSS detection (reflected)
- **directory_bruteforce.py** - Hidden directory/file discovery
- **cms_detector.py** - CMS & technology identification
- **wordpress_scanner.py** - WordPress vulnerability & user enumeration
- **backup_finder.py** - Backup/recovery file scanner
- **git_exposure.py** - Git/SVN/DVCS config exposure scanner
- **api_fuzzer.py** - REST API & GraphQL endpoint fuzzer
- **cookie_analyzer.py** - Cookie security analyzer & JWT inspector ⭐

### 03 - Password & Bruteforce (7 tools)
- **hash_cracker.py** - Multi-algorithm hash cracker (MD5/SHA/NTLM)
- **hash_identifier.py** - Hash type detection (20+ algorithms) ⭐
- **http_bruteforce.py** - HTTP login bruteforcer (Basic/Digest/Form)
- **ssh_bruteforce.py** - SSH login bruteforcer
- **ftp_bruteforce.py** - FTP login bruteforcer
- **rdp_bruteforce.py** - RDP login bruteforcer ⭐
- **password_generator.py** - Strong password generator & strength checker

### 04 - Exploitation (18 tools)
- **listener.py** - Multi-client reverse shell listener
- **msfvenom_helper.py** - msfvenom command generator untuk 30+ payloads
- **payload_generator.py** - Encoded payload (XOR/base64/hex/unicode)
- **shellcode_encoder.py** - Shellcode encoding (XOR/alpha-mixed/NOP sled)
- **cve_finder.py** - CVE database search via NVD API
- **exploit_finder.py** - Exploit search di Exploit-DB & GitHub
- **persistence.py** - Persistence script generator (Windows/Linux)
- **lfi_tester.py** - LFI/RFI scanner (path traversal + wrappers)
- **command_injection.py** - OS command injection tester
- **ssti_scanner.py** - Server-Side Template Injection scanner
- **xxe_tester.py** - XML External Entity vulnerability tester
- **file_upload_tester.py** - File upload bypass & shell upload
- **cors_tester.py** - CORS misconfiguration checker
- **idor_tester.py** - IDOR (Insecure Direct Object Reference) scanner
- **csrf_tester.py** - CSRF vulnerability tester + PoC generator
- **jwt_analyzer.py** - JWT token decode/attack/bruteforce
- **waf_detector.py** - WAF detection with bypass encoding tests
- **web_shell_generator.py** - PHP/ASP/JSP web shell generator ⭐

### 05 - OSINT (4 tools)
- **osint_tool.py** - Multi-source OSINT gathering
- **email_harvester.py** - Email harvester dengan crawling
- **username_finder.py** - Username existence di 80+ platform
- **google_dorker.py** - Google dork generator (50+ dorks)

### 06 - Wireless & Sniffing (6 tools)
- **wifi_scanner.py** - WiFi network scanner (Linux)
- **wifi_deauth.py** - WiFi deauthentication attack
- **wifi_cracker.py** - WPA/WPA2 handshake capture & crack
- **packet_sniffer.py** - Network packet sniffer dengan PCAP output
- **bluetooth_scanner.py** - Bluetooth LE scanner
- **mac_changer.py** - MAC address changer (Windows/Linux)

### 07 - Spoofing & MITM (4 tools)
- **arp_spoofer.py** - ARP cache poisoning untuk MITM
- **dns_spoofer.py** - DNS response spoofing
- **dhcp_spoofer.py** - DHCP rogue server
- **netcut.py** - ARP-based network disruptor

### 08 - Post-Exploitation (8 tools)
- **win_privesc.py** - Windows privilege escalation checker
- **lin_privesc.py** - Linux privilege escalation checker
- **kernel_exploit_checker.py** - Kernel exploit suggester (60+ CVEs)
- **keylogger.py** - Keylogger (educational/authorized)
- **screenshot.py** - Screenshot tool
- **credential_harvester.py** - Credential search di host
- **log_cleaner.py** - Event logs & trace cleaner (Win/Linux)
- **dll_hijacker.py** - DLL hijacking opportunity finder ⭐

### 09 - Miscellaneous (7 tools)
- **steganography.py** - LSB steganography di image
- **stego_detector.py** - Steganalysis & detection ⭐
- **http_fuzzer.py** - HTTP parameter/path fuzzer
- **ddos_tool.py** - Authorized HTTP load tester
- **ssl_scanner.py** - SSL/TLS configuration scanner
- **network_discovery.py** - Multi-protocol network discovery
- **report_generator.py** - Export scan results to HTML/JSON/Markdown

### 10 - Cloud Security (3 tools) ⭐NEW
- **aws_enum.py** - AWS S3/IAM/EC2 enumeration
- **azure_enum.py** - Azure AD/Storage enumeration
- **gcp_enum.py** - GCP bucket/IAM/VM enumeration

### 11 - Container Security (2 tools) ⭐NEW
- **docker_enum.py** - Docker daemon enumeration & escape checks
- **k8s_enum.py** - Kubernetes RBAC/pod/secret enumeration

### 12 - Forensics (3 tools) ⭐NEW
- **memory_dump.py** - Memory acquisition & analysis
- **disk_analyzer.py** - MBR/GPT partition & file recovery
- **registry_reader.py** - Offline registry hive parser

### 13 - Tunneling (3 tools)
- **port_forward.py** - TCP port forwarder / SOCKS relay
- **dns_tunnel.py** - DNS tunneling (server + client)
- **icmp_tunnel.py** - ICMP tunneling (server + client)

### Bonus - OCySec OSINT Framework (`ocysint/`)
- **run.py** - Standalone OSINT framework (email, username, phone, domain, IP, dork)
- 9 modul + 3 format report (TXT/JSON/HTML)

## Cara Penggunaan

### Mode Interaktif (Sub-Menu)
```bash
python hackerai.py
```
Akan muncul menu utama 13 kategori → pilih kategori → pilih tool.

### Quick Actions
```bash
python hackerai.py --list    # List semua 84 tools
python hackerai.py           # lalu pilih D = Check dependencies
python hackerai.py           # lalu pilih W = Web Dashboard (port 8080)
```

### Mode Langsung
```bash
# Contoh: SQL injection test
python 02-webapp/sqli_tester.py -u "http://target.com/page?id=1"

# Contoh: Port scan
python 01-network/port_scanner.py -t 192.168.1.1 -p 1-1000

# Contoh: Generate hash cracker
python 03-password/hash_cracker.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -t md5 -w wordlist.txt
```

## Tools yang Butuh Root/Admin

Tools berikut butuh privilege tinggi:
- network_scanner.py, wifi_scanner.py, wifi_deauth.py, wifi_cracker.py
- packet_sniffer.py, mac_changer.py, arp_spoofer.py
- dns_spoofer.py, dhcp_spoofer.py, netcut.py
- icmp_tunnel.py, dns_tunnel.py

Jalankan dengan:
- **Linux**: `sudo python <tool>.py`
- **Windows**: Buka CMD/PowerShell sebagai Administrator

## Dependencies

Install semua dependencies:
```bash
pip install -r requirements.txt
```

Atau install sesuai kebutuhan:
```bash
pip install scapy requests paramiko beautifulsoup4 Pillow pynput
```

## Tips

1. **Selalu dapatkan authorization** sebelum testing sistem apapun
2. **Gunakan VPN/proxy** saat testing untuk anonimitas
3. **Update wordlist** dari SecLists untuk hasil terbaik
4. **Kombinasikan tools** - recon dulu, baru targeted exploit
5. **Backup data** sebelum melakukan exploitation

## Legal Disclaimer

Tools ini dibuat untuk:
- Authorized penetration testing
- Educational purposes
- Security research
- CTF competitions
- Bug bounty programs

Penyalahgunaan tools ini untuk aktivitas ilegal adalah tanggung jawab pengguna sepenuhnya. Selalu dapatkan izin tertulis sebelum melakukan testing.

