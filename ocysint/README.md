# OCySec OSINT Framework

Modular OSINT (Open Source Intelligence) framework untuk **authorized penetration testing & security assessment**.

> ⚠️ **DISCLAIMER:** Tool ini hanya untuk OSINT pada target yang Anda punya izin tertulis. Penyalahgunaan dapat melanggar hukum (UU ITE, GDPR, dll).

## ✨ Fitur

| Modul | Fungsi |
|-------|--------|
| **email** | Validasi format, MX lookup, Gravatar, HIBP breach, deteksi provider |
| **username** | Enumerasi 50+ platform (GitHub, Twitter, IG, Reddit, dll) |
| **phone** | Normalisasi, country/carrier lookup, integrasi Numverify |
| **domain** | WHOIS, DNS records, subdomain (crt.sh + HackerTarget), SSL cert, HTTP headers |
| **ip** | Shodan + Censys lookup, port/service/CVE |
| **file** | Extract EXIF (termasuk GPS), PDF metadata, DOCX metadata, hash |
| **dork** | Generate 30+ Google Dork siap pakai per kategori |
| **password** | Cek password breach via HIBP k-anonymity (aman, password TIDAK dikirim utuh) |
| **breach** | HIBP breach & paste check |
| **leak** | DeHashed/IntelX/LeakCheck (perlu API key) |
| **config** | Kelola API key tersimpan |

## 📦 Instalasi

```bash
# Windows
run.bat

# Linux/macOS
chmod +x run.sh
./run.sh
```

Atau manual:
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## 🚀 Cara Pakai

### Email reconnaissance
```bash
python run.py email target@company.com --breach --leak --report html
```

### Username enumeration
```bash
python run.py username johndoe -c 30
```

### Phone lookup
```bash
python run.py phone +6281234567890
```

### Domain reconnaissance
```bash
python run.py domain example.com --shodan --report all
```

### IP / Shodan
```bash
python run.py ip 1.2.3.4
```

### Extract metadata
```bash
python run.py file photo.jpg
```

### Generate dorks
```bash
python run.py dork example.com
python run.py dork example.com --category "Files暴露 (filetype)"
```

### Cek password bocor
```bash
python run.py password "MyP@ssw0rd123"
```

### Auto-detect target
```bash
python run.py all target@company.com
```

## 🔑 Setup API Key

```bash
python run.py config list
python run.py config set hibp <your-key>
python run.py config set shodan <your-key>
python run.py config set numverify <your-key>
python run.py config set dehashed <email:key>
python run.py config set intelx <your-key>
python run.py config set leakcheck <your-key>
python run.py config set censys_id <id>
python run.py config set censys_secret <secret>
python run.py config unset hibp
```

Config disimpan di `~/.ocysint/config.json` (chmod 600).

### API key gratis / gratis tier

| Service | URL | Free? |
|---------|-----|-------|
| HaveIBeenPwned | https://haveibeenpwned.com/API/Key | Berbayar (~$3.5/bln) |
| Shodan | https://shodan.io | Free tier terbatas |
| Numverify | https://numverify.com | Free tier 100/bulan |
| VirusTotal | https://virustotal.com | Free 4 req/menit |
| Hunter.io | https://hunter.io | Free 25/bulan |
| Censys | https://censys.io | Free tier |
| DeHashed | https://dehashed.com | Berbayar |
| IntelX | https://intelx.io | Free tier |

> 💡 **Breach DB**: Tool ini TIDAK menyertakan database breach dump. Anda bisa query HIBP via API resmi, atau gunakan DeHashed/IntelX jika punya subscription.

## 📊 Output Report

Laporan otomatis dalam format TXT, JSON, dan HTML (dengan tampilan dark theme). Disimpan di `ocysint/reports/` (atau path yang Anda tentukan dengan `--output`).

Contoh laporan HTML punya card layout, badge true/false berwarna, dan link langsung ke URL profil.

## 📁 Struktur

```
ocysint/
├── core/
│   ├── banner.py      # ASCII banner & warna
│   ├── config.py      # API key management
│   └── utils.py       # HTTP, regex, async helper
├── modules/
│   ├── email_recon.py
│   ├── username_recon.py
│   ├── phone_recon.py
│   ├── domain_recon.py
│   ├── shodan_recon.py
│   ├── breach_check.py
│   ├── leak_check.py
│   ├── google_dork.py
│   └── metadata.py
├── reports/
│   └── generator.py   # TXT/JSON/HTML
├── data/              # (reserved - untuk plugin data)
├── wordlists/         # (reserved - untuk user-supplied wordlist)
├── run.py             # CLI entry point
├── run.bat            # Windows launcher
├── run.sh             # Unix launcher
└── requirements.txt
```

## 🔒 Etika & Legal

- **Selalu dapat izin tertulis** sebelum melakukan OSINT pada target/bindari/instansi.
- Jangan gunakan untuk stalking, doxxing, atau骚扰.
- Hormati ToS platform (rate limit, robots.txt).
- Data breach yang ditemukan harus dilaporkan ke pemilik & tidak diekspos publik.
- Tool ini TIDAK berisi dump credential curian - semua query ke API resmi.

## 📜 Lisensi

Tool ini untuk Authorized Penetration Testing saja. Penggunaan tanpa izin adalah ilegal.

