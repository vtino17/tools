#!/usr/bin/env python3
"""
WordPress Vulnerability Scanner

Scanner keamanan untuk website WordPress. Mendeteksi versi, enumerasi user,
plugin themes, mengecek misconfigurasi umum, XMLRPC, REST API, dan direktori
uploads yang terekspos.

Usage:
    python wordpress_scanner.py -u https://target.com
    python wordpress_scanner.py -u https://target.com --enumerate u,p,t
    python wordpress_scanner.py -u https://target.com --enumerate u --threads 20
"""

import argparse
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    sys.exit("[!] Modul 'requests' tidak terinstall. Jalankan: pip install requests")

try:
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass

# ═══════════════════════════════
# PLUGIN WORDLIST (50+ common)
# ═══════════════════════════════

COMMON_PLUGINS = [
    "akismet", "contact-form-7", "woocommerce", "wordpress-seo", "jetpack",
    "wordfence", "wp-super-cache", "w3-total-cache", "elementor", "updraftplus",
    "all-in-one-seo-pack", "google-analytics-for-wordpress", "really-simple-ssl",
    "duplicate-post", "redirection", "wp-rocket", "imagify", "wp-smushit",
    "litespeed-cache", "wp-optimize", "broken-link-checker", "wordfence-security",
    "limit-login-attempts-reloaded", "wp-mail-smtp", "bbpress", "buddypress",
    "advanced-custom-fields", "revslider", "wp-file-manager", "duplicator",
    "all-in-one-wp-migration", "mailchimp-for-wp", "ninja-forms", "gravityforms",
    "wpforms-lite", "classic-editor", "disable-comments", "duplicate-page",
    "gdpr-cookie-compliance", "cookie-law-info", "popup-maker", "the-events-calendar",
    "regenerate-thumbnails", "easy-digital-downloads", "give", "members",
    "wp-migrate-db", "query-monitor", "user-role-editor", "wps-hide-login",
    "better-search-replace", "loginizer", "simple-history",
]

# ═══════════════════════════════
# HEADERS
# ═══════════════════════════════

def _get_headers():
    return {
        "User-Agent": "Mozilla/5.0 (compatible; WPScanner/1.0)",
        "Accept": "*/*",
        "Connection": "close",
    }


def _get_json_headers():
    h = _get_headers()
    h["Accept"] = "application/json"
    return h


# ═══════════════════════════════
# DETECT WORDPRESS
# ═══════════════════════════════

def detect_wordpress(url, timeout=10):
    """Deteksi apakah target adalah WordPress dan dapatkan versinya."""
    base = url.rstrip("/")
    info = {"is_wp": False, "version": None, "sources": []}

    try:
        resp = requests.get(base, headers=_get_headers(), timeout=timeout, verify=False)
    except RequestException:
        return info

    text = resp.text.lower()
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    # Cek indikator WordPress
    wp_signs = [
        "wp-content", "wp-includes", "wp-json", "wordpress",
        "<meta name=\"generator\" content=\"wordpress",
        "/wp-admin/", "/wp-login.php",
    ]
    wp_score = sum(1 for s in wp_signs if s in text)

    if wp_score >= 2 or "wp-content" in text:
        info["is_wp"] = True
    else:
        return info

    # Versi dari meta generator
    m = re.search(r'<meta\s+name="generator"\s+content="WordPress\s+([0-9.]+)"', resp.text, re.IGNORECASE)
    if m:
        info["version"] = m.group(1)
        info["sources"].append("meta-generator")

    # Versi dari readme.html
    if not info["version"]:
        try:
            r = requests.get(f"{base}/readme.html", headers=_get_headers(), timeout=timeout, verify=False)
            if r.status_code == 200:
                m = re.search(r"WordPress\s+Version\s+([0-9.]+)", r.text, re.IGNORECASE)
                m2 = re.search(r"Stable tag:\s*([0-9.]+)", r.text, re.IGNORECASE)
                if m:
                    info["version"] = m.group(1)
                    info["sources"].append("readme.html")
                elif m2:
                    info["version"] = m2.group(1)
                    info["sources"].append("readme.html")
        except RequestException:
            pass

    # Versi dari RSS feed
    if not info["version"]:
        try:
            r = requests.get(f"{base}/feed/", headers=_get_headers(), timeout=timeout, verify=False)
            if r.status_code == 200:
                m = re.search(r"<generator>https?://wordpress\.org/\?v=([0-9.]+)</generator>", r.text, re.IGNORECASE)
                if m:
                    info["version"] = m.group(1)
                    info["sources"].append("rss-feed")
        except RequestException:
            pass

    # Versi dari wp-json
    if not info["version"]:
        try:
            r = requests.get(f"{base}/wp-json/", headers=_get_headers(), timeout=timeout, verify=False)
            if r.status_code == 200:
                # Namespace 'wp/v2' indicates WP
                info["sources"].append("wp-json")
        except RequestException:
            pass

    return info


# ═══════════════════════════════
# ENUMERATION
# ═══════════════════════════════

def enumerate_users_via_rest(base_url, timeout=10):
    """Enumerasi user via WordPress REST API."""
    users = []
    page = 1
    while True:
        url = f"{base_url}/wp-json/wp/v2/users?per_page=100&page={page}"
        try:
            resp = requests.get(url, headers=_get_json_headers(), timeout=timeout, verify=False)
            if resp.status_code != 200:
                break
            data = resp.json()
            if not data:
                break
            for u in data:
                users.append({
                    "id": u.get("id"),
                    "name": u.get("name", "N/A"),
                    "slug": u.get("slug", "N/A"),
                    "link": u.get("link", ""),
                })
            page += 1
            if page > 10:  # safety limit
                break
        except RequestException:
            break
        except ValueError:
            break
    return users


def enumerate_users_via_author(base_url, timeout=10):
    """Enumerasi user via author archive."""
    users = []
    for author_id in range(1, 21):
        url = f"{base_url}/?author={author_id}"
        try:
            resp = requests.get(url, headers=_get_headers(), timeout=timeout, verify=False, allow_redirects=False)
            if resp.status_code in (301, 302):
                loc = resp.headers.get("Location", "")
                m = re.search(r"/author/([^/]+)/?", loc)
                if m:
                    users.append({"id": author_id, "slug": m.group(1), "name": "N/A", "link": loc})
                    continue
            if resp.status_code == 200 and "/author/" in resp.url:
                m = re.search(r"/author/([^/]+)/?", resp.url)
                if m:
                    users.append({"id": author_id, "slug": m.group(1), "name": "N/A", "link": resp.url})
        except RequestException:
            continue
    return users


def enumerate_plugins(base_url, threads=10, timeout=10):
    """Enumerasi plugin umum via path checking."""
    found = []
    session = requests.Session()

    def _check(plugin):
        try:
            # Cek readme.txt plugin
            r = session.get(f"{base_url}/wp-content/plugins/{plugin}/readme.txt",
                            headers=_get_headers(), timeout=timeout, verify=False)
            if r.status_code == 200 and ("===" in r.text[:200] or "Plugin Name" in r.text[:500]):
                version = "unknown"
                m = re.search(r"Stable tag:\s*([0-9.]+)", r.text)
                if m:
                    version = m.group(1)
                return {"name": plugin, "version": version, "source": "readme.txt"}
        except Exception:
            pass
        try:
            # Cek style.css (theme atau plugin dengan CSS)
            r = session.get(f"{base_url}/wp-content/plugins/{plugin}/",
                            headers=_get_headers(), timeout=timeout, verify=False)
            if r.status_code == 200:
                return {"name": plugin, "version": "unknown", "source": "directory"}
        except Exception:
            pass
        try:
            # Index listing
            r = session.get(f"{base_url}/wp-content/plugins/{plugin}/index.php",
                            headers=_get_headers(), timeout=timeout, verify=False)
            if r.status_code == 200:
                return {"name": plugin, "version": "unknown", "source": "index"}
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=min(threads, 30)) as executor:
        futures = {executor.submit(_check, p): p for p in COMMON_PLUGINS}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    return found


def enumerate_themes(base_url, timeout=10):
    """Cek informasi tema dari source code."""
    themes = []
    try:
        resp = requests.get(base_url, headers=_get_headers(), timeout=timeout, verify=False)
        text = resp.text
    except RequestException:
        return themes

    # Cari wp-content/themes/<theme-name>/
    matches = re.findall(r"wp-content/themes/([^/'\"]+)", text)
    seen = set()
    for theme_name in matches:
        if theme_name not in seen:
            seen.add(theme_name)
            # Coba dapatkan versi dari style.css
            version = "unknown"
            try:
                r = requests.get(f"{base_url}/wp-content/themes/{theme_name}/style.css",
                                 headers=_get_headers(), timeout=timeout, verify=False)
                if r.status_code == 200:
                    m = re.search(r"Version:\s*([0-9.]+)", r.text)
                    if m:
                        version = m.group(1)
            except RequestException:
                pass
            themes.append({"name": theme_name, "version": version, "source": "html"})

    return themes


# ═══════════════════════════════
# MISCONFIGURATION CHECKS
# ═══════════════════════════════

def check_misconfigs(base_url, timeout=10):
    """Cek berbagai misconfigurasi WordPress."""
    findings = []
    session = requests.Session()

    # XML-RPC
    try:
        r = session.get(f"{base_url}/xmlrpc.php", headers=_get_headers(), timeout=timeout, verify=False)
        if r.status_code in (200, 405):
            findings.append({
                "type": "xmlrpc",
                "severity": "MEDIUM",
                "description": "XML-RPC endpoint aktif - memungkinkan brute force dan pingback",
                "url": f"{base_url}/xmlrpc.php",
                "evidence": f"Status {r.status_code}",
            })
    except RequestException:
        pass

    # Test XML-RPC system.listMethods
    try:
        xml_body = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'
        r = session.post(f"{base_url}/xmlrpc.php", data=xml_body, headers={"Content-Type": "text/xml"},
                         timeout=timeout, verify=False)
        if "system.listMethods" in r.text or "wp.getUsers" in r.text:
            findings.append({
                "type": "xmlrpc_methods",
                "severity": "HIGH",
                "description": "XML-RPC memungkinkan enumerasi method (potensial brute force)",
                "url": f"{base_url}/xmlrpc.php",
                "evidence": "system.listMethods terpapar",
            })
    except RequestException:
        pass

    # wp-json exposed
    try:
        r = session.get(f"{base_url}/wp-json/", headers=_get_headers(), timeout=timeout, verify=False)
        if r.status_code == 200 and "namespaces" in r.text:
            findings.append({
                "type": "rest_api",
                "severity": "INFO",
                "description": "WP REST API terekspos (wp-json root)",
                "url": f"{base_url}/wp-json/",
                "evidence": "Root API dengan namespaces",
            })
    except RequestException:
        pass

    # wp-json wp/v2/users
    try:
        r = session.get(f"{base_url}/wp-json/wp/v2/users", headers=_get_json_headers(),
                        timeout=timeout, verify=False)
        if r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data, list) and len(data) > 0:
                    findings.append({
                        "type": "user_enum",
                        "severity": "MEDIUM",
                        "description": f"REST API user enumeration aktif ({len(data)} user)",
                        "url": f"{base_url}/wp-json/wp/v2/users",
                        "evidence": f"{len(data)} user terekspos",
                    })
            except ValueError:
                pass
    except RequestException:
        pass

    # Uploads directory listing
    try:
        r = session.get(f"{base_url}/wp-content/uploads/", headers=_get_headers(), timeout=timeout, verify=False)
        if r.status_code == 200 and ("Index of" in r.text or "Parent Directory" in r.text):
            findings.append({
                "type": "directory_listing",
                "severity": "HIGH",
                "description": "Directory listing AKTIF pada wp-content/uploads/",
                "url": f"{base_url}/wp-content/uploads/",
                "evidence": "Directory index terlihat",
            })
    except RequestException:
        pass

    # wp-config.php backup / exposed
    wp_config_checks = [
        "wp-config.php.bak",
        "wp-config.php~",
        "wp-config.php.old", 
        "wp-config.php.backup",
        "wp-config.php.save",
        "wp-config.txt",
    ]
    for path in wp_config_checks:
        try:
            r = session.get(f"{base_url}/{path}", headers=_get_headers(), timeout=timeout, verify=False)
            if r.status_code == 200 and ("DB_NAME" in r.text or "DB_PASSWORD" in r.text):
                findings.append({
                    "type": "wpconfig",
                    "severity": "CRITICAL",
                    "description": f"Backup wp-config.php terekspos: {path}",
                    "url": f"{base_url}/{path}",
                    "evidence": "Database credentials terlihat",
                })
                break
        except RequestException:
            pass

    # wp-content directory listing
    try:
        r = session.get(f"{base_url}/wp-content/", headers=_get_headers(), timeout=timeout, verify=False)
        if r.status_code == 200 and ("Index of" in r.text or "Parent Directory" in r.text):
            findings.append({
                "type": "directory_listing",
                "severity": "MEDIUM",
                "description": "Directory listing AKTIF pada wp-content/",
                "url": f"{base_url}/wp-content/",
                "evidence": "Directory index terlihat",
            })
    except RequestException:
        pass

    return findings


# ═══════════════════════════════
# MAIN
# ═══════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="WordPress Vulnerability Scanner - Deteksi versi, plugin, tema, user, & misconfig",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh:
  python wordpress_scanner.py -u https://target.com
  python wordpress_scanner.py -u https://target.com --enumerate u,p
  python wordpress_scanner.py -u https://target.com --enumerate u,p,t --threads 20
  python wordpress_scanner.py -u https://target.com/subdir/
        """,
    )
    parser.add_argument("-u", "--url", required=True, help="URL target WordPress (contoh: https://target.com)")
    parser.add_argument("-e", "--enumerate", default="u,p,t",
                        help="Jenis enumerasi: u=users, p=plugins, t=themes (default: u,p,t)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Thread paralel (default: 10)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout request (default: 10)")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")
    timeout = args.timeout
    threads = min(args.threads, 30)
    enum_opts = set(args.enumerate.lower().split(","))

    print(r"""
╦ ╦╔═╗  ╔═╗╔═╗╔═╗╔╗╔╔╗╔╔═╗╦═╗
║║║╠═╝  ╚═╗║  ╠═╣║║║║║║║╣ ╠╦╝
╚╩╝╩    ╚═╝╚═╝╩ ╩╝╚╝╝╚╝╚═╝╩╚═  v1.0
""")

    print(f"\n[*] Target: {base_url}")
    print(f"[*] Enumerasi: {', '.join(sorted(enum_opts))}")
    print(f"[*] Threads: {threads}")

    # ═══════ DETECTION
    print("\n[1] DETEKSI WORDPRESS\n" + "-" * 40)
    wp_info = detect_wordpress(base_url, timeout)

    if not wp_info["is_wp"]:
        print("[-] Target BUKAN WordPress (atau tidak terdeteksi).")
        print("[*] Mencoba melanjutkan scan sebagai website umum...")
    else:
        print("[+] WORDPRESS TERDETEKSI")
        if wp_info["version"]:
            print(f"[+] Versi: {wp_info['version']} (source: {', '.join(wp_info['sources'])})")
        else:
            print("[*] Versi tidak terdeteksi")
        print(f"[+] Detection sources: {', '.join(wp_info['sources']) or 'wp-content pattern'}")

    # ═══════ MISCONFIGURATIONS
    print("\n[2] MISCONFIGURATION CHECK\n" + "-" * 40)
    findings = check_misconfigs(base_url, timeout)
    if findings:
        for f in findings:
            sev = f["severity"]
            icon = "[!]" if sev in ("CRITICAL", "HIGH") else "[+]" if sev == "MEDIUM" else "[*]"
            print(f"{icon} [{sev}] {f['description']}")
            print(f"    URL: {f['url']}")
            if f.get("evidence"):
                print(f"    Evidence: {f['evidence']}")
    else:
        print("[-] Tidak ada misconfigurasi yang terdeteksi.")

    # ═══════ USER ENUMERATION
    if "u" in enum_opts:
        print("\n[3] USER ENUMERATION\n" + "-" * 40)
        users_rest = enumerate_users_via_rest(base_url, timeout)
        users_author = enumerate_users_via_author(base_url, timeout)

        all_users = {}
        for u in users_rest:
            all_users[u["slug"]] = u
        for u in users_author:
            if u["slug"] not in all_users:
                all_users[u["slug"]] = u

        if all_users:
            print(f"[+] Ditemukan {len(all_users)} user:")
            print(f"\n{'ID':<8} {'Username':<30} {'Link'}")
            print("-" * 70)
            for slug, u in sorted(all_users.items()):
                print(f"{u['id']:<8} {slug:<30} {u.get('link', 'N/A'):<40}")
        else:
            print("[-] Tidak dapat enumerasi user (mungkin REST API dibatasi).")

    # ═══════ PLUGIN ENUMERATION
    if "p" in enum_opts:
        print("\n[4] PLUGIN ENUMERATION\n" + "-" * 40)
        plugins = enumerate_plugins(base_url, threads, timeout)
        if plugins:
            print(f"[+] Ditemukan {len(plugins)} plugin:")
            print(f"\n{'Plugin Name':<45} {'Version':<15} {'Source'}")
            print("-" * 75)
            for p in sorted(plugins, key=lambda x: x["name"]):
                print(f"{p['name']:<45} {p['version']:<15} {p['source']}")
        else:
            print("[-] Tidak ada plugin umum yang terdeteksi.")

    # ═══════ THEME ENUMERATION
    if "t" in enum_opts:
        print("\n[5] THEME ENUMERATION\n" + "-" * 40)
        themes = enumerate_themes(base_url, timeout)
        if themes:
            print(f"[+] Ditemukan {len(themes)} tema:")
            print(f"\n{'Theme Name':<40} {'Version':<15}")
            print("-" * 55)
            for t in themes:
                print(f"{t['name']:<40} {t['version']:<15}")
        else:
            print("[-] Tidak dapat mendeteksi tema.")

    # ═══════ SUMMARY
    print("\n" + "=" * 60)
    print("  RINGKASAN")
    print("=" * 60)
    print(f"  WordPress    : {'Ya' if wp_info['is_wp'] else 'Tidak/Mungkin'}")
    print(f"  Versi       : {wp_info['version'] or 'Tidak terdeteksi'}")
    print(f"  Misconfig   : {len(findings)} temuan")
    if "u" in enum_opts:
        print(f"  Users       : {len(all_users) if 'all_users' in dir() else 'N/A'}")
    if "p" in enum_opts:
        print(f"  Plugins     : {len(plugins) if 'plugins' in dir() else 'N/A'} ditemukan")
    if "t" in enum_opts:
        print(f"  Themes      : {len(themes) if 'themes' in dir() else 'N/A'} ditemukan")


if __name__ == "__main__":
    main()
