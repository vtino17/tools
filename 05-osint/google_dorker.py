#!/usr/bin/env python3
"""
Google Dorker - Generate and execute Google dorks
Membuat query Google dork yang powerful untuk recon.
Usage: python google_dorker.py -d example.com
"""
import argparse
import sys
import requests
import webbrowser


DORK_TEMPLATES = {
    "files": [
        'site:{d} filetype:pdf',
        'site:{d} filetype:doc',
        'site:{d} filetype:docx',
        'site:{d} filetype:xls',
        'site:{d} filetype:xlsx',
        'site:{d} filetype:csv',
        'site:{d} filetype:txt',
        'site:{d} filetype:log',
        'site:{d} filetype:sql',
        'site:{d} filetype:db',
        'site:{d} filetype:bak',
        'site:{d} filetype:conf',
        'site:{d} filetype:cfg',
        'site:{d} filetype:xml',
        'site:{d} filetype:json',
    ],
    "directories": [
        'site:{d} intitle:index.of',
        'site:{d} intitle:"index of"',
        'site:{d} "parent directory"',
        'site:{d} inurl:admin',
        'site:{d} inurl:login',
        'site:{d} inurl:wp-admin',
        'site:{d} inurl:phpmyadmin',
        'site:{d} inurl:backup',
        'site:{d} inurl:config',
    ],
    "vulnerable": [
        'site:{d} inurl:"php?id="',
        'site:{d} inurl:"asp?id="',
        'site:{d} inurl:"page?id="',
        'site:{d} inurl:"itemid="',
        'site:{d} inurl:"cat="',
        'site:{d} inurl:"productid="',
        'site:{d} inurl:"category="',
        'site:{d} inurl:"newsid="',
        'site:{d} inurl:"id=" intext:"Warning"',
        'site:{d} "Warning: mysql"',
        'site:{d} "Warning: pg_connect"',
        'site:{d} "Fatal error"',
        'site:{d} "You have an error in your SQL syntax"',
    ],
    "sensitive": [
        'site:{d} intext:"password" filetype:txt',
        'site:{d} intext:"password" filetype:log',
        'site:{d} intext:"username" filetype:csv',
        'site:{d} intitle:"login" intext:"admin"',
        'site:{d} intitle:"admin" intext:"login"',
        'site:{d} inurl:".env"',
        'site:{d} inurl:".git"',
        'site:{d} inurl:"web.config"',
        'site:{d} inurl:".htpasswd"',
        'site:{d} "BEGIN RSA PRIVATE KEY"',
        'site:{d} "BEGIN OPENSSH PRIVATE KEY"',
        'site:{d} "BEGIN PRIVATE KEY"',
        'site:{d} "AWS_SECRET"',
        'site:{d} "API_KEY"',
    ],
    "leaks": [
        'site:{d} "@gmail.com" filetype:txt',
        'site:{d} "@yahoo.com" filetype:txt',
        'site:{d} intext:"ssn" filetype:csv',
        'site:{d} intext:"credit card" filetype:txt',
        'site:{d} intext:"confidential"',
        'site:{d} intext:"internal use only"',
    ],
    "subdomains": [
        'site:*.{d}',
        '-site:www.{d} site:{d}',
        'site:*.{d} -www',
    ],
    "tech": [
        'site:{d} inurl:"/wp-content/"',
        'site:{d} inurl:"/wp-includes/"',
        'site:{d} inurl:"/administrator/"',
        'site:{d} inurl:"/cgi-bin/"',
        'site:{d} inurl:"/api/"',
        'site:{d} inurl:"/graphql"',
        'site:{d} inurl:".well-known/"',
        'site:{d} "powered by"',
        'site:{d} "X-Powered-By"',
    ],
}


def generate_dorks(domain, categories=None):
    if categories is None:
        categories = list(DORK_TEMPLATES.keys())
    dorks = []
    for cat in categories:
        if cat in DORK_TEMPLATES:
            for tmpl in DORK_TEMPLATES[cat]:
                dorks.append((cat, tmpl.format(d=domain)))
    return dorks


def execute_dork(query, count=10):
    """Execute a single Google dork"""
    try:
        r = requests.get("https://www.google.com/search",
                         params={"q": query, "num": count},
                         headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
                         timeout=10)
        return r.status_code == 200, r.text[:500] if r.status_code == 200 else None
    except:
        return False, None


def main():
    parser = argparse.ArgumentParser(description="Google Dork Generator & Executor")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-c", "--category", choices=list(DORK_TEMPLATES.keys()) + ["all"], default="all", help="Dork category")
    parser.add_argument("-o", "--output", help="Output to file")
    parser.add_argument("--execute", action="store_true", help="Try to execute dorks (may be blocked)")
    parser.add_argument("--no-urls", action="store_true", help="Don't generate search URLs")
    args = parser.parse_args()

    categories = list(DORK_TEMPLATES.keys()) if args.category == "all" else [args.category]
    dorks = generate_dorks(args.domain, categories)

    print(f"[*] Generated {len(dorks)} dorks for: {args.domain}")
    print("=" * 70)

    output = []
    for cat, dork in dorks:
        print(f"\n[{cat.upper()}]")
        print(f"  {dork}")
        if not args.no_urls:
            from urllib.parse import quote_plus
            url = f"https://www.google.com/search?q={quote_plus(dork)}"
            print(f"  {url}")
        output.append(f"[{cat}] {dork}")

    if args.output:
        with open(args.output, "w") as f:
            f.write("\n".join(output))
        print(f"\n[+] Dorks saved to: {args.output}")

    if args.execute:
        print("\n[*] Executing dorks (may be limited by Google)...")
        for cat, dork in dorks[:5]:
            print(f"[*] Trying: {dork}")
            success, content = execute_dork(dork)
            if success:
                print("    [+] Results received (check output for content)")
            else:
                print("    [-] Failed or blocked")

    print("=" * 70)


if __name__ == "__main__":
    main()

