#!/usr/bin/env python3
"""
Email Harvester - Extract email addresses from web pages
Mengumpulkan alamat email dari halaman web, search engines.
Usage: python email_harvester.py -d example.com -l 100
"""
import requests
import argparse
import sys
import re
import time
from urllib.parse import urljoin, urlparse, quote_plus


EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')


def extract_emails_from_text(text):
    return list(set(EMAIL_REGEX.findall(text)))


def crawl_url(session, url, depth, visited, current_depth=0):
    if current_depth > depth or url in visited:
        return []
    visited.add(url)

    try:
        r = session.get(url, timeout=10, verify=False, headers={"User-Agent": "Mozilla/5.0"})
        emails = extract_emails_from_text(r.text)

        # Extract links for further crawling
        if current_depth < depth:
            links = re.findall(r'href=["\']?([^"\'#\s<>]+)', r.text, re.IGNORECASE)
            for link in links[:30]:
                absolute = urljoin(url, link)
                if urlparse(absolute).netloc == urlparse(url).netloc:
                    emails.extend(crawl_url(session, absolute, depth, visited, current_depth + 1))
        return emails
    except requests.exceptions.RequestException:
        return []


def google_search(session, query, pages=1):
    """Search Google for emails"""
    emails = []
    for page in range(pages):
        try:
            url = f"https://www.google.com/search?q={quote_plus(query)}&start={page*10}"
            r = session.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
            emails.extend(extract_emails_from_text(r.text))
            time.sleep(2)
        except:
            pass
    return emails


def bing_search(session, query, pages=1):
    """Search Bing for emails"""
    emails = []
    for page in range(pages):
        try:
            url = f"https://www.bing.com/search?q={quote_plus(query)}&first={page*10+1}"
            r = session.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})
            emails.extend(extract_emails_from_text(r.text))
            time.sleep(2)
        except:
            pass
    return emails


def main():
    parser = argparse.ArgumentParser(description="Email Address Harvester")
    parser.add_argument("-d", "--domain", help="Target domain")
    parser.add_argument("-u", "--url", help="Single URL to scan")
    parser.add_argument("-l", "--limit", type=int, default=100, help="Max emails to find")
    parser.add_argument("--depth", type=int, default=1, help="Crawl depth")
    parser.add_argument("--search", help="Search query (e.g. '@example.com')")
    parser.add_argument("--engine", choices=["google", "bing"], default="bing", help="Search engine")
    args = parser.parse_args()

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})

    all_emails = set()

    if args.url:
        print(f"[*] Scanning {args.url}")
        visited = set()
        emails = crawl_url(session, args.url, args.depth, visited)
        all_emails.update(emails)

    if args.domain:
        print(f"[*] Crawling {args.domain}")
        visited = set()
        start_urls = [
            f"https://{args.domain}",
            f"http://{args.domain}",
            f"https://{args.domain}/contact",
            f"https://{args.domain}/contact-us",
            f"https://{args.domain}/about",
            f"https://{args.domain}/team",
            f"https://{args.domain}/staff",
            f"https://{args.domain}/leadership",
        ]
        for url in start_urls:
            emails = crawl_url(session, url, args.depth, visited)
            all_emails.update(emails)
            if len(all_emails) >= args.limit:
                break

    if args.search:
        print(f"[*] Searching {args.engine} for: {args.search}")
        if args.engine == "google":
            emails = google_search(session, args.search, 3)
        else:
            emails = bing_search(session, args.search, 3)
        all_emails.update(emails)

    print("\n" + "=" * 70)
    print(f"[+] Found {len(all_emails)} unique email(s):")
    print("=" * 70)
    for email in sorted(all_emails)[:args.limit]:
        print(f"  {email}")
    print("=" * 70)


if __name__ == "__main__":
    main()

