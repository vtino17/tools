"""Domain & IP reconnaissance: WHOIS, DNS, subdomain, SSL, HTTP header."""

import asyncio
import socket
import ssl
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import aiohttp
import dns.resolver
import requests
import whois

from core.utils import is_valid_domain, random_ua


async def _crtsh_subdomains(session: aiohttp.ClientSession, domain: str) -> List[str]:
    """Ambil subdomain dari Certificate Transparency logs via crt.sh."""
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        async with session.get(url, timeout=20) as r:
            if r.status != 200:
                return []
            data = await r.json()
            names = set()
            for row in data:
                name = row.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lower().lstrip("*.")
                    if n.endswith("." + domain) and is_valid_domain(n):
                        names.add(n)
            return sorted(names)
    except Exception:
        return []


async def _hackertarget_subdomains(session: aiohttp.ClientSession, domain: str) -> List[str]:
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        async with session.get(url, timeout=20) as r:
            text = await r.text()
            if "error" in text.lower()[:50]:
                return []
            subs = []
            for line in text.splitlines():
                parts = line.split(",")
                if parts and parts[0]:
                    subs.append(parts[0].strip().lower())
            return [s for s in subs if is_valid_domain(s)]
    except Exception:
        return []


async def enumerate_subdomains(domain: str) -> List[str]:
    timeout = aiohttp.ClientTimeout(total=25)
    headers = {"User-Agent": random_ua()}
    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        crt, ht = await asyncio.gather(
            _crtsh_subdomains(session, domain),
            _hackertarget_subdomains(session, domain),
        )
    merged = set(crt) | set(ht)
    return sorted(merged)


def whois_lookup(domain: str) -> Dict[str, Any]:
    try:
        w = whois.whois(domain)

        def _fmt(v):
            if isinstance(v, list):
                return [str(x) for x in v]
            if isinstance(v, datetime):
                return v.isoformat()
            return str(v) if v is not None else None

        return {
            "registrar": _fmt(w.registrar),
            "creation_date": _fmt(w.creation_date),
            "expiration_date": _fmt(w.expiration_date),
            "updated_date": _fmt(w.updated_date),
            "name_servers": _fmt(w.name_servers),
            "status": _fmt(w.status),
            "emails": _fmt(w.emails),
            "org": _fmt(w.org),
            "country": _fmt(w.country),
        }
    except Exception as e:
        return {"error": str(e)}


DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]


def dns_records(domain: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for t in DNS_TYPES:
        try:
            answers = dns.resolver.resolve(domain, t, lifetime=5)
            out[t] = [str(r) for r in answers]
        except Exception:
            out[t] = []
    return out


def resolve_ips(domain: str) -> List[str]:
    ips: List[str] = []
    try:
        for info in socket.getaddrinfo(domain, None):
            ips.append(info[4][0])
    except Exception:
        pass
    return sorted(set(ips))


def ssl_info(domain: str, port: int = 443) -> Dict[str, Any]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                # Cert fields
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                san = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
                not_before = cert.get("notBefore")
                not_after = cert.get("notAfter")
                return {
                    "subject_cn": subject.get("commonName"),
                    "issuer_cn": issuer.get("commonName"),
                    "issuer_org": issuer.get("organizationName"),
                    "valid_from": not_before,
                    "valid_to": not_after,
                    "sans": san,
                    "tls_version": ssock.version(),
                }
    except Exception as e:
        return {"error": str(e)}


async def http_headers(domain: str) -> Dict[str, Any]:
    url = domain if domain.startswith("http") else f"https://{domain}"
    timeout = aiohttp.ClientTimeout(total=12)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(
                url, allow_redirects=True, headers={"User-Agent": random_ua()}
            ) as r:
                return {
                    "final_url": str(r.url),
                    "status": r.status,
                    "server": r.headers.get("Server"),
                    "content_type": r.headers.get("Content-Type"),
                    "powered_by": r.headers.get("X-Powered-By"),
                    "hsts": r.headers.get("Strict-Transport-Security"),
                    "csp": r.headers.get("Content-Security-Policy"),
                    "x_frame": r.headers.get("X-Frame-Options"),
                    "headers": dict(r.headers),
                }
    except Exception as e:
        return {"error": str(e)}


def run_domain_recon(domain: str, do_subdomain: bool = True) -> Dict[str, Any]:
    if not is_valid_domain(domain):
        return {"domain": domain, "valid": False, "error": "format domain tidak valid"}
    domain = domain.lower().strip()
    out: Dict[str, Any] = {
        "domain": domain,
        "valid": True,
        "ips": resolve_ips(domain),
        "dns": dns_records(domain),
        "whois": whois_lookup(domain),
        "ssl": ssl_info(domain),
    }
    try:
        out["http"] = asyncio.run(http_headers(domain))
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            out["http"] = loop.run_until_complete(http_headers(domain))
        finally:
            loop.close()
    if do_subdomain:
        try:
            out["subdomains"] = enumerate_subdomains(domain)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                out["subdomains"] = loop.run_until_complete(enumerate_subdomains(domain))
            finally:
                loop.close()
    return out
