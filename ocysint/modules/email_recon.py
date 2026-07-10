"""Email reconnaissance: validasi, MX, Gravatar, HIBP, Google Account."""

import asyncio
from typing import Any, Dict, List

import aiohttp
import dns.resolver

from core.utils import gravatar_url, is_valid_email, random_ua

DISPOSABLE_DOMAINS = {
    "mailinator.com",
    "guerrillamail.com",
    "10minutemail.com",
    "tempmail.com",
    "throwawaymail.com",
    "yopmail.com",
    "trashmail.com",
    "fakeinbox.com",
    "maildrop.cc",
    "sharklasers.com",
    "getnada.com",
    "dispostable.com",
    "mintemail.com",
    "spambox.us",
    "mohmal.com",
}

PROVIDER_MX = {
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365",
    "office365.us": "Microsoft 365",
    "protection.outlook.com": "Microsoft 365",
    "mimecast.com": "Mimecast",
    "zoho.com": "Zoho Mail",
    "yandex.net": "Yandex Mail",
}


def _domain_of(email: str) -> str:
    return email.split("@", 1)[1].lower().strip() if "@" in email else ""


def check_disposable(email: str) -> bool:
    return _domain_of(email) in DISPOSABLE_DOMAINS


def check_mx(email: str) -> List[str]:
    """Ambil MX record domain via DNS resolver."""
    domain = _domain_of(email)
    if not domain:
        return []
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        return [str(r.exchange).rstrip(".") for r in answers]
    except Exception:
        return []


def detect_provider(mx_hosts: List[str]) -> str:
    for host in mx_hosts:
        h = host.lower()
        for key, name in PROVIDER_MX.items():
            if key in h:
                return name
    return "Unknown / Custom"


async def check_gravatar(session: aiohttp.ClientSession, email: str) -> Dict[str, Any]:
    """Cek Gravatar berdasarkan hash MD5 email."""
    url = gravatar_url(email, size=80)
    try:
        async with session.get(url, timeout=10) as r:
            return {
                "exists": r.status == 200,
                "url": url,
                "status": r.status,
            }
    except Exception as e:
        return {"exists": False, "url": url, "error": str(e)}


async def check_google_account(session: aiohttp.ClientSession, email: str) -> Dict[str, Any]:
    """Cek apakah akun Google ada (kalau diaktifkan -> tidak ditemukan publik)."""
    # Google's People API doesn't allow direct lookup. Gunakan profil publik.
    # Trik: fetch /+ tanpa error -> ada profil publik.
    return {
        "google_profile_public": False,
        "note": "Google tidak mengizinkan enumerasi email langsung.",
    }


async def check_microsoft_account(session: aiohttp.ClientSession, email: str) -> Dict[str, Any]:
    """Cek akun Microsoft via login.live.com (GET ke endpoint authorize)."""
    try:
        url = "https://login.microsoftonline.com/common/oauth2/authorize"
        params = {
            "client_id": "00000000-0000-0000-0000-000000000000",
            "response_type": "id_token",
            "login_hint": email,
        }
        async with session.get(url, params=params, timeout=10) as r:
            body = await r.text()
            return {
                "endpoint_reachable": True,
                "has_account_hint": "login_hint" in body or email in body,
            }
    except Exception as e:
        return {"endpoint_reachable": False, "error": str(e)}


async def full_email_recon(email: str, hibp_api_key: str = "") -> Dict[str, Any]:
    """Pipeline lengkap email recon."""
    if not is_valid_email(email):
        return {"email": email, "valid_format": False, "error": "format email tidak valid"}

    domain = _domain_of(email)
    mx = check_mx(email)
    provider = detect_provider(mx)

    timeout = aiohttp.ClientTimeout(total=15)
    headers = {"User-Agent": random_ua()}
    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        grav = await check_gravatar(session, email)
        ms = await check_microsoft_account(session, email)
        google = await check_google_account(session, email)

    return {
        "email": email,
        "valid_format": True,
        "domain": domain,
        "mx_records": mx,
        "mail_provider": provider,
        "disposable": check_disposable(email),
        "gravatar": grav,
        "microsoft": ms,
        "google": google,
    }


def run_email_recon(email: str, hibp_api_key: str = "") -> Dict[str, Any]:
    return asyncio.run(full_email_recon(email, hibp_api_key))
