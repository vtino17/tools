"""Breach check via HaveIBeenPwned API (resmi & legal)."""

import hashlib
import sys
from typing import Any, Dict, List

import requests

from core.config import get_api_key
from core.utils import random_ua

HIBP_API = "https://haveibeenpwned.com/api/v3"
HIBP_PWD_RANGE = "https://api.pwnedpasswords.com/range"


def check_email_breaches(email: str, api_key: str = "") -> Dict[str, Any]:
    """
    Query HIBP breach API.
    - Tanpa API key: rate-limited 1 request/IP, endpoint publik
    - Dengan API key: lebih cepat
    """
    headers = {"User-Agent": random_ua()}
    if api_key:
        headers["hibp-api-key"] = api_key
    try:
        r = requests.get(
            f"{HIBP_API}/breachedaccount/{email}",
            params={"truncateResponse": "false"},
            headers=headers,
            timeout=15,
        )
        if r.status_code == 200:
            breaches = r.json()
            return {
                "email": email,
                "breached": True,
                "count": len(breaches),
                "breaches": [
                    {
                        "name": b.get("Name"),
                        "domain": b.get("Domain"),
                        "breach_date": b.get("BreachDate"),
                        "pwn_count": b.get("PwnCount"),
                        "description": (b.get("Description") or "")[:200],
                        "data_classes": b.get("DataClasses", []),
                    }
                    for b in breaches
                ],
            }
        elif r.status_code == 404:
            return {"email": email, "breached": False, "count": 0, "breaches": []}
        elif r.status_code == 429:
            return {
                "email": email,
                "error": "rate_limited",
                "note": "Tambahkan API key HIBP di config.",
            }
        else:
            return {"email": email, "error": f"http_{r.status_code}", "body": r.text[:200]}
    except Exception as e:
        return {"email": email, "error": str(e)}


def check_email_pastes(email: str, api_key: str = "") -> Dict[str, Any]:
    headers = {"User-Agent": random_ua()}
    if api_key:
        headers["hibp-api-key"] = api_key
    try:
        r = requests.get(
            f"{HIBP_API}/pasteaccount/{email}",
            headers=headers,
            timeout=15,
        )
        if r.status_code == 200:
            return {"email": email, "pastes": r.json()}
        elif r.status_code == 404:
            return {"email": email, "pastes": []}
        else:
            return {"email": email, "error": f"http_{r.status_code}"}
    except Exception as e:
        return {"email": email, "error": str(e)}


def check_password_breach(password: str) -> Dict[str, Any]:
    """
    Cek password via k-anonymity (HASH SHA1, kirim 5 karakter pertama).
    Password TIDAKKAH dikirim utuh ke server - aman.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        r = requests.get(
            f"{HIBP_PWD_RANGE}/{prefix}", timeout=15, headers={"User-Agent": random_ua()}
        )
        if r.status_code != 200:
            return {"error": f"http_{r.status_code}"}
        for line in r.text.splitlines():
            h, count = line.split(":")
            if h.strip() == suffix:
                return {"pwned": True, "count": int(count), "sha1_prefix": prefix}
        return {"pwned": False, "count": 0, "sha1_prefix": prefix}
    except Exception as e:
        return {"error": str(e)}


def run_breach_check(email: str = "", password: str = "") -> Dict[str, Any]:
    """Run full breach check (email + paste + opsional password)."""
    api_key = get_api_key("hibp") or ""
    out: Dict[str, Any] = {}
    if email:
        out["email_breaches"] = check_email_breaches(email, api_key)
        out["email_pastes"] = check_email_pastes(email, api_key)
    if password:
        out["password_check"] = check_password_breach(password)
    return out
