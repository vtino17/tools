"""Phone number reconnaissance: format, negara, carrier, Numverify API."""

import re
from typing import Any, Dict, Optional

import requests

from core.config import get_api_key
from core.utils import normalize_phone, random_ua

# Mapping digit prefix kasar (bukan sumber resmi, untuk info umum saja)
PREFIX_HINTS = {
    "1": "US/Canada",
    "44": "UK",
    "62": "Indonesia",
    "60": "Malaysia",
    "65": "Singapore",
    "91": "India",
    "86": "China",
    "81": "Japan",
    "82": "Korea",
    "61": "Australia",
    "49": "Germany",
    "33": "France",
    "39": "Italy",
    "34": "Spain",
    "55": "Brazil",
    "52": "Mexico",
    "7": "Russia/Kazakhstan",
    "90": "Turkey",
    "966": "Saudi Arabia",
    "971": "UAE",
    "20": "Egypt",
    "27": "South Africa",
    "234": "Nigeria",
    "63": "Philippines",
    "66": "Thailand",
    "84": "Vietnam",
    "92": "Pakistan",
    "880": "Bangladesh",
    "94": "Sri Lanka",
    "977": "Nepal",
}

INMARSAT_RE = re.compile(r"^(\+?\d{1,3})(\d+)$")
VOIP_KEYWORDS = ["voip", "virtual", "fongo", "textnow", "google voice", "skype"]


def basic_phone_info(phone: str) -> Dict[str, Any]:
    norm = normalize_phone(phone)
    digits = norm.replace("+", "")
    country_code = ""
    matched_country = "Unknown"
    for cc, name in sorted(PREFIX_HINTS.items(), key=lambda x: -len(x[0])):
        if digits.startswith(cc):
            country_code = cc
            matched_country = name
            break
    length = len(digits)
    validity = 7 <= length <= 15
    return {
        "input": phone,
        "normalized": norm,
        "country_code": country_code,
        "country_hint": matched_country,
        "length": length,
        "is_valid_length": validity,
    }


def numverify_lookup(phone: str, api_key: str) -> Dict[str, Any]:
    """Query Numverify API (perlu API key)."""
    if not api_key:
        return {"skipped": True, "reason": "no_numverify_api_key"}
    try:
        r = requests.get(
            "http://apilayer.net/api/validate",
            params={"access_key": api_key, "number": phone, "format": 1},
            timeout=15,
            headers={"User-Agent": random_ua()},
        )
        data = r.json()
        return {
            "source": "numverify",
            "valid": data.get("valid"),
            "number": data.get("number"),
            "local_format": data.get("local_format"),
            "international_format": data.get("international_format"),
            "country_prefix": data.get("country_prefix"),
            "country_code": data.get("country_code"),
            "country_name": data.get("country_name"),
            "location": data.get("location"),
            "carrier": data.get("carrier"),
            "line_type": data.get("line_type"),
            "is_voip": any(k in (data.get("carrier", "") or "").lower() for k in VOIP_KEYWORDS)
            or (data.get("line_type") or "").lower() == "voip",
        }
    except Exception as e:
        return {"source": "numverify", "error": str(e)}


def run_phone_recon(phone: str) -> Dict[str, Any]:
    info = basic_phone_info(phone)
    api_key = get_api_key("numverify")
    nv = numverify_lookup(info["normalized"], api_key or "")
    info["numverify"] = nv
    return info
