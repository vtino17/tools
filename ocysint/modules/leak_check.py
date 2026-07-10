"""
Leak check via API pihak ketiga resmi (DeHashed, IntelligenceX, LeakCheck).

⚠ Modul ini HANYA menghubungkan ke API resmi. Tidak ada dump breach yang
disertakan atau di-cache lokal. Anda harus menyediakan API key Anda sendiri
(berlangganan) - lihat https://www.dehashed.com, https://intelx.io, dll.

Semua permintaan dilakukan secara live ke server resmi.
"""

import base64
from typing import Any, Dict, List

import requests

from core.config import get_api_key
from core.utils import random_ua


def dehashed_search(query: str, field: str = "email", api_key: str = "") -> Dict[str, Any]:
    """
    Query DeHashed (perlu subscription API key).
    field: email | username | password | ip_address | name | phone | domain
    """
    if not api_key:
        return {
            "skipped": True,
            "reason": "no_dehashed_api_key",
            "note": "Set via: ocysint config set dehashed <key>",
        }
    user, _, key = api_key.partition(":")
    if not key:
        return {"error": "Format DeHashed key harus 'email:key'"}
    try:
        r = requests.post(
            "https://api.dehashed.com/search?query=",
            data={"query": f'"{field}":"{query}"', "page": 0},
            auth=(user, key),
            headers={"User-Agent": random_ua(), "Accept": "application/json"},
            timeout=20,
        )
        if r.status_code == 200:
            data = r.json()
            entries = data.get("entries", [])[:50]  # batasi 50 hasil
            return {
                "source": "dehashed",
                "total": data.get("total", 0),
                "balance": data.get("balance"),
                "entries": entries,
            }
        return {"error": f"http_{r.status_code}", "body": r.text[:200]}
    except Exception as e:
        return {"error": str(e)}


def intelx_search(query: str, api_key: str = "", media_type: int = 0) -> Dict[str, Any]:
    """
    Query Intelligence X (perlu API key). Hanya untuk riset/OSINT legal.
    """
    if not api_key:
        return {"skipped": True, "reason": "no_intelx_api_key"}
    headers = {"x-key": api_key, "User-Agent": random_ua()}
    try:
        r = requests.post(
            "https://2.intelx.io/intelligent/search",
            json={
                "term": query,
                "media": media_type,
                "buckets": [],
                "timeout": 15,
                "maxresults": 50,
            },
            headers=headers,
            timeout=20,
        )
        if r.status_code != 200:
            return {"error": f"http_{r.status_code}"}
        search_id = r.json().get("id")
        if not search_id:
            return {"error": "no_search_id"}
        r2 = requests.get(
            f"https://2.intelx.io/intelligent/search/result?id={search_id}&statistics=1&previewlines=3",
            headers=headers,
            timeout=20,
        )
        if r2.status_code != 200:
            return {"error": f"http_{r2.status_code}"}
        return {"source": "intelx", "results": r2.json().get("records", [])[:50]}
    except Exception as e:
        return {"error": str(e)}


def leakcheck_search(query: str, api_key: str = "") -> Dict[str, Any]:
    """
    LeakCheck.io public API (perlu API key jika di luar free tier).
    """
    if not api_key:
        return {"skipped": True, "reason": "no_leakcheck_api_key"}
    try:
        r = requests.get(
            "https://leakcheck.io/api/public",
            params={"check": query, "key": api_key},
            headers={"User-Agent": random_ua()},
            timeout=15,
        )
        if r.status_code == 200:
            return {"source": "leakcheck", "data": r.json()}
        return {"error": f"http_{r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def run_leak_check(query: str, source: str = "auto") -> Dict[str, Any]:
    """
    Jalankan leak check di sumber yang diminta.
    source: 'auto' | 'dehashed' | 'intelx' | 'leakcheck'
    """
    out: Dict[str, Any] = {"query": query, "sources": {}}
    sources_to_try: List[str]
    if source == "auto":
        sources_to_try = [s for s in ("dehashed", "intelx", "leakcheck") if get_api_key(s)]
    else:
        sources_to_try = [source]

    if not sources_to_try:
        out["note"] = "Tidak ada API key. Set via: ocysint config set <source> <key>"
        return out

    for src in sources_to_try:
        key = get_api_key(src) or ""
        if src == "dehashed":
            out["sources"]["dehashed"] = dehashed_search(query, "email", key)
        elif src == "intelx":
            out["sources"]["intelx"] = intelx_search(query, key)
        elif src == "leakcheck":
            out["sources"]["leakcheck"] = leakcheck_search(query, key)
    return out
