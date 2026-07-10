"""Shodan & Censys reconnaissance (perlu API key)."""
from typing import Any, Dict

import requests

from core.config import get_api_key
from core.utils import random_ua


def shodan_host(ip: str, api_key: str = "") -> Dict[str, Any]:
    if not api_key:
        return {"skipped": True, "reason": "no_shodan_api_key"}
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}",
                         params={"key": api_key},
                         headers={"User-Agent": random_ua()},
                         timeout=20)
        if r.status_code == 200:
            d = r.json()
            return {
                "source": "shodan",
                "ip": d.get("ip_str"),
                "org": d.get("org"),
                "isp": d.get("isp"),
                "os": d.get("os"),
                "asn": d.get("asn"),
                "country": d.get("country_name"),
                "city": d.get("city"),
                "ports": d.get("ports", []),
                "hostnames": d.get("hostnames", []),
                "vulns": list(d.get("vulns", {}).keys()) if d.get("vulns") else [],
                "services": [
                    {
                        "port": s.get("port"),
                        "transport": s.get("transport"),
                        "product": s.get("product"),
                        "version": s.get("version"),
                        "banner": (s.get("data") or "")[:200],
                    }
                    for s in d.get("data", [])[:30]
                ],
            }
        return {"error": f"http_{r.status_code}", "body": r.text[:200]}
    except Exception as e:
        return {"error": str(e)}


def shodan_dns(domain: str, api_key: str = "") -> Dict[str, Any]:
    if not api_key:
        return {"skipped": True, "reason": "no_shodan_api_key"}
    try:
        r = requests.get(f"https://api.shodan.io/dns/resolve",
                         params={"hostnames": domain, "key": api_key},
                         timeout=15)
        if r.status_code == 200:
            return {"source": "shodan", "resolved": r.json()}
        return {"error": f"http_{r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def censys_host(ip: str, api_id: str = "", api_secret: str = "") -> Dict[str, Any]:
    if not api_id or not api_secret:
        return {"skipped": True, "reason": "no_censys_credentials"}
    try:
        r = requests.get(
            f"https://search.censys.io/api/v2/hosts/{ip}",
            auth=(api_id, api_secret),
            headers={"User-Agent": random_ua()},
            timeout=20,
        )
        if r.status_code == 200:
            d = r.json().get("result", {})
            services = d.get("services", [])
            return {
                "source": "censys",
                "ip": d.get("ip"),
                "location": d.get("location"),
                "services": [
                    {
                        "port": s.get("port"),
                        "service_name": s.get("service_name"),
                        "transport": s.get("transport_protocol"),
                    }
                    for s in services[:30]
                ],
            }
        return {"error": f"http_{r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def run_shodan_recon(target: str, kind: str = "ip") -> Dict[str, Any]:
    """kind: ip | domain"""
    out: Dict[str, Any] = {"target": target, "kind": kind, "sources": {}}
    shodan_key = get_api_key("shodan") or ""
    censys_id = get_api_key("censys_id") or ""
    censys_secret = get_api_key("censys_secret") or ""

    if kind == "ip":
        if shodan_key:
            out["sources"]["shodan"] = shodan_host(target, shodan_key)
        if censys_id and censys_secret:
            out["sources"]["censys"] = censys_host(target, censys_id, censys_secret)
    elif kind == "domain":
        if shodan_key:
            out["sources"]["shodan_dns"] = shodan_dns(target, shodan_key)
    if not out["sources"]:
        out["note"] = "Tidak ada Shodan/Censys API key. Set via: ocysint config set shodan <key>"
    return out

