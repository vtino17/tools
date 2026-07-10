"""Manajemen konfigurasi dan API key OCySec OSINT."""

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

CONFIG_DIR = Path.home() / ".ocysint"
CONFIG_FILE = CONFIG_DIR / "config.json"

DEFAULTS: Dict[str, Any] = {
    "api_keys": {
        "hibp": "",  # HaveIBeenPwned
        "shodan": "",  # Shodan
        "censys_id": "",
        "censys_secret": "",
        "numverify": "",  # Numverify
        "hunter": "",  # Hunter.io
        "virustotal": "",  # VirusTotal
        "securitytrails": "",
        "dehashed": "",  # DeHashed (perlu subscription)
        "intelx": "",  # Intelligence X
        "leakcheck": "",  # LeakCheck
        "clearbit": "",
        "fullcontact": "",
    },
    "timeout": 15,
    "max_concurrent": 20,
    "user_agent": "OCySec-OSINT/2.0 (Authorized Pentest)",
    "report_dir": str(Path.cwd() / "ocysint" / "reports"),
    "output_format": "txt",  # txt | json | html
}


def _ensure_config() -> Dict[str, Any]:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_FILE.exists():
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(DEFAULTS, f, indent=2)
        try:
            os.chmod(CONFIG_FILE, 0o600)
        except Exception:
            pass
        return DEFAULTS
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def load_config() -> Dict[str, Any]:
    """Muat konfigurasi, isi dengan default jika ada key hilang."""
    cfg = _ensure_config()
    changed = False
    for k, v in DEFAULTS.items():
        if k not in cfg:
            cfg[k] = v
            changed = True
    if isinstance(cfg.get("api_keys"), dict):
        for k, v in DEFAULTS["api_keys"].items():
            cfg["api_keys"].setdefault(k, v)
    if changed:
        save_config(cfg)
    return cfg


def save_config(cfg: Dict[str, Any]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except Exception:
        pass


def get_api_key(name: str) -> Optional[str]:
    """Ambil API key. Prioritas: env var OCYSINT_<NAME> > config file."""
    env = os.environ.get(f"OCYSINT_{name.upper()}")
    if env:
        return env
    cfg = load_config()
    return cfg.get("api_keys", {}).get(name)


def set_api_key(name: str, value: str) -> None:
    cfg = load_config()
    cfg["api_keys"][name] = value
    save_config(cfg)
