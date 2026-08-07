"""Validated shared configuration for HackerAI tools."""

import os
import json
from pathlib import Path

# ─── Base Paths ──────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
TOOLS_DIR = BASE_DIR
WORDLIST_DIR = BASE_DIR / "wordlists"
REPORT_DIR = BASE_DIR / "reports"
LOG_DIR = BASE_DIR / "logs"


def _bounded_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


# ─── Network Settings ────────────────────────────────────────
TIMEOUT = _bounded_int("HAI_TIMEOUT", 10, 1, 300)
THREADS = _bounded_int("HAI_THREADS", 50, 1, 256)
USER_AGENT = os.getenv(
    "HAI_USER_AGENT",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
)
PROXY = os.getenv("HAI_PROXY", "")  # http://127.0.0.1:8080

# ─── API Keys ────────────────────────────────────────────────
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
HUNTER_API_KEY = os.getenv("HUNTER_API_KEY", "")

# ─── Output Settings ─────────────────────────────────────────
VERBOSE = os.getenv("HAI_VERBOSE", "0") == "1"
COLOR = os.getenv("HAI_COLOR", "1") == "1"
LOG_LEVEL = os.getenv("HAI_LOG_LEVEL", "INFO").upper()
if LOG_LEVEL not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
    raise ValueError("HAI_LOG_LEVEL must be DEBUG, INFO, WARNING, ERROR, or CRITICAL")
LOG_FILE = os.getenv("HAI_LOG_FILE", str(LOG_DIR / "hackerai.log"))

# ─── Tool-Specific Defaults ──────────────────────────────────
# Port scanner
PORT_SCAN_RANGE = os.getenv("HAI_PORT_RANGE", "1-1000")
PORT_SCAN_PROTOCOLS = ["tcp"]

# SQLi tester
SQLI_TIMEOUT = _bounded_int("HAI_SQLI_TIMEOUT", 5, 1, 120)

# SSH bruteforce
SSH_PORT = _bounded_int("HAI_SSH_PORT", 22, 1, 65535)
SSH_TIMEOUT = _bounded_int("HAI_SSH_TIMEOUT", 5, 1, 300)

# Hash cracker
HASH_ALGORITHMS = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "ntlm"]

# OSINT
OSINT_THREADS = _bounded_int("HAI_OSINT_THREADS", 20, 1, 128)


# ─── Helpers ─────────────────────────────────────────────────
def get_default_wordlist(name="common.txt"):
    """Return a wordlist path, falling back to a standard SecLists location."""
    path = WORDLIST_DIR / name
    if path.exists():
        return str(path)
    # Try the common system-wide SecLists location.
    fallback = Path("/usr/share/seclists/Discovery/Web-Content/") / name
    if fallback.exists():
        return str(fallback)
    return str(path)


def load_json_config(path: str) -> dict:
    """Load a bounded JSON object from a regular file."""
    p = Path(path)
    if not p.exists():
        return {}
    if not p.is_file():
        raise ValueError(f"Configuration path is not a file: {p}")
    if p.stat().st_size > 1_048_576:
        raise ValueError("Configuration file exceeds the 1 MiB limit")
    with p.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("Configuration root must be a JSON object")
    return data


def env_info() -> str:
    """Return a short description of active environment overrides."""
    parts = []
    if PROXY:
        parts.append(f"proxy={PROXY}")
    if SHODAN_API_KEY:
        parts.append("shodan=yes")
    if VERBOSE:
        parts.append("verbose")
    return ", ".join(parts) if parts else "default"
