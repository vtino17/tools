"""
HackerAI - Shared Configuration
Centralized config untuk semua tools. Baca dari .env atau environment variable.
"""

import os
import json
from pathlib import Path

# ─── Base Paths ──────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent
TOOLS_DIR = BASE_DIR
WORDLIST_DIR = BASE_DIR / "wordlists"
REPORT_DIR = BASE_DIR / "reports"
LOG_DIR = BASE_DIR / "logs"

# ─── Network Settings ────────────────────────────────────────
TIMEOUT = int(os.getenv("HAI_TIMEOUT", "10"))
THREADS = int(os.getenv("HAI_THREADS", "50"))
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
LOG_FILE = os.getenv("HAI_LOG_FILE", str(LOG_DIR / "hackerai.log"))

# ─── Tool-Specific Defaults ──────────────────────────────────
# Port scanner
PORT_SCAN_RANGE = os.getenv("HAI_PORT_RANGE", "1-1000")
PORT_SCAN_PROTOCOLS = ["tcp"]

# SQLi tester
SQLI_TIMEOUT = int(os.getenv("HAI_SQLI_TIMEOUT", "5"))

# SSH bruteforce
SSH_PORT = int(os.getenv("HAI_SSH_PORT", "22"))
SSH_TIMEOUT = int(os.getenv("HAI_SSH_TIMEOUT", "5"))

# Hash cracker
HASH_ALGORITHMS = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "ntlm"]

# OSINT
OSINT_THREADS = int(os.getenv("HAI_OSINT_THREADS", "20"))

# ─── Helpers ─────────────────────────────────────────────────
def get_default_wordlist(name="common.txt"):
    """Return path to wordlist, fallback ke SecLists path jika ada."""
    path = WORDLIST_DIR / name
    if path.exists():
        return str(path)
    # Coba SecLists path umum
    fallback = Path("/usr/share/seclists/Discovery/Web-Content/") / name
    if fallback.exists():
        return str(fallback)
    return str(path)


def load_json_config(path: str) -> dict:
    """Load JSON config dari file."""
    p = Path(path)
    if p.exists():
        with open(p) as f:
            return json.load(f)
    return {}


def env_info() -> str:
    """Info singkat environment yang aktif."""
    parts = []
    if PROXY:
        parts.append(f"proxy={PROXY}")
    if SHODAN_API_KEY:
        parts.append("shadan=yes")
    if VERBOSE:
        parts.append("verbose")
    return ", ".join(parts) if parts else "default"
