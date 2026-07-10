#!/usr/bin/env python3
"""ASCII banner untuk OCySec OSINT Framework."""

import random
import sys

BANNERS = [
    r"""
   ____   __  ____ ______ ____   ___  __________  __ _____________
  / __ \ /  |/  // ____// __ \ /   |/_  __/  _/ |/ //_  __/  _/ _ \
 / / / // /|_/ // __/  / /_/ // /| | / /  / / / |/ /  / /  / // ___/
/ /_/ // /  / // /___ / _, _// ___ |/ / _/ / / /|  /  / / _/ // /
\____//_/  /_/_____//_/ |_/_/  |_/_/ /___/_/ |_/  /_/ /___/_/_/
                                                                v2.0
              [ OCySec OSINT Framework - by ocysint ]
""",
    r"""
  ___  _______ ___   __  ____  __  ___________ ___
 / _ \/ __/ // / | /  |/  / / / / /_  __/  _/ __ \
/ ___/\__/ _  /| |/ /|_/ / /_/ /  / / _/ / ___/ /
/_/   /___/_/ |_/___/_/\____/  /_/ /___/_//____/

   [ Modular OSINT Framework - Authorized Pentest Use ]
""",
]

COLORS = {
    "reset": "\033[0m",
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "white": "\033[97m",
    "bold": "\033[1m",
    "dim": "\033[2m",
}


def _supports_color() -> bool:
    """Deteksi apakah terminal mendukung warna (Windows + Unix)."""
    plat = sys.platform
    if plat == "win32":
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


_COLOR_ENABLED = _supports_color()


def c(text: str, color: str) -> str:
    """Bungkus teks dengan warna jika terminal mendukung."""
    if not _COLOR_ENABLED:
        return text
    code = COLORS.get(color, "")
    return f"{code}{text}{COLORS['reset']}"


def print_banner() -> None:
    """Cetak banner acak dengan pewarnaan."""
    banner = random.choice(BANNERS)
    print(c(banner, "cyan"))
    print(c("=" * 70, "magenta"))
    print(c("  Authorized Penetration Testing & OSINT Framework", "yellow"))
    print(c("  Gunakan hanya pada target yang Anda punya izin.", "red"))
    print(c("=" * 70, "magenta"))
    print()


def info(msg: str) -> None:
    print(f"{c('[i]', 'blue')} {msg}")


def ok(msg: str) -> None:
    print(f"{c('[+]', 'green')} {msg}")


def warn(msg: str) -> None:
    print(f"{c('[!]', 'yellow')} {msg}")


def err(msg: str) -> None:
    print(f"{c('[X]', 'red')} {msg}")


def section(title: str) -> None:
    print()
    print(c(f"==[ {title} ]==" + "=" * max(0, 60 - len(title)), "magenta"))
