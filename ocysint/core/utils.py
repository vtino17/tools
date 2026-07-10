"""Fungsi utilitas bersama (HTTP, async, regex, validasi)."""
import asyncio
import hashlib
import random
import re
import string
import time
from typing import Any, Awaitable, Callable, Iterable, List, Optional, TypeVar

import aiohttp

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
PHONE_DIGITS = re.compile(r"\D+")

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "OCySec-OSINT/2.0 (Authorized Pentest)",
]

T = TypeVar("T")


def random_ua() -> str:
    return random.choice(USER_AGENTS)


def is_valid_email(email: str) -> bool:
    return bool(EMAIL_REGEX.match(email or ""))


def normalize_phone(phone: str, default_cc: str = "62") -> str:
    """Normalisasi nomor telepon ke format digit (default +62 Indonesia)."""
    if not phone:
        return ""
    digits = PHONE_DIGITS.sub("", phone)
    if digits.startswith("0"):
        digits = default_cc + digits[1:]
    elif not digits.startswith("+"):
        if len(digits) <= 11:
            digits = default_cc + digits
    return "+" + digits if not digits.startswith("+") else digits


def is_valid_domain(domain: str) -> bool:
    pattern = re.compile(
        r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$"
    )
    return bool(pattern.match(domain or ""))


def md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def gravatar_url(email: str, size: int = 200) -> str:
    return f"https://www.gravatar.com/avatar/{md5(email.lower().strip())}?d=404&s={size}"


async def bounded_gather(
    items: Iterable[T],
    coro_func: Callable[[T], Awaitable[Any]],
    concurrency: int = 20,
    show_progress: bool = False,
) -> List[Any]:
    """Jalankan coroutine untuk setiap item dengan batas concurrency."""
    sem = asyncio.Semaphore(concurrency)
    results: List[Any] = []
    total = len(list(items)) if not isinstance(items, list) else len(items)
    if isinstance(items, list):
        items_list = items
    else:
        items_list = list(items)
    completed = 0

    async def _runner(item: T) -> Any:
        nonlocal completed
        async with sem:
            try:
                r = await coro_func(item)
            except Exception as e:  # jangan biarkan 1 error menjatuhkan batch
                r = {"_error": str(e), "_item": item}
            completed += 1
            if show_progress:
                print(f"  [{completed}/{total}] selesai", end="\r")
            return r

    tasks = [_runner(i) for i in items_list]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    if show_progress:
        print()
    return results


def chunked(seq: List[T], size: int) -> Iterable[List[T]]:
    for i in range(0, len(seq), size):
        yield seq[i:i + size]


def rate_limited_sleep(seconds: float) -> None:
    time.sleep(seconds)


def humanize_bytes(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

