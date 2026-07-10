"""Username enumeration: cek ketersediaan username di 50+ platform."""

import asyncio
from typing import Any, Dict, List

import aiohttp

from core.utils import bounded_gather, random_ua

PLATFORMS: Dict[str, Dict[str, Any]] = {
    "GitHub": {"url": "https://github.com/{}", "method": "status_code", "expect": 200},
    "GitLab": {"url": "https://gitlab.com/{}", "method": "status_code", "expect": 200},
    "Twitter/X": {"url": "https://x.com/{}", "method": "status_code", "expect": 200},
    "Instagram": {"url": "https://www.instagram.com/{}/", "method": "status_code", "expect": 200},
    "Facebook": {"url": "https://www.facebook.com/{}", "method": "status_code", "expect": 200},
    "Reddit": {"url": "https://www.reddit.com/user/{}", "method": "status_code", "expect": 200},
    "TikTok": {"url": "https://www.tiktok.com/@{}", "method": "status_code", "expect": 200},
    "YouTube": {"url": "https://www.youtube.com/@{}", "method": "status_code", "expect": 200},
    "Twitch": {"url": "https://www.twitch.tv/{}", "method": "status_code", "expect": 200},
    "Steam": {
        "url": "https://steamcommunity.com/id/{}",
        "method": "response_url",
        "deny_substrings": ["error"],
    },
    "Pinterest": {"url": "https://www.pinterest.com/{}/", "method": "status_code", "expect": 200},
    "LinkedIn": {"url": "https://www.linkedin.com/in/{}", "method": "status_code", "expect": 200},
    "Medium": {"url": "https://medium.com/@{}", "method": "status_code", "expect": 200},
    "Dev.to": {"url": "https://dev.to/{}", "method": "status_code", "expect": 200},
    "StackOverflow": {
        "url": "https://stackoverflow.com/users/{}",
        "method": "status_code",
        "expect": 200,
    },
    "Behance": {"url": "https://www.behance.net/{}", "method": "status_code", "expect": 200},
    "Dribbble": {"url": "https://dribbble.com/{}", "method": "status_code", "expect": 200},
    "Spotify": {"url": "https://open.spotify.com/user/{}", "method": "status_code", "expect": 200},
    "SoundCloud": {"url": "https://soundcloud.com/{}", "method": "status_code", "expect": 200},
    "Tumblr": {"url": "https://{}.tumblr.com", "method": "status_code", "expect": 200},
    "Flickr": {"url": "https://www.flickr.com/people/{}", "method": "status_code", "expect": 200},
    "Vimeo": {"url": "https://vimeo.com/{}", "method": "status_code", "expect": 200},
    "WordPress": {"url": "https://{}.wordpress.com", "method": "status_code", "expect": 200},
    "Blogger": {"url": "https://{}.blogspot.com", "method": "status_code", "expect": 200},
    "About.me": {"url": "https://about.me/{}", "method": "status_code", "expect": 200},
    "Gravatar": {"url": "https://en.gravatar.com/{}", "method": "status_code", "expect": 200},
    "Bitbucket": {"url": "https://bitbucket.org/{}", "method": "status_code", "expect": 200},
    "Keybase": {"url": "https://keybase.io/{}", "method": "status_code", "expect": 200},
    "HackerOne": {"url": "https://hackerone.com/{}", "method": "status_code", "expect": 200},
    "BugCrowd": {"url": "https://bugcrowd.com/{}", "method": "status_code", "expect": 200},
    "Docker Hub": {"url": "https://hub.docker.com/u/{}", "method": "status_code", "expect": 200},
    "npm": {"url": "https://www.npmjs.com/~{}", "method": "status_code", "expect": 200},
    "PyPI": {"url": "https://pypi.org/user/{}", "method": "status_code", "expect": 200},
    "RubyGems": {"url": "https://rubygems.org/profiles/{}", "method": "status_code", "expect": 200},
    "GitHub Gist": {"url": "https://gist.github.com/{}", "method": "status_code", "expect": 200},
    "Kaggle": {"url": "https://www.kaggle.com/{}", "method": "status_code", "expect": 200},
    "Replit": {"url": "https://replit.com/@{}", "method": "status_code", "expect": 200},
    "CodePen": {"url": "https://codepen.io/{}", "method": "status_code", "expect": 200},
    "HackerRank": {"url": "https://www.hackerrank.com/{}", "method": "status_code", "expect": 200},
    "LeetCode": {"url": "https://leetcode.com/{}", "method": "status_code", "expect": 200},
    "Fiverr": {"url": "https://www.fiverr.com/{}", "method": "status_code", "expect": 200},
    "Upwork": {
        "url": "https://www.upwork.com/freelancers/~{}",
        "method": "status_code",
        "expect": 200,
    },
    "Paypal": {"url": "https://www.paypal.com/paypalme/{}", "method": "status_code", "expect": 200},
    "BuyMeACoffee": {
        "url": "https://www.buymeacoffee.com/{}",
        "method": "status_code",
        "expect": 200,
    },
    "Patreon": {"url": "https://www.patreon.com/{}", "method": "status_code", "expect": 200},
    "DeviantArt": {"url": "https://www.deviantart.com/{}", "method": "status_code", "expect": 200},
    "ProductHunt": {
        "url": "https://www.producthunt.com/@{}",
        "method": "status_code",
        "expect": 200,
    },
    "SlideShare": {"url": "https://www.slideshare.net/{}", "method": "status_code", "expect": 200},
    "Scribd": {"url": "https://www.scribd.com/{}", "method": "status_code", "expect": 200},
    "Issuu": {"url": "https://issuu.com/{}", "method": "status_code", "expect": 200},
    "Mastodon.social": {
        "url": "https://mastodon.social/@{}",
        "method": "status_code",
        "expect": 200,
    },
    "Threads": {"url": "https://www.threads.net/@{}", "method": "status_code", "expect": 200},
    "VK": {"url": "https://vk.com/{}", "method": "status_code", "expect": 200},
    "Telegram": {"url": "https://t.me/{}", "method": "status_code", "expect": 200},
    "Disqus": {"url": "https://disqus.com/{}", "method": "status_code", "expect": 200},
    "Wikia/Fandom": {"url": "https://www.fandom.com/u/{}", "method": "status_code", "expect": 200},
}


async def _check_platform(
    session: aiohttp.ClientSession,
    platform: str,
    info_dict: Dict[str, Any],
    username: str,
) -> Dict[str, Any]:
    url = info_dict["url"].format(username)
    try:
        async with session.get(url, timeout=12, allow_redirects=True) as r:
            body = await r.text() if r.status == 200 else ""
            exists = False
            method = info_dict["method"]
            if method == "status_code":
                exists = r.status == info_dict.get("expect", 200)
            elif method == "response_url":
                exists = username.lower() in str(r.url).lower()
            if "deny_substrings" in info_dict and exists:
                exists = not any(s.lower() in body.lower() for s in info_dict["deny_substrings"])
            return {
                "platform": platform,
                "url": url,
                "exists": exists,
                "status": r.status,
                "final_url": str(r.url) if r.url else url,
            }
    except asyncio.TimeoutError:
        return {"platform": platform, "url": url, "exists": False, "error": "timeout"}
    except Exception as e:
        return {"platform": platform, "url": url, "exists": False, "error": str(e)[:80]}


async def _check_all(username: str, concurrency: int = 20) -> List[Dict[str, Any]]:
    timeout = aiohttp.ClientTimeout(total=12)
    headers = {"User-Agent": random_ua()}
    async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
        items = [(p, info) for p, info in PLATFORMS.items()]

        async def _run(item):
            p, info_d = item
            return await _check_platform(session, p, info_d, username)

        results = await bounded_gather(items, _run, concurrency=concurrency)
    return results


def run_username_recon(username: str, concurrency: int = 20) -> List[Dict[str, Any]]:
    """Kembalikan list dict berisi informasi tiap platform."""
    return asyncio.run(_check_all(username, concurrency))


def filter_found(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [r for r in results if r.get("exists")]
