#!/usr/bin/env python3
"""
Username Finder - Check username existence across platforms
Cek keberadaan username di 100+ platform media sosial.
Usage: python username_finder.py -u username
"""

import requests
import argparse
import sys
import concurrent.futures
import json

PLATFORMS = {
    "GitHub": "https://github.com/{u}",
    "GitLab": "https://gitlab.com/{u}",
    "Twitter": "https://twitter.com/{u}",
    "Instagram": "https://www.instagram.com/{u}/",
    "Facebook": "https://www.facebook.com/{u}",
    "LinkedIn": "https://www.linkedin.com/in/{u}",
    "Reddit": "https://www.reddit.com/user/{u}",
    "Pinterest": "https://www.pinterest.com/{u}/",
    "TikTok": "https://www.tiktok.com/@{u}",
    "YouTube": "https://www.youtube.com/@{u}",
    "Twitch": "https://www.twitch.tv/{u}",
    "Steam": "https://steamcommunity.com/id/{u}",
    "Vimeo": "https://vimeo.com/{u}",
    "SoundCloud": "https://soundcloud.com/{u}",
    "Spotify": "https://open.spotify.com/user/{u}",
    "Medium": "https://medium.com/@{u}",
    "Dev.to": "https://dev.to/{u}",
    "Hashnode": "https://hashnode.com/@{u}",
    "Behance": "https://www.behance.net/{u}",
    "Dribbble": "https://dribbble.com/{u}",
    "Flickr": "https://www.flickr.com/people/{u}/",
    "500px": "https://500px.com/p/{u}",
    "DeviantArt": "https://www.deviantart.com/{u}",
    "About.me": "https://about.me/{u}",
    "Bitbucket": "https://bitbucket.org/{u}/",
    "HackerOne": "https://hackerone.com/{u}",
    "Bugcrowd": "https://bugcrowd.com/{u}",
    "Keybase": "https://keybase.io/{u}",
    "Docker Hub": "https://hub.docker.com/u/{u}",
    "npm": "https://www.npmjs.com/~{u}",
    "PyPI": "https://pypi.org/user/{u}/",
    "RubyGems": "https://rubygems.org/profiles/{u}",
    "Mastodon (mastodon.social)": "https://mastodon.social/@{u}",
    "Mastodon (fosstodon)": "https://fosstodon.org/@{u}",
    "Pleroma": "https://pleroma.social/{u}",
    "Matrix": "https://matrix.to/#/@{u}:matrix.org",
    "Telegram (web)": "https://t.me/{u}",
    "WhatsApp": "https://wa.me/{u}",
    "Signal": "https://signal.org/#{u}",
    "Wire": "https://app.wire.com/{u}",
    "Disqus": "https://disqus.com/by/{u}/",
    "Stack Overflow": "https://stackoverflow.com/users/{u}",
    "Quora": "https://www.quora.com/profile/{u}",
    "Gravatar": "https://en.gravatar.com/{u}",
    "WordPress": "https://{u}.wordpress.com",
    "Blogger": "https://{u}.blogspot.com",
    "Tumblr": "https://{u}.tumblr.com",
    "Substack": "https://{u}.substack.com",
    "Gumroad": "https://gumroad.com/{u}",
    "Buy Me a Coffee": "https://www.buymeacoffee.com/{u}",
    "Patreon": "https://www.patreon.com/{u}",
    "Kickstarter": "https://www.kickstarter.com/profile/{u}",
    "GoFundMe": "https://www.gofundme.com/u/{u}",
    "Wattpad": "https://www.wattpad.com/user/{u}",
    "Roblox": "https://www.roblox.com/user.aspx?username={u}",
    "Steam": "https://steamcommunity.com/id/{u}",
    "Xbox": "https://account.xbox.com/en-US/Profile?GamerTag={u}",
    "PlayStation": "https://psnprofiles.com/{u}",
    "Nintendo": "https://www.nintendo.com/?u={u}",
    "Chess.com": "https://www.chess.com/member/{u}",
    "Lichess": "https://lichess.org/@/{u}",
    "Runkeeper": "https://runkeeper.com/{u}/profile",
    "Strava": "https://www.strava.com/athletes/{u}",
    "MyFitnessPal": "https://www.myfitnesspal.com/profile/{u}",
    "Goodreads": "https://www.goodreads.com/{u}",
    "Last.fm": "https://www.last.fm/user/{u}",
    "Letterboxd": "https://letterboxd.com/{u}/",
    "IMDb": "https://www.imdb.com/user/{u}/",
    "GuruShots": "https://gurushots.com/{u}/photos",
    "VSCO": "https://vsco.co/{u}/gallery",
    "TripAdvisor": "https://www.tripadvisor.com/members/{u}",
    "Airbnb": "https://www.airbnb.com/users/show/{u}",
    "Couchsurfing": "https://www.couchsurfing.com/people/{u}",
    "Foursquare": "https://foursquare.com/user/{u}",
    "Yelp": "https://www.yelp.com/user_details?userid={u}",
    "Zomato": "https://www.zomato.com/{u}",
    "Untappd": "https://untappd.com/user/{u}",
    "Trakt": "https://www.trakt.tv/users/{u}",
    "Anilist": "https://anilist.co/user/{u}/",
    "MyAnimeList": "https://myanimelist.net/profile/{u}",
    "MangaUpdates": "https://www.mangaupdates.com/members.html?id={u}",
    "HubPages": "https://hubpages.com/@{u}",
    "Wikipedia": "https://en.wikipedia.org/wiki/User:{u}",
    "Wikidata": "https://www.wikidata.org/wiki/User:{u}",
    "Archive.org": "https://archive.org/details/@{u}",
    "ProductHunt": "https://www.producthunt.com/@{u}",
    "AngelList": "https://angel.co/u/{u}",
    "Crunchbase": "https://www.crunchbase.com/person/{u}",
    "F6S": "https://www.f6s.com/{u}",
    "Slant": "https://www.slant.co/users/{u}",
    "Badoo": "https://badoo.com/profile/{u}",
    "Meetup": "https://www.meetup.com/members/{u}/",
    "Tribe": "https://tribe.so/@{u}",
}


def check_platform(session, platform, url_template, username, timeout=8):
    url = url_template.format(u=username)
    try:
        r = session.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
        )
        if r.status_code == 200:
            return (platform, url, True)
    except requests.exceptions.RequestException:
        pass
    return None


def main():
    parser = argparse.ArgumentParser(description="Username Finder")
    parser.add_argument("-u", "--username", required=True, help="Username to search")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Thread count")
    args = parser.parse_args()

    print(f"[*] Searching for username: {args.username}")
    print(f"[*] Platforms to check: {len(PLATFORMS)}")
    print("-" * 70)

    requests.packages.urllib3.disable_warnings()
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"})

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(check_platform, session, p, url, args.username): p
            for p, url in PLATFORMS.items()
        }
        completed = 0
        for future in concurrent.futures.as_completed(futures):
            completed += 1
            result = future.result()
            if result:
                found.append(result)
                platform, url, _ = result
                print(f"[+] {platform:30} {url}")
            if completed % 20 == 0:
                print(f"[*] Progress: {completed}/{len(PLATFORMS)}", end="\r")

    print("-" * 70)
    print(f"[+] Found on {len(found)} platform(s)")
    for platform, url, _ in found:
        print(f"    {platform:30} {url}")


if __name__ == "__main__":
    main()
