# -*- coding:UTF-8 -*-
"""
Personal, Dating & Social Media OSINT Controller (SOCMINT) for SPO v2.0.
Implements high-concurrency username & identity enumeration across 60+ platforms
spanning 8 categories:
  1. Dating & Relationships (Tinder, Badoo, OkCupid, PlentyOfFish, Bumble, Happn)
  2. Social Networks (Instagram, TikTok, X/Twitter, Threads, Facebook, Snapchat,
     Pinterest, Bluesky, Mastodon, Tumblr, VK, Flickr, Kwai)
  3. Messaging & Communities (Telegram, Reddit, Discord, Quora, Substack, Disqus)
  4. Video, Streaming & Audio (YouTube, Twitch, Kick, Spotify, SoundCloud, Vimeo,
     Last.fm, Letterboxd)
  5. Creator & Subscription (Linktree, Patreon, Ko-fi, BuyMeACoffee, About.me,
     OnlyFans, Privacy.com.br, Fansly)
  6. Gaming & Esports (Steam, Chess.com, Lichess, Roblox, osu!, itch.io, MyAnimeList)
  7. Professional & Freelance (LinkedIn, Behance, Dribbble, Medium, Fiverr,
     99Freelas, Workana, SlideShare)
  8. Dev, SecOps & Web3 (GitHub, GitLab, Bitbucket, HuggingFace, Kaggle, DockerHub,
     PyPI, npm, Crates.io, Dev.to, HackerNews, TabNews, Keybase, HackerOne,
     Bugcrowd, TryHackMe, LeetCode, OpenSea)
"""
import hashlib
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus
import requests


class Facebook:
    HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,pt-BR;q=0.8",
    }

    API_HEADERS = {
        "User-Agent": "SPO-Sneak-Peek-OSINT/2.0 (+https://github.com/eriktonon/SPO-Sneak-Peek-OSINT)",
        "Accept": "application/json",
    }

    PLATFORMS: List[Dict[str, Any]] = [
        # --- 1. DATING & RELATIONSHIPS ---
        {
            "name": "Tinder",
            "category": "Dating & Apps",
            "url": "https://tinder.com/@{u}",
            "dork_domain": "tinder.com",
            "not_found": ["looking for someone", "page not found", "404"],
        },
        {
            "name": "Badoo",
            "category": "Dating & Apps",
            "url": "https://badoo.com/profile/{u}",
            "dork_domain": "badoo.com",
            "not_found": ["page not found", "404", "error"],
        },
        {
            "name": "OkCupid",
            "category": "Dating & Apps",
            "url": "https://www.okcupid.com/profile/{u}",
            "dork_domain": "okcupid.com",
            "not_found": ["page not found", "doesn't exist", "404"],
        },
        {
            "name": "PlentyOfFish (POF)",
            "category": "Dating & Apps",
            "url": "https://www.pof.com/viewprofile.aspx?profile_id={u}",
            "dork_domain": "pof.com",
            "not_found": ["page not found", "no longer available"],
        },
        {
            "name": "Bumble",
            "category": "Dating & Apps",
            "url": "https://bumble.com/app",
            "dork_domain": "bumble.com",
            "pivot_only": True,
        },
        {
            "name": "Happn",
            "category": "Dating & Apps",
            "url": "https://www.happn.com/en/",
            "dork_domain": "happn.com",
            "pivot_only": True,
        },

        # --- 2. MAINSTREAM SOCIAL NETWORKS ---
        {
            "name": "Instagram",
            "category": "Social Media",
            "url": "https://www.instagram.com/{u}/",
            "dork_domain": "instagram.com",
            "not_found": ["sorry, this page isn't available", "page not found"],
        },
        {
            "name": "TikTok",
            "category": "Social Media",
            "url": "https://www.tiktok.com/@{u}",
            "dork_domain": "tiktok.com",
            "not_found": ["couldn't find this account", "page not available"],
        },
        {
            "name": "X (Twitter)",
            "category": "Social Media",
            "url": "https://x.com/{u}",
            "dork_domain": "x.com",
            "not_found": ["this account doesn’t exist", "account suspended"],
        },
        {
            "name": "Threads",
            "category": "Social Media",
            "url": "https://www.threads.net/@{u}",
            "dork_domain": "threads.net",
            "not_found": ["page not found", "not available"],
        },
        {
            "name": "Facebook",
            "category": "Social Media",
            "url": "https://www.facebook.com/{u}",
            "dork_domain": "facebook.com",
            "not_found": ["this content isn't available", "page not found"],
        },
        {
            "name": "Pinterest",
            "category": "Social Media",
            "url": "https://www.pinterest.com/{u}/",
            "dork_domain": "pinterest.com",
            "not_found": ["user not found", "page not found"],
        },
        {
            "name": "Snapchat",
            "category": "Social Media",
            "url": "https://www.snapchat.com/add/{u}",
            "dork_domain": "snapchat.com",
            "not_found": ["sorry, This content was not found", "bitmoji", "404"],
        },
        {
            "name": "Bluesky",
            "category": "Social Media",
            "url": "https://bsky.app/profile/{u}.bsky.social",
            "api": "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={u}.bsky.social",
            "dork_domain": "bsky.app",
        },
        {
            "name": "Mastodon (mastodon.social)",
            "category": "Social Media",
            "url": "https://mastodon.social/@{u}",
            "dork_domain": "mastodon.social",
            "not_found": ["the page you are looking for isn't here", "404"],
        },
        {
            "name": "Tumblr",
            "category": "Social Media",
            "url": "https://{u}.tumblr.com",
            "dork_domain": "tumblr.com",
            "not_found": ["there's nothing here", "not found"],
        },
        {
            "name": "VK (VKontakte)",
            "category": "Social Media",
            "url": "https://vk.com/{u}",
            "dork_domain": "vk.com",
            "not_found": ["404 not found", "page not found"],
        },
        {
            "name": "Flickr",
            "category": "Social Media",
            "url": "https://www.flickr.com/people/{u}/",
            "dork_domain": "flickr.com",
            "not_found": ["page not found", "404"],
        },
        {
            "name": "Kwai",
            "category": "Social Media",
            "url": "https://www.kwai.com/@{u}",
            "dork_domain": "kwai.com",
            "not_found": ["404", "not found"],
        },

        # --- 3. MESSAGING & FORUMS ---
        {
            "name": "Telegram",
            "category": "Messaging & Forums",
            "url": "https://t.me/{u}",
            "dork_domain": "t.me",
            "must_contain": "tgme_page_title",
        },
        {
            "name": "Reddit",
            "category": "Messaging & Forums",
            "url": "https://www.reddit.com/user/{u}",
            "api": "https://www.reddit.com/user/{u}/about.json",
            "dork_domain": "reddit.com",
        },
        {
            "name": "HackerNews",
            "category": "Messaging & Forums",
            "url": "https://news.ycombinator.com/user?id={u}",
            "api": "https://hacker-news.firebaseio.com/v0/user/{u}.json",
            "dork_domain": "news.ycombinator.com",
        },
        {
            "name": "TabNews",
            "category": "Messaging & Forums",
            "url": "https://www.tabnews.com.br/{u}",
            "api": "https://www.tabnews.com.br/api/v1/users/{u}",
            "dork_domain": "tabnews.com.br",
        },
        {
            "name": "Quora",
            "category": "Messaging & Forums",
            "url": "https://www.quora.com/profile/{u}",
            "dork_domain": "quora.com",
            "not_found": ["page not found", "404"],
        },
        {
            "name": "Substack",
            "category": "Messaging & Forums",
            "url": "https://substack.com/@{u}",
            "dork_domain": "substack.com",
            "not_found": ["page not found", "404"],
        },
        {
            "name": "Disqus",
            "category": "Messaging & Forums",
            "url": "https://disqus.com/by/{u}/",
            "dork_domain": "disqus.com",
            "not_found": ["page not found", "unable to find"],
        },

        # --- 4. VIDEO, STREAMING & AUDIO ---
        {
            "name": "YouTube",
            "category": "Video & Streaming",
            "url": "https://www.youtube.com/@{u}",
            "dork_domain": "youtube.com",
            "not_found": ["this page isn't available", "404 not found"],
        },
        {
            "name": "Twitch",
            "category": "Video & Streaming",
            "url": "https://www.twitch.tv/{u}",
            "dork_domain": "twitch.tv",
            "not_found": ["time machine", "content is unavailable"],
        },
        {
            "name": "Kick",
            "category": "Video & Streaming",
            "url": "https://kick.com/{u}",
            "dork_domain": "kick.com",
            "not_found": ["404", "page not found"],
        },
        {
            "name": "Spotify",
            "category": "Video & Streaming",
            "url": "https://open.spotify.com/user/{u}",
            "dork_domain": "open.spotify.com",
            "not_found": ["page not found", "couldn't find that page"],
        },
        {
            "name": "SoundCloud",
            "category": "Video & Streaming",
            "url": "https://soundcloud.com/{u}",
            "dork_domain": "soundcloud.com",
            "not_found": ["we can't find that user", "404"],
        },
        {
            "name": "Vimeo",
            "category": "Video & Streaming",
            "url": "https://vimeo.com/{u}",
            "dork_domain": "vimeo.com",
            "not_found": ["sorry, we couldn't find that page", "404"],
        },
        {
            "name": "Last.fm",
            "category": "Video & Streaming",
            "url": "https://www.last.fm/user/{u}",
            "dork_domain": "last.fm",
            "not_found": ["page not found", "404"],
        },
        {
            "name": "Letterboxd",
            "category": "Video & Streaming",
            "url": "https://letterboxd.com/{u}/",
            "dork_domain": "letterboxd.com",
            "not_found": ["sorry, we can’t find the page", "404"],
        },

        # --- 5. CREATOR, SUBSCRIPTION & ADULT ---
        {
            "name": "Linktree",
            "category": "Creator & Links",
            "url": "https://linktr.ee/{u}",
            "dork_domain": "linktr.ee",
            "not_found": ["the page you’re looking for doesn’t exist", "page not found"],
        },
        {
            "name": "Patreon",
            "category": "Creator & Links",
            "url": "https://www.patreon.com/{u}",
            "dork_domain": "patreon.com",
            "not_found": ["page not found", "404"],
        },
        {
            "name": "Ko-fi",
            "category": "Creator & Links",
            "url": "https://ko-fi.com/{u}",
            "dork_domain": "ko-fi.com",
            "not_found": ["page not found", "404"],
        },
        {
            "name": "BuyMeACoffee",
            "category": "Creator & Links",
            "url": "https://www.buymeacoffee.com/{u}",
            "dork_domain": "buymeacoffee.com",
            "not_found": ["page not found", "404"],
        },
        {
            "name": "About.me",
            "category": "Creator & Links",
            "url": "https://about.me/{u}",
            "dork_domain": "about.me",
            "not_found": ["page not found", "404"],
        },
        {
            "name": "OnlyFans",
            "category": "Creator & Links",
            "url": "https://onlyfans.com/{u}",
            "dork_domain": "onlyfans.com",
            "not_found": ["sorry, this page is not available", "404"],
        },
        {
            "name": "Privacy.com.br",
            "category": "Creator & Links",
            "url": "https://privacy.com.br/profile/{u}",
            "dork_domain": "privacy.com.br",
            "not_found": ["404", "não encontrado"],
        },
        {
            "name": "Fansly",
            "category": "Creator & Links",
            "url": "https://fansly.com/{u}",
            "dork_domain": "fansly.com",
            "not_found": ["404", "not found"],
        },

        # --- 6. GAMING & ESPORTS ---
        {
            "name": "Steam",
            "category": "Gaming & Esports",
            "url": "https://steamcommunity.com/id/{u}",
            "dork_domain": "steamcommunity.com",
            "not_found": ["the specified profile could not be found", "error"],
        },
        {
            "name": "Chess.com",
            "category": "Gaming & Esports",
            "url": "https://www.chess.com/member/{u}",
            "api": "https://api.chess.com/pub/player/{u}",
            "dork_domain": "chess.com",
        },
        {
            "name": "Lichess",
            "category": "Gaming & Esports",
            "url": "https://lichess.org/@/{u}",
            "api": "https://lichess.org/api/user/{u}",
            "dork_domain": "lichess.org",
        },
        {
            "name": "Roblox",
            "category": "Gaming & Esports",
            "url": "https://www.roblox.com/user.aspx?username={u}",
            "dork_domain": "roblox.com",
            "not_found": ["page cannot be found", "404"],
        },
        {
            "name": "osu!",
            "category": "Gaming & Esports",
            "url": "https://osu.ppy.sh/users/{u}",
            "dork_domain": "osu.ppy.sh",
            "not_found": ["user not found", "404"],
        },
        {
            "name": "itch.io",
            "category": "Gaming & Esports",
            "url": "https://{u}.itch.io",
            "dork_domain": "itch.io",
            "not_found": [" couldn't find that page", "404"],
        },
        {
            "name": "MyAnimeList",
            "category": "Gaming & Esports",
            "url": "https://myanimelist.net/profile/{u}",
            "dork_domain": "myanimelist.net",
            "not_found": ["404 not found", " cannot be found"],
        },

        # --- 7. PROFESSIONAL, DESIGN & FREELANCE ---
        {
            "name": "LinkedIn",
            "category": "Professional",
            "url": "https://www.linkedin.com/in/{u}",
            "dork_domain": "linkedin.com/in",
            "not_found": ["page not found", "profile is not available"],
        },
        {
            "name": "Medium",
            "category": "Professional",
            "url": "https://medium.com/@{u}",
            "dork_domain": "medium.com",
            "not_found": ["page not found", "404"],
        },
        {
            "name": "Behance",
            "category": "Professional",
            "url": "https://www.behance.net/{u}",
            "dork_domain": "behance.net",
            "not_found": ["oops! we can’t find that page", "404"],
        },
        {
            "name": "Dribbble",
            "category": "Professional",
            "url": "https://dribbble.com/{u}",
            "dork_domain": "dribbble.com",
            "not_found": ["whoops, that page is gone", "404"],
        },
        {
            "name": "SlideShare",
            "category": "Professional",
            "url": "https://www.slideshare.net/{u}",
            "dork_domain": "slideshare.net",
            "not_found": ["page not found", "404"],
        },
        {
            "name": "Fiverr",
            "category": "Professional",
            "url": "https://www.fiverr.com/{u}",
            "dork_domain": "fiverr.com",
            "not_found": ["page not found", "404"],
        },
        {
            "name": "99Freelas",
            "category": "Professional",
            "url": "https://www.99freelas.com.br/user/{u}",
            "dork_domain": "99freelas.com.br",
            "not_found": ["página não encontrada", "404"],
        },
        {
            "name": "Workana",
            "category": "Professional",
            "url": "https://www.workana.com/freelancer/{u}",
            "dork_domain": "workana.com",
            "not_found": ["404", "not found"],
        },

        # --- 8. DEV, SECOPS, AI & WEB3 ---
        {
            "name": "GitHub",
            "category": "Dev, SecOps & Web3",
            "url": "https://github.com/{u}",
            "api": "https://api.github.com/users/{u}",
            "dork_domain": "github.com",
        },
        {
            "name": "GitLab",
            "category": "Dev, SecOps & Web3",
            "url": "https://gitlab.com/{u}",
            "api": "https://gitlab.com/api/v4/users?username={u}",
            "dork_domain": "gitlab.com",
        },
        {
            "name": "Bitbucket",
            "category": "Dev, SecOps & Web3",
            "url": "https://bitbucket.org/{u}/",
            "dork_domain": "bitbucket.org",
            "not_found": ["page not found", "404"],
        },
        {
            "name": "HuggingFace",
            "category": "Dev, SecOps & Web3",
            "url": "https://huggingface.co/{u}",
            "dork_domain": "huggingface.co",
            "not_found": ["404", "sorry, we can't find"],
        },
        {
            "name": "Kaggle",
            "category": "Dev, SecOps & Web3",
            "url": "https://www.kaggle.com/{u}",
            "dork_domain": "kaggle.com",
            "not_found": ["404", "we can't find that page"],
        },
        {
            "name": "DockerHub",
            "category": "Dev, SecOps & Web3",
            "url": "https://hub.docker.com/u/{u}",
            "api": "https://hub.docker.com/v2/users/{u}/",
            "dork_domain": "hub.docker.com",
        },
        {
            "name": "PyPI",
            "category": "Dev, SecOps & Web3",
            "url": "https://pypi.org/user/{u}/",
            "dork_domain": "pypi.org",
            "not_found": ["page not found", "404"],
        },
        {
            "name": "npm",
            "category": "Dev, SecOps & Web3",
            "url": "https://www.npmjs.com/~{u}",
            "dork_domain": "npmjs.com",
            "not_found": ["not found", "404"],
        },
        {
            "name": "Crates.io (Rust)",
            "category": "Dev, SecOps & Web3",
            "url": "https://crates.io/users/{u}",
            "api": "https://crates.io/api/v1/users/{u}",
            "dork_domain": "crates.io",
        },
        {
            "name": "Dev.to",
            "category": "Dev, SecOps & Web3",
            "url": "https://dev.to/{u}",
            "api": "https://dev.to/api/users/by_username?url={u}",
            "dork_domain": "dev.to",
        },
        {
            "name": "Keybase",
            "category": "Dev, SecOps & Web3",
            "url": "https://keybase.io/{u}",
            "api": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}",
            "dork_domain": "keybase.io",
        },
        {
            "name": "HackerOne",
            "category": "Dev, SecOps & Web3",
            "url": "https://hackerone.com/{u}",
            "dork_domain": "hackerone.com",
            "not_found": ["page not found", "404"],
        },
        {
            "name": "Bugcrowd",
            "category": "Dev, SecOps & Web3",
            "url": "https://bugcrowd.com/{u}",
            "dork_domain": "bugcrowd.com",
            "not_found": ["page not found", "404"],
        },
        {
            "name": "TryHackMe",
            "category": "Dev, SecOps & Web3",
            "url": "https://tryhackme.com/p/{u}",
            "dork_domain": "tryhackme.com",
            "not_found": ["page not found", "404"],
        },
        {
            "name": "LeetCode",
            "category": "Dev, SecOps & Web3",
            "url": "https://leetcode.com/u/{u}/",
            "dork_domain": "leetcode.com",
            "not_found": ["page not found", "404"],
        },
        {
            "name": "OpenSea (Web3)",
            "category": "Dev, SecOps & Web3",
            "url": "https://opensea.io/{u}",
            "dork_domain": "opensea.io",
            "not_found": ["this page is lost", "404"],
        },
    ]

    @classmethod
    def _clean_handle(cls, raw: Optional[str]) -> str:
        if not raw:
            return ""
        text = raw.strip()
        if "://" in text:
            text = text.rstrip("/").split("/")[-1]
        return text.lstrip("@").strip()

    @staticmethod
    def _extract_html_title(html_snippet: str) -> str:
        match = re.search(r"<title[^>]*>(.*?)</title>", html_snippet, re.IGNORECASE | re.DOTALL)
        title = re.sub(r"\s+", " ", match.group(1)).strip() if match else ""
        og_match = re.search(
            r'<meta[^>]+(?:property|name)=["\']og:title["\'][^>]+content=["\']([^"\']+)["\']',
            html_snippet,
            re.IGNORECASE,
        )
        og_title = re.sub(r"\s+", " ", og_match.group(1)).strip() if og_match else ""
        combined = og_title or title
        return combined[:95]

    @classmethod
    def _check_platform(cls, platform: Dict[str, Any], username: str) -> Dict[str, Any]:
        name = platform["name"]
        category = platform.get("category", "Social Media")
        profile_link = platform["url"].format(u=username)
        dork_domain = platform.get("dork_domain", "")
        enc_u = quote_plus(username)
        dork_url = (
            f"https://www.google.com/search?q=site:{dork_domain}+%22{enc_u}%22"
            if dork_domain
            else f"https://www.google.com/search?q=%22{enc_u}%22+{quote_plus(name)}"
        )

        if platform.get("pivot_only"):
            return {
                "platform": name,
                "category": category,
                "url": dork_url,
                "dork_url": dork_url,
                "exists": False,
                "status_label": "DORK PIVOT",
                "details": f"App-only / Search index pivot (site:{dork_domain})",
            }

        api_endpoint = platform.get("api")
        exists = False
        status_label = "ABSENT"
        details = "HTTP 404 / Not Found"

        try:
            if name == "GitHub" and api_endpoint:
                r = requests.get(api_endpoint.format(u=username), headers=cls.API_HEADERS, timeout=4.0)
                if r.status_code == 200:
                    d = r.json()
                    exists = True
                    status_label = "VERIFIED"
                    details = f"{d.get('name') or username} • {d.get('public_repos', 0)} repos • {d.get('followers', 0)} followers"
            elif name == "GitLab" and api_endpoint:
                r = requests.get(api_endpoint.format(u=username), headers=cls.API_HEADERS, timeout=4.0)
                if r.status_code == 200 and isinstance(r.json(), list) and len(r.json()) > 0:
                    d = r.json()[0]
                    exists = True
                    status_label = "VERIFIED"
                    details = f"{d.get('name') or username} ({d.get('state', 'active')})"
            elif name == "Dev.to" and api_endpoint:
                r = requests.get(api_endpoint.format(u=username), headers=cls.API_HEADERS, timeout=4.0)
                if r.status_code == 200:
                    d = r.json()
                    exists = True
                    status_label = "VERIFIED"
                    details = d.get("summary") or d.get("name") or "Active Dev.to author"
            elif name == "HackerNews" and api_endpoint:
                r = requests.get(api_endpoint.format(u=username), headers=cls.API_HEADERS, timeout=4.0)
                if r.status_code == 200 and isinstance(r.json(), dict) and r.json().get("id"):
                    d = r.json()
                    exists = True
                    status_label = "VERIFIED"
                    details = f"Karma: {d.get('karma', 0)}"
            elif name == "Keybase" and api_endpoint:
                r = requests.get(api_endpoint.format(u=username), headers=cls.API_HEADERS, timeout=4.0)
                if r.status_code == 200:
                    them = r.json().get("them") or []
                    if them and them[0]:
                        exists = True
                        status_label = "VERIFIED"
                        details = "Cryptographic identity verified"
            elif name == "TabNews" and api_endpoint:
                r = requests.get(api_endpoint.format(u=username), headers=cls.API_HEADERS, timeout=4.0)
                if r.status_code == 200 and r.json().get("username"):
                    d = r.json()
                    exists = True
                    status_label = "VERIFIED"
                    details = f"TabCoins: {d.get('tabcoins', 0)}"
            elif name == "Reddit" and api_endpoint:
                r = requests.get(api_endpoint.format(u=username), headers=cls.API_HEADERS, timeout=4.0)
                if r.status_code == 200 and isinstance(r.json(), dict) and r.json().get("data", {}).get("name"):
                    d = r.json()["data"]
                    exists = True
                    status_label = "VERIFIED"
                    details = f"Karma: {d.get('total_karma', 0)}"
            elif name == "DockerHub" and api_endpoint:
                r = requests.get(api_endpoint.format(u=username), headers=cls.API_HEADERS, timeout=4.0)
                if r.status_code == 200 and r.json().get("username"):
                    d = r.json()
                    exists = True
                    status_label = "VERIFIED"
                    details = f"DockerHub namespace ({d.get('type', 'User')})"
            elif name == "Chess.com" and api_endpoint:
                r = requests.get(api_endpoint.format(u=username), headers=cls.API_HEADERS, timeout=4.0)
                if r.status_code == 200 and r.json().get("username"):
                    d = r.json()
                    exists = True
                    status_label = "VERIFIED"
                    details = f"Chess.com player ({d.get('followers', 0)} followers)"
            elif name == "Lichess" and api_endpoint:
                r = requests.get(api_endpoint.format(u=username), headers=cls.API_HEADERS, timeout=4.0)
                if r.status_code == 200 and r.json().get("id"):
                    d = r.json()
                    exists = True
                    status_label = "VERIFIED"
                    details = f"Lichess player • {d.get('count', {}).get('all', 0)} games"
            elif name == "Crates.io (Rust)" and api_endpoint:
                r = requests.get(api_endpoint.format(u=username), headers=cls.API_HEADERS, timeout=4.0)
                if r.status_code == 200 and r.json().get("user", {}).get("login"):
                    d = r.json()["user"]
                    exists = True
                    status_label = "VERIFIED"
                    details = f"Rust Crates author ({d.get('name') or username})"
            elif name == "Bluesky" and api_endpoint:
                r = requests.get(api_endpoint.format(u=username), headers=cls.API_HEADERS, timeout=4.0)
                if r.status_code == 200 and r.json().get("handle"):
                    d = r.json()
                    exists = True
                    status_label = "VERIFIED"
                    details = f"@{d.get('handle')} • {d.get('followersCount', 0)} followers"
            else:
                r = requests.get(profile_link, headers=cls.HEADERS, timeout=3.8, allow_redirects=True)
                snippet = (r.text or "")[:8000]
                snippet_lower = snippet.lower()
                not_found_markers = platform.get("not_found") or ["page not found", "404 not found"]
                must_contain = platform.get("must_contain")
                title = cls._extract_html_title(snippet)
                title_lower = title.lower()
                u_norm = re.sub(r"[^a-z0-9]", "", username.lower())
                title_norm = re.sub(r"[^a-z0-9]", "", title_lower)

                if r.status_code == 200:
                    if must_contain and must_contain.lower() not in snippet_lower:
                        exists = False
                        status_label = "ABSENT"
                        details = "Handle unoccupied"
                    elif any(nf.lower() in snippet_lower for nf in not_found_markers) or any(
                        err in title_lower for err in ("404", "not found", "error", "unavailable")
                    ):
                        exists = False
                        status_label = "ABSENT"
                        details = "Profile not found"
                    elif "/login" in (r.url or "").lower():
                        exists = False
                        status_label = "AUTH WALL"
                        details = "Login wall — use Dork Pivot or Direct Link"
                    elif (must_contain and must_contain.lower() in snippet_lower) or (
                        u_norm and len(u_norm) >= 3 and u_norm in title_norm
                    ):
                        exists = True
                        status_label = "VERIFIED"
                        details = title if title else "Verified Public Profile"
                    else:
                        exists = False
                        status_label = "SPA / DORK"
                        details = f"SPA shell ({title or name}) — inspect via Profile or Dork"
                elif r.status_code in (403, 429, 999):
                    status_label = "WAF / DORK"
                    details = f"HTTP {r.status_code} WAF protected — use Direct Link / Dork"
        except Exception:
            status_label = "TIMEOUT / DORK"
            details = "Probe timed out — use Direct Link / Dork"

        return {
            "platform": name,
            "category": category,
            "url": profile_link,
            "dork_url": dork_url,
            "exists": exists,
            "status_label": status_label,
            "details": str(details)[:140],
        }

    @classmethod
    def _github_deep_recon(cls, username: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "found": False,
            "avatar_url": "",
            "name": "",
            "bio": "",
            "company": "",
            "location": "",
            "blog": "",
            "email": "",
            "twitter_username": "",
            "public_repos": 0,
            "followers": 0,
            "created_at": "",
            "commit_emails": [],
            "top_repos": [],
        }
        if not username or "@" in username:
            return info

        try:
            r = requests.get(f"https://api.github.com/users/{username}", headers=cls.API_HEADERS, timeout=6)
            if r.status_code != 200:
                return info
            d = r.json()
            info.update(
                {
                    "found": True,
                    "avatar_url": d.get("avatar_url") or "",
                    "name": d.get("name") or username,
                    "bio": d.get("bio") or "",
                    "company": d.get("company") or "",
                    "location": d.get("location") or "",
                    "blog": d.get("blog") or "",
                    "email": d.get("email") or "",
                    "twitter_username": d.get("twitter_username") or "",
                    "public_repos": int(d.get("public_repos") or 0),
                    "followers": int(d.get("followers") or 0),
                    "created_at": d.get("created_at") or "",
                }
            )

            repos_r = requests.get(
                f"https://api.github.com/users/{username}/repos?sort=updated&per_page=6",
                headers=cls.API_HEADERS,
                timeout=5,
            )
            if repos_r.status_code == 200 and isinstance(repos_r.json(), list):
                for repo in repos_r.json()[:6]:
                    info["top_repos"].append(
                        {
                            "name": repo.get("name"),
                            "url": repo.get("html_url"),
                            "description": repo.get("description") or "",
                            "language": repo.get("language") or "N/A",
                            "stars": repo.get("stargazers_count", 0),
                        }
                    )

            events_r = requests.get(
                f"https://api.github.com/users/{username}/events/public?per_page=30",
                headers=cls.API_HEADERS,
                timeout=5,
            )
            emails_set = set()
            if info["email"]:
                emails_set.add(info["email"])
            if events_r.status_code == 200 and isinstance(events_r.json(), list):
                for ev in events_r.json():
                    for commit in ev.get("payload", {}).get("commits", []):
                        author_email = commit.get("author", {}).get("email")
                        if author_email and "noreply.github.com" not in author_email:
                            emails_set.add(author_email)
            info["commit_emails"] = sorted(emails_set)
        except Exception:
            pass

        return info

    @classmethod
    def _gravatar_recon(cls, query: str) -> Dict[str, Any]:
        clean = (query or "").strip().lower()
        if not clean:
            return {"avatar_url": "", "found": False, "hash": ""}
        sha256_hash = hashlib.sha256(clean.encode("utf-8")).hexdigest()
        found = False
        display_name = ""
        try:
            r = requests.get(f"https://en.gravatar.com/{sha256_hash}.json", headers=cls.API_HEADERS, timeout=4.5)
            if r.status_code == 200:
                found = True
                entry = (r.json().get("entry") or [{}])[0]
                display_name = entry.get("displayName") or entry.get("preferredUsername") or ""
        except Exception:
            pass
        return {
            "found": found,
            "hash": sha256_hash,
            "display_name": display_name,
            "avatar_url": f"https://www.gravatar.com/avatar/{sha256_hash}?d=identicon&s=200",
        }

    @classmethod
    def investigate_person(cls, raw_input: Optional[str], email: Optional[str] = None) -> Dict[str, Any]:
        """Run full Personal, Dating & Social OSINT reconnaissance across 60+ platforms."""
        handle = cls._clean_handle(raw_input)
        target_email = (email or (handle if "@" in handle else "")).strip()
        username = handle.split("@")[0] if "@" in handle else handle

        if not username and not target_email:
            return {
                "query": "",
                "username": "",
                "email": "",
                "avatar_url": "",
                "github": {"found": False},
                "gravatar": {"found": False},
                "platforms": [],
                "category_counts": {},
                "social_dorks": {},
            }

        with ThreadPoolExecutor(max_workers=24) as pool:
            gh_future = pool.submit(cls._github_deep_recon, username)
            grav_future = pool.submit(cls._gravatar_recon, target_email or username)
            plat_futures = [pool.submit(cls._check_platform, p, username) for p in cls.PLATFORMS]

            gh_info = gh_future.result()
            grav_info = grav_future.result()
            platforms = [f.result() for f in plat_futures]

        # Sort so VERIFIED profiles appear first within the list, preserving category order
        platforms.sort(key=lambda item: (0 if item.get("exists") else 1, item.get("category", ""), item.get("platform", "")))

        category_counts: Dict[str, int] = {}
        for p in platforms:
            cat = p.get("category", "Other")
            category_counts[cat] = category_counts.get(cat, 0) + 1

        avatar_url = gh_info.get("avatar_url") or grav_info.get("avatar_url") or ""
        enc = quote_plus(username)
        social_dorks = {
            "Tinder Web Profile & Bio Dork": f"https://www.google.com/search?q=site:tinder.com+%22{enc}%22+OR+%22tinder.com/@{enc}%22",
            "Dating Apps (Bumble / Badoo / OkCupid / Happn)": f"https://www.google.com/search?q=%22{enc}%22+(site:badoo.com+OR+site:okcupid.com+OR+site:bumble.com+OR+site:pof.com+OR+site:happn.com)",
            "Instagram Profile, Mentions & Tags": f"https://www.google.com/search?q=site:instagram.com+%22{enc}%22",
            "TikTok Profile, Videos & Comments": f"https://www.google.com/search?q=site:tiktok.com+%22{enc}%22",
            "Telegram Channels, Groups & Users (t.me)": f"https://www.google.com/search?q=site:t.me+%22{enc}%22",
            "WhatsApp Public Links (wa.me / chat.whatsapp)": f"https://www.google.com/search?q=%22{enc}%22+(site:wa.me+OR+site:chat.whatsapp.com+OR+site:api.whatsapp.com)",
            "OnlyFans / Privacy.com.br / Fansly Dork": f"https://www.google.com/search?q=%22{enc}%22+(site:onlyfans.com+OR+site:privacy.com.br+OR+site:fansly.com+OR+site:linktr.ee)",
            "X / Twitter Profile & Mentions": f"https://x.com/search?q={enc}&f=user",
            "Threads (@threads.net) Footprint": f"https://www.google.com/search?q=site:threads.net+%22{enc}%22",
            "LinkedIn Corporate & Executive Search": f"https://www.google.com/search?q=site:linkedin.com/in/+%22{enc}%22",
            "Facebook Public Directory & Groups": f"https://www.facebook.com/public/{enc}",
            "Discord / Steam / Gaming Aliases Dork": f"https://www.google.com/search?q=%22{enc}%22+(site:steamcommunity.com+OR+site:discord.com+OR+site:twitch.tv+OR+site:kick.com)",
            "GitHub Commits & Source Code Search": f"https://github.com/search?q=%22{enc}%22&type=commits",
            "Pastebin, Gists & Document Leaks Dork": f"https://www.google.com/search?q=%22{enc}%22+(site:pastebin.com+OR+site:gist.github.com+OR+filetype:pdf+OR+filetype:xlsx)",
            "Jusbrasil & Diários Oficiais (Brazil Legal)": f"https://www.jusbrasil.com.br/busca?q={enc}",
            "Escavador & Currículo Lattes (Brazil Academic)": f"https://www.google.com/search?q=%22{enc}%22+(site:escavador.com+OR+site:cnpq.br)",
        }

        return {
            "query": raw_input,
            "username": username,
            "email": target_email or (gh_info["commit_emails"][0] if gh_info.get("commit_emails") else ""),
            "avatar_url": avatar_url,
            "github": gh_info,
            "gravatar": grav_info,
            "platforms": platforms,
            "total_platforms": len(platforms),
            "found_count": sum(1 for p in platforms if p.get("exists")),
            "category_counts": category_counts,
            "social_dorks": social_dorks,
        }

    # --- Backward-Compatible Legacy Methods ---

    @classmethod
    def location_by_facebook(cls, profile: Optional[str]) -> Dict[str, str]:
        recon = cls.investigate_person(profile)
        gh = recon.get("github", {})
        loc: Dict[str, str] = {}
        if gh.get("location"):
            loc["Location"] = gh["location"]
        if gh.get("company"):
            loc["Company / Org"] = gh["company"]
        if gh.get("blog"):
            loc["Website / Blog"] = gh["blog"]
        if not loc and profile:
            loc["Target Handle"] = cls._clean_handle(profile)
        return loc

    @classmethod
    def perfil_picture(cls, profile: Optional[str]) -> str:
        recon = cls.investigate_person(profile)
        return recon.get("avatar_url") or ""

    @classmethod
    def likes(cls, profile: Optional[str]) -> List[str]:
        recon = cls.investigate_person(profile)
        discovered = [
            f"{p['platform']}: {p['url']} ({p['details']})"
            for p in recon.get("platforms", [])
            if p.get("exists")
        ]
        return discovered
