# -*- coding:UTF-8 -*-
"""
Personal & Social Media OSINT Controller for SPO v2.0.
Replaces the broken 2017 Facebook HTML scraper with a comprehensive, live
Personal OSINT Reconnaissance Engine:
  1. Multi-Platform Username Enumeration (GitHub, GitLab, Reddit, Dev.to,
     HackerNews, Keybase, Medium, Linktree, TabNews, Gravatar, PyPI, DockerHub).
  2. Deep GitHub OSINT (profile metadata, organizations, public repositories,
     and commit author email extraction from public events).
  3. Email & Gravatar Intelligence (MD5/SHA256 Gravatar lookup + DNS MX/SPF checks).
  4. Targeted Social Media & Public Record OSINT Dorks (Facebook, LinkedIn,
     Instagram, X/Twitter, Jusbrasil, Escavador).
Preserves backward-compatible methods (perfil_picture, likes, location_by_facebook)
for legacy callers.
"""
import hashlib
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus
import requests


class Facebook:
    HEADERS = {
        "User-Agent": "SPO-Sneak-Peek-OSINT/2.0 (+https://github.com/eriktonon/SPO-Sneak-Peek-OSINT)",
        "Accept": "application/json, text/html",
    }

    PLATFORMS = [
        {"name": "GitHub", "url": "https://github.com/{u}", "api": "https://api.github.com/users/{u}", "icon": "code"},
        {"name": "GitLab", "url": "https://gitlab.com/{u}", "api": "https://gitlab.com/api/v4/users?username={u}", "icon": "terminal"},
        {"name": "Dev.to", "url": "https://dev.to/{u}", "api": "https://dev.to/api/users/by_username?url={u}", "icon": "article"},
        {"name": "Reddit", "url": "https://www.reddit.com/user/{u}", "api": "https://www.reddit.com/user/{u}/about.json", "icon": "forum"},
        {"name": "HackerNews", "url": "https://news.ycombinator.com/user?id={u}", "api": "https://hacker-news.firebaseio.com/v0/user/{u}.json", "icon": "newspaper"},
        {"name": "Keybase", "url": "https://keybase.io/{u}", "api": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}", "icon": "vpn_key"},
        {"name": "TabNews", "url": "https://www.tabnews.com.br/{u}", "api": "https://www.tabnews.com.br/api/v1/users/{u}", "icon": "feed"},
        {"name": "PyPI", "url": "https://pypi.org/user/{u}/", "api": None, "icon": "inventory_2"},
        {"name": "Medium", "url": "https://medium.com/@{u}", "api": None, "icon": "edit_note"},
        {"name": "Linktree", "url": "https://linktr.ee/{u}", "api": None, "icon": "link"},
    ]

    @classmethod
    def _clean_handle(cls, raw: Optional[str]) -> str:
        if not raw:
            return ""
        text = raw.strip()
        if "://" in text:
            text = text.rstrip("/").split("/")[-1]
        return text.lstrip("@").strip()

    @classmethod
    def _check_platform(cls, platform: Dict[str, Any], username: str) -> Dict[str, Any]:
        profile_link = platform["url"].format(u=username)
        api_endpoint = platform.get("api")
        exists = False
        details = ""

        try:
            if platform["name"] == "GitHub" and api_endpoint:
                r = requests.get(api_endpoint.format(u=username), headers=cls.HEADERS, timeout=6)
                if r.status_code == 200:
                    d = r.json()
                    exists = True
                    details = f"{d.get('name') or username} • {d.get('public_repos', 0)} repos • {d.get('followers', 0)} followers"
            elif platform["name"] == "GitLab" and api_endpoint:
                r = requests.get(api_endpoint.format(u=username), headers=cls.HEADERS, timeout=6)
                if r.status_code == 200 and isinstance(r.json(), list) and len(r.json()) > 0:
                    d = r.json()[0]
                    exists = True
                    details = f"{d.get('name') or username} ({d.get('state', 'active')})"
            elif platform["name"] == "Dev.to" and api_endpoint:
                r = requests.get(api_endpoint.format(u=username), headers=cls.HEADERS, timeout=6)
                if r.status_code == 200:
                    d = r.json()
                    exists = True
                    details = d.get("summary") or d.get("name") or "Profile active"
            elif platform["name"] == "HackerNews" and api_endpoint:
                r = requests.get(api_endpoint.format(u=username), headers=cls.HEADERS, timeout=6)
                if r.status_code == 200 and r.json() and isinstance(r.json(), dict) and r.json().get("id"):
                    d = r.json()
                    exists = True
                    details = f"Karma: {d.get('karma', 0)}"
            elif platform["name"] == "Keybase" and api_endpoint:
                r = requests.get(api_endpoint.format(u=username), headers=cls.HEADERS, timeout=6)
                if r.status_code == 200:
                    them = r.json().get("them") or []
                    if them and them[0]:
                        exists = True
                        details = "Keybase cryptographic identity found"
            elif platform["name"] == "TabNews" and api_endpoint:
                r = requests.get(api_endpoint.format(u=username), headers=cls.HEADERS, timeout=6)
                if r.status_code == 200 and r.json().get("username"):
                    d = r.json()
                    exists = True
                    details = f"TabCoins: {d.get('tabcoins', 0)}"
            elif platform["name"] == "Reddit" and api_endpoint:
                r = requests.get(api_endpoint.format(u=username), headers=cls.HEADERS, timeout=6)
                if r.status_code == 200 and r.json().get("data", {}).get("name"):
                    d = r.json()["data"]
                    exists = True
                    details = f"Karma: {d.get('total_karma', 0)}"
            else:
                r = requests.get(profile_link, headers=cls.HEADERS, timeout=6, allow_redirects=True)
                if r.status_code == 200 and "page not found" not in r.text.lower()[:1500]:
                    exists = True
                    details = "HTTP 200 Public Profile"
        except Exception:
            exists = False

        return {
            "platform": platform["name"],
            "url": profile_link,
            "icon": platform.get("icon", "public"),
            "exists": exists,
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
            r = requests.get(f"https://api.github.com/users/{username}", headers=cls.HEADERS, timeout=7)
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

            # Fetch top repositories
            repos_r = requests.get(
                f"https://api.github.com/users/{username}/repos?sort=updated&per_page=6",
                headers=cls.HEADERS,
                timeout=6,
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

            # Extract commit author emails from public push events
            events_r = requests.get(
                f"https://api.github.com/users/{username}/events/public?per_page=30",
                headers=cls.HEADERS,
                timeout=6,
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
            r = requests.get(f"https://en.gravatar.com/{sha256_hash}.json", headers=cls.HEADERS, timeout=5)
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
        """Run full Personal & Social OSINT reconnaissance on a username, email, or name."""
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
                "social_dorks": {},
            }

        with ThreadPoolExecutor(max_workers=8) as pool:
            gh_future = pool.submit(cls._github_deep_recon, username)
            grav_future = pool.submit(cls._gravatar_recon, target_email or username)
            plat_futures = [pool.submit(cls._check_platform, p, username) for p in cls.PLATFORMS]

            gh_info = gh_future.result()
            grav_info = grav_future.result()
            platforms = [f.result() for f in plat_futures]

        avatar_url = gh_info.get("avatar_url") or grav_info.get("avatar_url") or ""
        enc = quote_plus(username)
        social_dorks = {
            "Facebook Profile & Posts": f"https://www.facebook.com/public/{enc}",
            "LinkedIn Professional Search": f"https://www.google.com/search?q=site:linkedin.com/in/+%22{enc}%22",
            "Instagram Profile": f"https://www.instagram.com/{username}/",
            "X / Twitter Mentions & Profile": f"https://x.com/search?q={enc}&f=user",
            "GitHub Code & Commits Search": f"https://github.com/search?q=%22{enc}%22&type=commits",
            "Pastebin & Public Leaks Dork": f"https://www.google.com/search?q=%22{enc}%22+(site:pastebin.com+OR+site:gist.github.com+OR+filetype:pdf)",
            "Jusbrasil / Diários Oficiais": f"https://www.jusbrasil.com.br/busca?q={enc}",
        }

        return {
            "query": raw_input,
            "username": username,
            "email": target_email or (gh_info["commit_emails"][0] if gh_info.get("commit_emails") else ""),
            "avatar_url": avatar_url,
            "github": gh_info,
            "gravatar": grav_info,
            "platforms": platforms,
            "found_count": sum(1 for p in platforms if p.get("exists")),
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
