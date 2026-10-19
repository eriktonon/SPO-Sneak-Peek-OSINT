# -*- coding:UTF-8 -*-
"""
Subdomain Enumeration & Certificate Transparency Controller for SPO v2.0.
Replaces the defunct ThreatCrowd API with a multi-source OSINT pipeline:
  1. crt.sh (Certificate Transparency Logs JSON API)
  2. HackerTarget HostSearch API
  3. AlienVault OTX Passive DNS API
"""
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Set
import requests


class Subdomains:
    HEADERS = {
        "User-Agent": "SPO-Sneak-Peek-OSINT/2.0 (+https://github.com/eriktonon/SPO-Sneak-Peek-OSINT)",
        "Accept": "application/json",
    }

    @staticmethod
    def _clean_domain(domain: str) -> str:
        d = (domain or "").strip().lower()
        if "://" in d:
            d = d.split("://", 1)[1]
        d = d.split("/")[0].split(":")[0].strip(".")
        if d.startswith("www."):
            d = d[4:]
        return d

    def _from_crtsh(self, domain: str) -> Set[str]:
        found: Set[str] = set()
        try:
            resp = requests.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                headers=self.HEADERS,
                timeout=10,
            )
            if resp.status_code == 200:
                for entry in resp.json():
                    name_val = str(entry.get("name_value") or "")
                    for line in name_val.splitlines():
                        sub = line.strip().lower().lstrip("*.")
                        if sub.endswith(domain) and " " not in sub:
                            found.add(sub)
        except Exception:
            pass
        return found

    def _from_hackertarget(self, domain: str) -> Set[str]:
        found: Set[str] = set()
        try:
            resp = requests.get(
                "https://api.hackertarget.com/hostsearch/",
                params={"q": domain},
                headers=self.HEADERS,
                timeout=8,
            )
            if resp.status_code == 200 and "API count exceeded" not in resp.text:
                for line in resp.text.splitlines():
                    parts = line.split(",")
                    if parts:
                        sub = parts[0].strip().lower()
                        if sub.endswith(domain) and " " not in sub:
                            found.add(sub)
        except Exception:
            pass
        return found

    def _from_alienvault_otx(self, domain: str) -> Set[str]:
        found: Set[str] = set()
        try:
            resp = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                headers=self.HEADERS,
                timeout=8,
            )
            if resp.status_code == 200:
                data = resp.json()
                for record in data.get("passive_dns", []):
                    hostname = str(record.get("hostname") or "").strip().lower()
                    if hostname.endswith(domain) and " " not in hostname:
                        found.add(hostname)
        except Exception:
            pass
        return found

    def getSubdomains(self, domain: str) -> List[str]:
        """Return deduplicated, sorted list of discovered subdomains for a domain."""
        clean = self._clean_domain(domain)
        if not clean:
            return []

        combined: Set[str] = set()
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = [
                pool.submit(self._from_crtsh, clean),
                pool.submit(self._from_hackertarget, clean),
                pool.submit(self._from_alienvault_otx, clean),
            ]
            for fut in futures:
                try:
                    combined.update(fut.result(timeout=12))
                except Exception:
                    pass

        return sorted(combined)[:100]

    def getSubdomainsDetailed(self, domain: str, resolve_limit: int = 20) -> List[Dict[str, Any]]:
        """Return subdomains with resolved IPv4 addresses for the top hosts."""
        subs = self.getSubdomains(domain)
        results: List[Dict[str, Any]] = []

        def _resolve(host: str) -> Dict[str, Any]:
            ip = None
            try:
                ip = socket.gethostbyname(host)
            except Exception:
                pass
            return {"subdomain": host, "ip": ip}

        with ThreadPoolExecutor(max_workers=8) as pool:
            resolved = list(pool.map(_resolve, subs[:resolve_limit]))

        results.extend(resolved)
        for host in subs[resolve_limit:]:
            results.append({"subdomain": host, "ip": None})
        return results
