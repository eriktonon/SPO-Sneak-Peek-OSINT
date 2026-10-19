# -*- coding:UTF-8 -*-
"""
Server, IP & Vulnerability Reconnaissance Controller for SPO v2.0.
Combines:
  1. Shodan InternetDB (https://internetdb.shodan.io/{ip}) — 100% Free, Zero API Key!
     Returns open ports, hostnames, CPEs, tags, and known CVEs (vulnerabilities).
  2. IP Geolocation & ASN Intelligence (ip-api.com).
  3. Full Shodan API (when user configures their Shodan API key in /insertKeys).
"""
import socket
from typing import Any, Dict, Optional
import requests

try:
    import shodan as shodan_sdk
except ImportError:
    shodan_sdk = None


class Shodan:
    HEADERS = {
        "User-Agent": "SPO-Sneak-Peek-OSINT/2.0 (+https://github.com/eriktonon/SPO-Sneak-Peek-OSINT)",
        "Accept": "application/json",
    }

    @staticmethod
    def resolve_target_ip(target: str) -> Optional[str]:
        clean = (target or "").strip().lower()
        if "://" in clean:
            clean = clean.split("://", 1)[1]
        clean = clean.split("/")[0].split(":")[0]
        if not clean:
            return None
        try:
            return socket.gethostbyname(clean)
        except Exception:
            return None

    def query_internetdb(self, ip: str) -> Dict[str, Any]:
        """Query Shodan InternetDB (free, no API key needed) for ports, CVEs, CPEs, hostnames."""
        if not ip:
            return {}
        try:
            resp = requests.get(
                f"https://internetdb.shodan.io/{ip}",
                headers=self.HEADERS,
                timeout=8,
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return {}

    def query_ip_geo(self, ip: str) -> Dict[str, Any]:
        """Query IP Geolocation, ASN, ISP, and Reverse DNS."""
        if not ip:
            return {}
        try:
            resp = requests.get(
                f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,reverse,hosting,proxy,query",
                headers=self.HEADERS,
                timeout=6,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return data
        except Exception:
            pass
        return {}

    def search(self, key: Optional[str], query: str) -> Dict[str, Any]:
        """
        Perform comprehensive Server & Service OSINT on an IP, domain, or Shodan query.
        Always returns InternetDB + Geo/ASN intelligence even if no Shodan API key is set!
        """
        clean_query = (query or "").strip()
        if not clean_query:
            return {"error": "Empty target or query"}

        resolved_ip = self.resolve_target_ip(clean_query)
        internetdb_data = self.query_internetdb(resolved_ip) if resolved_ip else {}
        geo_data = self.query_ip_geo(resolved_ip) if resolved_ip else {}

        result: Dict[str, Any] = {
            "target": clean_query,
            "ip": resolved_ip,
            "ports": internetdb_data.get("ports", []),
            "hostnames": internetdb_data.get("hostnames", []),
            "cpes": internetdb_data.get("cpes", []),
            "vulns": internetdb_data.get("vulns", []),
            "tags": internetdb_data.get("tags", []),
            "geo": geo_data,
            "shodan_api_used": False,
            "shodan_banners": [],
            "shodan_total": 0,
            "shodan_error": None,
        }

        if key and shodan_sdk:
            try:
                api = shodan_sdk.Shodan(key.strip())
                if resolved_ip and clean_query == resolved_ip:
                    host_info = api.host(resolved_ip)
                    result["shodan_api_used"] = True
                    result["shodan_total"] = len(host_info.get("data", []))
                    for item in host_info.get("data", [])[:15]:
                        result["shodan_banners"].append(
                            {
                                "ip_str": item.get("ip_str") or resolved_ip,
                                "port": item.get("port"),
                                "transport": item.get("transport", "tcp"),
                                "product": item.get("product") or item.get("_shodan", {}).get("module", ""),
                                "version": item.get("version") or "",
                                "org": item.get("org") or host_info.get("org") or "",
                                "data": str(item.get("data") or "")[:400],
                            }
                        )
                else:
                    search_res = api.search(clean_query, limit=15)
                    result["shodan_api_used"] = True
                    result["shodan_total"] = search_res.get("total", 0)
                    for match in search_res.get("matches", [])[:15]:
                        result["shodan_banners"].append(
                            {
                                "ip_str": match.get("ip_str"),
                                "port": match.get("port"),
                                "transport": match.get("transport", "tcp"),
                                "product": match.get("product") or "",
                                "version": match.get("version") or "",
                                "org": match.get("org") or "",
                                "data": str(match.get("data") or "")[:400],
                            }
                        )
            except Exception as exc:
                result["shodan_error"] = str(exc)

        return result
