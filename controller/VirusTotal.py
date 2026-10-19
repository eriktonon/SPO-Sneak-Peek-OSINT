# -*- coding:UTF-8 -*-
"""
Threat Intelligence & Passive DNS Controller for SPO v2.0.
Upgraded from deprecated VirusTotal API v2 (with hardcoded key) to:
  1. VirusTotal API v3 (https://www.virustotal.com/api/v3/...) when key is provided.
  2. AlienVault OTX Passive DNS & Threat Pulses (100% free, zero-key fallback).
"""
import os
from typing import Any, Dict, List, Optional
import requests


class VirusTotal:
    HEADERS = {
        "User-Agent": "SPO-Sneak-Peek-OSINT/2.0 (+https://github.com/eriktonon/SPO-Sneak-Peek-OSINT)",
        "Accept": "application/json",
    }

    def searchDomain(self, ip_or_domain: str, api_key: Optional[str] = None) -> List[str]:
        """Return passive DNS resolutions (hostnames/IPs) for an IP or domain."""
        detailed = self.analyzeTarget(ip_or_domain, api_key=api_key)
        return detailed.get("resolutions", [])

    def analyzeTarget(self, target: str, api_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Query VirusTotal v3 (if key available) and AlienVault OTX for passive DNS
        resolutions and threat intelligence reputation.
        """
        clean = (target or "").strip()
        if not clean:
            return {"resolutions": [], "malicious": 0, "suspicious": 0, "harmless": 0, "pulses": 0, "source": None}

        vt_key = (api_key or os.environ.get("VIRUSTOTAL_API_KEY") or "").strip()
        resolutions: List[str] = []
        stats = {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
        pulses_count = 0
        sources_used: List[str] = []

        is_ip = all(part.isdigit() for part in clean.split(".")) and len(clean.split(".")) == 4

        # 1. VirusTotal API v3 (if key is configured)
        if vt_key:
            try:
                endpoint = f"ip_addresses/{clean}" if is_ip else f"domains/{clean}"
                vt_headers = {**self.HEADERS, "x-apikey": vt_key}
                resp = requests.get(
                    f"https://www.virustotal.com/api/v3/{endpoint}",
                    headers=vt_headers,
                    timeout=8,
                )
                if resp.status_code == 200:
                    attrs = resp.json().get("data", {}).get("attributes", {})
                    last_stats = attrs.get("last_analysis_stats", {})
                    for k in stats:
                        stats[k] = int(last_stats.get(k, 0))
                    sources_used.append("VirusTotal v3")

                res_resp = requests.get(
                    f"https://www.virustotal.com/api/v3/{endpoint}/resolutions?limit=25",
                    headers=vt_headers,
                    timeout=8,
                )
                if res_resp.status_code == 200:
                    for item in res_resp.json().get("data", []):
                        at = item.get("attributes", {})
                        val = at.get("host_name") if is_ip else at.get("ip_address")
                        if val and val not in resolutions:
                            resolutions.append(val)
            except Exception:
                pass

        # 2. AlienVault OTX Passive DNS & Threat Pulses (Free, Zero-Key)
        try:
            otx_type = "IPv4" if is_ip else "domain"
            otx_resp = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{clean}/passive_dns",
                headers=self.HEADERS,
                timeout=8,
            )
            if otx_resp.status_code == 200:
                for rec in otx_resp.json().get("passive_dns", [])[:35]:
                    val = rec.get("hostname") if is_ip else rec.get("address")
                    if val and val not in resolutions:
                        resolutions.append(val)
                if "AlienVault OTX" not in sources_used:
                    sources_used.append("AlienVault OTX")

            gen_resp = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{clean}/general",
                headers=self.HEADERS,
                timeout=6,
            )
            if gen_resp.status_code == 200:
                pulses_count = int(gen_resp.json().get("pulse_info", {}).get("count", 0))
        except Exception:
            pass

        return {
            "target": clean,
            "resolutions": resolutions[:40],
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "harmless": stats["harmless"],
            "undetected": stats["undetected"],
            "otx_pulses": pulses_count,
            "source": " + ".join(sources_used) if sources_used else "AlienVault OTX",
        }
