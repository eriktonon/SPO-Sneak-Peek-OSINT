# -*- coding:UTF-8 -*-
"""
Domain WHOIS, RDAP (Registro.br & IANA), and DNS Reconnaissance controller for SPO v2.0.
Uses structured RDAP JSON APIs first with fallback to python-whois and DNS-over-HTTPS (DoH).
"""
import re
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import requests

try:
    import whois as pywhois
except ImportError:
    pywhois = None


class Whois:
    HEADERS = {
        "User-Agent": "SPO-Sneak-Peek-OSINT/2.0 (+https://github.com/eriktonon/SPO-Sneak-Peek-OSINT)",
        "Accept": "application/rdap+json, application/json",
    }

    @staticmethod
    def normalize_domain(raw: Optional[str]) -> str:
        if not raw:
            return ""
        text = raw.strip().lower()
        if "://" in text:
            parsed = urlparse(text)
            text = parsed.netloc or parsed.path
        text = text.split("/")[0].split(":")[0].strip(".")
        if text.startswith("www."):
            text = text[4:]
        return text

    @staticmethod
    def _format_cnpj_if_match(doc: str) -> str:
        digits = re.sub(r"\D", "", doc or "")
        if len(digits) == 14:
            return f"{digits[:2]}.{digits[2:5]}.{digits[5:8]}/{digits[8:12]}-{digits[12:14]}"
        if len(digits) == 11:
            return f"{digits[:3]}.{digits[3:6]}.{digits[6:9]}-{digits[9:11]}"
        return doc

    def _query_rdap(self, domain: str) -> Dict[str, Any]:
        rdap_urls = []
        if domain.endswith(".br"):
            rdap_urls.append(f"https://rdap.registro.br/domain/{domain}")
        rdap_urls.append(f"https://rdap.org/domain/{domain}")

        for url in rdap_urls:
            try:
                resp = requests.get(url, headers=self.HEADERS, timeout=8)
                if resp.status_code == 200:
                    return resp.json()
            except Exception:
                continue
        return {}

    def _parse_rdap(self, rdap: Dict[str, Any]) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "owner": None,
            "ownerid": None,
            "owneremail": None,
            "created": None,
            "expires": None,
            "updated": None,
            "country": None,
            "nameservers": [],
            "status": rdap.get("status", []),
        }
        if not rdap:
            return info

        # Nameservers
        for ns in rdap.get("nameservers", []):
            ldh = ns.get("ldhName")
            if ldh:
                info["nameservers"].append(ldh.lower())

        # Events (registration, expiration, last changed)
        for ev in rdap.get("events", []):
            action = (ev.get("eventAction") or "").lower()
            date = ev.get("eventDate")
            if "registration" in action and not info["created"]:
                info["created"] = date
            elif "expiration" in action and not info["expires"]:
                info["expires"] = date
            elif ("last changed" in action or "update" in action) and not info["updated"]:
                info["updated"] = date

        # Entities (registrant, administrative, technical, abuse)
        for ent in rdap.get("entities", []):
            roles = [r.lower() for r in ent.get("roles", [])]
            handle = ent.get("handle") or ""
            # Registro.br places CNPJ/CPF in publicIds or handle
            for pid in ent.get("publicIds", []):
                identifier = pid.get("identifier")
                if identifier and not info["ownerid"]:
                    info["ownerid"] = self._format_cnpj_if_match(identifier)

            if not info["ownerid"] and re.fullmatch(r"\d{11}|\d{14}", re.sub(r"\D", "", handle)):
                info["ownerid"] = self._format_cnpj_if_match(handle)

            vcard = ent.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
                for item in vcard[1]:
                    if not isinstance(item, list) or len(item) < 4:
                        continue
                    prop_name = str(item[0]).lower()
                    prop_val = item[3]
                    if prop_name == "fn" and prop_val and ("registrant" in roles or not info["owner"]):
                        info["owner"] = str(prop_val)
                    elif prop_name == "email" and prop_val and not info["owneremail"]:
                        info["owneremail"] = str(prop_val)
                    elif prop_name == "adr" and isinstance(prop_val, list) and len(prop_val) >= 7:
                        country_val = prop_val[-1]
                        if country_val and not info["country"]:
                            info["country"] = str(country_val)

            # Nested entities
            for sub_ent in ent.get("entities", []):
                sub_vcard = sub_ent.get("vcardArray")
                if isinstance(sub_vcard, list) and len(sub_vcard) > 1:
                    for item in sub_vcard[1]:
                        if isinstance(item, list) and len(item) >= 4:
                            if str(item[0]).lower() == "email" and item[3] and not info["owneremail"]:
                                info["owneremail"] = str(item[3])

        # Fallback: Registro.br sometimes puts representative name in remarks or legal-representative
        return info

    def _query_dns_records(self, domain: str) -> Dict[str, List[str]]:
        records: Dict[str, List[str]] = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": []}
        if not domain:
            return records

        # Fast A/AAAA via socket first
        try:
            for res in socket.getaddrinfo(domain, None):
                ip = res[4][0]
                if ":" in ip:
                    if ip not in records["AAAA"]:
                        records["AAAA"].append(ip)
                else:
                    if ip not in records["A"]:
                        records["A"].append(ip)
        except Exception:
            pass

        # DNS-over-HTTPS (Google DoH JSON API) for MX, NS, TXT, A
        for rtype in ("A", "MX", "NS", "TXT"):
            try:
                resp = requests.get(
                    "https://dns.google/resolve",
                    params={"name": domain, "type": rtype},
                    headers={"Accept": "application/dns-json"},
                    timeout=5,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for ans in data.get("Answer", []):
                        val = str(ans.get("data", "")).strip('"')
                        if val and val not in records[rtype]:
                            records[rtype].append(val)
            except Exception:
                continue

        return records

    def owner(self, domain: Optional[str]) -> Dict[str, Any]:
        """Return domain ownership, RDAP metadata, and DNS records."""
        clean_domain = self.normalize_domain(domain)
        if not clean_domain:
            return {
                "owner": None,
                "ownerid": None,
                "owneremail": None,
                "created": None,
                "expires": None,
                "country": None,
                "nameservers": [],
                "status": [],
                "dns": {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": []},
            }

        rdap_raw = self._query_rdap(clean_domain)
        parsed = self._parse_rdap(rdap_raw)

        # Fallback to python-whois if RDAP missed fields
        if pywhois and (not parsed.get("owner") or not parsed.get("created")):
            try:
                w = pywhois.whois(clean_domain)
                if not parsed.get("owner"):
                    parsed["owner"] = w.get("owner") or w.get("org") or w.get("name")
                if not parsed.get("ownerid") and w.get("ownerid"):
                    parsed["ownerid"] = self._format_cnpj_if_match(str(w.get("ownerid")))
                if not parsed.get("owneremail"):
                    emails = w.get("emails") or w.get("email")
                    if isinstance(emails, list) and emails:
                        parsed["owneremail"] = emails[0]
                    elif isinstance(emails, str):
                        parsed["owneremail"] = emails
                if not parsed.get("created") and w.get("creation_date"):
                    cdate = w.get("creation_date")
                    parsed["created"] = str(cdate[0] if isinstance(cdate, list) else cdate)
                if not parsed.get("expires") and w.get("expiration_date"):
                    edate = w.get("expiration_date")
                    parsed["expires"] = str(edate[0] if isinstance(edate, list) else edate)
                if not parsed.get("country") and w.get("country"):
                    parsed["country"] = str(w.get("country"))
            except Exception:
                pass

        if isinstance(parsed.get("owner"), list):
            parsed["owner"] = ", ".join(str(x) for x in parsed["owner"] if x)

        parsed["dns"] = self._query_dns_records(clean_domain)
        if not parsed.get("nameservers") and parsed["dns"].get("NS"):
            parsed["nameservers"] = parsed["dns"]["NS"]

        return parsed

    def domainInfo(self, domain: Optional[str]) -> Dict[str, Any]:
        """Return expiration date, creation date, and country."""
        info = self.owner(domain)
        return {
            "expires": info.get("expires"),
            "country": info.get("country"),
            "created": info.get("created"),
            "nameservers": info.get("nameservers", []),
            "dns": info.get("dns", {}),
        }
