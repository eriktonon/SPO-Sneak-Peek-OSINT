# SPO — Sneak Peek OSINT v2.0 (2026 Edition)

> **Tactical Open Source Intelligence (OSINT) Reconnaissance Platform** for Security Researchers, Penetration Testers, Threat Intelligence Analysts, Lawyers, HR, and Investigative Journalists.

---

## What Changed in v2.0 (2026 Modernization)

| Area | Legacy v1.0 (2018) | Modern v2.0 (2026) |
|---|---|---|
| **Runtime & Web Stack** | Python 3.5 (with `vspo/` virtualenv committed to git) + Flask 0.12 | **Python 3.10–3.12+**, **Flask 3.x**, **Gunicorn**, **Docker Compose** |
| **Database & Vault** | Hardcoded MySQL (`japonesdafederal`), raw string SQL concatenation | **Zero-Config SQLite WAL (`data/spo.db`)**, **100% Parameterized SQL**, full Case/Project CRUD & JSON Report Export |
| **Authentication & Security** | Static salt `"potato"` SHA-256, broken `validatorSQLI.py` (`find > 0`), `KeyError` on unauthenticated routes | **PBKDF2-SHA256** salted hashing (`werkzeug.security`), `@login_required` guard, security headers (`nosniff`, `SAMEORIGIN`) |
| **Domain & WHOIS Recon** | `python-whois` only (crashed with `UnboundLocalError` if `ownerid` != 18 chars) | **Registro.br RDAP + IANA RDAP JSON** + **Google DoH DNS (`A`, `MX`, `NS`, `TXT`)** + `python-whois` fallback |
| **Company & CNPJ OSINT** | Defunct `compras.dados.gov.br` HTTP endpoint & CAPTCHA-blocked Receita ASP pages | **BrasilAPI CNPJ v1 + ReceitaWS** (Razão Social, QSA Partners, Capital Social, CNAEs) + **PNCP & Portal da Transparência** |
| **Subdomain Enumeration** | Defunct `threatcrowd.org` API | **crt.sh (Certificate Transparency)** + **HackerTarget** + **AlienVault OTX Passive DNS** with concurrent IP resolution |
| **Legal & Jurisprudence** | Broken Jusbrasil HTML scraper | **Querido Diário API (Official Gazettes)** + **Jusbrasil / DOU / Escavador / CEIS-CNEP Sanctions** pivots |
| **Server & Threat Intel** | Unfinished stub (`searchServers.html` was empty) & hardcoded VirusTotal v2 key | **Shodan InternetDB (Free Open Ports, CPEs & CVEs)** + **IP Geo/ASN** + **AlienVault OTX** + optional **Shodan & VirusTotal v3** |
| **Personal & Social OSINT** | Broken 2017 Facebook HTML class scraper (`_6a _6b`) | **10-Platform Concurrent Username Recon** + **GitHub Deep Recon & Commit Email Extractor** + **Gravatar** + Social Dorks |

---

## Quick Start

### Option 1: Local Python (Zero-Config SQLite)

```bash
git clone https://github.com/eriktonon/SPO-Sneak-Peek-OSINT.git
cd SPO-Sneak-Peek-OSINT
python -m venv .venv
# Windows: .venv\Scripts\activate | Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

Open **`http://localhost:1337`** in your browser. On first access, SPO automatically initializes `data/spo.db` and guides you through creating your first operator account.

### Option 2: Docker Compose

```bash
docker compose up --build -d
```

---

## Running Tests

```bash
pytest -v
```

---

## Credits & License

- **Original Creator (2018)**: Victor de Queiroz (`CATx003@protonmail.com`)
- **v2.0 Architecture & Modernization (2026)**: Erik Tonon
- **License**: GNU General Public License v2.0 (`GPL-2.0-only`)
