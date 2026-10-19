# SPO — Sneak Peek OSINT v2.0 (2026 Edition)

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Flask 3.x](https://img.shields.io/badge/Flask-3.x-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Security: Strix & OWASP Top 10](https://img.shields.io/badge/Security-Strix%20DAST%20%2B%20OWASP%20Top%2010-e11d48?logo=securityscorecard&logoColor=white)](SECURITY.md)
[![SQLite WAL](https://img.shields.io/badge/Database-SQLite%20WAL%20(Zero--Config)-003B57?logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-10b981.svg)](LICENSE)
[![Sponsor @eriktonon](https://img.shields.io/badge/Sponsor-%40eriktonon-ea4aaa?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/eriktonon)

```text
             ██████  ██▓███   ▒█████  
           ▒██    ▒ ▓██░  ██▒▒██▒  ██▒
           ░ ▓██▄   ▓██░ ██▓▒▒██░  ██▒
             ▒   ██▒▒██▄█▓▒ ▒▒██   ██░
           ▒██████▒▒▒██▒ ░  ░░ ████▓▒░
           ▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░░ ▒░▒░▒░ 
           ░ ░▒  ░ ░░▒ ░       ░ ▒ ▒░ 
           ░  ░  ░  ░░       ░ ░ ░ ▒  
                 ░               ░ ░

     S n e a k   P e e k   O S I N T   v 2 . 0
     Lead Architect & Maintainer: Erik Tonon (@eriktonon)
```

**Sneak Peek OSINT (SPO)** is an Open-Source Intelligence (OSINT) reconnaissance and **Offensive-Defensive AppSec platform** engineered for **Security Researchers, Penetration Testers, Threat Intelligence Analysts, Compliance & Legal Teams, HR Professionals, and Investigative Journalists**.

In **v2.0 (2026 Edition)**, SPO has been completely modernized and hardened with **PE-AGENTS-IBM Shift-Left Security** and the **Strix DAST & Prevention Engine** (`/pentest-strix` + `/PE-AGENTS-IBM Segurança`), featuring a **Zero-Config SQLite WAL persistence layer**, **100% free zero-key OSINT intelligence providers**, and a **Tactical Dark UI**.

---

## 🛡️ What's New in v2.0 (2026 Edition)

| Module / Layer | Legacy v1.0 (2018) | Modernized v2.0 (2026 — Erik Tonon) |
| :--- | :--- | :--- |
| **Runtime & Web Stack** | Python 3.5 + Flask 0.12 + committed `vspo/` venv | **Python 3.10–3.12 + Flask 3.x + Gunicorn + Non-Root Docker Compose** |
| **Database Engine** | Manual MySQL server setup + raw SQL string concatenation | **Zero-Config SQLite WAL (`data/spo.db`) + 100% Parameterized SQL** |
| **Authentication & AuthZ** | Static `"potato"` SHA-256 salt + no rate limiting | **Salted `PBKDF2-HMAC-SHA256` + Constant-Time Digest + Sliding-Window Brute-Force Shield + CSRF Tokens** |
| **Strix DAST & Prevention (`/pentest-strix`)** | *None* | **Built-in Black-Box Surface DAST Auditor (OWASP Top 10 headers, TLS cipher inspection, `.env`/`.git` exposure probes, DNS SPF/DMARC anti-spoofing, CVSS v3.1 scoring & Shift-Left Autofix snippets)** |
| **SSRF & Network Guardrail (`/PE-AGENTS-IBM Segurança`)** | Unvalidated outbound requests | **`SSRFGuard` blocking loopback, RFC1918 private networks, Cloud Metadata (`169.254.169.254`), DNS Rebinding, and critical gateway `192.168.3.1`** |
| **Domain & WHOIS Recon** | Legacy `python-whois` only | **Registro.br & IANA RDAP JSON APIs + Google DNS-over-HTTPS (A, AAAA, MX, NS, TXT) + `python-whois` fallback** |
| **Brazilian Corporate OSINT (CNPJ)** | Defunct `compras.dados.gov.br` HTTP endpoint | **BrasilAPI + ReceitaWS multi-provider pipeline (QSA Partners, Capital Social, CNAEs) + Portal da Transparência & PNCP links** |
| **Subdomain Discovery** | Defunct ThreatCrowd API | **Concurrent multi-source enumeration: Certificate Transparency (`crt.sh`) + HackerTarget + AlienVault OTX Passive DNS + live IPv4 resolution** |
| **Server, IP & Vulnerability Intel** | Required paid Shodan key + hardcoded VirusTotal v2 key | **Zero-Key Shodan InternetDB (open ports, CPEs, CVEs) + IP Geolocation/ASN + VirusTotal API v3 + AlienVault OTX Threat Pulses** |
| **Personal & Social Recon** | Broken 2017 Facebook HTML scraper | **Concurrent 10-platform username recon + Deep GitHub OSINT (repos + commit author email extraction) + SHA-256 Gravatar + Social Dorks** |

---

## 🔒 Preventive Tactics & Strix Security Engine (`/pentest-strix` & `/PE-AGENTS-IBM Segurança`)

SPO v2.0 implements both **internal Shift-Left self-protection** and **external Offensive-Defensive DAST auditing** in [`controller/StrixSecurity.py`](controller/StrixSecurity.py):

### 1. Internal Shift-Left Hardening (Protecting SPO Operator & Infrastructure)
- **`SSRFGuard` (OWASP A10:2021)**: Validates every target domain/IP before executing outbound OSINT or DAST requests. Automatically blocks loopback (`127.0.0.0/8`, `::1`), RFC1918 internal networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local Cloud Metadata (`169.254.169.254`), DNS Rebinding, and enforces a strict guardrail on `192.168.3.1`.
- **`LoginRateLimiter` (OWASP A04 / A07:2021)**: Sliding-window rate limiter per client IP that automatically locks out credential-stuffing or brute-force attempts (`HTTP 429`).
- **`CSRFShield` & `PasswdHash` (OWASP A01 / A02:2021)**: Synchronizer token validation and password verification using `hmac.compare_digest` (constant-time execution) with salted `PBKDF2-HMAC-SHA256`.
- **`SecurityHeadersMiddleware` (OWASP A05:2021)**: Automatically injects `Content-Security-Policy` (CSP), `Strict-Transport-Security` (HSTS), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, and `Cross-Origin-Opener-Policy`.
- **`SecurityAuditLogger` (OWASP A09:2021)**: Real-time structured security telemetry visible directly inside the `/securityAudit` dashboard.

### 2. Strix Offensive-Defensive Surface Auditor (`/securityAudit`)
- **AppSec Posture Score (0–100, Grade `A+` to `F`)**: Evaluates target domains against OWASP Top 10 controls.
- **TLS & Cryptographic Inspection**: Verifies TLS version (`TLSv1.3` / `TLSv1.2`), active cipher suite, issuer CA, and certificate expiration.
- **Sensitive Artifact Exposure Probes**: Non-destructive checks for exposed `/.env`, `/.git/HEAD`, `/actuator/env`, and `/swagger.json`.
- **DNS Email Anti-Spoofing**: Verifies `SPF` (`v=spf1`) and `DMARC` (`_dmarc`) TXT records to detect domain spoofing and phishing risks.
- **Shift-Left Autofix Snippets**: Every finding includes a reproducible `curl`/`nslookup` PoC and ready-to-apply remediation code.

---

## 🚀 Quick Start

### Option 1: Docker Compose (Recommended)

```bash
git clone https://github.com/eriktonon/SPO-Sneak-Peek-OSINT.git
cd SPO-Sneak-Peek-OSINT
docker compose up --build -d
```

Open **`http://localhost:1337`** in your browser. On your first visit, SPO will guide you through creating your local operator account.

### Option 2: Local Python Environment (Windows / Linux / macOS)

```bash
git clone https://github.com/eriktonon/SPO-Sneak-Peek-OSINT.git
cd SPO-Sneak-Peek-OSINT
python -m venv .venv

# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# Linux / macOS:
# source .venv/bin/activate

pip install -r requirements.txt
python main.py
```

---

## 🧪 Running the Automated Verification Suite

```bash
python -m pytest -v
```

---

## 👨‍💻 Author & Maintainer

**Erik Tonon** ([@eriktonon](https://github.com/eriktonon))  
*Head of Platform Engineering & GenAI @ IBM Consulting | Ex-Associate Director @ BTG Pactual | Founder @ EdgeSearch Labs*

- 🌐 **Website & Portfolio**: [https://eriktonon.com](https://eriktonon.com)
- 🛡️ **BTM Readiness & AppSec Score**: [https://score.eriktonon.com](https://score.eriktonon.com)
- 💼 **LinkedIn**: [https://www.linkedin.com/in/eriktonon/](https://www.linkedin.com/in/eriktonon/)
- 💻 **GitHub**: [https://github.com/eriktonon](https://github.com/eriktonon)
- 💖 **GitHub Sponsors**: [https://github.com/sponsors/eriktonon](https://github.com/sponsors/eriktonon)

---

## 🪙 Crypto Donations & Support

**SPO — Sneak Peek OSINT** is 100% free and open-source software. If this project supports your security research, OSINT investigations, or Red/Blue Team operations, you can contribute directly via cryptocurrency:

| Network / Asset | Official Wallet Address (`@eriktonon`) |
| :--- | :--- |
| **Bitcoin (BTC — Native SegWit)** | `bc1q0hr95ay33rtazfepg64yddf52q3yqh7ud83cza` |
| **Ethereum (ETH / ERC-20 / Base / Polygon)** | `0xE69FCE4Fa35CF3bd98F496337b1eA223270b2c92` |
| **Solana (SOL / SPL)** | `3E8L1Hdqe7Xk6GCrzHbtY5sReAfLFc9CdwgZxP7qaoHq` |

---

## ⚖️ Legal Disclaimer & License

This software is provided strictly for **authorized security auditing, educational research, corporate due diligence, and lawful Open-Source Intelligence (OSINT)** gathering using publicly accessible data sources. Users are solely responsible for complying with applicable local laws (including LGPD/GDPR) and authorization boundaries.

Licensed under the **GNU General Public License v2.0 (GPLv2)** — see [LICENSE](LICENSE) for details.
