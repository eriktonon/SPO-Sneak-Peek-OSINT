# Security Policy & Shift-Left Architecture — SPO v2.0

## Maintainer & Security Contact

- **Lead Architect & Maintainer**: **Erik Tonon** ([@eriktonon](https://github.com/eriktonon))
- **Website**: [https://eriktonon.com](https://eriktonon.com)
- **BTM Readiness & Security Score**: [https://score.eriktonon.com](https://score.eriktonon.com)
- **LinkedIn**: [https://www.linkedin.com/in/eriktonon/](https://www.linkedin.com/in/eriktonon/)

---

## Built-In Preventive Security Controls (`/PE-AGENTS-IBM Segurança` & `/pentest-strix`)

SPO v2.0 incorporates **Shift-Left Application Security** and **Build to Manage (BTM)** principles out of the box via [`controller/StrixSecurity.py`](controller/StrixSecurity.py):

1. **SSRF & Network Boundary Guard (`SSRFGuard`) — OWASP A10:2021**
   - Blocks outbound reconnaissance requests targeting loopback (`127.0.0.1`, `::1`), RFC1918 private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local Cloud Metadata (`169.254.169.254`), and DNS Rebinding attacks.
   - Enforces the mandatory **PE-AGENTS-IBM Firewall Guardrail** protecting critical gateway infrastructure (`192.168.3.1`).
2. **Adaptive Password Hashing & Constant-Time Verification — OWASP A02:2021**
   - Uses salted `PBKDF2-HMAC-SHA256` via Werkzeug and constant-time digest comparisons (`hmac.compare_digest`) to eliminate timing side-channels.
3. **100% Parameterized SQL & Input Sanitization — OWASP A03:2021**
   - Every SQLite WAL query in `controller/spoDAO.py` uses strict `?` bind parameters, paired with `controller/validatorSQLI.py` heuristics.
4. **Sliding-Window Rate Limiter & Brute-Force Lockout (`LoginRateLimiter`) — OWASP A04 / A07:2021**
   - Automatically locks out repeated failed authentication attempts per client IP and enforces constant-time CSRF synchronizer tokens (`CSRFShield`).
5. **Defensive HTTP Headers (`SecurityHeadersMiddleware`) — OWASP A05:2021**
   - Injects `Content-Security-Policy`, `Strict-Transport-Security` (HSTS), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, and `HttpOnly`/`SameSite=Lax` session cookies.
6. **SIEM-Ready Security Audit Telemetry (`SecurityAuditLogger`) — OWASP A09:2021**
   - Records structured UTC security events for authentication successes/lockouts and SSRF blocks.
