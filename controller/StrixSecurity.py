import hmac
import ipaddress
import json
import logging
import secrets
import socket
import ssl
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

logger = logging.getLogger("spo.strix_security")


class SecurityAuditLogger:
    """Structured security event logger (OWASP A09 - Security Logging & Monitoring)."""

    _events: deque = deque(maxlen=250)

    @classmethod
    def log_event(
        cls,
        event_type: str,
        severity: str,
        message: str,
        client_ip: str = "127.0.0.1",
        username: str = "anonymous",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        entry = {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "event_type": event_type,
            "severity": severity.upper(),
            "client_ip": client_ip,
            "username": username,
            "message": message,
            "metadata": metadata or {},
        }
        cls._events.appendleft(entry)
        logger.warning("STRIX_SECURITY_EVENT: %s", json.dumps(entry, ensure_ascii=False))
        return entry

    @classmethod
    def recent_events(cls, limit: int = 25) -> List[Dict[str, Any]]:
        return list(cls._events)[:limit]


class SSRFGuard:
    """
    Preventive SSRF & Network Boundary Guard (OWASP A10:2021 + PE-AGENTS-IBM Firewall Guardrail).
    Blocks outbound requests to loopback, RFC1918 private networks, link-local metadata
    (169.254.169.254), multicast, and explicitly protects the critical gateway 192.168.3.1.
    """

    CRITICAL_PROTECTED_HOSTS = {"192.168.3.1", "localhost", "127.0.0.1", "::1", "0.0.0.0", "169.254.169.254"}
    ALLOWED_SCHEMES = {"http", "https"}

    @classmethod
    def extract_hostname(cls, target: str) -> str:
        cleaned = (target or "").strip()
        if not cleaned:
            return ""
        if "://" in cleaned:
            parsed = urlparse(cleaned)
            if parsed.scheme.lower() not in cls.ALLOWED_SCHEMES:
                raise ValueError(f"Protocolo '{parsed.scheme}' bloqueado pelo SSRFGuard (apenas HTTP/HTTPS permitidos).")
            return (parsed.hostname or "").strip().lower()
        return cleaned.split("/")[0].split(":")[0].strip().lower()

    @classmethod
    def is_ip_forbidden(cls, ip_str: str) -> Tuple[bool, str]:
        if ip_str == "192.168.3.1":
            return True, "Bloqueio Crítico PE-AGENTS-IBM: O gateway/firewall 192.168.3.1 é estritamente protegido."
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return True, f"Endereço IP inválido: {ip_str}"

        if ip_obj.is_loopback:
            return True, f"SSRFGuard bloqueou endereço de loopback ({ip_str})."
        if ip_obj.is_link_local or ip_str == "169.254.169.254":
            return True, f"SSRFGuard bloqueou endpoint de Cloud Metadata / Link-Local ({ip_str})."
        if ip_obj.is_private:
            return True, f"SSRFGuard bloqueou rede privada interna RFC1918 ({ip_str})."
        if ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
            return True, f"SSRFGuard bloqueou faixa de IP reservada/multicast ({ip_str})."
        return False, "OK"

    @classmethod
    def validate_target(cls, target: str, resolve_dns: bool = False) -> Tuple[bool, str]:
        try:
            hostname = cls.extract_hostname(target)
        except ValueError as exc:
            return False, str(exc)

        if not hostname:
            return False, "Alvo vazio ou inválido."

        if hostname in cls.CRITICAL_PROTECTED_HOSTS or hostname.endswith(".local") or hostname.endswith(".internal"):
            reason = (
                "Bloqueio Crítico PE-AGENTS-IBM: O gateway/firewall 192.168.3.1 é estritamente protegido."
                if hostname == "192.168.3.1"
                else f"SSRFGuard bloqueou host interno/protegido: {hostname}"
            )
            SecurityAuditLogger.log_event(
                event_type="SSRF_BLOCKED",
                severity="CRITICAL" if hostname == "192.168.3.1" else "HIGH",
                message=reason,
                metadata={"target": target, "hostname": hostname},
            )
            return False, reason

        # Check if hostname is a literal IP address
        try:
            ipaddress.ip_address(hostname)
            forbidden, reason = cls.is_ip_forbidden(hostname)
            if forbidden:
                SecurityAuditLogger.log_event(
                    event_type="SSRF_BLOCKED",
                    severity="CRITICAL" if hostname == "192.168.3.1" else "HIGH",
                    message=reason,
                    metadata={"target": target, "ip": hostname},
                )
                return False, reason
            return True, hostname
        except ValueError:
            pass

        if resolve_dns:
            try:
                infos = socket.getaddrinfo(hostname, None)
                for info in infos:
                    resolved_ip = info[4][0]
                    forbidden, reason = cls.is_ip_forbidden(resolved_ip)
                    if forbidden:
                        SecurityAuditLogger.log_event(
                            event_type="SSRF_DNS_REBIND_BLOCKED",
                            severity="HIGH",
                            message=f"DNS Rebinding bloqueado para {hostname} -> {resolved_ip}: {reason}",
                            metadata={"target": target, "resolved_ip": resolved_ip},
                        )
                        return False, f"DNS do domínio '{hostname}' resolve para IP restrito ({resolved_ip})."
            except socket.gaierror:
                pass

        return True, hostname


class LoginRateLimiter:
    """
    Sliding-Window Rate Limiter & Brute-Force Shield (OWASP A04 Insecure Design / A07 Auth Failures).
    Protects authentication endpoints against credential stuffing and dictionary attacks.
    """

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300, lockout_seconds: int = 300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._attempts: Dict[str, List[float]] = defaultdict(list)
        self._lockouts: Dict[str, float] = {}

    def is_locked(self, key: str) -> Tuple[bool, int]:
        now = time.time()
        unlock_at = self._lockouts.get(key, 0.0)
        if unlock_at > now:
            return True, int(unlock_at - now)
        if key in self._lockouts:
            del self._lockouts[key]
        return False, 0

    def record_failure(self, key: str, username: str = "unknown") -> Tuple[bool, int]:
        now = time.time()
        cutoff = now - self.window_seconds
        history = [ts for ts in self._attempts[key] if ts > cutoff]
        history.append(now)
        self._attempts[key] = history

        if len(history) >= self.max_attempts:
            self._lockouts[key] = now + self.lockout_seconds
            SecurityAuditLogger.log_event(
                event_type="BRUTE_FORCE_LOCKOUT",
                severity="HIGH",
                message=f"IP/Chave '{key}' bloqueado temporariamente após {len(history)} falhas de login.",
                client_ip=key,
                username=username,
                metadata={"attempts": len(history), "lockout_seconds": self.lockout_seconds},
            )
            return True, self.lockout_seconds
        return False, max(0, self.max_attempts - len(history))

    def reset(self, key: str) -> None:
        self._attempts.pop(key, None)
        self._lockouts.pop(key, None)


class CSRFShield:
    """Constant-time CSRF synchronizer token generator & validator (OWASP A01 / A05)."""

    SESSION_KEY = "_spo_csrf_nonce"

    @classmethod
    def get_or_create_token(cls, session_obj: Any) -> str:
        existing = session_obj.get(cls.SESSION_KEY)
        if not existing or not isinstance(existing, str):
            existing = secrets.token_urlsafe(32)
            session_obj[cls.SESSION_KEY] = existing
        return existing

    @classmethod
    def verify_token(cls, session_obj: Any, provided_token: Optional[str]) -> bool:
        expected = session_obj.get(cls.SESSION_KEY)
        if not expected or not provided_token:
            return False
        return hmac.compare_digest(str(expected), str(provided_token))


class SecurityHeadersMiddleware:
    """
    Applies OWASP Top 10 / PE-AGENTS-IBM Shift-Left defensive HTTP headers to every response.
    """

    DEFAULT_HEADERS = {
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "0",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com data:; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        ),
    }

    @classmethod
    def apply_headers(cls, response: Any) -> Any:
        for header_name, header_val in cls.DEFAULT_HEADERS.items():
            response.headers.setdefault(header_name, header_val)
        return response


class StrixSecurityAuditor:
    """
    Strix Offensive-Defensive DAST & Prevention Auditor (/pentest-strix + /PE-AGENTS-IBM Segurança).
    Performs non-destructive Black-Box DAST surface analysis, OWASP Top 10 header inspection,
    TLS/SSL verification, sensitive path exposure probing, and DNS Email Anti-Spoofing (SPF/DMARC),
    returning CVSS v3.1 scores, PoC commands, and Shift-Left Autofix Prevention code.
    """

    SENSITIVE_PROBE_PATHS = [
        ("/.env", "Exposição de Arquivo de Variáveis de Ambiente (.env)", "CRITICAL", 9.8, "CWE-200", "A05:2021 - Security Misconfiguration"),
        ("/.git/HEAD", "Exposição de Repositório Git (.git/HEAD)", "HIGH", 7.5, "CWE-538", "A05:2021 - Security Misconfiguration"),
        ("/actuator/env", "Spring Boot Actuator Exposto sem Autenticação", "CRITICAL", 9.1, "CWE-200", "A05:2021 - Security Misconfiguration"),
        ("/swagger.json", "Especificação OpenAPI/Swagger Exposta Publicamente", "LOW", 3.7, "CWE-200", "A05:2021 - Security Misconfiguration"),
    ]

    def __init__(self, timeout: int = 6):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "SPO-Strix-Auditor/2.0 (+https://eriktonon.com; Defensive-AppSec-Scanner)"
        })

    def _normalize_target_url(self, raw_target: str) -> Tuple[str, str]:
        cleaned = (raw_target or "").strip()
        if not cleaned.startswith(("http://", "https://")):
            cleaned = f"https://{cleaned}"
        parsed = urlparse(cleaned)
        hostname = (parsed.hostname or "").strip().lower()
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        return base_url, hostname

    def _inspect_tls(self, hostname: str) -> Dict[str, Any]:
        tls_info: Dict[str, Any] = {
            "supported": False,
            "protocol": None,
            "cipher": None,
            "issuer": None,
            "expires_at": None,
        }
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    tls_info["supported"] = True
                    tls_info["protocol"] = ssock.version()
                    cipher = ssock.cipher()
                    tls_info["cipher"] = cipher[0] if cipher else None
                    cert = ssock.getpeercert()
                    if cert:
                        tls_info["expires_at"] = cert.get("notAfter")
                        issuer_tuples = cert.get("issuer", ())
                        issuer_parts = [
                            f"{k}={v}" for rdn in issuer_tuples for k, v in rdn if k in ("organizationName", "commonName")
                        ]
                        tls_info["issuer"] = ", ".join(issuer_parts)
        except Exception as exc:
            tls_info["error"] = str(exc)
        return tls_info

    def _inspect_dns_email_security(self, hostname: str) -> Dict[str, Any]:
        """Checks SPF and DMARC records via Google DNS-over-HTTPS (DoH)."""
        result = {"spf_present": False, "spf_record": None, "dmarc_present": False, "dmarc_record": None}
        try:
            resp_txt = self.session.get(
                "https://dns.google/resolve",
                params={"name": hostname, "type": "TXT"},
                timeout=self.timeout,
            )
            if resp_txt.ok:
                for ans in resp_txt.json().get("Answer", []):
                    txt_data = str(ans.get("data", "")).strip('"')
                    if "v=spf1" in txt_data.lower():
                        result["spf_present"] = True
                        result["spf_record"] = txt_data

            resp_dmarc = self.session.get(
                "https://dns.google/resolve",
                params={"name": f"_dmarc.{hostname}", "type": "TXT"},
                timeout=self.timeout,
            )
            if resp_dmarc.ok:
                for ans in resp_dmarc.json().get("Answer", []):
                    txt_data = str(ans.get("data", "")).strip('"')
                    if "v=dmarc1" in txt_data.lower():
                        result["dmarc_present"] = True
                        result["dmarc_record"] = txt_data
        except Exception as exc:
            logger.debug("DNS SPF/DMARC lookup error for %s: %s", hostname, exc)
        return result

    def audit_target(self, raw_target: str, probe_sensitive_paths: bool = True) -> Dict[str, Any]:
        is_valid, reason_or_host = SSRFGuard.validate_target(raw_target, resolve_dns=True)
        if not is_valid:
            return {
                "target": raw_target,
                "blocked_by_ssrf_guard": True,
                "error": reason_or_host,
                "score": 0,
                "grade": "BLOCKED",
                "findings": [],
                "passed_controls": [],
            }

        base_url, hostname = self._normalize_target_url(raw_target)
        findings: List[Dict[str, Any]] = []
        passed_controls: List[Dict[str, str]] = []
        headers_snapshot: Dict[str, str] = {}
        status_code: Optional[int] = None

        # 1. Fetch main HTTP response
        try:
            resp = self.session.get(base_url, timeout=self.timeout, allow_redirects=True)
            status_code = resp.status_code
            headers_snapshot = {k: v for k, v in resp.headers.items()}
            final_url = resp.url
        except requests.RequestException:
            # Fallback to HTTP if HTTPS fails
            fallback_url = f"http://{hostname}"
            try:
                resp = self.session.get(fallback_url, timeout=self.timeout, allow_redirects=True)
                status_code = resp.status_code
                headers_snapshot = {k: v for k, v in resp.headers.items()}
                final_url = resp.url
            except requests.RequestException as exc:
                return {
                    "target": raw_target,
                    "hostname": hostname,
                    "blocked_by_ssrf_guard": False,
                    "error": f"Não foi possível conectar ao alvo ({hostname}): {exc}",
                    "score": 0,
                    "grade": "N/A",
                    "findings": [],
                    "passed_controls": [],
                }

        lower_headers = {k.lower(): v for k, v in headers_snapshot.items()}

        # 2. Check HTTPS / HSTS (OWASP A02:2021 - Cryptographic Failures)
        if not final_url.startswith("https://"):
            findings.append({
                "id": "STRIX-A02-001",
                "title": "Ausência de Criptografia em Trânsito (HTTP sem Redirect HTTPS)",
                "severity": "HIGH",
                "cvss": 7.4,
                "cwe": "CWE-319",
                "owasp": "A02:2021 - Cryptographic Failures",
                "evidence": f"Endpoint respondeu em texto claro via {final_url}",
                "poc": f"curl -I -L {base_url}",
                "remediation": "Forçar redirecionamento 301 para HTTPS no Ingress/Reverse Proxy e ativar HSTS.",
                "autofix_snippet": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            })
        else:
            passed_controls.append({"control": "HTTPS Enforced", "detail": f"Tráfego cifrado ativo em {final_url}"})

        if "strict-transport-security" not in lower_headers:
            findings.append({
                "id": "STRIX-A05-001",
                "title": "Header HSTS (Strict-Transport-Security) Ausente",
                "severity": "MEDIUM",
                "cvss": 5.3,
                "cwe": "CWE-523",
                "owasp": "A05:2021 - Security Misconfiguration",
                "evidence": "Header 'Strict-Transport-Security' não encontrado na resposta HTTP.",
                "poc": f"curl -s -D - -o /dev/null {final_url} | grep -i Strict-Transport-Security",
                "remediation": "Adicionar header Strict-Transport-Security para prevenir ataques de SSL Stripping.",
                "autofix_snippet": "response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'",
            })
        else:
            passed_controls.append({
                "control": "HSTS (Strict-Transport-Security)",
                "detail": lower_headers["strict-transport-security"],
            })

        # 3. Check Content-Security-Policy (OWASP A03 / A05)
        if "content-security-policy" not in lower_headers:
            findings.append({
                "id": "STRIX-A05-002",
                "title": "Content-Security-Policy (CSP) Ausente",
                "severity": "MEDIUM",
                "cvss": 6.1,
                "cwe": "CWE-693",
                "owasp": "A05:2021 - Security Misconfiguration",
                "evidence": "Nenhum header 'Content-Security-Policy' retornado pelo servidor.",
                "poc": f"curl -s -D - -o /dev/null {final_url} | grep -i Content-Security-Policy",
                "remediation": "Definir política CSP restritiva com default-src 'self' e frame-ancestors 'none'.",
                "autofix_snippet": "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; base-uri 'self'",
            })
        else:
            passed_controls.append({
                "control": "Content-Security-Policy (CSP)",
                "detail": lower_headers["content-security-policy"][:120],
            })

        # 4. Check Clickjacking protection (X-Frame-Options / frame-ancestors)
        csp_val = lower_headers.get("content-security-policy", "").lower()
        if "x-frame-options" not in lower_headers and "frame-ancestors" not in csp_val:
            findings.append({
                "id": "STRIX-A05-003",
                "title": "Proteção Anti-Clickjacking Ausente (X-Frame-Options / frame-ancestors)",
                "severity": "MEDIUM",
                "cvss": 4.7,
                "cwe": "CWE-1021",
                "owasp": "A05:2021 - Security Misconfiguration",
                "evidence": "Ausência de X-Frame-Options e de diretiva CSP frame-ancestors.",
                "poc": f"curl -I {final_url}",
                "remediation": "Configurar X-Frame-Options: DENY ou SAMEORIGIN e CSP frame-ancestors 'none'.",
                "autofix_snippet": "response.headers['X-Frame-Options'] = 'DENY'",
            })
        else:
            passed_controls.append({
                "control": "Anti-Clickjacking (X-Frame-Options)",
                "detail": lower_headers.get("x-frame-options", "CSP frame-ancestors"),
            })

        # 5. Check MIME Sniffing protection (X-Content-Type-Options)
        if lower_headers.get("x-content-type-options", "").lower() != "nosniff":
            findings.append({
                "id": "STRIX-A05-004",
                "title": "X-Content-Type-Options: nosniff Ausente",
                "severity": "LOW",
                "cvss": 3.7,
                "cwe": "CWE-16",
                "owasp": "A05:2021 - Security Misconfiguration",
                "evidence": f"Valor atual: '{lower_headers.get('x-content-type-options', 'ausente')}'",
                "poc": f"curl -I {final_url}",
                "remediation": "Definir X-Content-Type-Options: nosniff em todas as respostas HTTP.",
                "autofix_snippet": "response.headers['X-Content-Type-Options'] = 'nosniff'",
            })
        else:
            passed_controls.append({"control": "X-Content-Type-Options", "detail": "nosniff"})

        # 6. Check Permissive CORS (Wildcard Origin)
        acao = lower_headers.get("access-control-allow-origin", "")
        if acao.strip() == "*":
            findings.append({
                "id": "STRIX-A01-001",
                "title": "CORS Excessivamente Permissivo (Wildcard Origin)",
                "severity": "MEDIUM",
                "cvss": 5.3,
                "cwe": "CWE-942",
                "owasp": "A01:2021 - Broken Access Control",
                "evidence": "Header CORS allow-origin configurado como curinga irrestrito.",
                "poc": f"curl -H 'Origin: https://evil.example.com' -I {final_url}",
                "remediation": "Restringir origens permitidas no CORS a uma allowlist explícita de domínios confiáveis.",
                "autofix_snippet": "Access-Control-Allow-Origin: https://app.seudominio.com",
            })

        # 7. Check Server / X-Powered-By Version Banner Disclosure
        server_banner = lower_headers.get("server", "")
        powered_by = lower_headers.get("x-powered-by", "")
        if powered_by or any(ch.isdigit() for ch in server_banner):
            findings.append({
                "id": "STRIX-A05-005",
                "title": "Vazamento de Versão/Tecnologia em Headers (Server / X-Powered-By)",
                "severity": "LOW",
                "cvss": 3.1,
                "cwe": "CWE-200",
                "owasp": "A05:2021 - Security Misconfiguration",
                "evidence": f"Server='{server_banner}' | X-Powered-By='{powered_by}'",
                "poc": f"curl -I {final_url}",
                "remediation": "Omitir versões exatas de servidor web (server_tokens off no Nginx) e remover X-Powered-By.",
                "autofix_snippet": "# nginx.conf\nserver_tokens off;\nproxy_hide_header X-Powered-By;",
            })
        else:
            passed_controls.append({"control": "Banner Hardening", "detail": "Sem versão explícita exposta em Server/X-Powered-By"})

        # 8. Check Sensitive Path Exposure (Non-destructive GET probes)
        if probe_sensitive_paths:
            for path, title, sev, cvss_score, cwe_id, owasp_cat in self.SENSITIVE_PROBE_PATHS:
                probe_url = f"{base_url}{path}"
                try:
                    p_resp = self.session.get(probe_url, timeout=3, allow_redirects=False)
                    body_sample = (p_resp.text or "")[:160]
                    is_exposed = False
                    if path == "/.env" and p_resp.status_code == 200 and ("=" in body_sample and "<html" not in body_sample.lower()):
                        is_exposed = True
                    elif path == "/.git/HEAD" and p_resp.status_code == 200 and "ref: refs/" in body_sample:
                        is_exposed = True
                    elif path == "/actuator/env" and p_resp.status_code == 200 and "propertySources" in body_sample:
                        is_exposed = True
                    elif path == "/swagger.json" and p_resp.status_code == 200 and '"swagger"' in body_sample.lower():
                        is_exposed = True

                    if is_exposed:
                        findings.append({
                            "id": f"STRIX-EXP-{path.strip('/').replace('/', '-').upper()}",
                            "title": title,
                            "severity": sev,
                            "cvss": cvss_score,
                            "cwe": cwe_id,
                            "owasp": owasp_cat,
                            "evidence": f"HTTP 200 em {probe_url}",
                            "poc": f"curl -i {probe_url}",
                            "remediation": f"Bloquear acesso público a '{path}' no servidor web/WAF imediatamente.",
                            "autofix_snippet": f"location ~ /\\.(env|git) {{ deny all; return 404; }}",
                        })
                except requests.RequestException:
                    continue

        # 9. Inspect TLS & DNS Anti-Spoofing (SPF / DMARC)
        tls_details = self._inspect_tls(hostname)
        dns_email = self._inspect_dns_email_security(hostname)

        if not dns_email["spf_present"]:
            findings.append({
                "id": "STRIX-DNS-SPF",
                "title": "Registro DNS SPF Ausente (Risco de Email Spoofing / Phishing)",
                "severity": "LOW",
                "cvss": 4.3,
                "cwe": "CWE-290",
                "owasp": "A05:2021 - Security Misconfiguration",
                "evidence": f"Nenhum registro TXT 'v=spf1' encontrado para {hostname}.",
                "poc": f"nslookup -type=txt {hostname}",
                "remediation": "Publicar registro TXT SPF restringindo os servidores autorizados a enviar e-mails.",
                "autofix_snippet": f'{hostname}. IN TXT "v=spf1 -all"',
            })
        else:
            passed_controls.append({"control": "DNS SPF Anti-Spoofing", "detail": dns_email["spf_record"] or "v=spf1"})

        if not dns_email["dmarc_present"]:
            findings.append({
                "id": "STRIX-DNS-DMARC",
                "title": "Registro DNS DMARC Ausente (_dmarc)",
                "severity": "LOW",
                "cvss": 4.0,
                "cwe": "CWE-290",
                "owasp": "A05:2021 - Security Misconfiguration",
                "evidence": f"Nenhum registro TXT 'v=DMARC1' em _dmarc.{hostname}.",
                "poc": f"nslookup -type=txt _dmarc.{hostname}",
                "remediation": "Configurar política DMARC (p=quarantine ou p=reject) para proteção de marca e domínio.",
                "autofix_snippet": f'_dmarc.{hostname}. IN TXT "v=DMARC1; p=reject; adkim=s; aspf=s;"',
            })
        else:
            passed_controls.append({"control": "DNS DMARC Policy", "detail": dns_email["dmarc_record"] or "v=DMARC1"})

        # 10. Compute Posture Score (0 - 100) & Grade
        severity_penalties = {"CRITICAL": 35, "HIGH": 22, "MEDIUM": 12, "LOW": 5}
        penalty = sum(severity_penalties.get(f["severity"], 5) for f in findings)
        score = max(0, 100 - penalty)

        if score >= 92:
            grade = "A+"
        elif score >= 85:
            grade = "A"
        elif score >= 75:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 45:
            grade = "D"
        else:
            grade = "F"

        return {
            "target": raw_target,
            "hostname": hostname,
            "final_url": final_url,
            "http_status": status_code,
            "blocked_by_ssrf_guard": False,
            "score": score,
            "grade": grade,
            "tls": tls_details,
            "dns_email": dns_email,
            "headers": headers_snapshot,
            "findings": findings,
            "passed_controls": passed_controls,
            "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        }

    @staticmethod
    def get_internal_prevention_matrix() -> List[Dict[str, str]]:
        """Returns the active Shift-Left preventive controls embedded in SPO v2.0."""
        return [
            {
                "code": "OWASP A01 / A10",
                "control": "SSRFGuard & OPNsense 192.168.3.1 Hardening",
                "status": "ACTIVE",
                "description": "Bloqueia varreduras contra loopback, redes internas RFC1918, Cloud Metadata (169.254.169.254) e protege estritamente o gateway 192.168.3.1 contra DNS Rebinding.",
            },
            {
                "code": "OWASP A02",
                "control": "PBKDF2-HMAC-SHA256 & Constant-Time Digest",
                "status": "ACTIVE",
                "description": "Senhas com salt aleatório de 16 bytes + 310.000 iterações PBKDF2-SHA256 e comparação resistente a Timing Attacks via hmac.compare_digest.",
            },
            {
                "code": "OWASP A03",
                "control": "100% Parameterized SQL & ValidatorSQLI",
                "status": "ACTIVE",
                "description": "Zero interpolação de strings SQL em spoDAO.py + sanitização preventiva contra payloads Union/Stacked/Boolean SQLi e XSS.",
            },
            {
                "code": "OWASP A04 / A07",
                "control": "Sliding-Window Rate Limiter & Lockout",
                "status": "ACTIVE",
                "description": "Proteção anti-brute-force por IP/usuário com bloqueio temporário automático após 5 tentativas inválidas e tokens sincronizadores CSRF.",
            },
            {
                "code": "OWASP A05",
                "control": "Shift-Left Defensive HTTP Headers",
                "status": "ACTIVE",
                "description": "Injeção automática de Content-Security-Policy (CSP), HSTS, X-Frame-Options: DENY, X-Content-Type-Options: nosniff e Permissions-Policy.",
            },
            {
                "code": "OWASP A09",
                "control": "SecurityAuditLogger (SIEM-Ready Trail)",
                "status": "ACTIVE",
                "description": "Trilha de auditoria estruturada em memória e log para bloqueios de SSRF, falhas de autenticação, lockouts e violações de CSRF.",
            },
        ]
