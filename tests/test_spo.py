# -*- coding:UTF-8 -*-
"""
Automated Verification Suite for SPO - Sneak Peek OSINT v2.0.
Tests password hashing, SQL injection defense, SQLite DAO persistence,
Strix SSRFGuard (including 192.168.3.1 guardrail), LoginRateLimiter,
OWASP defensive headers, authentication guards, case management, and OSINT controllers.
"""
import os
import tempfile
import pytest

from controller.PasswdHash import PasswdHash
from controller.validatorSQLI import ValidateSQLI
from controller.spoDAO import SpoDAO
from controller.CNPJ import CNPJ
from controller.Whois import Whois
from controller.StrixSecurity import (
    CSRFShield,
    LoginRateLimiter,
    SSRFGuard,
    StrixSecurityAuditor,
)


@pytest.fixture()
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass


def test_password_hash_and_legacy_fallback():
    ph = PasswdHash()
    hashed = ph.hash("S3cur3P@ss!")
    assert hashed.startswith("pbkdf2:sha256:")
    assert ph.verify(hashed, "S3cur3P@ss!") is True
    assert ph.verify(hashed, "wrong") is False

    # Legacy v1 SHA256 + "potato" fallback
    import hashlib
    legacy = hashlib.sha256(("oldpasspotato").encode("utf-8")).hexdigest()
    assert ph.verify(legacy, "oldpass") is True


def test_sqli_validator_catches_index_zero_and_payloads():
    v = ValidateSQLI()
    assert v.validatorSQLI("' OR 1=1 --") is True
    assert v.validatorSQLI("admin' --") is True
    assert v.validatorSQLI("SELECT * FROM user_spo") is True
    assert v.validatorSQLI("eriktonon") is False


def test_strix_ssrf_guard_and_firewall_guardrail():
    # Critical OPNsense firewall 192.168.3.1 must always be blocked
    ok, msg = SSRFGuard.validate_target("192.168.3.1")
    assert ok is False
    assert "192.168.3.1" in msg

    # Loopback, Cloud Metadata & RFC1918 private IPs must be blocked
    for forbidden_target in (
        "127.0.0.1",
        "localhost",
        "http://169.254.169.254/latest/meta-data/",
        "10.0.0.15",
        "172.16.5.4",
        "file:///etc/passwd",
        "internal.service.local",
    ):
        allowed, _ = SSRFGuard.validate_target(forbidden_target)
        assert allowed is False, f"Expected SSRFGuard to block {forbidden_target}"

    # Valid external public domain / IP must be allowed
    allowed_pub, host_pub = SSRFGuard.validate_target("https://eriktonon.com/about", resolve_dns=False)
    assert allowed_pub is True
    assert host_pub == "eriktonon.com"


def test_strix_login_rate_limiter_and_csrf_shield():
    limiter = LoginRateLimiter(max_attempts=3, window_seconds=60, lockout_seconds=120)
    ip = "203.0.113.50"
    assert limiter.is_locked(ip)[0] is False

    locked1, rem1 = limiter.record_failure(ip, "erik")
    assert locked1 is False and rem1 == 2
    locked2, rem2 = limiter.record_failure(ip, "erik")
    assert locked2 is False and rem2 == 1
    locked3, lockout_secs = limiter.record_failure(ip, "erik")
    assert locked3 is True and lockout_secs == 120
    assert limiter.is_locked(ip)[0] is True

    limiter.reset(ip)
    assert limiter.is_locked(ip)[0] is False

    # CSRF constant-time token verification
    fake_session = {}
    tok = CSRFShield.get_or_create_token(fake_session)
    assert len(tok) > 20
    assert CSRFShield.verify_token(fake_session, tok) is True
    assert CSRFShield.verify_token(fake_session, "invalid_csrf") is False


def test_dao_user_keys_projects_and_scans(temp_db):
    dao = SpoDAO(db_path=temp_db)
    assert dao.testFirstAccess() is True

    # SQLi attempt rejected
    assert dao.insertUser("admin' OR '1'='1", "pass") is None

    uid = dao.insertUser("erik", "StrongPass123")
    assert uid is not None
    assert dao.testFirstAccess() is False
    assert dao.testLogin("erik", "StrongPass123") is True
    assert dao.testLogin("erik", "WrongPass") is False

    user_row = dao.getIDUser("erik")
    assert user_row is not None
    assert user_row["id_user"] == uid

    # API Keys
    assert dao.insertShodanKey(user_row, "SHODAN1234567890") is True
    assert dao.getShodanKey(user_row)["key_value"] == "SHODAN1234567890"
    assert dao.updateShodanKey(user_row, "SHODAN_UPDATED_9999") is True
    assert dao.getShodanKey(user_row)["key_value"] == "SHODAN_UPDATED_9999"

    # Projects & Scan History
    pid = dao.createProject(user_row, "Operation Alpha", "Corporate Recon")
    assert pid is not None
    scan_id = dao.saveScanResult(
        user_row,
        scan_type="company",
        target="example.com.br",
        payload={"domain": "example.com.br"},
        summary="Test summary",
        project_id=pid,
    )
    assert scan_id > 0

    proj = dao.getProject(user_row, pid)
    assert proj is not None
    assert proj["name_project"] == "Operation Alpha"
    assert len(proj["scans"]) == 1

    stats = dao.getDashboardStats(user_row)
    assert stats["projects"] == 1
    assert stats["total_scans"] == 1
    assert stats["company_scans"] == 1


def test_cnpj_and_whois_utilities():
    c = CNPJ()
    assert c.treat("00.000.000/0001-91") == "00000000000191"
    assert c.format_cnpj("00000000000191") == "00.000.000/0001-91"
    assert Whois.normalize_domain("https://www.Petrobras.com.br/path?a=1") == "petrobras.com.br"
    assert len(StrixSecurityAuditor.get_internal_prevention_matrix()) >= 6


def test_flask_routes_security_headers_and_author_wallets(temp_db, monkeypatch):
    monkeypatch.setenv("SPO_DB_PATH", temp_db)
    import main
    main.dao = SpoDAO(db_path=temp_db)
    main.rate_limiter.reset("127.0.0.1")
    main.spo.config["TESTING"] = True

    with main.spo.test_client() as client:
        # Health check is public & includes OWASP defensive headers
        res = client.get("/health")
        assert res.status_code == 200
        assert res.get_json()["status"] == "ok"
        assert res.headers.get("X-Frame-Options") == "DENY"
        assert res.headers.get("X-Content-Type-Options") == "nosniff"
        assert "default-src 'self'" in res.headers.get("Content-Security-Policy", "")
        assert "max-age=31536000" in res.headers.get("Strict-Transport-Security", "")

        # First access redirects / to /wellcome
        res = client.get("/")
        assert res.status_code == 302
        assert "/wellcome" in res.headers["Location"]

        # Unauthenticated access to /dashboard redirects to /
        res = client.get("/dashboard")
        assert res.status_code == 302

        # Register first operator
        res = client.post("/firstLogin", data={"user": "erik", "password": "MySecretPassword"})
        assert res.status_code == 200
        assert b"Operator Account Created" in res.data

        # Login with registered operator
        res = client.post("/", data={"user": "erik", "password": "MySecretPassword"})
        assert res.status_code == 302
        assert "/dashboard" in res.headers["Location"]

        # Access protected routes including /securityAudit and /graniteAI
        for route in (
            "/dashboard",
            "/companyInvestigation",
            "/searchServers",
            "/personalInvestigation",
            "/securityAudit",
            "/graniteAI",
            "/projects",
            "/insertKeys",
            "/aboutOSINT",
            "/manual",
            "/about",
        ):
            r = client.get(route)
            assert r.status_code == 200, f"Route {route} failed with {r.status_code}"

        # Verify Erik Tonon profile & crypto wallets on /about
        about_html = client.get("/about").data.decode("utf-8")
        assert "Erik Tonon" in about_html
        assert "bc1q0hr95ay33rtazfepg64yddf52q3yqh7ud83cza" in about_html
        assert "0xE69FCE4Fa35CF3bd98F496337b1eA223270b2c92" in about_html
        assert "3E8L1Hdqe7Xk6GCrzHbtY5sReAfLFc9CdwgZxP7qaoHq" in about_html

        # Verify Granite 4.2 Uncensored page & analysis execution
        granite_html = client.get("/graniteAI").data.decode("utf-8")
        assert "eriktonon/granite4.2-uncensored" in granite_html
        ai_post = client.post(
            "/graniteAI",
            data={
                "mode": "osint_correlation",
                "prompt": "Analyze subdomain exposure and open ports for example.com",
            },
        )
        assert ai_post.status_code == 200
        assert b"eriktonon/granite4.2-uncensored" in ai_post.data

        # Verify SSRFGuard blocks 192.168.3.1 on /securityAudit
        ssrf_res = client.post("/securityAudit", data={"target": "192.168.3.1"})
        assert ssrf_res.status_code == 200
        assert b"192.168.3.1" in ssrf_res.data

        # Verify Datadog DRUIDS CSS & SEO endpoints (/robots.txt, /sitemap.xml)
        css_res = client.get("/static/css/datadog-druids.css")
        assert css_res.status_code == 200
        assert b"--dd-purple" in css_res.data

        robots_res = client.get("/robots.txt")
        assert robots_res.status_code == 200
        assert b"Sitemap:" in robots_res.data

        sitemap_res = client.get("/sitemap.xml")
        assert sitemap_res.status_code == 200
        assert b"<urlset" in sitemap_res.data

