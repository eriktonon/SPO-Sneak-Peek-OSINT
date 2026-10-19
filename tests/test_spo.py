# -*- coding:UTF-8 -*-
"""
Automated Verification Suite for SPO - Sneak Peek OSINT v2.0.
Tests password hashing, SQL injection defense, SQLite DAO persistence,
authentication guards, case management, and OSINT controllers.
"""
import os
import tempfile
import pytest

from controller.PasswdHash import PasswdHash
from controller.validatorSQLI import ValidateSQLI
from controller.spoDAO import SpoDAO
from controller.CNPJ import CNPJ
from controller.Whois import Whois


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


def test_flask_routes_and_auth_guard(temp_db, monkeypatch):
    monkeypatch.setenv("SPO_DB_PATH", temp_db)
    import main
    main.dao = SpoDAO(db_path=temp_db)
    main.spo.config["TESTING"] = True

    with main.spo.test_client() as client:
        # Health check is public
        res = client.get("/health")
        assert res.status_code == 200
        assert res.get_json()["status"] == "ok"

        # First access redirects / to /wellcome
        res = client.get("/")
        assert res.status_code == 302
        assert "/wellcome" in res.headers["Location"]

        # Unauthenticated access to /dashboard redirects to / instead of 500 KeyError
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

        # Access protected routes
        for route in ("/dashboard", "/companyInvestigation", "/searchServers", "/personalInvestigation", "/projects", "/insertKeys", "/aboutOSINT", "/manual", "/about"):
            r = client.get(route)
            assert r.status_code == 200, f"Route {route} failed with {r.status_code}"
