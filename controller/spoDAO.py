# -*- coding:UTF-8 -*-
"""
Data Access Object (DAO) for SPO - Sneak Peek OSINT v2.0.
Uses 100% parameterized SQL queries and supports users, multi-service API keys,
investigation projects, and OSINT scan history persistence.
"""
import json
from typing import Any, Dict, List, Optional
from controller import DataFactory
from controller import PasswdHash
from controller import validatorSQLI


class SpoDAO:
    def __init__(self, db_path: Optional[str] = None):
        self.connection = DataFactory.DataFactory(db_path=db_path)
        self.passhash = PasswdHash.PasswdHash()
        self.sqli = validatorSQLI.ValidateSQLI()

    @staticmethod
    def _extract_user_id(user_id_or_dict: Any) -> int:
        if isinstance(user_id_or_dict, dict):
            return int(user_id_or_dict.get("id_user", 0))
        return int(user_id_or_dict)

    def testFirstAccess(self) -> bool:
        """Return True if no users are registered in the database yet."""
        row = self.connection.select("SELECT id_user FROM user_spo LIMIT 1;")
        return row is None

    def insertUser(self, user: str, passwd: str) -> Optional[int]:
        """Create a new user with PBKDF2-SHA256 password hash."""
        if not user or not passwd:
            return None
        clean_user = user.strip()
        if self.sqli.validatorSQLI(clean_user):
            return None
        hashed = self.passhash.hash(passwd)
        existing = self.connection.select(
            "SELECT id_user FROM user_spo WHERE login = ?;", (clean_user,)
        )
        if existing:
            return int(existing["id_user"])
        return self.connection.insert(
            "INSERT INTO user_spo (login, password) VALUES (?, ?);",
            (clean_user, hashed),
        )

    def testLogin(self, user: str, passwd: str) -> bool:
        """Authenticate user credentials against stored password hash."""
        if not user or not passwd:
            return False
        clean_user = user.strip()
        if self.sqli.validatorSQLI(clean_user):
            return False
        row = self.connection.select(
            "SELECT id_user, login, password FROM user_spo WHERE login = ?;",
            (clean_user,),
        )
        if not row:
            return False
        return self.passhash.verify(row["password"], passwd)

    def getIDUser(self, user: str) -> Optional[Dict[str, Any]]:
        """Return {'id_user': <int>} for the given username."""
        if not user:
            return None
        return self.connection.select(
            "SELECT id_user FROM user_spo WHERE login = ?;", (user.strip(),)
        )

    # --- API Keys Management (Shodan, VirusTotal, GitHub, etc.) ---

    def getApiKey(self, user_id: Any, service_name: str) -> Optional[Dict[str, Any]]:
        uid = self._extract_user_id(user_id)
        return self.connection.select(
            "SELECT id_key, key_value, name_key, updated_at FROM key_api WHERE id_user = ? AND name_key = ?;",
            (uid, service_name.lower().strip()),
        )

    def getAllApiKeys(self, user_id: Any) -> Dict[str, str]:
        uid = self._extract_user_id(user_id)
        rows = self.connection.select_all(
            "SELECT name_key, key_value FROM key_api WHERE id_user = ?;", (uid,)
        )
        return {r["name_key"]: r["key_value"] for r in rows if r.get("key_value")}

    def upsertApiKey(self, user_id: Any, service_name: str, key_value: str) -> bool:
        if not key_value or not service_name:
            return False
        clean_key = key_value.strip()
        clean_service = service_name.lower().strip()
        if self.sqli.validatorSQLI(clean_key):
            return False
        uid = self._extract_user_id(user_id)
        existing = self.getApiKey(uid, clean_service)
        if existing is None:
            self.connection.insert(
                "INSERT INTO key_api (key_value, name_key, id_user) VALUES (?, ?, ?);",
                (clean_key, clean_service, uid),
            )
        else:
            self.connection.update(
                "UPDATE key_api SET key_value = ?, updated_at = CURRENT_TIMESTAMP WHERE id_user = ? AND name_key = ?;",
                (clean_key, uid, clean_service),
            )
        return True

    # Backward-compatible Shodan key helpers
    def insertShodanKey(self, user_id: Any, key: str) -> bool:
        return self.upsertApiKey(user_id, "shodan", key)

    def getShodanKey(self, user_id: Any) -> Optional[Dict[str, Any]]:
        return self.getApiKey(user_id, "shodan")

    def updateShodanKey(self, user_id: Any, key: str) -> bool:
        return self.upsertApiKey(user_id, "shodan", key)

    # --- Investigation Projects & Case Evidence ---

    def createProject(self, user_id: Any, name: str, scope: str = "General OSINT Investigation") -> Optional[int]:
        if not name or not name.strip():
            return None
        uid = self._extract_user_id(user_id)
        return self.connection.insert(
            "INSERT INTO project (id_user, name_project, scope_project) VALUES (?, ?, ?);",
            (uid, name.strip(), (scope or "General OSINT Investigation").strip()),
        )

    def listProjects(self, user_id: Any) -> List[Dict[str, Any]]:
        uid = self._extract_user_id(user_id)
        return self.connection.select_all(
            """
            SELECT p.id_project, p.name_project, p.scope_project, p.created_at,
                   COUNT(s.id_scan) AS scan_count
            FROM project p
            LEFT JOIN scan_history s ON s.id_project = p.id_project
            WHERE p.id_user = ?
            GROUP BY p.id_project
            ORDER BY p.id_project DESC;
            """,
            (uid,),
        )

    def getProject(self, user_id: Any, project_id: int) -> Optional[Dict[str, Any]]:
        uid = self._extract_user_id(user_id)
        project = self.connection.select(
            "SELECT * FROM project WHERE id_project = ? AND id_user = ?;",
            (project_id, uid),
        )
        if not project:
            return None
        scans = self.getProjectScans(uid, project_id)
        project["scans"] = scans
        return project

    def deleteProject(self, user_id: Any, project_id: int) -> int:
        uid = self._extract_user_id(user_id)
        return self.connection.delete(
            "DELETE FROM project WHERE id_project = ? AND id_user = ?;",
            (project_id, uid),
        )

    def saveScanResult(
        self,
        user_id: Any,
        scan_type: str,
        target: str,
        payload: Dict[str, Any],
        summary: str = "",
        project_id: Optional[int] = None,
    ) -> int:
        uid = self._extract_user_id(user_id)
        payload_str = json.dumps(payload, ensure_ascii=False, default=str)
        return self.connection.insert(
            """
            INSERT INTO scan_history (id_project, id_user, scan_type, target, summary, payload_json)
            VALUES (?, ?, ?, ?, ?, ?);
            """,
            (project_id, uid, scan_type, target.strip(), summary, payload_str),
        )

    def getProjectScans(self, user_id: Any, project_id: int) -> List[Dict[str, Any]]:
        uid = self._extract_user_id(user_id)
        rows = self.connection.select_all(
            """
            SELECT id_scan, id_project, scan_type, target, summary, payload_json, created_at
            FROM scan_history
            WHERE id_user = ? AND id_project = ?
            ORDER BY id_scan DESC;
            """,
            (uid, project_id),
        )
        for r in rows:
            try:
                r["payload"] = json.loads(r.get("payload_json") or "{}")
            except Exception:
                r["payload"] = {}
        return rows

    def getRecentScans(self, user_id: Any, limit: int = 15) -> List[Dict[str, Any]]:
        uid = self._extract_user_id(user_id)
        rows = self.connection.select_all(
            """
            SELECT s.id_scan, s.id_project, s.scan_type, s.target, s.summary, s.payload_json, s.created_at,
                   p.name_project
            FROM scan_history s
            LEFT JOIN project p ON p.id_project = s.id_project
            WHERE s.id_user = ?
            ORDER BY s.id_scan DESC
            LIMIT ?;
            """,
            (uid, limit),
        )
        for r in rows:
            try:
                r["payload"] = json.loads(r.get("payload_json") or "{}")
            except Exception:
                r["payload"] = {}
        return rows

    def getDashboardStats(self, user_id: Any) -> Dict[str, Any]:
        uid = self._extract_user_id(user_id)
        proj_count = self.connection.select(
            "SELECT COUNT(*) AS cnt FROM project WHERE id_user = ?;", (uid,)
        )
        scan_count = self.connection.select(
            "SELECT COUNT(*) AS cnt FROM scan_history WHERE id_user = ?;", (uid,)
        )
        company_scans = self.connection.select(
            "SELECT COUNT(*) AS cnt FROM scan_history WHERE id_user = ? AND scan_type = 'company';",
            (uid,),
        )
        server_scans = self.connection.select(
            "SELECT COUNT(*) AS cnt FROM scan_history WHERE id_user = ? AND scan_type = 'server';",
            (uid,),
        )
        personal_scans = self.connection.select(
            "SELECT COUNT(*) AS cnt FROM scan_history WHERE id_user = ? AND scan_type = 'personal';",
            (uid,),
        )
        strix_scans = self.connection.select(
            "SELECT COUNT(*) AS cnt FROM scan_history WHERE id_user = ? AND scan_type = 'strix';",
            (uid,),
        )
        keys = self.getAllApiKeys(uid)
        return {
            "projects": int((proj_count or {}).get("cnt", 0)),
            "total_scans": int((scan_count or {}).get("cnt", 0)),
            "company_scans": int((company_scans or {}).get("cnt", 0)),
            "server_scans": int((server_scans or {}).get("cnt", 0)),
            "personal_scans": int((personal_scans or {}).get("cnt", 0)),
            "strix_scans": int((strix_scans or {}).get("cnt", 0)),
            "configured_keys": list(keys.keys()),
        }

