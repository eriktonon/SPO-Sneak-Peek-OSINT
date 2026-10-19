# -*- coding:UTF-8 -*-
"""
Zero-Config SQLite DataFactory for SPO - Sneak Peek OSINT v2.0.
Automatically initializes the database and schema on first run, and executes
all queries using parameterized statements to prevent SQL injection.
"""
import os
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union


class DataFactory:
    def __init__(self, db_path: Optional[str] = None):
        env_path = os.environ.get("SPO_DB_PATH")
        base_dir = Path(__file__).resolve().parent.parent
        default_path = base_dir / "data" / "spo.db"
        self.db_path = Path(db_path or env_path or default_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    def _init_schema(self) -> None:
        schema_file = Path(__file__).resolve().parent.parent / "sql" / "schema.sql"
        with self._get_connection() as conn:
            if schema_file.exists():
                sql_script = schema_file.read_text(encoding="utf-8")
                conn.executescript(sql_script)
            conn.commit()

    def insert(self, sql: str, params: Union[Tuple[Any, ...], List[Any]] = ()) -> int:
        with self._get_connection() as conn:
            cursor = conn.execute(sql, params)
            conn.commit()
            return int(cursor.lastrowid or 0)

    def select(self, sql: str, params: Union[Tuple[Any, ...], List[Any]] = ()) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute(sql, params)
            row = cursor.fetchone()
            return dict(row) if row is not None else None

    def select_all(self, sql: str, params: Union[Tuple[Any, ...], List[Any]] = ()) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.execute(sql, params)
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def update(self, sql: str, params: Union[Tuple[Any, ...], List[Any]] = ()) -> int:
        with self._get_connection() as conn:
            cursor = conn.execute(sql, params)
            conn.commit()
            return int(cursor.rowcount or 0)

    def delete(self, sql: str, params: Union[Tuple[Any, ...], List[Any]] = ()) -> int:
        with self._get_connection() as conn:
            cursor = conn.execute(sql, params)
            conn.commit()
            return int(cursor.rowcount or 0)
