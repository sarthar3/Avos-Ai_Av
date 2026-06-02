"""
AVOS AI - Database Manager
SQLite for logs/events + SQLCipher for encrypted vault
"""

import sqlite3
import logging
import os
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager
from datetime import datetime

logger = logging.getLogger('AVOS.DB')

DB_PATH     = 'logs/avos.db'
VAULT_PATH  = 'logs/avos_vault.db'
SCHEMA_PATH = 'core/db/schema.sql'


class DatabaseManager:
    """Thread-safe SQLite database manager."""

    def __init__(self):
        self.db_path    = DB_PATH
        self.vault_path = VAULT_PATH

    def initialize(self):
        """Create tables from schema.sql if not exist."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._run_schema()
        logger.info("Database initialized successfully.")

    def _run_schema(self):
        schema_sql = Path(SCHEMA_PATH).read_text(encoding='utf-8') if Path(SCHEMA_PATH).exists() else INLINE_SCHEMA
        with self._conn() as conn:
            conn.executescript(schema_sql)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ─── Threats ──────────────────────────────────────────────────────────────
    def insert_threat(self, threat: dict):
        sql = """
        INSERT INTO threats (
            event_id, event_type, threat_level, score, source,
            path, pid, details_json, timestamp, remediated, explanation
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """
        with self._conn() as conn:
            conn.execute(sql, (
                threat.get('event_id'),
                threat.get('event_type'),
                threat.get('threat_level', {}).get('name') if isinstance(threat.get('threat_level'), dict) else str(threat.get('threat_level', '')),
                threat.get('score', 0.0),
                threat.get('source'),
                threat.get('path'),
                threat.get('pid'),
                json.dumps(threat.get('details', {})),
                threat.get('timestamp'),
                1 if threat.get('remediated') else 0,
                threat.get('explanation', '')
            ))

    def get_threats(self, limit: int = 100, offset: int = 0, level_filter: str = '') -> List[Dict]:
        """Get threats with proper parameterized queries to prevent SQL injection."""
        params = []
        sql = "SELECT * FROM threats"
        
        if level_filter:
            # Validate level_filter against allowed values
            allowed_levels = ['CLEAN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
            if level_filter.upper() in allowed_levels:
                sql += " WHERE threat_level = ?"
                params.append(level_filter.upper())
            else:
                logger.warning(f"Invalid threat level filter: {level_filter}")
        
        sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def get_threats_today(self) -> int:
        sql = "SELECT COUNT(*) FROM threats WHERE date(timestamp, 'unixepoch') = date('now')"
        with self._conn() as conn:
            return conn.execute(sql).fetchone()[0]

    def quarantine_file(self, original_path: str, quarantine_path: str):
        sql = "INSERT INTO quarantine (original_path, quarantine_path, quarantined_at) VALUES (?,?,?)"
        with self._conn() as conn:
            conn.execute(sql, (original_path, quarantine_path, datetime.utcnow().isoformat()))

    # ─── Signatures ───────────────────────────────────────────────────────────
    def get_signature(self, sha256: str) -> Optional[str]:
        sql = "SELECT name FROM signatures WHERE sha256 = ?"
        with self._conn() as conn:
            row = conn.execute(sql, (sha256,)).fetchone()
        return row['name'] if row else None

    def add_signature(self, sha256: str, md5: str, name: str, severity: str):
        sql = "INSERT OR REPLACE INTO signatures (sha256, md5, name, severity, added_at) VALUES (?,?,?,?,?)"
        with self._conn() as conn:
            conn.execute(sql, (sha256, md5, name, severity, datetime.utcnow().isoformat()))

    def get_all_signatures(self) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM signatures").fetchall()
        return [dict(r) for r in rows]

    # ─── Breach Alerts ────────────────────────────────────────────────────────
    def upsert_breach_alert(self, email: str, source: str, date: str, data_types: str):
        sql = """
        INSERT OR REPLACE INTO breach_alerts (email, source, breach_date, data_types, alerted_at)
        VALUES (?,?,?,?,?)
        """
        with self._conn() as conn:
            conn.execute(sql, (email, source, date, data_types, datetime.utcnow().isoformat()))

    def get_breach_alerts(self) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM breach_alerts ORDER BY alerted_at DESC").fetchall()
        return [dict(r) for r in rows]

    # ─── Config ───────────────────────────────────────────────────────────────
    def set_config(self, key: str, value: str):
        sql = "INSERT OR REPLACE INTO config (key, value) VALUES (?,?)"
        with self._conn() as conn:
            conn.execute(sql, (key, value))

    def get_config(self, key: str) -> Optional[str]:
        sql = "SELECT value FROM config WHERE key = ?"
        with self._conn() as conn:
            row = conn.execute(sql, (key,)).fetchone()
        return row['value'] if row else None

    # ─── Events (EDR) ─────────────────────────────────────────────────────────
    def insert_event(self, event: dict):
        sql = """
        INSERT INTO events (event_type, pid, path, details_json, timestamp)
        VALUES (?,?,?,?,?)
        """
        with self._conn() as conn:
            conn.execute(sql, (
                event.get('event_type'),
                event.get('pid'),
                event.get('path'),
                json.dumps(event.get('details', {})),
                event.get('timestamp', datetime.utcnow().timestamp())
            ))

    def get_events(self, limit: int = 500) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]
    # ─── Vault (Encrypted Storage) ────────────────────────────────────────────
    def store_vault_key(self, key_name: str, key_value: str):
        """Store sensitive key in vault (for future SQLCipher integration)."""
        sql = "INSERT OR REPLACE INTO vault (key_name, key_value, created_at) VALUES (?,?,?)"
        with self._conn() as conn:
            conn.execute(sql, (key_name, key_value, datetime.utcnow().isoformat()))
    
    def get_vault_key(self, key_name: str) -> Optional[str]:
        """Retrieve sensitive key from vault."""
        sql = "SELECT key_value FROM vault WHERE key_name = ?"
        with self._conn() as conn:
            row = conn.execute(sql, (key_name,)).fetchone()
        return row['key_value'] if row else None


    # ─── CLI Init ─────────────────────────────────────────────────────────────
    @staticmethod
    def cli_init():
        """Run from command line: python -m core.db.db_manager --init"""
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument('--init', action='store_true')
        args = parser.parse_args()
        if args.init:
            db = DatabaseManager()
            db.initialize()
            print("[AVOS DB] Database initialized at:", DB_PATH)


INLINE_SCHEMA = """
CREATE TABLE IF NOT EXISTS threats (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     TEXT UNIQUE,
    event_type   TEXT,
    threat_level TEXT,
    score        REAL,
    source       TEXT,
    path         TEXT,
    pid          INTEGER,
    details_json TEXT,
    timestamp    REAL,
    remediated   INTEGER DEFAULT 0,
    explanation  TEXT
);

CREATE TABLE IF NOT EXISTS quarantine (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    original_path   TEXT,
    quarantine_path TEXT,
    quarantined_at  TEXT
);

CREATE TABLE IF NOT EXISTS signatures (
    sha256     TEXT PRIMARY KEY,
    md5        TEXT,
    name       TEXT NOT NULL,
    severity   TEXT DEFAULT 'HIGH',
    added_at   TEXT
);

CREATE TABLE IF NOT EXISTS breach_alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT,
    source      TEXT,
    breach_date TEXT,
    data_types  TEXT,
    alerted_at  TEXT,
    UNIQUE(email, source)
);

CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type   TEXT,
    pid          INTEGER,
    path         TEXT,
    details_json TEXT,
    timestamp    REAL
);

CREATE TABLE IF NOT EXISTS vault (
    key_name   TEXT PRIMARY KEY,
    key_value  TEXT NOT NULL,
    created_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_threats_timestamp ON threats(timestamp);
CREATE INDEX IF NOT EXISTS idx_threats_level     ON threats(threat_level);
CREATE INDEX IF NOT EXISTS idx_events_timestamp  ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_pid        ON events(pid);
"""


if __name__ == '__main__':
    DatabaseManager.cli_init()
