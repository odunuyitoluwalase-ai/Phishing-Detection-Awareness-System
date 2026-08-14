"""
history.py
Persists analyzed URLs and their results to a local SQLite database so past
lookups can be reviewed, filtered, and exported.
"""

import csv
import json
import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import List, Optional

from models import AnalysisResult, Indicator

DEFAULT_DB_PATH = Path(__file__).parent / "phishing_history.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    host TEXT,
    registrable_domain TEXT,
    risk_score INTEGER,
    risk_level TEXT,
    analyzed_at TEXT,
    indicators_json TEXT,
    recommendations_json TEXT
);
"""


class HistoryStore:
    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        self.db_path = str(db_path)
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.execute(SCHEMA)

    def save(self, result: AnalysisResult) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                """INSERT INTO history
                   (url, host, registrable_domain, risk_score, risk_level,
                    analyzed_at, indicators_json, recommendations_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    result.url,
                    result.host,
                    result.registrable_domain,
                    result.risk_score,
                    result.risk_level,
                    result.analyzed_at,
                    json.dumps([asdict(i) for i in result.indicators]),
                    json.dumps(result.recommendations),
                ),
            )
            return cur.lastrowid

    def list(self, limit: int = 20, risk_level: Optional[str] = None) -> List[sqlite3.Row]:
        with self._connect() as conn:
            if risk_level:
                cur = conn.execute(
                    """SELECT * FROM history WHERE risk_level = ?
                       ORDER BY id DESC LIMIT ?""",
                    (risk_level, limit),
                )
            else:
                cur = conn.execute(
                    "SELECT * FROM history ORDER BY id DESC LIMIT ?", (limit,)
                )
            return cur.fetchall()

    def get(self, record_id: int) -> Optional[sqlite3.Row]:
        with self._connect() as conn:
            cur = conn.execute("SELECT * FROM history WHERE id = ?", (record_id,))
            return cur.fetchone()

    def clear(self):
        with self._connect() as conn:
            conn.execute("DELETE FROM history")

    def export_csv(self, out_path: str, limit: int = 1000):
        rows = self.list(limit=limit)
        with open(out_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "id", "url", "host", "registrable_domain", "risk_score",
                "risk_level", "analyzed_at",
            ])
            for r in rows:
                writer.writerow([
                    r["id"], r["url"], r["host"], r["registrable_domain"],
                    r["risk_score"], r["risk_level"], r["analyzed_at"],
                ])
        return out_path
