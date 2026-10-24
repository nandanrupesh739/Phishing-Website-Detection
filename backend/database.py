"""
PhishGuard AI — SQLite Database Layer
======================================
Creates and manages the local scan history database.
All queries use parameterised SQL to prevent SQL injection.
"""

from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator

from backend.config import DB_PATH, HISTORY_PAGE_SIZE

log = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────
# Schema
# ──────────────────────────────────────────────────────────────────────────
CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS scan_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    submitted_url   TEXT    NOT NULL,
    prediction      TEXT,
    risk_level      TEXT,
    model_score     REAL,
    score_type      TEXT,
    model_version   TEXT,
    scan_timestamp  TEXT    NOT NULL
);
"""

CREATE_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_scan_timestamp
    ON scan_history (scan_timestamp DESC);
"""


# ──────────────────────────────────────────────────────────────────────────
# Connection helper
# ──────────────────────────────────────────────────────────────────────────

@contextmanager
def _get_conn() -> Generator[sqlite3.Connection, None, None]:
    """Yield a sqlite3 connection with row_factory enabled, then close it."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# ──────────────────────────────────────────────────────────────────────────
# Initialisation
# ──────────────────────────────────────────────────────────────────────────

def init_db() -> None:
    """Create the database file and tables if they do not exist."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _get_conn() as conn:
        conn.execute(CREATE_TABLE_SQL)
        conn.execute(CREATE_INDEX_SQL)
    log.info("Database initialised at %s", DB_PATH)


# ──────────────────────────────────────────────────────────────────────────
# Write
# ──────────────────────────────────────────────────────────────────────────

def insert_scan(
    submitted_url: str,
    prediction: str | None,
    risk_level: str | None,
    model_score: float | None,
    score_type: str | None,
    model_version: str | None,
) -> int:
    """
    Insert a scan result into the history table.
    Returns the new row id.

    NOTE: Only URL structure data is stored — no page content, cookies, or
    authentication material.  Users should be aware that the URL itself
    may contain sensitive query parameters.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    with _get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO scan_history
                (submitted_url, prediction, risk_level, model_score,
                 score_type, model_version, scan_timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                submitted_url,
                prediction,
                risk_level,
                model_score,
                score_type,
                model_version,
                timestamp,
            ),
        )
        return cur.lastrowid  # type: ignore[return-value]


# ──────────────────────────────────────────────────────────────────────────
# Read
# ──────────────────────────────────────────────────────────────────────────

def get_history(limit: int = HISTORY_PAGE_SIZE, offset: int = 0) -> list[dict]:
    """
    Return recent scan records, newest first.
    Returns a list of dicts with safe field names.
    """
    with _get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, submitted_url, prediction, risk_level,
                   model_score, score_type, model_version, scan_timestamp
            FROM scan_history
            ORDER BY scan_timestamp DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()
    return [dict(row) for row in rows]


def get_history_stats() -> dict:
    """Return aggregate statistics about scan history."""
    with _get_conn() as conn:
        row = conn.execute(
            """
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN prediction = 'PHISHING' THEN 1 ELSE 0 END) AS phishing_count,
                SUM(CASE WHEN prediction = 'LIKELY LEGITIMATE' THEN 1 ELSE 0 END) AS legitimate_count,
                SUM(CASE WHEN prediction IS NULL THEN 1 ELSE 0 END) AS error_count
            FROM scan_history
            """
        ).fetchone()
    return dict(row) if row else {}


def get_total_count() -> int:
    """Return the total number of scan records."""
    with _get_conn() as conn:
        row = conn.execute("SELECT COUNT(*) as cnt FROM scan_history").fetchone()
    return int(row["cnt"]) if row else 0


# ──────────────────────────────────────────────────────────────────────────
# Delete
# ──────────────────────────────────────────────────────────────────────────

def clear_history() -> int:
    """Delete all scan history records.  Returns number of rows deleted."""
    with _get_conn() as conn:
        cur = conn.execute("DELETE FROM scan_history")
        deleted = cur.rowcount
    log.info("Cleared %d scan history records.", deleted)
    return deleted
