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
    """Create the database file and tables if they do not exist, and migrate legacy schemas."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _get_conn() as conn:
        conn.execute(CREATE_TABLE_SQL)
        conn.execute(CREATE_INDEX_SQL)
        # Old-schema migration: add score_type column if table was created by older schema
        cur = conn.execute("PRAGMA table_info(scan_history)")
        existing_cols = [row["name"] if isinstance(row, sqlite3.Row) else row[1] for row in cur.fetchall()]
        if "score_type" not in existing_cols:
            conn.execute("ALTER TABLE scan_history ADD COLUMN score_type TEXT")
            log.info("Migrated scan_history table: added missing column 'score_type'")
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
    anonymize: bool | None = None,
) -> int:
    """
    Insert a scan result into the history table.
    Returns the new row id.

    If anonymize is True (or config.ANONYMIZE_URLS is enabled), only the
    hostname and a truncated SHA-256 hash of the URL are stored.
    """
    import hashlib
    import urllib.parse
    from backend import config

    should_anonymize = anonymize if anonymize is not None else config.ANONYMIZE_URLS
    if should_anonymize and submitted_url:
        try:
            parsed = urllib.parse.urlsplit(submitted_url if "://" in submitted_url else "http://" + submitted_url)
            host = parsed.netloc or parsed.path.split("/")[0] or "unknown-host"
        except Exception:
            host = "unknown-host"
        url_hash = hashlib.sha256(submitted_url.encode("utf-8")).hexdigest()[:12]
        stored_url = f"{host} [sha256:{url_hash}]"
    else:
        stored_url = submitted_url

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
                stored_url,
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
                COALESCE(SUM(CASE WHEN prediction = 'PHISHING' THEN 1 ELSE 0 END), 0) AS phishing_count,
                COALESCE(SUM(CASE WHEN prediction IN ('SAFE', 'LIKELY LEGITIMATE') THEN 1 ELSE 0 END), 0) AS legitimate_count,
                COALESCE(SUM(CASE WHEN prediction IS NULL THEN 1 ELSE 0 END), 0) AS error_count
            FROM scan_history
            """
        ).fetchone()
    if not row:
        return {"total": 0, "phishing_count": 0, "legitimate_count": 0, "error_count": 0}
    return {
        "total": int(row["total"] or 0),
        "phishing_count": int(row["phishing_count"] or 0),
        "legitimate_count": int(row["legitimate_count"] or 0),
        "error_count": int(row["error_count"] or 0),
    }


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
