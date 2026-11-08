
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


DATABASE_PATH = Path(__file__).resolve().parents[2] / "banguard.db"


def _get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    """Create M6 database tables if they do not exist."""

    with _get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS assessment_reports (
                report_id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                current_version INTEGER NOT NULL DEFAULT 0
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS report_versions (
                report_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                report_json TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                registered_at TEXT NOT NULL,
                blockchain_tx_hash TEXT,
                PRIMARY KEY (report_id, version),
                FOREIGN KEY (report_id) REFERENCES assessment_reports(report_id) ON DELETE CASCADE
            )
        """)


def save_report_version(report_id: str, investigation_id: str, report_created_at: str, report_json: str, content_hash: str) -> int:
    """Save a report or create a new version if its content changes."""

    initialize_database()

    with _get_connection() as connection:
        existing = connection.execute("SELECT investigation_id, current_version FROM assessment_reports WHERE report_id = ?", (report_id,)).fetchone()

        if existing is None:
            connection.execute("INSERT INTO assessment_reports (report_id, investigation_id, created_at) VALUES (?, ?, ?)", (report_id, investigation_id, report_created_at))
            current_version = 0
        else:
            if existing["investigation_id"] != investigation_id:
                raise ValueError("Report ID already belongs to another investigation.")

            current_version = existing["current_version"]

            if current_version > 0:
                latest = connection.execute("SELECT content_hash FROM report_versions WHERE report_id = ? AND version = ?", (report_id, current_version)).fetchone()

                if latest["content_hash"] == content_hash:
                    return current_version

        new_version = current_version + 1

        connection.execute("INSERT INTO report_versions (report_id, version, report_json, content_hash, registered_at) VALUES (?, ?, ?, ?, ?)", (report_id, new_version, report_json, content_hash, datetime.now(timezone.utc).isoformat()))
        connection.execute("UPDATE assessment_reports SET current_version = ? WHERE report_id = ?", (new_version, report_id))

        return new_version


def get_report_version(report_id: str, version: int | None = None) -> dict | None:
    """Retrieve a specific report version or its latest version."""

    initialize_database()

    with _get_connection() as connection:
        if version is None:
            row = connection.execute("""
                SELECT rv.*
                FROM report_versions rv
                JOIN assessment_reports ar ON rv.report_id = ar.report_id
                WHERE rv.report_id = ? AND rv.version = ar.current_version
            """, (report_id,)).fetchone()
        else:
            row = connection.execute("SELECT * FROM report_versions WHERE report_id = ? AND version = ?", (report_id, version)).fetchone()

        return dict(row) if row else None


def update_blockchain_tx_hash(report_id: str, version: int, transaction_hash: str):
    """Store the blockchain transaction hash for a registered version."""

    with _get_connection() as connection:
        cursor = connection.execute("UPDATE report_versions SET blockchain_tx_hash = ? WHERE report_id = ? AND version = ?", (transaction_hash, report_id, version))

        if cursor.rowcount == 0:
            raise ValueError("Report version does not exist.")
