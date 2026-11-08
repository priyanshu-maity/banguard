
import json
import sqlite3
from pathlib import Path


DATABASE_PATH = Path(__file__).resolve().parents[1] / "banguard.db"


def _get_connection():
    connection = sqlite3.connect(DATABASE_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    with _get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS api_investigations (
                investigation_id TEXT PRIMARY KEY,
                report_id TEXT NOT NULL UNIQUE,
                investigation_type TEXT NOT NULL,
                created_at TEXT NOT NULL,
                result_json TEXT NOT NULL,
                report_json TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_api_investigations_report_id
            ON api_investigations(report_id)
        """)


def save_investigation(result: dict):
    report = result.get("threat_report")

    if not report:
        raise ValueError("Cannot persist an investigation without a threat report.")

    investigation_id = result["investigation_id"]
    report_id = report["report_id"]

    with _get_connection() as connection:
        connection.execute("""
            INSERT INTO api_investigations (
                investigation_id,
                report_id,
                investigation_type,
                created_at,
                result_json,
                report_json
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            investigation_id,
            report_id,
            result["investigation_type"],
            report["created_at"],
            json.dumps(result, ensure_ascii=False, allow_nan=False),
            json.dumps(report, ensure_ascii=False, allow_nan=False),
        ))


def get_investigation(investigation_id: str):
    with _get_connection() as connection:
        row = connection.execute(
            "SELECT result_json FROM api_investigations WHERE investigation_id = ?",
            (investigation_id,),
        ).fetchone()

    return json.loads(row["result_json"]) if row else None


def get_report(report_id: str):
    with _get_connection() as connection:
        row = connection.execute(
            "SELECT report_json FROM api_investigations WHERE report_id = ?",
            (report_id,),
        ).fetchone()

    return json.loads(row["report_json"]) if row else None
