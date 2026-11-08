import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .schema import SharedIndicator


DATABASE_PATH = Path(__file__).resolve().parents[2] / "banguard.db"

def _get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    return connection

def initialize_database():
    """Create the database tables and indexes if they do not exist."""

    with _get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                investigation_id TEXT PRIMARY KEY,
                original_url TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                value TEXT NOT NULL,
                source_module TEXT NOT NULL,

                FOREIGN KEY (investigation_id)
                    REFERENCES investigations(investigation_id)
                    ON DELETE CASCADE,

                UNIQUE (
                    investigation_id,
                    indicator_type,
                    value,
                    source_module
                )
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_indicator_lookup
            ON indicators (indicator_type, value)
        """)



