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

def save_investigation(investigation_id: str, original_url: str, indicators: list[SharedIndicator],):
    """Save an investigation and its extracted indicators."""

    initialize_database()

    with _get_connection() as connection:
        connection.execute("""
            INSERT OR IGNORE INTO investigations (
                investigation_id,
                original_url,
                created_at
            )
            VALUES (?, ?, ?)
        """, (
            investigation_id,
            original_url,
            datetime.now(timezone.utc).isoformat(),
        ))

        for indicator in indicators:
            for source in indicator.sources:
                connection.execute("""
                    INSERT OR IGNORE INTO indicators (
                        investigation_id,
                        indicator_type,
                        value,
                        source_module
                    )
                    VALUES (?, ?, ?, ?)
                """, (
                    investigation_id,
                    indicator.indicator_type.value,
                    indicator.value,
                    source.module,
                ))


def find_matching_investigations(indicators: list[SharedIndicator], exclude_investigation_id: str | None = None,) -> list[dict]:
    """Find previous investigations containing the supplied indicators."""

    initialize_database()
    matches = []

    with _get_connection() as connection:
        for indicator in indicators:
            query = """
                SELECT investigation_id, indicator_type, value, source_module
                FROM indicators
                WHERE indicator_type = ?
                AND value = ?
            """
            parameters = [indicator.indicator_type.value, indicator.value,]

            if exclude_investigation_id is not None:
                query += " AND investigation_id != ?"
                parameters.append(exclude_investigation_id)

            rows = connection.execute(query, parameters,).fetchall()
            matches.extend(dict(row) for row in rows)

    return matches
