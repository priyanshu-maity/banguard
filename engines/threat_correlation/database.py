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

