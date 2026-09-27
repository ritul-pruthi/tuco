import sqlite3

from app.core import config


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS investigations (
                id TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                format TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                packet_count INTEGER,
                started_at TEXT,
                ended_at TEXT,
                duration_seconds REAL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
