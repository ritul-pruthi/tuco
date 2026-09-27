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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS hosts (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL REFERENCES investigations(id),
                ip TEXT NOT NULL,
                mac TEXT,
                scope TEXT NOT NULL,
                packets_sent INTEGER NOT NULL DEFAULT 0,
                packets_received INTEGER NOT NULL DEFAULT 0,
                bytes_sent INTEGER NOT NULL DEFAULT 0,
                bytes_received INTEGER NOT NULL DEFAULT 0,
                unique_destinations INTEGER NOT NULL DEFAULT 0,
                unique_ports INTEGER NOT NULL DEFAULT 0,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_hosts_investigation_ip
            ON hosts (investigation_id, ip)
            """
        )
        conn.commit()

