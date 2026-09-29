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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS flows (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL REFERENCES investigations(id),
                src_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                dst_ip TEXT NOT NULL,
                dst_port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                packets_sent INTEGER NOT NULL DEFAULT 0,
                packets_received INTEGER NOT NULL DEFAULT 0,
                bytes_sent INTEGER NOT NULL DEFAULT 0,
                bytes_received INTEGER NOT NULL DEFAULT 0,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                tcp_state TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_flows_investigation_endpoints
            ON flows (investigation_id, src_ip, dst_ip, protocol)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS dns_records (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL REFERENCES investigations(id),
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                query TEXT NOT NULL,
                query_type TEXT NOT NULL,
                response_code INTEGER NOT NULL,
                answers TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_dns_records_investigation_query
            ON dns_records (investigation_id, query)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS http_records (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL REFERENCES investigations(id),
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                source_port INTEGER NOT NULL,
                destination_ip TEXT NOT NULL,
                destination_port INTEGER NOT NULL,
                method TEXT NOT NULL,
                host TEXT,
                path TEXT,
                user_agent TEXT,
                status_code INTEGER
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_http_records_investigation_host
            ON http_records (investigation_id, host)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tls_records (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL REFERENCES investigations(id),
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                source_port INTEGER NOT NULL,
                destination_ip TEXT NOT NULL,
                destination_port INTEGER NOT NULL,
                sni TEXT,
                tls_version TEXT,
                certificate_subject TEXT,
                certificate_issuer TEXT,
                certificate_not_before TEXT,
                certificate_not_after TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_tls_records_investigation_sni
            ON tls_records (investigation_id, sni)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS detections (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL REFERENCES investigations(id),
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                source_port INTEGER,
                destination_ip TEXT NOT NULL,
                destination_port INTEGER,
                timeframe_start TEXT NOT NULL,
                timeframe_end TEXT NOT NULL,
                observed_metric TEXT NOT NULL,
                observed_value REAL NOT NULL,
                threshold_description TEXT NOT NULL,
                threshold_value REAL NOT NULL,
                explanation TEXT NOT NULL,
                evidence TEXT NOT NULL,
                limitations TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_detections_investigation_rule
            ON detections (investigation_id, rule_id)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_detections_investigation_severity
            ON detections (investigation_id, severity)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS iocs (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL REFERENCES investigations(id),
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                occurrences INTEGER NOT NULL,
                scope TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                evidence_ids TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_iocs_investigation_type
            ON iocs (investigation_id, ioc_type)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_iocs_investigation_value
            ON iocs (investigation_id, value)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS timeline_events (
                id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL REFERENCES investigations(id),
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source TEXT NOT NULL,
                destination TEXT NOT NULL,
                summary TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                evidence_id TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_timeline_events_investigation_timestamp
            ON timeline_events (investigation_id, timestamp)
            """
        )
        conn.commit()
