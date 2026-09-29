import json
import sqlite3

from app.schemas.dns_record import DnsRecord


def save_dns_records(
    conn: sqlite3.Connection, investigation_id: str, records: list[DnsRecord]
) -> None:
    conn.execute("DELETE FROM dns_records WHERE investigation_id = ?", (investigation_id,))
    if records:
        conn.executemany(
            """
            INSERT INTO dns_records (
                id, investigation_id, timestamp, source_ip, destination_ip,
                query, query_type, response_code, answers
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    record.id,
                    record.investigation_id,
                    record.timestamp,
                    record.source_ip,
                    record.destination_ip,
                    record.query,
                    record.query_type,
                    record.response_code,
                    json.dumps(record.answers),
                )
                for record in records
            ],
        )
    conn.commit()


def get_dns_records(conn: sqlite3.Connection, investigation_id: str) -> list[DnsRecord]:
    rows = conn.execute(
        "SELECT * FROM dns_records WHERE investigation_id = ? ORDER BY timestamp ASC, id ASC",
        (investigation_id,),
    ).fetchall()
    return [DnsRecord(**{**dict(row), "answers": json.loads(row["answers"])}) for row in rows]
