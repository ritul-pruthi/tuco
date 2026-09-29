import sqlite3

from app.schemas.http_record import HttpRecord


def save_http_records(
    conn: sqlite3.Connection, investigation_id: str, records: list[HttpRecord]
) -> None:
    conn.execute("DELETE FROM http_records WHERE investigation_id = ?", (investigation_id,))
    if records:
        conn.executemany(
            """
            INSERT INTO http_records (
                id, investigation_id, timestamp, source_ip, source_port,
                destination_ip, destination_port, method, host, path,
                user_agent, status_code
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    record.id,
                    record.investigation_id,
                    record.timestamp,
                    record.source_ip,
                    record.source_port,
                    record.destination_ip,
                    record.destination_port,
                    record.method,
                    record.host,
                    record.path,
                    record.user_agent,
                    record.status_code,
                )
                for record in records
            ],
        )
    conn.commit()


def get_http_records(conn: sqlite3.Connection, investigation_id: str) -> list[HttpRecord]:
    rows = conn.execute(
        "SELECT * FROM http_records WHERE investigation_id = ? ORDER BY timestamp ASC, id ASC",
        (investigation_id,),
    ).fetchall()
    return [HttpRecord.model_validate(dict(row)) for row in rows]
