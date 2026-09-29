import sqlite3

from app.schemas.tls_record import TlsRecord


def save_tls_records(
    conn: sqlite3.Connection, investigation_id: str, records: list[TlsRecord]
) -> None:
    conn.execute("DELETE FROM tls_records WHERE investigation_id = ?", (investigation_id,))
    if records:
        conn.executemany(
            """
            INSERT INTO tls_records (
                id, investigation_id, timestamp, source_ip, source_port,
                destination_ip, destination_port, sni, tls_version,
                certificate_subject, certificate_issuer,
                certificate_not_before, certificate_not_after
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    record.sni,
                    record.tls_version,
                    record.certificate_subject,
                    record.certificate_issuer,
                    record.certificate_not_before,
                    record.certificate_not_after,
                )
                for record in records
            ],
        )
    conn.commit()


def get_tls_records(conn: sqlite3.Connection, investigation_id: str) -> list[TlsRecord]:
    rows = conn.execute(
        "SELECT * FROM tls_records WHERE investigation_id = ? ORDER BY timestamp ASC, id ASC",
        (investigation_id,),
    ).fetchall()
    return [TlsRecord.model_validate(dict(row)) for row in rows]
