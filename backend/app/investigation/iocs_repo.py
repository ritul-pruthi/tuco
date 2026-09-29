import json
import sqlite3

from app.schemas.ioc import Ioc


def save_iocs(conn: sqlite3.Connection, investigation_id: str, iocs: list[Ioc]) -> None:
    conn.execute("DELETE FROM iocs WHERE investigation_id = ?", (investigation_id,))
    if iocs:
        conn.executemany(
            """
            INSERT INTO iocs (
                id, investigation_id, ioc_type, value, first_seen, last_seen,
                occurrences, scope, evidence_type, evidence_ids
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    ioc.id,
                    ioc.investigation_id,
                    ioc.ioc_type,
                    ioc.value,
                    ioc.first_seen,
                    ioc.last_seen,
                    ioc.occurrences,
                    ioc.scope,
                    ioc.evidence_type,
                    json.dumps(ioc.evidence_ids),
                )
                for ioc in iocs
            ],
        )
    conn.commit()


def get_iocs(conn: sqlite3.Connection, investigation_id: str) -> list[Ioc]:
    rows = conn.execute(
        """
        SELECT * FROM iocs
        WHERE investigation_id = ?
        ORDER BY ioc_type ASC, occurrences DESC, value ASC
        """,
        (investigation_id,),
    ).fetchall()
    return [
        Ioc.model_validate({**dict(row), "evidence_ids": json.loads(row["evidence_ids"])})
        for row in rows
    ]
