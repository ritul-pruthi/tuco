import sqlite3

from app.schemas.investigation import InvestigationResponse


def get_investigation(
    conn: sqlite3.Connection, investigation_id: str
) -> InvestigationResponse | None:
    row = conn.execute(
        "SELECT * FROM investigations WHERE id = ?",
        (investigation_id,),
    ).fetchone()
    if row is None:
        return None
    return InvestigationResponse.model_validate(dict(row))


def list_investigations(
    conn: sqlite3.Connection,
    limit: int = 100,
    offset: int = 0,
) -> list[InvestigationResponse]:
    bounded_limit = max(1, min(limit, 500))
    bounded_offset = max(0, offset)
    rows = conn.execute(
        """
        SELECT * FROM investigations
        ORDER BY created_at DESC, id DESC
        LIMIT ? OFFSET ?
        """,
        (bounded_limit, bounded_offset),
    ).fetchall()
    return [InvestigationResponse.model_validate(dict(row)) for row in rows]
