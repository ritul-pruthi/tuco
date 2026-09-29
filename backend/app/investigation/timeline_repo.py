import sqlite3

from app.schemas.timeline_event import TimelineEvent


def save_timeline_events(
    conn: sqlite3.Connection, investigation_id: str, events: list[TimelineEvent]
) -> None:
    conn.execute("DELETE FROM timeline_events WHERE investigation_id = ?", (investigation_id,))
    if events:
        conn.executemany(
            """
            INSERT INTO timeline_events (
                id, investigation_id, timestamp, event_type, source,
                destination, summary, evidence_type, evidence_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    event.id,
                    event.investigation_id,
                    event.timestamp,
                    event.event_type,
                    event.source,
                    event.destination,
                    event.summary,
                    event.evidence_type,
                    event.evidence_id,
                )
                for event in events
            ],
        )
    conn.commit()


def get_timeline_events(conn: sqlite3.Connection, investigation_id: str) -> list[TimelineEvent]:
    rows = conn.execute(
        """
        SELECT * FROM timeline_events
        WHERE investigation_id = ?
        ORDER BY timestamp ASC, id ASC
        """,
        (investigation_id,),
    ).fetchall()
    return [TimelineEvent.model_validate(dict(row)) for row in rows]
