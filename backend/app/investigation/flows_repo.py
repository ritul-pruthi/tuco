import sqlite3

from app.schemas.flow import Flow


def save_flows(conn: sqlite3.Connection, investigation_id: str, flows: list[Flow]) -> None:
    """Save aggregated flows for an investigation.

    Deletes any existing flows for this investigation before inserting, ensuring
    idempotency.
    """
    conn.execute(
        "DELETE FROM flows WHERE investigation_id = ?",
        (investigation_id,),
    )
    if flows:
        conn.executemany(
            """
            INSERT INTO flows (
                id, investigation_id, src_ip, src_port, dst_ip, dst_port,
                protocol, packets_sent, packets_received, bytes_sent, bytes_received,
                first_seen, last_seen, tcp_state
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    f.id,
                    f.investigation_id,
                    f.src_ip,
                    f.src_port,
                    f.dst_ip,
                    f.dst_port,
                    f.protocol,
                    f.packets_sent,
                    f.packets_received,
                    f.bytes_sent,
                    f.bytes_received,
                    f.first_seen,
                    f.last_seen,
                    f.tcp_state,
                )
                for f in flows
            ],
        )
    conn.commit()


def get_flows(conn: sqlite3.Connection, investigation_id: str) -> list[Flow]:
    """Retrieve all flows for an investigation ordered by canonical endpoints and protocol."""
    rows = conn.execute(
        """
        SELECT * FROM flows
        WHERE investigation_id = ?
        ORDER BY src_ip ASC, src_port ASC, dst_ip ASC, dst_port ASC, protocol ASC
        """,
        (investigation_id,),
    ).fetchall()
    return [Flow.model_validate(dict(row)) for row in rows]


def get_flow(conn: sqlite3.Connection, investigation_id: str, flow_id: str) -> Flow | None:
    """Retrieve a single flow by ID for an investigation."""
    row = conn.execute(
        "SELECT * FROM flows WHERE investigation_id = ? AND id = ?",
        (investigation_id, flow_id),
    ).fetchone()
    if row is None:
        return None
    return Flow.model_validate(dict(row))
