import sqlite3

from app.schemas.host import Host


def save_hosts(conn: sqlite3.Connection, investigation_id: str, hosts: list[Host]) -> None:
    """Save aggregated hosts for an investigation.

    Deletes any existing hosts for this investigation before inserting, ensuring
    idempotency.
    """
    conn.execute(
        "DELETE FROM hosts WHERE investigation_id = ?",
        (investigation_id,),
    )
    if hosts:
        conn.executemany(
            """
            INSERT INTO hosts (
                id, investigation_id, ip, mac, scope,
                packets_sent, packets_received, bytes_sent, bytes_received,
                unique_destinations, unique_ports, first_seen, last_seen
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    h.id,
                    h.investigation_id,
                    h.ip,
                    h.mac,
                    h.scope,
                    h.packets_sent,
                    h.packets_received,
                    h.bytes_sent,
                    h.bytes_received,
                    h.unique_destinations,
                    h.unique_ports,
                    h.first_seen,
                    h.last_seen,
                )
                for h in hosts
            ],
        )
    conn.commit()


def get_hosts(conn: sqlite3.Connection, investigation_id: str) -> list[Host]:
    """Retrieve all hosts for an investigation ordered by IP."""
    rows = conn.execute(
        "SELECT * FROM hosts WHERE investigation_id = ? ORDER BY ip ASC",
        (investigation_id,),
    ).fetchall()
    return [Host.model_validate(dict(row)) for row in rows]


def get_host(conn: sqlite3.Connection, investigation_id: str, host_id: str) -> Host | None:
    """Retrieve a single host by ID for an investigation."""
    row = conn.execute(
        "SELECT * FROM hosts WHERE investigation_id = ? AND id = ?",
        (investigation_id, host_id),
    ).fetchone()
    if row is None:
        return None
    return Host.model_validate(dict(row))
