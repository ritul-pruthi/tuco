import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated

from app.core.db import get_connection
from app.core.storage import save_upload
from app.investigation.hosts_repo import get_hosts, save_hosts
from app.parsers.host_aggregator import aggregate_hosts
from app.parsers.pcap_parser import parse_pcap
from app.schemas.host import Host
from app.schemas.investigation import InvestigationResponse
from fastapi import APIRouter, File, HTTPException, UploadFile

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/investigations", response_model=InvestigationResponse, status_code=201)
def create_investigation(file: Annotated[UploadFile, File()]):
    final_path, _internal_filename, file_format = save_upload(file)
    try:
        size_bytes = final_path.stat().st_size
        inv_id = uuid.uuid4().hex
        created_at = datetime.now(UTC).isoformat()

        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO investigations (
                    id, filename, format, size_bytes, packet_count,
                    started_at, ended_at, duration_seconds, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    inv_id,
                    file.filename or "",
                    file_format,
                    size_bytes,
                    None,
                    None,
                    None,
                    None,
                    "uploaded",
                    created_at,
                ),
            )
            conn.commit()
    except Exception:
        if final_path.exists():
            try:
                final_path.unlink()
            except OSError:
                pass
        raise

    try:
        summary = parse_pcap(final_path, file_format)
        started_at = (
            datetime.fromtimestamp(summary.first_timestamp, tz=UTC).isoformat()
            if summary.first_timestamp is not None
            else None
        )
        ended_at = (
            datetime.fromtimestamp(summary.last_timestamp, tz=UTC).isoformat()
            if summary.last_timestamp is not None
            else None
        )
        packet_count = summary.packet_count
        duration_seconds = summary.duration_seconds

        with get_connection() as conn:
            conn.execute(
                """
                UPDATE investigations
                SET packet_count = ?, started_at = ?, ended_at = ?, duration_seconds = ?, status = ?
                WHERE id = ?
                """,
                (packet_count, started_at, ended_at, duration_seconds, "parsed", inv_id),
            )
            conn.commit()

        # Run aggregation synchronously
        hosts = aggregate_hosts(final_path, file_format, inv_id)
        with get_connection() as conn:
            save_hosts(conn, inv_id, hosts)
            conn.execute(
                "UPDATE investigations SET status = ? WHERE id = ?",
                ("aggregated", inv_id),
            )
            conn.commit()

        return InvestigationResponse(
            id=inv_id,
            filename=file.filename or "",
            format=file_format,
            size_bytes=size_bytes,
            packet_count=packet_count,
            started_at=started_at,
            ended_at=ended_at,
            duration_seconds=duration_seconds,
            status="aggregated",
            created_at=created_at,
        )
    except ValueError as val_err:
        logger.warning("Failed to process capture for investigation %s: %s", inv_id, val_err)
        with get_connection() as conn:
            conn.execute(
                "UPDATE investigations SET status = ? WHERE id = ?",
                ("failed", inv_id),
            )
            conn.commit()

        return InvestigationResponse(
            id=inv_id,
            filename=file.filename or "",
            format=file_format,
            size_bytes=size_bytes,
            packet_count=None,
            started_at=None,
            ended_at=None,
            duration_seconds=None,
            status="failed",
            created_at=created_at,
        )
    except Exception:
        logger.exception("Unexpected error processing capture for investigation %s", inv_id)
        with get_connection() as conn:
            conn.execute(
                "UPDATE investigations SET status = ? WHERE id = ?",
                ("failed", inv_id),
            )
            conn.commit()

        return InvestigationResponse(
            id=inv_id,
            filename=file.filename or "",
            format=file_format,
            size_bytes=size_bytes,
            packet_count=None,
            started_at=None,
            ended_at=None,
            duration_seconds=None,
            status="failed",
            created_at=created_at,
        )


@router.get("/investigations/{investigation_id}/hosts", response_model=list[Host])
def get_investigation_hosts(investigation_id: str):
    with get_connection() as conn:
        inv = conn.execute(
            "SELECT id FROM investigations WHERE id = ?",
            (investigation_id,),
        ).fetchone()
        if inv is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return get_hosts(conn, investigation_id)
