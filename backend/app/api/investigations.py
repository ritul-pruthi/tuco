import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated

from app.core.db import get_connection
from app.core.storage import save_upload
from app.detections.base import DetectionContext
from app.detections.registry import build_default_engine
from app.investigation.detections_repo import get_detections, save_detections
from app.investigation.dns_repo import get_dns_records, save_dns_records
from app.investigation.flows_repo import get_flows, save_flows
from app.investigation.hosts_repo import get_hosts, save_hosts
from app.investigation.http_repo import get_http_records, save_http_records
from app.parsers.dns_extractor import extract_dns
from app.parsers.flow_aggregator import aggregate_flows
from app.parsers.host_aggregator import aggregate_hosts
from app.parsers.http_extractor import extract_http
from app.parsers.pcap_parser import parse_pcap
from app.schemas.detection import Detection
from app.schemas.dns_record import DnsRecord
from app.schemas.flow import Flow
from app.schemas.host import Host
from app.schemas.http_record import HttpRecord
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

        # Run host and flow aggregation synchronously
        hosts = aggregate_hosts(final_path, file_format, inv_id)
        flows = aggregate_flows(final_path, file_format, inv_id)
        dns_records = extract_dns(final_path, file_format, inv_id)
        http_records = extract_http(final_path, file_format, inv_id)
        with get_connection() as conn:
            save_hosts(conn, inv_id, hosts)
            save_flows(conn, inv_id, flows)
            save_dns_records(conn, inv_id, dns_records)
            save_http_records(conn, inv_id, http_records)
            detection_context = DetectionContext(
                investigation_id=inv_id,
                hosts=get_hosts(conn, inv_id),
                flows=get_flows(conn, inv_id),
                dns_records=get_dns_records(conn, inv_id),
                http_records=get_http_records(conn, inv_id),
            )
            detections = build_default_engine().run(detection_context)
            save_detections(conn, inv_id, detections)
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


@router.get("/investigations/{investigation_id}/flows", response_model=list[Flow])
def get_investigation_flows(investigation_id: str):
    with get_connection() as conn:
        inv = conn.execute(
            "SELECT id FROM investigations WHERE id = ?",
            (investigation_id,),
        ).fetchone()
        if inv is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return get_flows(conn, investigation_id)


@router.get("/investigations/{investigation_id}/dns", response_model=list[DnsRecord])
def get_investigation_dns(investigation_id: str):
    with get_connection() as conn:
        inv = conn.execute(
            "SELECT id FROM investigations WHERE id = ?",
            (investigation_id,),
        ).fetchone()
        if inv is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return get_dns_records(conn, investigation_id)


@router.get("/investigations/{investigation_id}/http", response_model=list[HttpRecord])
def get_investigation_http(investigation_id: str):
    with get_connection() as conn:
        inv = conn.execute(
            "SELECT id FROM investigations WHERE id = ?",
            (investigation_id,),
        ).fetchone()
        if inv is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return get_http_records(conn, investigation_id)


@router.get("/investigations/{investigation_id}/detections", response_model=list[Detection])
def get_investigation_detections(investigation_id: str):
    with get_connection() as conn:
        inv = conn.execute(
            "SELECT id FROM investigations WHERE id = ?",
            (investigation_id,),
        ).fetchone()
        if inv is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return get_detections(conn, investigation_id)
