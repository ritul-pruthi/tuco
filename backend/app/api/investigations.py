import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Annotated

from app.ai import config as ai_config
from app.ai.evidence_bundle import build_evidence_bundle
from app.ai.factory import get_provider
from app.ai.prompts import PROMPT_VERSION, build_user_message, get_system_prompt
from app.ai.provider import AIProviderError, AIProviderTimeout, AIProviderUnavailable
from app.ai.schemas import AiSummaryResponse
from app.core.db import get_connection
from app.core.storage import save_upload
from app.detections.base import DetectionContext
from app.detections.registry import build_default_engine
from app.investigation.detections_repo import get_detections, save_detections
from app.investigation.dns_repo import get_dns_records, save_dns_records
from app.investigation.flows_repo import get_flows, save_flows
from app.investigation.hosts_repo import get_hosts, save_hosts
from app.investigation.http_repo import get_http_records, save_http_records
from app.investigation.investigations_repo import get_investigation, list_investigations
from app.investigation.iocs_repo import get_iocs, save_iocs
from app.investigation.timeline_builder import build_timeline
from app.investigation.timeline_repo import get_timeline_events, save_timeline_events
from app.investigation.tls_repo import get_tls_records, save_tls_records
from app.ioc.extractor import extract_iocs
from app.parsers.dns_extractor import extract_dns
from app.parsers.flow_aggregator import aggregate_flows
from app.parsers.host_aggregator import aggregate_hosts
from app.parsers.http_extractor import extract_http
from app.parsers.pcap_parser import parse_pcap
from app.parsers.tls_extractor import extract_tls
from app.schemas.detection import Detection
from app.schemas.dns_record import DnsRecord
from app.schemas.flow import Flow
from app.schemas.host import Host
from app.schemas.http_record import HttpRecord
from app.schemas.investigation import InvestigationResponse
from app.schemas.ioc import Ioc
from app.schemas.timeline_event import TimelineEvent
from app.schemas.tls_record import TlsRecord
from fastapi import APIRouter, File, HTTPException, UploadFile

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/investigations")
def list_investigation_records(limit: int = 100, offset: int = 0):
    bounded_limit = max(1, min(limit, 500))
    bounded_offset = max(0, offset)
    with get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM investigations").fetchone()[0]
        items = list_investigations(conn, bounded_limit, bounded_offset)
    return {
        "items": items,
        "total": total,
        "limit": bounded_limit,
        "offset": bounded_offset,
    }


@router.get("/investigations/{investigation_id}", response_model=InvestigationResponse)
def get_investigation_record(investigation_id: str):
    with get_connection() as conn:
        investigation = get_investigation(conn, investigation_id)
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return investigation


@router.post(
    "/investigations/{investigation_id}/ai-summary",
    response_model=AiSummaryResponse,
)
def create_ai_summary(investigation_id: str):
    with get_connection() as conn:
        investigation = get_investigation(conn, investigation_id)
        if investigation is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        try:
            bundle = build_evidence_bundle(conn, investigation_id)
        except ValueError:
            raise HTTPException(status_code=404, detail="Investigation not found")

    started_at = time.monotonic()
    try:
        provider = get_provider()
    except ValueError as exc:
        logger.info(
            "AI summary: investigation_id=%s provider=%s model=%s duration=%.3fs outcome=error",
            investigation_id,
            ai_config.AI_PROVIDER,
            ai_config.AI_MODEL,
            time.monotonic() - started_at,
        )
        raise HTTPException(
            status_code=500,
            detail=f"AI configuration error: {exc}",
        )
    if provider is None:
        logger.info(
            "AI summary: investigation_id=%s provider=%s model=%s duration=%.3fs outcome=error",
            investigation_id,
            ai_config.AI_PROVIDER,
            ai_config.AI_MODEL,
            time.monotonic() - started_at,
        )
        raise HTTPException(
            status_code=503,
            detail="AI features are disabled. Set TUCO_AI_ENABLED=true to enable.",
        )

    try:
        raw_output = provider.generate(
            build_user_message(bundle),
            system=get_system_prompt(),
        )
    except AIProviderUnavailable:
        logger.info(
            "AI summary: investigation_id=%s provider=%s model=%s duration=%.3fs outcome=unavailable",
            investigation_id,
            provider.name,
            provider.model,
            time.monotonic() - started_at,
        )
        raise HTTPException(
            status_code=503,
            detail=f"AI provider is unreachable. Is Ollama running at {ai_config.AI_BASE_URL}?",
        )
    except AIProviderTimeout:
        logger.info(
            "AI summary: investigation_id=%s provider=%s model=%s duration=%.3fs outcome=timeout",
            investigation_id,
            provider.name,
            provider.model,
            time.monotonic() - started_at,
        )
        raise HTTPException(
            status_code=504,
            detail="AI generation timed out. Consider increasing TUCO_AI_TIMEOUT.",
        )
    except AIProviderError as exc:
        logger.info(
            "AI summary: investigation_id=%s provider=%s model=%s duration=%.3fs outcome=error",
            investigation_id,
            provider.name,
            provider.model,
            time.monotonic() - started_at,
        )
        raise HTTPException(
            status_code=500,
            detail=f"AI provider returned an error: {str(exc)[:200]}",
        )
    except Exception:  # noqa: BLE001
        logger.info(
            "AI summary: investigation_id=%s provider=%s model=%s duration=%.3fs outcome=error",
            investigation_id,
            provider.name,
            provider.model,
            time.monotonic() - started_at,
        )
        raise HTTPException(status_code=500, detail="AI summary generation failed.")

    logger.info(
        "AI summary: investigation_id=%s provider=%s model=%s duration=%.3fs outcome=success",
        investigation_id,
        provider.name,
        provider.model,
        time.monotonic() - started_at,
    )
    return AiSummaryResponse(
        raw_output=raw_output,
        provider=provider.name,
        model=provider.model,
        prompt_version=PROMPT_VERSION,
        generated_at=datetime.now(UTC).isoformat(),
    )


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
        tls_records = extract_tls(final_path, file_format, inv_id)
        with get_connection() as conn:
            save_hosts(conn, inv_id, hosts)
            save_flows(conn, inv_id, flows)
            save_dns_records(conn, inv_id, dns_records)
            save_http_records(conn, inv_id, http_records)
            save_tls_records(conn, inv_id, tls_records)
            detection_context = DetectionContext(
                investigation_id=inv_id,
                hosts=get_hosts(conn, inv_id),
                flows=get_flows(conn, inv_id),
                dns_records=get_dns_records(conn, inv_id),
                http_records=get_http_records(conn, inv_id),
            )
            detections = build_default_engine().run(detection_context)
            save_detections(conn, inv_id, detections)
            iocs = extract_iocs(conn, inv_id)
            save_iocs(conn, inv_id, iocs)
            timeline_events = build_timeline(conn, inv_id)
            save_timeline_events(conn, inv_id, timeline_events)
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


@router.get("/investigations/{investigation_id}/tls", response_model=list[TlsRecord])
def get_investigation_tls(investigation_id: str):
    with get_connection() as conn:
        inv = conn.execute(
            "SELECT id FROM investigations WHERE id = ?",
            (investigation_id,),
        ).fetchone()
        if inv is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return get_tls_records(conn, investigation_id)


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


@router.get("/investigations/{investigation_id}/iocs", response_model=list[Ioc])
def get_investigation_iocs(investigation_id: str):
    with get_connection() as conn:
        inv = conn.execute(
            "SELECT id FROM investigations WHERE id = ?",
            (investigation_id,),
        ).fetchone()
        if inv is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return get_iocs(conn, investigation_id)


@router.get("/investigations/{investigation_id}/timeline", response_model=list[TimelineEvent])
def get_investigation_timeline(investigation_id: str):
    with get_connection() as conn:
        inv = conn.execute(
            "SELECT id FROM investigations WHERE id = ?",
            (investigation_id,),
        ).fetchone()
        if inv is None:
            raise HTTPException(status_code=404, detail="Investigation not found")
        return get_timeline_events(conn, investigation_id)
