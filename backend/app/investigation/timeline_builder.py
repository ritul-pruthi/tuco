import sqlite3
from datetime import UTC, datetime

from app.investigation.detections_repo import get_detections
from app.investigation.dns_repo import get_dns_records
from app.investigation.flows_repo import get_flows
from app.investigation.hosts_repo import get_hosts
from app.investigation.http_repo import get_http_records
from app.investigation.tls_repo import get_tls_records
from app.schemas.timeline_event import TimelineEvent


def build_timeline(conn: sqlite3.Connection, investigation_id: str) -> list[TimelineEvent]:
    events: list[tuple[datetime, TimelineEvent]] = []

    for host in _load(get_hosts, conn, investigation_id):
        if not host.ip:
            continue
        _add_event(
            events,
            investigation_id,
            host.first_seen,
            "host_first_seen",
            host.ip,
            "",
            f"Host {host.ip} first seen ({host.scope})",
            "host",
            host.id,
        )

    # Flows are loaded as part of the complete evidence set; the timeline has no flow event type.
    _load(get_flows, conn, investigation_id)

    for record in _load(get_dns_records, conn, investigation_id):
        if not record.source_ip or not record.destination_ip:
            continue
        _add_event(
            events,
            investigation_id,
            record.timestamp,
            "dns_query",
            record.source_ip,
            record.destination_ip,
            f"DNS query {record.query} ({record.query_type}) → {len(record.answers)} answers",
            "dns",
            record.id,
        )

    for record in _load(get_http_records, conn, investigation_id):
        destination = record.host or record.destination_ip
        if not record.source_ip or not destination:
            continue
        _add_event(
            events,
            investigation_id,
            record.timestamp,
            "http_request",
            record.source_ip,
            destination,
            f"{record.method} {record.path} → {record.status_code}",
            "http",
            record.id,
        )

    for record in _load(get_tls_records, conn, investigation_id):
        destination = record.sni or record.destination_ip
        if not record.source_ip or not destination:
            continue
        _add_event(
            events,
            investigation_id,
            record.timestamp,
            "tls_handshake",
            record.source_ip,
            destination,
            f"TLS {record.tls_version or 'unknown'} handshake to {destination}",
            "tls",
            record.id,
        )

    for detection in _load(get_detections, conn, investigation_id):
        if not detection.source_ip or not detection.destination_ip:
            continue
        _add_event(
            events,
            investigation_id,
            detection.timeframe_end,
            "detection",
            detection.source_ip,
            detection.destination_ip,
            f"[{detection.severity.upper()}] {detection.title}",
            "detection",
            detection.id,
        )
        if detection.rule_id == "large_outbound_transfer_v1":
            _add_event(
                events,
                investigation_id,
                detection.timeframe_end,
                "large_transfer",
                detection.source_ip,
                detection.destination_ip,
                f"[{detection.severity.upper()}] {detection.title}",
                "detection",
                detection.id,
            )

    return [event for _timestamp, event in sorted(events, key=lambda item: (item[0], item[1].id))]


def _add_event(
    events: list[tuple[datetime, TimelineEvent]],
    investigation_id: str,
    timestamp: str,
    event_type: str,
    source: str,
    destination: str,
    summary: str,
    evidence_type: str,
    evidence_id: str,
) -> None:
    try:
        parsed_timestamp = datetime.fromisoformat(timestamp)
    except (TypeError, ValueError):
        return
    if parsed_timestamp.tzinfo is None:
        parsed_timestamp = parsed_timestamp.replace(tzinfo=UTC)
    else:
        parsed_timestamp = parsed_timestamp.astimezone(UTC)
    events.append(
        (
            parsed_timestamp,
            TimelineEvent(
                id=f"{event_type}:{evidence_id}",
                investigation_id=investigation_id,
                timestamp=timestamp,
                event_type=event_type,
                source=source,
                destination=destination,
                summary=summary,
                evidence_type=evidence_type,
                evidence_id=evidence_id,
            ),
        )
    )


def _load(loader, conn: sqlite3.Connection, investigation_id: str):
    try:
        return loader(conn, investigation_id)
    except (TypeError, ValueError, KeyError, sqlite3.Error):
        return []
