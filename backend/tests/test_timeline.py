import io
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from app.core import config
from app.core.db import get_connection, init_db
from app.investigation.detections_repo import save_detections
from app.investigation.dns_repo import save_dns_records
from app.investigation.hosts_repo import save_hosts
from app.investigation.http_repo import save_http_records
from app.investigation.timeline_builder import build_timeline
from app.investigation.timeline_repo import get_timeline_events, save_timeline_events
from app.investigation.tls_repo import save_tls_records
from app.main import app
from app.schemas.detection import Detection
from app.schemas.dns_record import DnsRecord
from app.schemas.host import Host
from app.schemas.http_record import HttpRecord
from app.schemas.tls_record import TlsRecord
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    upload_dir = tmp_path / "uploads"
    tmp_dir = tmp_path / "tmp"
    upload_dir.mkdir()
    tmp_dir.mkdir()
    monkeypatch.setattr(config, "UPLOAD_DIR", upload_dir)
    monkeypatch.setattr(config, "TMP_DIR", tmp_dir)
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_tuco.db")
    init_db()


START = datetime(2024, 1, 1, tzinfo=UTC)


def add_investigation(investigation_id: str = "investigation-1") -> None:
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO investigations (id, filename, format, size_bytes, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (investigation_id, "sample.pcap", "pcap", 1, "aggregated", START.isoformat()),
        )


def timestamp(offset: int) -> str:
    return (START + timedelta(seconds=offset)).isoformat()


def make_host(host_id: str = "host-1", offset: int = 1, first_seen: str | None = None) -> Host:
    seen = first_seen or timestamp(offset)
    return Host(
        id=host_id,
        investigation_id="investigation-1",
        ip="10.0.0.5",
        scope="internal",
        packets_sent=1,
        packets_received=0,
        bytes_sent=1,
        bytes_received=0,
        unique_destinations=1,
        unique_ports=1,
        first_seen=seen,
        last_seen=seen,
    )


def make_dns(record_id: str = "dns-1", offset: int = 2) -> DnsRecord:
    return DnsRecord(
        id=record_id,
        investigation_id="investigation-1",
        timestamp=timestamp(offset),
        source_ip="10.0.0.5",
        destination_ip="8.8.8.8",
        query="example.com",
        query_type="A",
        response_code=0,
        answers=["93.184.216.34"],
    )


def make_http(record_id: str = "http-1", offset: int = 3) -> HttpRecord:
    return HttpRecord(
        id=record_id,
        investigation_id="investigation-1",
        timestamp=timestamp(offset),
        source_ip="10.0.0.5",
        source_port=50000,
        destination_ip="93.184.216.34",
        destination_port=80,
        method="GET",
        host="example.com",
        path="/index.html",
        user_agent="test",
        status_code=200,
    )


def make_tls(record_id: str = "tls-1", offset: int = 4) -> TlsRecord:
    return TlsRecord(
        id=record_id,
        investigation_id="investigation-1",
        timestamp=timestamp(offset),
        source_ip="10.0.0.5",
        source_port=50000,
        destination_ip="93.184.216.34",
        destination_port=443,
        sni="example.com",
        tls_version="TLS 1.3",
        certificate_subject=None,
        certificate_issuer=None,
        certificate_not_before=None,
        certificate_not_after=None,
    )


def make_detection(
    detection_id: str = "detection-1",
    rule_id: str = "port_scan_v1",
    offset: int = 5,
) -> Detection:
    return Detection(
        id=detection_id,
        investigation_id="investigation-1",
        rule_id=rule_id,
        title="Suspicious activity",
        severity="high",
        confidence="high",
        source_ip="10.0.0.5",
        source_port=None,
        destination_ip="8.8.8.8",
        destination_port=None,
        timeframe_start=timestamp(offset - 1),
        timeframe_end=timestamp(offset),
        observed_metric="count",
        observed_value=2,
        threshold_description="count > 1",
        threshold_value=1,
        explanation="Evidence-backed test detection",
        evidence=[],
        limitations="Test data",
        created_at=timestamp(offset),
    )


def save_evidence(*, hosts=None, dns=None, http=None, tls=None, detections=None) -> None:
    add_investigation()
    with get_connection() as conn:
        save_hosts(conn, "investigation-1", hosts or [])
        save_dns_records(conn, "investigation-1", dns or [])
        save_http_records(conn, "investigation-1", http or [])
        save_tls_records(conn, "investigation-1", tls or [])
        save_detections(conn, "investigation-1", detections or [])


def build_events(**evidence):
    save_evidence(**evidence)
    with get_connection() as conn:
        return build_timeline(conn, "investigation-1")


def test_build_timeline_includes_hosts():
    events = build_events(hosts=[make_host()])
    assert events[0].event_type == "host_first_seen"
    assert events[0].evidence_id == "host-1"
    assert events[0].summary == "Host 10.0.0.5 first seen (internal)"


def test_build_timeline_includes_dns():
    event = build_events(dns=[make_dns()])[0]
    assert event.event_type == "dns_query"
    assert event.destination == "8.8.8.8"
    assert event.evidence_type == "dns"


def test_build_timeline_includes_http():
    event = build_events(http=[make_http()])[0]
    assert event.event_type == "http_request"
    assert event.destination == "example.com"
    assert event.summary == "GET /index.html → 200"


def test_build_timeline_includes_tls():
    event = build_events(tls=[make_tls()])[0]
    assert event.event_type == "tls_handshake"
    assert event.destination == "example.com"
    assert event.summary == "TLS TLS 1.3 handshake to example.com"


def test_build_timeline_includes_detections():
    event = build_events(detections=[make_detection()])[0]
    assert event.event_type == "detection"
    assert event.summary == "[HIGH] Suspicious activity"


def test_build_timeline_large_transfer_derived_from_detection():
    events = build_events(detections=[make_detection(rule_id="large_outbound_transfer_v1")])
    assert {event.event_type for event in events} == {"detection", "large_transfer"}
    assert all(event.evidence_id == "detection-1" for event in events)


def test_build_timeline_sorted_chronologically():
    events = build_events(
        hosts=[make_host(offset=5)],
        dns=[make_dns(offset=1)],
        http=[make_http(offset=3)],
        tls=[make_tls(offset=4)],
        detections=[make_detection(offset=2)],
    )
    assert [event.event_type for event in events] == [
        "dns_query",
        "detection",
        "http_request",
        "tls_handshake",
        "host_first_seen",
    ]


def test_build_timeline_skips_malformed_timestamps():
    events = build_events(hosts=[make_host(first_seen="not-a-timestamp")], dns=[make_dns()])
    assert [event.event_type for event in events] == ["dns_query"]


def test_save_timeline_is_idempotent():
    events = build_events(hosts=[make_host()])
    with get_connection() as conn:
        save_timeline_events(conn, "investigation-1", events)
        save_timeline_events(conn, "investigation-1", events)
        saved = get_timeline_events(conn, "investigation-1")
    assert saved == events


def test_timeline_endpoint_returns_empty_for_existing():
    add_investigation()
    with TestClient(app) as client:
        response = client.get("/api/investigations/investigation-1/timeline")
    assert response.status_code == 200
    assert response.json() == []


def test_timeline_endpoint_returns_404_for_missing():
    with TestClient(app) as client:
        response = client.get("/api/investigations/missing/timeline")
    assert response.status_code == 404


def test_upload_returns_aggregated_with_timeline():
    with TestClient(app) as client, Path("data/samples/http.pcap").open("rb") as capture:
        upload_response = client.post(
            "/api/investigations",
            files={"file": ("http.pcap", io.BytesIO(capture.read()), "application/octet-stream")},
        )
        assert upload_response.status_code == 201
        investigation = upload_response.json()
        assert investigation["status"] == "aggregated"
        timeline_response = client.get(f"/api/investigations/{investigation['id']}/timeline")
    assert timeline_response.status_code == 200
    assert len(timeline_response.json()) >= 1
