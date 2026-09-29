import io
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from app.core import config
from app.core.db import init_db
from app.detections.base import DetectionContext
from app.detections.http_indicator import HTTPIndicatorDetector
from app.main import app
from app.schemas.http_record import HttpRecord
from fastapi.testclient import TestClient
from scapy.all import IP, TCP, Ether, Raw, wrpcap


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


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def make_record(
    index: int,
    *,
    timestamp: datetime | None = None,
    user_agent: str | None = "Firefox/128.0",
    path: str | None = "/index.html",
    status_code: int | None = 200,
    host: str | None = "example.com",
) -> HttpRecord:
    observed_at = timestamp or datetime(2024, 1, 1, tzinfo=UTC)
    return HttpRecord(
        id=f"http-{index}",
        investigation_id="investigation-1",
        timestamp=observed_at.isoformat(),
        source_ip="10.0.0.5",
        source_port=50000 + index,
        destination_ip="10.0.0.1",
        destination_port=80,
        method="GET",
        host=host,
        path=path,
        user_agent=user_agent,
        status_code=status_code,
    )


def detect(records: list[HttpRecord]):
    context = DetectionContext("investigation-1", [], [], [], records)
    return HTTPIndicatorDetector().detect(context)


def test_suspicious_user_agent_fires():
    detections = detect([make_record(0, user_agent="sqlmap/1.7")])

    assert len(detections) == 1
    assert detections[0].title == "HTTP indicator — suspicious user agent"
    assert detections[0].observed_value == 1
    assert "sqlmap" in detections[0].explanation


def test_suspicious_user_agent_case_insensitive():
    assert len(detect([make_record(0, user_agent="SQLMap")])) == 1


def test_suspicious_user_agent_does_not_fire_on_normal():
    assert detect([make_record(0)]) == []


def test_suspicious_path_fires():
    detections = detect([make_record(0, path="/.env")])

    assert len(detections) == 1
    assert detections[0].title == "HTTP indicator — suspicious path access"
    assert detections[0].observed_metric == "1 requests to suspicious paths"


def test_suspicious_path_does_not_fire_on_normal():
    assert detect([make_record(0, path="/index.html")]) == []


def test_high_error_rate_fires():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    records = [
        make_record(index, timestamp=start + timedelta(seconds=index * 3), status_code=404)
        for index in range(21)
    ]

    detections = detect(records)

    assert len(detections) == 1
    assert detections[0].title == "HTTP indicator — high error rate"
    assert detections[0].observed_value == 21


def test_high_error_rate_does_not_fire_outside_window():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    records = [
        make_record(index, timestamp=start + timedelta(seconds=index * 30), status_code=404)
        for index in range(21)
    ]

    assert detect(records) == []


def test_multiple_indicators_same_source():
    detections = detect([make_record(0, user_agent="sqlmap", path="/.env")])

    assert len(detections) == 2
    assert {detection.title for detection in detections} == {
        "HTTP indicator — suspicious user agent",
        "HTTP indicator — suspicious path access",
    }


def test_handles_missing_user_agent():
    assert len(detect([make_record(0, user_agent=None)])) == 0


def test_handles_malformed_timestamp():
    record = make_record(0, user_agent="sqlmap")
    record = record.model_copy(update={"timestamp": "not-a-timestamp"})

    assert detect([record]) == []


def test_upload_returns_aggregated_with_http_indicator(client: TestClient, tmp_path: Path):
    packet = (
        Ether()
        / IP(src="10.0.0.5", dst="10.0.0.1")
        / TCP(sport=50000, dport=80, flags="PA")
        / Raw(load=b"GET /.env HTTP/1.1\r\nHost: example.com\r\nUser-Agent: sqlmap/1.7\r\n\r\n")
    )
    pcap_path = tmp_path / "http-indicator.pcap"
    wrpcap(str(pcap_path), [packet])

    with pcap_path.open("rb") as capture:
        upload_response = client.post(
            "/api/investigations",
            files={
                "file": (
                    "http-indicator.pcap",
                    io.BytesIO(capture.read()),
                    "application/octet-stream",
                )
            },
        )

    assert upload_response.status_code == 201
    investigation = upload_response.json()
    assert investigation["status"] == "aggregated"
    detections_response = client.get(f"/api/investigations/{investigation['id']}/detections")

    assert detections_response.status_code == 200
    assert any(item["rule_id"] == "http_indicator_v1" for item in detections_response.json())
