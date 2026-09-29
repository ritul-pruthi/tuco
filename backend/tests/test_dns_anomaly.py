import io
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from app.core import config
from app.core.db import init_db
from app.detections.base import DetectionContext
from app.detections.dns_anomaly import DNSAnomalyDetector
from app.main import app
from app.schemas.dns_record import DnsRecord
from fastapi.testclient import TestClient
from scapy.all import DNS, DNSQR, Ether, IP, UDP, wrpcap


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
    query: str = "example.com",
    timestamp: datetime | None = None,
    response_code: int = 0,
    destination_ip: str = "10.0.0.1",
) -> DnsRecord:
    observed_at = timestamp or datetime(2024, 1, 1, tzinfo=UTC)
    return DnsRecord(
        id=f"dns-{index}",
        investigation_id="investigation-1",
        timestamp=observed_at.isoformat(),
        source_ip="10.0.0.5",
        destination_ip=destination_ip,
        query=query,
        query_type="A",
        response_code=response_code,
        answers=[],
    )


def detect(records: list[DnsRecord]):
    context = DetectionContext("investigation-1", [], [], records, [])
    return DNSAnomalyDetector().detect(context)


def test_dns_long_query_fires():
    records = [make_record(index, "x" * 53 + ".example.com") for index in range(5)]

    detections = detect(records)

    assert len(detections) == 1
    assert detections[0].title == "DNS anomaly — long query names"
    assert detections[0].observed_metric == "5 long query names"
    assert len(detections[0].evidence) == 5


def test_dns_long_query_does_not_fire_below_threshold():
    records = [make_record(index, "x" * 53 + ".example.com") for index in range(4)]

    assert detect(records) == []


def test_dns_high_frequency_fires():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    records = [
        make_record(index, timestamp=start + timedelta(seconds=index * 0.5)) for index in range(100)
    ]

    detections = detect(records)

    assert len(detections) == 1
    assert detections[0].title == "DNS anomaly — high query frequency"
    assert detections[0].observed_metric == "100 queries in 60s"


def test_dns_high_frequency_does_not_fire_outside_window():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    records = [
        make_record(index, timestamp=start + timedelta(seconds=index * 6.1)) for index in range(100)
    ]

    assert detect(records) == []


def test_dns_subdomain_variability_fires():
    records = [make_record(index, f"sub{index}.example.com") for index in range(20)]

    detections = detect(records)

    assert len(detections) == 1
    assert detections[0].title == "DNS anomaly — unusual subdomain variability"
    assert detections[0].observed_metric == "20 distinct subdomains under example.com"


def test_dns_repeated_failures_fires():
    records = [make_record(index, response_code=3) for index in range(10)]

    detections = detect(records)

    assert len(detections) == 1
    assert detections[0].title == "DNS anomaly — repeated failures"
    assert detections[0].observed_metric == "10 failed DNS responses"


def test_dns_no_false_positive_on_clean_traffic():
    records = [make_record(index, "www.example.com") for index in range(20)]

    assert detect(records) == []


def test_dns_multiple_anomalies_same_source():
    start = datetime(2024, 1, 1, tzinfo=UTC)
    records = [
        make_record(index, "x" * 53 + ".example.com", start + timedelta(seconds=index * 0.5))
        for index in range(100)
    ]

    detections = detect(records)

    assert len(detections) == 2
    assert {detection.title for detection in detections} == {
        "DNS anomaly — long query names",
        "DNS anomaly — high query frequency",
    }


def test_dns_handles_malformed_timestamp():
    records = [make_record(index) for index in range(10)]
    records[0] = records[0].model_copy(update={"timestamp": "not-a-timestamp"})

    detections = detect(records)

    assert detections == []


def test_upload_returns_aggregated_with_dns_anomaly(client: TestClient, tmp_path: Path):
    packets = []
    start = 1704067200.0
    for index in range(10):
        packet = (
            Ether()
            / IP(src="10.0.0.5", dst="10.0.0.1")
            / UDP(sport=53000 + index, dport=53)
            / DNS(
                id=index,
                qr=1,
                rcode=3,
                qd=DNSQR(qname="missing.example.com", qtype="A"),
            )
        )
        packet.time = start + index
        packets.append(packet)
    pcap_path = tmp_path / "dns-anomaly.pcap"
    wrpcap(str(pcap_path), packets)

    with pcap_path.open("rb") as capture:
        upload_response = client.post(
            "/api/investigations",
            files={
                "file": ("dns-anomaly.pcap", io.BytesIO(capture.read()), "application/octet-stream")
            },
        )

    assert upload_response.status_code == 201
    investigation = upload_response.json()
    assert investigation["status"] == "aggregated"
    detections_response = client.get(f"/api/investigations/{investigation['id']}/detections")

    assert detections_response.status_code == 200
    assert any(item["rule_id"] == "dns_anomaly_v1" for item in detections_response.json())
