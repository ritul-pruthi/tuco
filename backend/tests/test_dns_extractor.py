import io
import uuid
from pathlib import Path

import pytest
from app.core import config
from app.core.db import get_connection, init_db
from app.investigation.dns_repo import get_dns_records, save_dns_records
from app.main import app
from app.parsers.dns_extractor import extract_dns
from app.schemas.dns_record import DnsRecord
from fastapi.testclient import TestClient
from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, wrpcap


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


def dns_response(query: str, query_type: str, answer: str, source: str = "10.0.0.2"):
    return (
        Ether()
        / IP(src=source, dst="10.0.0.1")
        / UDP(sport=53, dport=53000)
        / DNS(
            id=42,
            qr=1,
            qd=DNSQR(qname=query, qtype=query_type),
            an=DNSRR(rrname=query, type=query_type, rdata=answer),
        )
    )


def test_extract_dns_basic(tmp_path: Path):
    path = tmp_path / "dns.pcap"
    packet = dns_response("example.com", "A", "93.184.216.34")
    packet.time = 1700000000.0
    wrpcap(str(path), [packet])

    records = extract_dns(path, "pcap", uuid.uuid4().hex)

    assert len(records) == 1
    assert records[0].query == "example.com"
    assert records[0].query_type == "A"
    assert records[0].response_code == 0
    assert records[0].answers == ["93.184.216.34"]
    assert records[0].source_ip == "10.0.0.2"
    assert records[0].destination_ip == "10.0.0.1"
    assert records[0].timestamp == "2023-11-14T22:13:20+00:00"


def test_extract_dns_multiple_types(tmp_path: Path):
    path = tmp_path / "dns_types.pcap"
    packets = [
        dns_response("a.example.com", "A", "192.0.2.1"),
        dns_response("a.example.com", "AAAA", "2001:db8::1"),
        dns_response("alias.example.com", "CNAME", "a.example.com"),
    ]
    wrpcap(str(path), packets)

    records = extract_dns(path, "pcap", uuid.uuid4().hex)

    assert [(record.query_type, record.answers) for record in records] == [
        ("A", ["192.0.2.1"]),
        ("AAAA", ["2001:db8::1"]),
        ("CNAME", ["a.example.com"]),
    ]


def test_extract_dns_multi_answer(tmp_path: Path):
    path = tmp_path / "multi_answer.pcap"
    packet = (
        Ether()
        / IP(src="10.0.0.2", dst="10.0.0.1")
        / UDP(sport=53, dport=53000)
        / DNS(
            id=42,
            qr=1,
            qd=DNSQR(qname="example.com", qtype="A"),
            an=[
                DNSRR(rrname="example.com", type="CNAME", rdata="alias.example.com"),
                DNSRR(rrname="alias.example.com", type="A", rdata="192.0.2.1"),
                DNSRR(rrname="alias.example.com", type="A", rdata="192.0.2.2"),
            ],
        )
    )
    wrpcap(str(path), [packet])

    records = extract_dns(path, "pcap", uuid.uuid4().hex)

    assert len(records) == 1
    assert records[0].answers == ["alias.example.com", "192.0.2.1", "192.0.2.2"]


def test_extract_dns_empty_pcap(tmp_path: Path):
    path = tmp_path / "empty.pcap"
    wrpcap(str(path), [])

    assert extract_dns(path, "pcap", uuid.uuid4().hex) == []


def test_extract_dns_no_dns_packets(tmp_path: Path):
    path = tmp_path / "tcp.pcap"
    packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80)
    wrpcap(str(path), [packet])

    assert extract_dns(path, "pcap", uuid.uuid4().hex) == []


def test_extract_dns_malformed_pcap(tmp_path: Path):
    path = tmp_path / "malformed.pcap"
    path.write_bytes(b"not a pcap")

    with pytest.raises(ValueError, match="Failed to extract DNS"):
        extract_dns(path, "pcap", uuid.uuid4().hex)


def test_save_dns_is_idempotent():
    investigation_id = uuid.uuid4().hex
    record = DnsRecord(
        id=uuid.uuid4().hex,
        investigation_id=investigation_id,
        timestamp="2023-11-14T22:13:20+00:00",
        source_ip="10.0.0.2",
        destination_ip="10.0.0.1",
        query="example.com",
        query_type="A",
        response_code=0,
        answers=["93.184.216.34"],
    )

    with get_connection() as conn:
        conn.execute(
            "INSERT INTO investigations (id, filename, format, size_bytes, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (investigation_id, "test.pcap", "pcap", 0, "uploaded", record.timestamp),
        )
        save_dns_records(conn, investigation_id, [record])
        first_count = conn.execute(
            "SELECT COUNT(*) FROM dns_records WHERE investigation_id = ?", (investigation_id,)
        ).fetchone()[0]
        save_dns_records(conn, investigation_id, [record])
        second_count = conn.execute(
            "SELECT COUNT(*) FROM dns_records WHERE investigation_id = ?", (investigation_id,)
        ).fetchone()[0]
        loaded = get_dns_records(conn, investigation_id)

    assert first_count == second_count == 1
    assert loaded[0].answers == ["93.184.216.34"]


def test_upload_returns_aggregated_with_dns(client: TestClient, tmp_path: Path):
    path = tmp_path / "upload.pcap"
    wrpcap(str(path), [dns_response("example.com", "A", "93.184.216.34")])

    response = client.post(
        "/api/investigations",
        files={"file": ("dns.pcap", io.BytesIO(path.read_bytes()), "application/octet-stream")},
    )

    assert response.status_code == 201
    investigation = response.json()
    assert investigation["status"] == "aggregated"

    dns_response_data = client.get(f"/api/investigations/{investigation['id']}/dns")
    assert dns_response_data.status_code == 200
    assert len(dns_response_data.json()) == 1
    assert dns_response_data.json()[0]["query"] == "example.com"


def test_dns_endpoint_returns_empty_for_existing_investigation(client: TestClient):
    response = client.post(
        "/api/investigations",
        files={
            "file": (
                "empty.pcap",
                io.BytesIO(
                    b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00"
                ),
                "application/octet-stream",
            )
        },
    )
    investigation_id = response.json()["id"]

    assert client.get(f"/api/investigations/{investigation_id}/dns").json() == []


def test_dns_endpoint_returns_404_for_missing_investigation(client: TestClient):
    response = client.get("/api/investigations/missing/dns")

    assert response.status_code == 404
