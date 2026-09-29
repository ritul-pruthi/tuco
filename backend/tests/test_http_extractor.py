import io
import uuid
from pathlib import Path

import pytest
from app.core import config
from app.core.db import get_connection, init_db
from app.investigation.http_repo import get_http_records, save_http_records
from app.main import app
from app.parsers.http_extractor import extract_http
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


def http_request(
    method: str = "GET",
    path: str = "/index.html",
    source_port: int = 50000,
    destination_port: int = 80,
    host: str = "example.com",
    user_agent: str = "test-agent",
):
    return (
        Ether()
        / IP(src="10.0.0.1", dst="10.0.0.2")
        / TCP(sport=source_port, dport=destination_port, flags="PA")
        / Raw(
            load=(
                f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\n\r\n"
            ).encode()
        )
    )


def http_response(source_port: int = 80, destination_port: int = 50000, status: int = 200):
    return (
        Ether()
        / IP(src="10.0.0.2", dst="10.0.0.1")
        / TCP(sport=source_port, dport=destination_port, flags="PA")
        / Raw(load=f"HTTP/1.1 {status} OK\r\nContent-Length: 0\r\n\r\n".encode())
    )


def test_extract_http_get_request(tmp_path: Path):
    path = tmp_path / "get.pcap"
    packet = http_request()
    packet.time = 1700000000.0
    wrpcap(str(path), [packet])

    records = extract_http(path, "pcap", uuid.uuid4().hex)

    assert len(records) == 1
    assert records[0].method == "GET"
    assert records[0].host == "example.com"
    assert records[0].path == "/index.html"
    assert records[0].user_agent == "test-agent"
    assert records[0].status_code is None
    assert records[0].source_ip == "10.0.0.1"
    assert records[0].source_port == 50000
    assert records[0].destination_ip == "10.0.0.2"
    assert records[0].destination_port == 80
    assert records[0].timestamp == "2023-11-14T22:13:20+00:00"


def test_extract_http_request_and_response(tmp_path: Path):
    path = tmp_path / "response.pcap"
    request = http_request()
    request.time = 1700000000.0
    response = http_response()
    response.time = 1700000001.0
    wrpcap(str(path), [request, response])

    records = extract_http(path, "pcap", uuid.uuid4().hex)

    assert len(records) == 1
    assert records[0].status_code == 200


def test_extract_http_post_request(tmp_path: Path):
    path = tmp_path / "post.pcap"
    wrpcap(str(path), [http_request(method="POST", path="/submit")])

    records = extract_http(path, "pcap", uuid.uuid4().hex)

    assert len(records) == 1
    assert records[0].method == "POST"
    assert records[0].path == "/submit"


def test_extract_http_empty_pcap(tmp_path: Path):
    path = tmp_path / "empty.pcap"
    wrpcap(str(path), [])

    assert extract_http(path, "pcap", uuid.uuid4().hex) == []


def test_extract_http_no_http_packets(tmp_path: Path):
    path = tmp_path / "ssh.pcap"
    packet = (
        Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=22) / Raw(load=b"ssh")
    )
    wrpcap(str(path), [packet])

    assert extract_http(path, "pcap", uuid.uuid4().hex) == []


def test_extract_http_skips_https(tmp_path: Path):
    path = tmp_path / "https.pcap"
    wrpcap(str(path), [http_request(destination_port=443)])

    assert extract_http(path, "pcap", uuid.uuid4().hex) == []


def test_extract_http_malformed_pcap(tmp_path: Path):
    path = tmp_path / "malformed.pcap"
    path.write_bytes(b"not a pcap")

    with pytest.raises(ValueError, match="Failed to extract HTTP"):
        extract_http(path, "pcap", uuid.uuid4().hex)


def test_save_http_is_idempotent():
    investigation_id = uuid.uuid4().hex
    record = HttpRecord(
        id=uuid.uuid4().hex,
        investigation_id=investigation_id,
        timestamp="2023-11-14T22:13:20+00:00",
        source_ip="10.0.0.1",
        source_port=50000,
        destination_ip="10.0.0.2",
        destination_port=80,
        method="GET",
        host="example.com",
        path="/index.html",
        user_agent="test-agent",
        status_code=200,
    )

    with get_connection() as conn:
        conn.execute(
            "INSERT INTO investigations (id, filename, format, size_bytes, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (investigation_id, "test.pcap", "pcap", 0, "uploaded", record.timestamp),
        )
        save_http_records(conn, investigation_id, [record])
        first_count = conn.execute(
            "SELECT COUNT(*) FROM http_records WHERE investigation_id = ?", (investigation_id,)
        ).fetchone()[0]
        save_http_records(conn, investigation_id, [record])
        second_count = conn.execute(
            "SELECT COUNT(*) FROM http_records WHERE investigation_id = ?", (investigation_id,)
        ).fetchone()[0]
        loaded = get_http_records(conn, investigation_id)

    assert first_count == second_count == 1
    assert loaded[0].status_code == 200


def test_upload_returns_aggregated_with_http(client: TestClient, tmp_path: Path):
    path = tmp_path / "upload.pcap"
    wrpcap(str(path), [http_request(), http_response()])

    response = client.post(
        "/api/investigations",
        files={"file": ("http.pcap", io.BytesIO(path.read_bytes()), "application/octet-stream")},
    )

    assert response.status_code == 201
    investigation = response.json()
    assert investigation["status"] == "aggregated"
    http_response_data = client.get(f"/api/investigations/{investigation['id']}/http")
    assert http_response_data.status_code == 200
    assert http_response_data.json()[0]["status_code"] == 200


def test_http_endpoint_returns_empty_for_existing_investigation(client: TestClient):
    path = Path(config.TMP_DIR) / "empty.pcap"
    wrpcap(str(path), [])
    response = client.post(
        "/api/investigations",
        files={"file": ("empty.pcap", io.BytesIO(path.read_bytes()), "application/octet-stream")},
    )
    investigation_id = response.json()["id"]

    assert client.get(f"/api/investigations/{investigation_id}/http").json() == []


def test_http_endpoint_returns_404_for_missing_investigation(client: TestClient):
    response = client.get("/api/investigations/missing/http")

    assert response.status_code == 404
