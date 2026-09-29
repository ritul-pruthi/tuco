import io
import uuid
from pathlib import Path

import pytest
from app.core import config
from app.core.db import get_connection, init_db
from app.investigation.tls_repo import get_tls_records, save_tls_records
from app.main import app
from app.parsers.tls_extractor import extract_tls
from app.schemas.tls_record import TlsRecord
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


def tls_client_hello(sni: str | None = "example.com") -> bytes:
    extensions = b""
    if sni is not None:
        hostname = sni.encode()
        server_name = b"\x00" + len(hostname).to_bytes(2, "big") + hostname
        server_names = len(server_name).to_bytes(2, "big") + server_name
        extensions += b"\x00\x00" + len(server_names).to_bytes(2, "big") + server_names
    hello = (
        b"\x03\x03"
        + b"\x00" * 32
        + b"\x00"
        + b"\x00\x02\x00\x2f"
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    return (
        b"\x16\x03\x03"
        + (len(hello) + 4).to_bytes(2, "big")
        + b"\x01"
        + len(hello).to_bytes(3, "big")
        + hello
    )


def tls_packet(payload: bytes, destination_port: int = 443):
    return (
        Ether()
        / IP(src="10.0.0.5", dst="10.0.0.6")
        / TCP(sport=54321, dport=destination_port)
        / Raw(load=payload)
    )


def test_extract_tls_client_hello_sni(tmp_path: Path):
    path = tmp_path / "client-hello.pcap"
    packet = tls_packet(tls_client_hello())
    packet.time = 1700000000.0
    wrpcap(str(path), [packet])

    records = extract_tls(path, "pcap", uuid.uuid4().hex)

    assert len(records) == 1
    assert records[0].sni == "example.com"
    assert records[0].tls_version == "TLS 1.2"


def test_extract_tls_no_sni(tmp_path: Path):
    path = tmp_path / "client-hello-no-sni.pcap"
    wrpcap(str(path), [tls_packet(tls_client_hello(None))])

    records = extract_tls(path, "pcap", uuid.uuid4().hex)

    assert len(records) == 1
    assert records[0].sni is None


def test_extract_tls_no_tls_traffic(tmp_path: Path):
    path = tmp_path / "http.pcap"
    packet = tls_packet(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", 80)
    wrpcap(str(path), [packet])

    assert extract_tls(path, "pcap", uuid.uuid4().hex) == []


def test_extract_tls_empty_pcap(tmp_path: Path):
    path = tmp_path / "empty.pcap"
    wrpcap(str(path), [])

    assert extract_tls(path, "pcap", uuid.uuid4().hex) == []


def test_extract_tls_skips_non_443(tmp_path: Path):
    path = tmp_path / "non-443.pcap"
    wrpcap(str(path), [tls_packet(tls_client_hello(), 8080)])

    assert extract_tls(path, "pcap", uuid.uuid4().hex) == []


def test_extract_tls_handles_malformed_packet(tmp_path: Path):
    path = tmp_path / "malformed-tls.pcap"
    wrpcap(str(path), [tls_packet(b"\x16\x03\x03\x00")])

    assert extract_tls(path, "pcap", uuid.uuid4().hex) == []


def test_save_tls_is_idempotent():
    investigation_id = uuid.uuid4().hex
    record = TlsRecord(
        id=uuid.uuid4().hex,
        investigation_id=investigation_id,
        timestamp="2023-11-14T22:13:20+00:00",
        source_ip="10.0.0.5",
        source_port=54321,
        destination_ip="10.0.0.6",
        destination_port=443,
        sni="example.com",
        tls_version="TLS 1.2",
        certificate_subject=None,
        certificate_issuer=None,
        certificate_not_before=None,
        certificate_not_after=None,
    )
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO investigations (id, filename, format, size_bytes, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (investigation_id, "test.pcap", "pcap", 0, "uploaded", record.timestamp),
        )
        save_tls_records(conn, investigation_id, [record])
        first_count = conn.execute(
            "SELECT COUNT(*) FROM tls_records WHERE investigation_id = ?", (investigation_id,)
        ).fetchone()[0]
        save_tls_records(conn, investigation_id, [record])
        second_count = conn.execute(
            "SELECT COUNT(*) FROM tls_records WHERE investigation_id = ?", (investigation_id,)
        ).fetchone()[0]
        loaded = get_tls_records(conn, investigation_id)

    assert first_count == second_count == 1
    assert loaded[0].sni == "example.com"


def test_tls_endpoint_returns_404_for_missing(client: TestClient):
    response = client.get("/api/investigations/nonexistent/tls")

    assert response.status_code == 404


def test_tls_endpoint_returns_empty_for_existing(client: TestClient, tmp_path: Path):
    path = tmp_path / "empty.pcap"
    wrpcap(str(path), [])
    response = client.post(
        "/api/investigations",
        files={"file": ("empty.pcap", io.BytesIO(path.read_bytes()), "application/octet-stream")},
    )

    investigation_id = response.json()["id"]
    assert client.get(f"/api/investigations/{investigation_id}/tls").json() == []


def test_upload_returns_aggregated_with_tls(client: TestClient):
    path = Path("data/samples/tls_client_hello.pcap")
    response = client.post(
        "/api/investigations",
        files={
            "file": (
                "tls_client_hello.pcap",
                io.BytesIO(path.read_bytes()),
                "application/octet-stream",
            )
        },
    )

    assert response.status_code == 201
    investigation = response.json()
    assert investigation["status"] == "aggregated"
    tls_response = client.get(f"/api/investigations/{investigation['id']}/tls")
    assert tls_response.status_code == 200
    assert len(tls_response.json()) == 1
    assert tls_response.json()[0]["sni"] == "example.com"
