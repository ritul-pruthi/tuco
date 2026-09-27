import io
from pathlib import Path

import pytest
from app.core import config
from app.core.db import get_connection, init_db
from app.main import app
from fastapi.testclient import TestClient

VALID_PCAP_BYTES = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00"
VALID_PCAP_BE_BYTES = b"\xa1\xb2\xc3\xd4\x00\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x01\x00\x00"
VALID_PCAPNG_BYTES = (
    b"\n\r\r\n\x1c\x00\x00\x00M<+\x1a\x01\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff"
    b"\x1c\x00\x00\x00\x01\x00\x00\x00\x14\x00\x00\x00\x01\x00\x00\x00\x00\x00\x04\x00\x14\x00\x00\x00"
)


@pytest.fixture(autouse=True)
def setup_test_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    test_upload_dir = tmp_path / "uploads"
    test_tmp_dir = tmp_path / "tmp"
    test_db_path = tmp_path / "test_tuco.db"

    test_upload_dir.mkdir(parents=True, exist_ok=True)
    test_tmp_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(config, "UPLOAD_DIR", test_upload_dir)
    monkeypatch.setattr(config, "TMP_DIR", test_tmp_dir)
    monkeypatch.setattr(config, "DB_PATH", test_db_path)

    init_db()

    yield

    # DB and directory cleanups are automatically handled by tmp_path


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_upload_rejects_wrong_extension(client: TestClient):
    file_content = b"This is plain text"
    response = client.post(
        "/api/investigations",
        files={"file": ("test.txt", io.BytesIO(file_content), "text/plain")},
    )
    assert response.status_code == 400
    data = response.json()
    assert "Invalid file extension" in data["detail"]


def test_upload_rejects_bad_magic_bytes(client: TestClient):
    file_content = b"NOT_A_VALID_PCAP_HEADER_DATA"
    response = client.post(
        "/api/investigations",
        files={"file": ("bad.pcap", io.BytesIO(file_content), "application/octet-stream")},
    )
    assert response.status_code == 400
    data = response.json()
    assert "magic bytes" in data["detail"].lower()


def test_upload_accepts_valid_pcap(client: TestClient):
    response = client.post(
        "/api/investigations",
        files={"file": ("sample.pcap", io.BytesIO(VALID_PCAP_BYTES), "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert data["filename"] == "sample.pcap"
    assert data["format"] == "pcap"
    assert data["size_bytes"] == len(VALID_PCAP_BYTES)
    assert data["status"] == "parsed"
    assert data["packet_count"] == 0
    assert data["started_at"] is None
    assert data["ended_at"] is None
    assert data["duration_seconds"] is None
    assert "created_at" in data

    # Verify persisted in database
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM investigations WHERE id = ?", (data["id"],)).fetchone()
        assert row is not None
        assert row["filename"] == "sample.pcap"
        assert row["format"] == "pcap"
        assert row["status"] == "parsed"
        assert row["packet_count"] == 0
        assert row["size_bytes"] == len(VALID_PCAP_BYTES)


def test_upload_accepts_valid_pcapng(client: TestClient):
    response = client.post(
        "/api/investigations",
        files={"file": ("sample.pcapng", io.BytesIO(VALID_PCAPNG_BYTES), "application/octet-stream")},
    )
    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert data["filename"] == "sample.pcapng"
    assert data["format"] == "pcapng"
    assert data["size_bytes"] == len(VALID_PCAPNG_BYTES)
    assert data["status"] == "parsed"
    assert data["packet_count"] == 0


def test_upload_rejects_oversized_file(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "MAX_UPLOAD_BYTES", 10)
    response = client.post(
        "/api/investigations",
        files={"file": ("big.pcap", io.BytesIO(VALID_PCAP_BYTES), "application/octet-stream")},
    )
    assert response.status_code == 413
    assert "exceeds maximum" in response.json()["detail"].lower()

    # Ensure no leftover temp files
    assert list(config.TMP_DIR.iterdir()) == []
