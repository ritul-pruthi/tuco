from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from app.core import config
from app.core.db import get_connection, init_db
from app.main import app
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


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def add_investigation(investigation_id: str, created_at: str) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO investigations (
                id, filename, format, size_bytes, packet_count,
                started_at, ended_at, duration_seconds, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                investigation_id,
                f"{investigation_id}.pcap",
                "pcap",
                10,
                0,
                None,
                None,
                None,
                "aggregated",
                created_at,
            ),
        )
        conn.commit()


def test_get_investigation_by_id(client: TestClient):
    created_at = datetime(2026, 1, 1, tzinfo=UTC).isoformat()
    add_investigation("investigation-1", created_at)

    response = client.get("/api/investigations/investigation-1")

    assert response.status_code == 200
    assert response.json() == {
        "id": "investigation-1",
        "filename": "investigation-1.pcap",
        "format": "pcap",
        "size_bytes": 10,
        "packet_count": 0,
        "started_at": None,
        "ended_at": None,
        "duration_seconds": None,
        "status": "aggregated",
        "created_at": created_at,
    }


def test_get_investigation_returns_404_for_missing(client: TestClient):
    response = client.get("/api/investigations/missing")

    assert response.status_code == 404
    assert response.json() == {"detail": "Investigation not found"}


def test_list_investigations_empty(client: TestClient):
    response = client.get("/api/investigations")

    assert response.status_code == 200
    assert response.json() == {"items": [], "total": 0, "limit": 100, "offset": 0}


def test_list_investigations_returns_all(client: TestClient):
    add_investigation("investigation-1", "2026-01-01T00:00:00+00:00")
    add_investigation("investigation-2", "2026-01-02T00:00:00+00:00")

    response = client.get("/api/investigations")

    assert response.status_code == 200
    assert response.json()["total"] == 2
    assert [item["id"] for item in response.json()["items"]] == [
        "investigation-2",
        "investigation-1",
    ]


def test_list_investigations_ordered_newest_first(client: TestClient):
    base_time = datetime(2026, 1, 1, tzinfo=UTC)
    add_investigation("old", base_time.isoformat())
    add_investigation("new", (base_time + timedelta(seconds=1)).isoformat())

    response = client.get("/api/investigations")

    assert [item["id"] for item in response.json()["items"]] == ["new", "old"]


def test_list_investigations_respects_limit(client: TestClient):
    for index in range(3):
        add_investigation(f"investigation-{index}", f"2026-01-0{index + 1}T00:00:00+00:00")

    response = client.get("/api/investigations?limit=2")

    assert response.json()["limit"] == 2
    assert len(response.json()["items"]) == 2


def test_list_investigations_respects_offset(client: TestClient):
    for index in range(3):
        add_investigation(f"investigation-{index}", f"2026-01-0{index + 1}T00:00:00+00:00")

    response = client.get("/api/investigations?offset=1")

    assert response.json()["offset"] == 1
    assert [item["id"] for item in response.json()["items"]] == [
        "investigation-1",
        "investigation-0",
    ]


def test_list_investigations_clamps_limit(client: TestClient):
    for index in range(2):
        add_investigation(f"investigation-{index}", f"2026-01-0{index + 1}T00:00:00+00:00")

    low_response = client.get("/api/investigations?limit=0")
    high_response = client.get("/api/investigations?limit=501")

    assert low_response.json()["limit"] == 1
    assert len(low_response.json()["items"]) == 1
    assert high_response.json()["limit"] == 500
    assert len(high_response.json()["items"]) == 2


def test_list_investigations_clamps_negative_offset(client: TestClient):
    add_investigation("investigation-1", "2026-01-01T00:00:00+00:00")

    response = client.get("/api/investigations?offset=-1")

    assert response.json()["offset"] == 0
    assert len(response.json()["items"]) == 1
