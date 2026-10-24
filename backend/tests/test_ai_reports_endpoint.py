from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from app.core import config
from app.core.db import get_connection, init_db
from app.main import app
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "endpoint.db")
    init_db()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO investigations
            (id, filename, format, size_bytes, packet_count, started_at, ended_at,
             duration_seconds, status, created_at)
            VALUES ('inv-test', 'capture.pcap', 'pcap', 1, 0, NULL, NULL, NULL,
                    'aggregated', '2026-01-01T00:00:00Z')
            """
        )
        conn.commit()
    with TestClient(app) as test_client:
        yield test_client


def provider_mock() -> Mock:
    provider = Mock(name="provider")
    provider.name = "test-provider"
    provider.model = "test-model"
    provider.generate.return_value = (
        '{"summary":"Observed traffic.","key_findings":[],"mitre_context":[],'
        '"recommended_next_steps":[],"limitations":'
        '["Absence of detection is not evidence of absence of compromise."]}'
    )
    return provider


def test_existing_investigation_with_no_reports_returns_empty_list(client: TestClient):
    response = client.get("/api/investigations/inv-test/ai-reports")
    assert response.status_code == 200
    assert response.json() == []


def test_reports_endpoint_returns_three_newest_first(client: TestClient):
    provider = provider_mock()
    with patch("app.api.investigations.get_provider", return_value=provider):
        responses = [
            client.post("/api/investigations/inv-test/ai-summary") for _ in range(3)
        ]

    assert all(response.status_code == 200 for response in responses)
    history = client.get("/api/investigations/inv-test/ai-reports")
    assert history.status_code == 200
    records = history.json()
    assert len(records) == 3
    assert records[0]["id"] == responses[2].json()["report_id"]
    assert set(records[0]) == {
        "id",
        "investigation_id",
        "model",
        "prompt_version",
        "report",
        "markdown",
        "warnings",
        "created_at",
    }
    assert isinstance(records[0]["report"], dict)
    assert isinstance(records[0]["warnings"], list)


def test_unknown_investigation_returns_404(client: TestClient):
    response = client.get("/api/investigations/missing/ai-reports")
    assert response.status_code == 404
