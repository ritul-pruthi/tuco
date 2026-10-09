from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from app.ai.provider import AIProviderError, AIProviderTimeout, AIProviderUnavailable
from app.core import config
from app.core.db import get_connection, init_db
from app.main import app
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config, "DB_PATH", tmp_path / "test_tuco.db")
    init_db()
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO investigations
            (id, filename, format, size_bytes, packet_count, started_at, ended_at,
             duration_seconds, status, created_at)
            VALUES ('inv-test', 'capture.pcap', 'pcap', 1234, 10,
                    '2026-01-01T00:00:00Z', '2026-01-01T00:01:00Z',
                    60.0, 'aggregated', '2026-01-01T00:02:00Z')
            """
        )
        conn.executemany(
            """
            INSERT INTO hosts
            (id, investigation_id, ip, mac, scope, packets_sent, packets_received,
             bytes_sent, bytes_received, unique_destinations, unique_ports,
             first_seen, last_seen)
            VALUES (?, 'inv-test', ?, NULL, ?, 1, 2, 100, 200, 3, 4,
                    '2026-01-01T00:00:01Z', '2026-01-01T00:00:59Z')
            """,
            [
                ("host-1", "10.0.0.1", "internal"),
                ("host-2", "8.8.8.8", "external"),
            ],
        )
        conn.execute(
            """
            INSERT INTO detections
            (id, investigation_id, rule_id, title, severity, confidence, source_ip,
             source_port, destination_ip, destination_port, timeframe_start,
             timeframe_end, observed_metric, observed_value, threshold_description,
             threshold_value, explanation, evidence, limitations, created_at)
            VALUES ('det-1', 'inv-test', 'port_scan_v1', 'Port scan', 'medium',
                    'high', '10.0.0.1', NULL, '8.8.8.8', NULL,
                    '2026-01-01T00:00:01Z', '2026-01-01T00:00:05Z', 'ports', 5,
                    'more than 3', 3, 'Observed multiple ports', '[{"id":"flow-1"}]',
                    'Does not prove compromise', '2026-01-01T00:00:05Z')
            """
        )
        conn.commit()

    with TestClient(app) as test_client:
        yield test_client


def provider_mock() -> Mock:
    provider = Mock()
    provider.name = "ollama"
    provider.model = "qwen3.5:4b"
    provider.generate.return_value = "## Summary\nObserved network activity."
    return provider


def test_ai_summary_returns_report_and_calls_provider(client: TestClient):
    provider = provider_mock()
    with patch("app.api.investigations.get_provider", return_value=provider):
        response = client.post("/api/investigations/inv-test/ai-summary")

    assert response.status_code == 200
    body = response.json()
    assert body["raw_output"].startswith("## Summary")
    assert body["provider"] == "ollama"
    assert body["model"] == "qwen3.5:4b"
    assert body["prompt_version"] == "v1"
    assert body["generated_at"]
    assert body["warnings"] == []
    provider.generate.assert_called_once()
    args, kwargs = provider.generate.call_args
    assert "<EVIDENCE>" in args[0]
    assert kwargs["system"]
    assert "timeout" not in kwargs


def test_ai_summary_missing_investigation_returns_404(client: TestClient):
    response = client.post("/api/investigations/missing/ai-summary")
    assert response.status_code == 404
    assert response.json()["detail"] == "Investigation not found"


def test_ai_summary_disabled_returns_503(client: TestClient):
    with patch("app.api.investigations.get_provider", return_value=None):
        response = client.post("/api/investigations/inv-test/ai-summary")
    assert response.status_code == 503
    assert response.json()["detail"] == (
        "AI features are disabled. Set TUCO_AI_ENABLED=true to enable."
    )


@pytest.mark.parametrize(
    ("error", "status_code", "detail"),
    [
        (
            AIProviderUnavailable("unreachable"),
            503,
            "AI provider is unreachable. Is Ollama running at http://localhost:11434?",
        ),
        (
            AIProviderTimeout("timed out"),
            504,
            "AI generation timed out. Consider increasing TUCO_AI_TIMEOUT.",
        ),
        (
            AIProviderError("bad response"),
            500,
            "AI provider returned an error: bad response",
        ),
        (RuntimeError("unexpected"), 500, "AI summary generation failed."),
    ],
)
def test_ai_summary_maps_provider_errors(
    client: TestClient,
    error: Exception,
    status_code: int,
    detail: str,
):
    provider = provider_mock()
    provider.generate.side_effect = error
    with patch("app.api.investigations.get_provider", return_value=provider):
        response = client.post("/api/investigations/inv-test/ai-summary")
    assert response.status_code == status_code
    assert response.json()["detail"] == detail


def test_ollama_request_disables_thinking():
    from app.ai.ollama_provider import OllamaProvider

    response = Mock(status_code=200)
    response.json.return_value = {"response": "report"}
    with patch("app.ai.ollama_provider.httpx.post", return_value=response) as post:
        OllamaProvider("test-model").generate("prompt")
    assert post.call_args.kwargs["json"]["think"] is False
