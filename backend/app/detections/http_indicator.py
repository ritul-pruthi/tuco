import uuid
from collections import defaultdict
from datetime import UTC, datetime

from app.detections.base import BaseDetector, DetectionContext
from app.detections.config import (
    HTTP_HIGH_ERROR_RATE_COUNT,
    HTTP_HIGH_ERROR_RATE_WINDOW_SECONDS,
    HTTP_INDICATOR_CONFIDENCE,
    HTTP_INDICATOR_SEVERITY,
    HTTP_SUSPICIOUS_PATH_SUBSTRINGS,
    HTTP_SUSPICIOUS_UA_SUBSTRINGS,
)
from app.schemas.detection import Detection


class HTTPIndicatorDetector(BaseDetector):
    rule_id = "http_indicator_v1"
    title = "Suspicious HTTP indicators"
    limitations = (
        "These are indicators, not proof of compromise. Legitimate tools, security scanners, "
        "and monitoring software also produce similar patterns."
    )

    def detect(self, context: DetectionContext) -> list[Detection]:
        groups: dict[str, list[tuple[datetime, object]]] = defaultdict(list)
        for record in context.http_records:
            try:
                timestamp = datetime.fromisoformat(record.timestamp)
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=UTC)
                source_ip = record.source_ip
                if not isinstance(source_ip, str):
                    continue
                groups[source_ip].append((timestamp.astimezone(UTC), record))
            except (AttributeError, TypeError, ValueError):
                continue

        detections: list[Detection] = []
        for source_ip, observations in groups.items():
            ordered = sorted(observations, key=lambda item: item[0])
            detections.extend(self._suspicious_user_agent(context, source_ip, ordered))
            detections.extend(self._suspicious_path(context, source_ip, ordered))
            detections.extend(self._high_error_rate(context, source_ip, ordered))
        return detections

    def _suspicious_user_agent(
        self, context: DetectionContext, source_ip: str, observations: list[tuple[datetime, object]]
    ) -> list[Detection]:
        qualifying: list[tuple[datetime, object, str]] = []
        for timestamp, record in observations:
            user_agent = record.user_agent
            if not isinstance(user_agent, str):
                continue
            for pattern in HTTP_SUSPICIOUS_UA_SUBSTRINGS:
                if pattern.lower() in user_agent.lower():
                    qualifying.append((timestamp, record, pattern))
                    break
        if not qualifying:
            return []
        count = len(qualifying)
        pattern = qualifying[0][2]
        records = [(timestamp, record) for timestamp, record, _ in qualifying]
        return [
            self._make_detection(
                context,
                source_ip,
                "HTTP indicator — suspicious user agent",
                records,
                f"{count} requests with tool-like user agent",
                count,
                f"matched user agent pattern '{pattern}'",
                1,
                f"{source_ip} made {count} requests with a user agent matching '{pattern}'.",
            )
        ]

    def _suspicious_path(
        self, context: DetectionContext, source_ip: str, observations: list[tuple[datetime, object]]
    ) -> list[Detection]:
        qualifying: list[tuple[datetime, object]] = []
        for timestamp, record in observations:
            path = record.path
            if isinstance(path, str) and any(
                pattern.lower() in path.lower() for pattern in HTTP_SUSPICIOUS_PATH_SUBSTRINGS
            ):
                qualifying.append((timestamp, record))
        if not qualifying:
            return []
        count = len(qualifying)
        first_path = qualifying[0][1].path
        return [
            self._make_detection(
                context,
                source_ip,
                "HTTP indicator — suspicious path access",
                qualifying,
                f"{count} requests to suspicious paths",
                count,
                "matched a suspicious path pattern",
                1,
                f"{source_ip} made {count} requests to suspicious paths; the first example was '{first_path}'.",
            )
        ]

    def _high_error_rate(
        self, context: DetectionContext, source_ip: str, observations: list[tuple[datetime, object]]
    ) -> list[Detection]:
        errors = [
            (timestamp, record)
            for timestamp, record in observations
            if isinstance(record.status_code, int) and record.status_code >= 400
        ]
        best_window: list[tuple[datetime, object]] = []
        window_start = 0
        for window_end, observation in enumerate(errors):
            while (
                observation[0] - errors[window_start][0]
            ).total_seconds() > HTTP_HIGH_ERROR_RATE_WINDOW_SECONDS:
                window_start += 1
            candidate = errors[window_start : window_end + 1]
            if len(candidate) > len(best_window):
                best_window = candidate
        if len(best_window) < HTTP_HIGH_ERROR_RATE_COUNT:
            return []
        count = len(best_window)
        return [
            self._make_detection(
                context,
                source_ip,
                "HTTP indicator — high error rate",
                best_window,
                f"{count} error responses in {HTTP_HIGH_ERROR_RATE_WINDOW_SECONDS}s",
                count,
                f"{HTTP_HIGH_ERROR_RATE_COUNT}+ error responses in {HTTP_HIGH_ERROR_RATE_WINDOW_SECONDS}s",
                HTTP_HIGH_ERROR_RATE_COUNT,
                f"{source_ip} received {count} HTTP error responses within a "
                f"{HTTP_HIGH_ERROR_RATE_WINDOW_SECONDS}-second window.",
            )
        ]

    def _make_detection(
        self,
        context: DetectionContext,
        source_ip: str,
        title: str,
        observations: list[tuple[datetime, object]],
        observed_metric: str,
        observed_value: int,
        threshold_description: str,
        threshold_value: int,
        explanation: str,
    ) -> Detection:
        hosts = {
            record.host
            for _, record in observations
            if isinstance(record.host, str) and record.host
        }
        destination_ip = next(iter(hosts)) if len(hosts) == 1 else "multiple"
        return Detection(
            id=uuid.uuid4().hex,
            investigation_id=context.investigation_id,
            rule_id=self.rule_id,
            title=title,
            severity=HTTP_INDICATOR_SEVERITY,
            confidence=HTTP_INDICATOR_CONFIDENCE,
            source_ip=source_ip,
            source_port=None,
            destination_ip=destination_ip,
            destination_port=80,
            timeframe_start=observations[0][0].isoformat(),
            timeframe_end=observations[-1][0].isoformat(),
            observed_metric=observed_metric,
            observed_value=observed_value,
            threshold_description=threshold_description,
            threshold_value=threshold_value,
            explanation=explanation,
            evidence=[{"type": "http", "id": record.id} for _, record in observations[:20]],
            limitations=self.limitations,
            created_at=datetime.now(UTC).isoformat(),
        )
