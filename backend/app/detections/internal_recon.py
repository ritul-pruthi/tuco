import logging
import uuid
from collections import defaultdict
from datetime import UTC, datetime

from app.core.scope import classify_scope
from app.detections.base import BaseDetector, DetectionContext
from app.detections.config import (
    INTERNAL_RECON_CONFIDENCE,
    INTERNAL_RECON_MIN_DISTINCT_TARGETS,
    INTERNAL_RECON_SEVERITY,
    INTERNAL_RECON_WINDOW_SECONDS,
)
from app.schemas.detection import Detection

logger = logging.getLogger(__name__)


class InternalReconDetector(BaseDetector):
    rule_id = "internal_recon_v1"
    title = "Possible internal reconnaissance"

    def detect(self, context: DetectionContext) -> list[Detection]:
        relationships: dict[str, list[tuple[str, datetime, str]]] = defaultdict(list)
        for flow in context.flows:
            try:
                timestamp = datetime.fromisoformat(flow.first_seen)
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=UTC)
                timestamp = timestamp.astimezone(UTC)
                if flow.packets_sent > 0:
                    self._add_observation(
                        relationships, flow.src_ip, flow.dst_ip, timestamp, flow.id
                    )
                if flow.packets_received > 0:
                    self._add_observation(
                        relationships, flow.dst_ip, flow.src_ip, timestamp, flow.id
                    )
            except (AttributeError, TypeError, ValueError):
                logger.warning("Skipping malformed flow during internal recon detection")

        detections: list[Detection] = []
        for scanner_ip, observations in relationships.items():
            if classify_scope(scanner_ip) != "internal":
                continue

            earliest_by_target: dict[str, tuple[datetime, str]] = {}
            for target_ip, timestamp, flow_id in observations:
                if classify_scope(target_ip) != "internal":
                    continue
                if (
                    target_ip not in earliest_by_target
                    or timestamp < earliest_by_target[target_ip][0]
                ):
                    earliest_by_target[target_ip] = (timestamp, flow_id)

            ordered = sorted(earliest_by_target.items(), key=lambda item: (item[1][0], item[0]))
            best_window: list[tuple[str, tuple[datetime, str]]] = []
            window_start = 0
            for window_end, observation in enumerate(ordered):
                current_time = observation[1][0]
                while (
                    current_time - ordered[window_start][1][0]
                ).total_seconds() > INTERNAL_RECON_WINDOW_SECONDS:
                    window_start += 1
                candidate = ordered[window_start : window_end + 1]
                if len(candidate) > len(best_window):
                    best_window = candidate

            if len(best_window) < INTERNAL_RECON_MIN_DISTINCT_TARGETS:
                continue
            window_observations = [item[1] for item in best_window]
            window_start_time = min(item[0] for item in window_observations)
            window_end_time = max(item[0] for item in window_observations)
            count = len(best_window)
            detections.append(
                Detection(
                    id=uuid.uuid4().hex,
                    investigation_id=context.investigation_id,
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=INTERNAL_RECON_SEVERITY,
                    confidence=INTERNAL_RECON_CONFIDENCE,
                    source_ip=scanner_ip,
                    source_port=None,
                    destination_ip="multiple",
                    destination_port=None,
                    timeframe_start=window_start_time.isoformat(),
                    timeframe_end=window_end_time.isoformat(),
                    observed_metric=f"{count} distinct internal targets",
                    observed_value=count,
                    threshold_description=(
                        f"{INTERNAL_RECON_MIN_DISTINCT_TARGETS}+ distinct internal targets in "
                        f"{INTERNAL_RECON_WINDOW_SECONDS}s"
                    ),
                    threshold_value=INTERNAL_RECON_MIN_DISTINCT_TARGETS,
                    explanation=(
                        f"{scanner_ip} contacted {count} distinct internal targets within "
                        f"{INTERNAL_RECON_WINDOW_SECONDS} seconds."
                    ),
                    evidence=[{"type": "flow", "id": item[1]} for item in window_observations],
                    limitations=(
                        "Internal scanning may reflect legitimate inventory tools, vulnerability "
                        "scanners, or misconfigured software."
                    ),
                    created_at=datetime.now(UTC).isoformat(),
                )
            )
        return detections

    @staticmethod
    def _add_observation(
        relationships: dict[str, list[tuple[str, datetime, str]]],
        scanner_ip: str,
        target_ip: str,
        timestamp: datetime,
        flow_id: str,
    ) -> None:
        relationships[scanner_ip].append((target_ip, timestamp, flow_id))
