import logging
import uuid
from collections import defaultdict
from datetime import UTC, datetime

from app.detections.base import BaseDetector, DetectionContext
from app.detections.config import (
    PORT_SCAN_CONFIDENCE,
    PORT_SCAN_MIN_DISTINCT_PORTS,
    PORT_SCAN_SEVERITY,
    PORT_SCAN_WINDOW_SECONDS,
)
from app.schemas.detection import Detection

logger = logging.getLogger(__name__)


class PortScanDetector(BaseDetector):
    rule_id = "port_scan_v1"
    title = "Possible port scan"

    def detect(self, context: DetectionContext) -> list[Detection]:
        relationships: dict[tuple[str, str], list[tuple[int, datetime, str]]] = defaultdict(list)
        for flow in context.flows:
            try:
                timestamp = datetime.fromisoformat(flow.first_seen)
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=UTC)
                timestamp = timestamp.astimezone(UTC)
                if flow.packets_sent > 0:
                    relationships[(flow.src_ip, flow.dst_ip)].append(
                        (flow.dst_port, timestamp, flow.id)
                    )
                if flow.packets_received > 0:
                    relationships[(flow.dst_ip, flow.src_ip)].append(
                        (flow.src_port, timestamp, flow.id)
                    )
            except (AttributeError, TypeError, ValueError):
                logger.warning("Skipping malformed flow during port scan detection")

        detections: list[Detection] = []
        for (source_ip, target_ip), observations in relationships.items():
            earliest_by_port: dict[int, tuple[datetime, str]] = {}
            for port, timestamp, flow_id in observations:
                if port not in earliest_by_port or timestamp < earliest_by_port[port][0]:
                    earliest_by_port[port] = (timestamp, flow_id)
            ordered = sorted(earliest_by_port.items(), key=lambda item: (item[1][0], item[0]))
            best_window: list[tuple[int, tuple[datetime, str]]] = []
            window_start = 0
            for window_end, observation in enumerate(ordered):
                current_time = observation[1][0]
                while (
                    current_time - ordered[window_start][1][0]
                ).total_seconds() > PORT_SCAN_WINDOW_SECONDS:
                    window_start += 1
                candidate = ordered[window_start : window_end + 1]
                if len(candidate) > len(best_window):
                    best_window = candidate

            if len(best_window) < PORT_SCAN_MIN_DISTINCT_PORTS:
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
                    severity=PORT_SCAN_SEVERITY,
                    confidence=PORT_SCAN_CONFIDENCE,
                    source_ip=source_ip,
                    source_port=None,
                    destination_ip=target_ip,
                    destination_port=None,
                    timeframe_start=window_start_time.isoformat(),
                    timeframe_end=window_end_time.isoformat(),
                    observed_metric=f"{count} distinct destination ports",
                    observed_value=count,
                    threshold_description=(
                        f"{PORT_SCAN_MIN_DISTINCT_PORTS}+ distinct ports in "
                        f"{PORT_SCAN_WINDOW_SECONDS} seconds"
                    ),
                    threshold_value=PORT_SCAN_MIN_DISTINCT_PORTS,
                    explanation=(
                        f"{source_ip} contacted {target_ip} on {count} distinct destination "
                        f"ports within {PORT_SCAN_WINDOW_SECONDS} seconds."
                    ),
                    evidence=[{"type": "flow", "id": item[1]} for item in window_observations],
                    limitations=(
                        "A high port count may also reflect legitimate scanning tools, "
                        "monitoring, or load-balancing clients."
                    ),
                    created_at=datetime.now(UTC).isoformat(),
                )
            )
        return detections
