import logging
import math
import uuid
from collections import defaultdict
from datetime import UTC, datetime
from itertools import pairwise

from app.detections.base import BaseDetector, DetectionContext
from app.detections.config import (
    BEACON_CONFIDENCE,
    BEACON_MAX_INTERVAL_CV,
    BEACON_MIN_DURATION_SECONDS,
    BEACON_MIN_INTERVAL_SECONDS,
    BEACON_MIN_OBSERVATIONS,
    BEACON_SEVERITY,
)
from app.schemas.detection import Detection

logger = logging.getLogger(__name__)


class BeaconDetector(BaseDetector):
    rule_id = "beacon_v1"
    title = "Possible beacon-like periodic communication"

    def detect(self, context: DetectionContext) -> list[Detection]:
        groups: dict[tuple[str, str, int, str], list[tuple[datetime, str]]] = defaultdict(list)
        for flow in context.flows:
            try:
                timestamp = datetime.fromisoformat(flow.first_seen)
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=UTC)
                timestamp = timestamp.astimezone(UTC)
                group_key = (flow.src_ip, flow.dst_ip, flow.dst_port, flow.protocol)
                groups[group_key].append((timestamp, flow.id))
            except (AttributeError, TypeError, ValueError):
                logger.warning("Skipping malformed flow during beacon detection")

        detections: list[Detection] = []
        for (source_ip, destination_ip, destination_port, protocol), observations in groups.items():
            if len(observations) < BEACON_MIN_OBSERVATIONS:
                continue

            ordered = sorted(observations, key=lambda item: item[0])
            duration = (ordered[-1][0] - ordered[0][0]).total_seconds()
            if duration < BEACON_MIN_DURATION_SECONDS:
                continue

            raw_intervals = [
                (current[0] - previous[0]).total_seconds()
                for previous, current in pairwise(ordered)
            ]
            intervals = [
                interval for interval in raw_intervals if interval >= BEACON_MIN_INTERVAL_SECONDS
            ]
            if len(intervals) < BEACON_MIN_OBSERVATIONS - 1:
                continue

            mean_interval = sum(intervals) / len(intervals)
            if mean_interval == 0:
                continue
            variance = sum((interval - mean_interval) ** 2 for interval in intervals) / len(
                intervals
            )
            coefficient_of_variation = math.sqrt(variance) / mean_interval
            if coefficient_of_variation > BEACON_MAX_INTERVAL_CV:
                continue

            detections.append(
                Detection(
                    id=uuid.uuid4().hex,
                    investigation_id=context.investigation_id,
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=BEACON_SEVERITY,
                    confidence=BEACON_CONFIDENCE,
                    source_ip=source_ip,
                    source_port=None,
                    destination_ip=destination_ip,
                    destination_port=destination_port,
                    timeframe_start=ordered[0][0].isoformat(),
                    timeframe_end=ordered[-1][0].isoformat(),
                    observed_metric=(
                        f"{len(intervals)} intervals with {coefficient_of_variation:.2f} regularity"
                    ),
                    observed_value=len(intervals),
                    threshold_description=(
                        f"{BEACON_MIN_OBSERVATIONS}+ observations over "
                        f"{BEACON_MIN_DURATION_SECONDS}s with CV <= {BEACON_MAX_INTERVAL_CV}"
                    ),
                    threshold_value=BEACON_MIN_OBSERVATIONS,
                    explanation=(
                        f"{source_ip} contacted {destination_ip} with a mean interval of "
                        f"{mean_interval:.1f} seconds and a coefficient of variation of "
                        f"{coefficient_of_variation:.2f}."
                    ),
                    evidence=[{"type": "flow", "id": flow_id} for _, flow_id in ordered],
                    limitations=(
                        "Periodic traffic is common in legitimate software (NTP, software update "
                        "checks, heartbeats). Investigate the destination reputation and payload "
                        "context before concluding."
                    ),
                    created_at=datetime.now(UTC).isoformat(),
                )
            )
        return detections
