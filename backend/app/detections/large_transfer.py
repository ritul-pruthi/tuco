import uuid
from datetime import UTC, datetime

from app.core.scope import classify_scope
from app.detections.base import BaseDetector, DetectionContext
from app.detections.config import (
    LARGE_OUTBOUND_CONFIDENCE,
    LARGE_OUTBOUND_INTERNAL_TO_EXTERNAL_ONLY,
    LARGE_OUTBOUND_MIN_BYTES,
    LARGE_OUTBOUND_SEVERITY,
)
from app.schemas.detection import Detection


class LargeOutboundTransferDetector(BaseDetector):
    rule_id = "large_outbound_transfer_v1"
    title = "Large outbound transfer"
    limitations = (
        "Large transfers to external hosts have many legitimate causes (backups, uploads, "
        "streaming, software updates). Investigate the destination, protocol, and payload "
        "context before concluding."
    )

    def detect(self, context: DetectionContext) -> list[Detection]:
        detections: list[Detection] = []
        for flow in context.flows:
            try:
                first_seen = datetime.fromisoformat(flow.first_seen)
                last_seen = datetime.fromisoformat(flow.last_seen)
                if first_seen.tzinfo is None:
                    first_seen = first_seen.replace(tzinfo=UTC)
                if last_seen.tzinfo is None:
                    last_seen = last_seen.replace(tzinfo=UTC)

                packets_sent = flow.packets_sent
                packets_received = flow.packets_received
                if not isinstance(packets_sent, int) or not isinstance(packets_received, int):
                    continue

                if packets_sent > 0:
                    sender = flow.src_ip
                    receiver = flow.dst_ip
                    bytes_out = flow.bytes_sent
                    sport = flow.src_port
                    dport = flow.dst_port
                elif packets_received > 0:
                    sender = flow.dst_ip
                    receiver = flow.src_ip
                    bytes_out = flow.bytes_received
                    sport = flow.dst_port
                    dport = flow.src_port
                else:
                    continue

                if not isinstance(bytes_out, int) or bytes_out < LARGE_OUTBOUND_MIN_BYTES:
                    continue
                if not isinstance(sender, str) or not isinstance(receiver, str):
                    continue
                if LARGE_OUTBOUND_INTERNAL_TO_EXTERNAL_ONLY and (
                    classify_scope(sender) != "internal" or classify_scope(receiver) != "external"
                ):
                    continue
                if not isinstance(sport, int) or not isinstance(dport, int):
                    continue
                protocol = flow.protocol
                if not isinstance(protocol, str):
                    continue
            except (AttributeError, TypeError, ValueError):
                continue

            detections.append(
                Detection(
                    id=uuid.uuid4().hex,
                    investigation_id=context.investigation_id,
                    rule_id=self.rule_id,
                    title=self.title,
                    severity=LARGE_OUTBOUND_SEVERITY,
                    confidence=LARGE_OUTBOUND_CONFIDENCE,
                    source_ip=sender,
                    source_port=sport,
                    destination_ip=receiver,
                    destination_port=dport,
                    timeframe_start=first_seen.isoformat(),
                    timeframe_end=last_seen.isoformat(),
                    observed_metric=(
                        f"{bytes_out / (1024 * 1024):.1f} MB from {sender} to {receiver}"
                    ),
                    observed_value=bytes_out,
                    threshold_description=(
                        f"{LARGE_OUTBOUND_MIN_BYTES / (1024 * 1024):.0f} MB single-flow outbound"
                    ),
                    threshold_value=LARGE_OUTBOUND_MIN_BYTES,
                    explanation=(
                        f"{sender} sent {bytes_out / (1024 * 1024):.1f} MB to {receiver} "
                        f"over {protocol} port {dport}."
                    ),
                    evidence=[{"type": "flow", "id": flow.id}],
                    limitations=self.limitations,
                    created_at=datetime.now(UTC).isoformat(),
                )
            )

        return sorted(detections, key=lambda detection: detection.observed_value, reverse=True)
