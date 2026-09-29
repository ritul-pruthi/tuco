import ipaddress
import uuid
from collections import Counter, defaultdict
from datetime import UTC, datetime

from app.detections.base import BaseDetector, DetectionContext
from app.detections.config import (
    DNS_ANOMALY_CONFIDENCE,
    DNS_ANOMALY_SEVERITY,
    DNS_HIGH_FREQUENCY_COUNT,
    DNS_HIGH_FREQUENCY_WINDOW_SECONDS,
    DNS_LONG_QUERY_LENGTH,
    DNS_REPEATED_FAILURE_COUNT,
    DNS_SUBDOMAIN_VARIABILITY_THRESHOLD,
)
from app.schemas.detection import Detection


class DNSAnomalyDetector(BaseDetector):
    rule_id = "dns_anomaly_v1"
    title = "DNS anomaly indicators"
    limitations = (
        "These are indicators, not proof of tunneling or malware. Long names, frequent queries, "
        "and failures also occur in legitimate software."
    )

    def detect(self, context: DetectionContext) -> list[Detection]:
        groups: dict[str, list[tuple[datetime, object]]] = defaultdict(list)
        for record in context.dns_records:
            try:
                timestamp = datetime.fromisoformat(record.timestamp)
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=UTC)
                if not isinstance(record.query, str) or not isinstance(record.source_ip, str):
                    continue
                groups[record.source_ip].append((timestamp.astimezone(UTC), record))
            except (AttributeError, TypeError, ValueError):
                continue

        detections: list[Detection] = []
        for source_ip, observations in groups.items():
            ordered = sorted(observations, key=lambda item: item[0])
            detections.extend(self._long_query_detection(context, source_ip, ordered))
            detections.extend(self._frequency_detection(context, source_ip, ordered))
            detections.extend(self._variability_detection(context, source_ip, ordered))
            detections.extend(self._failure_detection(context, source_ip, ordered))
        return detections

    def _long_query_detection(
        self, context: DetectionContext, source_ip: str, observations: list[tuple[datetime, object]]
    ) -> list[Detection]:
        qualifying = [item for item in observations if len(item[1].query) > DNS_LONG_QUERY_LENGTH]
        if len(qualifying) < 5:
            return []
        count = len(qualifying)
        longest_query = max((item[1].query for item in qualifying), key=len)
        return [
            self._make_detection(
                context,
                source_ip,
                "DNS anomaly — long query names",
                qualifying,
                f"{count} long query names",
                count,
                f"5+ queries longer than {DNS_LONG_QUERY_LENGTH} characters",
                5,
                f"{source_ip} made {count} DNS queries longer than {DNS_LONG_QUERY_LENGTH} "
                f"characters; the longest query observed was {len(longest_query)} characters.",
            )
        ]

    def _frequency_detection(
        self, context: DetectionContext, source_ip: str, observations: list[tuple[datetime, object]]
    ) -> list[Detection]:
        best_window: list[tuple[datetime, object]] = []
        window_start = 0
        for window_end, observation in enumerate(observations):
            while (
                observation[0] - observations[window_start][0]
            ).total_seconds() > DNS_HIGH_FREQUENCY_WINDOW_SECONDS:
                window_start += 1
            candidate = observations[window_start : window_end + 1]
            if len(candidate) > len(best_window):
                best_window = candidate
        if len(best_window) < DNS_HIGH_FREQUENCY_COUNT:
            return []
        count = len(best_window)
        return [
            self._make_detection(
                context,
                source_ip,
                "DNS anomaly — high query frequency",
                best_window,
                f"{count} queries in {DNS_HIGH_FREQUENCY_WINDOW_SECONDS}s",
                count,
                f"{DNS_HIGH_FREQUENCY_COUNT}+ queries in {DNS_HIGH_FREQUENCY_WINDOW_SECONDS}s",
                DNS_HIGH_FREQUENCY_COUNT,
                f"{source_ip} made {count} DNS queries within a {DNS_HIGH_FREQUENCY_WINDOW_SECONDS}-second window.",
            )
        ]

    def _variability_detection(
        self, context: DetectionContext, source_ip: str, observations: list[tuple[datetime, object]]
    ) -> list[Detection]:
        subdomains: dict[str, dict[str, tuple[datetime, object]]] = defaultdict(dict)
        for timestamp, record in observations:
            labels = record.query.rstrip(".").split(".")
            try:
                ipaddress.ip_address(record.query.rstrip("."))
            except ValueError:
                if len(labels) >= 3:
                    parent = ".".join(labels[-2:])
                    subdomains[parent][record.query] = (timestamp, record)
        candidates = [
            (parent, records)
            for parent, records in subdomains.items()
            if len(records) >= DNS_SUBDOMAIN_VARIABILITY_THRESHOLD
        ]
        if not candidates:
            return []
        parent, records = max(candidates, key=lambda item: len(item[1]))
        qualifying = sorted(records.values(), key=lambda item: item[0])
        count = len(qualifying)
        return [
            self._make_detection(
                context,
                source_ip,
                "DNS anomaly — unusual subdomain variability",
                qualifying,
                f"{count} distinct subdomains under {parent}",
                count,
                f"{DNS_SUBDOMAIN_VARIABILITY_THRESHOLD}+ distinct subdomains under one parent domain",
                DNS_SUBDOMAIN_VARIABILITY_THRESHOLD,
                f"{source_ip} queried {count} distinct subdomains under {parent}.",
            )
        ]

    def _failure_detection(
        self, context: DetectionContext, source_ip: str, observations: list[tuple[datetime, object]]
    ) -> list[Detection]:
        qualifying = [item for item in observations if item[1].response_code != 0]
        if len(qualifying) < DNS_REPEATED_FAILURE_COUNT:
            return []
        count = len(qualifying)
        return [
            self._make_detection(
                context,
                source_ip,
                "DNS anomaly — repeated failures",
                qualifying,
                f"{count} failed DNS responses",
                count,
                f"{DNS_REPEATED_FAILURE_COUNT}+ failed DNS responses",
                DNS_REPEATED_FAILURE_COUNT,
                f"{source_ip} received {count} DNS responses with a non-zero response code.",
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
        destination_ip = Counter(record.destination_ip for _, record in observations).most_common(
            1
        )[0][0]
        evidence = [{"type": "dns", "id": record.id} for _, record in observations[:20]]
        return Detection(
            id=uuid.uuid4().hex,
            investigation_id=context.investigation_id,
            rule_id=self.rule_id,
            title=title,
            severity=DNS_ANOMALY_SEVERITY,
            confidence=DNS_ANOMALY_CONFIDENCE,
            source_ip=source_ip,
            source_port=None,
            destination_ip=destination_ip or "multiple",
            destination_port=53,
            timeframe_start=observations[0][0].isoformat(),
            timeframe_end=observations[-1][0].isoformat(),
            observed_metric=observed_metric,
            observed_value=observed_value,
            threshold_description=threshold_description,
            threshold_value=threshold_value,
            explanation=explanation,
            evidence=evidence,
            limitations=self.limitations,
            created_at=datetime.now(UTC).isoformat(),
        )
