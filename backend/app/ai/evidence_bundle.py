import json
import sqlite3
from collections import Counter
from typing import Any

from app.ai.mitre_map import aggregate_techniques, techniques_for_rule
from app.investigation.detections_repo import get_detections
from app.investigation.dns_repo import get_dns_records
from app.investigation.flows_repo import get_flows
from app.investigation.hosts_repo import get_hosts
from app.investigation.http_repo import get_http_records
from app.investigation.investigations_repo import get_investigation
from app.investigation.iocs_repo import get_iocs
from app.investigation.timeline_repo import get_timeline_events
from app.investigation.tls_repo import get_tls_records

MAX_HOSTS = 50
MAX_FLOWS = 50
MAX_DNS_QUERIES = 50
MAX_HTTP_HOSTS = 20
MAX_TLS_SNIS = 20
MAX_TIMELINE_EVENTS = 60
MAX_OBSERVABLES = 200
MAX_BUNDLE_BYTES = 100_000


def build_evidence_bundle(conn: sqlite3.Connection, investigation_id: str) -> dict[str, Any]:
    investigation = get_investigation(conn, investigation_id)
    if investigation is None:
        raise ValueError(f"Investigation not found: {investigation_id}")

    hosts = get_hosts(conn, investigation_id)
    flows = get_flows(conn, investigation_id)
    dns_records = get_dns_records(conn, investigation_id)
    http_records = get_http_records(conn, investigation_id)
    tls_records = get_tls_records(conn, investigation_id)
    detections = get_detections(conn, investigation_id)
    observables = get_iocs(conn, investigation_id)
    timeline_events = get_timeline_events(conn, investigation_id)

    return _build_with_limits(
        investigation,
        hosts,
        flows,
        dns_records,
        http_records,
        tls_records,
        detections,
        observables,
        timeline_events,
        MAX_HOSTS,
        MAX_FLOWS,
        MAX_DNS_QUERIES,
        MAX_HTTP_HOSTS,
        MAX_TLS_SNIS,
        MAX_TIMELINE_EVENTS,
    )


def _build_with_limits(
    investigation: Any,
    hosts: list[Any],
    flows: list[Any],
    dns_records: list[Any],
    http_records: list[Any],
    tls_records: list[Any],
    detections: list[Any],
    observables: list[Any],
    timeline_events: list[Any],
    max_hosts: int,
    max_flows: int,
    max_dns_queries: int,
    max_http_hosts: int,
    max_tls_snis: int,
    max_timeline_events: int,
) -> dict[str, Any]:
    bundle = _assemble_bundle(
        investigation,
        hosts,
        flows,
        dns_records,
        http_records,
        tls_records,
        detections,
        observables,
        timeline_events,
        max_hosts,
        max_flows,
        max_dns_queries,
        max_http_hosts,
        max_tls_snis,
        max_timeline_events,
    )
    while len(json.dumps(bundle, separators=(",", ":")).encode("utf-8")) > MAX_BUNDLE_BYTES:
        if max_timeline_events > 1:
            max_timeline_events = max(1, max_timeline_events // 2)
        elif max_flows > 1:
            max_flows = max(1, max_flows // 2)
        elif max_hosts > 1:
            max_hosts = max(1, max_hosts // 2)
        elif max_dns_queries > 1 or max_http_hosts > 1 or max_tls_snis > 1:
            max_dns_queries = max(1, max_dns_queries // 2)
            max_http_hosts = max(1, max_http_hosts // 2)
            max_tls_snis = max(1, max_tls_snis // 2)
        else:
            break
        bundle = _assemble_bundle(
            investigation,
            hosts,
            flows,
            dns_records,
            http_records,
            tls_records,
            detections,
            observables,
            timeline_events,
            max_hosts,
            max_flows,
            max_dns_queries,
            max_http_hosts,
            max_tls_snis,
            max_timeline_events,
        )
    return bundle


def _assemble_bundle(
    investigation: Any,
    hosts: list[Any],
    flows: list[Any],
    dns_records: list[Any],
    http_records: list[Any],
    tls_records: list[Any],
    detections: list[Any],
    observables: list[Any],
    timeline_events: list[Any],
    max_hosts: int,
    max_flows: int,
    max_dns_queries: int,
    max_http_hosts: int,
    max_tls_snis: int,
    max_timeline_events: int,
) -> dict[str, Any]:
    selected_hosts = sorted(
        hosts,
        key=lambda host: (-(host.bytes_sent + host.bytes_received), host.ip),
    )[:max_hosts]
    selected_flows = sorted(
        flows,
        key=lambda flow: (
            -(flow.bytes_sent + flow.bytes_received),
            flow.src_ip,
            flow.src_port,
            flow.dst_ip,
            flow.dst_port,
        ),
    )[:max_flows]
    detection_bundle = [_detection_entry(detection) for detection in detections]
    rule_ids = [detection.rule_id for detection in detections]
    dns_summary = _dns_summary(dns_records, max_dns_queries)
    http_summary = _http_summary(http_records, max_http_hosts)
    tls_summary = _tls_summary(tls_records, max_tls_snis)

    return {
        "investigation": {
            "id": investigation.id,
            "filename": investigation.filename,
            "format": investigation.format,
            "size_bytes": investigation.size_bytes,
            "packet_count": investigation.packet_count,
            "started_at": investigation.started_at,
            "ended_at": investigation.ended_at,
            "duration_seconds": investigation.duration_seconds,
        },
        "summary": {
            "host_count": len(hosts),
            "internal_host_count": sum(host.scope == "internal" for host in hosts),
            "external_host_count": sum(host.scope == "external" for host in hosts),
            "flow_count": len(flows),
            "dns_record_count": len(dns_records),
            "http_record_count": len(http_records),
            "tls_record_count": len(tls_records),
            "detection_count": len(detections),
            "observable_count": len(observables),
        },
        "hosts": [_host_entry(host) for host in selected_hosts],
        "flows": [_flow_entry(flow) for flow in selected_flows],
        "detections": detection_bundle,
        "mitre_techniques": aggregate_techniques(rule_ids),
        "dns": dns_summary,
        "http": http_summary,
        "tls": tls_summary,
        "observables": [
            _observable_entry(observable) for observable in observables[:MAX_OBSERVABLES]
        ],
        "timeline_highlights": _timeline_highlights(
            timeline_events, hosts, detections, max_timeline_events
        ),
        "limits": {
            "hosts_truncated": len(hosts) > max_hosts,
            "flows_truncated": len(flows) > max_flows,
            "dns_truncated": dns_summary["truncated"],
            "http_truncated": http_summary["truncated"],
            "tls_truncated": tls_summary["truncated"],
            "timeline_truncated": _timeline_was_truncated(
                timeline_events, hosts, detections, max_timeline_events
            ),
        },
    }


def _host_entry(host: Any) -> dict[str, Any]:
    return {
        "ip": host.ip,
        "scope": host.scope,
        "packets_sent": host.packets_sent,
        "packets_received": host.packets_received,
        "bytes_sent": host.bytes_sent,
        "bytes_received": host.bytes_received,
        "unique_destinations": host.unique_destinations,
        "unique_ports": host.unique_ports,
        "first_seen": host.first_seen,
        "last_seen": host.last_seen,
    }


def _flow_entry(flow: Any) -> dict[str, Any]:
    return {
        "src_ip": flow.src_ip,
        "src_port": flow.src_port,
        "dst_ip": flow.dst_ip,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
        "packets_sent": flow.packets_sent,
        "packets_received": flow.packets_received,
        "bytes_sent": flow.bytes_sent,
        "bytes_received": flow.bytes_received,
        "tcp_state": flow.tcp_state,
        "first_seen": flow.first_seen,
        "last_seen": flow.last_seen,
    }


def _detection_entry(detection: Any) -> dict[str, Any]:
    entry = detection.model_dump()
    entry.pop("id")
    entry.pop("evidence")
    entry["evidence_count"] = len(detection.evidence)
    entry["mitre_techniques"] = techniques_for_rule(detection.rule_id)
    return entry


def _dns_summary(records: list[Any], limit: int) -> dict[str, Any]:
    grouped: dict[str, dict[str, Any]] = {}
    for record in records:
        item = grouped.setdefault(record.query, {"query_type": record.query_type, "count": 0})
        item["count"] += 1
        item["query_type"] = min(item["query_type"], record.query_type)
    top_queries = [
        {"query": query, "query_type": item["query_type"], "count": item["count"]}
        for query, item in sorted(grouped.items(), key=lambda pair: (-pair[1]["count"], pair[0]))[
            :limit
        ]
    ]
    return {
        "record_count": len(records),
        "unique_query_count": len(grouped),
        "top_queries": top_queries,
        "failed_query_count": sum(record.response_code != 0 for record in records),
        "truncated": len(grouped) > limit,
    }


def _http_summary(records: list[Any], host_limit: int) -> dict[str, Any]:
    method_counts = Counter(record.method for record in records)
    host_counts = Counter(record.host for record in records if record.host is not None)
    user_agent_counts = Counter(
        record.user_agent for record in records if record.user_agent is not None
    )
    status_class_counts = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
    for record in records:
        if record.status_code is not None:
            status_class = f"{record.status_code // 100}xx"
            if status_class in status_class_counts:
                status_class_counts[status_class] += 1
    return {
        "record_count": len(records),
        "method_counts": {method: method_counts[method] for method in sorted(method_counts)},
        "status_class_counts": status_class_counts,
        "top_hosts": [
            {"host": host, "count": count}
            for host, count in sorted(host_counts.items(), key=lambda item: (-item[1], item[0]))[
                :host_limit
            ]
        ],
        "top_user_agents": [
            {"user_agent": user_agent, "count": count}
            for user_agent, count in sorted(
                user_agent_counts.items(), key=lambda item: (-item[1], item[0])
            )[:10]
        ],
        "truncated": len(host_counts) > host_limit,
    }


def _tls_summary(records: list[Any], sni_limit: int) -> dict[str, Any]:
    version_counts = Counter(record.tls_version for record in records if record.tls_version)
    sni_counts = Counter(record.sni for record in records if record.sni is not None)
    return {
        "record_count": len(records),
        "tls_version_counts": {
            version: version_counts[version] for version in sorted(version_counts)
        },
        "top_snis": [
            {"sni": sni, "count": count}
            for sni, count in sorted(sni_counts.items(), key=lambda item: (-item[1], item[0]))[
                :sni_limit
            ]
        ],
        "truncated": len(sni_counts) > sni_limit,
    }


def _observable_entry(observable: Any) -> dict[str, Any]:
    return {
        "ioc_type": observable.ioc_type,
        "value": observable.value,
        "scope": observable.scope,
        "occurrences": observable.occurrences,
        "first_seen": observable.first_seen,
        "last_seen": observable.last_seen,
    }


def _timeline_highlights(
    events: list[Any], hosts: list[Any], detections: list[Any], limit: int
) -> list[dict[str, str]]:
    detection_ids = {detection.id for detection in detections}

    def entry_for(event: Any) -> dict[str, str]:
        if isinstance(event, dict):
            return event
        return {
            "timestamp": event.timestamp,
            "event_type": event.event_type,
            "summary": event.summary,
        }

    def unique_sorted(entries: list[dict[str, str]]) -> list[dict[str, str]]:
        unique: dict[tuple[str, str, str], dict[str, str]] = {}
        for entry in entries:
            key = (entry["timestamp"], entry["event_type"], entry["summary"])
            unique.setdefault(key, entry)
        return sorted(
            unique.values(),
            key=lambda entry: (entry["timestamp"], entry["event_type"], entry["summary"]),
        )

    detection_entries = unique_sorted(
        [
            entry_for(event)
            for event in events
            if event.event_type == "detection" or event.evidence_id in detection_ids
        ]
    )
    host_entries = unique_sorted(
        [
            {
                "timestamp": host.first_seen,
                "event_type": "host_first_seen",
                "summary": f"Host observed: {host.ip}",
            }
            for host in hosts
        ]
    )
    endpoint_entries = (
        unique_sorted([entry_for(events[0]), entry_for(events[-1])]) if events else []
    )
    remaining_entries = unique_sorted([entry_for(event) for event in events])

    selected: list[dict[str, str]] = []
    selected_keys: set[tuple[str, str, str]] = set()

    def add_entries(entries: list[dict[str, str]]) -> None:
        for entry in entries:
            if len(selected) >= limit:
                return
            key = (entry["timestamp"], entry["event_type"], entry["summary"])
            if key not in selected_keys:
                selected_keys.add(key)
                selected.append(entry)

    add_entries(detection_entries)
    if len(selected) >= limit:
        return sorted(
            selected,
            key=lambda entry: (entry["timestamp"], entry["event_type"], entry["summary"]),
        )
    add_entries(host_entries)
    add_entries(endpoint_entries)
    add_entries(
        [
            entry
            for entry in remaining_entries
            if (entry["timestamp"], entry["event_type"], entry["summary"])
            not in selected_keys
        ]
    )
    return sorted(
        selected,
        key=lambda entry: (entry["timestamp"], entry["event_type"], entry["summary"]),
    )


def _timeline_was_truncated(
    events: list[Any], hosts: list[Any], detections: list[Any], limit: int
) -> bool:
    candidate_keys = {
        (event.timestamp, event.event_type, event.summary) for event in events
    }
    candidate_keys.update(
        (host.first_seen, "host_first_seen", f"Host observed: {host.ip}") for host in hosts
    )
    return len(candidate_keys) > limit
