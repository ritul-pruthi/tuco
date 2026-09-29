import ipaddress
import sqlite3
import uuid
from datetime import UTC, datetime

from app.core.scope import classify_scope
from app.investigation.dns_repo import get_dns_records
from app.investigation.flows_repo import get_flows
from app.investigation.hosts_repo import get_hosts
from app.investigation.http_repo import get_http_records
from app.schemas.ioc import Ioc


def extract_iocs(conn: sqlite3.Connection, investigation_id: str) -> list[Ioc]:
    accumulators: dict[tuple[str, str], dict] = {}

    for host in get_hosts(conn, investigation_id):
        try:
            timestamp = _timestamp_range(host.first_seen, host.last_seen)
            ioc_type = _ip_type(host.ip)
            if ioc_type is None:
                continue
            _add_ioc(
                accumulators,
                investigation_id,
                ioc_type,
                host.ip,
                timestamp,
                classify_scope(host.ip),
                "host",
                host.id,
            )
        except (AttributeError, TypeError, ValueError):
            continue

    for flow in get_flows(conn, investigation_id):
        try:
            timestamp = _timestamp_range(flow.first_seen, flow.last_seen)
            for value in (flow.src_ip, flow.dst_ip):
                ioc_type = _ip_type(value)
                if ioc_type is None:
                    continue
                _add_ioc(
                    accumulators,
                    investigation_id,
                    ioc_type,
                    value,
                    timestamp,
                    classify_scope(value),
                    "flow",
                    flow.id,
                )
        except (AttributeError, TypeError, ValueError):
            continue

    for record in get_dns_records(conn, investigation_id):
        try:
            timestamp = _timestamp_range(record.timestamp, record.timestamp)
            domain = _domain_value(record.query)
            if domain is not None:
                _add_ioc(
                    accumulators,
                    investigation_id,
                    "domain",
                    domain,
                    timestamp,
                    "n/a",
                    "dns",
                    record.id,
                )
        except (AttributeError, TypeError, ValueError):
            continue

    for record in get_http_records(conn, investigation_id):
        try:
            timestamp = _timestamp_range(record.timestamp, record.timestamp)
            host = record.host.strip().lower() if isinstance(record.host, str) else None
            if host:
                domain = _domain_value(host)
                if domain is not None:
                    _add_ioc(
                        accumulators,
                        investigation_id,
                        "domain",
                        domain,
                        timestamp,
                        "n/a",
                        "http",
                        record.id,
                    )

                scheme = "https" if record.destination_port == 443 else "http"
                path = record.path if isinstance(record.path, str) and record.path else "/"
                if not path.startswith("/"):
                    path = f"/{path}"
                url = f"{scheme}://{host}{path}"[:256]
                _add_ioc(
                    accumulators,
                    investigation_id,
                    "url",
                    url,
                    timestamp,
                    "n/a",
                    "http",
                    record.id,
                )

            if isinstance(record.user_agent, str) and record.user_agent:
                _add_ioc(
                    accumulators,
                    investigation_id,
                    "user_agent",
                    record.user_agent,
                    timestamp,
                    "n/a",
                    "http",
                    record.id,
                )
        except (AttributeError, TypeError, ValueError):
            continue

    iocs = [
        Ioc(
            id=uuid.uuid4().hex,
            investigation_id=investigation_id,
            ioc_type=data["ioc_type"],
            value=data["value"],
            first_seen=data["first_seen"].isoformat(),
            last_seen=data["last_seen"].isoformat(),
            occurrences=data["occurrences"],
            scope=data["scope"],
            evidence_type=data["evidence_type"],
            evidence_ids=data["evidence_ids"],
        )
        for data in accumulators.values()
    ]
    return sorted(iocs, key=lambda ioc: (ioc.ioc_type, -ioc.occurrences, ioc.value))


def _timestamp_range(first_seen: str, last_seen: str) -> tuple[datetime, datetime]:
    first = _parse_timestamp(first_seen)
    last = _parse_timestamp(last_seen)
    return first, last


def _parse_timestamp(value: str) -> datetime:
    timestamp = datetime.fromisoformat(value)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return timestamp.astimezone(UTC)


def _ip_type(value: str) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return "ipv4" if address.version == 4 else "ipv6"


def _domain_value(value: str) -> str | None:
    if not isinstance(value, str):
        return None
    domain = value.strip().rstrip(".").lower()
    if not domain:
        return None
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    return None


def _add_ioc(
    accumulators: dict[tuple[str, str], dict],
    investigation_id: str,
    ioc_type: str,
    value: str,
    timestamp: tuple[datetime, datetime],
    scope: str,
    evidence_type: str,
    evidence_id: str,
) -> None:
    key = (ioc_type, value)
    first_seen, last_seen = timestamp
    data = accumulators.setdefault(
        key,
        {
            "investigation_id": investigation_id,
            "ioc_type": ioc_type,
            "value": value,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "occurrences": 0,
            "scope": scope,
            "evidence_type": evidence_type,
            "evidence_ids": [],
        },
    )
    data["occurrences"] += 1
    data["first_seen"] = min(data["first_seen"], first_seen)
    data["last_seen"] = max(data["last_seen"], last_seen)
    if evidence_id not in data["evidence_ids"] and len(data["evidence_ids"]) < 20:
        data["evidence_ids"].append(evidence_id)
