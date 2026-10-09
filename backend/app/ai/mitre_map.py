from collections.abc import Iterable

RULE_TO_TECHNIQUES: dict[str, list[dict[str, str]]] = {
    "port_scan_v1": [{"id": "T1046", "name": "Network Service Discovery"}],
    "internal_recon_v1": [{"id": "T1018", "name": "Remote System Discovery"}],
    "beacon_v1": [{"id": "T1071", "name": "Application Layer Protocol"}],
    "dns_anomaly_v1": [{"id": "T1071.004", "name": "DNS"}],
    "http_indicator_v1": [{"id": "T1595", "name": "Active Scanning"}],
    "large_outbound_transfer_v1": [
        {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"}
    ],
}


def techniques_for_rule(rule_id: str) -> list[dict[str, str]]:
    return [dict(technique) for technique in RULE_TO_TECHNIQUES.get(rule_id, [])]


def aggregate_techniques(rule_ids: Iterable[str]) -> list[dict[str, object]]:
    aggregated: dict[str, dict[str, object]] = {}
    for rule_id in sorted(set(rule_ids)):
        for technique in techniques_for_rule(rule_id):
            technique_id = technique["id"]
            if technique_id not in aggregated:
                aggregated[technique_id] = {
                    "id": technique_id,
                    "name": technique["name"],
                    "rule_ids": [],
                }
            aggregated[technique_id]["rule_ids"].append(rule_id)

    return [
        {
            "id": item["id"],
            "name": item["name"],
            "rule_ids": sorted(item["rule_ids"]),
        }
        for item in sorted(aggregated.values(), key=lambda item: item["id"])
    ]
