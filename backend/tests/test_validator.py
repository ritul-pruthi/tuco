from copy import deepcopy

import pytest
from app.ai.validator import extract_bundle_numbers, validate_report

BUNDLE = {
    "investigation": {"id": "d4537c305f59433c8fd5d828e2b9a900"},
    "summary": {"host_count": 3, "detection_count": 1},
    "hosts": [
        {"ip": "10.0.0.10", "scope": "internal"},
        {"ip": "10.0.0.50", "scope": "internal"},
        {"ip": "8.8.8.8", "scope": "external"},
    ],
    "flows": [
        {"src_ip": "10.0.0.10", "dst_ip": "10.0.0.50", "dst_port": 43},
        {"src_ip": "10.0.0.10", "dst_ip": "10.0.0.50", "dst_port": 44},
        {"src_ip": "10.0.0.10", "dst_ip": "8.8.8.8", "dst_port": 53},
    ],
    "detections": [
        {
            "rule_id": "port_scan_v1",
            "severity": "medium",
            "confidence": "medium",
            "source_ip": "10.0.0.10",
            "destination_ip": "10.0.0.50",
            "observed_metric": "25 distinct destination ports",
            "observed_value": 25.0,
            "threshold_description": "20+ distinct ports in 10 seconds",
            "threshold_value": 20.0,
            "explanation": "10.0.0.10 contacted 10.0.0.50 on 25 distinct destination ports within 10 seconds.",
            "evidence_count": 25,
        }
    ],
    "mitre_techniques": [
        {
            "id": "T1046",
            "name": "Network Service Discovery",
            "rule_ids": ["port_scan_v1"],
        }
    ],
    "dns": {"record_count": 0},
    "http": {"record_count": 0},
    "tls": {"record_count": 0},
    "observables": [
        {"ioc_type": "ipv4", "value": "10.0.0.10"},
        {"ioc_type": "ipv4", "value": "10.0.0.50"},
        {"ioc_type": "ipv4", "value": "8.8.8.8"},
    ],
}

MINIMAL_BUNDLE = {
    "detections": [],
    "mitre_techniques": [],
}

RUN_1_REPORT = {
    "summary": "Port Scan Detected on Internal Host (10.0.0.50) from Scanning Source (10.0.0.10)",
    "key_findings": [
        "Internal host 10.0.0.10 performed a network service discovery attack against 10.0.0.50.",
        "The attacker contacted 25 distinct ports within a 4-second window, exceeding the threshold of 20 ports in 10 seconds.",
        "Traffic analysis indicates no successful TCP connections (ACKs) were established; only SYN packets were observed.",
    ],
    "mitre_context": [
        {
            "id": "T1046",
            "name": "Network Service Discovery",
            "rule_ids": ["port_scan_v1"],
        }
    ],
    "recommended_next_steps": [
        "Block source IP 10.0.0.10 at the firewall.",
        "Investigate host 10.0.0.50 for potential reconnaissance or lateral movement preparation.",
    ],
    "limitations": [
        "False positives may occur if 10.0.0.10 is a legitimate network scanner or monitoring agent.",
        "Absence of SYN-ACK packets suggests the scan did not trigger responses, but could indicate a firewall blocking stateless connections.",
    ],
}

RUN_2_REPORT = {
    "summary": "Analysis of network traffic between internal hosts reveals a potential port scanning activity targeting 10.0.0.50 from 10.0.0.10.",
    "key_findings": [
        "Host 10.0.0.10 initiated contact with host 10.0.0.50 on 25 distinct ports within a 2-second window.",
        "All observed flows to 10.0.0.50 resulted in incomplete TCP handshakes (SYN_SENT state).",
        "No successful DNS or HTTP transactions were recorded for the suspicious internal IPs.",
        "External connectivity to 8.8.8.8 was observed but occurred after the primary suspicious activity window.",
    ],
    "mitre_context": [
        {
            "id": "T1046",
            "name": "Network Service Discovery",
            "rule_ids": ["port_scan_v1"],
        }
    ],
    "recommended_next_steps": [
        "Isolate host 10.0.0.10 to prevent further lateral movement.",
        "Verify administrative access and software updates on host 10.0.0.50.",
        "Review recent changes to firewall rules on the internal network.",
        "Deploy additional logging or intrusion detection for host 10.0.0.10.",
    ],
    "limitations": [
        "The analysis is based on sampled flow data; if the sample rate was low, some connections may have been missed.",
        "False positives may occur if automated discovery tools are running on host 10.0.0.10.",
    ],
}


def test_clean_report_has_no_warnings():
    report = {
        "summary": "No detections fired.",
        "key_findings": [],
        "mitre_context": [],
        "recommended_next_steps": [],
        "limitations": ["Absence of detection is not evidence of absence of compromise."],
    }
    assert validate_report(report, BUNDLE) == []


def test_run_1_report_flags_expected_violations():
    warnings = validate_report(RUN_1_REPORT, BUNDLE)
    warning_keys = {
        (warning["type"], warning["value"], warning["field"]) for warning in warnings
    }
    assert ("banned_word", "attacker", "key_findings[1]") in warning_keys
    assert (
        "banned_word",
        "lateral movement",
        "recommended_next_steps[1]",
    ) in warning_keys
    assert ("fabricated_number", "4", "key_findings[1]") in warning_keys
    assert (
        "directive_phrasing",
        "Block",
        "recommended_next_steps[0]",
    ) in warning_keys
    assert (
        "speculation_marker",
        "could indicate",
        "limitations[1]",
    ) in warning_keys
    assert (
        "missing_required_limitation",
        "absence-of-detection-disclaimer",
        "limitations",
    ) in warning_keys


def test_run_2_report_flags_expected_violations():
    warnings = validate_report(RUN_2_REPORT, BUNDLE)
    warning_keys = {
        (warning["type"], warning["value"], warning["field"]) for warning in warnings
    }
    assert ("banned_word", "isolate", "recommended_next_steps[0]") in warning_keys
    assert (
        "banned_word",
        "lateral movement",
        "recommended_next_steps[0]",
    ) in warning_keys
    assert ("fabricated_number", "2", "key_findings[0]") in warning_keys
    assert (
        "directive_phrasing",
        "Isolate",
        "recommended_next_steps[0]",
    ) in warning_keys
    assert (
        "missing_required_limitation",
        "absence-of-detection-disclaimer",
        "limitations",
    ) in warning_keys


def test_validation_is_deterministic_and_sorted():
    first = validate_report(RUN_1_REPORT, BUNDLE)
    second = validate_report(deepcopy(RUN_1_REPORT), deepcopy(BUNDLE))
    assert first == second
    assert first == sorted(
        first, key=lambda warning: (warning["field"], warning["type"], warning["value"])
    )


def test_extract_bundle_numbers():
    assert {25, 20, 43, 44, 53, 3, 1, 0}.issubset(
        extract_bundle_numbers(BUNDLE)
    )


def test_field_coverage():
    report = {
        "summary": "The attacker saw 999 hosts.",
        "key_findings": ["The attacker saw 998 hosts."],
        "mitre_context": [],
        "recommended_next_steps": ["Consider reviewing the evidence."],
        "limitations": ["This could indicate 997 missing records."],
    }
    warnings = validate_report(report, BUNDLE)
    fields = {(warning["type"], warning["field"]) for warning in warnings}
    assert ("banned_word", "summary") in fields
    assert ("banned_word", "key_findings[0]") in fields
    assert ("banned_word", "limitations[0]") not in fields
    assert ("speculation_marker", "limitations[0]") in fields
    assert ("fabricated_number", "summary") in fields
    assert ("fabricated_number", "key_findings[0]") in fields


def test_inspect_is_allowed_directive_phrasing():
    report = {
        "recommended_next_steps": ["Inspect the source host."],
        "limitations": ["Absence of detection is not evidence of absence of compromise."],
    }
    warnings = validate_report(report, BUNDLE)
    assert not any(warning["type"] == "directive_phrasing" for warning in warnings)


def test_deploy_is_allowed_directive_phrasing():
    report = {
        "recommended_next_steps": ["Deploy additional monitoring."],
        "limitations": ["Absence of detection is not evidence of absence of compromise."],
    }
    warnings = validate_report(report, BUNDLE)
    assert not any(warning["type"] == "directive_phrasing" for warning in warnings)


def test_confirms_is_a_banned_word():
    report = {
        "key_findings": ["The observed traffic confirms no successful connection."],
        "limitations": ["Absence of detection is not evidence of absence of compromise."],
    }
    warnings = validate_report(report, BUNDLE)
    assert any(
        warning["type"] == "banned_word" and warning["value"] == "confirms"
        for warning in warnings
    )


def test_missing_required_limitation_is_flagged():
    report = {"limitations": ["Something else."]}
    warnings = validate_report(report, BUNDLE)
    assert any(
        warning["type"] == "missing_required_limitation" for warning in warnings
    )


@pytest.mark.parametrize(
    "limitation",
    [
        "Absence of detection is not evidence of absence of compromise.",
        "Note: Absence of detection is not evidence of absence of compromise.",
    ],
)
def test_required_limitation_is_not_flagged(limitation: str):
    report = {"limitations": [limitation]}
    warnings = validate_report(report, BUNDLE)
    assert not any(
        warning["type"] == "missing_required_limitation" for warning in warnings
    )


def test_canonical_limitation_with_prefix_does_not_flag_compromise():
    report = {
        "summary": "",
        "key_findings": [],
        "mitre_context": [],
        "recommended_next_steps": [],
        "limitations": [
            "Note: absence of detection is not evidence of absence of compromise."
        ],
    }
    warnings = validate_report(report, MINIMAL_BUNDLE)
    assert not any(
        w["type"] == "banned_word" and w["value"] == "compromise"
        for w in warnings
    )
    assert not any(
        w["type"] == "missing_required_limitation" for w in warnings
    )


def test_compromise_word_outside_limitation_is_still_flagged():
    report = {
        "summary": "The host is compromised.",
        "key_findings": [],
        "mitre_context": [],
        "recommended_next_steps": [],
        "limitations": [
            "Absence of detection is not evidence of absence of compromise."
        ],
    }
    warnings = validate_report(report, MINIMAL_BUNDLE)
    assert any(
        w["type"] == "banned_word"
        and w["value"] == "compromised"
        and w["field"] == "summary"
        for w in warnings
    )
