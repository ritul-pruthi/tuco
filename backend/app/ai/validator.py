import re
from typing import Any

BANNED_WORDS = [
    "attacker",
    "threat actor",
    "adversary",
    "malicious",
    "compromised",
    "certainly",
    "compromise",
    "infected",
    "isolate",
    "quarantine",
    "immediately",
    "contain",
    "containment",
    "confirm",
    "confirms",
    "confirmed",
    "proven",
    "definitely",
    "evidence strongly",
    "indicator of compromise",
    "gained initial access",
    "lateral movement",
    "threat level",
    "high-confidence",
    "undoubtedly",
]

SPECULATION_MARKERS = [
    "could indicate",
    "may indicate",
    "might indicate",
    "suggests",
    "may have",
    "might have",
    "possibly",
    "potentially",
    "perhaps",
    "presumably",
    "appears to be",
]

DIRECTIVE_ALLOWED_PREFIXES = [
    "consider",
    "investigate",
    "correlate",
    "verify",
    "review",
    "inspect",
    "examine",
    "analyze",
    "assess",
    "validate",
    "audit",
    "check",
    "monitor",
    "deploy",
    "enable",
    "configure",
    "escalate",
    "notify",
]

DIRECTIVE_FORBIDDEN_PREFIXES = [
    "block",
    "isolate",
    "quarantine",
    "contain",
    "disable",
    "shut",
    "terminate",
    "stop",
    "prevent",
    "remove",
    "deny",
    "drop",
]

_NUMBER_PATTERN = re.compile(r"\b\d+\b")
_IP_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_RULE_ID_PATTERN = re.compile(r"\b[a-z_]+_v\d+\b")
_REQUIRED_LIMITATION_SUBSTRING = (
    "absence of detection is not evidence of absence of compromise"
)


def extract_bundle_numbers(bundle: dict) -> set[int | float]:
    numbers: set[int | float] = set()

    def visit(value: Any) -> None:
        if isinstance(value, bool):
            return
        if isinstance(value, (int, float)):
            numbers.add(value)
        elif isinstance(value, str):
            numbers.update(int(match) for match in _NUMBER_PATTERN.findall(value))
        elif isinstance(value, dict):
            for child in value.values():
                visit(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                visit(child)

    visit(bundle)
    return numbers


def _warning(
    warning_type: str, field: str, value: str, context: str
) -> dict[str, str]:
    return {
        "type": warning_type,
        "field": field,
        "value": value,
        "context": context,
    }


def validate_report(report: dict, bundle: dict) -> list[dict]:
    warnings: list[dict[str, str]] = []
    text_fields: list[tuple[str, str]] = []

    if isinstance(report.get("summary"), str):
        text_fields.append(("summary", report["summary"]))
    for field in ("key_findings", "recommended_next_steps", "limitations"):
        values = report.get(field, [])
        if isinstance(values, list):
            text_fields.extend(
                (f"{field}[{index}]", value)
                for index, value in enumerate(values)
                if isinstance(value, str)
            )

    mitre_context = report.get("mitre_context", [])
    if isinstance(mitre_context, list):
        for index, entry in enumerate(mitre_context):
            if not isinstance(entry, dict):
                continue
            for key in ("id", "name", "rule_ids"):
                value = entry.get(key)
                if isinstance(value, str):
                    text_fields.append((f"mitre_context[{index}].{key}", value))
                elif key == "rule_ids" and isinstance(value, list):
                    text_fields.extend(
                        (f"mitre_context[{index}].rule_ids[{rule_index}]", rule_id)
                        for rule_index, rule_id in enumerate(value)
                        if isinstance(rule_id, str)
                    )

    bundle_strings: list[str] = []

    def collect_strings(value: Any) -> None:
        if isinstance(value, str):
            bundle_strings.append(value)
        elif isinstance(value, dict):
            for child in value.values():
                collect_strings(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                collect_strings(child)

    collect_strings(bundle)
    allowed_ips = {
        ip_address
        for bundle_string in bundle_strings
        for ip_address in _IP_PATTERN.findall(bundle_string)
    }
    bundle_numbers = extract_bundle_numbers(bundle)
    allowed_rule_ids = {
        detection.get("rule_id")
        for detection in bundle.get("detections", [])
        if isinstance(detection, dict) and isinstance(detection.get("rule_id"), str)
    }
    allowed_rule_ids.update(
        rule_id
        for technique in bundle.get("mitre_techniques", [])
        if isinstance(technique, dict)
        for rule_id in technique.get("rule_ids", [])
        if isinstance(rule_id, str)
    )
    allowed_technique_ids = {
        technique.get("id")
        for technique in bundle.get("mitre_techniques", [])
        if isinstance(technique, dict) and isinstance(technique.get("id"), str)
    }

    for field, context in text_fields:
        context_lower = context.lower()
        for phrase in BANNED_WORDS:
            if (
                phrase == "compromise"
                and _REQUIRED_LIMITATION_SUBSTRING in context_lower
            ):
                continue
            if re.search(
                rf"\b{re.escape(phrase)}\b", context, flags=re.IGNORECASE
            ):
                warnings.append(_warning("banned_word", field, phrase, context))
        for marker in SPECULATION_MARKERS:
            if re.search(
                rf"\b{re.escape(marker)}\b", context, flags=re.IGNORECASE
            ):
                warnings.append(_warning("speculation_marker", field, marker, context))
        for number in _NUMBER_PATTERN.findall(context):
            if int(number) not in bundle_numbers:
                warnings.append(_warning("fabricated_number", field, number, context))
        for ip_address in _IP_PATTERN.findall(context):
            if ip_address not in allowed_ips:
                warnings.append(_warning("unknown_ip", field, ip_address, context))
        for rule_id in _RULE_ID_PATTERN.findall(context):
            if rule_id not in allowed_rule_ids:
                warnings.append(_warning("unknown_rule_id", field, rule_id, context))

    limitations = report.get("limitations", [])
    limitations_lower = " ".join(
        limitation.lower()
        for limitation in limitations
        if isinstance(limitation, str)
    )
    if _REQUIRED_LIMITATION_SUBSTRING not in limitations_lower:
        warnings.append(
            _warning(
                "missing_required_limitation",
                "limitations",
                "absence-of-detection-disclaimer",
                "",
            )
        )

    for index, value in enumerate(report.get("recommended_next_steps", [])):
        if not isinstance(value, str):
            continue
        match = re.match(r"\s*([A-Za-z]+)", value)
        if match is None:
            continue
        first_word = match.group(1)
        first_word_lower = first_word.lower()
        if (
            first_word_lower in DIRECTIVE_FORBIDDEN_PREFIXES
            or first_word_lower not in DIRECTIVE_ALLOWED_PREFIXES
        ):
            warnings.append(
                _warning(
                    "directive_phrasing",
                    f"recommended_next_steps[{index}]",
                    first_word,
                    value,
                )
            )

    if isinstance(mitre_context, list):
        for index, entry in enumerate(mitre_context):
            if not isinstance(entry, dict):
                continue
            technique_id = entry.get("id")
            if isinstance(technique_id, str) and technique_id not in allowed_technique_ids:
                warnings.append(
                    _warning(
                        "unknown_technique_id",
                        f"mitre_context[{index}].id",
                        technique_id,
                        technique_id,
                    )
                )

    unique_warnings = {
        (warning["field"], warning["type"], warning["value"]): warning
        for warning in warnings
    }
    return sorted(
        unique_warnings.values(),
        key=lambda warning: (warning["field"], warning["type"], warning["value"]),
    )
