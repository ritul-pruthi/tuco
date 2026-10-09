import re

_EVIDENCE_OPEN_RE = re.compile(r"<EVIDENCE>", re.IGNORECASE)
_EVIDENCE_CLOSE_RE = re.compile(r"</EVIDENCE>", re.IGNORECASE)


def escape_delimiters(text: str) -> str:
    """Replace evidence block delimiters with non-delimiting equivalents."""
    escaped = _EVIDENCE_CLOSE_RE.sub("</EVIDENCE_ESCAPED>", text)
    return _EVIDENCE_OPEN_RE.sub("<EVIDENCE_ESCAPED>", escaped)


def strip_control_chars(text: str) -> str:
    """Remove ASCII control characters except tab, newline, and carriage return."""
    return "".join(
        character
        for character in text
        if character in "\t\n\r" or ord(character) >= 32 and ord(character) != 127
    )


def sanitize_evidence_string(value: str) -> str:
    """Sanitize a captured evidence string for defense-in-depth use."""
    return escape_delimiters(strip_control_chars(value))


# These helpers exist as a defense-in-depth layer. Sub-task 4 will decide whether
# to pre-sanitize bundle strings or rely on the delimiter contract in the system
# prompt. Pre-sanitizing mutates evidence values, which risks misrepresenting
# what was captured — that is itself a RULES.md concern. The default is to NOT
# pre-sanitize unless the system prompt contract proves insufficient.
