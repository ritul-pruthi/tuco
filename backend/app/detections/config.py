# Twenty ports is high enough to indicate probing while avoiding ordinary connections.
PORT_SCAN_MIN_DISTINCT_PORTS = 20
# Ten seconds captures a concentrated scan without treating slow activity as one burst.
PORT_SCAN_WINDOW_SECONDS = 10
# Port scans are noteworthy, but the behavior alone is not evidence of compromise.
PORT_SCAN_SEVERITY = "medium"
# The threshold is deterministic, but legitimate tools can produce the same pattern.
PORT_SCAN_CONFIDENCE = "medium"

# Five internal targets in a short burst is enough to indicate probing while allowing small service checks.
INTERNAL_RECON_MIN_DISTINCT_TARGETS = 5
# Thirty seconds captures concentrated discovery activity without grouping routine periodic checks.
INTERNAL_RECON_WINDOW_SECONDS = 30
# Internal target discovery is noteworthy, but the behavior alone is not evidence of compromise.
INTERNAL_RECON_SEVERITY = "medium"
# The threshold is deterministic, but legitimate inventory and vulnerability tools can produce the same pattern.
INTERNAL_RECON_CONFIDENCE = "medium"
