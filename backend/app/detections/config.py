# Twenty ports is high enough to indicate probing while avoiding ordinary connections.
PORT_SCAN_MIN_DISTINCT_PORTS = 20
# Ten seconds captures a concentrated scan without treating slow activity as one burst.
PORT_SCAN_WINDOW_SECONDS = 10
# Port scans are noteworthy, but the behavior alone is not evidence of compromise.
PORT_SCAN_SEVERITY = "medium"
# The threshold is deterministic, but legitimate tools can produce the same pattern.
PORT_SCAN_CONFIDENCE = "medium"
