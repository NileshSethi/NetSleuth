"""Configuration constants, detection thresholds, and MITRE ATT&CK metadata for NetSleuth."""

# Detection rule thresholds
PORT_SCAN_WINDOW = 60           # Sliding window in seconds for port scan detection
PORT_SCAN_THRESHOLD = 10        # Minimum distinct ports on a single host to trigger alert
PORT_SCAN_SEVERITY = "MEDIUM"

HOST_SCAN_WINDOW = 60           # Sliding window in seconds for host scan detection
HOST_SCAN_THRESHOLD = 5         # Minimum distinct destination hosts to trigger alert
HOST_SCAN_SEVERITY = "MEDIUM"

EXFIL_WINDOW = 120              # Sliding window in seconds for exfiltration detection
EXFIL_BYTES_THRESHOLD = 500_000 # Minimum outbound bytes to an external host to trigger alert
EXFIL_SEVERITY = "HIGH"

# Incident grouping & scoring thresholds
INCIDENT_CORRELATION_WINDOW = 300  # 5 minutes: max gap between alerts from the same source IP

SEVERITY_BASE_SCORES = {
    "LOW": 10,
    "MEDIUM": 30,
    "HIGH": 50
}

EXTRA_ALERT_POINTS = 10         # Points added for each additional alert beyond the first
EXFIL_HIGH_BYTES = 5_000_000    # If exfiltrated bytes >= 5 MB, add 20 points
EXFIL_HIGH_POINTS = 20
EXFIL_MED_BYTES = 500_000       # If exfiltrated bytes >= 500 KB, add 10 points
EXFIL_MED_POINTS = 10
MAX_SCORE = 100

# MITRE ATT&CK Enterprise Framework Mappings
MITRE_MAPPINGS = {
    "port_scan": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery (TA0007)",
        "kill_chain_phase": "Reconnaissance",
        "description": "Adversary attempts to enumerate active listening services on a remote host to identify exploitable entry points."
    },
    "host_scan": {
        "technique_id": "T1018",
        "technique_name": "Remote System Discovery",
        "tactic": "Discovery (TA0007)",
        "kill_chain_phase": "Lateral Movement Prep",
        "description": "Adversary sweeps the internal subnet across known service ports to locate live peer systems for lateral expansion."
    },
    "exfiltration": {
        "technique_id": "T1048",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration (TA0010)",
        "kill_chain_phase": "Actions on Objectives",
        "description": "Adversary transmits sensitive collected assets over unmonitored or encrypted network paths to an untrusted external endpoint."
    }
}

# Required CSV columns
REQUIRED_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "dst_port",
    "protocol",
    "bytes",
    "action",
    "direction"
]
