# Document 05: Detection Rules & Algorithmic Heuristics

## 1. Detection Philosophy & Explainability
NetSleuth implements **deterministic, explainable heuristics** rather than opaque machine-learning models. In cybersecurity incident response:
> *An alert without clear, verifiable evidence is simply noise.*

Every detection rule in NetSleuth follows these criteria:
1. **Clear Pre-conditions:** The exact fields and conditions required to trigger are fully documented.
2. **Deterministic Evidence:** The resulting alert lists the specific flow records (`event_id`s), threshold values, and observed measurements that caused the trigger.
3. **Investigation Signals, Not Proof:** Alerts indicate *suspicious anomalies* warranting human analyst triage, not definitive proof of compromise.
4. **Configurable Parameters:** Thresholds are centralized in `config.py` and tunable in the Streamlit UI.

---

## 2. Rule 1: Vertical Port Scan Detection (`RULE-PORT-SCAN`)

### Detection Objective
Detect an adversary or automated scanning tool probing multiple service ports on a targeted host to discover listening network services and vulnerabilities.

### Required Fields
`timestamp`, `src_ip`, `dst_ip`, `dst_port`, `action`, `event_id`.

### Proposed Algorithm
1. Group records by unique pair `(src_ip, dst_ip)`.
2. Apply a rolling or sliding time window $T_{\text{port\_window}}$ (default: 60 seconds).
3. Count the cardinality of distinct `dst_port` values contacted within the window:
   $$\text{DistinctPorts}(src, dst, T) = |\{ \text{dst\_port} \mid \text{flow} \in [t, t + T] \}|$$
4. If $\text{DistinctPorts}(src, dst, T) \ge \Theta_{\text{port\_count}}$ (default: 15 distinct ports), trigger an alert.
5. Aggregate all associated flow IDs as cryptographic/forensic evidence.

### Configurable Thresholds
- `PORT_SCAN_WINDOW_SEC`: Default = 60 seconds (tunable range: 10–300s).
- `PORT_SCAN_THRESHOLD`: Default = 15 distinct ports (tunable range: 5–100 ports).

### Scenarios
- **Benign Scenario:** A developer uses an IDE or web browser that rapidly opens sequential outbound ephemeral ports to a known multi-service load balancer. (Managed by tuning port threshold or filtering ephemeral destination ports).
- **Suspicious Scenario:** An internal host (`10.0.0.45`) sends rapid TCP SYN connection attempts to ports 21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080 on a domain controller (`10.0.0.10`) within 30 seconds, resulting mostly in `REJECT` actions.

### Evidence Captured in Alert
- `src_ip`, `dst_ip`.
- Observed distinct port count vs. configured threshold.
- List of ports contacted (e.g., `[21, 22, 23, 80, 443, 445, 3389, ...]`).
- Count of `REJECT` vs. `ACCEPT` actions.
- Contributing flow `event_id` list.

### False Positives & Limitations
- **False Positives:** Legitimate enterprise vulnerability scanners (e.g., Nessus, Qualys) or network monitoring tools.
- **Limitations:** Extremely slow "low-and-slow" stealth scans (e.g., 1 port probe every 10 minutes) will evade short 60-second sliding windows.

### Recommended Defensive Follow-up
- Inspect the source host for unauthorized tools (e.g., `nmap`, `masscan`).
- Check host endpoint logs (EDR/Sysmon) for processes creating raw sockets.
- Isolate the source host if unauthorized.

---

## 3. Rule 2: Horizontal Host Scan / Network Sweep (`RULE-HOST-SCAN`)

### Detection Objective
Detect an adversary performing horizontal network reconnaissance by probing a single service or multiple services across a wide range of subnet hosts to discover live assets (lateral movement phase).

### Required Fields
`timestamp`, `src_ip`, `dst_ip`, `dst_port`, `action`, `event_id`.

### Proposed Algorithm
1. Group records by initiating `src_ip`.
2. Apply a sliding time window $T_{\text{host\_window}}$ (default: 120 seconds).
3. Count the cardinality of distinct `dst_ip` targets contacted within the window:
   $$\text{DistinctHosts}(src, T) = |\{ \text{dst\_ip} \mid \text{flow} \in [t, t + T] \}|$$
4. If $\text{DistinctHosts}(src, T) \ge \Theta_{\text{host\_count}}$ (default: 10 distinct hosts), trigger an alert.
5. Capture targeted destination IPs and queried ports.

### Configurable Thresholds
- `HOST_SCAN_WINDOW_SEC`: Default = 120 seconds (tunable range: 30–600s).
- `HOST_SCAN_THRESHOLD`: Default = 10 distinct destination hosts (tunable range: 3–50 hosts).

### Scenarios
- **Benign Scenario:** A centralized network monitoring server (e.g., Prometheus, Zabbix) periodically polls 50 internal instances via SNMP (port 161) or ICMP ping.
- **Suspicious Scenario:** A compromised workstation (`192.168.1.105`) sends connection requests to port 445 (SMB) across all IPs in `192.168.1.0/24` within 90 seconds.

### Evidence Captured in Alert
- `src_ip`.
- Count and list of unique destination IPs targeted.
- Targeted ports.
- Ratio of rejected connections (indicating dark or closed IPs).
- Contributing flow `event_id` list.

### False Positives & Limitations
- **False Positives:** Automated IT management servers, broadcast discovery protocols, Active Directory domain queries.
- **Limitations:** Does not distinguish whether the scan was randomized across the Internet or sequential within a private CIDR block without subnet context.

### Recommended Defensive Follow-up
- Verify if the source IP is an authorized asset scanner.
- Check authentication logs on targeted hosts for failed lateral logins.
- Restrict internal lateral communication using host-based micro-segmentation.

---

## 4. Rule 3: Anomalous Outbound Data Volume Spike (`RULE-EXFIL-SPIKE`)

### Detection Objective
Detect potential data exfiltration where an internal host suddenly transmits an unusually large volume of data to an external destination.

### Required Fields
`timestamp`, `src_ip`, `dst_ip`, `bytes`, `direction`, `action`, `event_id`.

### Proposed Algorithm
1. Filter records where `direction == 'OUTBOUND'` and `action == 'ACCEPT'`.
2. Evaluate individual flow volume or cumulative flow volume grouped by `(src_ip, dst_ip)` over a sliding window $T_{\text{vol\_window}}$ (default: 300 seconds).
3. Calculate:
   $$\text{TotalOutboundBytes}(src, dst, T) = \sum \text{bytes} \quad \text{for flows in } [t, t + T]$$
4. If $\text{TotalOutboundBytes}(src, dst, T) \ge \Theta_{\text{bytes\_threshold}}$ (default: 50 MB / 52,428,800 bytes), trigger an alert.

### Configurable Thresholds
- `EXFIL_WINDOW_SEC`: Default = 300 seconds (5 minutes).
- `EXFIL_BYTE_THRESHOLD`: Default = 52,428,800 bytes (50 MB) (tunable range: 5 MB to 1 GB).

### Scenarios
- **Benign Scenario:** An internal developer pushes a large compiled Docker image or database backup to an authorized corporate cloud repository (e.g., GitHub, AWS S3).
- **Suspicious Scenario:** An internal database server (`10.0.1.25`) establishes an outbound connection to an unknown external IP (`203.0.113.88`) over TCP port 443 and transfers 850 MB in 2 minutes outside business hours.

### Evidence Captured in Alert
- `src_ip` and external `dst_ip`.
- Total transferred bytes (formatted in human-readable KB/MB/GB).
- Destination port used (e.g., 443, 8080, 22).
- Time window start and end.
- Contributing flow `event_id` list.

### False Positives & Limitations
- **False Positives:** Routine software updates, OS patch downloads, approved large file uploads to Google Drive/OneDrive.
- **Limitations:** Flow logs record raw byte quantities, not payload contents; cannot detect low-volume intellectual property exfiltration (e.g., a 10 KB password file or API key).

### Recommended Defensive Follow-up
- Inspect DNS logs and threat intelligence reputation for the destination IP.
- Examine proxy/firewall logs for the specific domain name or TLS SNI.
- Determine the identity of the user and process responsible on the internal host.
