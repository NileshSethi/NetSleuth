# Document 04: Synthetic Dataset & Flow Log Schema

## 1. Overview & Data Philosophy
NetSleuth processes simulated network-flow logs modeled after modern cloud VPC flow logs (e.g., AWS VPC Flow Logs, GCP VPC Flow Logs). Each row represents an aggregated network connection flow observed at a virtual network interface over an aggregation interval.

To maintain strict educational and ethical integrity:
- All IP addresses are drawn exclusively from RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or RFC 5737 documentation ranges (`198.51.100.0/24`, `203.0.113.0/24`).
- No proprietary customer data, production network captures, or real-world credentials are used.
- Ground-truth evaluation labels are segregated from detection inputs to prevent label leakage.

---

## 2. Formal Schema Specification

| Field Name | Data Type | Nullable? | Allowable Values / Constraints | Description |
| :--- | :--- | :---: | :--- | :--- |
| `event_id` | String | No | Unique non-empty string (e.g., `flw-001a8f9c`) | Primary identifier for the flow log event. |
| `timestamp` | String (ISO-8601) | No | Format: `YYYY-MM-DDTHH:MM:SSZ` (UTC) | Time of flow recording or aggregation window start. |
| `src_ip` | String | No | Valid IPv4 format (`A.B.C.D`) | IPv4 address of the initiating host/interface. |
| `dst_ip` | String | No | Valid IPv4 format (`A.B.C.D`) | IPv4 address of the target host/interface. |
| `src_port` | Integer | No | Range: $1 \le \text{src\_port} \le 65535$ | Ephemeral or source port of the client connection. |
| `dst_port` | Integer | No | Range: $1 \le \text{dst\_port} \le 65535$ | Destination port corresponding to target service. |
| `protocol` | String | No | `TCP`, `UDP`, `ICMP` | Transport layer protocol. |
| `bytes` | Integer | No | Non-negative integer ($\ge 0$) | Total bytes transferred in the flow (source $\rightarrow$ destination). |
| `action` | String | No | `ACCEPT`, `REJECT` | Firewall or security group policy decision. |
| `direction` | String | No | `INBOUND`, `OUTBOUND`, `INTERNAL` | Traffic boundary classification relative to monitored VPC/subnet. |
| `cloud_region` | String | Yes | e.g., `us-east-1`, `eu-west-1` *(Optional metadata)* | Simulated cloud region hosting the monitored asset. |
| `vpc_id` | String | Yes | e.g., `vpc-0a1b2c3d` *(Optional metadata)* | Simulated Virtual Private Cloud network identifier. |
| `scenario_id` | String | Yes | e.g., `SCN-01-BENIGN`, `SCN-02-PORTSCAN` | Evaluation scenario tag *(Isolated from detectors)*. |
| `is_attack` | Boolean | Yes | `True`, `False` *(Evaluation only)* | Ground-truth binary attack label. |
| `attack_type` | String | Yes | `benign`, `port_scan`, `host_scan`, `exfiltration` | Ground-truth specific threat class. |

---

## 3. Detailed Field Semantics

### Timestamp Handling
- All timestamps must be explicitly UTC and formatted in ISO-8601 (`2026-10-18T14:30:00Z`).
- The parser parses timestamps using `pd.to_datetime(utc=True)` and sorts records in ascending chronological order prior to analysis.
- If a timestamp is invalid or unparseable, the parser rejects that record and records a telemetry error.

### Flow Bytes
- `bytes` represents the total volume of network payload and headers transmitted in the flow from `src_ip` to `dst_ip`.
- Negative byte counts are physically invalid and will cause row rejection during parsing.

### Traffic Direction Semantics
Direction classifies flow orientation relative to the monitored cloud private network:
- `INTERNAL`: Both `src_ip` and `dst_ip` belong to internal private subnets (e.g., `10.0.0.0/8`). Indicates east-west lateral communication.
- `INBOUND`: `src_ip` is an external IP (e.g., `203.0.113.50`) and `dst_ip` is an internal private asset.
- `OUTBOUND`: `src_ip` is an internal private asset and `dst_ip` is an external public address. Used by the exfiltration detector.

---

## 4. Separation of Ground-Truth Labels (No Label Leakage)

A fundamental principle of NetSleuth is **scientific validity**:
- The ground-truth columns (`scenario_id`, `is_attack`, `attack_type`) are generated solely to validate the system's accuracy.
- When `parser.py` loads data for detection, it passes only the feature columns to `detectors.py`.
- Heuristics run completely "blind" to whether a row was labeled as attack or benign.
- Only in `evaluation.py` are the detector outputs aligned against the ground-truth labels to compute accuracy metrics.

---

## 5. Planned Synthetic Test Scenarios (For Phase 2)

NetSleuth plans 5 distinct reproducible synthetic scenarios (generated via fixed random seeds):

| Scenario ID | Name | Dominant Traffic Pattern | Primary Expected Detection |
| :--- | :--- | :--- | :--- |
| `SCN-BENIGN-01` | Normal Enterprise Baseline | Routine web traffic (HTTP/S), DNS lookups, occasional SSH admin connections. | 0 Alerts (Clean baseline) |
| `SCN-PORTSCAN-02`| Vertical Reconnaissance | Single internal host probes 50+ ports on a file server within 60 seconds (`action=REJECT/ACCEPT`). | Rule 1: Vertical Port Scan |
| `SCN-HOSTSCAN-03`| Horizontal Discovery | Compromised host sweeps port 445 (SMB) across 30 distinct internal IPs in 120 seconds. | Rule 2: Horizontal Host Scan |
| `SCN-EXFIL-04` | Data Exfiltration | Single internal host uploads 2.5 GB to an external IP (`203.0.113.99`) over port 443 in 3 minutes. | Rule 3: Outbound Volume Spike |
| `SCN-BLENDED-05` | Multi-Stage APT Attack | Host scan $\rightarrow$ Port scan on discovered server $\rightarrow$ Lateral SMB flow $\rightarrow$ Massive outbound transfer. | All 3 Rules + Multi-Alert Incident Correlation |

*(Note: Synthetic dataset CSV files will be generated during Phase 2.)*
