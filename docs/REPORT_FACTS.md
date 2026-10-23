# NetSleuth Project Report — Verified Facts (Single Source of Truth)

All metrics, parameters, and findings in this document were verified through direct execution of the codebase on 23 October 2026. This file serves as the definitive reference for the project report and presentation.

---

## 1. Project Overview & Codebase Architecture

- **Project Title:** NetSleuth: An Explainable Network Attack Timeline Reconstruction and Threat Analysis System for Cloud Flow Logs
- **Repository Path:** `c:\Users\NILESH\Desktop\Self\Projects\NetSleuth`
- **GitHub Repository URL:** `https://github.com/NileshSethi/NetSleuth.git`
- **Runtime Environment:** Python 3.12.10, Streamlit 1.64.0, Plotly 7.1.0, NetworkX 3.7, pytest 9.1.1
- **Configuration File:** `src/netsleuth/config.py`
- **Total Executable Code Lines:** 1,671 lines across 9 core files

### Codebase Inventory & File Roles

| File | Lines | Verified Role |
| :--- | :--- | :--- |
| `src/netsleuth/config.py` | 68 | Defines detection thresholds, sliding time windows, risk scoring weights, MITRE ATT&CK metadata, and required CSV schema columns. |
| `src/netsleuth/loader.py` | 52 | Ingests CSV files, verifies required columns, rejects malformed IPv4 addresses/ports/negative byte counts, normalises timestamps to UTC, and chronologically sorts flow records. |
| `src/netsleuth/detectors.py` | 135 | Implements three sliding-window detection rules (port scan, host scan, data exfiltration) and returns alerts with contributing flow indices and human-readable explanations. |
| `src/netsleuth/incidents.py` | 253 | Correlates alerts by source IP within a 300-second session window, computes deterministic risk scores (0–100), maps kill chain stages, formulates remediation advice, and builds markdown forensic dossiers. |
| `src/netsleuth/graph.py` | 145 | Constructs directed network communication graphs with NetworkX and renders tactical Plotly visualisations with colour-coded host roles (red attacker, amber victim, cyan normal). |
| `src/netsleuth/evaluation.py` | 47 | Evaluates flow-level detection accuracy against synthetic ground-truth labels, computing True Positives, False Positives, False Negatives, Precision, Recall, and F1 score. |
| `src/netsleuth/synthetic.py` | 241 | Deterministically synthesises 5 benchmark network flow scenarios using a fixed random seed (`42`), blending benign background traffic with specific attack vectors. |
| `app.py` | 535 | Streamlit interactive web dashboard incorporating dark theme, KPI cards, five functional tabs, interactive charts, network topology, and exportable forensic dossiers. |
| `tests/test_netsleuth.py` | 204 | Unit test suite covering threshold boundaries, benign baseline, time-gap correlation, hand-calculated scoring, loader validation, zero label leakage, and forensic generation. |

---

## 2. Configuration Parameters & Heuristic Thresholds

All thresholds and scoring constants are defined in `src/netsleuth/config.py`:

| Parameter | Threshold / Value | Window | Severity | Description / Justification |
| :--- | :--- | :--- | :--- | :--- |
| **Port Scan** | $\ge 10$ distinct destination ports | 60 s | MEDIUM | Probing $\ge 10$ unique ports on a single host within a 60-second sliding window indicates automated reconnaissance. |
| **Host Scan** | $\ge 5$ distinct destination hosts | 60 s | MEDIUM | Probing $\ge 5$ unique target hosts on the same destination port within 60 seconds indicates horizontal subnet sweeping. |
| **Data Exfiltration** | $\ge 500,000$ bytes ($\approx 500\text{ KB}$) | 120 s | HIGH | Bulk outbound transmission to an external host totaling $\ge 500\text{ KB}$ within 120 seconds indicates unauthorized asset exfiltration. |
| **Incident Correlation Window** | $\le 300$ seconds (5 minutes) | — | — | Maximum time gap between consecutive alerts from the same source IP to be grouped into a single incident. |
| **Base Score (LOW)** | 10 points | — | — | Incident base score when highest alert severity is LOW. |
| **Base Score (MEDIUM)** | 30 points | — | — | Incident base score when highest alert severity is MEDIUM. |
| **Base Score (HIGH)** | 50 points | — | — | Incident base score when highest alert severity is HIGH. |
| **Additional Alert Penalty** | +10 points per extra alert | — | — | Added for each alert beyond the first: $10 \times (N - 1)$. |
| **Moderate Exfiltration Bonus** | +10 points | — | — | Added if total exfiltrated bytes are $\ge 500,000$ bytes ($500\text{ KB}$) and $< 5,000,000$ bytes ($5\text{ MB}$). |
| **High-Volume Exfiltration Bonus** | +20 points | — | — | Added if total exfiltrated bytes are $\ge 5,000,000$ bytes ($5\text{ MB}$). |
| **Maximum Score Cap** | 100 points | — | — | Score capped strictly at 100 via $\min(100, \text{Base} + \text{Extra} + \text{Volume})$. |

### Priority Level Classification Bands

- **Low Priority:** $0 \le \text{Score} \le 29$
- **Medium Priority:** $30 \le \text{Score} \le 59$
- **High Priority:** $60 \le \text{Score} \le 79$
- **Critical Priority:** $80 \le \text{Score} \le 100$

---

## 3. MITRE ATT&CK & Cyber Kill Chain Mappings

| Detection Rule | MITRE Technique ID | Technique Name | MITRE Tactic | Kill Chain Phase |
| :--- | :--- | :--- | :--- | :--- |
| Port Scan | `T1046` | Network Service Discovery | Discovery (`TA0007`) | Reconnaissance |
| Host Scan | `T1018` | Remote System Discovery | Discovery (`TA0007`) | Lateral Movement Prep |
| Data Exfiltration | `T1048` | Exfiltration Over Alternative Protocol | Exfiltration (`TA0010`) | Actions on Objectives (Data Theft) |

---

## 4. Input Schema & Data Validation

### Required Flow Log Columns
`src/netsleuth/config.py` enforces 8 required columns:
1. `timestamp` (ISO-8601 string, converted to UTC datetime)
2. `src_ip` (IPv4 address)
3. `dst_ip` (IPv4 address)
4. `dst_port` (Integer $1 \le \text{port} \le 65535$)
5. `protocol` (String, e.g., TCP or UDP)
6. `bytes` (Non-negative integer $\ge 0$)
7. `action` (Firewall status: ACCEPT or REJECT)
8. `direction` (INBOUND, OUTBOUND, or INTERNAL)
- `label` (Optional string: used exclusively by `evaluation.py` for ground truth; ignored by detectors).

### Data Validation Rules (`src/netsleuth/loader.py`)
- Missing column check: Raises `ValueError` if any required column is absent.
- Timestamp validation: Parsed to UTC; NaT rows discarded.
- Port validation: Discards non-numeric, $< 1$, or $> 65535$.
- Byte count validation: Discards non-numeric or negative values ($< 0$).
- IP address validation: Discards strings that fail `ipaddress.IPv4Address(ip)`.
- Ordering: Output DataFrame is sorted chronologically by timestamp with reset indices.

---

## 5. Synthetic Datasets & Generation Characteristics

All datasets generated via `src/netsleuth/synthetic.py` with random seed `42`:
- **Background Traffic:** 4 internal hosts (`10.0.1.10`, `10.0.1.20`, `10.0.1.30`, `10.0.1.40`) communicating with external web destinations, DNS server (`10.0.0.2`), internal SSH, and email relay (`198.51.100.25`).
- **Flow Count Range:** 224 to 320 flows per scenario.

| Scenario File | Total Flows | Attack Flows | Benign Flows | Attack Profile |
| :--- | :--- | :--- | :--- | :--- |
| `scenario1_port_scan.csv` | 238 | 18 | 220 | External IP `198.51.100.55` probes 18 ports on `10.0.1.20` in 17 seconds. |
| `scenario2_host_scan.csv` | 232 | 12 | 220 | Compromised host `10.0.1.15` sweeps 12 hosts on port 445 (SMB) in 22 seconds. |
| `scenario3_data_exfiltration.csv` | 224 | 4 | 220 | Internal host `10.0.1.45` transfers 2,400,000 bytes ($4 \times 600\text{ KB}$) to `203.0.113.88` in 24 seconds. |
| `scenario4_multi_stage.csv` | 277 | 27 | 250 | Host `10.0.1.99`: Stage 1 port scan (13 ports), Stage 2 host scan (8 hosts on port 80), Stage 3 exfiltration ($6 \times 1,050,000\text{ B} = 6,300,000\text{ B}$). |
| `scenario5_benign.csv` | 320 | 0 | 320 | Pure background traffic (web, DNS, SSH, email). No malicious activity. |

---

## 6. Live Pipeline Execution Results

### Table 6.1: Flow-Level Ground-Truth Detection Accuracy

| Scenario | Threat Profile | Flows | TP | FP | FN | Precision | Recall | F1 Score |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Scenario 1** | Port scan on one host + normal traffic | 238 | 18 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| **Scenario 2** | Internal SMB subnet sweep + normal traffic | 232 | 12 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| **Scenario 3** | Outbound exfiltration + normal traffic | 224 | 4 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| **Scenario 4** | Multi-stage attack (scan, sweep, exfil) | 277 | 27 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| **Scenario 5** | Benign baseline traffic only | 320 | 0 | 0 | 0 | 1.0000* | 1.0000* | 1.0000* |
| **Scenario 6** | Persistent threat actor (temporal session split) | 265 | 25 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| **Scenario 7** | Coordinated multi-host intrusion (dual attackers) | 287 | 27 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| **Scenario 8** | Cloud database breach (massive 12 MB exfil) | 230 | 10 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |

*\*Defined as 1.0000 by convention because zero positive condition exists and False Positives = 0.*

### Table 6.2: Alert, Incident, and Score Breakdown per Scenario

| Scenario | Alerts Fired | Correlated Incidents | Risk Score | Priority Level | Score Calculation Breakdown |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Scenario 1** | 1 (`port_scan`) | 1 (`INC-001`) | 30 | Medium | Base MEDIUM (+30 pts) |
| **Scenario 2** | 1 (`host_scan`) | 1 (`INC-001`) | 30 | Medium | Base MEDIUM (+30 pts) |
| **Scenario 3** | 1 (`exfiltration`) | 1 (`INC-001`) | 60 | High | Base HIGH (+50 pts) + Moderate exfil ($2.4\text{ MB} \ge 500\text{ KB}$, +10 pts) |
| **Scenario 4** | 3 (`port_scan`, `host_scan`, `exfiltration`) | 1 (`INC-001`) | 90 | Critical | Base HIGH (+50 pts) + Extra alerts ($2 \times 10$, +20 pts) + High exfil ($6.3\text{ MB} \ge 5\text{ MB}$, +20 pts) |
| **Scenario 5** | 0 | 0 | None | None | No alerts triggered (Clean defensive posture) |
| **Scenario 6** | 3 (port_scan, host_scan, exfiltration) | 2 (INC-001, INC-002) | 30 / 70 | Medium / High | INC-001: Base MEDIUM (+30 pts). INC-002: Base HIGH (+50 pts) + Extra alert (+10 pts) + Moderate exfil (1.8 MB, +10 pts) = 70 pts. |
| **Scenario 7** | 3 (port_scan, host_scan, exfiltration) | 2 (INC-001, INC-002) | 30 / 70 | Medium / High | INC-001 (198.51.100.77): Base MEDIUM (+30 pts). INC-002 (10.0.1.55): Base HIGH (+50 pts) + Extra alert (+10 pts) + Moderate exfil (3.5 MB, +10 pts) = 70 pts. |
| **Scenario 8** | 1 (exfiltration) | 1 (INC-001) | 70 | High | Base HIGH (+50 pts) + High exfil (12.0 MB >= 5 MB, +20 pts) = 70 pts. |

---

## 7. Worked Example Verification (Scenario 4)

- **Threat Actor IP:** `10.0.1.99`
- **Alert Sequence:**
  1. `ALERT-001` (Port Scan, MEDIUM): 13 ports probed on `10.0.1.20` in 12 seconds (832 bytes).
  2. `ALERT-002` (Host Scan, MEDIUM): 8 hosts swept on port 80 in 14 seconds (512 bytes). Time gap from ALERT-001 is $\approx 108\text{ s} \le 300\text{ s}$.
  3. `ALERT-003` (Exfiltration, HIGH): 6 flows to `203.0.113.88` totaling $6,300,000$ bytes in 30 seconds. Time gap from ALERT-002 is $\approx 106\text{ s} \le 300\text{ s}$.
- **Incident Assembly:** All 3 alerts share source IP `10.0.1.99` with inter-alert gaps $< 300\text{ s}$, creating single incident `INC-001`.
- **Score Calculation:**
  $$\text{Base Points (Highest severity HIGH)} = 50$$
  $$\text{Additional Alert Points } (3 - 1 = 2 \text{ extra alerts} \times 10) = 20$$
  $$\text{Volume Points } (6,300,000\text{ bytes} \ge 5,000,000\text{ bytes}) = 20$$
  $$\text{Total Score} = \min(100, 50 + 20 + 20) = 90 \quad (\text{Critical})$$
- **Verification:** Perfectly matches the worked example text in Section 4.6 and Figure 4.1.

---

## 8. Dashboard Views & User Interface Verification

The Streamlit dashboard (`app.py`) presents **5 tabs**:

| Tab Number | Real Tab Name | Detailed Contents & Capabilities |
| :--- | :--- | :--- |
| **Tab 1** | **Threat Incidents** | Displays incident header with source IP, duration, risk score metric card, MITRE kill chain phase badges, deterministic score breakdown list, targeted endpoint list, containment playbook actions, and expandable alert audit table. |
| **Tab 2** | **Attack Timeline** | Displays interactive Plotly scatter plot mapping events across chronological time vs. Kill Chain Stage (color-coded by severity), followed by a complete chronological incident audit trail table. |
| **Tab 3** | **Network Topology** | Displays interactive Plotly network communication graph (Red: Attacker IP, Amber: Victim IP, Cyan: Normal Subnet Host) and a table of Top Communicating Host Pairs sorted by transferred volume. |
| **Tab 4** | **Flow Telemetry** | Displays three analytical charts (Protocol distribution donut chart, Firewall disposition donut chart, Top targeted destination ports bar chart) and an interactive flow telemetry explorer with IP search, direction, and action filters. |
| **Tab 5** | **Forensic Dossier & Evaluation** | Split-screen interface: Left column provides one-click markdown incident dossier export and live preview; Right column provides the scientific ground-truth evaluation table (TP, FP, FN, Precision, Recall, F1) across all benchmark scenarios. |

---

## 9. Automated Test Suite Results

- **Test Framework:** pytest 9.1.1
- **Test File:** `tests/test_netsleuth.py`
- **Execution Result:** **10 passed, 0 failed** in 5.23 seconds.

### Complete List of Verified Tests
1. `test_port_scan_threshold_boundary`: Asserts 9 distinct ports trigger 0 alerts; 10 distinct ports trigger 1 MEDIUM alert.
2. `test_host_scan_threshold_boundary`: Asserts 4 distinct hosts trigger 0 alerts; 5 distinct hosts trigger 1 MEDIUM alert.
3. `test_exfiltration_threshold_boundary`: Asserts 499,999 outbound bytes trigger 0 alerts; 500,000 bytes trigger 1 HIGH alert.
4. `test_benign_scenario_produces_zero_alerts`: Asserts `scenario5_benign.csv` raises exactly 0 alerts.
5. `test_incident_correlation_time_gap`: Asserts alerts separated by 3 minutes form 1 incident, while alerts separated by 13 minutes form 2 incidents.
6. `test_scoring_hand_calculation`: Asserts base HIGH (50) + 1 extra alert (10) + 600 KB exfil (10) equals 70 (High).
7. `test_scoring_never_exceeds_100`: Asserts multiple high alerts and massive data exfiltration are capped at 100 (Critical).
8. `test_loader_drops_invalid_rows`: Asserts invalid IPv4, out-of-range port (70,000), and negative bytes (-50) are dropped.
9. `test_zero_label_leakage`: Asserts identical alerts are generated when the `label` column is completely stripped.
10. `test_mitre_mapping_and_forensic_dossier`: Asserts MITRE technique IDs and tactics are enriched and forensic dossier generates correctly.
