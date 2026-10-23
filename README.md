# NetSleuth

> **Explainable Network Threat Investigation, Attack Timeline Reconstruction, and Incident Forensic Analysis for Cloud Flow Telemetry.**

[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Streamlit-FF4B4B?logo=streamlit&logoColor=white)](https://streamlit.io/)
[![Testing](https://img.shields.io/badge/Tests-10%20Passed%20%7C%20100%25-059669?logo=pytest&logoColor=white)](https://pytest.org/)
[![Telemetry](https://img.shields.io/badge/Telemetry-AWS%20VPC%20Flow%20Logs%20v2-FF9900?logo=amazonaws&logoColor=white)](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
[![Framework](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK%20Enterprise-0284C7)](https://attack.mitre.org/)
[![Zero Label Leakage](https://img.shields.io/badge/Audit-Zero%20Label%20Leakage-10B981)](#zero-label-leakage-verification)

---

## Overview

**NetSleuth** is a lightweight, explainable network threat detection and forensic investigation platform designed for cloud network telemetry (AWS VPC Flow Logs). Built for cybersecurity and cloud computing education, NetSleuth ingests flow log datasets, evaluates them using deterministic sliding-window heuristics, correlates discrete alerts into multi-stage attack incidents, maps behaviors to the **MITRE ATT&CK Enterprise Matrix**, and provides an explicit additive scoring model (0–100) with a transparent audit trail.

The platform is presented through an interactive, enterprise-grade Security Operations Center (SOC) dashboard built with Streamlit and Plotly, accompanied by automated prescriptive containment playbooks and exportable markdown forensic dossiers.

![NetSleuth SOC Dashboard Preview](screenshots/soc_clean_top.png)

---

## Key Capabilities

- **Deterministic Sliding-Window Detectors:** Evaluates rolling time windows to identify vertical port scans (T1046: Network Service Discovery), horizontal subnet sweeps (T1018: Remote System Discovery), and high-volume data exfiltration (T1048: Exfiltration Over Alternative Protocol).
- **Temporal Incident Clustering:** Combines related alert milestones originating from the same source IP within a 300-second session window into unified incidents, eliminating alert fatigue.
- **Explainable Additive Scoring (0–100):** Replaces opaque machine-learning "black boxes" with an auditable mathematical model where every point added to an incident's priority score is backed by an explicit reason.
- **MITRE ATT&CK Cyber Kill Chain Alignment:** Visually tracks multi-stage adversary progression across Discovery, Lateral Movement, and Actions on Objectives.
- **Interactive Host Topology & Traffic Matrix:** Renders directed NetworkX communication graphs and top communicating host volume matrices in Plotly.
- **Prescriptive Containment Playbooks:** Automatically populates Standard Operating Procedures (SOPs) for incident response, including AWS Network ACL isolation and security group detachment.
- **Academic Rigor & Zero Label Leakage:** Verified via 10 automated unit tests ensuring heuristics never inspect or depend on ground-truth evaluation labels.

---

## System Architecture

NetSleuth follows a strict, unidirectional data pipeline where each processing stage has a single, testable responsibility:

```
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│  AWS VPC Flow   │ ────► │    loader.py    │ ────► │  detectors.py   │
│   Log Records   │       │ (Sanitization & │       │ (Sliding-Window │
│   (CSV Format)  │       │  Schema Check)  │       │   Heuristics)   │
└─────────────────┘       └─────────────────┘       └────────┬────────┘
                                                             │
                                                             ▼
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│     app.py      │ ◄──── │    graph.py     │ ◄──── │  incidents.py   │
│  (5-Tab SOC UI  │       │ (Plotly Graph & │       │  (Correlation & │
│  & Dossier Exp) │       │ Traffic Matrix) │       │ 0-100 Scoring)  │
└─────────────────┘       └─────────────────┘       └─────────────────┘
```

![NetSleuth Multi-Stage Architecture](docs/netsleuth_architecture.png)

### Processing Stages
1. **Telemetry Ingestion & Sanitization (`loader.py`):** Ingests CSV flow logs, checks required schema headers, normalizes Unix epoch seconds to standardized UTC date-times, maps IANA protocol numbers (6 &rarr; TCP, 17 &rarr; UDP, 1 &rarr; ICMP), and quarantines corrupted records (malformed IPs, negative bytes, out-of-range ports).
2. **Sliding-Window Threat Detection (`detectors.py`):** Scans chronological flow sequences using time-indexed rolling windows. Produces structured alerts containing timestamps, rule names, severity ratings, targets, and contributing flow indices.
3. **Temporal Incident Correlation (`incidents.py`):** Groups alerts by source IP. If the time gap between consecutive alerts is 300 seconds (5 minutes) or less, they are merged into a unified incident. Inactivity gaps exceeding 300 seconds split the actor's actions into distinct incident sessions.
4. **Explainable Risk Scoring Engine (`incidents.py`, `config.py`):** Calculates an additive 0–100 priority rating, maps triggers to MITRE ATT&CK techniques, and generates prescriptive containment playbooks.
5. **Interactive SOC Dashboard (`app.py`, `graph.py`):** Renders the 5-tab analytical deck, Plotly network topologies, chronological kill chain timelines, and provides one-click markdown forensic dossier export.

---

## Telemetry Specification: AWS VPC Flow Logs

NetSleuth natively adheres to the **AWS VPC Flow Log Version 2** specification:

| Field Name | AWS Flow Log Equivalent | Data Type | Forensic Description |
| :--- | :--- | :--- | :--- |
| `timestamp` | `start` / `end` | `datetime (UTC)` | Flow event timestamp normalized to UTC format. |
| `src_ip` | `srcaddr` | `string (IPv4)` | Source IP address originating the communication. |
| `dst_ip` | `dstaddr` | `string (IPv4)` | Destination IP address of the targeted host. |
| `src_port` | `srcport` | `integer (0–65535)` | Ephemeral source port number. |
| `dst_port` | `dstport` | `integer (0–65535)` | Destination service port (e.g., 22, 80, 443, 445). |
| `protocol` | `protocol` | `string` | Transport protocol name mapped from IANA numbers (`TCP`, `UDP`, `ICMP`). |
| `packets` | `packets` | `integer` | Count of packets transmitted within the flow window. |
| `bytes` | `bytes` | `integer` | Total volume of payload and header bytes transferred. |
| `action` | `action` | `string` | Firewall disposition: `ACCEPT` or `REJECT`. |
| `direction` | *Computed* | `string` | Relative path orientation: `INGRESS`, `EGRESS`, or `INTERNAL`. |

---

## Detection Heuristics & Scoring Model

### 1. Sliding-Window Detection Rules

| Attack Vector | Rule Identifier | Sliding Window | Detection Condition | Base Severity | Base Points | MITRE Reference |
| :--- | :--- | :---: | :--- | :---: | :---: | :--- |
| **Vertical Port Scan** | `port_scan` | 60s | $\ge 10$ unique destination ports on 1 target IP | `MEDIUM` | +30 pts | **T1046**: Network Service Discovery |
| **Horizontal Host Sweep** | `host_scan` | 60s | $\ge 5$ unique internal host IPs on 1 service port | `MEDIUM` | +30 pts | **T1018**: Remote System Discovery |
| **Data Exfiltration** | `exfiltration` | 120s | $\ge 500\text{ KB}$ (500,000 bytes) transferred outbound | `HIGH` | +50 pts | **T1048**: Exfil Over Alt. Protocol |

### 2. Additive Mathematical Scoring Formula

$$\text{Priority Score} = \min\Big(100, \;\; \text{Base Points} + \text{Extra Alert Points} + \text{Volume Bonus Points}\Big)$$

- **Base Points:** The highest severity among all alerts contributing to the incident (`HIGH` = 50, `MEDIUM` = 30, `LOW` = 10).
- **Extra Correlated Alert Points:** $+10\text{ points}$ for every additional alert correlated beyond the first ($(\text{alert\_count} - 1) \times 10$).
- **Data Exfiltration Volume Bonus:**
  - If total exfiltrated bytes $\ge 5\text{ MB}$ (5,000,000 bytes): **$+20\text{ points}$**
  - If total exfiltrated bytes $\ge 500\text{ KB}$ (500,000 bytes): **$+10\text{ points}$**
- **Score Ceiling:** Strictly capped at a maximum of 100 points.

### 3. Priority Level Classification

| Score Range | Priority Level | Operational Action |
| :---: | :---: | :--- |
| **80 – 100** | **Critical** | Multi-stage intrusion or high-volume exfiltration. Immediate host isolation required. |
| **60 – 79** | **High** | Correlated malicious activities or confirmed data exfiltration. |
| **30 – 59** | **Medium** | Isolated reconnaissance, vertical port probe, or horizontal sweep. |
| **0 – 29** | **Low** | Baseline telemetry anomaly or low-confidence indicator. |

---

## Worked Example: Multi-Stage Enterprise Attack (Scenario 4)

In Benchmark Scenario 4 (`scenario4_multi_stage.csv`), threat actor **`10.0.1.99`** triggers all three detection rules within a 5-minute session window:
1. **Vertical Port Scan:** Probes 18 distinct ports on `10.0.1.20` within 17 seconds (Severity: `MEDIUM`).
2. **Horizontal Host Sweep:** Scans 12 internal hosts on SMB port 445 within 11 seconds (Severity: `MEDIUM`).
3. **Outbound Data Exfiltration:** Transmits 6,300,000 bytes (6.3 MB) to adversary drop `203.0.113.88` within 24 seconds (Severity: `HIGH`).

### Priority Score Audit Trail
$$\begin{aligned}
\text{Base Severity (Highest = HIGH)} &= +50\text{ pts} \\
\text{Extra Alerts Bonus } (2 \text{ alerts} \times 10) &= +20\text{ pts} \\
\text{Volume Bonus } (\ge 5\text{ MB Exfiltration}) &= +20\text{ pts} \\
\hline
\mathbf{Total\text{ }Score} &= \mathbf{90\text{ }/\text{ }100\text{ (Critical Priority)}}
\end{aligned}$$

---

## Quantitative Benchmark Evaluation

NetSleuth was benchmarked against eight synthetic cloud traffic scenarios covering diverse intrusion patterns and normal baselines:

| Scenario File | Description | Total Flows | Malicious Flows | Alerts Raised | Incidents | Max Score | Priority | Precision | Recall | F1-Score |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `scenario1_port_scan.csv` | External Reconnaissance Probe | 238 | 18 | 1 | 1 | 30 | Medium | 1.000 | 1.000 | 1.000 |
| `scenario2_host_scan.csv` | Internal Subnet SMB Sweep | 232 | 12 | 1 | 1 | 30 | Medium | 1.000 | 1.000 | 1.000 |
| `scenario3_data_exfiltration.csv` | Outbound Asset Theft (2.4 MB) | 224 | 20 | 1 | 1 | 60 | High | 1.000 | 1.000 | 1.000 |
| `scenario4_multi_stage.csv` | Full Kill Chain Intrusion (6.3 MB) | 277 | 50 | 3 | 1 | 90 | Critical | 1.000 | 1.000 | 1.000 |
| `scenario5_benign.csv` | Subnet Baseline (Zero Threats) | 320 | 0 | 0 | 0 | 0 | Normal | 1.000* | 1.000* | 1.000* |
| `scenario6_persistent_threat.csv` | Temporal Split (12m Inactivity Gap)| 265 | 38 | 3 | 2 | 70 | High | 1.000 | 1.000 | 1.000 |
| `scenario7_coordinated_attack.csv` | Dual Attackers (Perimeter & Internal)| 277 | 42 | 3 | 2 | 70 | High | 1.000 | 1.000 | 1.000 |
| `scenario8_cloud_data_breach.csv` | Massive DB Dump (12.0 MB Exfil) | 230 | 10 | 1 | 1 | 70 | High | 1.000 | 1.000 | 1.000 |

*\*Note: In Scenario 5, precision and recall are recorded as 1.000 by convention because no attack flows are present. The primary metric is 0 false alarms (False Positive Rate = 0.0%).*

---

## Dashboard Walkthrough

The NetSleuth user interface organizes forensic intelligence across five specialized views:

| Analytical Tab | Features & Forensic Capabilities |
| :--- | :--- |
| **1. Threat Incidents** | Interactive incident cards displaying source IP, duration, calculated priority scores, prominent 3-stage MITRE ATT&CK kill-chain progression, transparent score calculations, impacted internal targets, and prescriptive remediation playbooks. |
| **2. Attack Timeline** | Chronological Plotly scatter plot mapping detected events against kill-chain stages over time, accompanied by an audit trail table with UTC timestamps and forensic findings. |
| **3. Network Topology** | Interactive directed NetworkX communication graph with SOC color coding (red threat actors, amber victims, cyan normal hosts), node connection metrics, and volume-ranked communicating host pairs. |
| **4. Flow Telemetry** | Donut charts for protocol distribution and firewall decisions (ACCEPT vs REJECT), targeted destination ports bar chart, and an interactive flow inspector with IP search and direction/action filtering. |
| **5. Forensic Dossier & Eval** | Live preview and one-click markdown export of formal investigation reports, alongside the scientific ground-truth evaluation table across all benchmark scenarios. |

---

## Zero Label Leakage Verification

In academic evaluation and benchmark testing, detection engines must remain completely isolated from ground-truth labels. NetSleuth guarantees zero label leakage:
- Detection heuristics in `detectors.py` operate strictly on `src_ip`, `dst_ip`, `dst_port`, `bytes`, and `timestamp`.
- The `test_zero_label_leakage` unit test executes the entire pipeline with and without the ground-truth `label` column, asserting identical alert counts, indices, and timestamps:
```python
def test_zero_label_leakage():
    df_with_label, _ = load_flows("data/synthetic/scenario4_multi_stage.csv")
    df_no_label = df_with_label.drop(columns=["label"])
    alerts_with = run_all_detectors(df_with_label)
    alerts_without = run_all_detectors(df_no_label)
    assert len(alerts_with) == len(alerts_without)
```

---

## Project Structure

```text
NetSleuth/
├── README.md                                  # Enterprise documentation and architecture guide
├── requirements.txt                           # Core dependencies (pandas, streamlit, plotly, etc.)
├── app.py                                     # Tactical SOC Streamlit dashboard (5 analytical tabs)
├── src/
│   └── netsleuth/
│       ├── __init__.py                        # Package initialization
│       ├── config.py                          # Thresholds, scoring weights, and MITRE metadata
│       ├── loader.py                          # Ingestion, schema validation, and sanitization
│       ├── detectors.py                       # 3 sliding-window heuristic threat detectors
│       ├── incidents.py                       # Correlation, 0-100 scoring, and dossier generation
│       ├── graph.py                           # NetworkX graph and Plotly topology visualization
│       ├── evaluation.py                      # Quantitative benchmark metrics (Precision, Recall)
│       └── synthetic.py                       # Deterministic synthetic scenario generation (Seed 42)
├── data/
│   └── synthetic/                             # 8 benchmark scenarios (224 to 320 records each)
│       ├── scenario1_port_scan.csv            # External vertical reconnaissance probe
│       ├── scenario2_host_scan.csv            # Internal lateral SMB sweep
│       ├── scenario3_data_exfiltration.csv    # Outbound asset theft
│       ├── scenario4_multi_stage.csv          # Multi-stage intrusion (Full kill chain)
│       ├── scenario5_benign.csv               # Baseline normal traffic (Zero false alarms)
│       ├── scenario6_persistent_threat.csv    # Temporal session boundary test (12m pause)
│       ├── scenario7_coordinated_attack.csv   # Dual attacker coordinated intrusion
│       └── scenario8_cloud_data_breach.csv    # Massive 12 MB database exfiltration
├── tests/
│   └── test_netsleuth.py                      # 10 automated unit tests (Pytest)
├── docs/
│   ├── NetSleuth_Academic_Project_Report.docx # Complete 15-page academic project report (.docx)
│   ├── NetSleuth_Academic_Project_Report_preview.pdf # Native 15-page PDF preview
│   ├── CLAUDE_REPORT_MASTER_PROMPT.md         # Copy-paste master prompt for Claude LLM
│   ├── netsleuth_architecture.png             # Multi-stage architecture diagram
│   ├── DESIGN.md                              # System design and scoring model specification
│   ├── DEMO_SCRIPT.md                         # 3-minute faculty presentation script & Viva Q&A
│   └── PRESENTATION_SLIDES.md                 # 12-slide comprehensive presentation deck
└── screenshots/                               # High-resolution dashboard figures
    ├── soc_clean_top.png                      # Header banner, KPI bar, and incident summary
    ├── soc_clean_details.png                  # Score breakdown and containment playbook grid
    ├── soc_tab2_timeline.png                  # Chronological attack timeline scatter plot
    ├── soc_tab3_topology.png                  # Network host topology graph and traffic matrix
    ├── fig5_1_incidents_score.png             # Report figure 11.1 (SOC dashboard view)
    └── fig5_2_mitre_pipeline.png              # MITRE ATT&CK progression stepper
```

---

## Installation & Quickstart

### 1. Prerequisites
- **Python 3.10+** (tested and verified on Python 3.12)
- Git

### 2. Clone Repository & Install Dependencies
```bash
git clone https://github.com/NileshSethi/NetSleuth.git
cd NetSleuth
pip install -r requirements.txt
```

### 3. Run the Automated Unit Test Suite
Verify that all 10 unit tests pass on your environment:
```bash
pytest tests/ -v
```
Expected output:
```text
tests/test_netsleuth.py::test_port_scan_threshold_boundary PASSED        [ 10%]
tests/test_netsleuth.py::test_host_scan_threshold_boundary PASSED        [ 20%]
tests/test_netsleuth.py::test_exfiltration_threshold_boundary PASSED     [ 30%]
tests/test_netsleuth.py::test_benign_scenario_produces_zero_alerts PASSED [ 40%]
tests/test_netsleuth.py::test_incident_correlation_time_gap PASSED       [ 50%]
tests/test_netsleuth.py::test_scoring_hand_calculation PASSED            [ 60%]
tests/test_netsleuth.py::test_scoring_never_exceeds_100 PASSED           [ 70%]
tests/test_netsleuth.py::test_loader_drops_invalid_rows PASSED           [ 80%]
tests/test_netsleuth.py::test_zero_label_leakage PASSED                  [ 90%]
tests/test_netsleuth.py::test_mitre_mapping_and_forensic_dossier PASSED  [100%]
============================== 10 passed in 2.95s ==============================
```

### 4. Launch the Interactive SOC Dashboard
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`. Use the sidebar dropdown to switch between the 8 benchmark scenarios or inspect active threat milestones.

---

## Limitations & Operational Boundaries

1. **Synthetic Telemetry:** The benchmark scenarios are generated synthetically using a fixed random seed. While this ensures scientific reproducibility, enterprise production networks contain far more unpredictable background traffic.
2. **Fixed Threshold Demonstrators:** Detection thresholds (60s sliding window, 10 ports, 5 hosts, 500 KB) are demonstration values that would require environment-specific calibration in a live production network.
3. **Metadata-Only Analysis:** Flow logs record connection headers and byte counts only; deep packet payload inspection (e.g., detecting encrypted payload signatures or SQL injection text) is outside the scope of flow telemetry.
4. **Advisory Containment Playbooks:** Suggested remediation actions (AWS Network ACL drops, security group revocation) are generated as advisory standard operating procedures and are not executed automatically on cloud infrastructure.

---

## Academic & Course Context

- **Project Title:** NetSleuth: Lightweight Security Event Detection and Threat Analysis Dashboard
- **Course:** Cybersecurity and Cloud Computing (Capstone / Mini-Project)
- **Institution:** Department of Computer Science
- **Student Team:**
  - Nilesh Sethi (PRN: 24070122121)
  - Om Gadwe (PRN: 24070122125)
  - Nimhan Vedant (PRN: 24070122122)
  - Omkar Roundal (PRN: 24070122127)
- **Academic Year:** 2026

---

## References

1. Amazon Web Services. (2024). *Logging IP traffic using VPC Flow Logs*. Amazon VPC User Guide. [AWS Documentation](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
2. MITRE Corporation. (2024). *MITRE ATT&CK Enterprise Matrix for Network Infrastructure*. [attack.mitre.org](https://attack.mitre.org/)
3. National Institute of Standards and Technology (NIST). (2012). *Computer Security Incident Handling Guide* (Special Publication 800-61 Rev. 2). U.S. Department of Commerce.
4. Scarfone, K., & Mell, P. (2007). *Guide to Intrusion Detection and Prevention Systems (IDPS)*. NIST Special Publication 800-94.
5. Streamlit Inc. (2024). *Streamlit: Open-source app framework for Machine Learning and Data Science*. [docs.streamlit.io](https://docs.streamlit.io/)
6. McKinney, W. (2010). *Data Structures for Statistical Computing in Python (Pandas)*. Proceedings of the 9th Python in Science Conference.
7. Hagberg, A., Swart, P., & Chult, D. (2008). *Exploring Network Structure, Dynamics, and Function using NetworkX*. Proceedings of the 7th Python in Science Conference.