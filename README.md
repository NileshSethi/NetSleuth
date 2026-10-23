# NetSleuth // Tactical Cyber Threat Intelligence & Incident Reconstruction

**NetSleuth** is an explainable network threat intelligence and digital forensic analysis platform designed for cybersecurity and cloud computing education. It ingests cloud-style network flow log records (simulating AWS VPC Flow Logs), flags multi-stage cyber threats using deterministic sliding-window heuristics, and correlates isolated alerts into cohesive incidents. The system maps each attack phase directly to the **MITRE ATT&CK Enterprise Framework**, calculates an explainable 0–100 risk score with a plain-English point breakdown, generates prescriptive containment playbooks, and exports downloadable forensic incident dossiers from an interactive, tactical SOC dashboard.

---

## Why It Matters

- **Solves Alert Fatigue:** Rather than overwhelming security analysts with fragmented alerts, NetSleuth links related malicious actions from the same threat actor into unified incidents.
- **Explainability Over Black-Box AI:** Many modern machine learning solutions output arbitrary risk scores without context. NetSleuth provides an explicit, additive mathematical breakdown explaining every single point added to an incident's score.
- **MITRE ATT&CK & Kill Chain Mapping:** Maps raw network flows to industry-standard adversary techniques (`T1046`, `T1018`, `T1048`) and reconstructs the narrative from initial reconnaissance to data theft.
- **Actionable Digital Forensics:** Provides emergency containment playbooks (e.g., AWS Security Group revocation, network isolation) and one-click downloadable Markdown forensic dossiers for executive and technical briefings.

---

## System Architecture

NetSleuth operates as a high-performance, unidirectional analytical pipeline:

```
[ Flow Log CSV ] ──► [ loader.py ] ──► [ detectors.py ] ──► [ incidents.py ] ──► [ app.py (SOC Dashboard) ]
                                                                     │
                                                       ┌─────────────┴─────────────┐
                                                       ▼                           ▼
                                              [ MITRE ATT&CK & ]          [ Forensic Dossier & ]
                                              [ 0-100 Scoring  ]          [ Plotly Topologies  ]
```

1. **Loader (`loader.py`):** Ingests CSV flow logs, validates schema fields, standardizes UTC timestamps, filters corrupt or impossible records (invalid IPs, negative byte counts, out-of-range ports), and sorts records chronologically.
2. **Detectors (`detectors.py`):** Runs three sliding-window heuristics targeting port scans, host scans, and outbound data exfiltration spikes with zero label leakage.
3. **Incidents (`incidents.py`):** Groups alerts originating from the same source IP within a 5-minute inactivity window, maps MITRE ATT&CK techniques, calculates an additive 0–100 priority score with a point breakdown, and formats exportable forensic dossiers.
4. **Graph (`graph.py`):** Constructs a directed communication graph using NetworkX and renders an interactive Plotly diagram highlighting threat actors (red), victims (orange), and benign peers (cyan), paired with a traffic communication matrix.
5. **Evaluation (`evaluation.py`):** Benchmarks detection accuracy against ground-truth labels across benchmark scenarios to compute True Positives, False Positives, False Negatives, Precision, Recall, and F1 scores.
6. **Dashboard (`app.py`):** A high-density 5-tab Streamlit SOC dashboard styled with tactical dark aesthetics, glassmorphic HUD metric cards, and interactive telemetry inspectors.

---

## Cloud Connection: AWS VPC Flow Logs

While NetSleuth processes local CSV files for reproducible offline analysis, its data schema directly simulates **AWS VPC Flow Logs**:

| NetSleuth Column | AWS VPC Flow Log Field | Field Description |
| :--- | :--- | :--- |
| `timestamp` | `start` / `end` | Event time normalized to ISO-8601 UTC format. |
| `src_ip` | `srcaddr` | Source IPv4 address of the connecting host. |
| `dst_ip` | `dstaddr` | Destination IPv4 address of the target host. |
| `dst_port` | `dstport` | Destination port number (e.g., 80, 443, 22, 445). |
| `protocol` | `protocol` | Transport protocol (mapped from IANA numbers: 6 = TCP, 17 = UDP). |
| `bytes` | `bytes` | Number of bytes transferred during the flow. |
| `action` | `action` | Network access rule disposition (`ACCEPT` or `REJECT`). |
| `direction` | *Calculated* | Determined by subnet orientation (`INBOUND`, `OUTBOUND`, `INTERNAL`). |

In an enterprise AWS deployment, VPC Flow Logs are automatically delivered to **Amazon S3** or streamed into **Amazon CloudWatch Logs**, which a cloud security pipeline would ingest and analyze using this exact logic.

---

## Project Structure

```text
NetSleuth/
├── README.md                 # Project architecture, cloud mapping, and execution guide
├── requirements.txt          # Core dependencies (pandas, streamlit, plotly, networkx, pytest)
├── app.py                    # 5-tab Tactical SOC Dashboard with custom CSS HUD
├── src/
│   └── netsleuth/
│       ├── __init__.py       # Package initializer
│       ├── config.py         # Heuristic thresholds, scoring weights, and MITRE metadata
│       ├── loader.py         # CSV ingestion, schema validation, and sanitization
│       ├── detectors.py      # 3 sliding-window heuristic threat detectors
│       ├── incidents.py      # Correlation, 0-100 scoring, MITRE mapping, and dossier generator
│       ├── graph.py          # NetworkX directed graph, Plotly visualization, and traffic matrix
│       ├── evaluation.py     # Ground-truth benchmark evaluation (Precision, Recall, F1)
│       └── synthetic.py      # Deterministic benchmark generator (Seed 42)
├── data/
│   └── synthetic/            # 5 canonical benchmark datasets (224 to 320 rows each)
│       ├── scenario1_port_scan.csv
│       ├── scenario2_host_scan.csv
│       ├── scenario3_data_exfiltration.csv
│       ├── scenario4_multi_stage.csv
│       └── scenario5_benign.csv
├── tests/
│   └── test_netsleuth.py     # 10 comprehensive pytest unit tests (100% passing)
├── docs/
│   ├── DESIGN.md             # 1-page architecture, MITRE mapping, and worked scoring formula
│   ├── REPORT.md             # 6-chapter formal academic project report (~1,900 words)
│   └── DEMO_SCRIPT.md        # 3-minute live demonstration script & top 10 viva defense Q&As
└── screenshots/              # Folder for application screenshots
```

---

## Installation & Quickstart

### 1. Prerequisites
- Python 3.10 or higher installed.

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Run the Automated Test Suite
```bash
pytest tests/ -v
```

### 4. Launch the Tactical SOC Dashboard
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

---

## Limitations

- **Synthetic Data:** Benchmark datasets were generated synthetically using controlled random seeds. While they provide a verified baseline, live corporate networks exhibit far more erratic background traffic.
- **Assumed Baselines:** Detection thresholds (60s window, 10 ports, 5 hosts, 500 KB) are assumed operational baselines and must be tuned to each organization's environment.
- **Expected High Benchmark Scores:** Perfect precision and recall on synthetic datasets are expected because the datasets were created to model these specific rules. It does not prove identical performance on live production networks.
- **No Packet Payload Inspection:** Flow logs record connection metadata only (IPs, ports, protocols, byte counts). Payload-based attacks like SQL injection or encrypted malware cannot be inspected.
- **Potential False Alarms:** In real-world enterprise environments, automated vulnerability scanners or cloud backup tools can mimic attack patterns unless whitelisted.

---

## Future Work

- **Live AWS Connectors:** Automated connectors to ingest VPC Flow Logs directly from Amazon S3 buckets or CloudWatch log groups via the AWS Boto3 SDK.
- **Dynamic Baselines:** Replacing static heuristic thresholds with statistical moving averages ($\mu \pm 3\sigma$) computed over 24-hour training windows.
- **Whitelist Configuration:** Allowing analysts to whitelist trusted administrative scanners and cloud backup agents.
- **Automated Incident Response:** Integrating playbooks with AWS Lambda to automatically isolate compromised instances or revoke security group rules upon Critical incident detection.