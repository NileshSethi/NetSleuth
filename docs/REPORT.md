# NetSleuth: Academic Capstone Project Report

**Course:** Cybersecurity and Cloud Computing  
**Project Title:** NetSleuth — An Explainable Network Threat Intelligence, Incident Timeline Reconstruction, and Forensic Analysis System  
**Author:** Student Project  
**Date:** October 2026  

---

## 1. Problem Statement

In contemporary enterprise and cloud computing architectures, network communication logs are generated at staggering scales. For example, cloud environments like Amazon Web Services (AWS) record every packet transition across virtual interfaces via AWS VPC Flow Logs. While these telemetry streams provide indispensable visibility into network operations, modern Security Operations Centers (SOCs) face four critical bottlenecks:

1. **Massive Telemetry Volume & Alert Fatigue:** Even a modest cloud deployment produces hundreds of thousands of flow records per hour. Traditional intrusion detection systems (IDS) generate disconnected alerts for isolated anomalies, leading to severe alert fatigue where critical breaches are lost in a sea of low-priority noise.
2. **Disconnected Kill Chain Events:** Sophisticated cyberattacks do not manifest as isolated events. A typical intrusion follows a structured multi-stage lifecycle: initial reconnaissance (vertical service port probing), lateral movement preparation (horizontal subnet sweeping), and actions on objectives (unauthorized data exfiltration). Traditional monitoring solutions frequently present these activities as three unrelated warnings, failing to correlate the overarching narrative.
3. **The "Black-Box" AI Dilemma:** Many modern commercial security platforms employ machine learning algorithms to flag anomalies. While capable of probabilistic detection, machine learning models frequently operate as opaque black boxes—they output an arbitrary risk score without explaining *why* an event was flagged. In enterprise security and compliance audits, security engineers cannot initiate high-impact containment actions (such as disconnecting a production database server) based on an unexplainable probability.
4. **Need for Accessible, Defensible Forensic Tools:** Many existing cybersecurity frameworks require distributed streaming clusters, heavy agent daemons, and complex configuration files. For students and practitioners seeking to understand core threat detection, event correlation, and digital forensics, there is a profound need for a transparent, defensible, and high-density defensive platform built from first principles.

NetSleuth was engineered to solve these challenges. It ingests cloud-style flow records, executes transparent sliding-window heuristics, maps alerts to official MITRE ATT&CK enterprise techniques, correlates isolated warnings into multi-stage incidents, calculates an explainable 0–100 risk score with a line-by-line point breakdown, and visualizes the attack progression within a tactical SOC dashboard.

---

## 2. System Design & Architecture

NetSleuth follows a modular, unidirectional data pipeline designed for maximum performance, maintainability, and zero external runtime dependencies.

```
[ Flow Log CSV ] ──► [ 1. loader.py ] ──► [ 2. detectors.py ] ──► [ 3. incidents.py ] ──► [ 4. app.py (SOC Dashboard) ]
                                                                             │
                                                               ┌─────────────┴─────────────┐
                                                               ▼                           ▼
                                                      [ MITRE ATT&CK & ]          [ Forensic Dossier & ]
                                                      [ 0-100 Scoring  ]          [ Plotly Topologies  ]
```

### 2.1 Core Architectural Modules

1. **Telemetry Ingestion & Sanitization (`src/netsleuth/loader.py`):**
   Reads CSV flow records into pandas DataFrames, verifies mandatory schema fields, standardizes timestamps into ISO-8601 UTC format, validates IPv4 syntax via `ipaddress`, drops corrupt records (such as negative byte counts or invalid port numbers outside 1–65535), and orders flows chronologically.
2. **Deterministic Threat Detectors (`src/netsleuth/detectors.py`):**
   Executes three sliding-window heuristics targeting port scans, host scans, and exfiltration spikes. Each detector outputs standardized alert dictionaries containing the rule name, severity, source IP, targeted assets, timestamps, plain-English finding sentences, and the exact row indices of contributing flow records. Ground-truth labels are completely inaccessible to detectors, preventing label leakage.
3. **Correlation, MITRE Alignment & Scoring (`src/netsleuth/incidents.py`):**
   Clusters alerts sharing the same source IP within a 5-minute inactivity window. Maps each alert to official MITRE ATT&CK techniques (`T1046`, `T1018`, `T1048`), determines the cyber kill chain progression, computes an additive 0–100 risk score, generates containment playbooks, and formats downloadable forensic investigation dossiers.
4. **Network Topology & Traffic Matrix (`src/netsleuth/graph.py`):**
   Builds a directed NetworkX graph of host-to-host communications and renders an interactive Plotly visualization that color-codes threat actors in radiant red (`#EF4444`), targeted victims in amber (`#F59E0B`), and benign hosts in cyan (`#38BDF8`). Computes an ordered communication matrix summarizing top network talkers.
5. **Scientific Evaluation Benchmarking (`src/netsleuth/evaluation.py`):**
   Performs flow-level ground-truth benchmarking across all synthetic scenarios to calculate True Positives, False Positives, False Negatives, Precision, Recall, and F1 scores.
6. **Tactical SOC Analyst Dashboard (`app.py`):**
   A high-density Streamlit application featuring dark tactical styling, glassmorphic metric cards, five analytical tabs, and one-click forensic report downloading.

### 2.2 Data Schema & Cloud Connection

NetSleuth accepts flow records modeled after **AWS VPC Flow Logs**:

| NetSleuth Column | AWS VPC Flow Log Field | Field Definition |
| :--- | :--- | :--- |
| `timestamp` | `start` / `end` | Event time normalized to ISO-8601 UTC format. |
| `src_ip` | `srcaddr` | Source IPv4 address of initiating network host. |
| `dst_ip` | `dstaddr` | Destination IPv4 address of targeted endpoint. |
| `dst_port` | `dstport` | Destination service port (1 to 65,535). |
| `protocol` | `protocol` | Transport layer protocol (e.g., TCP, UDP). |
| `bytes` | `bytes` | Total data volume transferred during the flow. |
| `action` | `action` | Firewall disposition (`ACCEPT` or `REJECT`). |
| `direction` | *Calculated* | Traffic orientation relative to subnet (`INBOUND`, `OUTBOUND`, `INTERNAL`). |
| `label` *(Optional)* | *Internal* | Ground-truth tag used strictly by `evaluation.py` for benchmark verification. |

In an operational AWS deployment, VPC Flow Logs are delivered to **Amazon S3** or streamed into **Amazon CloudWatch Logs**. NetSleuth's ingestion engine is architected to process these exact field structures.

---

## 3. Detection Rules, MITRE Mapping & Scoring

### 3.1 The Three Detection Heuristics

1. **Vertical Port Scan (`detect_port_scans`):**
   - *Heuristic:* A single source IP hits $\ge 10$ distinct destination ports on the same destination IP within a 60-second sliding time window.
   - *Severity:* `MEDIUM`.
   - *MITRE ATT&CK:* **T1046: Network Service Discovery** (Tactic: Discovery `TA0007`).
   - *Kill Chain Stage:* **Reconnaissance**.
   - *Rationale:* Normal client applications communicate with 1 or 2 specific ports. Rapidly querying 10 or more ports indicates automated scanning utilities (e.g., Nmap) seeking open services.
2. **Horizontal Host Scan (`detect_host_scans`):**
   - *Heuristic:* A single source IP connects to $\ge 5$ distinct destination IPs on the same destination port within a 60-second sliding time window.
   - *Severity:* `MEDIUM`.
   - *MITRE ATT&CK:* **T1018: Remote System Discovery** (Tactic: Discovery `TA0007`).
   - *Kill Chain Stage:* **Lateral Movement Preparation**.
   - *Rationale:* Internal endpoints rarely initiate connections to 5 separate peer computers on the same port in 60s. This pattern characterizes automated worm propagation or lateral reconnaissance across internal subnets.
3. **Outbound Data Exfiltration Spike (`detect_exfiltration`):**
   - *Heuristic:* Outbound traffic from an internal source IP to an external destination IP totals $\ge 500,000$ bytes (~500 KB) within a 120-second sliding time window.
   - *Severity:* `HIGH`.
   - *MITRE ATT&CK:* **T1048: Exfiltration Over Alternative Protocol** (Tactic: Exfiltration `TA0010`).
   - *Kill Chain Stage:* **Actions on Objectives / Data Theft**.
   - *Rationale:* Legitimate internal users generate small outbound web requests. Transmitting large volumes outbound in a short two-minute window represents suspicious egress requiring immediate triage.

### 3.2 Explainable Risk Scoring Formula

NetSleuth eliminates black-box obscurity by utilizing an additive, deterministic priority score bounded between 0 and 100:

$$\text{Risk Score} = \min\left(100, S_{\text{base}} + S_{\text{extra}} + S_{\text{volume}}\right)$$

Where:
- **Base Severity Points ($S_{\text{base}}$):** Highest alert severity in the incident (`LOW`: 10, `MEDIUM`: 30, `HIGH`: 50).
- **Attack Complexity Points ($S_{\text{extra}}$):** Adds **+10 points** for each additional alert in the incident beyond the first ($10 \times (N - 1)$).
- **Volumetric Impact Points ($S_{\text{volume}}$):** **+20 points** if exfiltrated outbound volume $\ge 5,000,000$ bytes (~5 MB); **+10 points** if $\ge 500,000$ bytes (~500 KB); **+0 points** otherwise.
- **Priority Tier:** `Low` ($<30$), `Medium` ($30-59$), `High` ($60-79$), `Critical` ($\ge 80$).

Each incident displays its exact point calculation alongside prescriptive emergency containment playbooks (e.g., AWS Security Group revocation, network isolation, host-based firewall blocking).

---

## 4. Experimental Results & Evaluation

The system was evaluated against five canonical benchmark datasets generated using fixed random seeds (Seed 42). Each dataset contains between 224 and 320 flow records, embedding realistic enterprise background traffic (web browsing, DNS queries, SSH administration, corporate email) alongside controlled threat patterns.

### 4.1 Quantitative Accuracy Benchmarks

Detection performance was evaluated at the flow level: a flow is classified as a True Positive (TP) if it is an attack flow and was captured within an alert's contributing flow list.

| Benchmark Dataset | Threat Profile | Total Flows | TP | FP | FN | Precision | Recall | F1 Score |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `scenario1_port_scan.csv` | External port probe on single host + normal traffic | 238 | 18 | 0 | 0 | **1.0000** | **1.0000** | **1.0000** |
| `scenario2_host_scan.csv` | Internal SMB subnet sweep + normal traffic | 232 | 12 | 0 | 0 | **1.0000** | **1.0000** | **1.0000** |
| `scenario3_data_exfiltration.csv` | High-volume outbound transfer + normal traffic | 224 | 4 | 0 | 0 | **1.0000** | **1.0000** | **1.0000** |
| `scenario4_multi_stage.csv` | Full kill chain (Port scan $\rightarrow$ Host sweep $\rightarrow$ Exfil) | 277 | 27 | 0 | 0 | **1.0000** | **1.0000** | **1.0000** |
| `scenario5_benign.csv` | Pure normal traffic (DNS, web, SSH, email) | 320 | 0 | 0 | 0 | **1.0000** | **1.0000** | **1.0000** |

### 4.2 Key Findings
1. **Zero False Positives:** In Scenario 5 (Benign Baseline), NetSleuth evaluated 320 normal flow records and raised zero false alarms ($\text{FP} = 0$), confirming that the heuristic thresholds cleanly filter normal enterprise activity.
2. **Complete Detection Coverage:** All attack flows across Scenarios 1–4 were detected without omission ($\text{FN} = 0$).
3. **Multi-Stage Incident Correlation:** In Scenario 4, the three separate alerts were successfully clustered into a single incident (`INC-001`) with a risk score of 90/100 (`Critical`), reconstructing the attacker's trajectory from initial discovery to data theft.

---

## 5. System Limitations

Academic honesty requires acknowledging operational boundaries:

1. **Synthetic Data vs. Enterprise Noise:** The benchmark datasets were generated using controlled random seeds. While they provide a verifiable baseline, real corporate networks exhibit chaotic file syncs, video conferencing spikes, and automated vulnerability scanners. Achieving 100% precision on synthetic data does not guarantee identical performance on live production networks.
2. **Assumed Thresholds:** The thresholds (60s window, 10 ports, 5 hosts, 500 KB) are assumed operational baselines chosen for demonstration. In a production environment, thresholds must be tailored to the organization's unique traffic baselines.
3. **No Packet Payload Inspection:** Flow logs record connection metadata (IPs, ports, protocols, byte counts) rather than full packet captures (PCAP). NetSleuth cannot detect attacks concealed within application payloads (e.g., SQL injection or Cross-Site Scripting).
4. **Batch Forensic Processing:** The current implementation processes static CSV logs in batch mode rather than consuming streaming Kafka or Kinesis feeds in real time.

---

## 6. Future Work

1. **Live Cloud Ingestion Connectors:** Integrate the AWS Boto3 SDK to automatically poll Amazon S3 buckets or stream from Amazon CloudWatch Logs.
2. **Dynamic Baseline Profiling:** Replace fixed heuristic thresholds with rolling statistical baselines ($\mu \pm 3\sigma$) computed over 24-hour training windows.
3. **Whitelist Management:** Provide a UI configuration to exempt approved network scanners and automated cloud backup services from triggering alerts.
4. **Automated Containment Execution:** Connect the remediation playbooks to AWS Lambda functions that automatically update Security Group ingress rules in response to Critical incidents.

---

## 7. Conclusion

NetSleuth demonstrates that explainable, rule-based cybersecurity analysis can deliver high-fidelity threat detection, multi-alert kill chain reconstruction, and defensible risk scoring without the opacity of black-box algorithms. By pairing clean Python architecture with MITRE ATT&CK framework alignment and an interactive tactical SOC dashboard, NetSleuth bridges the gap between cloud network flow telemetry and actionable digital forensics.
