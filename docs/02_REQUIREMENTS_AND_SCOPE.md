# Document 02: Requirements and Scope Specification

## 1. System Overview
NetSleuth is an explainable network attack timeline reconstruction and threat analysis tool. This document defines the functional and non-functional requirements, input/output contracts, operational constraints, and scope boundaries designed to ensure successful completion within a rigorous 2–3 day timeline.

---

## 2. Functional Requirements (FR)

### Ingestion & Data Preparation
- **FR-01: CSV Parsing:** The system shall ingest tabular network-flow records from standard CSV files.
- **FR-02: Schema Validation:** The system shall validate all required columns (`event_id`, `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `bytes`, `action`, `direction`) and reject or flag malformed rows without crashing.
- **FR-03: Temporal Normalization:** The system shall parse and normalize all timestamps into ISO-8601 UTC format and sort events chronologically.
- **FR-04: Boundary Tagging:** The system shall verify flow directional classification (`INBOUND`, `OUTBOUND`, `INTERNAL`).

### Detection Heuristics
- **FR-05: Vertical Port Scan Detection:** The system shall detect when a single source IP contacts $\ge N$ distinct destination ports on a single destination IP within a configurable sliding time window $T_{\text{port}}$.
- **FR-06: Horizontal Host Scan Detection:** The system shall detect when a single source IP contacts $\ge M$ distinct destination IPs within a configurable sliding time window $T_{\text{host}}$.
- **FR-07: Outbound Volume Anomaly Detection:** The system shall detect when an `OUTBOUND` flow exceeds a configurable byte threshold $B_{\text{exfil}}$ or statistical volumetric multiplier within time window $T_{\text{vol}}$.
- **FR-08: Alert Generation:** For each triggered rule, the system shall generate an alert structure containing rule ID, timestamp, entity identifiers, threshold parameters, and a list of contributing raw flow IDs.

### Correlation, Timeline & Analysis
- **FR-09: Incident Clustering:** The system shall correlate individual alerts that share an identical source IP or related target nodes within a correlation time window $T_{\text{corr}}$ into unified incidents.
- **FR-10: Incident Identifier:** Each correlated group shall receive a unique, deterministic `incident_id` (e.g., `INC-20261018-001`).
- **FR-11: Timeline Reconstruction:** The system shall assemble a chronologically ordered sequence of events for each incident, detailing phase transitions (e.g., reconnaissance $\rightarrow$ lateral movement $\rightarrow$ exfiltration).
- **FR-12: Communication Topology Graph:** The system shall construct a directed network graph where nodes represent IP hosts and edges represent flow activity (annotated with protocol, port count, and total byte volume).
- **FR-13: Explainable Risk Scoring:** The system shall assign each incident an explainable priority score ($0 \le S \le 100$) calculated from an explicit, documented linear formula of alert severities, target breadth, and data volume.

### Visualization & User Interface
- **FR-14: Dashboard KPI Summary:** The Streamlit dashboard shall display top-level metrics: total flows processed, total alerts flagged, correlated incidents, and average risk score.
- **FR-15: Interactive Parameter Tuning:** The UI shall provide sidebar controls allowing analysts to dynamically adjust detection thresholds ($N$, $M$, $B_{\text{exfil}}$, time windows) and re-run analysis on the fly.
- **FR-16: Visual Timeline Display:** The UI shall render an interactive timeline chart (Plotly) showing incident progression over time.
- **FR-17: Network Graph Display:** The UI shall render a host communication topology map highlighting flagged suspicious entities and high-volume edges.
- **FR-18: Incident Drill-Down:** The UI shall allow the analyst to inspect a specific incident, displaying its mathematical score breakdown and raw contributing flow records.

### Benchmarking & Evaluation
- **FR-19: Ground-Truth Evaluation:** The system shall evaluate detection performance against labeled synthetic datasets to calculate True Positives (TP), False Positives (FP), False Negatives (FN), Precision, Recall, and F1 Score.

---

## 3. Non-Functional Requirements (NFR)

- **NFR-01: Performance & Execution Speed:** The system shall process, analyze, and display a synthetic dataset of up to 100,000 flow records in under 5 seconds on a standard consumer laptop (Intel i5/AMD Ryzen 5, 8GB RAM).
- **NFR-02: Code Simplicity & Readability:** Code must adhere to PEP 8 standards, include type annotations, and maintain clean modular separation to facilitate oral defense and examination by academic evaluators.
- **NFR-03: Determinism & Reproducibility:** Given the same synthetic dataset and configuration parameters, all detection, correlation, and scoring algorithms must produce identical results across runs.
- **NFR-04: Robust Error Handling:** Invalid input records, unparseable dates, negative byte values, or empty files must be logged with meaningful error messages rather than causing unhandled runtime exceptions.
- **NFR-05: Zero External Network Dependency:** The application must run 100% offline without connecting to external cloud services, remote databases, or third-party APIs.
- **NFR-06: Security & Safety:** The system shall not execute active scans, shell commands, or network packet injection.

---

## 4. In-Scope vs. Out-of-Scope Boundary Matrix

| System Capability | In-Scope (MVP) | Out-of-Scope (Deferred) |
| :--- | :---: | :---: |
| Local CSV Flow Log Ingestion | ✅ | ❌ |
| Streaming Kafka / Kinesis Ingestion | ❌ | 🚫 Postponed |
| Deterministic Heuristic Detectors (Port/Host Scan, Volumetric Exfil) | ✅ | ❌ |
| Deep Learning / Black-box Neural Networks | ❌ | 🚫 Postponed |
| Rule-Based Temporal Incident Correlation | ✅ | ❌ |
| Multi-Cloud Cross-VPC API Integrations | ❌ | 🚫 Postponed |
| NetworkX Directed Communication Graph | ✅ | ❌ |
| 3D WebGL Live Graph Animation | ❌ | 🚫 Postponed |
| Transparent Linear Risk Scoring Formula | ✅ | ❌ |
| Automatic Firewall / IP Blocking | ❌ | 🚫 Prohibited |
| Local Streamlit Web UI | ✅ | ❌ |
| Microservice Architecture / Kubernetes Deployment | ❌ | 🚫 Postponed |

---

## 5. Input and Output Contracts

### Input Specification
- **Format:** Comma-Separated Values (`.csv`).
- **Encoding:** UTF-8.
- **Required Columns:** `event_id`, `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `bytes`, `action`, `direction`.
- **Ground-Truth Columns (for evaluation only):** `scenario_id`, `is_attack`, `attack_type` (must not be accessed by detection heuristics).

### Output Specification
- **Incident Summary Records:** Structured JSON/dictionary objects containing `incident_id`, `source_ip`, `target_ips`, `start_time`, `end_time`, `alert_count`, `risk_score`, and `severity`.
- **Chronological Timeline Table:** Ordered DataFrame containing timestamp, incident association, event category, description, and source-to-destination flow details.
- **Interactive Visualizations:** Plotly interactive HTML/Streamlit charts for timeline and network topology.
- **Evaluation Report:** Summary text/markdown detailing Precision, Recall, F1, and Confusion Matrix.

---

## 6. Time Constraints & 48-Hour Fallback Plan

Given the strict 2–3 day academic timeline, features are strictly stratified into three tiers:

### Tier 1: Critical Path MVP (Must Complete in 48 Hours)
1. Schema validation and CSV parser (`schema.py`, `parser.py`).
2. Deterministic synthetic dataset generator (`data/synthetic/`).
3. Port-scan and host-scan detection rules (`detectors.py`).
4. Basic incident correlation and timeline generation (`correlation.py`, `timeline.py`).
5. Core Streamlit dashboard with parameter sliders and timeline table (`app.py`).
6. Core unit tests (`tests/`).

### Tier 2: Standard Plan (Hours 48–72)
1. Outbound volume exfiltration detection rule.
2. NetworkX directed communication topology visualization.
3. Transparent incident-priority scoring module (`scoring.py`).
4. Evaluation module measuring precision/recall (`evaluation.py`).
5. Markdown incident report export (`reporting.py`).

### Tier 3: Optional Enhancements (Postpone if Time Permits)
1. Complex sub-graph community detection algorithms.
2. Multi-scenario comparative benchmarking views.
3. PDF automated report generation.
