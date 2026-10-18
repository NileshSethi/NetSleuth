# Document 01: Project Brief & Educational Scope

## 1. Project Identity
- **Project Name:** NetSleuth
- **Full Title:** NetSleuth: An Explainable Network Attack Timeline Reconstruction and Threat Analysis System
- **Academic Context:** 2–3 Day Undergraduate / Master's Cybersecurity Capstone Mini-Project
- **Target Domain:** Defensive Network Security, Digital Forensics, Cloud Incident Response, Applied Algorithms
- **Primary Language:** Python 3.10+

---

## 2. Background & Motivation
In modern cloud and enterprise architectures, infrastructure generates massive volumes of connection metadata, commonly referred to as network flow logs (such as AWS VPC Flow Logs, Google Cloud VPC Flow Logs, and Cisco NetFlow). These logs provide a high-level record of IP traffic going to and from network interfaces, detailing source IPs, destination IPs, ports, protocols, and transferred byte volumes.

When an intrusion occurs, Security Operations Center (SOC) analysts and digital forensic investigators must sift through millions of these records to reconstruct how the adversary entered the environment, what internal systems they surveyed, and whether data was stolen. 

However, junior analysts frequently encounter significant obstacles:
1. **Alert Fragmentation:** Security monitoring systems generate isolated alerts without showing the bigger chronological picture.
2. **"Black Box" Frustration:** Advanced machine-learning or proprietary SIEM systems frequently output risk scores without transparent mathematical or logical justification.
3. **Investigation Delay:** Manually correlating timestamps, IP addresses, and port numbers across spreadsheets is labor-intensive and error-prone.

NetSleuth was conceived as an explainable, deterministic analysis tool that transforms raw synthetic network-flow records into structured, correlated forensic stories with interactive graphs and chronological timelines.

---

## 3. Problem Statement
Given an unindexed, raw CSV file of network-flow records representing communication across an enterprise or cloud network segment over time:
- *How can an analyst rapidly distinguish between benign baseline communication and multi-stage suspicious activities?*
- *How can disparate detection events (e.g., reconnaissance followed by lateral probing followed by exfiltration) be correlated into a single, cohesive security incident?*
- *How can the progression of an attack be presented chronologically and topologically with 100% explainable evidence?*

---

## 4. Aim & Key Objectives

### Overall Aim
To develop a lightweight, modular, and explainable Python application that ingests simulated cloud-style network-flow records, detects suspicious communication patterns via configurable heuristics, correlates related alerts into unified incidents, reconstructs a chronological incident timeline, models host interactions via a directed graph, and presents findings in an intuitive analyst dashboard.

### Specific Technical Objectives
1. **Data Ingestion & Sanitization:** Parse and validate tabular network-flow data, handling corrupt fields, timestamp normalization (UTC), and IP validation.
2. **Explainable Heuristic Detection:** Implement three fundamental detection rules:
   - *Rule 1: Vertical Port Scan Detection* (scanning multiple ports on a single host).
   - *Rule 2: Horizontal Host Scan Detection* (sweeping multiple hosts on a network).
   - *Rule 3: Outbound Data Exfiltration Spike* (abnormal outbound byte transfer).
3. **Incident Correlation:** Cluster individual alerts sharing common entities (attacker IP, targeted subnet) within a defined temporal sliding window into named incidents.
4. **Chronological Forensic Timeline:** Sequence correlated events chronologically, generating a narrative log of attack progression.
5. **Graph Topology Analysis:** Construct a directed host-communication graph using NetworkX to map connections, calculate host centrality, and isolate affected assets.
6. **Transparent Incident Scoring:** Compute a clear, weighted priority score (0–100) with full mathematical explainability for each incident.
7. **Interactive Dashboard:** Build a local Streamlit interface allowing users to upload data, tune detection parameters, view timelines, and inspect network graphs.
8. **Empirical Evaluation:** Benchmark detection precision, recall, and F1 score against labeled synthetic test scenarios.

---

## 5. Scope & Boundary Conditions

### In-Scope (Phase 1–6 MVP Deliverables)
- Parsing local CSV flow records modeled after cloud VPC flow logs.
- Deterministic heuristic detection of port scans, host scans, and volumetric outbound anomalies.
- Rule-based incident correlation and timeline generation.
- Static and interactive directed graph representation using NetworkX and Plotly.
- Local Streamlit application running on localhost.
- Deterministic synthetic benchmark datasets representing both benign traffic and attack scenarios.
- Formal evaluation metrics (Precision, Recall, F1) computed against synthetic ground truth.

### Explicitly Out-of-Scope (To Guarantee 2–3 Day Delivery)
- Live packet capture (PCAP) or Deep Packet Inspection (DPI) of payload contents.
- Direct API connections to live cloud providers (AWS, Azure, GCP).
- Complex deep learning or opaque machine learning models.
- External database servers (PostgreSQL, MongoDB) or message brokers (Kafka).
- Automated remediation, firewall blocking, or host isolation.
- Multi-user authentication, RBAC, or enterprise cloud deployment.

---

## 6. How NetSleuth Differs From a Basic Scanner
Many entry-level student projects simply implement a single script that flags rows where `dst_port > X` or prints IPs that exceed a request count. NetSleuth differs significantly:
1. **Multi-Stage Incident Correlation:** Rather than outputting 50 disconnected alerts for 50 scanned ports, NetSleuth aggregates them into a single incident entity with associated evidence.
2. **Temporal Reasoning:** NetSleuth accounts for time windows and inter-event intervals, tracking the attack lifecycle from reconnaissance to action on objectives.
3. **Graph-Theoretic Perspective:** By modeling communication as a directed graph ($G = (V, E)$), NetSleuth visualizes fan-out, fan-in, and pivot behavior.
4. **Forensic Explainability:** Every alert and score is accompanied by an exact evidentiary breakdown: *why* it triggered, *which* threshold was crossed, and *what* flow IDs formed the proof.

---

## 7. Expected Deliverables
- A cleanly structured Python package (`src/netsleuth/`).
- Comprehensive documentation suite in `docs/`.
- Synthetic benchmark datasets with reproducible seeds in `data/synthetic/`.
- An interactive Streamlit dashboard (`app.py`).
- An automated unit test suite with high coverage (`tests/`).
- An academic project report and live demonstration guide (`docs/08_REPORT_AND_DEMO_PLAN.md`).

---

## 8. Expected Learning Outcomes
Upon completion and defense of this project, a student will have demonstrated mastery of:
- Network protocol fundamentals (IP addressing, TCP/UDP ports, flow volume metrics).
- Cyber kill chain phases (Reconnaissance, Lateral Movement, Exfiltration).
- Algorithmic sliding-window time-series aggregation in Python and pandas.
- Graph theory applied to cybersecurity topology analysis.
- Rigorous scientific evaluation methodology (Precision, Recall, F1, Confusion Matrices).
- Building professional, explainable cybersecurity decision-support tools.
