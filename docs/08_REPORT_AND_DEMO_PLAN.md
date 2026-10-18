# Document 08: Academic Report Outline & Demonstration Plan

## 1. Overview
This document prepares a college student or researcher for academic submission and live project defense before an evaluation committee or professor. It contains a complete academic report outline, an 8-step live demonstration script, an oral defense preparation guide, and a list of target screenshots to capture once the UI is implemented.

---

## 2. Professor-Ready Academic Report Outline

### Chapter 1: Title & Abstract
- **Title:** *NetSleuth: An Explainable Network Attack Timeline Reconstruction and Threat Analysis System*
- **Abstract:** Concise 250-word summary highlighting the problem of network alert fatigue, the need for explainable threat detection, the methodology using synthetic cloud flow logs, algorithmic sliding-window heuristics, incident correlation, chronological timeline reconstruction, graph topology modeling, and empirical results.

### Chapter 2: Introduction & Motivation
- Growth of cloud computing and network telemetry (VPC Flow Logs, NetFlow).
- Challenges in modern Security Operations Centers (SOCs).
- Need for transparent, verifiable educational tools in digital forensics.

### Chapter 3: Problem Statement & Objectives
- Formal mathematical and logical statement of the correlation problem.
- Primary and secondary technical objectives.
- Scope and explicit boundaries of the prototype.

### Chapter 4: Background & Theoretical Concepts
- Network Protocols: IP addressing, TCP handshakes, port numbers, ephemeral communication.
- Cyber Kill Chain & MITRE ATT&CK: Reconnaissance, Discovery, Exfiltration.
- Sliding-window time-series aggregation algorithms.
- Graph Theory in Network Forensics: Directed graphs, degree centrality, fan-out/fan-in metrics.

### Chapter 5: System Architecture & Design
- Architectural philosophy: Modular unidirectional data pipeline.
- Component breakdown (`parser`, `detectors`, `correlation`, `timeline`, `graph`, `scoring`, `evaluation`).
- Mermaid architectural diagrams and data flow sequence.

### Chapter 6: Tools & Technologies
- Language: Python 3.10+.
- Data Structures & Analytics: `pandas`, `NetworkX`.
- Visualization & UI: `Streamlit`, `Plotly`.
- Testing: `pytest`, `ruff`.

### Chapter 7: Dataset & Simulation Methodology
- Structure of cloud flow logs.
- Synthetic generation approach with deterministic random seeds.
- Design of benign enterprise baseline vs. attack scenarios (Port scan, Host sweep, Exfiltration).
- Prevention of ground-truth label leakage.

### Chapter 8: Detection Rules & Algorithmic Heuristics
- Mathematical formulation of Rule 1 (Vertical Port Scan).
- Mathematical formulation of Rule 2 (Horizontal Host Scan).
- Mathematical formulation of Rule 3 (Outbound Volume Spike).
- Configurable thresholds and parameter tuning rationale.

### Chapter 9: Incident Correlation, Scoring & Timeline Synthesis
- Correlation logic: Entity matching and temporal proximity clustering.
- Chronological timeline reconstruction algorithm.
- Explainable priority scoring model (linear weighted formula).

### Chapter 10: Experimental Results & Evaluation
- Automated testing results across unit test matrix.
- Detection performance metrics: Precision, Recall, F1 score across benchmark suites.
- Analysis of detected true positives and edge-case behavior.

### Chapter 11: Limitations & Critical Analysis
- False-positive analysis (e.g., vulnerability scanners, large legitimate backups).
- Sensitivity to sliding window durations ("low-and-slow" evasions).
- Absence of payload inspection (metadata-only limitations).

### Chapter 12: Defensive Recommendations & Operational Guidance
- Recommended remediation steps when specific rules trigger.
- Security group and network ACL best practices.
- Role of defense-in-depth and endpoint detection (EDR).

### Chapter 13: Conclusion & Future Scope
- Summary of project achievements.
- Future work: Live AWS S3 VPC flow log ingestion, machine learning anomaly detection, STIX/TAXII export.

### References
- Formal IEEE/ACM formatted citations for academic papers, NIST standards, and open-source libraries.

---

## 3. Live 5-Minute Demonstration Sequence

During project defense, execute the following structured 8-step walkthrough:

1. **Step 1: Environment & Architecture Overview (30 sec)**  
   Show the clean project directory structure and explain the modular architecture in `src/netsleuth/`. Show that the application runs locally without live cloud dependency.
2. **Step 2: Load Benign Baseline Scenario (30 sec)**  
   Select `SCN-BENIGN-01` in the Streamlit UI. Point out that the detection engine processes the flows and reports **0 Alerts / Clean Status**, proving the baseline threshold prevents trivial false alarms.
3. **Step 3: Load Port Scan Attack Scenario (45 sec)**  
   Switch to `SCN-PORTSCAN-02`. Show how Rule 1 triggers. Highlight the exact alert evidence: *Source IP `192.168.1.50` probed 25 distinct ports on `10.0.0.15` in 42 seconds*.
4. **Step 4: Load Blended Multi-Stage Incident (60 sec)**  
   Load `SCN-BLENDED-05`. Show that multiple alerts (Host Scan $\rightarrow$ Port Scan $\rightarrow$ Exfiltration) were triggered.
5. **Step 5: Inspect Correlated Incident & Explainable Score (45 sec)**  
   Demonstrate that NetSleuth did not output 3 disconnected alerts, but clustered them into a single `Incident ID: INC-001`. Show the **Explainable Risk Score** widget explaining *why* the score is 85/100.
6. **Step 6: Forensic Timeline Reconstruction (45 sec)**  
   Show the Plotly interactive timeline. Walk the evaluator through the chronological progression: initial probe, discovery sweep, and outbound data spike.
7. **Step 7: Network Topology Graph (30 sec)**  
   Switch to the NetworkX graph tab. Show the compromised attacker node prominently highlighted in red with high out-degree connections.
8. **Step 8: Evaluation Metrics & Academic Conclusion (15 sec)**  
   Display the Evaluation tab showing computed Precision, Recall, and F1 scores against the labeled benchmark.

---

## 4. Planned Screenshots Checklist

Capture and place the following screenshots into `screenshots/` during Phase 7:
1. `screenshots/01_dashboard_landing.png`: Main Streamlit UI with sidebar controls and scenario selector.
2. `screenshots/02_benign_baseline_run.png`: Clean execution with 0 alerts on normal traffic.
3. `screenshots/03_port_scan_detection.png`: Alert evidence card displaying distinct scanned ports and timestamps.
4. `screenshots/04_correlated_incident_detail.png`: Correlated incident view with explainable score breakdown.
5. `screenshots/05_chronological_timeline_chart.png`: Interactive Plotly timeline showing attack lifecycle.
6. `screenshots/06_network_topology_graph.png`: NetworkX directed graph showing host relationships.
7. `screenshots/07_evaluation_metrics_table.png`: Precision, Recall, and Confusion Matrix summary.
