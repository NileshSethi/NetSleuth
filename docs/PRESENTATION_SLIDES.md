# NetSleuth Presentation Blueprint: Slide-by-Slide Content & Design Guide

This document provides a slide-by-slide guide for creating the final project presentation for **NetSleuth**. All facts, thresholds, formulas, and results match the verified project codebase and the final project report.

Each slide contains:
1. **Slide Title & Layout Type**
2. **Visual / Asset Guidance:** Which diagram, screenshot, or table to place on the slide.
3. **Exact On-Slide Content:** Bullet points, tables, and metric callouts formatted for slides (concise and punchy).
4. **Key Data & Numbers:** Exact verified values to highlight.
5. **Speaker Notes:** A spoken script in plain, simple English for whoever presents that slide.

---

## Slide 1: Title Slide (Project Introduction)

- **Slide Type:** Title & Cover
- **Visuals:** Dark background (`#0B0F19`), clean modern typography, project logo or network icon.
- **On-Slide Content:**
  - **Main Title:** NetSleuth
  - **Subtitle:** An Explainable Network Attack Timeline Reconstruction & Threat Analysis System for Cloud Flow Logs
  - **Course:** Cybersecurity and Cloud Computing (Course Code: `[COURSE CODE]`)
  - **Team Members:** `[STUDENT NAME(S) & ROLL NUMBER(S)]`
  - **Project Guide:** `[GUIDE NAME AND DESIGNATION]`
  - **Department & Institution:** `[DEPARTMENT NAME]`, `[COLLEGE / UNIVERSITY NAME]`
  - **Date:** October 2026
- **Speaker Notes:**
  > "Good morning, respected professors and evaluators. Today, our team is presenting NetSleuth, an explainable threat analysis and attack timeline reconstruction system designed for cloud network flow logs. In modern cloud environments, monitoring network traffic is crucial, but making sense of thousands of log records is challenging. NetSleuth solves this by converting raw connection logs into clear, explainable attack stories."

---

## Slide 2: Background & Cloud Relevance

- **Slide Type:** Concept & Context (2-Column Layout)
- **Visuals:** A diagram or graphic showing AWS VPC Flow Logs collecting traffic from EC2/Subnets.
- **On-Slide Content:**
  - **What are Network Flow Logs?**
    - Summaries of network connections (IP traffic going to and from network interfaces).
    - Records *metadata* only: Source IP, Destination IP, Port, Protocol, Packet/Byte counts, Timestamp, and Action (ACCEPT/REJECT).
    - Flow logs **do not** contain packet payloads or message contents.
  - **Cloud Shared Responsibility Model:**
    - Cloud providers secure the underlying hardware and network virtualization.
    - Customers are responsible for securing and monitoring their own virtual network traffic and workloads.
    - AWS VPC Flow Logs are the primary defensive telemetry available to cloud security teams.
- **Key Data to Display:**
  - Standard capture fields: `timestamp`, `src_ip`, `dst_ip`, `dst_port`, `protocol`, `bytes`, `action`, `direction`.
- **Speaker Notes:**
  > "Under the cloud shared responsibility model, Amazon Web Services secures the cloud infrastructure, but customers are responsible for securing the resources they run inside it. VPC Flow Logs record every connection attempt across network interfaces. However, flow logs only contain connection metadata—who talked to whom, on what port, and how much data was sent—without inspecting the contents of the packets. This makes flow log analysis both privacy-preserving and lightweight, but it requires smart analysis techniques."

---

## Slide 3: The Problem Statement (Alert Fatigue & Black Boxes)

- **Slide Type:** Problem & Pain Points (3 or 4 Card Grid)
- **Visuals:** Red/warning visual cues, contrasting a cluttered log view vs. a clear incident view.
- **On-Slide Content:**
  - **1. Information Overload:** Even a modest cloud deployment generates hundreds of thousands of flow records per day; manual inspection is impossible.
  - **2. Scattered & Isolated Alerts:** Basic security tools flag individual connections. An attack with 20 scan attempts produces 20 disconnected alerts, causing alert fatigue.
  - **3. Missing Attack Context:** Real cyber intrusions happen in stages (scanning -> lateral movement -> data exfiltration). Traditional tools show these as separate events rather than one connected story.
  - **4. 'Black Box' Machine Learning Scores:** Many modern tools output risk numbers from neural networks without explaining *why*. Security analysts cannot safely take remedial action without clear justification.
- **Speaker Notes:**
  > "Security analysts face four major roadblocks when working with flow logs. First, the sheer volume causes fatigue. Second, simple alerting tools produce a separate warning for every bad packet, drowning engineers in noise. Third, related events look unrelated—a scan, a sweep, and an upload appear as three unconnected pings rather than a single multi-stage intrusion. Finally, black-box machine learning systems often output a risk score with no explanation. Analysts need explainability to take immediate action."

---

## Slide 4: Project Objectives & Scope

- **Slide Type:** Solution Overview (Bullet List with Checkmark Badges)
- **Visuals:** NetSleuth icon and key technical badges (Python, Streamlit, NetworkX, MITRE ATT&CK).
- **On-Slide Content:**
  - **Project Goals:**
    - Detect three core suspicious behaviours using deterministic, configurable sliding windows.
    - Correlate related alerts from the same source into unified, coherent incidents using a session time-gap rule.
    - Compute a 100% transparent, explainable priority risk score (0 to 100) with line-by-line point accounting.
    - Reconstruct attack chronologies into interactive visual timelines and host communication graphs.
    - Provide an intuitive, interactive SOC investigation dashboard that runs on a single laptop without heavy infrastructure.
  - **Explicit Scope Boundaries:**
    - **In Scope:** CSV log parsing (AWS VPC format), rule-based detection, incident correlation, risk scoring, timeline, topology graph, synthetic benchmarking.
    - **Out of Scope:** Live cloud connections (AWS API / CloudWatch), payload inspection, deep learning, automated firewall blocking (advisory only).
- **Speaker Notes:**
  > "NetSleuth was built to overcome these challenges through a lightweight, transparent pipeline. Our goal was not to build a bloated system requiring complex cloud clusters, but a focused, mathematically explainable engine that runs directly on an engineer's workstation. We detect scans and data exfiltration, group them by attacker session, calculate a point-by-point score from 0 to 100, and present the findings in an interactive dashboard."

---

## Slide 5: System Architecture & Data Pipeline

- **Slide Type:** Architecture & Pipeline Flow
- **Visuals:** Insert Figure 3.1 from the project report (The 5-stage architectural pipeline).
- **On-Slide Content:**
  - **Five-Stage One-Way Processing Pipeline:**
    1. **Ingestion & Validation (`loader.py`):** Ingests CSV, validates IPv4 syntax, ensures ports $1\text{--}65535$ and bytes $\ge 0$, normalises timestamps to UTC, and sorts chronologically.
    2. **Sliding-Window Detectors (`detectors.py`):** Runs port scan, host scan, and data exfiltration rules; emits structured alerts with flow indices and human-readable sentences.
    3. **Correlation & Scoring Engine (`incidents.py`):** Groups alerts by source IP within a 300-second window, computes risk score, enriches with MITRE techniques, and formulates response playbooks.
    4. **Visualization Layer (`graph.py`):** Builds directed host topology with NetworkX; visualises communication matrices with tactical SOC color coding in Plotly.
    5. **SOC Investigation Dashboard (`app.py`):** Streamlit web UI providing 5 analytic tabs, forensic dossier markdown export, and ground-truth evaluation.
- **Key Codebase Statistic:**
  - Clean modular architecture: **1,671 lines of Python** across 9 files.
- **Speaker Notes:**
  > "Here is our system architecture. NetSleuth operates as a clean, one-way pipeline. Raw CSV flow logs enter the loader, which strips corrupted rows and orders records by time. The cleaned data flows through three independent sliding-window detectors. When alerts fire, the incident engine merges alerts from the same threat actor occurring within 5 minutes of each other, calculates the risk score, and maps MITRE techniques. Finally, everything is visualized in an interactive Streamlit dashboard."

---

## Slide 6: Detection Heuristics & MITRE ATT&CK Mapping

- **Slide Type:** Technical Specifications (Table Layout)
- **Visuals:** Clean 2-column or 4-row comparison table with severity badges (Medium: Amber, High: Red).
- **On-Slide Content:**
  - **Three Sliding-Window Detection Rules:**

| Behaviour | Sliding Window | Detection Threshold | Severity | MITRE ATT&CK Technique | Kill Chain Stage |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Port Scan** | 60 seconds | $\ge 10$ unique ports on 1 target host | **MEDIUM** | `T1046` (Network Service Discovery) | Reconnaissance |
| **Host Scan** | 60 seconds | $\ge 5$ unique target hosts on 1 port | **MEDIUM** | `T1018` (Remote System Discovery) | Lateral Movement Prep |
| **Data Exfiltration** | 120 seconds | $\ge 500,000$ bytes ($\approx 500\text{ KB}$) outbound | **HIGH** | `T1048` (Exfiltration Over Alt. Protocol) | Actions on Objectives |

  - **Why Heuristic Sliding Windows?**
    - Completely deterministic: No training data required, zero hallucinations.
    - Fast and auditable: Every alert outputs a plain-English explanation sentence (e.g., *"10.0.0.5 tried 14 different ports on 10.0.1.20 in 38 seconds"*).
- **Speaker Notes:**
  > "NetSleuth implements three core detection heuristics mapped directly to the industry-standard MITRE ATT&CK framework. Rule 1 identifies vertical port scans when an IP probes 10 or more ports on a single host in one minute. Rule 2 flags horizontal host sweeps when an internal machine reaches 5 or more hosts on the same port in 60 seconds. Rule 3 detects data exfiltration when outbound traffic to an external IP exceeds 500 kilobytes in two minutes. All thresholds are defined centrally in `config.py` for full auditability."

---

## Slide 7: Incident Correlation & Explainable Risk Scoring

- **Slide Type:** Mathematical Model & Logic
- **Visuals:** A visual formula card and tier breakdown boxes.
- **On-Slide Content:**
  - **Incident Grouping Logic:**
    - **Condition 1 (Same Origin):** Alerts must originate from the same `src_ip`.
    - **Condition 2 (Time Proximity):** Time gap between the end of one alert and start of the next must be $\le \mathbf{300\text{ seconds (5 minutes)}}$.
  - **Deterministic Risk Scoring Formula (0 to 100):**
    $$\text{Risk Score} = \min(100, \text{Base Points} + \text{Extra Alert Points} + \text{Volume Points})$$
  - **Scoring Components:**
    - **Base Severity Points:** Highest alert severity in incident ($\text{LOW} = 10, \text{MEDIUM} = 30, \text{HIGH} = 50$).
    - **Multi-Stage Progression Penalty:** $+10\text{ points}$ for every additional alert beyond the first: $10 \times (N - 1)$.
    - **Exfiltration Volume Points:** $+10\text{ pts}$ for $\ge 500\text{ KB}$; $+20\text{ pts}$ for $\ge 5\text{ MB}$.
  - **Priority Bands:**
    - **Low:** 0–29 | **Medium:** 30–59 | **High:** 60–79 | **Critical:** 80–100
- **Speaker Notes:**
  > "Rather than using an untraceable statistical score, NetSleuth's risk score is calculated using an additive formula that can be verified by hand in 10 seconds. We begin with base points from the most severe alert—for example, 50 points for high severity. We then add 10 points for each additional alert to penalize multi-stage attacks that progress through multiple phases of the kill chain. Finally, we add up to 20 points based on the volume of stolen data. The total is strictly capped at 100 and mapped into four priority bands."

---

## Slide 8: Worked Example Walkthrough (Scenario 4)

- **Slide Type:** Case Study / Walkthrough
- **Visuals:** Insert Figure 4.1 from the project report (The stacked bar score breakdown: $50 + 20 + 20 = 90$).
- **On-Slide Content:**
  - **Scenario 4: Multi-Stage Enterprise Intrusion:**
    - Threat Actor: Internal host `10.0.1.99`
  - **Attack Progression Across Time:**
    - **Stage 1 (T + 60s):** Port scan probing 13 ports on `10.0.1.20` -> Triggers `ALERT-001` (Medium, Reconnaissance).
    - **Stage 2 (T + 180s):** Host scan sweeping 8 internal hosts on port 80 -> Triggers `ALERT-002` (Medium, Lateral Movement).
    - **Stage 3 (T + 300s):** Exfiltration of 6 flows totaling **6,300,000 bytes (6.3 MB)** to external IP `203.0.113.88` -> Triggers `ALERT-003` (High, Data Theft).
  - **Correlation & Hand Calculation:**
    - Inter-alert time gaps ($\approx 108\text{s}$ and $106\text{s}$) are $< 300\text{s}$ -> Merged into **`INC-001`**.
    - **Base Points (HIGH):** $+50$
    - **Additional Alerts ($2 \times 10$):** $+20$
    - **Volume Points ($6.3\text{ MB} \ge 5\text{ MB}$):** $+20$
    - **Total Risk Score:** $\mathbf{50 + 20 + 20 = 90 / 100 \text{ (CRITICAL)}}$
- **Speaker Notes:**
  > "Here is a concrete walkthrough of Scenario 4. Threat actor 10.0.1.99 first probes 13 ports on an internal server. Two minutes later, the attacker scans 8 hosts on port 80 searching for other victims. Two minutes after that, the attacker transmits 6.3 megabytes out of the network to an untrusted external server. Because all three actions occur within 5-minute session windows, NetSleuth correlates them into single incident INC-001. The base score is 50, plus 20 points for 2 extra alerts, plus 20 points for high-volume exfiltration, yielding an explainable score of 90, classified as Critical."

---

## Slide 9: Interactive SOC Dashboard (Five Analytic Views)

- **Slide Type:** Product Showcase / UI Grid
- **Visuals:** Insert screenshots of the running dashboard (Figures 5.1, 5.2, 5.3, 5.4 from the report).
- **On-Slide Content:**
  - **Built with Streamlit & Plotly (Executive SOC Dark Command Center):**
  - **Pinned Executive Header & KPI Banner:**
    - Seamlessly pinned command banner displaying live telemetry KPIs (Flow Records, Alerts, Incidents, Posture).
  - **Prominent MITRE ATT&CK Cyber Kill Chain Progression:**
    - High-visibility 3-stage visual pipeline: Stage 1 (Reconnaissance - T1046) ➔ Stage 2 (Lateral Movement - T1018) ➔ Stage 3 (Objectives/Exfiltration - T1048).
    - Glowing active cyber badges indicate observed attack phases, while unobserved stages are marked clearly.
  - **Five Dedicated Investigation Tabs:**
    1. **Threat Incidents:** Prominent kill-chain progression, visual risk score bar, deterministic point breakdown, targeted hosts, and playbooks.
    2. **Attack Timeline:** Interactive chronological scatter plot mapping events across kill-chain stages and an audit trail.
    3. **Network Topology:** Directed host-to-host graph with color-coded nodes (**Red:** Attacker, **Amber:** Victim, **Cyan:** Normal hosts) with volume-formatted pair matrices.
    4. **Flow Telemetry:** Protocol and firewall disposition donut charts, top targeted ports bar chart, and searchable log explorer.
    5. **Forensic Dossier & Evaluation:** One-click export of formal Markdown dossiers alongside live ground-truth evaluation across 8 scenarios.
- **Speaker Notes:**
  > "All of this intelligence is delivered through an executive dark-themed SOC command center dashboard. At the very top, a pinned executive header displays real-time telemetry metrics and system threat posture. In Tab 1, rather than hiding MITRE labels in small badges, NetSleuth features a prominent 3-stage Cyber Kill Chain progression pipeline—instantly highlighting whether the threat was caught in early Reconnaissance or progressed to Lateral Movement and Data Exfiltration. The dashboard also features an interactive timeline in Tab 2, a wide-spaced network topology graph in Tab 3, deep protocol analytics in Tab 4, and one-click forensic dossier generation in Tab 5."

---

## Slide 10: Quantitative Benchmark Evaluation & Results

- **Slide Type:** Scientific Results & Data
- **Visuals:** Clean summary table displaying evaluation metrics across all 8 canonical and extended benchmark scenarios.
- **On-Slide Content:**
  - **Synthetic Test Evaluation (Fixed Random Seed 42):**

| Scenario File | Threat Profile | Total Flows | True Pos. (TP) | False Pos. (FP) | False Neg. (FN) | Precision | Recall | F1 Score | Incident Score |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Scenario 1** | Port scan probe (Reconnaissance) | 238 | 18 | 0 | 0 | **1.0000** | **1.0000** | **1.0000** | 30 (Medium) |
| **Scenario 2** | Internal SMB sweep (Lateral Movement) | 232 | 12 | 0 | 0 | **1.0000** | **1.0000** | **1.0000** | 30 (Medium) |
| **Scenario 3** | Outbound data exfiltration (Data Theft) | 224 | 4 | 0 | 0 | **1.0000** | **1.0000** | **1.0000** | 60 (High) |
| **Scenario 4** | Multi-stage full enterprise kill chain | 277 | 27 | 0 | 0 | **1.0000** | **1.0000** | **1.0000** | 90 (Critical) |
| **Scenario 5** | Benign baseline (Zero false positives) | 320 | 0 | 0 | 0 | **1.0000\*** | **1.0000\*** | **1.0000\*** | 0 (Clean) |
| **Scenario 6** | Persistent actor (Session split >300s) | 265 | 25 | 0 | 0 | **1.0000** | **1.0000** | **1.0000** | 30 & 70 (2 Incs) |
| **Scenario 7** | Coordinated multi-host intrusion (Dual) | 287 | 27 | 0 | 0 | **1.0000** | **1.0000** | **1.0000** | 30 & 70 (2 Incs) |
| **Scenario 8** | Cloud database breach (12 MB bulk exfil) | 230 | 10 | 0 | 0 | **1.0000** | **1.0000** | **1.0000** | 70 (High) |

  - **Key Evaluation Takeaways:**
    - **100% Mathematical Precision & Recall ($F_1 = 1.0000$):** Validated across 8 diverse attack patterns.
    - **Temporal Session Splitting (Scenario 6):** Proves that an attacker pausing for 12 minutes correctly splits into two isolated incidents (INC-001 and INC-002).
    - **Concurrent Multi-Host Intrusion (Scenario 7):** Demonstrates simultaneous tracking of external perimeter reconnaissance and an internal compromised host.
    - **High-Volume Tier Validation (Scenario 8):** Confirms that massive data transfer triggers the +20 pt volume penalty.
    - **Zero False Positives:** In benign traffic (320 flows), zero false alarms were raised.
- **Speaker Notes:**
  > "To thoroughly evaluate NetSleuth, we tested it across eight synthetic benchmark scenarios ranging from single reconnaissance probes to complex multi-attacker enterprise intrusions. Across all scenarios, the system achieved 100% precision and recall with zero false positives. Beyond the canonical scenarios, Scenario 6 proves our time-gap boundary logic by cleanly splitting a persistent attacker into two separate incidents after a 12-minute quiet gap. Scenario 7 demonstrates simultaneous tracking of external probes and an internal compromised host, while Scenario 8 tests large 12-megabyte cloud database theft. This proves that our deterministic heuristics are robust and fully explainable."

---

## Slide 11: Engineering Rigour & Automated Validation

- **Slide Type:** Code Quality & Verification
- **Visuals:** Terminal output snippet showing `pytest` passing 10/10 tests in 5.23 seconds.
- **On-Slide Content:**
  - **Comprehensive Automated Test Suite (`pytest`):**
    - **10 automated unit tests, 100% passing (0 failures).**
  - **Key Engineering Checks Verified:**
    - **Threshold Boundary Tests:** Proves that 9 ports trigger 0 alerts while 10 trigger an alert; 4 hosts trigger 0 alerts while 5 trigger an alert; 499,999 bytes trigger 0 alerts while 500,000 bytes trigger an alert.
    - **Session Gap Tests:** Proves that alerts 3 minutes apart merge into 1 incident, while alerts 13 minutes apart correctly split into 2 incidents.
    - **Data Sanitization:** Verifies that corrupted IP formats, out-of-range ports (e.g., 70,000), and negative byte counts are rejected.
    - **Zero Label Leakage (`test_zero_label_leakage`):** Mathematically proves that detectors produce identical alerts whether ground-truth label columns are present or completely stripped.
- **Speaker Notes:**
  > "To ensure rigorous engineering, we built an automated unit test suite with pytest. All 10 tests pass in 5.23 seconds. Crucially, we tested exact boundary conditions: 9 ports trigger zero alerts, while 10 ports trigger immediately. We also proved zero label leakage: detection logic operates exclusively on traffic metadata—timestamps, ports, and bytes. Even if the ground-truth answer key is completely removed, the detection output is 100% identical."

---

## Slide 12: Honest Limitations & Academic Discussion

- **Slide Type:** Academic Honesty & Critical Thinking
- **Visuals:** Alert/Notice styling with clean bullet cards.
- **On-Slide Content:**
  - **Honest Limitations (What NetSleuth Cannot Do):**
    - **Synthetic Data Baseline:** Test datasets were generated by the project itself; real production enterprise networks contain significantly higher ambient noise.
    - **Static Heuristic Thresholds:** Fixed numbers (10 ports, 5 hosts, 500 KB) are assumed operational baselines. A real SOC would need dynamic tuning.
    - **Evasion Vulnerability ('Low-and-Slow'):** An attacker who probes 1 port every 10 minutes or uploads data below 500 KB will evade fixed sliding-window rules.
    - **Metadata Only:** Because flow logs contain no packet payloads, application-layer attacks (such as SQL injection or cross-site scripting) cannot be detected.
    - **Batch Processing:** Currently processes uploaded CSV files rather than live streaming telemetry.
- **Speaker Notes:**
  > "In keeping with academic honesty, we highlight five real-world limitations. First, our 100% scores reflect synthetic datasets generated for testing; real enterprise networks are far noisier. Second, fixed thresholds can be bypassed by stealthy 'low-and-slow' attackers who space out their probes over hours. Third, because flow logs do not inspect packet contents, attacks hidden inside valid HTTP payloads are invisible. NetSleuth is designed as a foundational, transparent pipeline for understanding cloud flow logs, not a silver bullet."

---

## Slide 13: Future Work & Architectural Roadmap

- **Slide Type:** Future Enhancements (Roadmap Timeline)
- **Visuals:** Stepped timeline or 4 connected milestone cards.
- **On-Slide Content:**
  - **1. Live Cloud Streaming Ingestion:**
    - Direct integration with AWS S3 event notifications and Amazon Kinesis to stream live VPC Flow Logs in real time.
  - **2. Dynamic Baseline Tuning:**
    - Replace static constants with rolling statistical baselines (e.g., triggering alerts when traffic exceeds 3 standard deviations from a host's 7-day average).
  - **3. Enterprise Whitelisting & Exemption Engine:**
    - Allow administrators to exempt vulnerability scanners (like Nessus) and scheduled backup jobs from raising false alerts.
  - **4. Human-in-the-Loop Automated Remediation:**
    - Connect recommended playbooks directly to AWS APIs to apply Security Group drops or NACL blocks upon human analyst confirmation.
- **Speaker Notes:**
  > "For future work, we have defined four clear evolutionary steps. First, connecting NetSleuth directly to AWS S3 buckets to stream live cloud flow logs in real time. Second, introducing dynamic statistical baselines that adapt to each host's normal traffic patterns. Third, adding an enterprise whitelist so scheduled backup jobs and authorized security scanners don't trigger alerts. Finally, integrating automated response playbooks with AWS IAM to isolate compromised instances with one click."

---

## Slide 14: Conclusion & Key Takeaways

- **Slide Type:** Conclusion & Q&A
- **Visuals:** Strong closing summary card, GitHub repository link, and Q&A prompt.
- **On-Slide Content:**
  - **Summary of Achievements:**
    - Successfully built an explainable, lightweight security pipeline for cloud flow logs.
    - Replaced disconnected, noisy alerts with unified, multi-stage attack incidents.
    - Developed a transparent 0–100 risk scoring algorithm where every point is accounted for.
    - Designed an interactive SOC dashboard with timelines, network graphs, and exportable forensic dossiers.
    - Verified by 10 automated unit tests with zero label leakage.
  - **Repository:** `https://github.com/NileshSethi/NetSleuth.git`
  - **Questions & Discussion:**
    - Thank you for your time. We welcome your questions!
- **Speaker Notes:**
  > "In conclusion, NetSleuth demonstrates that cloud threat detection does not need to be an unexplained black box. By combining clean sliding-window rules, intelligent time-gap session correlation, and explainable additive scoring, NetSleuth turns overwhelming network logs into clear, actionable attack narratives. Thank you for your time and attention, and we are now ready for your questions."

---

## Quick Reference Table for Slide Designers

| Slide # | Slide Title | Key Visual / Asset to Embed | Main Takeaway |
| :---: | :--- | :--- | :--- |
| **1** | Title Slide | Dark enterprise background, NetSleuth logo | Clear project identity and course alignment |
| **2** | Background & Cloud Relevance | AWS VPC Flow Log architecture diagram | Shared responsibility & flow metadata principles |
| **3** | The Problem Statement | Visual comparison: Log clutter vs. Alert Fatigue | Why existing tools fail analysts |
| **4** | Project Objectives & Scope | Modern checkmark grid with scope limits | Explainability, correlation, and single-laptop execution |
| **5** | System Architecture | Figure 3.1 from report (5-stage data flow) | Clean 1,671-line modular Python pipeline |
| **6** | Detection Rules & MITRE Mapping | Structured 3-rule comparison table | T1046, T1018, and T1048 sliding windows |
| **7** | Correlation & Explainable Scoring | Mathematical formula card & 4 priority tiers | min(100, Base + Extra + Volume) explainability |
| **8** | Worked Example Walkthrough | Figure 4.1 from report (stacked score breakdown) | Scenario 4 hand calculation: 50 + 20 + 20 = 90 |
| **9** | Interactive SOC Dashboard | Figures 5.1–5.4 (Screenshots of 4 tabs) | Dark-theme SOC UI with 5 dedicated investigation views |
| **10** | Benchmark Evaluation & Results | Table 6.1 & 6.2 summary table | Perfect 1.0000 F1 score & 0 false positives |
| **11** | Engineering Rigour & Testing | Terminal snippet: 10/10 pytest passing | Boundary testing & zero label leakage verification |
| **12** | Honest Limitations | Clear alert cards with academic caveats | Synthetic data, fixed windows, metadata-only limits |
| **13** | Future Roadmap | 4-step progressive timeline | Streaming ingestion, dynamic baselines, AWS automation |
| **14** | Conclusion & Q&A | Summary highlights + GitHub repo link | Viva readiness and closing Q&A |
