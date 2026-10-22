# Document 12: Live Demonstration Script & Viva Defense Guide

This document equips the student with an exact, timed 5-minute live demonstration sequence, answers to the top 15 technical questions asked during college project evaluations, and a quick-reference CLI command cheat sheet.

---

## 1. Five-Minute Live Demonstration Walkthrough

When presenting before an evaluation panel or professor, adhere to the following sequence to showcase the system systematically:

```
[00:00 - 00:45] Step 1: Architecture & Lightweight Philosophy
[00:45 - 01:30] Step 2: Benign Baseline Demo (Zero False Alarms)
[01:30 - 02:30] Step 3: Reconnaissance Detection (Port Scan & Host Sweep)
[02:30 - 03:30] Step 4: Multi-Stage Incident Correlation & Explainable Scoring
[03:30 - 04:15] Step 5: Chronological Forensic Timeline & Host Graph
[04:15 - 05:00] Step 6: Scientific Evaluation Metrics & Q&A Transition
```

### Step 1: System Overview (0:00 – 0:45)
- **Action:** Open terminal and browser with NetSleuth running at `http://localhost:8501`.
- **Script:**
  > *"Good morning, evaluators. Today I am presenting NetSleuth: an explainable network attack timeline reconstruction and threat analysis system. In enterprise SOCs, analysts suffer from alert fatigue because traditional tools generate thousands of isolated alerts without showing the bigger picture. NetSleuth ingests cloud-style network flow logs, detects malicious reconnaissance and exfiltration heuristics using sliding temporal windows, clusters related alerts into unified incidents, and reconstructs a complete chronological forensic timeline with transparent, explainable priority scores. The entire system is built in Python with zero external cloud dependencies or black-box ML models."*

### Step 2: Benign Baseline Verification (0:45 – 1:30)
- **Action:** In the left sidebar under "Select Dataset Source", pick **"Scenario 1: Benign Enterprise Baseline"**.
- **Script:**
  > *"First, let's establish our baseline. I have loaded 200 normal enterprise flow records containing legitimate web browsing, DNS lookups, and administrative SSH sessions. Looking at the KPI cards at the top, NetSleuth processed all 200 valid flows with 0 malformed records and flagged exactly 0 alerts. This demonstrates that our sliding window thresholds are calibrated to prevent false alarms during normal business operations."*

### Step 3: Targeted Reconnaissance Detection (1:30 – 2:30)
- **Action:** Change the scenario selector to **"Scenario 2: Vertical Port Scan"**.
- **Script:**
  > *"Now let's simulate an adversary probing our network. I've switched to Scenario 2. The KPI cards instantly update: 1 alert was generated and correlated into Incident INC-001. Under Tab 1 (Incident Drill-Down), we see that an internal host `192.168.1.50` probed 25 distinct destination ports on database server `10.0.0.15` within a 42-second sliding window. Notice that NetSleuth displays the exact ports probed—ranging from standard SSH and HTTP ports to high ephemeral ports. The evidence is 100% transparent and reproducible."*

### Step 4: Multi-Stage Incident & Explainable Scoring (2:30 – 3:30)
- **Action:** Switch scenario selector to **"Scenario 5: Blended Multi-Stage Attack"**.
- **Script:**
  > *"Next, let's observe how NetSleuth handles a multi-stage advanced persistent threat (APT) campaign. In Scenario 5, an attacker executes a horizontal host sweep, pivots to a vertical port scan, and finally exfiltrates sensitive database dumps to an external command-and-control server. Instead of forcing an analyst to triage 3 disconnected alerts, NetSleuth's correlation engine automatically links these events into a single incident: INC-001. Look at our Explainable Risk Score breakdown: INC-001 received an 85 out of 100. We don't just give an opaque number—NetSleuth breaks it down: 50 points from multi-rule diversity (host scan + port scan + exfiltration), 10 points for target scope across 2 internal servers, and 25 points for exfiltrating 55 MB of data."*

### Step 5: Timeline Reconstruction & Topology Graph (3:30 – 4:15)
- **Action:** Click **"Tab 2: Chronological Timeline"**, then switch to **"Tab 3: Network Topology Graph"**.
- **Script:**
  > *"Under Tab 2, NetSleuth synthesizes an interactive chronological timeline interleaving the raw flow events with flagged alert milestones. An investigator can hover over each milestone to inspect timestamps, protocols, and transferred bytes. Switching to Tab 3, our NetworkX graph engine renders the communication topology. The malicious attacker IP `192.168.1.50` is automatically highlighted in red with a prominent high out-degree fan-out, making it immediately visible even in dense networks."*

### Step 6: Empirical Evaluation & Benchmarks (4:15 – 5:00)
- **Action:** Click **"Tab 6: Evaluation & Benchmarks"**.
- **Script:**
  > *"Finally, Tab 6 demonstrates our scientific evaluation against labeled ground truth. Importantly, our detectors operated completely blind to these labels to avoid data leakage. Across our benchmark suite, NetSleuth achieves a 100% precision with 0 false positives on benign traffic, and an overall F1 score of 0.947 on the blended attack scenario. We have 58 automated unit tests covering all components with 100% pass rate. Thank you, and I look forward to your questions."*

---

## 2. Top 15 Viva & Oral Examination Questions & Answers

### Q1: What is the core problem NetSleuth solves?
> **Answer:** "NetSleuth solves alert fatigue and forensic fragmentation in network security. Traditional intrusion detection systems emit atomic, disconnected alerts whenever an individual threshold is violated. Analysts are forced to manually correlate timestamps and IP addresses across disparate logs. NetSleuth automates this by ingesting raw flow logs, detecting reconnaissance and exfiltration heuristics, clustering related alerts into unified incidents, and reconstructing a clear, chronological forensic timeline with explainable priority scores."

### Q2: Why did you use heuristic detection instead of machine learning or deep learning?
> **Answer:** "We chose deterministic heuristic rules for three key reasons:
> 1. **Explainability & Auditability:** In digital forensics and compliance audits, an analyst must explain *exactly why* a flow was flagged (e.g., '25 ports probed in 42 seconds'). Machine learning models (especially neural networks) are black boxes that output opaque probability values.
> 2. **Zero Training / Data Dependency:** Heuristic rules require no labeled training datasets, preventing concept drift and eliminating adversarial evasion through data poisoning.
> 3. **Computational Efficiency:** Heuristics implemented with sliding-window aggregations in pandas run instantaneously without requiring GPU hardware or complex inference runtimes."

### Q3: What is 'Zero Label Leakage' and how did you enforce it?
> **Answer:** "Zero label leakage means that ground-truth labels (such as `is_attack`, `attack_type`, or `scenario_id`) are never accessed or referenced by our parser, detection algorithms, or correlation engines. The detectors run purely on real-world flow metadata: timestamps, IPs, ports, protocols, and byte counts. Ground-truth labels are isolated exclusively for post-hoc calculation of Precision, Recall, and F1 scores in `evaluation.py`."

### Q4: How does the sliding window algorithm work in your detectors?
> **Answer:** "In `detectors.py`, we sort flows chronologically by UTC timestamp. For each entity grouping (e.g., `src_ip` for host scans, or `(src_ip, dst_ip)` for port scans), we iterate through candidate flows and maintain a time window $\Delta t = t_k - t_{\text{start}} \le W$. We count the distinct destination ports or IPs within that rolling interval. If the unique count reaches or exceeds the threshold $\theta$ within window $W$, an alert is triggered, recording the start time, end time, and the IDs of all contributing flows."

### Q5: What is the computational complexity of your detection algorithms?
> **Answer:** "Sorting the $N$ flow records chronologically takes $O(N \log N)$. Filtering by grouping (e.g., source IP) using pandas hash indexing takes $O(N)$ amortized time. Within each group, iterating through the two-pointer sliding window takes $O(m)$ where $m$ is the number of flows in that group. Because $\sum m = N$, the overall time complexity of detection is dominated by sorting, which is $O(N \log N)$. Space complexity is $O(N)$ to store the flow records in memory."

### Q6: How does the correlation engine group alerts into an incident?
> **Answer:** "The correlation engine in `correlation.py` applies entity clustering and temporal proximity. First, it sorts alerts by start time. When examining an alert, it checks whether any existing incident shares the same source IP within a sliding window of 300 seconds. Second, it performs pivot chaining: if an alert's target IP matches a host that was recently compromised and subsequently acted as a scanner in another alert, both alerts are merged into a single multi-stage incident."

### Q7: Explain your priority scoring formula. Why is it linear?
> **Answer:** "We use a transparent additive formula bounded between 0 and 100:
> $$\text{Score} = \min(100, S_{\text{rules}} + S_{\text{targets}} + S_{\text{volume}})$$
> We chose a linear model because every point is directly attributable:
> - Rule diversity ($0–40$ pts) rewards detecting multiple tactics (e.g., port scan + exfiltration).
> - Target scope ($0–30$ pts) scales by 5 points per distinct victim host.
> - Volumetric impact ($0–30$ pts) awards 5 points per 10 MB exfiltrated.
> Analysts can inspect the exact point contribution for each category without guessing."

### Q8: How does NetSleuth distinguish internal private traffic from external traffic?
> **Answer:** "In `graph_analysis.py` and `detectors.py`, we implemented `is_private_ip()` which checks IP membership against the three standard IETF RFC 1918 subnets: `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`. This avoids false classifications where documentation IPs (like `203.0.113.0/24`) might be misidentified by default Python helpers."

### Q9: What happens if an attacker performs a 'low-and-slow' scan over several days?
> **Answer:** "A low-and-slow scan (e.g., probing 1 port every 2 hours) falls outside our 60-second sliding window $W$. This is an inherent trade-off of sliding-window algorithms: shorter windows minimize memory usage and catch rapid scans, while wider windows detect slow scans but increase state memory. In NetSleuth, the window duration is a configurable parameter in `config.py` and via sidebar sliders, allowing analysts to expand the window to 3600 seconds or more for deep threat hunting."

### Q10: How do you handle malformed or corrupted CSV records?
> **Answer:** "Our parser `parser.py` implements defensive data sanitization:
> 1. It validates the presence of all 10 canonical columns; missing columns trigger a `SchemaValidationError`.
> 2. It parses ISO-8601 timestamps and converts them to UTC.
> 3. It checks that IP addresses are valid IPv4 strings, port numbers are integers within $[1, 65535]$, and byte counts are non-negative.
> 4. In default mode, malformed rows are dropped and logged to `ParserTelemetry`; in strict mode, any malformed row raises an exception."

### Q11: What are the evaluation results across your synthetic benchmark scenarios?
> **Answer:** "Across our five benchmark scenarios:
> - On Scenario 1 (Benign Baseline), we achieved a 0% False Positive Rate (100% Precision).
> - On Scenarios 2, 3, and 4 (Port Scan, Host Sweep, Exfiltration), we achieved 100% Precision, 100% Recall, and an F1 score of 1.0.
> - On Scenario 5 (Multi-stage Blended APT), we achieved 100% Precision and 90% Recall ($F_1 = 0.947$), missing only a few low-volume border flows.
> All 58 unit tests pass in 7.26 seconds."

### Q12: Why are flow logs used instead of full packet captures (PCAP)?
> **Answer:** "In high-throughput cloud networks (10–100 Gbps), storing full packet payloads is cost-prohibitive, introduces severe privacy and compliance risks (recording unencrypted PII or passwords), and requires massive processing infrastructure. Flow logs provide transport-level metadata (IPs, ports, protocols, bytes, action) which is lightweight, preserves privacy, and contains sufficient behavioral telemetry to detect reconnaissance and volumetric exfiltration."

### Q13: Could NetSleuth be deployed in a live AWS environment?
> **Answer:** "Yes. While the MVP operates on local CSV files to guarantee reproducible academic defense, the schema was intentionally designed around AWS VPC Flow Logs (Version 2). In production, an AWS Lambda function triggered by new S3 flow log deliveries could feed records into NetSleuth's `load_and_validate_flow_csv()` parser via an S3 stream."

### Q14: How does the network topology graph help an analyst?
> **Answer:** "The NetworkX directed graph in Tab 3 maps the communication structure of the network. Each node represents an IP address and edges represent traffic flow. The graph computes In-Degree, Out-Degree, and Degree Centrality. In reconnaissance attacks, the scanning host displays an abnormally high Out-Degree (fan-out) to dozens of internal nodes. NetSleuth automatically highlights suspected attacker nodes in red, allowing an analyst to visually identify compromised hosts in seconds."

### Q15: What are the main limitations of your project, and what would you improve next?
> **Answer:** "The main limitations are:
> 1. It cannot inspect packet payloads (e.g., detecting SQL injection or malware signatures inside an HTTP payload).
> 2. It currently processes static batch files rather than continuous live socket streams.
> In future work, we plan to implement live streaming ingestion via Apache Kafka or AWS SQS, adaptive threshold tuning using statistical baselines, and automated STIX/TAXII threat intelligence sharing."

---

## 3. Quick Reference Command Cheat Sheet

| Purpose | Terminal Command |
| :--- | :--- |
| **Run Streamlit Dashboard** | `streamlit run app.py` |
| **Run Entire Test Suite** | `pytest tests/ -v` |
| **Run Fast Test Suite** | `pytest tests/ -q` |
| **Regenerate Synthetic Scenarios** | `python src/netsleuth/synthetic.py` |
| **Run Linter / Code Quality** | `ruff check src/ tests/` |
