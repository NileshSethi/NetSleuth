# NetSleuth: Demonstration Script & Viva Defense Guide

This guide provides a structured 3-minute live demonstration script followed by the top 10 likely viva (oral examination) defense questions and concise answers.

---

## Part 1: The 3-Minute Live Demonstration Script

### Preparation
1. Open terminal and run: `streamlit run app.py`
2. Open browser at: `http://localhost:8501`
3. Maximize browser window to display the tactical dark SOC theme.

---

### Minute 1: Introduction, Cloud Telemetry & KPI HUD (0:00 – 1:00)

**What you say:**
> "Good morning, professors. Today I am presenting **NetSleuth**, an explainable threat intelligence and attack timeline reconstruction system designed for cloud network flow logs.
>
> In cloud platforms like AWS, VPC Flow Logs capture millions of network flow records. Security analysts face alert fatigue, disconnected alerts, and opaque machine learning algorithms that cannot explain why an event was flagged.
>
> As shown on screen, NetSleuth is designed like a tactical SOC defense center. In the sidebar, we can ingest live cloud CSVs or pre-built benchmark scenarios. Let us select **Scenario 4: Multi-Stage Attack**. Notice our top HUD metrics immediately reflect **277 Flow Records**, **3 Alerts Triggered**, **1 Correlated Incident**, **0 Corrupted Rows**, and an active Threat Posture of **CRITICAL**."

**What you do:**
- Point out the sidebar with the active heuristics and scenario selector.
- Select **Scenario 4 — Multi-Stage Attack**.
- Highlight the five top HUD metric cards.

---

### Minute 2: MITRE Kill Chain, Explainable Scoring & Playbooks (1:00 – 2:00)

**What you say:**
> "In **Tab 1: Threat Incidents**, notice how NetSleuth solves the disconnected alert problem. Instead of 3 isolated alarms, it correlates all actions from threat actor `10.0.1.99` into incident `INC-001`.
>
> Furthermore, it maps the attack to the **MITRE ATT&CK Enterprise Framework**:
> - `T1046 (Network Service Discovery)` for Reconnaissance,
> - `T1018 (Remote System Discovery)` for Lateral Movement Prep, and
> - `T1048 (Exfiltration Over Alternative Protocol)` for Data Theft.
>
> What makes NetSleuth unique is **total explainability**. Look at the risk score: **90 / 100 (Critical)**. We show the exact mathematical calculation: Base High severity (+50), two additional alerts (+20), and exfiltrated volume exceeding 5 MB (+20). Underneath, NetSleuth provides an emergency containment playbook directing the engineer to isolate the IP at the AWS Network ACL and revoke egress routes."

**What you do:**
- Show the container for `INC-001` in Tab 1, pointing out the MITRE Kill Chain stepper and line-by-line math breakdown.
- Highlight the Recommended Containment Playbook.
- Click **Tab 2: Attack Timeline** to display the Plotly chronological progression and audit log.

---

### Minute 3: Topology, Telemetry Inspector & One-Click Dossier (2:00 – 3:00)

**What you say:**
> "In **Tab 3: Network Topology**, we visualize the network communication graph. The threat actor is highlighted in red, targeted victims in amber, and benign internal hosts in cyan, supported by a Top Communicating Pairs matrix.
>
> In **Tab 4: Flow Telemetry**, analysts have deep visibility into TCP vs UDP distribution, firewall action ratios, targeted ports, and an interactive flow search bar.
>
> Finally, in **Tab 5: Forensic Dossier & Evaluation**, with a single click on **'Export Incident Dossier'**, an analyst can export a complete Markdown forensic dossier ready for executive briefing. Alongside it is our scientific benchmark evaluation table proving zero false positives on benign baseline traffic and 100% precision across all threat scenarios.
>
> In conclusion, NetSleuth turns overwhelming network flow logs into an actionable, visual, and defensible digital forensic narrative. Thank you, and I am ready for your questions."

**What you do:**
- Click **Tab 3: Host Topology & Matrix**, highlight the red attacker node and traffic table.
- Click **Tab 4: Flow Telemetry & Inspector**, highlight the protocol donut charts and top ports.
- Click **Tab 5: Forensic Dossier & Evaluation**, demonstrate the download button, dossier preview, and benchmark evaluation table.
- Conclude your presentation.

---

## Part 2: Top 10 Viva Questions & Concise Answers

### Q1: Why did you use deterministic heuristics instead of Machine Learning?
**Answer:**  
"Because in cybersecurity forensics and incident response, **explainability is mandatory**. Machine learning models frequently act as black boxes where analysts cannot explain *why* an event was flagged. Rule-based heuristics are deterministic, transparent, easy to audit, and allow analysts to defend critical containment actions to management and regulatory bodies."

---

### Q2: How does your project relate to Cloud Computing?
**Answer:**  
"In cloud platforms like AWS, VPC Flow Logs capture metadata for all IP traffic passing through cloud network interfaces. NetSleuth's CSV schema directly mirrors AWS VPC Flow Log fields such as `srcaddr`, `dstaddr`, `dstport`, `bytes`, and `action`. In a production setup, these logs are stored in Amazon S3 or CloudWatch, which this tool can ingest."

---

### Q3: What is the MITRE ATT&CK Framework and how did you use it?
**Answer:**  
"The MITRE ATT&CK framework is the global industry standard knowledge base of adversary tactics and techniques. We mapped each detection rule to its official MITRE ID: **T1046 (Network Service Discovery)** for port scans, **T1018 (Remote System Discovery)** for host scans, and **T1048 (Exfiltration Over Alternative Protocol)** for outbound data theft, reconstructing the attack across the Cyber Kill Chain."

---

### Q4: What is a False Positive and a False Negative?
**Answer:**  
- **False Positive (FP):** Normal, benign traffic that the system incorrectly flags as an attack (a false alarm).  
- **False Negative (FN):** An actual attack that evades detection and goes unnoticed.  
"A good security system aims to minimize both, but minimizing false positives is especially important to prevent analyst alert fatigue."

---

### Q5: How did you select your detection thresholds?
**Answer:**  
"The thresholds (10 ports in 60s for port scan, 5 hosts in 60s for host scan, and 500 KB in 120s for exfiltration) are **assumed heuristic baselines chosen for demonstration**. They reflect realistic differences between normal web browsing and automated attack tools. In a corporate environment, these thresholds would be tuned based on an organization's specific network baseline."

---

### Q6: How does your incident correlation logic work?
**Answer:**  
"It uses two conditions:
1. **Source Entity:** Alerts must originate from the same `src_ip`.
2. **Time Window:** The time gap between the end of one alert and the start of the next must be **5 minutes (300 seconds) or less**.  
This connects multi-stage actions—like reconnaissance and exfiltration—into a single incident."

---

### Q7: How is the risk score calculated? Can it exceed 100?
**Answer:**  
"The score is an additive sum of three factors:
1. **Base points:** The highest alert severity in the incident (Low: 10, Medium: 30, High: 50).
2. **Extra alerts:** +10 points for each additional alert beyond the first.
3. **Exfiltration volume:** +10 points if $\ge 500\text{ KB}$, or +20 points if $\ge 5\text{ MB}$.  
The final total is strictly capped at 100 using `min(100, score)`, so it can never exceed 100."

---

### Q8: What is 'label leakage' and how did you prevent it?
**Answer:**  
"Label leakage occurs when a detection algorithm accidentally reads the ground-truth answer (such as a `label` column) to make its decision. We prevent this by ensuring our detectors in `detectors.py` **never read or reference the `label` column**. The label is used exclusively by `evaluation.py` for benchmark verification. We have an automated unit test proving the detectors produce the exact same alerts when the label column is completely removed."

---

### Q9: What are the primary limitations of Network Flow Logs?
**Answer:**  
"Flow logs only record **metadata**—IP addresses, ports, protocols, and byte counts. They **do not capture packet payloads**. Therefore, flow logs cannot detect attacks hidden inside payload content, such as SQL injection, Cross-Site Scripting (XSS), or malicious file attachments. They are designed for network visibility and volumetric anomaly detection."

---

### Q10: What would you change or add if you deployed this on a real enterprise network?
**Answer:**  
"I would make three key additions:
1. Connect directly to live AWS S3 or CloudWatch log streams instead of static CSV files.
2. Implement **whitelisting** for approved network scanners, backup servers, and administrative tools.
3. Use **dynamic baselining** (calculating statistical moving averages for each host) rather than fixed static thresholds."
