# NetSleuth Lite — VIVA Preparation Guide

This guide prepares you for an oral examination on the NetSleuth Lite project.
Read the code before your viva so you know where every function lives.

---

## Part 1 — Quick Reference Cheat Sheet

### What the project does (one sentence)

NetSleuth Lite reads an AWS VPC Flow Log CSV, detects three types of suspicious
network behaviour using counting rules, groups related alerts into incidents with
a 0-100 risk score, and displays everything in a Streamlit web dashboard.

### Three detection rules

| Rule | Trigger | Window | Severity | MITRE |
|---|---|---|---|---|
| Port Scan | >= 10 distinct ports on one host from one source | 60 s | MEDIUM | T1046 |
| Host Scan | >= 5 distinct hosts on one port from one source | 60 s | MEDIUM | T1018 |
| Exfiltration | >= 500,000 bytes outbound to one host from one source | 120 s | HIGH | T1048 |

### Score formula (memorise this)

```
score = min(100, base_severity + extra_alerts + exfil_bonus)

base_severity: LOW=10, MEDIUM=30, HIGH=50
extra_alerts:  10 x (number of alerts - 1)
exfil_bonus:   20 if total exfil bytes >= 5,000,000
               10 if total exfil bytes >= 500,000
```

### Scenario 4 score (the exam favourite)

50 (HIGH base) + 20 (2 extra alerts x 10) + 20 (6.3 MB >= 5 MB) = **90 — Critical**

### Incident correlation rule

Alerts from the same source IP are one incident if the gap between end of previous
alert and start of next alert is <= 300 seconds (5 minutes).

### File map

| File | What to say |
|---|---|
| `config.py` | All constants; change one number to change a threshold |
| `loader.py` | Reads CSV, validates IPs, ports, bytes; drops bad rows |
| `detectors.py` | Three functions, one per rule; sorted output with IDs |
| `incidents.py` | Groups alerts, scores, MITRE mapping, forensic dossier |
| `evaluation.py` | Compares detected row indices against label column |
| `synthetic.py` | Generates 5 deterministic test datasets with seed=42 |
| `graph.py` | NetworkX graph + Plotly visualisation |
| `app.py` | Streamlit UI with 5 tabs |
| `tests/test_netsleuth.py` | 10 unit tests, all pass |

---

## Part 2 — 25 Expected Viva Questions and Answers

### Basic Understanding

**Q1. What is a VPC Flow Log?**

A VPC Flow Log is a record kept by AWS of every network packet that enters or leaves
a virtual machine running in the cloud. Each record is one row in a CSV file. It shows
who sent data, who received it, which port, how many bytes, and whether it was allowed
or blocked.

**Q2. What is a port scan and why is it dangerous?**

A port scan is when an attacker sends connection attempts to many different ports on
one machine in a short time. Ports are like doors into a service. The attacker is
trying to find which doors are open. Open ports can be vulnerable to further attacks.
It is dangerous because it is usually the first step of a larger attack.

**Q3. What is a host scan?**

A host scan, also called a network sweep, is when an attacker probes the same port on
many different machines. The attacker wants to find all machines that are running a
particular service, for example, all machines with SMB file sharing open. This helps
them plan a lateral movement attack (moving from one machine to another inside the
same network).

**Q4. What is data exfiltration?**

Exfiltration means stealing data by sending it out of the network to a machine the
attacker controls. In this project, the tool looks for large outbound transfers.
If one machine sends 500 KB or more to the same external destination in 120 seconds,
that is flagged as a potential exfiltration.

**Q5. Why did you choose these three specific attacks?**

These three attacks are common first steps in a real attack chain. Port scanning and
host scanning are reconnaissance activities that happen before an attack escalates.
Exfiltration is the final goal of many attacks: stealing data. Together they cover the
beginning, middle, and end of an attack. They are also simple enough to detect with
counting rules and to explain clearly.

---

### Code-Level Questions

**Q6. Walk me through the code flow when a CSV file is loaded.**

The file is passed to `load_flows` in `loader.py`. The function reads it with
`pd.read_csv`, checks that all required columns are present, converts the timestamp
column to UTC datetime, converts port and bytes to numbers, removes rows with invalid
IP addresses, ports outside 1-65535, or negative bytes. Then it sorts by timestamp and
returns the clean DataFrame along with the number of dropped rows.

**Q7. How does the port scan detector work exactly?**

It groups the DataFrame by (source IP, destination IP). For each group it sorts by
timestamp. It uses a sliding window: it picks the first row as the window start, finds
all rows within 60 seconds, counts how many distinct destination ports are in that
window. If there are 10 or more, it raises an alert and moves the pointer past all rows
in the window. If there are fewer than 10, it moves the pointer by one row and tries
again.

**Q8. What is a sliding window and why is it used?**

A sliding window is a range of time that moves through the data. Instead of looking at
all traffic at once, the tool looks at a fixed-size time block (60 seconds for port and
host scans, 120 seconds for exfiltration). As the window slides forward in time, the
tool can catch attacks that happen quickly and continuously, even if they span many
rows in the CSV.

**Q9. What does the `score_incident` function return?**

It returns three things: the numeric score (0-100), the risk level string
(Low/Medium/High/Critical), and a list called `breakdown` that has one line of text
for each scoring step. The breakdown list is shown directly in the dashboard so the
user can verify the calculation.

**Q10. How does the 5-minute correlation window work?**

After all alerts are generated, `build_incidents` groups them by source IP. Within
each group, alerts are sorted by time. The function compares the end time of the
current alert with the start time of the next alert. If the gap is 300 seconds or less,
both alerts belong to the same incident. If the gap is more than 300 seconds, a new
incident starts. This is why all three stages of Scenario 4 become one Critical incident
even though they span 275 seconds.

**Q11. What is label leakage and how does your code prevent it?**

Label leakage is when a machine learning model or detection algorithm accidentally
reads the answer (the label) while it is trying to find the answer. In this project,
the synthetic CSV files have a `label` column that says whether each row is an attack
or normal. The detectors in `detectors.py` never look at the label column. They only
look at traffic fields like source IP, destination IP, port, bytes, and direction.
Unit test 9 proves this by running the detectors on a CSV with the label column and
without it, and verifying the alerts are identical.

**Q12. What does the evaluation module do?**

`evaluation.py` has one job: compare the set of row indices that the detector flagged
against the ground-truth label column. For each row: if it is labelled attack and
flagged, it is a True Positive. If it is labelled normal and flagged, it is a False
Positive. If it is labelled attack and not flagged, it is a False Negative.
Precision = TP / (TP + FP). Recall = TP / (TP + FN). F1 = harmonic mean.

**Q13. What does MITRE ATT&CK provide and how do you use it?**

MITRE ATT&CK is a list of tactics and techniques that real attackers use, with IDs.
In this project, each detection rule is mapped to one MITRE technique ID in `config.py`.
When an alert is created, the MITRE technique name, ID, tactic, and kill chain phase
are added to the alert dictionary. The dashboard shows these to the analyst so they
can understand what stage of an attack pattern they are seeing.

---

### Results and Evaluation

**Q14. Your evaluation shows 1.0 precision and recall on all scenarios. Is that a real result?**

It is a real result but it requires an honest explanation. The synthetic data was
designed by the same code that sets the thresholds. Each attack pattern deliberately
exceeds the threshold by a large margin. The benign traffic was designed to stay well
below the threshold. So the detector will always catch every attack and never flag any
normal traffic on these datasets. This is expected. On real network traffic, results
would be different and the thresholds would need tuning.

**Q15. What does a precision of 1.0 mean?**

Precision of 1.0 means every flow that the tool flagged as an attack was actually an
attack. There were zero false positives: the tool never accused a normal connection of
being suspicious.

**Q16. What does a recall of 1.0 mean?**

Recall of 1.0 means the tool caught every single attack flow. There were zero false
negatives: no attack went undetected.

**Q17. What is the F1 score and why use it?**

The F1 score is the harmonic mean of precision and recall. It is used as a single
combined measure of accuracy. A detector that flags everything would have high recall
but low precision. A detector that flags almost nothing would have high precision but
low recall. The F1 score is low if either precision or recall is low.

**Q18. What was the score for the multi-stage attack and explain why?**

Score 90, level Critical. The attacker IP 10.0.1.99 triggered three alerts within
275 seconds. The highest severity was HIGH (from the exfiltration alert) giving 50
base points. There were 2 additional alerts beyond the first, adding 20 points.
The exfiltration volume was 6,300,000 bytes which is above 5 MB, adding another 20
points. Total: 50 + 20 + 20 = 90.

**Q19. Why is Scenario 3 scored 60 and not higher?**

Scenario 3 has a single exfiltration alert with 2,400,000 bytes. The base score for
HIGH severity is 50. The bytes are above 500 KB (500,000) so 10 points are added.
But 2,400,000 is less than 5,000,000, so the +20 bonus does not apply.
There is only one alert so no extra-alert bonus. Total: 50 + 10 = 60, level High.

---

### Design and Architecture

**Q20. Why did you put all constants in config.py?**

Having one file for all constants makes the code easier to maintain. If a security
analyst wants to make the port scan rule stricter by raising the threshold from 10 to
15 ports, they change one number in one place. They do not have to search through
multiple files. It also makes it clear what values are configurable.

**Q21. Why Streamlit? What does it give you?**

Streamlit lets you build an interactive web dashboard entirely in Python without
writing any HTML or JavaScript. You write Python code, call Streamlit functions, and
a browser-based UI appears. For this project it provides tabs, charts, tables, file
upload, download buttons, and dropdowns with very little extra code.

**Q22. What does the network graph show?**

The graph is a directed network diagram where each node is a host IP address and each
edge (arrow) is a communication link. The colour of a node shows its role: red means
confirmed attacker, orange means targeted host, and cyan means a normal background
host. The graph uses the NetworkX library to build the graph structure and Plotly to
draw it. The layout algorithm (spring layout) places nodes that communicate frequently
close together.

**Q23. How did you make the tool deterministic?**

The synthetic data generator uses Python's `random` module with a fixed seed of 42.
This means the same data is generated every time the code runs. The graph layout also
uses `seed=42` in the NetworkX spring layout function. So the same CSV produces the
same alerts, the same incidents, and the same dashboard layout on every run.

---

### Hard Examiner Questions

**Q24. What would happen if the thresholds were wrong for a real environment?**

If the port scan threshold of 10 is too low for a real environment, normal activity
(like a monitoring tool checking many ports) could trigger false alarms. This would
annoy the security team and they might start ignoring alerts. This is called alert
fatigue and is a real problem in security operations. The right threshold depends on
the specific network and would need to be calibrated using real traffic data.

**Q25. If you had more time, what one change would improve this project the most?**

The most useful improvement would be testing on real AWS VPC Flow Logs, even a small
anonymised sample. This would reveal how many false positives the current thresholds
produce on real traffic and allow tuning. A second useful improvement would be replacing
the fixed thresholds with a simple baseline: measure the normal rate of port connections
per minute for each IP over a training period, and flag activity that deviates
significantly from that baseline.

---

## Part 3 — 30-Second Explanations for Key Concepts

### What is your project?

"NetSleuth Lite reads cloud network flow logs, applies three counting rules to find
suspicious activity, groups related alerts into incidents with a risk score from 0 to
100, and shows everything in a web dashboard. Every decision the tool makes can be
explained in one sentence."

### What is a sliding window?

"It is a time box that moves through the data. I look at 60 seconds of traffic at a
time. If I see 10 or more ports being probed in that 60-second box, I raise a port scan
alert. Then I move the box forward and check again."

### How is the score calculated?

"The score starts from the highest severity: HIGH gives 50 points, MEDIUM gives 30.
Then 10 points are added for each extra alert beyond the first. If a lot of data was
stolen, up to 20 more points are added. The total is capped at 100."

### What is MITRE ATT&CK?

"It is a public list of attack techniques used by real attackers, each with an ID like
T1046. I map my three detection rules to MITRE IDs so an analyst can look up more
information about the attack pattern the tool detected."

---

## Part 4 — Things You Must Be Able to Point to in the Code

Before your viva, open each file and be able to point to:

1. The threshold values in `config.py` — lines 4-14.
2. The IP validation in `loader.py` — the `is_valid_ipv4` function.
3. The sliding window loop in `detectors.py` — the `while i < n:` blocks.
4. The score formula in `incidents.py` — the `score_incident` function.
5. The correlation window check in `incidents.py` — `if gap_seconds <= INCIDENT_CORRELATION_WINDOW`.
6. The get_risk_level function in `incidents.py` — four if/return statements.
7. The evaluation TP/FP/FN calculation in `evaluation.py` — lines 22-28.
8. The dossier generation in `incidents.py` — `generate_forensic_dossier`.

---

*End of VIVA Preparation Guide.*
