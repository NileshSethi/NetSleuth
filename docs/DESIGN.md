# NetSleuth — Tactical System Design & Threat Intelligence Architecture

This document outlines the technical design, detection heuristics, MITRE ATT&CK framework mapping, and explainable scoring methodology behind **NetSleuth**, built for the university *Cybersecurity and Cloud Computing* course.

---

## 1. The Three Heuristic Detection Rules

NetSleuth uses three deterministic sliding-window heuristics to detect suspicious activity in cloud network flow records without relying on black-box statistical models.

| Rule Name | Window | Condition | Assigned Severity | Reason for Threshold Choice |
| :--- | :--- | :--- | :--- | :--- |
| **Port Scan** | 60 seconds | Single source IP connects to $\ge 10$ distinct destination ports on one target IP | `MEDIUM` | Standard client software talks to 1 or 2 service ports; 10 distinct ports in a minute indicates automated port probing or service discovery (Nmap). |
| **Host Scan** | 60 seconds | Single source IP connects to $\ge 5$ distinct destination IPs on the same destination port | `MEDIUM` | Workstations communicate with designated servers; hitting 5 separate peers on the same port in 60s indicates subnet sweeping or worm-like lateral spread. |
| **Data Exfiltration** | 120 seconds | Outbound traffic from one internal source to an external IP totals $\ge 500,000$ bytes (~500 KB) | `HIGH` | Bulk outbound uploads over a short two-minute window represent unusual data egress that warrants immediate analyst review. |

---

## 2. MITRE ATT&CK Enterprise Framework Alignment

Every detected alert is enriched with official MITRE ATT&CK enterprise techniques to contextualize the cyber kill chain:

| Detection Rule | MITRE Technique ID | Technique Name | MITRE Tactic | Cyber Kill Chain Stage |
| :--- | :--- | :--- | :--- | :--- |
| **Port Scan** | `T1046` | Network Service Discovery | Discovery (`TA0007`) | **Reconnaissance** |
| **Host Scan** | `T1018` | Remote System Discovery | Discovery (`TA0007`) | **Lateral Movement Prep** |
| **Exfiltration** | `T1048` | Exfiltration Over Alternative Protocol | Exfiltration (`TA0010`) | **Actions on Objectives / Theft** |

---

## 3. Incident Grouping & Correlation Rule

Isolated alerts are clustered into multi-stage incidents using spatial and temporal proximity:
- **Entity Grouping:** Alerts originating from the **same source IP** are linked.
- **Temporal Grouping:** If the gap between the end of one alert and the start of the next alert is **5 minutes (300 seconds) or less**, they belong to the same incident. Gaps exceeding 300s initiate a new incident.
- **Why 5 minutes?** Attackers conduct interactive sessions (reconnaissance $\rightarrow$ lateral spread $\rightarrow$ exfiltration) within minutes. A 5-minute inactivity gap represents a defensible operational session boundary.

---

## 4. Explainable Risk Scoring Formula

Incident risk is calculated as a transparent, additive sum bounded between **0 and 100**:

$$\text{Total Score} = \min\left(100, \text{Base Points} + \text{Extra Alert Points} + \text{Volume Points}\right)$$

### 1. Base Points (Highest Severity in Incident)
- `LOW`: 10 points
- `MEDIUM`: 30 points
- `HIGH`: 50 points

### 2. Extra Alert Points (Attack Complexity)
- **+10 points** for each additional alert beyond the first ($10 \times (N - 1)$). Multi-stage attacks pose greater risk than isolated warnings.

### 3. Volumetric Impact Points (Data Exfiltration Scale)
- **+20 points** if total exfiltrated outbound bytes $\ge 5,000,000$ bytes (~5 MB).
- **+10 points** if total exfiltrated outbound bytes $\ge 500,000$ bytes (~500 KB).
- **+0 points** if volume is below 500 KB or no exfiltration occurred.

### Priority Levels
- **0 to 29:** `Low` | **30 to 59:** `Medium` | **60 to 79:** `High` | **80 to 100:** `Critical`

---

## 5. Worked Scoring Example

### Scenario
An internal host `10.0.1.99` triggers three sequential alerts within a 5-minute window:
1. `port_scan` alert (Severity: `MEDIUM`, MITRE `T1046`)
2. `host_scan` alert (Severity: `MEDIUM`, MITRE `T1018`)
3. `exfiltration` alert (Severity: `HIGH`, MITRE `T1048`, total bytes = 6,300,000 bytes)

### Calculation Step-by-Step
1. **Base Points:** The highest severity is `HIGH` $\rightarrow$ **+50 points**.
2. **Extra Alerts:** $3 - 1 = 2$ extra alerts $\rightarrow 2 \times 10 =$ **+20 points**.
3. **Volume Points:** Total exfiltrated bytes is 6.3 MB ($\ge 5\text{ MB}$) $\rightarrow$ **+20 points**.
4. **Sum:** $50 + 20 + 20 = 90$ points.
5. **Capped Score:** $\min(100, 90) = \mathbf{90}$ points $\rightarrow$ **Critical Priority**.

The dashboard presents this calculation line-by-line alongside an emergency containment playbook for network defenders.
