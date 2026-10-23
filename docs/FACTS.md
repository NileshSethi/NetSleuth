# NetSleuth Lite — Verified Facts File

All numbers in this file come from a live execution of the code on 23 October 2026.
Nothing is estimated or rounded. Use these numbers in any report or presentation.

---

## 1. Project Identity

| Field | Value |
|---|---|
| Tool name | NetSleuth Lite |
| Full title | NetSleuth Lite: A Simple Explainable Network Attack Timeline and Threat Analysis Tool for Cloud Flow Logs |
| Language | Python 3.12.10 |
| Interface | Streamlit web dashboard |
| Data source | AWS VPC Flow Log-style CSV |
| Randomness seed | 42 (fixed; all results are deterministic) |

---

## 2. Lines of Code (actual file counts)

| File | Purpose | Lines |
|---|---|---|
| `src/netsleuth/config.py` | Constants and MITRE mappings | 67 |
| `src/netsleuth/loader.py` | CSV ingestion and validation | 51 |
| `src/netsleuth/detectors.py` | Three detection rules | 134 |
| `src/netsleuth/incidents.py` | Correlation, scoring, dossier | 252 |
| `src/netsleuth/evaluation.py` | Precision/recall evaluation | 46 |
| `src/netsleuth/synthetic.py` | Synthetic dataset generator | 240 |
| `src/netsleuth/graph.py` | Network topology visualisation | 144 |
| `app.py` | Streamlit dashboard | 534 |
| `tests/test_netsleuth.py` | Unit tests | 203 |
| **Total** | | **1,671** |

---

## 3. Detection Rule Thresholds (from config.py)

| Rule | Condition | Window | Severity | MITRE ID |
|---|---|---|---|---|
| Port Scan | >= 10 distinct ports on one host | 60 seconds | MEDIUM | T1046 |
| Host Scan | >= 5 distinct hosts on one port | 60 seconds | MEDIUM | T1018 |
| Data Exfiltration | >= 500,000 bytes outbound to one host | 120 seconds | HIGH | T1048 |

---

## 4. Scoring Formula Constants (from config.py)

| Constant | Value |
|---|---|
| Base score — LOW severity | 10 points |
| Base score — MEDIUM severity | 30 points |
| Base score — HIGH severity | 50 points |
| Extra points per additional alert (beyond first) | 10 points |
| Bonus — exfil bytes >= 5,000,000 (5 MB) | +20 points |
| Bonus — exfil bytes >= 500,000 (500 KB) | +10 points |
| Maximum allowed score | 100 |

Risk level bands: Low = 0–29, Medium = 30–59, High = 60–79, Critical = 80–100.

---

## 5. Incident Correlation Window

Alerts from the same source IP are merged into one incident if the gap between
the end of one alert and the start of the next is <= **300 seconds (5 minutes)**.

---

## 6. Benchmark Scenario Results (live execution)

### Scenario 1 — Port Scan

- **Attacker IP:** 198.51.100.55
- **Target:** 10.0.1.20
- **Total flows:** 238 (220 normal + 18 attack)
- **Dropped:** 0
- **Ports probed:** 18 distinct ports in 17 seconds
- **Alerts fired:** 1 (ALERT-001, port_scan, MEDIUM)
- **Incidents created:** 1 (INC-001)
- **Score:** 30 / 100 (Medium)
- **Score breakdown:** Base MEDIUM +30 pts
- **MITRE:** T1046 Network Service Discovery
- **Kill chain stage:** Reconnaissance

### Scenario 2 — Host Scan

- **Attacker IP:** 10.0.1.15
- **Target:** 12 hosts on port 445
- **Total flows:** 232 (220 normal + 12 attack)
- **Dropped:** 0
- **Hosts probed:** 12 distinct hosts in 22 seconds
- **Alerts fired:** 1 (ALERT-001, host_scan, MEDIUM)
- **Incidents created:** 1 (INC-001)
- **Score:** 30 / 100 (Medium)
- **Score breakdown:** Base MEDIUM +30 pts
- **MITRE:** T1018 Remote System Discovery
- **Kill chain stage:** Lateral Movement Prep

### Scenario 3 — Data Exfiltration

- **Attacker IP:** 10.0.1.45
- **Destination:** 203.0.113.88
- **Total flows:** 224 (220 normal + 4 attack)
- **Dropped:** 0
- **Data transferred:** 2,400,000 bytes (4 flows x 600,000 bytes) in 24 seconds
- **Alerts fired:** 1 (ALERT-001, exfiltration, HIGH)
- **Incidents created:** 1 (INC-001)
- **Score:** 60 / 100 (High)
- **Score breakdown:** Base HIGH +50 pts, Moderate exfil (2.4 MB >= 500 KB) +10 pts
- **MITRE:** T1048 Exfiltration Over Alternative Protocol
- **Kill chain stage:** Actions on Objectives

### Scenario 4 — Multi-Stage Attack

- **Attacker IP:** 10.0.1.99
- **Total flows:** 277 (250 normal + 27 attack)
- **Dropped:** 0
- **Stage 1:** Port scan — 13 ports on 10.0.1.20 in approx. 13 seconds (ALERT-001, MEDIUM, 832 bytes)
- **Stage 2:** Host scan — 8 hosts on port 80 in approx. 16 seconds (ALERT-002, MEDIUM, 512 bytes)
- **Stage 3:** Exfiltration — 6,300,000 bytes to 203.0.113.88 in approx. 36 seconds (ALERT-003, HIGH)
- **All 3 alerts within 275-second window, correlated into 1 incident**
- **Alerts fired:** 3 (ALERT-001, ALERT-002, ALERT-003)
- **Incidents created:** 1 (INC-001)
- **Total bytes in incident:** 6,301,344
- **Score:** 90 / 100 (Critical)
- **Score breakdown:**
  - Base HIGH +50 pts
  - 2 additional correlated alerts +20 pts
  - High-volume exfil (6,300,000 bytes >= 5 MB) +20 pts
  - Total: 90 / 100 (Critical)
- **MITRE techniques:** T1046, T1018, T1048
- **Kill chain stages:** Reconnaissance, Lateral Movement Prep, Actions on Objectives

### Scenario 5 — Benign Baseline

- **Total flows:** 320 (all normal)
- **Dropped:** 0
- **Alerts fired:** 0
- **Incidents created:** 0
- **False positives:** 0

---

## 7. Evaluation Metrics (flow-level ground truth)

| Scenario | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| Scenario 1 — Port Scan | 18 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| Scenario 2 — Host Scan | 12 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| Scenario 3 — Data Exfiltration | 4 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| Scenario 4 — Multi-Stage Attack | 27 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| Scenario 5 — Benign Baseline | 0 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |

All five scenarios achieve perfect precision and recall because the synthetic data is
generated by the same code that defines the thresholds. This is expected and is
stated honestly in the report.

---

## 8. Unit Test Results

- **Test runner:** pytest 9.1.1
- **Platform:** Windows, Python 3.12.10
- **Tests collected:** 10
- **Tests passed:** 10
- **Tests failed:** 0
- **Duration:** 3.58 seconds

### Test names

1. `test_port_scan_threshold_boundary`
2. `test_host_scan_threshold_boundary`
3. `test_exfiltration_threshold_boundary`
4. `test_benign_scenario_produces_zero_alerts`
5. `test_incident_correlation_time_gap`
6. `test_scoring_hand_calculation`
7. `test_scoring_never_exceeds_100`
8. `test_loader_drops_invalid_rows`
9. `test_zero_label_leakage`
10. `test_mitre_mapping_and_forensic_dossier`

---

## 9. MITRE ATT&CK Mappings (from config.py)

### T1046 — Network Service Discovery
- Tactic: Discovery (TA0007)
- Kill chain phase: Reconnaissance

### T1018 — Remote System Discovery
- Tactic: Discovery (TA0007)
- Kill chain phase: Lateral Movement Prep

### T1048 — Exfiltration Over Alternative Protocol
- Tactic: Exfiltration (TA0010)
- Kill chain phase: Actions on Objectives

---

## 10. Known Limitations (honest)

1. All data is synthetic and generated by the same code that sets thresholds.
2. Fixed sliding-window heuristics. Slow-and-low attacks below the threshold will not be detected.
3. No machine learning is used.
4. No real VPC Flow Logs were used in testing.
5. Exfiltration detector only checks direction == "OUTBOUND". Internal large transfers are ignored.
6. The scoring formula is additive and deterministic. It does not adapt to context or baselines.
