# Document 07: Testing and Evaluation Framework

## 1. Quality & Scientific Evaluation Objectives
The testing and evaluation framework for NetSleuth serves two critical purposes:
1. **Software Verification:** Ensuring code correctness, graceful handling of edge cases, schema compliance, and crash-resilience via automated `pytest` suites.
2. **Detection Evaluation:** Empirically measuring detection efficacy (Precision, Recall, F1 score, False Positive Rate) against labeled synthetic ground-truth datasets without label leakage.

> **ACADEMIC HONESTY RULE:**  
> Performance metrics must never be fabricated. In Phase 1, the framework defines the *methodology* and *metrics calculation formulas*. Actual numbers will be calculated in Phase 6 based on real execution.

---

## 2. Unit & Integration Test Matrix

All tests will reside in the `tests/` directory and run via `pytest -v`.

| Test Category | Test File | Test Case Description | Expected Result |
| :--- | :--- | :--- | :--- |
| **Ingestion** | `test_parser.py` | Valid standard CSV with 1,000 clean flow rows. | Returns DataFrame of 1,000 rows sorted by UTC timestamp. |
| **Ingestion** | `test_parser.py` | Missing required column (e.g., missing `dst_port`). | Raises `ValidationError` with descriptive message. |
| **Ingestion** | `test_parser.py` | Corrupted IP strings (e.g., `999.999.1.1` or `invalid_ip`). | Discards malformed row, logs warning, processes remainder. |
| **Ingestion** | `test_parser.py` | Non-ISO-8601 or unparseable timestamp string. | Discards malformed row, records error counter. |
| **Ingestion** | `test_parser.py` | Missing values (NaNs in `bytes` or `action`). | Imputes default or discards based on strict schema policy. |
| **Ingestion** | `test_parser.py` | Completely empty CSV file (0 bytes or header only). | Returns empty typed DataFrame without crashing. |
| **Ingestion** | `test_parser.py` | Duplicate identical `event_id` rows. | Deduplicates records, preserving first chronological instance. |
| **Detection** | `test_detectors.py` | Benign traffic baseline (normal web browsing). | Zero alerts triggered. |
| **Detection** | `test_detectors.py` | Single IP probing 20 ports on 1 target within 60s. | Triggers 1 `RULE-PORT-SCAN` alert with correct evidence. |
| **Detection** | `test_detectors.py` | Port probes spaced across 30 minutes (exceeding window).| Zero alerts triggered (sliding window boundary test). |
| **Detection** | `test_detectors.py` | Single IP sweeping 15 distinct hosts on port 445 in 90s. | Triggers 1 `RULE-HOST-SCAN` alert with target list. |
| **Detection** | `test_detectors.py` | Outbound flow of 100 MB (`OUTBOUND`, `ACCEPT`). | Triggers 1 `RULE-EXFIL-SPIKE` alert. |
| **Detection** | `test_detectors.py` | Inbound flow of 100 MB (`INBOUND`, `ACCEPT`). | Zero alerts (direction filter test). |
| **Correlation**| `test_correlation.py`| Port scan and host scan alerts from same source IP. | Merges into 1 correlated `Incident` object. |
| **Timeline** | `test_timeline.py` | Timeline events generated from correlated incident. | Strict ascending timestamp order verified. |
| **Scoring** | `test_scoring.py` | Multi-alert incident vs. single-alert benign anomaly. | Multi-alert incident receives significantly higher score. |

---

## 3. Detection Evaluation Methodology

### Evaluation Unit Definition
To ensure statistical consistency and avoid confusing event-level flow volume with threat detections, NetSleuth defines the **Evaluation Unit** at two clearly separated levels:
1. **Alert-Level Metric:** Evaluates whether an individual detection alert correctly identified a malicious flow cluster.
2. **Scenario-Level Metric:** Evaluates whether a multi-stage attack scenario was detected and correlated without false alarm.

*Rule: Event-level packet counts must never be mixed with incident-level alert counts.*

### Ground-Truth Isolation
The synthetic dataset generator stamps evaluation columns:
- `is_attack`: Boolean (`True` / `False`)
- `attack_type`: String (`benign`, `port_scan`, `host_scan`, `exfiltration`)

These columns are stripped or ignored when passing data into `detectors.py`. Detection occurs purely on traffic metadata. Once alerts are generated, `evaluation.py` cross-references alert timestamps and involved IPs with the ground-truth annotations.

---

## 4. Formal Evaluation Metrics

NetSleuth computes standard information retrieval and classification metrics:

### 1. Confusion Matrix
- **True Positive ($TP$):** A malicious activity window was correctly flagged by a detection rule.
- **False Positive ($FP$):** Benign activity was incorrectly flagged as malicious.
- **False Negative ($FN$):** A malicious activity window occurred but was missed by detectors.
- **True Negative ($TN$):** Benign activity occurred and was correctly not flagged.

### 2. Precision
Measures the proportion of triggered alerts that were truly malicious (alert fidelity):
$$\text{Precision} = \frac{TP}{TP + FP}$$

### 3. Recall (Sensitivity / Detection Rate)
Measures the proportion of actual attacks that were successfully detected:
$$\text{Recall} = \frac{TP}{TP + FN}$$

### 4. F1 Score
The harmonic mean of precision and recall, balancing false alarms against missed detections:
$$\text{F1} = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$$

### 5. False Positive Rate (FPR)
$$\text{FPR} = \frac{FP}{FP + TN}$$

---

## 5. Benchmark Scenarios for Evaluation (Phase 6)

During Phase 6, evaluation metrics will be computed across the following test suites:
- **Benchmark Suite 1 (Clean Baseline):** 10,000 benign records $\rightarrow$ Expected $FP = 0$.
- **Benchmark Suite 2 (Reconnaissance Attacks):** 5,000 records containing 3 distinct vertical port scans $\rightarrow$ Measure Recall.
- **Benchmark Suite 3 (Discovery Sweeps):** 5,000 records containing 2 horizontal sweeps $\rightarrow$ Measure Recall.
- **Benchmark Suite 4 (Blended Complex Attack):** 20,000 records mixing benign enterprise traffic with an end-to-end intrusion kill chain $\rightarrow$ Measure Precision, Recall, F1.
