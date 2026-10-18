# Document 06: Implementation Roadmap & Milestones

## 1. Overview
This roadmap establishes a dependency-aware, disciplined 3-day engineering plan for NetSleuth. Each phase builds sequentially upon verified foundations, ensuring that working, testable software is achieved at every milestone.

---

## 2. Three-Day Implementation Schedule

### Day 1: Foundation, Ingestion & Heuristic Detection Engine
*Objective: Build robust parsing, deterministic test datasets, and core detection algorithms.*

- **Task 1.1: Schema & Ingestion Implementation**
  - Implement Pydantic/dataclass schema in `src/netsleuth/schema.py`.
  - Implement CSV parsing, UTC conversion, and validation in `src/netsleuth/parser.py`.
- **Task 1.2: Synthetic Dataset Generation**
  - Implement generator script to output reproducible scenarios in `data/synthetic/` (`SCN-BENIGN-01`, `SCN-PORTSCAN-02`, `SCN-HOSTSCAN-03`, `SCN-EXFIL-04`).
- **Task 1.3: Heuristic Detectors**
  - Implement Rule 1 (Vertical Port Scan) in `src/netsleuth/detectors.py`.
  - Implement Rule 2 (Horizontal Host Scan) in `src/netsleuth/detectors.py`.
  - Implement Rule 3 (Outbound Volume Spike) in `src/netsleuth/detectors.py`.
- **Task 1.4: Day 1 Unit Testing**
  - Add pytest test suite in `tests/test_parser.py` and `tests/test_detectors.py`.
- **Day 1 Minimum Acceptable Result:**
  - `pytest tests/` runs clean.
  - Feeding synthetic CSV into detection engine outputs structured Alert dictionaries with correct evidence.

---

### Day 2: Incident Correlation, Timeline & Streamlit Interface
*Objective: Correlate alerts into multi-stage incidents, build chronological timelines, and create the analyst dashboard.*

- **Task 2.1: Multi-Alert Incident Correlation**
  - Implement entity-based and temporal clustering in `src/netsleuth/correlation.py`.
  - Assign deterministic `incident_id`s.
- **Task 2.2: Chronological Timeline Reconstruction**
  - Merge contributing raw flow records with alert milestones in `src/netsleuth/timeline.py`.
  - Sequence events chronologically with attack stage tags.
- **Task 2.3: Directed Graph Topology Analysis**
  - Implement `networkx.DiGraph` construction and degree metrics in `src/netsleuth/graph_analysis.py`.
- **Task 2.4: Transparent Risk Scoring Engine**
  - Implement linear explainable priority scoring ($0–100$) in `src/netsleuth/scoring.py`.
- **Task 2.5: Interactive Streamlit Dashboard**
  - Build UI layout in `app.py`: scenario loader, threshold sliders, summary KPI cards, Plotly timeline view, interactive network graph, and incident drill-down.
- **Day 2 Minimum Acceptable Result:**
  - `streamlit run app.py` launches a fully interactive dashboard.
  - An analyst can upload or select synthetic data, see correlated incidents, inspect the timeline chart, and view the communication graph.

---

### Day 3: Benchmarking, Validation, Academic Report & Demonstration
*Objective: Scientific evaluation, bug fixing, report compilation, and presentation readiness.*

- **Task 3.1: Ground-Truth Evaluation Pipeline**
  - Implement precision, recall, F1, and confusion matrix calculation in `src/netsleuth/evaluation.py`.
  - Benchmark detectors against the 5 synthetic test scenarios.
- **Task 3.2: Defect Remediation & Edge Case Tuning**
  - Run full test suite, identify any false positives, and adjust default thresholds in `config.py`.
- **Task 3.3: Reporting Module**
  - Implement plain-text and Markdown incident export in `src/netsleuth/reporting.py`.
- **Task 3.4: Screenshot Capture & Documentation Finalization**
  - Capture real UI screenshots of the running dashboard into `screenshots/`.
  - Finalize the academic capstone report in `reports/` following `docs/08_REPORT_AND_DEMO_PLAN.md`.
- **Day 3 Minimum Acceptable Result:**
  - All tests passing with 0 errors.
  - Complete, professional college demonstration walkthrough prepared with verified metrics.

---

## 3. Critical-Path Analysis

The critical path through NetSleuth is:
$$\text{Schema/Parser} \longrightarrow \text{Synthetic Data} \longrightarrow \text{Detectors} \longrightarrow \text{Correlation} \longrightarrow \text{Timeline} \longrightarrow \text{Streamlit UI}$$

If any of these 6 steps fail, the end-to-end demonstration cannot function. Graph analysis and evaluation metrics, while important, are non-blocking enhancements to this spine.

---

## 4. 48-Hour Compressed Timeline (Contingency Fallback)

If unexpected delays reduce the implementation window from 72 hours to 48 hours, apply the following triage plan:

| Component | 72-Hour Standard Plan | 48-Hour Emergency Plan |
| :--- | :--- | :--- |
| **Synthetic Scenarios** | 5 comprehensive scenarios | 3 core scenarios (Benign, Port Scan, Blended) |
| **Detectors** | 3 rules (Port, Host, Volume) | 2 rules (Port Scan, Host Scan) |
| **Graph Visualization** | Interactive Plotly graph | Static NetworkX matplotlib plot or summary table |
| **Reporting Export** | Formatted Markdown & text exporter | On-screen Streamlit export table |
| **Evaluation** | Automated matrix calculation across all runs | Focused evaluation on 1 multi-stage scenario |
