# NetSleuth — Master Implementation Task Checklist

This checklist tracks the end-to-end development of NetSleuth across its planned phases. 
Items marked `[x]` have been implemented and verified. Items marked `[ ]` represent planned tasks awaiting their respective development phases.

---

## Phase 1: Project Scaffolding & Architecture (CURRENT)
- [x] Inspect existing workspace and preserve user files.
- [x] Configure and verify root `.gitignore` to prevent credential or raw data leakage.
- [x] Create `.env.example` explaining local-only synthetic operation.
- [x] Create persistent developer/agent instructions (`AGENTS.md`).
- [x] Create dependency specifications (`requirements.txt` and `requirements-dev.txt`).
- [x] Create master implementation plan (`TASKS.md`) and version log (`CHANGELOG.md`).
- [x] Create comprehensive architectural and technical documentation suite in `docs/`:
  - [x] `01_PROJECT_BRIEF.md`
  - [x] `02_REQUIREMENTS_AND_SCOPE.md`
  - [x] `03_SYSTEM_ARCHITECTURE.md`
  - [x] `04_DATASET_SCHEMA.md`
  - [x] `05_DETECTION_RULES.md`
  - [x] `06_IMPLEMENTATION_ROADMAP.md`
  - [x] `07_TESTING_AND_EVALUATION.md`
  - [x] `08_REPORT_AND_DEMO_PLAN.md`
  - [x] `09_SETUP_AND_TROUBLESHOOTING.md`
  - [x] `10_DECISIONS_AND_ASSUMPTIONS.md`
  - [x] `11_PROJECT_STATUS.md`
- [x] Create directory scaffolding and directory documentation:
  - [x] `data/` (`raw/`, `processed/`, `synthetic/` + READMEs)
  - [x] `tests/` + README and `.gitkeep`
  - [x] `reports/` + README and `.gitkeep`
  - [x] `screenshots/` + `.gitkeep`
- [x] Create modular Python package structure in `src/netsleuth/` with typed placeholders:
  - [x] `__init__.py`
  - [x] `config.py`
  - [x] `schema.py`
  - [x] `parser.py`
  - [x] `detectors.py`
  - [x] `correlation.py`
  - [x] `timeline.py`
  - [x] `graph_analysis.py`
  - [x] `scoring.py`
  - [x] `evaluation.py`
  - [x] `reporting.py`
- [x] Create minimal Streamlit application placeholder (`app.py`).
- [x] Verify directory consistency, git-ignore rules, and documentation alignment.

---

## Phase 2: Input Validation, Parser & Synthetic Datasets (COMPLETED)
- [x] Define immutable schema and validation contracts in `src/netsleuth/schema.py`.
- [x] Implement robust CSV parser in `src/netsleuth/parser.py`:
  - [x] Column validation and missing column handling (`SchemaValidationError`).
  - [x] Timestamp parsing to UTC and chronological sorting.
  - [x] IP address formatting (IPv4) and port range validation (1–65535), non-negative byte count.
  - [x] Malformed line filtering, strict mode toggle, and error telemetry.
- [x] Implement deterministic synthetic dataset generator in `src/netsleuth/synthetic.py`:
  - [x] Scenario 1: Pure benign enterprise baseline (`scenario_01_benign.csv`).
  - [x] Scenario 2: Internal vertical port scan reconnaissance (`scenario_02_port_scan.csv`).
  - [x] Scenario 3: Horizontal discovery host sweep (`scenario_03_host_scan.csv`).
  - [x] Scenario 4: Suspicious high-volume outbound data exfiltration (`scenario_04_exfiltration.csv`).
  - [x] Scenario 5: Multi-stage blended APT attack (`scenario_05_blended_attack.csv`).
- [x] Save reproducible benchmark datasets in `data/synthetic/`.
- [x] Comprehensive unit tests (15 test cases passing) in `tests/test_parser.py`.

---

## Phase 3: Detection Engine (COMPLETED)
- [x] Implement Rule 1: Vertical Port Scan detector in `src/netsleuth/detectors.py`.
  - [x] Sliding time-window grouping by source IP and destination IP.
  - [x] Distinct destination port threshold check.
  - [x] Explainable alert payload with metadata and raw flow IDs.
- [x] Implement Rule 2: Horizontal Host Scan detector in `src/netsleuth/detectors.py`.
  - [x] Sliding time-window grouping by source IP.
  - [x] Distinct destination IP threshold check.
  - [x] Alert payload generation with evidence summary.
- [x] Implement Rule 3: Outbound Data Volume Spike detector in `src/netsleuth/detectors.py`.
  - [x] Flow direction filtering (`OUTBOUND`, `ACCEPT`).
  - [x] Byte threshold rolling volume spike detection.
  - [x] Alert payload generation with byte count and destination details.
- [x] Master orchestrator `run_all_detectors()`.
- [x] Unit tests for each detection rule in `tests/test_detectors.py` (11 passing tests).

---

## Phase 4: Event Correlation, Timeline & Scoring (COMPLETED)
- [x] Implement incident correlation engine in `src/netsleuth/correlation.py`:
  - [x] Group individual alerts sharing source IP or common targets within temporal proximity.
  - [x] Generate unique, deterministic `incident_id` identifiers.
  - [x] Generate narrative summaries and incident telemetry.
- [x] Implement chronological timeline builder in `src/netsleuth/timeline.py`:
  - [x] Merge raw contributing flows with detection alert events.
  - [x] Sort strictly by UTC timestamp.
  - [x] Annotate key inflection points (initial probe, lateral pivot, exfiltration burst).
  - [x] Extract Plotly-compatible event objects via `extract_timeline_events()`.
- [x] Implement explainable incident-priority scoring in `src/netsleuth/scoring.py`:
  - [x] Multi-factor transparent scoring model (rule severity, target breadth, data volume).
  - [x] Produce clear, human-readable scoring breakdown for analyst auditability.
- [x] Unit tests for correlation, timeline, and scoring (15 passing tests across `test_correlation.py`, `test_scoring.py`, `test_timeline.py`).

---

## Phase 5: Graph Analysis & Streamlit Analyst Dashboard (COMPLETED)
- [x] Implement NetworkX host communication graph in `src/netsleuth/graph_analysis.py`:
  - [x] Directed graph construction (source -> destination) with flow and byte weights.
  - [x] Node degree, centrality, RFC 1918 classification, and total traffic volume attribution.
  - [x] Interactive Plotly 2D topology figure generation with highlighted suspicious nodes.
- [x] Implement comprehensive Streamlit UI in `app.py`:
  - [x] Sidebar for custom CSV upload and 5 preset benchmark scenario selections.
  - [x] Configurable detector parameter sliders (sliding windows, port thresholds, byte volume limits).
  - [x] Top KPI summary metrics (total flows, valid/dropped flows, flagged alerts, correlated incidents, max threat score).
  - [x] Tab 1: Incident drill-down with explainable score breakdown and alert evidence details.
  - [x] Tab 2: Chronological incident timeline with interactive Plotly scatter/milestone chart.
  - [x] Tab 3: Interactive host communication topology graph and centrality metrics table.
  - [x] Tab 4: Forensic Markdown report preview and live download button.
  - [x] Tab 5: Searchable, filterable raw flow record table.
- [x] Forensic report generator in `src/netsleuth/reporting.py`.
- [x] Unit tests for graph analysis and reporting (9 passing tests across `test_graph_analysis.py` and `test_reporting.py`).

---

## Phase 6: Testing, Evaluation & Benchmarking (COMPLETED)
- [x] Implement evaluation metrics pipeline in `src/netsleuth/evaluation.py`:
  - [x] Compare detector alerts against separate ground-truth flow labels (`is_attack`, `attack_type`).
  - [x] Compute True Positives (TP), False Positives (FP), False Negatives (FN), True Negatives (TN).
  - [x] Calculate Precision, Recall, F1 Score, and False Positive Rate.
  - [x] Benchmark individual scenarios (`benchmark_scenario`) and batch suite (`benchmark_all_scenarios`).
- [x] Run automated pytest test suite covering all modules:
  - [x] Schema and ingestion tests (`test_parser.py` — 15 tests).
  - [x] Detector boundary and heuristic tests (`test_detectors.py` — 11 tests).
  - [x] Correlation clustering tests (`test_correlation.py` — 6 tests).
  - [x] Timeline sequencing tests (`test_timeline.py` — 4 tests).
  - [x] Explainable scoring tests (`test_scoring.py` — 5 tests).
  - [x] Network topology graph tests (`test_graph_analysis.py` — 6 tests).
  - [x] Forensic reporting tests (`test_reporting.py` — 3 tests).
  - [x] Scientific evaluation benchmark tests (`test_evaluation.py` — 8 tests).
  - [x] Full automated test suite passing (58 tests total, 100% pass rate).
- [x] Documented evaluation findings: 0 false positives on baseline (100% precision) and high detection recall on attack scenarios.

---

## Phase 7: Academic Report, Screenshots & Demonstration (COMPLETED)
- [x] Create screenshot catalog and visual walkthrough specifications in `screenshots/README.md`.
- [x] Author comprehensive, professor-ready academic mini-project report in `reports/academic_project_report.md` covering all 10 core chapters, mathematical formulations, and empirical benchmark findings.
- [x] Author live demonstration script, top 15 viva defense Q&A guide, and CLI cheatsheet in `docs/12_DEMO_AND_VIVA_GUIDE.md`.
- [x] Verify complete system workflow, tests (58/58 passing), and Streamlit application readiness.
