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

## Phase 4: Event Correlation, Timeline & Scoring (PLANNED)
- [ ] Implement incident correlation engine in `src/netsleuth/correlation.py`:
  - [ ] Group individual alerts sharing source IP or common targets within temporal proximity.
  - [ ] Generate unique, deterministic `incident_id` identifiers.
- [ ] Implement chronological timeline builder in `src/netsleuth/timeline.py`:
  - [ ] Merge raw contributing flows with detection alert events.
  - [ ] Sort strictly by UTC timestamp.
  - [ ] Annotate key inflection points (e.g., initial probe, pivot, exfiltration burst).
- [ ] Implement explainable incident-priority scoring in `src/netsleuth/scoring.py`:
  - [ ] Multi-factor transparent scoring model (rule severity, target count, data volume).
  - [ ] Produce clear, human-readable scoring breakdown for analyst auditability.
- [ ] Unit tests for correlation and timeline reconstruction in `tests/test_correlation.py` and `tests/test_timeline.py`.

---

## Phase 5: Graph Analysis & Streamlit Analyst Dashboard (PLANNED)
- [ ] Implement NetworkX host communication graph in `src/netsleuth/graph_analysis.py`:
  - [ ] Directed graph construction (source -> destination).
  - [ ] Node degree, centrality, and total traffic volume attribution.
  - [ ] Highlighting of flagged suspicious nodes.
- [ ] Implement comprehensive Streamlit UI in `app.py`:
  - [ ] Sidebar for CSV upload or synthetic scenario selection.
  - [ ] Configurable detector parameter sliders (time window, port threshold, byte threshold).
  - [ ] Executive KPI summary metrics (total flows, flagged alerts, correlated incidents).
  - [ ] Chronological incident timeline view with interactive Plotly scatter/gantt charts.
  - [ ] Host communication topology view (interactive network graph).
  - [ ] Deep-dive incident table with explainable score breakdown and raw evidence drill-down.
  - [ ] Analyst export option (summary report generation in Markdown/HTML via `reporting.py`).

---

## Phase 6: Testing, Evaluation & Benchmarking (PLANNED)
- [ ] Implement evaluation metrics pipeline in `src/netsleuth/evaluation.py`:
  - [ ] Compare detector alerts against separate ground-truth scenario labels.
  - [ ] Compute true positives, false positives, false negatives, precision, recall, and F1 score.
- [ ] Run automated pytest test suite covering all modules:
  - [ ] Schema validation tests.
  - [ ] Detector boundary and edge-case tests.
  - [ ] Correlation and timeline consistency tests.
  - [ ] End-to-end synthetic scenario benchmark tests.
- [ ] Document documented evaluation findings and analyze any observed false positives.

---

## Phase 7: Academic Report, Screenshots & Demonstration (PLANNED)
- [ ] Capture verified application UI screenshots in `screenshots/`:
  - [ ] Dashboard landing view.
  - [ ] Port scan incident detection and evidence breakdown.
  - [ ] Chronological timeline reconstruction chart.
  - [ ] Host communication directed graph.
  - [ ] Evaluation metric summary.
- [ ] Draft final academic mini-project report based on `docs/08_REPORT_AND_DEMO_PLAN.md`.
- [ ] Prepare live college demonstration walkthrough script and Q&A defense cheat sheet.
