# Changelog

All notable changes to the **NetSleuth** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - 2026-10-18

### Added
- **Academic Capstone Report & Demonstration Preparation (Phase 7):**
  - Authored comprehensive, professor-ready academic capstone project report in `reports/academic_project_report.md` covering 10 detailed chapters, formal problem statement, sliding-window detection algorithms, explainable scoring formulation, empirical evaluation results, threat modeling, and defensive recommendations.
  - Authored complete live 5-minute demonstration script, top 15 viva and oral examination defense Q&A guide, and quick reference CLI cheatsheet in `docs/12_DEMO_AND_VIVA_GUIDE.md`.
  - Created screenshot catalog and visual walkthrough capture specifications in `screenshots/README.md`.
  - Completed end-to-end project implementation across all 7 planned phases.

## [0.6.0] - 2026-10-18

### Added
- **Testing, Scientific Evaluation & Benchmarking (Phase 6):**
  - Implemented metrics computation in `src/netsleuth/evaluation.py` calculating True Positives (TP), False Positives (FP), True Negatives (TN), False Negatives (FN), Precision, Recall, F1 Score, and Confusion Matrix.
  - Implemented scenario benchmark pipelines (`benchmark_scenario` and `benchmark_all_scenarios`) for automated evaluation across synthetic scenarios.
  - Implemented Tab 6 ("Evaluation & Benchmarks") in `app.py` displaying live confusion matrices, precision/recall/F1 metrics, and comparative evaluation tables.
  - Added unit test suite in `tests/test_evaluation.py` (8 passing unit tests) confirming 0 false positives on benign baseline (100% precision) and high detection recall on attack scenarios.
  - Automated test suite expanded to 58 unit tests across all modules (100% pass rate).

## [0.5.0] - 2026-10-18

### Added
- **Graph Analysis & Analyst Dashboard (Phase 5):**
  - Implemented directed host communication graph modeling using NetworkX in `src/netsleuth/graph_analysis.py` with RFC 1918 classification, centrality, and in/out degree metrics.
  - Implemented interactive Plotly 2D network topology visualization with spring layout, edge hover tooltips, and highlighted red attacker nodes.
  - Implemented comprehensive Streamlit web application in `app.py` with custom CSV uploader, 5 preset benchmark scenarios, live threshold sliders, KPI metric cards, incident drill-down, chronological attack timeline chart, topology graph, report download, and telemetry search.
  - Implemented forensic Markdown report generator in `src/netsleuth/reporting.py`.
  - Added unit test suites across `tests/test_graph_analysis.py` and `tests/test_reporting.py` (9 passing tests).

## [0.4.0] - 2026-10-18

### Added
- **Correlation, Timeline & Scoring (Phase 4):**
  - Implemented multi-alert incident correlation in `src/netsleuth/correlation.py` clustering alerts by source IP, pivot targets, and temporal sliding windows with deterministic `incident_id` generation.
  - Implemented forensic chronological timeline reconstruction in `src/netsleuth/timeline.py` interleaving contributing raw flows with alert milestone markers.
  - Implemented `extract_timeline_events()` for Plotly Gantt/scatter chart rendering.
  - Implemented transparent, explainable incident priority scoring in `src/netsleuth/scoring.py` evaluating rule severity/diversity (0–40 pts), target breadth (0–30 pts), and volumetric impact (0–30 pts).
  - Added unit test suites across `tests/test_correlation.py`, `tests/test_scoring.py`, and `tests/test_timeline.py` (15 passing unit tests).

## [0.3.0] - 2026-10-18

### Added
- **Heuristic Threat Detection Engine (Phase 3):**
  - Implemented Rule 1: Vertical Port Scan detector (`detect_port_scans`) with sliding time-window grouping by `(src_ip, dst_ip)` and distinct port cardinality tracking.
  - Implemented Rule 2: Horizontal Host Scan detector (`detect_host_scans`) with sliding time-window grouping by `src_ip` and target IP sweep tracking.
  - Implemented Rule 3: Anomalous Outbound Volume Spike detector (`detect_exfiltration_spikes`) with outbound byte summing and threshold evaluation.
  - Implemented `run_all_detectors()` orchestrator combining all rules and sorting alerts chronologically.
  - Added `Alert.to_dict()` helper for clean serialization.
  - Added unit test suite in `tests/test_detectors.py` (11 passing tests) verifying port scan, host sweep, volume spike, direction filtering, window boundary edges, zero false alarms on benign baseline, and full multi-rule coverage on blended attacks.

## [0.2.0] - 2026-10-18

### Added
- **Parser & Schema Validation (Phase 2):**
  - Implemented field-level validation helpers in `src/netsleuth/schema.py` (`is_valid_ipv4`, `is_valid_port`, `is_valid_bytes`, `FlowRecord.validate()`).
  - Implemented robust `load_and_validate_flow_csv()` parser in `src/netsleuth/parser.py` with column checking, UTC timestamp normalization, bounds enforcement, enum standardization, deduplication, and chronological sorting.
  - Implemented reproducible synthetic dataset generator in `src/netsleuth/synthetic.py`.
  - Generated 5 benchmark scenarios with fixed seeds in `data/synthetic/` (`scenario_01_benign.csv`, `scenario_02_port_scan.csv`, `scenario_03_host_scan.csv`, `scenario_04_exfiltration.csv`, `scenario_05_blended_attack.csv`).
  - Added comprehensive automated test suite in `tests/test_parser.py` (15 passing unit tests).

## [0.1.0] - 2026-10-18

### Added
- **Project Scaffolding (Phase 1):**
  - Initialized production-grade `.gitignore` protecting credentials, private datasets, local virtual environments, and build artifacts.
  - Added `.env.example` defining environment configuration requirements for local-only synthetic operation.
  - Created `AGENTS.md` establishing persistent developer and AI agent constraints, ethical guidelines, and testing protocols.
  - Specified core dependencies in `requirements.txt` (`pandas`, `streamlit`, `plotly`, `networkx`) and testing dependencies in `requirements-dev.txt` (`pytest`, `ruff`).
  - Added comprehensive technical documentation suite in `docs/` covering project brief, system requirements, architecture, dataset schema, detection rules, roadmap, testing plan, presentation plan, setup troubleshooting, architectural decisions, and project status.
  - Structured modular Python package under `src/netsleuth/` with typed placeholder interfaces (`config`, `schema`, `parser`, `detectors`, `correlation`, `timeline`, `graph_analysis`, `scoring`, `evaluation`, `reporting`).
  - Added minimal placeholder Streamlit web application (`app.py`) displaying project title, architecture summary, and development status.
  - Created folder placeholders and README guides for `data/`, `tests/`, `reports/`, and `screenshots/`.
  - Added master task tracker in `TASKS.md`.
