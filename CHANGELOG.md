# Changelog

All notable changes to the **NetSleuth** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
