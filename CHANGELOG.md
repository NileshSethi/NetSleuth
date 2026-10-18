# Changelog

All notable changes to the **NetSleuth** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
