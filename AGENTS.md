# AGENTS.md — Persistent Developer & Agent Guidelines

## 1. Project Objective & Context

**Project Name:** NetSleuth  
**Full Title:** NetSleuth: An Explainable Network Attack Timeline Reconstruction and Threat Analysis System  
**Domain:** Defensive cybersecurity, network security, digital forensics, data structures, and algorithms.  
**Primary Stack:** Python 3.10+, pandas, Streamlit, Plotly, NetworkX, pytest.

NetSleuth is an educational and analytical tool designed to process simulated cloud-style network-flow records (CSV), identify suspicious traffic patterns (port scans, host scans, outbound exfiltration spikes), correlate related events into incidents, build communication graphs, and reconstruct chronological incident timelines with explainable priority scores.

> **CRITICAL WORKFLOW NOTICE:**  
> **Phase 1 is SCAFFOLDING AND DOCUMENTATION ONLY.**  
> Do not jump into feature implementation, detector logic, or test execution until Phase 1 is fully verified and explicitly authorized by the user for Phase 2.

---

## 2. Core Engineering Rules & Behavioral Directives

All AI agents and contributing developers must adhere strictly to the following 20 guidelines:

1. **Understand Architecture & Tech Stack:** NetSleuth is a local Python application with a Streamlit interface. It operates entirely on local synthetic CSV flow records. No live cloud account or external daemon is required or permitted for the MVP.
2. **Read Documentation Before Implementation:** Always read the relevant documents in `docs/` (such as `03_SYSTEM_ARCHITECTURE.md`, `04_DATASET_SCHEMA.md`, and `05_DETECTION_RULES.md`) before modifying or creating code.
3. **Simple, Readable, Educational Code:** Prefer simple, modular, and transparent Python code that a college student can understand, explain to an evaluator, and defend during an oral examination. Avoid overly clever one-liners or esoteric metaprogramming.
4. **Strong Typing & Documentation:** Use meaningful variable and function names, explicit type hints (`typing`), and clear docstrings for all modules, classes, and public functions.
5. **Strict Modular Separation:** Maintain clean boundaries across modules in `src/netsleuth/`:
   - `config.py`: Thresholds and constants
   - `schema.py`: Data definitions and validation contracts
   - `parser.py`: CSV ingestion, parsing, sanitization, and sorting
   - `detectors.py`: Individual detection heuristics (port scan, host scan, data volume)
   - `correlation.py`: Multi-alert incident grouping and correlation
   - `timeline.py`: Chronological timeline assembly and event narrative
   - `graph_analysis.py`: Host interaction network graph (NetworkX)
   - `scoring.py`: Transparent, explainable incident priority scoring
   - `evaluation.py`: Precision, recall, F1, and confusion matrix calculation
   - `reporting.py`: Incident summary generation (Markdown/text exports)
6. **Configurable Thresholds:** Never hardcode "magic numbers" or arbitrary detection thresholds into detection algorithms. Centralize defaults in `config.py` and allow analyst overrides via dataclasses or function parameters.
7. **Robust Input Validation:** Handle missing columns, malformed timestamps, corrupted IP strings, negative byte counts, and empty files gracefully with clear warning/error messages rather than unhandled tracebacks.
8. **Deterministic Synthetic Datasets:** Generate reproducible synthetic datasets using fixed random seeds so that test runs and evaluations produce identical, verifiable outcomes across machines.
9. **Zero Label Leakage:** Never use ground-truth scenario or label fields (e.g., `is_attack`, `attack_type`, `scenario_id`) as inputs to detection or correlation algorithms. Labels are reserved exclusively for `evaluation.py`.
10. **Test-Driven Rigor:** Add pytest unit tests for every parser edge case, detection rule, correlation logic, and scoring function.
11. **Academic & Technical Honesty:** Never fabricate test results, fake evaluation metrics, or simulate false "successes." If a detector produces false positives or misses an edge case, report it transparently as an analytical finding.
12. **Defensive & Ethical Scope:** NetSleuth is strictly a defensive analysis tool. Never execute unauthorized network scanning, port probing, exploitation scripts, or live packet capturing against external networks.
13. **No Live Cloud Dependency:** Do not introduce AWS/Azure/GCP credentials, boto3/azure SDKs, or cloud authentication requirements for the MVP. The data format simulates cloud flow logs (e.g., AWS VPC Flow Logs style), but data remains local.
14. **No Automated Remediation or Disruption:** NetSleuth is an analytical decision-support system. Never implement automatic firewall rule modifications, IP blocking, host shutdown, or system disruption.
15. **Lightweight Infrastructure:** Avoid introducing Docker, Kubernetes, external relational databases (PostgreSQL/MySQL), Redis, or complex microservices. A virtual environment with standard Python libraries is sufficient.
16. **Keep Documentation Synchronized:** Update `docs/`, `TASKS.md`, and `CHANGELOG.md` whenever architectural decisions, schemas, or behaviors are revised.
17. **Prioritize Working MVP Over Feature Creep:** Focus on delivering a solid, tested, and demonstrable minimum viable product within the 2–3 day college project timeline before considering optional enhancements.
18. **Verify Before Declaring Done:** Never declare a feature, task, or bug fix complete without executing the relevant automated tests and validating output.
19. **Protect User Files:** Never overwrite, delete, or modify existing user files or unrelated projects. Always inspect existing code and respect workspace boundaries.
20. **Explicit Authorization for Scope Expansion:** Always ask for user confirmation before expanding project scope, adding non-standard dependencies, or altering core architecture.

---

## 3. Workflow Progression

- **Current Status:** **Phase 1 (Scaffolding & Architecture)**
- **Next Phase:** **Phase 2 (Parser & Synthetic Dataset Generation)** — *Awaiting explicit authorization.*
