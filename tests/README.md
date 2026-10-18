# NetSleuth Test Suite

This directory contains the automated test suite for NetSleuth, executed via `pytest`.

## Directory Structure (Planned for Phase 2–6)
- `test_parser.py`: Tests for CSV ingestion, schema validation, timestamp parsing, missing values, and malformed inputs.
- `test_detectors.py`: Unit tests for Rule 1 (Port Scan), Rule 2 (Host Scan), and Rule 3 (Volume Spike).
- `test_correlation.py`: Unit tests for incident clustering and deterministic ID generation.
- `test_timeline.py`: Unit tests for chronological sequencing and event tagging.
- `test_graph_analysis.py`: Unit tests for NetworkX graph construction, node degree calculations, and cycle detection.
- `test_scoring.py`: Unit tests for explainable linear priority score calculations.
- `test_evaluation.py`: Unit tests for Precision, Recall, and Confusion Matrix calculation.

## How to Run Tests
Once dependencies are installed in Phase 2:
```bash
# Run all tests
pytest -v

# Run with coverage report
pytest --cov=src/netsleuth -v
```
