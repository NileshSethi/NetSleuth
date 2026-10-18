# Data Directory Hierarchy & Governance

This directory contains datasets used by NetSleuth for threat detection, timeline reconstruction, and evaluation.

## Directory Structure

- **`data/raw/`**: Reserved for raw, unparsed user flow logs.
  - *Git Policy:* Content in this directory is strictly ignored by `.gitignore` (except `.gitkeep`) to prevent inadvertent leakage of private network captures.
- **`data/processed/`**: Reserved for sanitized, parsed, or cached intermediary DataFrames.
  - *Git Policy:* Content in this directory is ignored by `.gitignore` (except `.gitkeep`).
- **`data/synthetic/`**: Version-controlled, reproducible synthetic benchmark datasets.
  - *Git Policy:* Fully tracked by Git. These files contain safe, non-sensitive, RFC-compliant synthetic network flows used for unit testing, demonstrations, and baseline evaluation.

## Data Ethics and Guidelines
- Never place actual production network captures, proprietary IP lists, or confidential payloads into this repository.
- Use only RFC 1918 private IP addresses or RFC 5737 documentation IP addresses in all test datasets.
