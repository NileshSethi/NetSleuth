# Synthetic Benchmark Datasets

This directory houses deterministic, reproducible synthetic network-flow datasets generated for NetSleuth.

## Purpose & Scope
Because NetSleuth is designed as an educational, offline analysis tool, it relies on mathematically modeled flow records rather than requiring live cloud infrastructure or hazardous packet captures.

## Planned Scenarios (Generated in Phase 2)
1. **`scenario_01_benign.csv`**: Pure enterprise baseline (HTTP, HTTPS, DNS, NTP, routine internal traffic). Zero expected alerts.
2. **`scenario_02_port_scan.csv`**: Internal host performing a vertical port scan against an internal server.
3. **`scenario_03_host_scan.csv`**: Internal host sweeping port 445 (SMB) across multiple subnet hosts.
4. **`scenario_04_exfiltration.csv`**: Internal database transferring an anomalous volume of outbound data to an external documentation-range IP.
5. **`scenario_05_blended_attack.csv`**: End-to-end multi-stage intrusion combining discovery, reconnaissance, lateral probe, and exfiltration.

## Generation Rules
- Generated using fixed random seeds (`random.seed(42)`, `numpy.random.seed(42)`).
- Ground truth columns (`is_attack`, `attack_type`) are embedded for evaluation purposes only and must be excluded from detector inputs.
