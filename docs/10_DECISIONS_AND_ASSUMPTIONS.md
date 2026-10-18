# Document 10: Architectural Decisions & Design Assumptions

## 1. Context & Architectural Decision Records (ADRs)
This document records key technical decisions, rationale, trade-offs, and operating assumptions established during Phase 1. Each decision was chosen to maximize academic value, explainability, and defensibility while guaranteeing delivery within the 2–3 day constraint.

---

## 2. Summary of Architectural Decisions

### ADR-01: Python 3.10+ as Primary Language
- **Decision:** Build the entire system in pure Python.
- **Rationale:** Python provides the richest ecosystem for data science (`pandas`), network graphs (`NetworkX`), and web dashboards (`Streamlit`). It enables rapid prototyping, clean code readability, and easy explanation during academic defense.
- **Trade-off:** Slower than C++ or Rust for processing millions of packets per second. However, for batch analysis of simulated datasets ($10^3–10^5$ rows), Python's performance with vectorized pandas operations is instantaneous (< 2 seconds).

### ADR-02: Streamlit for Analyst User Interface
- **Decision:** Use Streamlit rather than React, Vue, or Django.
- **Rationale:** Streamlit allows writing the entire interactive web frontend in pure Python with built-in state management and UI widgets (sliders, file uploaders, data tables). It eliminates JavaScript build chains and frontend boilerplate, saving 1–2 days of development time.
- **Trade-off:** Less flexibility for custom low-level DOM manipulation, but more than sufficient for an interactive data science and cybersecurity dashboard.

### ADR-03: CSV as Primary Input Format
- **Decision:** Support local comma-separated values (`.csv`) for the initial version.
- **Rationale:** CSV is universal, human-readable, easily inspected in Excel/VS Code, and natively supported by pandas without external database drivers.
- **Trade-off:** Larger file sizes than Parquet or SQLite, but ideal for transparency and educational demonstration.

### ADR-04: Simulated Cloud Flow Records (VPC Flow Logs)
- **Decision:** Use synthetic cloud-style flow logs instead of raw packet captures (`.pcap`).
- **Rationale:** PCAP files are massive (gigabytes), contain encrypted payloads that cannot be inspected without keys, and require complex packet parsing libraries (`scapy`, `dpkt`). Flow logs represent standard high-level cloud telemetry that enterprise SOCs actually analyze for network anomalies.
- **Trade-off:** Does not inspect packet payloads, but focuses cleanly on Layer 3/Layer 4 connection patterns.

### ADR-05: pandas for Tabular Transformation & Windowing
- **Decision:** Use `pandas` for grouping, sorting, and rolling time-window calculations.
- **Rationale:** Highly optimized C-backend vectorization enables sliding-window aggregations across thousands of rows in milliseconds.
- **Trade-off:** Memory footprint scales with DataFrame size, which is trivial for the target dataset scale.

### ADR-06: NetworkX for Topology Analysis
- **Decision:** Use `NetworkX` for graph data structures and communication modeling.
- **Rationale:** Standard, battle-tested Python library providing directed graph structures (`DiGraph`), degree centrality, neighbor extraction, and seamless conversion to Plotly visual layouts.
- **Trade-off:** In-memory graph processing, perfect for local network segments.

### ADR-07: Plotly for Dynamic Visualizations
- **Decision:** Use `Plotly` rather than static `matplotlib` or `seaborn`.
- **Rationale:** Plotly produces interactive HTML charts with hover tooltips, zoom, pan, and timeline Gantt views that wow evaluators during live presentations.
- **Trade-off:** Slightly heavier client-side bundle, easily handled by modern browsers.

### ADR-08: Deferral of Live Cloud API Integrations
- **Decision:** Do not connect to live AWS, Azure, or GCP APIs in the MVP.
- **Rationale:** Live cloud connections require active billing accounts, IAM credentials, VPC setup, and internet access during defense, introducing significant failure points.
- **Trade-off:** None for a college prototype; simulating the log format provides identical analytical validity.

### ADR-09: Deferral of Machine Learning / Deep Learning
- **Decision:** Use deterministic, explainable heuristics rather than black-box ML models.
- **Rationale:** In digital forensics, an analyst must justify *why* an alert fired. Heuristics are 100% explainable and verifiable. Unsupervised ML models often suffer from high false-positive rates and opaque decision boundaries that are difficult to defend academically.
- **Trade-off:** Does not detect unknown zero-day anomaly classes, but excels at known behavioral patterns.

### ADR-10: Exclusion of Automated Blocking / Remediation
- **Decision:** Exclude automated firewall modifications, IP blocking, or system shutdown.
- **Rationale:** NetSleuth is an analytical decision-support and forensic reconstruction tool. Automated blocking poses safety risks and violates ethical safety boundaries in an educational setting.

---

## 3. Assumptions & Open Questions

### Core Assumptions
1. **Clock Synchronization:** All synthetic records assume synchronized UTC clocks without significant timestamp skew across reporting network interfaces.
2. **Deterministic Evaluation:** Ground-truth labels are complete and accurate for the synthetic scenarios.
3. **Single Attacker per Synthetic Scenario:** Initial benchmark scenarios assume a small number of attacker IPs (1–2) to keep incident correlation clean and demonstrable.

### Future Architectural Alternatives
- **Parquet Storage:** If dataset scale exceeds 1,000,000 rows in future versions, migrate ingestion from CSV to Apache Parquet for columnar compression.
- **DuckDB Integration:** If complex SQL querying across multiple flow files is required, embed DuckDB as a zero-dependency local SQL engine.
