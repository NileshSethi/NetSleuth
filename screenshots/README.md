# NetSleuth — Demonstration Screenshot Catalog

This directory contains visual captures of the NetSleuth analyst dashboard during live execution across benchmark scenarios. These images serve as graphical figures for academic reports, presentation slide decks, and project defense documentation.

---

## Screenshot Inventory & Descriptions

| File Name | View / Tab | Scenario | Description / Key Visual Elements |
| :--- | :--- | :--- | :--- |
| `01_dashboard_landing.png` | Sidebar & KPIs | Preset / Custom | Main landing screen showing sidebar configuration, threshold sliders, and top KPI metric cards (Total Flows, Flagged Alerts, Correlated Incidents, Max Score). |
| `02_benign_baseline_run.png` | Overview | `SCN-01 (Benign)` | Clean run on benign enterprise traffic showing 0 alerts, 0 incidents, and green health status (100% Precision verification). |
| `03_port_scan_detection.png` | Tab 1: Incident Drill-Down | `SCN-02 (Port Scan)` | Alert evidence card showing vertical reconnaissance attack by `192.168.1.50` probing 25 distinct ports on `10.0.0.15`. |
| `04_correlated_incident_detail.png` | Tab 1: Incident Drill-Down | `SCN-05 (Blended APT)` | Multi-stage incident `INC-001` showing multi-alert clustering and explainable priority score breakdown (85/100). |
| `05_chronological_timeline_chart.png` | Tab 2: Chronological Timeline | `SCN-05 (Blended APT)` | Interactive Plotly chronological scatter/timeline chart showing the attack lifecycle progression over time. |
| `06_network_topology_graph.png` | Tab 3: Topology Graph | `SCN-05 (Blended APT)` | NetworkX directed graph rendering host interactions, with the attacker node highlighted in bright red. |
| `07_evaluation_metrics_table.png` | Tab 6: Evaluation & Benchmarks | All Scenarios | Live Confusion Matrix ($TP, FP, TN, FN$) and Precision, Recall, and F1 score evaluation table. |

---

## Instructions for Capturing Screenshots

1. Launch the Streamlit application in a terminal:
   ```powershell
   streamlit run app.py
   ```
2. Navigate to `http://localhost:8501` in your browser.
3. For each screenshot:
   - Select the corresponding scenario in the sidebar.
   - Navigate to the specified tab.
   - Use Windows Snipping Tool (`Win + Shift + S`) or browser developer tools to capture the browser window at $1920 \times 1080$ resolution.
   - Save the image to this `screenshots/` directory matching the exact filename listed in the table above.
