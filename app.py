"""NetSleuth: Streamlit Web Application Entry Point.

An Explainable Network Attack Timeline Reconstruction and Threat Analysis System.
This is the minimal Phase 1 scaffolding placeholder interface.
"""

import sys
from pathlib import Path

# Ensure 'src' is on sys.path for local module discovery
src_path = Path(__file__).resolve().parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

try:
    import streamlit as st
    STREAMLIT_AVAILABLE = True
except ImportError:
    STREAMLIT_AVAILABLE = False


def main():
    if not STREAMLIT_AVAILABLE:
        print("NetSleuth: Streamlit is not installed in the current environment.")
        print("Please install requirements using: pip install -r requirements.txt")
        print("Then launch with: streamlit run app.py")
        return

    st.set_page_config(
        page_title="NetSleuth — Threat Analysis System",
        page_icon="🔍",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    st.title("🔍 NetSleuth: Network Threat Analysis System")
    st.subheader(
        "An Explainable Network Attack Timeline Reconstruction and Threat Analysis System"
    )

    st.info(
        "ℹ️ **Current Status: Phase 1 — Scaffolding & Architecture**\n\n"
        "NetSleuth is currently undergoing initial repository scaffolding and architectural documentation. "
        "Core detection heuristics, incident correlation engines, and interactive graph visualizations "
        "are specified in detail and will be implemented in subsequent phases upon user authorization."
    )

    st.markdown("---")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 📋 Planned System Capabilities")
        st.markdown(
            """
            - **Local Synthetic Telemetry:** Works 100% offline using simulated cloud-style VPC flow logs (CSV format). No external cloud credentials required.
            - **Deterministic Heuristic Detectors:**
                - *Vertical Port Scan* (Single source probing multiple ports on a target).
                - *Horizontal Host Scan* (Single source sweeping multiple network hosts).
                - *Outbound Exfiltration Spike* (Abnormal outbound data transfer volumes).
            - **Multi-Alert Incident Correlation:** Aggregates related alerts into unified, named incidents.
            - **Chronological Timeline Reconstruction:** Sequences flow events to tell the forensic story of an attack.
            - **NetworkX Topology Graph:** Interactive directed graph of communicating hosts with blast-radius analysis.
            - **Explainable Priority Scoring:** Transparent risk scores (0–100) with auditable mathematical justification.
            """
        )

    with col2:
        st.markdown("### 🛠️ Architecture & Development Roadmap")
        st.markdown(
            """
            | Phase | Milestone | Status |
            | :--- | :--- | :--- |
            | **Phase 1** | Scaffolding, Documentation & Contracts | **Complete (Active)** |
            | **Phase 2** | Ingestion Parser & Synthetic Datasets | *Pending Authorization* |
            | **Phase 3** | Heuristic Threat Detection Engine | *Planned* |
            | **Phase 4** | Incident Correlation & Timeline Builder | *Planned* |
            | **Phase 5** | Graph Analysis & Interactive Dashboard | *Planned* |
            | **Phase 6** | Automated Tests & Benchmark Evaluation | *Planned* |
            | **Phase 7** | Academic Report & Live Demonstration | *Planned* |
            """
        )

    st.markdown("---")
    st.caption(
        "NetSleuth — Defensive Cybersecurity & Forensic Education Tool | "
        "Strictly for authorized analysis and simulated education | Version 0.1.0"
    )


if __name__ == "__main__":
    main()
