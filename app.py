"""NetSleuth: Streamlit Web Application Entry Point.

An Explainable Network Attack Timeline Reconstruction and Threat Analysis System.
Provides an interactive forensic analyst dashboard for investigating simulated cloud flow logs.
"""

import io
import sys
from pathlib import Path
from typing import Optional, List

# Ensure 'src' is on sys.path for local module discovery
src_path = Path(__file__).resolve().parent / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from netsleuth.config import DetectionConfig, CorrelationConfig, ScoringConfig
from netsleuth.parser import load_and_validate_flow_csv
from netsleuth.detectors import run_all_detectors, Alert
from netsleuth.correlation import correlate_alerts_into_incidents, Incident
from netsleuth.scoring import score_all_incidents
from netsleuth.timeline import build_incident_timeline, extract_timeline_events
from netsleuth.graph_analysis import build_communication_graph, generate_network_graph_figure, calculate_host_metrics
from netsleuth.reporting import generate_incident_markdown_report, generate_batch_executive_summary
from netsleuth.evaluation import evaluate_detection_performance, benchmark_all_scenarios


# Preset Benchmark Scenario Mapping
SCENARIOS = {
    "Scenario 01: Benign Enterprise Baseline": "data/synthetic/scenario_01_benign.csv",
    "Scenario 02: Vertical Port Scan Reconnaissance": "data/synthetic/scenario_02_port_scan.csv",
    "Scenario 03: Horizontal Host Sweep Discovery": "data/synthetic/scenario_03_host_scan.csv",
    "Scenario 04: Outbound Data Exfiltration Spike": "data/synthetic/scenario_04_exfiltration.csv",
    "Scenario 05: Multi-Stage Blended APT Intrusion": "data/synthetic/scenario_05_blended_attack.csv",
}


def _safe_styler_map(styler, func, subset=None):
    """Safely apply cell-wise styler functions across pandas versions (map in 2.1+, applymap in <2.1)."""
    if hasattr(styler, "map"):
        return styler.map(func, subset=subset)
    return styler.applymap(func, subset=subset)


def build_timeline_plotly_chart(timeline_df: pd.DataFrame) -> go.Figure:
    """Create an interactive Plotly timeline scatter chart of network events and alerts."""
    if timeline_df.empty:
        fig = go.Figure()
        fig.update_layout(title="No events in timeline")
        return fig

    color_map = {
        "PORT_SCAN_PROBE": "#F59E0B",
        "HOST_DISCOVERY_SWEEP": "#EAB308",
        "EXFILTRATION_BURST": "#EF4444",
        "LATERAL_TRANSFER": "#8B5CF6",
        "NETWORK_FLOW": "#3B82F6",
        "RULE-PORT-SCAN": "#DC2626",
        "RULE-HOST-SCAN": "#B91C1C",
        "RULE-EXFIL-SPIKE": "#991B1B",
    }

    fig = px.scatter(
        timeline_df,
        x="timestamp",
        y="source",
        color="category",
        symbol="is_alert",
        symbol_map={True: "diamond", False: "circle"},
        size="bytes",
        size_max=22,
        hover_data={
            "timestamp": "|%Y-%m-%d %H:%M:%S",
            "destination": True,
            "port": True,
            "bytes": ":,",
            "action": True,
            "description": False,
        },
        hover_name="description",
        color_discrete_map=color_map,
        title="<b>Chronological Incident Timeline & Alert Milestones</b>",
    )

    fig.update_traces(marker={"line": {"width": 1.5, "color": "white"}})
    fig.update_layout(
        height=450,
        paper_bgcolor="rgba(15, 23, 42, 0.95)",
        plot_bgcolor="rgba(15, 23, 42, 0.95)",
        font={"color": "#E2E8F0"},
        xaxis={"title": "UTC Timestamp", "gridcolor": "rgba(255, 255, 255, 0.1)"},
        yaxis={"title": "Initiating Host (Source IP)", "gridcolor": "rgba(255, 255, 255, 0.1)"},
        legend={"orientation": "h", "yanchor": "bottom", "y": 1.02, "xanchor": "right", "x": 1.0},
        margin={"l": 20, "r": 20, "t": 60, "b": 20},
    )
    return fig


def main():
    st.set_page_config(
        page_title="NetSleuth — Network Threat Analysis & Timeline",
        page_icon="🔍",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Custom Header Style
    st.markdown(
        """
        <style>
        .metric-card {
            background-color: #1E293B;
            border-radius: 8px;
            padding: 16px;
            border-left: 4px solid #3B82F6;
        }
        .sev-badge-critical { color: #EF4444; font-weight: bold; }
        .sev-badge-high { color: #F97316; font-weight: bold; }
        .sev-badge-medium { color: #FBBF24; font-weight: bold; }
        .sev-badge-low { color: #10B981; font-weight: bold; }
        </style>
        """,
        unsafe_allow_html=True,
    )

    st.title("🔍 NetSleuth: Explainable Threat Analysis System")
    st.caption(
        "Network Attack Timeline Reconstruction, Graph Analysis & Threat Prioritization | "
        "Defensive Forensic Decision Support"
    )

    # --------------------------------------------------------------------------
    # Sidebar: Data Ingestion & Configuration
    # --------------------------------------------------------------------------
    with st.sidebar:
        st.header("⚙️ Data & Detection Settings")

        data_source = st.radio(
            "Select Input Source",
            ["Benchmark Synthetic Scenario", "Upload Custom Flow CSV"],
            index=0,
        )

        flow_df: Optional[pd.DataFrame] = None
        source_name = ""

        if data_source == "Benchmark Synthetic Scenario":
            chosen_scenario = st.selectbox("Benchmark Scenarios", list(SCENARIOS.keys()), index=4)
            scenario_path = Path(SCENARIOS[chosen_scenario])
            source_name = chosen_scenario
            if scenario_path.exists():
                try:
                    flow_df = load_and_validate_flow_csv(scenario_path)
                except Exception as e:
                    st.error(f"Failed to load scenario: {e}")
            else:
                st.warning(f"Benchmark file not found: {scenario_path}. Generate via synthetic module.")
        else:
            uploaded_file = st.file_uploader("Upload Network Flow CSV", type=["csv"])
            if uploaded_file is not None:
                source_name = uploaded_file.name
                try:
                    flow_df = load_and_validate_flow_csv(uploaded_file)
                except Exception as e:
                    st.error(f"CSV Validation Error: {e}")

        st.markdown("---")
        st.subheader("🎯 Heuristic Thresholds")

        with st.expander("Detection Parameters", expanded=False):
            port_window = st.slider("Port Scan Window (sec)", 10, 300, 60, 10)
            port_thresh = st.slider("Port Scan Threshold (distinct ports)", 5, 50, 15, 1)

            host_window = st.slider("Host Scan Window (sec)", 30, 600, 120, 15)
            host_thresh = st.slider("Host Scan Threshold (distinct hosts)", 3, 50, 10, 1)

            exfil_window = st.slider("Exfil Window (sec)", 60, 900, 300, 30)
            exfil_mb = st.slider("Exfil Byte Threshold (MB)", 5, 200, 50, 5)
            exfil_bytes = exfil_mb * 1024 * 1024

        with st.expander("Correlation & Scoring", expanded=False):
            corr_window = st.slider("Correlation Window (sec)", 60, 1800, 600, 60)

        det_config = DetectionConfig(
            port_scan_window_sec=port_window,
            port_scan_threshold=port_thresh,
            host_scan_window_sec=host_window,
            host_scan_threshold=host_thresh,
            exfil_window_sec=exfil_window,
            exfil_byte_threshold=exfil_bytes,
        )
        corr_config = CorrelationConfig(correlation_window_sec=corr_window)
        scoring_config = ScoringConfig()

        st.markdown("---")
        st.caption("NetSleuth v0.4.0 — Offline Synthetic Mode")

    # Guard check: Ensure data is loaded
    if flow_df is None or flow_df.empty:
        st.info("👈 Please select a scenario or upload a CSV file from the sidebar to begin analysis.")
        return

    # --------------------------------------------------------------------------
    # Execute Pipeline: Detection -> Correlation -> Scoring
    # --------------------------------------------------------------------------
    with st.spinner("Executing detection heuristics and incident correlation..."):
        alerts = run_all_detectors(flow_df, config=det_config)
        incidents = correlate_alerts_into_incidents(alerts, config=corr_config)
        scored_incidents = score_all_incidents(incidents, config=scoring_config)

    # Collect flagged IPs
    flagged_ips = [a.src_ip for a in alerts]
    for a in alerts:
        if a.dst_ip:
            flagged_ips.append(a.dst_ip)
    flagged_ips = sorted(list(set(flagged_ips)))

    # --------------------------------------------------------------------------
    # Top KPI Metrics Banner
    # --------------------------------------------------------------------------
    total_flows = len(flow_df)
    total_alerts = len(alerts)
    total_incidents = len(scored_incidents)
    max_score = scored_incidents[0].risk_score if scored_incidents else 0.0
    dropped_rows = flow_df.attrs.get("dropped_row_count", 0)

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        st.metric("Total Flows Analyzed", f"{total_flows:,}")
    with m2:
        st.metric("Valid Flows", f"{total_flows - dropped_rows:,}", delta=f"-{dropped_rows} dropped" if dropped_rows else None)
    with m3:
        st.metric("Threat Alerts", f"{total_alerts}", delta="Flagged" if total_alerts else "Clean")
    with m4:
        st.metric("Correlated Incidents", f"{total_incidents}")
    with m5:
        sev_color = "red" if max_score >= 80 else "orange" if max_score >= 60 else "green"
        st.metric("Peak Threat Score", f"{max_score}/100")

    st.markdown("---")

    # --------------------------------------------------------------------------
    # Main Tabs
    # --------------------------------------------------------------------------
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "🚨 Correlated Incidents & Scoring",
        "⏱️ Chronological Timeline",
        "🕸️ Host Topology Graph",
        "📄 Forensic Report Export",
        "📋 Raw Flow Telemetry",
        "📊 Evaluation & Benchmarks",
    ])

    # --------------------------------------------------------------------------
    # Tab 1: Correlated Incidents & Explainable Scoring
    # --------------------------------------------------------------------------
    with tab1:
        if not scored_incidents:
            st.success("✅ **Clean Network Traffic!** No suspicious anomalies or attack patterns detected.")
            st.write("All network connection records remained within normal baseline thresholds.")
        else:
            inc_options = {
                f"{inc.incident_id} — {inc.primary_source_ip} (Score: {inc.risk_score}/100)": inc
                for inc in scored_incidents
            }
            selected_inc_label = st.selectbox("Select Incident to Investigate", list(inc_options.keys()))
            selected_incident: Incident = inc_options[selected_inc_label]

            col_score, col_details = st.columns([1, 2])

            with col_score:
                st.markdown("### 🎯 Priority Risk Score")
                score_val = selected_incident.risk_score
                breakdown = selected_incident.score_breakdown or {}
                sev_label = breakdown.get("severity_label", "MEDIUM")

                st.progress(score_val / 100.0)
                st.markdown(f"## **`{score_val} / 100`** — **{sev_label}**")

                st.markdown("#### 🔬 Explainable Point Breakdown")
                factors = breakdown.get("factors", {})

                f1 = factors.get("rule_severity_and_diversity", {})
                f2 = factors.get("target_breadth", {})
                f3 = factors.get("volumetric_impact", {})

                st.info(f"**Rule Severity & Diversity:** `{f1.get('points', 0)} / 40 pts`\n\n_{f1.get('explanation', '')}_")
                st.info(f"**Target Blast Radius:** `{f2.get('points', 0)} / 30 pts`\n\n_{f2.get('explanation', '')}_")
                st.info(f"**Volumetric Impact:** `{f3.get('points', 0)} / 30 pts`\n\n_{f3.get('explanation', '')}_")

            with col_details:
                st.markdown("### 📋 Incident Narrative")
                st.markdown(f"> **{selected_incident.summary}**")

                d_col1, d_col2, d_col3 = st.columns(3)
                with d_col1:
                    st.write(f"**Primary Attacker:** `{selected_incident.primary_source_ip}`")
                    st.write(f"**Start Time:** `{selected_incident.start_time}`")
                with d_col2:
                    st.write(f"**Targets in Radius:** `{len(selected_incident.associated_ips) - 1}`")
                    st.write(f"**End Time:** `{selected_incident.end_time}`")
                with d_col3:
                    st.write(f"**Duration:** `{round(selected_incident.duration_sec, 1)} seconds`")
                    st.write(f"**Contributing Flows:** `{len(selected_incident.contributing_flow_ids)}`")

                st.markdown("#### 🚨 Associated Detection Alerts")
                alert_table_data = []
                for a in selected_incident.alerts:
                    alert_table_data.append({
                        "Alert ID": a.alert_id,
                        "Rule Name": a.rule_name,
                        "Timestamp (UTC)": a.timestamp,
                        "Severity": a.severity,
                        "Source IP": a.src_ip,
                        "Destination IP": a.dst_ip or "Multiple",
                        "Contributing Flows": len(a.contributing_flow_ids),
                    })
                st.dataframe(pd.DataFrame(alert_table_data), use_container_width=True)

    # --------------------------------------------------------------------------
    # Tab 2: Chronological Incident Timeline
    # --------------------------------------------------------------------------
    with tab2:
        if not scored_incidents:
            st.info("No incidents detected to reconstruct timeline.")
        else:
            selected_incident = scored_incidents[0]
            if "selected_incident" in locals():
                selected_incident = selected_incident

            st.markdown(f"### Chronological Attack Reconstruction: `{selected_incident.incident_id}`")
            timeline_df = build_incident_timeline(selected_incident, flow_df)

            if not timeline_df.empty:
                # Interactive Plotly Chart
                fig_timeline = build_timeline_plotly_chart(timeline_df)
                st.plotly_chart(fig_timeline, use_container_width=True)

                st.markdown("#### Detailed Chronological Event Narrative Table")
                display_cols = [
                    "timestamp", "event_type", "category", "source", "destination",
                    "port", "protocol", "bytes", "action", "description"
                ]
                st.dataframe(
                    _safe_styler_map(
                        timeline_df[display_cols].style,
                        lambda val: "background-color: rgba(239, 68, 68, 0.2)" if val == "ALERT_TRIGGER" else "",
                        subset=["event_type"],
                    ),
                    use_container_width=True,
                    height=350,
                )

    # --------------------------------------------------------------------------
    # Tab 3: Host Communication Graph
    # --------------------------------------------------------------------------
    with tab3:
        st.markdown("### Host Interaction Network Topology & Blast Radius")
        with st.spinner("Constructing NetworkX communication graph..."):
            comm_graph = build_communication_graph(flow_df, flagged_ips=flagged_ips)
            fig_graph = generate_network_graph_figure(comm_graph)
            st.plotly_chart(fig_graph, use_container_width=True)

        st.markdown("#### Host Centrality & Traffic Volume Metrics")
        host_metrics = calculate_host_metrics(comm_graph)
        if host_metrics:
            metrics_df = pd.DataFrame(list(host_metrics.values()))
            metrics_df.sort_values(by="total_bytes", ascending=False, inplace=True)
            st.dataframe(
                _safe_styler_map(
                    metrics_df.style,
                    lambda v: "color: #EF4444; font-weight: bold" if v is True else "",
                    subset=["is_flagged"],
                ),
                use_container_width=True,
                height=250,
            )

    # --------------------------------------------------------------------------
    # Tab 4: Forensic Report Export
    # --------------------------------------------------------------------------
    with tab4:
        st.markdown("### 📄 Incident Forensic Report Generator")
        if not scored_incidents:
            st.info("No incidents detected to generate report.")
        else:
            rep_incident = scored_incidents[0]
            report_text = generate_incident_markdown_report(rep_incident)

            st.download_button(
                label="📥 Download Forensic Markdown Report",
                data=report_text,
                file_name=f"NetSleuth_Report_{rep_incident.incident_id}.md",
                mime="text/markdown",
            )

            st.markdown("#### Live Report Preview")
            st.markdown(report_text)

    # --------------------------------------------------------------------------
    # Tab 5: Raw Flow Telemetry
    # --------------------------------------------------------------------------
    with tab5:
        st.markdown("### 📋 Normalized Network Flow Records")
        st.caption(f"Showing flow records from source: `{source_name}` (Sorted by UTC timestamp)")

        search_query = st.text_input("Filter by IP, Protocol, or Port", "")
        filtered_df = flow_df
        if search_query:
            q = search_query.strip().lower()
            mask = (
                filtered_df["src_ip"].str.lower().str.contains(q)
                | filtered_df["dst_ip"].str.lower().str.contains(q)
                | filtered_df["protocol"].str.lower().str.contains(q)
                | filtered_df["dst_port"].astype(str).str.contains(q)
            )
            filtered_df = filtered_df[mask]

        st.dataframe(filtered_df, use_container_width=True, height=450)

    # --------------------------------------------------------------------------
    # Tab 6: Scientific Evaluation & Benchmark Metrics
    # --------------------------------------------------------------------------
    with tab6:
        st.markdown("### 📊 Detection Performance & Ground-Truth Benchmarks")
        st.caption("Zero-Label Leakage Evaluation: Detectors operate blind to ground-truth labels.")

        eval_col1, eval_col2 = st.columns([1, 1])

        with eval_col1:
            st.markdown("#### Active Dataset Evaluation")
            eval_res = evaluate_detection_performance(alerts, flow_df)
            if eval_res.get("status") == "UNLABELED_DATASET":
                st.info("ℹ️ The currently loaded dataset does not contain evaluation ground-truth labels ('is_attack').")
            else:
                m = eval_res.get("metrics", {})
                cm = eval_res.get("confusion_matrix", {})

                em1, em2, em3 = st.columns(3)
                em1.metric("Precision", f"{m.get('precision', 0.0) * 100:.1f}%")
                em2.metric("Recall", f"{m.get('recall', 0.0) * 100:.1f}%")
                em3.metric("F1 Score", f"{m.get('f1_score', 0.0) * 100:.1f}%")

                st.markdown("##### Confusion Matrix")
                cm_df = pd.DataFrame(
                    [
                        [cm.get("tp", 0), cm.get("fn", 0)],
                        [cm.get("fp", 0), cm.get("tn", 0)],
                    ],
                    index=["Actual Attack", "Actual Benign"],
                    columns=["Predicted Attack", "Predicted Benign"],
                )
                st.table(cm_df)

                if eval_res.get("class_breakdown"):
                    st.markdown("##### Threat Class Breakdown")
                    st.dataframe(pd.DataFrame(eval_res["class_breakdown"]).T, use_container_width=True)

        with eval_col2:
            st.markdown("#### Benchmark Suite Across All 5 Scenarios")
            if st.button("🚀 Run Full Automated Benchmark Suite", key="btn_run_bench"):
                with st.spinner("Benchmarking all 5 canonical scenarios..."):
                    bench_df = benchmark_all_scenarios("data/synthetic", config=det_config)
                    st.session_state["benchmark_df"] = bench_df

            if "benchmark_df" in st.session_state:
                st.dataframe(st.session_state["benchmark_df"], use_container_width=True)
            else:
                st.caption("Click the button above to execute automated evaluation across all 5 benchmark scenarios.")

            st.markdown("---")
            st.markdown(
                """
                **Scientific Formulas for Defense:**
                - **Precision:** $\\frac{TP}{TP + FP}$ *(Alert Fidelity)*
                - **Recall:** $\\frac{TP}{TP + FN}$ *(Detection Coverage)*
                - **F1 Score:** $2 \\cdot \\frac{\\text{Precision} \\cdot \\text{Recall}}{\\text{Precision} + \\text{Recall}}$
                - **False Positive Rate:** $\\frac{FP}{FP + TN}$
                """
            )


if __name__ == "__main__":
    main()
