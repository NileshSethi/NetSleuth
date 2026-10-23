"""NetSleuth: Explainable Network Threat Investigation & Attack Reconstruction System."""

import sys
# Invalidate in-memory cached submodules so long-running Streamlit instances load fresh code
for _mod in list(sys.modules.keys()):
    if _mod.startswith("src.netsleuth"):
        del sys.modules[_mod]

import os
import glob
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from src.netsleuth.loader import load_flows
from src.netsleuth.detectors import run_all_detectors
from src.netsleuth.incidents import build_incidents, generate_forensic_dossier
from src.netsleuth.graph import plot_graph, get_top_communicators
from src.netsleuth.evaluation import evaluate_all_scenarios

# Configure Streamlit page layout and branding
st.set_page_config(
    page_title="NetSleuth | Network Threat Investigation Platform",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enterprise Academic & SOC Styling (CSS Injection)
st.markdown("""
<style>
    /* Compact top padding so header seamlessly pins to the top */
    .block-container {
        padding-top: 1rem !important;
        padding-bottom: 2rem !important;
        max-width: 98% !important;
    }

    /* Hide default Streamlit chrome header decorations */
    header[data-testid="stHeader"] {
        background: transparent !important;
        height: 1.5rem !important;
    }
    #MainMenu, footer, .stDeployButton {
        display: none !important;
    }

    /* Dark SOC command background and typography */
    .stApp {
        background-color: #070B14;
        color: #E2E8F0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }

    /* Seamless Executive SOC Header Banner */
    .soc-header-banner {
        background: linear-gradient(135deg, #0B132B 0%, #1C2541 50%, #0B132B 100%);
        border: 1px solid rgba(56, 189, 248, 0.3);
        border-top: 3px solid #38BDF8;
        border-radius: 8px;
        padding: 20px 24px;
        margin-bottom: 18px;
        box-shadow: 0 8px 30px rgba(0, 0, 0, 0.45);
    }
    .soc-header-top {
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 12px;
        margin-bottom: 8px;
    }
    .soc-category-tag {
        font-size: 0.72rem;
        font-weight: 800;
        letter-spacing: 0.14em;
        text-transform: uppercase;
        color: #38BDF8;
        background: rgba(56, 189, 248, 0.12);
        border: 1px solid rgba(56, 189, 248, 0.35);
        padding: 3px 8px;
        border-radius: 4px;
        display: inline-block;
    }
    .soc-main-title {
        font-size: 2.3rem;
        font-weight: 900;
        letter-spacing: -0.02em;
        margin: 0;
        line-height: 1.1;
        background: linear-gradient(90deg, #FFFFFF 0%, #BAE6FD 50%, #38BDF8 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .soc-version-badge {
        font-size: 0.75rem;
        font-weight: 700;
        color: #94A3B8;
        background: #0F172A;
        border: 1px solid #334155;
        padding: 2px 8px;
        border-radius: 12px;
        margin-left: 8px;
        vertical-align: middle;
        -webkit-text-fill-color: #94A3B8;
    }
    .soc-sub-title {
        font-size: 0.98rem;
        color: #94A3B8;
        margin: 6px 0 14px 0;
        line-height: 1.4;
    }
    .soc-meta-pills {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
    }
    .soc-pill {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        font-size: 0.75rem;
        font-weight: 600;
        color: #CBD5E1;
        background: rgba(15, 23, 42, 0.85);
        border: 1px solid rgba(148, 163, 184, 0.25);
        border-radius: 4px;
        padding: 4px 10px;
    }
    .soc-pill-active {
        color: #34D399;
        border-color: rgba(52, 211, 153, 0.4);
        background: rgba(16, 185, 129, 0.12);
    }

    /* KPI Summary Card Styling */
    .kpi-container {
        display: grid;
        grid-template-columns: repeat(5, 1fr);
        gap: 12px;
        margin-bottom: 20px;
    }
    .kpi-card {
        background: rgba(15, 23, 42, 0.85);
        border: 1px solid rgba(148, 163, 184, 0.18);
        border-radius: 6px;
        padding: 12px 16px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
    }
    .kpi-label {
        color: #94A3B8;
        font-size: 0.72rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-bottom: 4px;
    }
    .kpi-value {
        color: #F8FAFC;
        font-size: 1.8rem;
        font-weight: 800;
        line-height: 1.2;
    }

    /* Incident Card Glassmorphism Container */
    .incident-panel {
        background: rgba(15, 23, 42, 0.9);
        border: 1px solid rgba(56, 189, 248, 0.25);
        border-radius: 8px;
        padding: 22px;
        margin-bottom: 20px;
        box-shadow: 0 6px 20px rgba(0, 0, 0, 0.35);
    }

    /* Severity Badges */
    .badge-critical {
        background: rgba(239, 68, 68, 0.2);
        color: #F87171;
        border: 1px solid #EF4444;
        padding: 4px 12px;
        border-radius: 4px;
        font-weight: 800;
        font-size: 0.85rem;
        letter-spacing: 0.08em;
    }
    .badge-high {
        background: rgba(249, 115, 22, 0.2);
        color: #FB923C;
        border: 1px solid #F97316;
        padding: 4px 12px;
        border-radius: 4px;
        font-weight: 800;
        font-size: 0.85rem;
        letter-spacing: 0.08em;
    }
    .badge-medium {
        background: rgba(245, 158, 11, 0.2);
        color: #FBBF24;
        border: 1px solid #F59E0B;
        padding: 4px 12px;
        border-radius: 4px;
        font-weight: 800;
        font-size: 0.85rem;
        letter-spacing: 0.08em;
    }
    .badge-low {
        background: rgba(16, 185, 129, 0.2);
        color: #34D399;
        border: 1px solid #10B981;
        padding: 4px 12px;
        border-radius: 4px;
        font-weight: 800;
        font-size: 0.85rem;
        letter-spacing: 0.08em;
    }

    /* --------------------------------------------------------- */
    /* PROMINENT MITRE ATT&CK KILL CHAIN PROGRESSION PIPELINE     */
    /* --------------------------------------------------------- */
    .kc-pipeline-wrapper {
        background: #0A0F1D;
        border: 1px solid rgba(56, 189, 248, 0.2);
        border-radius: 8px;
        padding: 16px;
        margin: 16px 0;
    }
    .kc-pipeline-title {
        font-size: 0.82rem;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        color: #38BDF8;
        margin-bottom: 12px;
        display: flex;
        align-items: center;
        gap: 6px;
    }
    .kc-pipeline-stepper {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
        flex-wrap: wrap;
    }
    .kc-stage-card {
        flex: 1;
        min-width: 220px;
        padding: 12px 14px;
        border-radius: 6px;
        transition: all 0.2s ease;
    }
    .kc-stage-active-recon {
        background: linear-gradient(135deg, rgba(2, 132, 199, 0.25) 0%, rgba(15, 23, 42, 0.9) 100%);
        border: 1.5px solid #38BDF8;
        box-shadow: 0 0 15px rgba(56, 189, 248, 0.25);
    }
    .kc-stage-active-lateral {
        background: linear-gradient(135deg, rgba(245, 158, 11, 0.25) 0%, rgba(15, 23, 42, 0.9) 100%);
        border: 1.5px solid #F59E0B;
        box-shadow: 0 0 15px rgba(245, 158, 11, 0.25);
    }
    .kc-stage-active-exfil {
        background: linear-gradient(135deg, rgba(239, 68, 68, 0.25) 0%, rgba(15, 23, 42, 0.9) 100%);
        border: 1.5px solid #EF4444;
        box-shadow: 0 0 15px rgba(239, 68, 68, 0.25);
    }
    .kc-stage-inactive {
        background: rgba(15, 23, 42, 0.45);
        border: 1px dashed rgba(100, 116, 139, 0.35);
        opacity: 0.55;
    }
    .kc-stage-num {
        font-size: 0.7rem;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-bottom: 4px;
    }
    .kc-stage-name {
        font-size: 0.95rem;
        font-weight: 800;
        color: #F8FAFC;
        margin-bottom: 4px;
    }
    .kc-stage-tech {
        font-size: 0.75rem;
        font-family: monospace;
        color: #94A3B8;
    }
    .kc-stage-status-badge {
        display: inline-block;
        font-size: 0.68rem;
        font-weight: 700;
        padding: 2px 6px;
        border-radius: 3px;
        margin-top: 6px;
        text-transform: uppercase;
    }
    .kc-arrow {
        color: #475569;
        font-size: 1.4rem;
        font-weight: 800;
        user-select: none;
    }

    /* Risk Score Gauge Box */
    .risk-score-box {
        background: rgba(10, 15, 29, 0.9);
        border: 1px solid rgba(148, 163, 184, 0.25);
        border-radius: 8px;
        padding: 16px;
        text-align: center;
    }
    .risk-score-num {
        font-size: 2.4rem;
        font-weight: 900;
        line-height: 1;
        margin-bottom: 6px;
    }
    .risk-bar-container {
        height: 8px;
        background: rgba(51, 65, 85, 0.5);
        border-radius: 4px;
        overflow: hidden;
        margin: 8px 0;
    }
    .risk-bar-fill {
        height: 100%;
        border-radius: 4px;
    }

    /* Tabs styling */
    button[data-baseweb="tab"] {
        color: #94A3B8 !important;
        font-weight: 700 !important;
        font-size: 0.95rem !important;
    }
    button[aria-selected="true"] {
        color: #38BDF8 !important;
        border-bottom-color: #38BDF8 !important;
    }

    /* --------------------------------------------------------- */
    /* ULTRA-PREMIUM TACTICAL CYBER SIDEBAR STYLING              */
    /* --------------------------------------------------------- */
    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, #070B14 0%, #0D1527 50%, #070B14 100%) !important;
        border-right: 1px solid rgba(56, 189, 248, 0.22) !important;
        box-shadow: 6px 0 24px rgba(0, 0, 0, 0.55);
    }
    section[data-testid="stSidebar"] div.block-container {
        padding-top: 1.2rem !important;
        padding-left: 1rem !important;
        padding-right: 1rem !important;
    }

    /* Sidebar Brand Title */
    .sidebar-header-box {
        margin-bottom: 12px;
        padding-bottom: 8px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    }
    .sidebar-brand-name {
        font-size: 1.35rem;
        font-weight: 800;
        letter-spacing: 0.04em;
        line-height: 1.1;
        color: #F8FAFC;
        margin: 2px 0;
    }
    .sidebar-brand-desc {
        color: #64748B;
        font-size: 0.72rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.06em;
    }

    /* Streamlined Scenario Summary Card */
    .scenario-summary-box {
        background: rgba(15, 23, 42, 0.7);
        border: 1px solid rgba(148, 163, 184, 0.15);
        border-radius: 6px;
        padding: 10px 12px;
        margin: 8px 0 12px 0;
    }
    .scenario-summary-title {
        font-size: 0.82rem;
        font-weight: 700;
        color: #F1F5F9;
        margin-bottom: 6px;
        line-height: 1.3;
    }
    .scenario-meta-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-size: 0.72rem;
        margin-bottom: 4px;
    }
    .scenario-meta-label {
        color: #64748B;
        font-weight: 600;
    }
    .scenario-meta-val {
        color: #CBD5E1;
        font-family: monospace;
        font-weight: 600;
        font-size: 0.72rem;
    }

    /* Streamlined Detection Heuristics List */
    .heuristics-box {
        background: rgba(15, 23, 42, 0.5);
        border: 1px solid rgba(148, 163, 184, 0.12);
        border-radius: 6px;
        padding: 8px 10px;
        margin: 6px 0 12px 0;
    }
    .heuristic-row {
        padding: 5px 0;
        border-bottom: 1px solid rgba(255, 255, 255, 0.04);
    }
    .heuristic-row:last-child {
        border-bottom: none;
    }
    .heuristic-name {
        font-size: 0.73rem;
        font-weight: 700;
        color: #E2E8F0;
    }
    .heuristic-spec {
        font-size: 0.7rem;
        font-family: monospace;
        color: #94A3B8;
    }

    /* Minimal About Box */
    .about-sidebar-box {
        font-size: 0.72rem;
        color: #64748B;
        line-height: 1.4;
        padding-top: 8px;
        border-top: 1px solid rgba(255, 255, 255, 0.06);
    }

    /* Incident Details Seamless Balanced Grid */
    .incident-details-grid {
        display: grid;
        grid-template-columns: 1fr 1.15fr;
        gap: 16px;
        margin-top: 14px;
        align-items: stretch;
    }
    @media (max-width: 900px) {
        .incident-details-grid {
            grid-template-columns: 1fr;
        }
    }
    .grid-col-card {
        background: rgba(10, 15, 29, 0.7);
        border: 1px solid rgba(148, 163, 184, 0.18);
        border-radius: 8px;
        padding: 16px 18px;
        display: flex;
        flex-direction: column;
        justify-content: flex-start;
        box-shadow: 0 4px 14px rgba(0, 0, 0, 0.25);
    }
    .detail-card-title {
        font-size: 0.78rem;
        font-weight: 800;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: #94A3B8;
        margin-bottom: 12px;
        display: flex;
        align-items: center;
        gap: 6px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        padding-bottom: 8px;
    }
    .audit-item {
        background: rgba(15, 23, 42, 0.85);
        border: 1px solid rgba(56, 189, 248, 0.22);
        border-radius: 5px;
        padding: 7px 11px;
        margin-bottom: 7px;
        font-family: monospace;
        font-size: 0.82rem;
        color: #38BDF8;
    }
    .target-tag {
        display: inline-block;
        background: rgba(56, 189, 248, 0.12);
        border: 1px solid rgba(56, 189, 248, 0.35);
        color: #38BDF8;
        font-family: monospace;
        font-size: 0.82rem;
        font-weight: 700;
        padding: 4px 10px;
        border-radius: 4px;
        margin: 3px 6px 3px 0;
    }
    .playbook-step {
        background: rgba(15, 23, 42, 0.85);
        border-left: 3.5px solid #38BDF8;
        border-radius: 0 6px 6px 0;
        padding: 10px 14px;
        margin-bottom: 10px;
        font-size: 0.83rem;
        line-height: 1.45;
        color: #CBD5E1;
    }
</style>
""", unsafe_allow_html=True)

# Helper function to format UTC timestamps cleanly
def format_time(t) -> str:
    """Format timestamp into standardized UTC representation."""
    try:
        ts = pd.to_datetime(t)
        return ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(t)

# Helper to format bytes
def format_bytes_human(b: int) -> str:
    if b >= 1_000_000:
        return f"{b / 1_000_000:.2f} MB"
    elif b >= 1_000:
        return f"{b / 1_000:.1f} KB"
    return f"{b:,} B"

# -------------------------------------------------------------
# SIDEBAR CONFIGURATION: TACTICAL INVESTIGATION DECK
# -------------------------------------------------------------
st.sidebar.html("""
<div class="sidebar-header-box">
    <div class="sidebar-brand-name">NetSleuth</div>
    <div class="sidebar-brand-desc">Cloud Network Threat Forensics</div>
</div>
""")

data_dir = "data/synthetic"
scenario_files = sorted(glob.glob(os.path.join(data_dir, "*.csv")))

scenario_display_names = {
    "scenario1_port_scan.csv": "Scenario 1 — External Port Scan (Reconnaissance)",
    "scenario2_host_scan.csv": "Scenario 2 — Internal Host Sweep (Lateral Movement)",
    "scenario3_data_exfiltration.csv": "Scenario 3 — Outbound Data Exfiltration (Data Theft)",
    "scenario4_multi_stage.csv": "Scenario 4 — Multi-Stage Enterprise Attack (Full Kill Chain)",
    "scenario5_benign.csv": "Scenario 5 — Benign Baseline Traffic (Zero False Alarms)",
    "scenario6_persistent_threat.csv": "Scenario 6 — Persistent Threat Actor (Temporal Session Split)",
    "scenario7_coordinated_attack.csv": "Scenario 7 — Coordinated Multi-Host Intrusion (Dual Attackers)",
    "scenario8_cloud_data_breach.csv": "Scenario 8 — Cloud Database Breach (Massive 12 MB Exfil)"
}

SCENARIO_DOSSIERS = {
    "scenario1_port_scan.csv": {
        "title": "External Reconnaissance Probe",
        "actor": "198.51.100.55",
        "target": "10.0.1.20 (Web Server)",
        "vector": "18 Ports in 17s (Vertical Scan)",
        "mitre": "T1046: Network Service Discovery"
    },
    "scenario2_host_scan.csv": {
        "title": "Internal Lateral Movement Sweep",
        "actor": "10.0.1.15",
        "target": "12 Subnet Endpoints",
        "vector": "Port 445 SMB Horizontal Sweep",
        "mitre": "T1018: Remote System Discovery"
    },
    "scenario3_data_exfiltration.csv": {
        "title": "Outbound Asset Exfiltration",
        "actor": "10.0.1.45",
        "target": "203.0.113.88 (External C2)",
        "vector": "2,400,000 Bytes in 24s",
        "mitre": "T1048: Exfiltration Over Alt. Protocol"
    },
    "scenario4_multi_stage.csv": {
        "title": "Full Enterprise Kill Chain Intrusion",
        "actor": "10.0.1.99",
        "target": "10.0.1.20, Subnet, 203.0.113.88",
        "vector": "Port Scan → Subnet Sweep → 6.3 MB Exfil",
        "mitre": "T1046 → T1018 → T1048"
    },
    "scenario5_benign.csv": {
        "title": "Subnet Normal Baseline Traffic",
        "actor": "Normal Subnet Hosts",
        "target": "DNS, Web, SSH, Email",
        "vector": "Zero Malicious Flows (320 flows)",
        "mitre": "Normal Baseline Operations"
    },
    "scenario6_persistent_threat.csv": {
        "title": "Temporal Session Boundary Split",
        "actor": "10.0.1.105",
        "target": "10.0.1.20 & RDP Endpoints",
        "vector": "Scan (T+60s) → 12m Gap → Exfiltration",
        "mitre": "T1046 (Recon) & T1048 (Theft)"
    },
    "scenario7_coordinated_attack.csv": {
        "title": "Coordinated Multi-Host Intrusion",
        "actor": "198.51.100.77 & 10.0.1.55",
        "target": "Perimeter Host & Internal SSH",
        "vector": "External Probe + Internal 3.5 MB Exfil",
        "mitre": "T1046 (Ext) & T1018/T1048 (Int)"
    },
    "scenario8_cloud_data_breach.csv": {
        "title": "Cloud Database Massive Exfil",
        "actor": "10.0.1.80",
        "target": "203.0.113.200 (Adversary Drop)",
        "vector": "12,000,000 Bytes (10x1.2 MB)",
        "mitre": "T1048: Data Theft"
    }
}

scenario_options = {}
for f in scenario_files:
    fname = os.path.basename(f)
    disp = scenario_display_names.get(fname, fname.replace(".csv", "").replace("_", " ").title())
    scenario_options[disp] = f

# Default to Scenario 4 (Multi-Stage Enterprise Attack)
default_idx = 3 if len(scenario_options) > 3 else 0
st.sidebar.markdown("<div style='font-size:0.75rem; font-weight:700; letter-spacing:0.06em; text-transform:uppercase; color:#94A3B8; margin-bottom:4px;'>INVESTIGATION SCENARIO:</div>", unsafe_allow_html=True)
choice = st.sidebar.selectbox("Active Benchmark Scenario", list(scenario_options.keys()), index=default_idx, label_visibility="collapsed")
selected_file = scenario_options.get(choice)

# Streamlined Scenario Summary
if selected_file:
    curr_fname = os.path.basename(selected_file)
    meta = SCENARIO_DOSSIERS.get(curr_fname, {})
    if meta:
        st.sidebar.html(f"""
        <div class="scenario-summary-box">
            <div class="scenario-summary-title">{meta['title']}</div>
            <div class="scenario-meta-row">
                <span class="scenario-meta-label">Threat Actor:</span>
                <span class="scenario-meta-val">{meta['actor']}</span>
            </div>
            <div class="scenario-meta-row">
                <span class="scenario-meta-label">Target:</span>
                <span class="scenario-meta-val">{meta['target']}</span>
            </div>
            <div class="scenario-meta-row">
                <span class="scenario-meta-label">Vector:</span>
                <span class="scenario-meta-val">{meta['vector']}</span>
            </div>
            <div class="scenario-meta-row">
                <span class="scenario-meta-label">MITRE Ref:</span>
                <span class="scenario-meta-val">{meta['mitre']}</span>
            </div>
        </div>
        """)

# Active Detection Heuristics List
st.sidebar.html("""
<div style="font-size:0.72rem; font-weight:700; letter-spacing:0.06em; text-transform:uppercase; color:#64748B; margin-top:10px; margin-bottom:4px;">
    Detection Rules (Sliding Windows)
</div>
<div class="heuristics-box">
    <div class="heuristic-row">
        <div class="heuristic-name">Port Scan &bull; T1046</div>
        <div class="heuristic-spec">&ge; 10 unique ports / 60s</div>
    </div>
    <div class="heuristic-row">
        <div class="heuristic-name">Host Sweep &bull; T1018</div>
        <div class="heuristic-spec">&ge; 5 unique hosts / 60s</div>
    </div>
    <div class="heuristic-row">
        <div class="heuristic-name">Data Exfiltration &bull; T1048</div>
        <div class="heuristic-spec">&ge; 500 KB outbound / 120s</div>
    </div>
</div>
""")

# Minimal About NetSleuth
st.sidebar.html("""
<div class="about-sidebar-box">
    <div style="font-size:0.72rem; font-weight:700; text-transform:uppercase; letter-spacing:0.06em; color:#64748B; margin-bottom:3px;">About NetSleuth</div>
    <div>An explainable network threat analysis engine for AWS VPC Flow Logs. Uses deterministic sliding windows and additive scoring to correlate attack milestones without black-box ML.</div>
</div>
""")

if not selected_file:
    st.warning("Please select a network flow scenario to initialize analysis.")
    st.stop()

# Ingest and sanitize dataset
try:
    df, dropped_rows = load_flows(selected_file)
except Exception as e:
    st.error(f"Failed to ingest flow records: {e}")
    st.stop()

# Execute threat correlation and incident generation
alerts = run_all_detectors(df)
incidents = build_incidents(alerts)

# Compute global threat posture
highest_level = "NORMAL"
max_score = 0
if incidents:
    scores = [inc["score"] for inc in incidents]
    max_score = max(scores)
    if max_score >= 80:
        highest_level = "CRITICAL"
    elif max_score >= 60:
        highest_level = "HIGH"
    elif max_score >= 30:
        highest_level = "MEDIUM"
    else:
        highest_level = "LOW"

# -------------------------------------------------------------
# SEAMLESS EXECUTIVE SOC HEADER BANNER
# -------------------------------------------------------------
st.markdown("""
<div class="soc-header-banner">
    <div class="soc-header-top">
        <div>
            <span class="soc-category-tag">Cloud Network Threat Investigation</span>
            <div style="display: flex; align-items: baseline; gap: 8px; margin-top: 4px;">
                <h1 class="soc-main-title">NetSleuth</h1>
                <span class="soc-version-badge">SOC v2.4 Enterprise</span>
            </div>
        </div>
        <div style="text-align: right;">
            <span class="soc-pill soc-pill-active">ENGINE ONLINE</span>
        </div>
    </div>
    <div class="soc-sub-title">An Explainable Network Threat Investigation, Incident Timeline Reconstruction, and Forensic Analysis System</div>
    <div class="soc-meta-pills">
        <span class="soc-pill">AWS VPC Flow Log Specification</span>
        <span class="soc-pill">MITRE ATT&amp;CK Enterprise Matrix</span>
        <span class="soc-pill">Deterministic Sliding Windows</span>
        <span class="soc-pill">Additive Scoring (0–100)</span>
        <span class="soc-pill">Zero Label Leakage Verified</span>
    </div>
</div>
""", unsafe_allow_html=True)

# -------------------------------------------------------------
# TOP EXECUTIVE KPI SUMMARY BAR
# -------------------------------------------------------------
posture_color = {
    "CRITICAL": "#F87171",
    "HIGH": "#FB923C",
    "MEDIUM": "#FBBF24",
    "LOW": "#34D399",
    "NORMAL": "#38BDF8"
}.get(highest_level, "#38BDF8")

st.markdown(f"""
<div class="kpi-container">
    <div class="kpi-card">
        <div class="kpi-label">Flow Records</div>
        <div class="kpi-value">{len(df):,}</div>
    </div>
    <div class="kpi-card">
        <div class="kpi-label">Alerts Triggered</div>
        <div class="kpi-value" style="color: {'#FBBF24' if len(alerts) > 0 else '#34D399'};">{len(alerts)}</div>
    </div>
    <div class="kpi-card">
        <div class="kpi-label">Correlated Incidents</div>
        <div class="kpi-value" style="color: {'#F87171' if len(incidents) > 0 else '#34D399'};">{len(incidents)}</div>
    </div>
    <div class="kpi-card">
        <div class="kpi-label">Dropped Corrupt</div>
        <div class="kpi-value" style="color: #94A3B8;">{dropped_rows}</div>
    </div>
    <div class="kpi-card" style="border-color: {posture_color}44;">
        <div class="kpi-label">System Threat Posture</div>
        <div class="kpi-value" style="color: {posture_color};">{highest_level}</div>
    </div>
</div>
""", unsafe_allow_html=True)

# -------------------------------------------------------------
# FIVE STRUCTURED ANALYTIC TABS
# -------------------------------------------------------------
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "Threat Incidents",
    "Attack Timeline",
    "Network Topology",
    "Flow Telemetry",
    "Forensic Dossier & Evaluation"
])

# -------------------------------------------------------------
# TAB 1: THREAT INCIDENTS & PROMINENT KILL CHAIN PROGRESSION
# -------------------------------------------------------------
with tab1:
    st.subheader("Correlated Threat Incidents & Explainable Scoring")
    if not incidents:
        st.info("Defensive Telemetry Clean: Zero malicious threat signatures identified in this flow capture.")
    else:
        for inc in incidents:
            badge_class = f"badge-{inc['level'].lower()}"
            t_start = format_time(inc["start_time"])
            t_end = format_time(inc["end_time"])

            # Determine presence of each MITRE stage for this incident
            has_recon = "port_scan" in inc["rules_triggered"]
            has_lateral = "host_scan" in inc["rules_triggered"]
            has_exfil = "exfiltration" in inc["rules_triggered"]

            recon_card_class = "kc-stage-card kc-stage-active-recon" if has_recon else "kc-stage-card kc-stage-inactive"
            lateral_card_class = "kc-stage-card kc-stage-active-lateral" if has_lateral else "kc-stage-card kc-stage-inactive"
            exfil_card_class = "kc-stage-card kc-stage-active-exfil" if has_exfil else "kc-stage-card kc-stage-inactive"

            recon_badge = "<span class='kc-stage-status-badge' style='background:#0284C7; color:#FFF;'>ACTIVE / TRIGGERED</span>" if has_recon else "<span class='kc-stage-status-badge' style='background:#334155; color:#94A3B8;'>NOT OBSERVED</span>"
            lateral_badge = "<span class='kc-stage-status-badge' style='background:#D97706; color:#FFF;'>ACTIVE / TRIGGERED</span>" if has_lateral else "<span class='kc-stage-status-badge' style='background:#334155; color:#94A3B8;'>NOT OBSERVED</span>"
            exfil_badge = "<span class='kc-stage-status-badge' style='background:#DC2626; color:#FFF;'>ACTIVE / TRIGGERED</span>" if has_exfil else "<span class='kc-stage-status-badge' style='background:#334155; color:#94A3B8;'>NOT OBSERVED</span>"

            # Color styling for risk score
            score_color = {
                "Critical": "#EF4444",
                "High": "#F97316",
                "Medium": "#F59E0B",
                "Low": "#10B981"
            }.get(inc["level"], "#38BDF8")

            # Format breakdown items with high-contrast styling
            audit_items_html = ""
            for item in inc["breakdown"]:
                if "Total calculated priority score" in item:
                    audit_items_html += f'<div class="audit-item" style="border-color: {score_color}; background: rgba(56, 189, 248, 0.12); color: #F8FAFC; font-weight: 700;">{item}</div>'
                else:
                    audit_items_html += f'<div class="audit-item"><span style="color:#38BDF8;">+</span> {item}</div>'

            # Format targeted assets tags
            if inc["targets"]:
                target_chips = "".join([f'<span class="target-tag">{t}</span>' for t in inc["targets"]])
                target_chips_html = f'<div style="display: flex; flex-wrap: wrap; gap: 6px;">{target_chips}</div><div style="font-size:0.75rem; color:#94A3B8; margin-top:8px;"><b>Scope:</b> {len(inc["targets"])} internal target endpoint(s) impacted.</div>'
            else:
                target_chips_html = '<span style="color:#94A3B8; font-size:0.8rem;">Multiple subnet endpoints scanned during horizontal sweep.</span>'

            # Format remediation steps with clean HTML
            import re
            playbook_steps_html = ""
            for idx, act in enumerate(inc["remediations"], start=1):
                cleaned = act.replace("**", "")
                if ":" in cleaned:
                    title, desc = cleaned.split(":", 1)
                    desc_styled = re.sub(r"`([^`]+)`", r'<code style="font-family:monospace; color:#38BDF8; background:rgba(56,189,248,0.15); padding:1px 6px; border-radius:3px; border:1px solid rgba(56,189,248,0.25);">\1</code>', desc.strip())
                    playbook_steps_html += f'<div class="playbook-step"><strong style="color:#F8FAFC;">{idx:02d}. {title.strip()}:</strong> <span style="color:#CBD5E1;">{desc_styled}</span></div>'
                else:
                    playbook_steps_html += f'<div class="playbook-step">{idx:02d}. {cleaned}</div>'

            with st.container():
                st.html(f"""
                <div class="incident-panel">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 16px; margin-bottom: 16px;">
                        <div>
                            <div style="font-size: 1.4rem; font-weight: 800; color: #F8FAFC; margin-bottom: 4px;">
                                {inc['incident_id']} — Threat Actor IP: 
                                <span style="font-family: monospace; color: #38BDF8; background: #0F172A; padding: 2px 10px; border-radius: 4px; border: 1px solid #1E293B;">{inc['src_ip']}</span>
                                <span class="{badge_class}" style="margin-left: 8px;">{inc['level'].upper()} PRIORITY</span>
                            </div>
                            <div style="color: #94A3B8; font-size: 0.88rem;">
                                <b>Investigation Interval:</b> {t_start} to {t_end} &nbsp;|&nbsp; 
                                <b>Session Duration:</b> {inc['duration_seconds']}s &nbsp;|&nbsp; 
                                <b>Correlated Alerts:</b> {inc['alert_count']} alert(s) &nbsp;|&nbsp; 
                                <b>Total Transferred:</b> {format_bytes_human(inc['total_bytes'])}
                            </div>
                        </div>
                        <div class="risk-score-box" style="min-width: 220px; border-color: {score_color}66;">
                            <div style="font-size: 0.72rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.1em; color: #94A3B8;">PRIORITY RISK SCORE</div>
                            <div class="risk-score-num" style="color: {score_color};">{inc['score']} <span style="font-size: 1rem; color: #94A3B8;">/ 100</span></div>
                            <div class="risk-bar-container">
                                <div class="risk-bar-fill" style="width: {inc['score']}%; background: {score_color};"></div>
                            </div>
                            <div style="font-size: 0.75rem; font-weight: 700; color: {score_color}; text-transform: uppercase;">{inc['level']} Priority Rating</div>
                        </div>
                    </div>

                    <!-- PROMINENT VISUAL MITRE ATT&CK KILL CHAIN PROGRESSION -->
                    <div class="kc-pipeline-wrapper">
                        <div class="kc-pipeline-title">
                            MITRE ATT&amp;CK Cyber Kill Chain Attack Progression
                        </div>
                        <div class="kc-pipeline-stepper">
                            <div class="{recon_card_class}">
                                <div class="kc-stage-num" style="color: {'#38BDF8' if has_recon else '#64748B'};">STAGE 1: DISCOVERY</div>
                                <div class="kc-stage-name">Reconnaissance</div>
                                <div class="kc-stage-tech">T1046: Network Service Discovery</div>
                                {recon_badge}
                            </div>
                            <div class="kc-arrow">&rarr;</div>
                            <div class="{lateral_card_class}">
                                <div class="kc-stage-num" style="color: {'#F59E0B' if has_lateral else '#64748B'};">STAGE 2: SPREAD</div>
                                <div class="kc-stage-name">Lateral Movement Prep</div>
                                <div class="kc-stage-tech">T1018: Remote System Discovery</div>
                                {lateral_badge}
                            </div>
                            <div class="kc-arrow">&rarr;</div>
                            <div class="{exfil_card_class}">
                                <div class="kc-stage-num" style="color: {'#EF4444' if has_exfil else '#64748B'};">STAGE 3: OBJECTIVES</div>
                                <div class="kc-stage-name">Actions on Objectives</div>
                                <div class="kc-stage-tech">T1048: Data Exfiltration</div>
                                {exfil_badge}
                            </div>
                        </div>
                    </div>

                    <!-- SEAMLESS BALANCED FORENSIC EVIDENCE & PLAYBOOK GRID -->
                    <div class="incident-details-grid">
                        <!-- LEFT CARD: FORENSIC SCORE AUDIT & TARGET SCOPE -->
                        <div class="grid-col-card">
                            <div class="detail-card-title">
                                EXPLAINABLE SCORE CALCULATION
                            </div>
                            <div style="margin-bottom: 12px;">
                                {audit_items_html}
                            </div>

                            <div class="detail-card-title" style="margin-top: auto; padding-top: 10px;">
                                TARGETED ASSETS &amp; IMPACT SCOPE
                            </div>
                            <div>
                                {target_chips_html}
                            </div>
                        </div>

                        <!-- RIGHT CARD: PRESCRIPTIVE CONTAINMENT PLAYBOOK (SOP) -->
                        <div class="grid-col-card" style="border-left: 3.5px solid #38BDF8;">
                            <div class="detail-card-title">
                                PRESCRIPTIVE CONTAINMENT PLAYBOOK (SOP)
                            </div>
                            <div>
                                {playbook_steps_html}
                            </div>
                        </div>
                    </div>
                </div>
                """)

                st.write("")
                with st.expander(f"Inspect {len(inc['alerts'])} Associated Alert Milestone(s)"):
                    alert_table = pd.DataFrame(inc["alerts"])[["alert_id", "rule", "severity", "target", "reason"]]
                    alert_table.columns = ["Alert ID", "Rule Name", "Severity", "Target", "Finding Summary"]
                    st.dataframe(alert_table, use_container_width=True)


# -------------------------------------------------------------
# TAB 2: ATTACK TIMELINE
# -------------------------------------------------------------
with tab2:
    st.subheader("Chronological Attack Progression & Kill Chain Narrative")
    all_events = []
    for inc in incidents:
        for ev in inc["timeline"]:
            all_events.append({
                "Incident ID": inc["incident_id"],
                "Timestamp": format_time(ev["time"]),
                "Raw Timestamp": pd.to_datetime(ev["time"]),
                "Kill Chain Stage": ev["stage"],
                "Rule Name": ev["rule"],
                "MITRE Reference": f"{ev['mitre_id']}: {ev['mitre_name']}",
                "Severity": ev["severity"],
                "Target": ev["target"],
                "Finding Summary": ev["reason"]
            })

    if not all_events:
        st.info("No suspicious timeline milestones recorded.")
    else:
        t_df = pd.DataFrame(all_events).sort_values(by="Raw Timestamp")

        fig_time = px.scatter(
            t_df,
            x="Raw Timestamp",
            y="Kill Chain Stage",
            color="Severity",
            symbol="Rule Name",
            hover_data=["Incident ID", "Target", "MITRE Reference", "Finding Summary"],
            title="Chronological Incident Progression by Kill Chain Phase",
            color_discrete_map={"LOW": "#38BDF8", "MEDIUM": "#F59E0B", "HIGH": "#EF4444"},
            template="plotly_dark"
        )
        fig_time.update_traces(marker=dict(size=14, line=dict(width=1.5, color="#F8FAFC")))
        fig_time.update_layout(
            height=340,
            margin=dict(l=20, r=20, t=50, b=20),
            xaxis_title="Observed Event Timestamp (UTC)",
            yaxis_title="Kill Chain Phase",
            paper_bgcolor="rgba(15, 23, 42, 0.95)",
            plot_bgcolor="rgba(15, 23, 42, 0.95)"
        )
        st.plotly_chart(fig_time, use_container_width=True)

        st.markdown("**Chronological Incident Audit Trail:**")
        display_t_df = t_df.drop(columns=["Raw Timestamp"])
        st.dataframe(display_t_df, use_container_width=True)

# -------------------------------------------------------------
# TAB 3: NETWORK TOPOLOGY
# -------------------------------------------------------------
with tab3:
    st.subheader("Host Communication Topology & Traffic Distribution")
    top_col, bottom_col = st.columns([3, 2])
    with top_col:
        fig_graph = plot_graph(df, incidents)
        st.plotly_chart(fig_graph, use_container_width=True)
    with bottom_col:
        st.markdown("**Top Communicating Host Pairs (Volume & Frequency):**")
        matrix_df = get_top_communicators(df, top_n=8)
        st.dataframe(matrix_df, use_container_width=True)

        st.caption("Visual Legend: Red = Confirmed Threat Actor IP | Amber = Targeted Host | Cyan = Normal Subnet Host")

# -------------------------------------------------------------
# TAB 4: FLOW TELEMETRY
# -------------------------------------------------------------
with tab4:
    st.subheader("Network Flow Telemetry & Protocol Inspection")
    chart1, chart2, chart3 = st.columns(3)

    with chart1:
        proto_counts = df["protocol"].value_counts().reset_index()
        proto_counts.columns = ["Protocol", "Count"]
        fig_proto = px.pie(
            proto_counts,
            names="Protocol",
            values="Count",
            title="Protocol Distribution (TCP vs UDP)",
            hole=0.45,
            color_discrete_sequence=["#38BDF8", "#F59E0B", "#10B981"],
            template="plotly_dark"
        )
        fig_proto.update_layout(height=260, margin=dict(l=10, r=10, t=40, b=10))
        st.plotly_chart(fig_proto, use_container_width=True)

    with chart2:
        action_counts = df["action"].value_counts().reset_index()
        action_counts.columns = ["Action", "Count"]
        fig_act = px.pie(
            action_counts,
            names="Action",
            values="Count",
            title="Firewall Disposition (ACCEPT vs REJECT)",
            hole=0.45,
            color_discrete_sequence=["#10B981", "#EF4444"],
            template="plotly_dark"
        )
        fig_act.update_layout(height=260, margin=dict(l=10, r=10, t=40, b=10))
        st.plotly_chart(fig_act, use_container_width=True)

    with chart3:
        top_ports = df["dst_port"].value_counts().head(7).reset_index()
        top_ports.columns = ["Port", "Count"]
        top_ports["Port"] = top_ports["Port"].astype(str)
        fig_ports = px.bar(
            top_ports,
            x="Port",
            y="Count",
            title="Top Targeted Destination Ports",
            color="Count",
            color_continuous_scale="Viridis",
            template="plotly_dark"
        )
        fig_ports.update_layout(height=260, margin=dict(l=10, r=10, t=40, b=10))
        st.plotly_chart(fig_ports, use_container_width=True)

    # Filterable network flow record inspector
    st.markdown("**Interactive Flow Telemetry Explorer:**")
    f_col1, f_col2, f_col3 = st.columns([2, 1, 1])
    with f_col1:
        ip_query = st.text_input("Filter by IP address (Source or Destination)", "")
    with f_col2:
        dir_filter = st.selectbox("Traffic Direction", ["ALL"] + sorted(df["direction"].unique().tolist()))
    with f_col3:
        action_filter = st.selectbox("Firewall Action", ["ALL"] + sorted(df["action"].unique().tolist()))

    filtered_df = df.copy()
    if ip_query.strip():
        q = ip_query.strip()
        filtered_df = filtered_df[(filtered_df["src_ip"].str.contains(q)) | (filtered_df["dst_ip"].str.contains(q))]
    if dir_filter != "ALL":
        filtered_df = filtered_df[filtered_df["direction"] == dir_filter]
    if action_filter != "ALL":
        filtered_df = filtered_df[filtered_df["action"] == action_filter]

    st.write(f"Displaying **{len(filtered_df):,}** of **{len(df):,}** total flow records:")
    st.dataframe(filtered_df.head(200), use_container_width=True)

# -------------------------------------------------------------
# TAB 5: FORENSIC DOSSIER & EVALUATION
# -------------------------------------------------------------
with tab5:
    st.subheader("Formal Forensic Dossier Export & Ground-Truth Benchmarks")
    dossier_col, eval_col = st.columns([1, 1])

    with dossier_col:
        st.markdown("#### Forensic Incident Dossier Export")
        if not incidents:
            st.info("No active incidents available for export.")
        else:
            active_inc = incidents[0]
            dossier_text = generate_forensic_dossier(active_inc, df)

            st.download_button(
                label=f"Export Incident Dossier ({active_inc['incident_id']}.md)",
                data=dossier_text,
                file_name=f"Forensic_Dossier_{active_inc['incident_id']}.md",
                mime="text/markdown",
                use_container_width=True
            )

            with st.expander("Live Forensic Dossier Preview", expanded=True):
                st.markdown(dossier_text)

    with eval_col:
        st.markdown("#### Scientific Evaluation Benchmarks (Ground Truth)")
        st.write("Quantitative classification accuracy measured across canonical & extended benchmark datasets:")

        all_scenario_dfs = {}
        for path in scenario_files:
            fname = os.path.basename(path)
            disp_title = scenario_display_names.get(fname, fname.replace(".csv", "").replace("_", " ").title())
            sdf, _ = load_flows(path)
            all_scenario_dfs[disp_title] = sdf

        eval_table = evaluate_all_scenarios(all_scenario_dfs)
        st.dataframe(eval_table, use_container_width=True)

        st.caption(
            "Evaluation Metrics Definition:<br>"
            "• True Positives (TP): Attack flows correctly flagged by detection heuristics.<br>"
            "• False Positives (FP): Normal benign flows incorrectly flagged as threats.<br>"
            "• False Negatives (FN): Attack flows that evaded detection.<br>"
            "• Precision & Recall: A score of 1.0000 validates deterministic heuristic correctness.",
            unsafe_allow_html=True
        )
