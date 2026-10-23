"""Unit tests for NetSleuth: loader, detectors, correlation, scoring, MITRE mapping, and forensic reporting."""

import io
from datetime import datetime, timedelta, timezone
import pandas as pd
from src.netsleuth.loader import load_flows
from src.netsleuth.detectors import (
    detect_port_scans,
    detect_host_scans,
    detect_exfiltration,
    run_all_detectors
)
from src.netsleuth.incidents import (
    build_incidents,
    score_incident,
    generate_forensic_dossier
)


def create_flow_row(timestamp, src_ip, dst_ip, dst_port, byte_count, proto="TCP", action="ACCEPT", direction="INTERNAL"):
    """Helper to construct a valid flow log dictionary."""
    return {
        "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": proto,
        "bytes": byte_count,
        "action": action,
        "direction": direction
    }


def test_port_scan_threshold_boundary():
    """Verify port scan requires exactly 10 distinct ports and ignores 9."""
    base_t = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)

    # 9 ports: below threshold
    df_9 = pd.DataFrame([
        create_flow_row(base_t + timedelta(seconds=i), "10.0.0.5", "10.0.1.10", 1000 + i, 60, direction="INBOUND")
        for i in range(9)
    ])
    df_9["timestamp"] = pd.to_datetime(df_9["timestamp"], utc=True)
    assert len(detect_port_scans(df_9)) == 0

    # 10 ports: at threshold
    df_10 = pd.DataFrame([
        create_flow_row(base_t + timedelta(seconds=i), "10.0.0.5", "10.0.1.10", 1000 + i, 60, direction="INBOUND")
        for i in range(10)
    ])
    df_10["timestamp"] = pd.to_datetime(df_10["timestamp"], utc=True)
    alerts = detect_port_scans(df_10)
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "port_scan"
    assert alerts[0]["severity"] == "MEDIUM"


def test_host_scan_threshold_boundary():
    """Verify host scan requires exactly 5 distinct hosts and ignores 4."""
    base_t = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)

    # 4 hosts: below threshold
    df_4 = pd.DataFrame([
        create_flow_row(base_t + timedelta(seconds=i), "10.0.0.5", f"10.0.1.{10+i}", 445, 60)
        for i in range(4)
    ])
    df_4["timestamp"] = pd.to_datetime(df_4["timestamp"], utc=True)
    assert len(detect_host_scans(df_4)) == 0

    # 5 hosts: at threshold
    df_5 = pd.DataFrame([
        create_flow_row(base_t + timedelta(seconds=i), "10.0.0.5", f"10.0.1.{10+i}", 445, 60)
        for i in range(5)
    ])
    df_5["timestamp"] = pd.to_datetime(df_5["timestamp"], utc=True)
    alerts = detect_host_scans(df_5)
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "host_scan"


def test_exfiltration_threshold_boundary():
    """Verify exfiltration triggers at >= 500,000 outbound bytes and ignores lower values."""
    base_t = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)

    # 499,999 bytes: below threshold
    df_below = pd.DataFrame([
        create_flow_row(base_t, "10.0.0.5", "198.51.100.1", 443, 499999, direction="OUTBOUND")
    ])
    df_below["timestamp"] = pd.to_datetime(df_below["timestamp"], utc=True)
    assert len(detect_exfiltration(df_below)) == 0

    # 500,000 bytes: at threshold
    df_at = pd.DataFrame([
        create_flow_row(base_t, "10.0.0.5", "198.51.100.1", 443, 500000, direction="OUTBOUND")
    ])
    df_at["timestamp"] = pd.to_datetime(df_at["timestamp"], utc=True)
    alerts = detect_exfiltration(df_at)
    assert len(alerts) == 1
    assert alerts[0]["rule"] == "exfiltration"
    assert alerts[0]["severity"] == "HIGH"


def test_benign_scenario_produces_zero_alerts():
    """Verify benign baseline dataset raises zero false alarms."""
    df, _ = load_flows("data/synthetic/scenario5_benign.csv")
    alerts = run_all_detectors(df)
    assert len(alerts) == 0


def test_incident_correlation_time_gap():
    """Verify alerts within 5 min become 1 incident, while 10 min gap creates 2 incidents."""
    t0 = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)
    t_plus_3m = t0 + timedelta(minutes=3)
    t_plus_13m = t0 + timedelta(minutes=13)

    # Within 5 minutes (gap is 3 mins)
    alerts_close = [
        {"src_ip": "10.0.0.5", "rule": "port_scan", "severity": "MEDIUM", "start_time": t0, "end_time": t0 + timedelta(seconds=30), "reason": "scan", "bytes": 0},
        {"src_ip": "10.0.0.5", "rule": "host_scan", "severity": "MEDIUM", "start_time": t_plus_3m, "end_time": t_plus_3m + timedelta(seconds=30), "reason": "scan", "bytes": 0}
    ]
    incidents_close = build_incidents(alerts_close)
    assert len(incidents_close) == 1
    assert incidents_close[0]["alert_count"] == 2

    # 10 minutes gap (> 5 min)
    alerts_far = [
        {"src_ip": "10.0.0.5", "rule": "port_scan", "severity": "MEDIUM", "start_time": t0, "end_time": t0 + timedelta(seconds=30), "reason": "scan", "bytes": 0},
        {"src_ip": "10.0.0.5", "rule": "host_scan", "severity": "MEDIUM", "start_time": t_plus_13m, "end_time": t_plus_13m + timedelta(seconds=30), "reason": "scan", "bytes": 0}
    ]
    incidents_far = build_incidents(alerts_far)
    assert len(incidents_far) == 2


def test_scoring_hand_calculation():
    """Verify hand-calculated score: Base HIGH (50) + 1 extra alert (10) + 600K bytes (10) = 70."""
    alerts = [
        {"severity": "MEDIUM", "rule": "port_scan", "bytes": 0},
        {"severity": "HIGH", "rule": "exfiltration", "bytes": 600_000}
    ]
    score, level, breakdown = score_incident(alerts)
    assert score == 70
    assert level == "High"
    assert any("+50 pts" in b for b in breakdown)
    assert any("+10 pts" in b for b in breakdown)


def test_scoring_never_exceeds_100():
    """Verify score calculation is strictly capped at 100."""
    alerts = [
        {"severity": "HIGH", "rule": "exfiltration", "bytes": 10_000_000}
    ] + [{"severity": "HIGH", "rule": "port_scan", "bytes": 0} for _ in range(10)]
    score, level, _ = score_incident(alerts)
    assert score == 100
    assert level == "Critical"


def test_loader_drops_invalid_rows():
    """Verify loader discards malformed IPs, invalid ports, and negative byte counts."""
    csv_data = """timestamp,src_ip,dst_ip,dst_port,protocol,bytes,action,direction
2026-10-20T10:00:00Z,10.0.0.1,10.0.0.2,80,TCP,100,ACCEPT,INTERNAL
2026-10-20T10:00:01Z,999.999.999.999,10.0.0.2,80,TCP,100,ACCEPT,INTERNAL
2026-10-20T10:00:02Z,10.0.0.1,10.0.0.2,70000,TCP,100,ACCEPT,INTERNAL
2026-10-20T10:00:03Z,10.0.0.1,10.0.0.2,80,TCP,-50,ACCEPT,INTERNAL
"""
    clean_df, dropped_count = load_flows(io.StringIO(csv_data))
    assert len(clean_df) == 1
    assert dropped_count == 3


def test_zero_label_leakage():
    """Verify detectors produce identical alerts whether the 'label' column exists or not."""
    df_with_label, _ = load_flows("data/synthetic/scenario4_multi_stage.csv")
    df_no_label = df_with_label.drop(columns=["label"])

    alerts_with = run_all_detectors(df_with_label)
    alerts_without = run_all_detectors(df_no_label)

    assert len(alerts_with) == len(alerts_without)
    for a1, a2 in zip(alerts_with, alerts_without):
        assert a1["rule"] == a2["rule"]
        assert a1["src_ip"] == a2["src_ip"]
        assert a1["target"] == a2["target"]
        assert a1["start_time"] == a2["start_time"]
        assert a1["flow_indices"] == a2["flow_indices"]


def test_mitre_mapping_and_forensic_dossier():
    """Verify MITRE ATT&CK technique enrichment and forensic dossier generation."""
    df, _ = load_flows("data/synthetic/scenario4_multi_stage.csv")
    alerts = run_all_detectors(df)
    incidents = build_incidents(alerts)

    assert len(incidents) == 1
    inc = incidents[0]
    assert "T1046: Network Service Discovery" in inc["mitre_techniques"]
    assert "Reconnaissance" in inc["kill_chain_stages"]
    assert len(inc["remediations"]) >= 2

    # Verify dossier generation
    dossier = generate_forensic_dossier(inc, df)
    assert inc["incident_id"] in dossier
    assert "Executive Incident Summary" in dossier
    assert "Recommended Containment & Remediation Actions" in dossier
