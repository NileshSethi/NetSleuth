"""Unit tests for NetSleuth Heuristic Threat Detection Engine.
"""

from pathlib import Path
import pandas as pd
import pytest

from netsleuth.config import DetectionConfig
from netsleuth.parser import load_and_validate_flow_csv
from netsleuth.detectors import (
    Alert,
    detect_port_scans,
    detect_host_scans,
    detect_exfiltration_spikes,
    run_all_detectors,
)


@pytest.fixture
def benign_df() -> pd.DataFrame:
    """Fixture providing clean parsed baseline traffic."""
    return load_and_validate_flow_csv("data/synthetic/scenario_01_benign.csv")


@pytest.fixture
def port_scan_df() -> pd.DataFrame:
    """Fixture providing clean parsed port scan traffic."""
    return load_and_validate_flow_csv("data/synthetic/scenario_02_port_scan.csv")


@pytest.fixture
def host_scan_df() -> pd.DataFrame:
    """Fixture providing clean parsed host sweep traffic."""
    return load_and_validate_flow_csv("data/synthetic/scenario_03_host_scan.csv")


@pytest.fixture
def exfil_df() -> pd.DataFrame:
    """Fixture providing clean parsed outbound exfiltration traffic."""
    return load_and_validate_flow_csv("data/synthetic/scenario_04_exfiltration.csv")


@pytest.fixture
def blended_df() -> pd.DataFrame:
    """Fixture providing clean parsed multi-stage blended attack traffic."""
    return load_and_validate_flow_csv("data/synthetic/scenario_05_blended_attack.csv")


# ------------------------------------------------------------------------------
# Alert Data Structure Tests
# ------------------------------------------------------------------------------

def test_alert_to_dict():
    """Verify Alert to_dict method serialization."""
    alert = Alert(
        alert_id="ALT-PORT-0001",
        rule_id="RULE-PORT-SCAN",
        rule_name="Vertical Port Scan",
        timestamp="2026-10-18T10:15:30Z",
        src_ip="10.0.1.45",
        dst_ip="10.0.0.15",
        severity="HIGH",
        evidence={"distinct_port_count": 25},
        contributing_flow_ids=["flw-01", "flw-02"],
    )
    d = alert.to_dict()
    assert d["alert_id"] == "ALT-PORT-0001"
    assert d["rule_id"] == "RULE-PORT-SCAN"
    assert d["severity"] == "HIGH"
    assert d["evidence"]["distinct_port_count"] == 25
    assert len(d["contributing_flow_ids"]) == 2


# ------------------------------------------------------------------------------
# Empty Input Tests
# ------------------------------------------------------------------------------

def test_detectors_on_empty_dataframe():
    """Verify all detectors return empty list when given an empty DataFrame."""
    empty_df = pd.DataFrame()
    assert detect_port_scans(empty_df) == []
    assert detect_host_scans(empty_df) == []
    assert detect_exfiltration_spikes(empty_df) == []
    assert run_all_detectors(empty_df) == []


# ------------------------------------------------------------------------------
# Rule 1: Vertical Port Scan Tests
# ------------------------------------------------------------------------------

def test_detect_port_scans_on_synthetic_scenario(port_scan_df):
    """Verify Rule 1 detects vertical port scan in scenario 2."""
    alerts = detect_port_scans(port_scan_df)
    assert len(alerts) >= 1

    alert = alerts[0]
    assert alert.rule_id == "RULE-PORT-SCAN"
    assert alert.src_ip == "10.0.1.45"
    assert alert.dst_ip == "10.0.0.15"
    assert alert.evidence["distinct_port_count"] >= 15
    assert len(alert.evidence["ports_contacted"]) >= 15
    assert len(alert.contributing_flow_ids) >= 15
    assert alert.evidence["reject_count"] > 0


def test_port_scan_timing_window_boundary():
    """Verify probes spaced widely apart (exceeding window) do not trigger."""
    # 20 distinct ports probed, but each probe is 120 seconds apart (window is 60s)
    rows = []
    base_ts = pd.Timestamp("2026-10-18 10:00:00", tz="UTC")
    for i in range(20):
        rows.append({
            "event_id": f"flw-{i:03d}",
            "timestamp": base_ts + pd.Timedelta(seconds=i * 120),
            "src_ip": "10.0.1.99",
            "dst_ip": "10.0.0.10",
            "src_port": 50000 + i,
            "dst_port": 1000 + i,
            "protocol": "TCP",
            "bytes": 64,
            "action": "REJECT",
            "direction": "INTERNAL",
        })
    df = pd.DataFrame(rows)
    config = DetectionConfig(port_scan_window_sec=60, port_scan_threshold=10)
    alerts = detect_port_scans(df, config=config)
    assert len(alerts) == 0


# ------------------------------------------------------------------------------
# Rule 2: Horizontal Host Scan Tests
# ------------------------------------------------------------------------------

def test_detect_host_scans_on_synthetic_scenario(host_scan_df):
    """Verify Rule 2 detects horizontal host scan in scenario 3."""
    alerts = detect_host_scans(host_scan_df)
    assert len(alerts) >= 1

    alert = alerts[0]
    assert alert.rule_id == "RULE-HOST-SCAN"
    assert alert.src_ip == "10.0.1.77"
    assert alert.evidence["distinct_host_count"] >= 10
    assert 445 in alert.evidence["ports_targeted"]
    assert len(alert.contributing_flow_ids) >= 10


def test_host_scan_below_threshold_no_alert():
    """Verify probing distinct hosts below threshold does not trigger."""
    rows = []
    base_ts = pd.Timestamp("2026-10-18 10:00:00", tz="UTC")
    # Only 3 hosts probed (threshold default is 10)
    for i in range(3):
        rows.append({
            "event_id": f"flw-{i:03d}",
            "timestamp": base_ts + pd.Timedelta(seconds=i * 5),
            "src_ip": "10.0.1.50",
            "dst_ip": f"10.0.2.{i+1}",
            "src_port": 50000 + i,
            "dst_port": 445,
            "protocol": "TCP",
            "bytes": 64,
            "action": "REJECT",
            "direction": "INTERNAL",
        })
    df = pd.DataFrame(rows)
    alerts = detect_host_scans(df)
    assert len(alerts) == 0


# ------------------------------------------------------------------------------
# Rule 3: Anomalous Outbound Volume Spike Tests
# ------------------------------------------------------------------------------

def test_detect_exfiltration_spikes_on_synthetic_scenario(exfil_df):
    """Verify Rule 3 detects outbound byte volume spike in scenario 4."""
    alerts = detect_exfiltration_spikes(exfil_df)
    assert len(alerts) >= 1

    alert = alerts[0]
    assert alert.rule_id == "RULE-EXFIL-SPIKE"
    assert alert.src_ip == "10.0.0.25"
    assert alert.dst_ip == "203.0.113.88"
    assert alert.evidence["total_bytes"] >= 52_428_800  # >= 50 MB
    assert alert.evidence["total_bytes_mb"] >= 50.0
    assert 443 in alert.evidence["destination_ports"]


def test_exfiltration_ignores_inbound_large_volume():
    """Verify high-volume INBOUND transfer is NOT flagged as outbound exfiltration."""
    rows = [{
        "event_id": "flw-inbound-large",
        "timestamp": pd.Timestamp("2026-10-18 10:00:00", tz="UTC"),
        "src_ip": "203.0.113.50",
        "dst_ip": "10.0.0.15",
        "src_port": 443,
        "dst_port": 54321,
        "protocol": "TCP",
        "bytes": 200_000_000,  # 200 MB inbound download
        "action": "ACCEPT",
        "direction": "INBOUND",
    }]
    df = pd.DataFrame(rows)
    alerts = detect_exfiltration_spikes(df)
    assert len(alerts) == 0


def test_exfiltration_ignores_rejected_flows():
    """Verify high-volume blocked/rejected flows are NOT flagged as successful exfiltration."""
    rows = [{
        "event_id": "flw-rejected-large",
        "timestamp": pd.Timestamp("2026-10-18 10:00:00", tz="UTC"),
        "src_ip": "10.0.0.15",
        "dst_ip": "203.0.113.50",
        "src_port": 54321,
        "dst_port": 443,
        "protocol": "TCP",
        "bytes": 200_000_000,
        "action": "REJECT",  # Blocked by firewall
        "direction": "OUTBOUND",
    }]
    df = pd.DataFrame(rows)
    alerts = detect_exfiltration_spikes(df)
    assert len(alerts) == 0


# ------------------------------------------------------------------------------
# Baseline & Blended Multi-Detector Integration Tests
# ------------------------------------------------------------------------------

def test_benign_scenario_produces_zero_alerts(benign_df):
    """Verify normal benign enterprise traffic triggers 0 false positives."""
    alerts = run_all_detectors(benign_df)
    assert len(alerts) == 0, f"Expected 0 alerts on benign baseline, got {len(alerts)}"


def test_blended_scenario_triggers_all_rules(blended_df):
    """Verify blended attack scenario triggers all 3 distinct detection rules."""
    alerts = run_all_detectors(blended_df)
    assert len(alerts) >= 3

    rule_ids_found = {a.rule_id for a in alerts}
    assert "RULE-PORT-SCAN" in rule_ids_found
    assert "RULE-HOST-SCAN" in rule_ids_found
    assert "RULE-EXFIL-SPIKE" in rule_ids_found

    # Verify alerts are sorted ascending by timestamp
    timestamps = [a.timestamp for a in alerts]
    assert timestamps == sorted(timestamps)
