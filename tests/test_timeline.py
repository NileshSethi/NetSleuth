"""Unit tests for NetSleuth Forensic Chronological Timeline Reconstruction Module.
"""

import pandas as pd
from netsleuth.parser import load_and_validate_flow_csv
from netsleuth.detectors import run_all_detectors, Alert
from netsleuth.correlation import correlate_alerts_into_incidents, Incident
from netsleuth.timeline import (
    build_incident_timeline,
    extract_timeline_events,
)


def test_build_timeline_empty_incident():
    """Verify empty incident produces an empty timeline DataFrame with correct schema."""
    inc = Incident(
        incident_id="INC-001",
        primary_source_ip="10.0.1.1",
        associated_ips=["10.0.1.1"],
        start_time="2026-10-18T10:00:00Z",
        end_time="2026-10-18T10:00:00Z",
    )
    df_empty = pd.DataFrame()
    timeline = build_incident_timeline(inc, df_empty)
    assert isinstance(timeline, pd.DataFrame)
    assert len(timeline) == 0
    assert "timestamp" in timeline.columns
    assert "description" in timeline.columns


def test_build_timeline_orders_chronologically():
    """Verify contributing flows and alert markers are strictly sorted ascending by timestamp."""
    alert = Alert(
        alert_id="ALT-001",
        rule_id="RULE-PORT-SCAN",
        rule_name="Vertical Port Scan",
        timestamp="2026-10-18T10:00:10Z",
        src_ip="10.0.1.5",
        dst_ip="10.0.0.10",
        severity="MEDIUM",
        evidence={"destination_ports": [80, 443]},
        contributing_flow_ids=["flw-01", "flw-02"],
    )

    inc = Incident(
        incident_id="INC-001",
        primary_source_ip="10.0.1.5",
        associated_ips=["10.0.1.5", "10.0.0.10"],
        start_time="2026-10-18T10:00:00Z",
        end_time="2026-10-18T10:00:10Z",
        alerts=[alert],
        contributing_flow_ids=["flw-01", "flw-02"],
    )

    raw_flows = pd.DataFrame([
        {
            "event_id": "flw-02",
            "timestamp": pd.Timestamp("2026-10-18 10:00:05", tz="UTC"),
            "src_ip": "10.0.1.5",
            "dst_ip": "10.0.0.10",
            "src_port": 50001,
            "dst_port": 443,
            "protocol": "TCP",
            "bytes": 64,
            "action": "ACCEPT",
            "direction": "INTERNAL",
        },
        {
            "event_id": "flw-01",
            "timestamp": pd.Timestamp("2026-10-18 10:00:01", tz="UTC"),
            "src_ip": "10.0.1.5",
            "dst_ip": "10.0.0.10",
            "src_port": 50000,
            "dst_port": 80,
            "protocol": "TCP",
            "bytes": 64,
            "action": "REJECT",
            "direction": "INTERNAL",
        },
    ])

    timeline = build_incident_timeline(inc, raw_flows)
    assert len(timeline) == 3  # 2 flows + 1 alert milestone

    # Check strict ascending chronological order
    timestamps = list(timeline["timestamp"])
    assert timestamps == sorted(timestamps)

    # First event is flw-01 at 10:00:01
    assert timeline.iloc[0]["event_id"] == "flw-01"
    assert timeline.iloc[0]["event_type"] == "FLOW"

    # Second event is flw-02 at 10:00:05
    assert timeline.iloc[1]["event_id"] == "flw-02"

    # Third event is ALT-001 at 10:00:10
    assert timeline.iloc[2]["event_id"] == "ALT-001"
    assert bool(timeline.iloc[2]["is_alert"]) is True


def test_extract_timeline_events():
    """Verify extraction of JSON-compatible event dictionaries for Plotly."""
    alert = Alert(
        alert_id="ALT-001",
        rule_id="RULE-PORT-SCAN",
        rule_name="Vertical Port Scan",
        timestamp="2026-10-18T10:00:02Z",
        src_ip="10.0.1.5",
        dst_ip="10.0.0.10",
        severity="MEDIUM",
        evidence={},
        contributing_flow_ids=["flw-01"],
    )
    inc = Incident(
        incident_id="INC-001",
        primary_source_ip="10.0.1.5",
        associated_ips=["10.0.1.5", "10.0.0.10"],
        start_time="2026-10-18T10:00:00Z",
        end_time="2026-10-18T10:00:02Z",
        alerts=[alert],
        contributing_flow_ids=["flw-01"],
    )
    raw_flows = pd.DataFrame([
        {
            "event_id": "flw-01",
            "timestamp": pd.Timestamp("2026-10-18 10:00:00", tz="UTC"),
            "src_ip": "10.0.1.5",
            "dst_ip": "10.0.0.10",
            "src_port": 50000,
            "dst_port": 80,
            "protocol": "TCP",
            "bytes": 100,
            "action": "ACCEPT",
            "direction": "INTERNAL",
        }
    ])

    timeline_df = build_incident_timeline(inc, raw_flows)
    events = extract_timeline_events(timeline_df)

    assert len(events) == 2
    assert isinstance(events[0]["timestamp"], str)
    assert events[0]["event_type"] == "FLOW"
    assert events[1]["event_type"] == "ALERT_TRIGGER"
    assert events[1]["is_alert"] is True


def test_end_to_end_timeline_on_blended_scenario():
    """Verify full pipeline: parse -> detect -> correlate -> timeline on scenario 5."""
    df = load_and_validate_flow_csv("data/synthetic/scenario_05_blended_attack.csv")
    alerts = run_all_detectors(df)
    incidents = correlate_alerts_into_incidents(alerts)

    assert len(incidents) > 0
    main_incident = incidents[0]

    timeline_df = build_incident_timeline(main_incident, df)
    assert len(timeline_df) > 0

    # Ensure strictly sorted ascending
    assert timeline_df["timestamp"].is_monotonic_increasing is True

    # Ensure both raw flows and alert milestones exist
    event_types = set(timeline_df["event_type"])
    assert "FLOW" in event_types
    assert "ALERT_TRIGGER" in event_types
