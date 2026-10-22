"""Unit tests for NetSleuth Incident Correlation Engine.
"""

import pytest
from netsleuth.detectors import Alert, run_all_detectors
from netsleuth.parser import load_and_validate_flow_csv
from netsleuth.config import CorrelationConfig
from netsleuth.correlation import (
    Incident,
    correlate_alerts_into_incidents,
)


def _make_dummy_alert(alert_id: str, rule_id: str, ts: str, src: str, dst: str, flow_ids=None) -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id=rule_id,
        rule_name=rule_id.replace("RULE-", "").replace("-", " ").title(),
        timestamp=ts,
        src_ip=src,
        dst_ip=dst,
        severity="MEDIUM",
        evidence={"test": True},
        contributing_flow_ids=flow_ids or [f"flw-{alert_id}"],
    )


def test_correlate_empty_alerts():
    """Verify empty alert list produces zero incidents."""
    incidents = correlate_alerts_into_incidents([])
    assert incidents == []


def test_correlate_single_alert():
    """Verify single alert produces a single incident."""
    a = _make_dummy_alert("A1", "RULE-PORT-SCAN", "2026-10-18T10:00:00Z", "10.0.1.5", "10.0.0.10")
    incidents = correlate_alerts_into_incidents([a])
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.incident_id == "INC-001"
    assert inc.primary_source_ip == "10.0.1.5"
    assert "10.0.0.10" in inc.associated_ips
    assert inc.alert_count == 1
    assert inc.start_time == "2026-10-18T10:00:00Z"
    assert inc.end_time == "2026-10-18T10:00:00Z"
    assert inc.duration_sec == 0.0


def test_correlate_temporal_clustering_same_source():
    """Verify alerts from same source within correlation window merge into one incident."""
    a1 = _make_dummy_alert("A1", "RULE-HOST-SCAN", "2026-10-18T10:00:00Z", "10.0.1.100", "10.0.0.5")
    a2 = _make_dummy_alert("A2", "RULE-PORT-SCAN", "2026-10-18T10:05:00Z", "10.0.1.100", "10.0.0.15")

    # 5 minutes gap (300s) is within default 600s window
    incidents = correlate_alerts_into_incidents([a1, a2])
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.alert_count == 2
    assert inc.start_time == "2026-10-18T10:00:00Z"
    assert inc.end_time == "2026-10-18T10:05:00Z"
    assert inc.duration_sec == 300.0
    assert set(inc.associated_ips) == {"10.0.1.100", "10.0.0.5", "10.0.0.15"}


def test_correlate_window_separation_creates_multiple_incidents():
    """Verify alerts from same source separated by more than correlation window form separate incidents."""
    a1 = _make_dummy_alert("A1", "RULE-PORT-SCAN", "2026-10-18T10:00:00Z", "10.0.1.50", "10.0.0.10")
    # 2 hours later (7200s gap, exceeding 600s window)
    a2 = _make_dummy_alert("A2", "RULE-PORT-SCAN", "2026-10-18T12:00:00Z", "10.0.1.50", "10.0.0.20")

    cfg = CorrelationConfig(correlation_window_sec=600)
    incidents = correlate_alerts_into_incidents([a1, a2], config=cfg)
    assert len(incidents) == 2
    assert incidents[0].incident_id == "INC-001"
    assert incidents[1].incident_id == "INC-002"


def test_correlate_pivot_entity_chaining():
    """Verify lateral movement pivot (Attacker A -> Server B -> Exfil C) correlates together."""
    # A attacks B at 10:00
    a1 = _make_dummy_alert("A1", "RULE-PORT-SCAN", "2026-10-18T10:00:00Z", "10.0.1.100", "10.0.0.15")
    # B then exfiltrates to C at 10:08 (within 10m window)
    a2 = _make_dummy_alert("A2", "RULE-EXFIL-SPIKE", "2026-10-18T10:08:00Z", "10.0.0.15", "203.0.113.99")

    incidents = correlate_alerts_into_incidents([a1, a2])
    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.alert_count == 2
    assert "203.0.113.99" in inc.associated_ips
    assert "10.0.0.15" in inc.associated_ips
    assert "10.0.1.100" in inc.associated_ips


def test_correlate_blended_synthetic_scenario():
    """Verify end-to-end correlation on scenario 5 blended attack."""
    df = load_and_validate_flow_csv("data/synthetic/scenario_05_blended_attack.csv")
    alerts = run_all_detectors(df)
    assert len(alerts) >= 3

    incidents = correlate_alerts_into_incidents(alerts)
    # The blended scenario events all occur within 25 minutes with overlapping entity links
    assert len(incidents) >= 1
    main_inc = incidents[0]
    assert main_inc.alert_count >= 2
    assert main_inc.summary != ""
    assert len(main_inc.contributing_flow_ids) > 0

    d = main_inc.to_dict()
    assert d["incident_id"] == main_inc.incident_id
    assert d["alert_count"] == main_inc.alert_count
