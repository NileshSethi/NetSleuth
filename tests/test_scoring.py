"""Unit tests for NetSleuth Explainable Incident Priority Scoring Engine.
"""

from netsleuth.detectors import Alert, run_all_detectors
from netsleuth.parser import load_and_validate_flow_csv
from netsleuth.correlation import Incident, correlate_alerts_into_incidents
from netsleuth.scoring import (
    calculate_incident_score,
    score_incident,
    score_all_incidents,
)


def _make_alert(alert_id: str, rule_id: str, severity: str = "MEDIUM", total_bytes: int = 0) -> Alert:
    return Alert(
        alert_id=alert_id,
        rule_id=rule_id,
        rule_name=rule_id.replace("RULE-", "").replace("-", " ").title(),
        timestamp="2026-10-18T10:00:00Z",
        src_ip="10.0.1.5",
        dst_ip="10.0.0.10",
        severity=severity,
        evidence={"total_bytes": total_bytes},
        contributing_flow_ids=[f"flw-{alert_id}"],
    )


def test_score_empty_incident():
    """Verify empty incident receives score 0."""
    inc = Incident(
        incident_id="INC-001",
        primary_source_ip="10.0.1.5",
        associated_ips=["10.0.1.5"],
        start_time="2026-10-18T10:00:00Z",
        end_time="2026-10-18T10:00:00Z",
        alerts=[],
    )
    score, breakdown = calculate_incident_score(inc)
    assert score == 0.0
    assert breakdown["severity_label"] == "LOW"


def test_score_single_alert_incident():
    """Verify single alert incident receives an explainable baseline score."""
    a = _make_alert("A1", "RULE-PORT-SCAN", severity="MEDIUM")
    inc = Incident(
        incident_id="INC-001",
        primary_source_ip="10.0.1.5",
        associated_ips=["10.0.1.5", "10.0.0.10"],
        start_time="2026-10-18T10:00:00Z",
        end_time="2026-10-18T10:00:00Z",
        alerts=[a],
        contributing_flow_ids=["flw-A1"],
    )
    score, breakdown = calculate_incident_score(inc)
    assert 10.0 <= score <= 50.0
    assert "rule_severity_and_diversity" in breakdown["factors"]
    assert "target_breadth" in breakdown["factors"]
    assert "volumetric_impact" in breakdown["factors"]
    assert breakdown["factors"]["target_breadth"]["points"] == 10.0  # 1 target


def test_score_blended_multi_stage_incident_receives_high_priority():
    """Verify complex blended multi-stage attack scores high/critical."""
    a1 = _make_alert("A1", "RULE-HOST-SCAN", severity="HIGH")
    a2 = _make_alert("A2", "RULE-PORT-SCAN", severity="HIGH")
    a3 = _make_alert("A3", "RULE-EXFIL-SPIKE", severity="HIGH", total_bytes=80_000_000)

    inc = Incident(
        incident_id="INC-001",
        primary_source_ip="10.0.1.100",
        associated_ips=["10.0.1.100", "10.0.0.1", "10.0.0.2", "10.0.0.15", "203.0.113.99"],
        start_time="2026-10-18T10:00:00Z",
        end_time="2026-10-18T10:25:00Z",
        alerts=[a1, a2, a3],
        contributing_flow_ids=[f"flw-{i}" for i in range(50)],
    )

    score, breakdown = calculate_incident_score(inc)
    assert score >= 75.0
    assert breakdown["severity_label"] in ("HIGH", "CRITICAL")
    assert breakdown["factors"]["rule_severity_and_diversity"]["points"] >= 35.0
    assert breakdown["factors"]["volumetric_impact"]["points"] == 30.0


def test_score_incident_attaches_to_object():
    """Verify score_incident updates the Incident instance attributes directly."""
    a = _make_alert("A1", "RULE-HOST-SCAN")
    inc = Incident(
        incident_id="INC-001",
        primary_source_ip="10.0.1.5",
        associated_ips=["10.0.1.5", "10.0.0.1"],
        start_time="2026-10-18T10:00:00Z",
        end_time="2026-10-18T10:00:00Z",
        alerts=[a],
    )
    res = score_incident(inc)
    assert res.risk_score > 0.0
    assert res.score_breakdown["final_score"] == res.risk_score


def test_score_all_incidents_sorts_descending():
    """Verify score_all_incidents orders incidents highest priority first."""
    # Low severity incident
    inc_low = Incident(
        incident_id="INC-LOW",
        primary_source_ip="10.0.1.1",
        associated_ips=["10.0.1.1", "10.0.0.1"],
        start_time="2026-10-18T10:00:00Z",
        end_time="2026-10-18T10:00:00Z",
        alerts=[_make_alert("A1", "RULE-PORT-SCAN", severity="LOW")],
    )

    # High severity incident (multiple rules, high volume)
    inc_high = Incident(
        incident_id="INC-HIGH",
        primary_source_ip="10.0.1.2",
        associated_ips=["10.0.1.2", "10.0.0.1", "10.0.0.2", "203.0.113.88"],
        start_time="2026-10-18T10:00:00Z",
        end_time="2026-10-18T10:20:00Z",
        alerts=[
            _make_alert("A2", "RULE-HOST-SCAN", severity="HIGH"),
            _make_alert("A3", "RULE-EXFIL-SPIKE", severity="HIGH", total_bytes=60_000_000),
        ],
    )

    scored = score_all_incidents([inc_low, inc_high])
    assert scored[0].incident_id == "INC-HIGH"
    assert scored[1].incident_id == "INC-LOW"
    assert scored[0].risk_score > scored[1].risk_score
