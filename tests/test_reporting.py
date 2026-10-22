"""Unit tests for NetSleuth Forensic Reporting and Export Module.
"""

from pathlib import Path
from netsleuth.detectors import Alert
from netsleuth.correlation import Incident
from netsleuth.scoring import calculate_incident_score
from netsleuth.reporting import (
    generate_incident_markdown_report,
    generate_batch_executive_summary,
)


def _make_incident() -> Incident:
    alert = Alert(
        alert_id="ALT-001",
        rule_id="RULE-PORT-SCAN",
        rule_name="Vertical Port Scan",
        timestamp="2026-10-18T10:00:00Z",
        src_ip="10.0.1.45",
        dst_ip="10.0.0.15",
        severity="HIGH",
        evidence={"distinct_port_count": 25},
        contributing_flow_ids=["flw-01", "flw-02"],
    )
    inc = Incident(
        incident_id="INC-001",
        primary_source_ip="10.0.1.45",
        associated_ips=["10.0.1.45", "10.0.0.15"],
        start_time="2026-10-18T10:00:00Z",
        end_time="2026-10-18T10:01:00Z",
        duration_sec=60.0,
        alerts=[alert],
        alert_count=1,
        contributing_flow_ids=["flw-01", "flw-02"],
        summary="Vertical reconnaissance scan targeting 10.0.0.15.",
    )
    score, breakdown = calculate_incident_score(inc)
    inc.risk_score = score
    inc.score_breakdown = breakdown
    return inc


def test_generate_incident_markdown_report():
    """Verify Markdown report content includes headers, scores, tables, and actions."""
    inc = _make_incident()
    report = generate_incident_markdown_report(inc)

    assert "# NetSleuth Incident Forensic Report — `INC-001`" in report
    assert "10.0.1.45" in report
    assert "Vertical Port Scan" in report
    assert "Recommended Defensive Follow-Up Actions" in report
    assert "Explainable Threat Score Breakdown" in report


def test_generate_incident_markdown_report_writes_file(tmp_path):
    """Verify writing report to disk."""
    inc = _make_incident()
    out_file = tmp_path / "test_report.md"
    generate_incident_markdown_report(inc, output_path=out_file)

    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "NetSleuth Incident Forensic Report" in content


def test_generate_batch_executive_summary():
    """Verify executive summary generation."""
    inc = _make_incident()
    summary = generate_batch_executive_summary([inc], total_flows=5000)

    assert "Executive Security Threat Summary" in summary
    assert "5,000" in summary
    assert "INC-001" in summary
