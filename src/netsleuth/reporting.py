"""Forensic Reporting and Export Module.

Generates structured Markdown and plain-text summary reports for security incidents,
timelines, and evaluation outcomes suitable for analyst review and academic presentation.
"""

from typing import Optional, List
from pathlib import Path

from netsleuth.correlation import Incident


def generate_incident_markdown_report(
    incident: Incident, output_path: Optional[Path] = None
) -> str:
    """Generate a clean, structured Markdown report detailing a security incident.

    Args:
        incident: Correlated Incident object.
        output_path: Optional file path to save report.

    Returns:
        Rendered Markdown text string.
    """
    score = incident.risk_score
    breakdown = incident.score_breakdown or {}
    factors = breakdown.get("factors", {})

    # Generate Alerts Table rows
    alert_rows = []
    for a in incident.alerts:
        evidence_summary = ""
        if a.rule_id == "RULE-PORT-SCAN":
            evidence_summary = f"{a.evidence.get('distinct_port_count', 0)} ports probed"
        elif a.rule_id == "RULE-HOST-SCAN":
            evidence_summary = f"{a.evidence.get('distinct_host_count', 0)} hosts swept"
        elif a.rule_id == "RULE-EXFIL-SPIKE":
            evidence_summary = f"{a.evidence.get('total_bytes_mb', 0)} MB exfiltrated"

        alert_rows.append(
            f"| `{a.alert_id}` | **{a.rule_name}** | `{a.timestamp}` | `{a.severity}` | {evidence_summary} |"
        )
    alert_table_str = "\n".join(alert_rows) if alert_rows else "| None | - | - | - | - |"

    # Factor points breakdown
    f1 = factors.get("rule_severity_and_diversity", {})
    f2 = factors.get("target_breadth", {})
    f3 = factors.get("volumetric_impact", {})

    report = f"""# NetSleuth Incident Forensic Report — `{incident.incident_id}`

> **Generated:** By NetSleuth Threat Analysis System  
> **Status:** Analyzed & Correlated  
> **Primary Threat Actor / Source:** `{incident.primary_source_ip}`  
> **Investigation Window:** `{incident.start_time}` to `{incident.end_time}` ({round(incident.duration_sec, 1)} seconds)

---

## 1. Executive Summary & Assessment

**Priority Risk Score:** **`{score}/100`** — **{breakdown.get('severity_label', 'MEDIUM')}**

{incident.summary}

---

## 2. Explainable Threat Score Breakdown

NetSleuth calculates risk priority using a linear, auditable scoring formula ($0–100$):

| Scoring Factor | Points Awarded | Max Factor Points | Audit Details |
| :--- | :---: | :---: | :--- |
| **Rule Severity & Diversity** | **{f1.get('points', 0)}** | 40 | {f1.get('explanation', 'N/A')} |
| **Target Breadth (Blast Radius)** | **{f2.get('points', 0)}** | 30 | {f2.get('explanation', 'N/A')} |
| **Volumetric & Flow Impact** | **{f3.get('points', 0)}** | 30 | {f3.get('explanation', 'N/A')} |
| **Total Priority Score** | **`{score}/100`** | **100** | *{breakdown.get('formula', 'Formula')}* |

---

## 3. Triggered Threat Alerts ({incident.alert_count})

| Alert ID | Detection Rule | Timestamp (UTC) | Severity | Key Evidence |
| :--- | :--- | :--- | :---: | :--- |
{alert_table_str}

---

## 4. Blast Radius & Involved Network Assets ({len(incident.associated_ips)})

- **Initiating Source Host:** `{incident.primary_source_ip}`
- **Target / Associated Assets:**
{chr(10).join(f'  - `{ip}`' for ip in incident.associated_ips if ip != incident.primary_source_ip)}
- **Total Forensic Flow Records:** `{len(incident.contributing_flow_ids)}` flow(s) cataloged.

---

## 5. Recommended Defensive Follow-Up Actions

1. **Immediate Host Containment:** Isolate source host `{incident.primary_source_ip}` at the network or security-group level to halt lateral movement.
2. **Endpoint Forensics (EDR):** Review process execution logs, command history, and network sockets active on `{incident.primary_source_ip}` during the incident window.
3. **Internal Micro-segmentation:** Restrict lateral ports (e.g., TCP 445 SMB, TCP 3389 RDP, TCP 22 SSH) across internal subnets.
4. **Threat Intelligence Correlation:** Verify destination external IP addresses with threat reputation feeds.

---
*Report automatically compiled by NetSleuth — Forensic Network Threat Analysis System.*
"""

    if output_path:
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(report, encoding="utf-8")

    return report


def generate_batch_executive_summary(
    incidents: List[Incident], total_flows: int
) -> str:
    """Generate a high-level executive summary across all correlated incidents."""
    total_inc = len(incidents)
    total_alerts = sum(inc.alert_count for inc in incidents)
    max_score = max((inc.risk_score for inc in incidents), default=0.0)

    summary = f"""# Executive Security Threat Summary

- **Total Network Flows Analyzed:** {total_flows:,}
- **Correlated Incidents Detected:** {total_inc}
- **Total Threat Alerts Flagged:** {total_alerts}
- **Peak Incident Priority Score:** {max_score}/100

### Top Incidents by Priority:
"""
    for inc in sorted(incidents, key=lambda x: x.risk_score, reverse=True)[:5]:
        summary += (
            f"- **`{inc.incident_id}`** (Score: {inc.risk_score}/100) — "
            f"Source: `{inc.primary_source_ip}` | Alerts: {inc.alert_count} | Targets: {len(inc.associated_ips)-1}\n"
        )
    return summary
