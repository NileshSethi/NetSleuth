"""Correlates alerts into incidents, computes explainable risk scores, maps MITRE ATT&CK, and generates forensic dossiers."""

from datetime import datetime, timezone
import pandas as pd
from .config import (
    INCIDENT_CORRELATION_WINDOW,
    SEVERITY_BASE_SCORES,
    EXTRA_ALERT_POINTS,
    EXFIL_HIGH_BYTES,
    EXFIL_HIGH_POINTS,
    EXFIL_MED_BYTES,
    EXFIL_MED_POINTS,
    MAX_SCORE,
    MITRE_MAPPINGS,
)


def get_risk_level(score: int) -> str:
    """Return risk category name based on 0-100 score."""
    if score < 30:
        return "Low"
    if score < 60:
        return "Medium"
    if score < 80:
        return "High"
    return "Critical"


def score_incident(alerts: list[dict]) -> tuple[int, str, list[str]]:
    """Calculate 0-100 score, risk level, and transparent point breakdown."""
    highest_sev = "LOW"
    for a in alerts:
        sev = a.get("severity", "LOW")
        if SEVERITY_BASE_SCORES.get(sev, 0) > SEVERITY_BASE_SCORES.get(highest_sev, 0):
            highest_sev = sev
    base_points = SEVERITY_BASE_SCORES.get(highest_sev, 10)
    breakdown = [f"Base severity level ({highest_sev}): +{base_points} pts"]

    extra_count = max(0, len(alerts) - 1)
    extra_points = extra_count * EXTRA_ALERT_POINTS
    if extra_count > 0:
        breakdown.append(f"Additional correlated alert count ({extra_count} alerts): +{extra_points} pts")

    exfil_bytes = sum(a.get("bytes", 0) for a in alerts if a.get("rule") == "exfiltration")
    bytes_points = 0
    if exfil_bytes >= EXFIL_HIGH_BYTES:
        bytes_points = EXFIL_HIGH_POINTS
        breakdown.append(f"High-volume data exfiltration ({exfil_bytes:,} bytes >= 5 MB): +{bytes_points} pts")
    elif exfil_bytes >= EXFIL_MED_BYTES:
        bytes_points = EXFIL_MED_POINTS
        breakdown.append(f"Moderate data exfiltration ({exfil_bytes:,} bytes >= 500 KB): +{bytes_points} pts")

    total_score = min(MAX_SCORE, base_points + extra_points + bytes_points)
    level = get_risk_level(total_score)
    breakdown.append(f"Total calculated priority score: {total_score} / {MAX_SCORE} ({level})")

    return total_score, level, breakdown


def build_timeline(alerts: list[dict]) -> list[dict]:
    """Create chronological timeline entries enriched with MITRE ATT&CK techniques."""
    timeline = []
    sorted_alerts = sorted(alerts, key=lambda a: a["start_time"])
    for alert in sorted_alerts:
        rule = alert["rule"]
        mitre = MITRE_MAPPINGS.get(rule, {})
        stage = mitre.get("kill_chain_phase", "Reconnaissance")

        timeline.append({
            "time": alert["start_time"],
            "alert_id": alert.get("alert_id", ""),
            "rule": rule,
            "stage": stage,
            "severity": alert["severity"],
            "target": alert.get("target", ""),
            "reason": alert["reason"],
            "mitre_id": mitre.get("technique_id", "N/A"),
            "mitre_name": mitre.get("technique_name", "N/A"),
            "flow_indices": alert.get("flow_indices", []),
            "bytes": alert.get("bytes", 0)
        })
    return timeline


def get_recommended_remediations(src_ip: str, rules_triggered: list[str]) -> list[str]:
    """Generate prescriptive cyber response playbooks based on triggered rules."""
    actions = [
        f"**Network Isolation:** Apply an emergency AWS Network ACL rule to DROP all ingress and egress for `{src_ip}`.",
        f"**Security Group Revocation:** Audit and detach inbound security group permissions associated with `{src_ip}`."
    ]
    if "exfiltration" in rules_triggered:
        actions.append("**Egress Control:** Revoke outbound public route table egress and restrict outbound traffic to internal subnets.")
    if "host_scan" in rules_triggered:
        actions.append("**Lateral Spread Mitigation:** Enforce host-based firewall rules blocking internal SMB (port 445) and SSH (port 22).")
    if "port_scan" in rules_triggered:
        actions.append("**Perimeter Hardening:** Perform vulnerability scan on targeted hosts and terminate unauthenticated network listeners.")
    return actions


def build_incidents(alerts: list[dict]) -> list[dict]:
    """Group alerts by source IP and 5-minute time window, score, and enrich with MITRE telemetry."""
    if not alerts:
        return []

    by_src: dict[str, list[dict]] = {}
    for a in alerts:
        by_src.setdefault(a["src_ip"], []).append(a)

    incidents = []
    incident_counter = 1

    for src_ip, src_alerts in by_src.items():
        src_alerts.sort(key=lambda a: a["start_time"])

        current_cluster = [src_alerts[0]]
        for alert in src_alerts[1:]:
            prev_end = current_cluster[-1]["end_time"]
            gap_seconds = (alert["start_time"] - prev_end).total_seconds()

            if gap_seconds <= INCIDENT_CORRELATION_WINDOW:
                current_cluster.append(alert)
            else:
                incidents.append(_assemble_incident(src_ip, current_cluster, incident_counter))
                incident_counter += 1
                current_cluster = [alert]

        if current_cluster:
            incidents.append(_assemble_incident(src_ip, current_cluster, incident_counter))
            incident_counter += 1

    incidents.sort(key=lambda inc: inc["start_time"])
    return incidents


def _assemble_incident(src_ip: str, alerts: list[dict], counter: int) -> dict:
    """Helper to assemble an incident dictionary with metadata, metrics, and remediation."""
    score, level, breakdown = score_incident(alerts)
    timeline = build_timeline(alerts)
    rules_triggered = list({a["rule"] for a in alerts})

    targets = set()
    for a in alerts:
        t = str(a.get("target", ""))
        if t and "hosts" not in t:
            targets.add(t)

    mitre_techniques = []
    kill_chain = []
    for r in rules_triggered:
        m = MITRE_MAPPINGS.get(r, {})
        if m:
            mitre_techniques.append(f"{m['technique_id']}: {m['technique_name']}")
            if m["kill_chain_phase"] not in kill_chain:
                kill_chain.append(m["kill_chain_phase"])

    total_bytes = sum(a.get("bytes", 0) for a in alerts)

    return {
        "incident_id": f"INC-{counter:03d}",
        "src_ip": src_ip,
        "alerts": alerts,
        "alert_count": len(alerts),
        "start_time": alerts[0]["start_time"],
        "end_time": alerts[-1]["end_time"],
        "duration_seconds": max(1, int((alerts[-1]["end_time"] - alerts[0]["start_time"]).total_seconds())),
        "score": score,
        "level": level,
        "breakdown": breakdown,
        "timeline": timeline,
        "targets": sorted(list(targets)),
        "target_count": len(targets),
        "rules_triggered": rules_triggered,
        "mitre_techniques": mitre_techniques,
        "kill_chain_stages": kill_chain,
        "total_bytes": total_bytes,
        "remediations": get_recommended_remediations(src_ip, rules_triggered)
    }


def generate_forensic_dossier(incident: dict, df: pd.DataFrame = None) -> str:
    """Generate a formal markdown forensic investigation report for the incident."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    inc_id = incident["incident_id"]
    src_ip = incident["src_ip"]
    score = incident["score"]
    level = incident["level"]

    report = f"""# Forensic Security Incident Dossier — {inc_id}
**Report Generated:** {now_str}  
**Classification:** Internal Cybersecurity Audit & Incident Response  
**Investigating System:** NetSleuth Threat Analysis Platform  

---

## 1. Executive Incident Summary
- **Incident Identifier:** `{inc_id}`
- **Identified Threat Actor (Source IP):** `{src_ip}`
- **Risk Score Assessment:** **{score} / 100 ({level} Priority)**
- **Total Correlated Alerts:** {incident['alert_count']} alert(s)
- **First Observed Activity:** {incident['start_time']}
- **Last Observed Activity:** {incident['end_time']}
- **Incident Duration:** {incident['duration_seconds']} seconds
- **Total Exfiltrated / Transferred Volume:** {incident['total_bytes']:,} bytes

---

## 2. Threat Actor Profile & Attack Kill Chain
The threat actor originating from `{src_ip}` demonstrated the following MITRE ATT&CK progression:

| MITRE Technique | Technique Name | Tactic | Kill Chain Stage |
| :--- | :--- | :--- | :--- |
"""
    for rule in incident["rules_triggered"]:
        m = MITRE_MAPPINGS.get(rule, {})
        report += f"| `{m.get('technique_id', 'N/A')}` | {m.get('technique_name', 'N/A')} | {m.get('tactic', 'N/A')} | **{m.get('kill_chain_phase', 'N/A')}** |\n"

    report += f"""
---

## 3. Explainable Risk Score Breakdown
The risk score of **{score} / 100** was computed deterministically as follows:
"""
    for item in incident["breakdown"]:
        report += f"- {item}\n"

    report += """
---

## 4. Chronological Forensic Evidence Log
"""
    for ev in incident["timeline"]:
        report += f"### Alert {ev['alert_id']} — {ev['stage']} (`{ev['rule']}`)\n"
        report += f"- **Timestamp:** {ev['time']}\n"
        report += f"- **Severity:** `{ev['severity']}`\n"
        report += f"- **Target:** `{ev['target']}`\n"
        report += f"- **MITRE Reference:** {ev['mitre_id']} ({ev['mitre_name']})\n"
        report += f"- **Forensic Findings:** {ev['reason']}\n"
        report += f"- **Contributing Flows:** {len(ev['flow_indices'])} flow record(s)\n\n"

    report += """---

## 5. Recommended Containment & Remediation Actions
The following defensive containment measures are recommended immediately:
"""
    for action in incident["remediations"]:
        report += f"- {action}\n"

    report += """
---
*End of Incident Dossier — Generated automatically by NetSleuth.*
"""
    return report
