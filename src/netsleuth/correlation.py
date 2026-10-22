"""Multi-Alert Incident Correlation Engine.

This module clusters discrete alerts sharing common entities (e.g., initiating
source IP or targeted subnet) within a temporal proximity window into unified
security Incident objects.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional
import pandas as pd

from netsleuth.detectors import Alert
from netsleuth.config import CorrelationConfig


@dataclass
class Incident:
    """Consolidated security incident composed of multiple correlated alerts."""

    incident_id: str
    primary_source_ip: str
    associated_ips: List[str]
    start_time: str
    end_time: str
    duration_sec: float = 0.0
    alerts: List[Alert] = field(default_factory=list)
    alert_count: int = 0
    risk_score: float = 0.0
    score_breakdown: Dict[str, Any] = field(default_factory=dict)
    summary: str = ""
    contributing_flow_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert Incident object to a plain dictionary for UI and serialization."""
        return {
            "incident_id": self.incident_id,
            "primary_source_ip": self.primary_source_ip,
            "associated_ips": self.associated_ips,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_sec": self.duration_sec,
            "alert_count": self.alert_count,
            "risk_score": self.risk_score,
            "score_breakdown": self.score_breakdown,
            "summary": self.summary,
            "alerts": [a.to_dict() for a in self.alerts],
            "contributing_flow_ids": self.contributing_flow_ids,
        }


def _parse_ts(ts_str: str) -> datetime:
    """Parse ISO-8601 UTC timestamp string to datetime."""
    return pd.to_datetime(ts_str, utc=True).to_pydatetime()


def _generate_incident_summary(incident: Incident) -> str:
    """Synthesize an informative narrative summary for an incident."""
    rule_names = []
    for a in incident.alerts:
        if a.rule_name not in rule_names:
            rule_names.append(a.rule_name)

    phases_str = ", ".join(rule_names)
    target_count = max(0, len(incident.associated_ips) - 1)

    if len(rule_names) > 1:
        narrative = (
            f"Multi-stage intrusion involving {phases_str} "
            f"initiated by {incident.primary_source_ip} targeting {target_count} asset(s) "
            f"over a {round(incident.duration_sec, 1)}s duration."
        )
    else:
        narrative = (
            f"Single-phase threat activity ({phases_str}) "
            f"observed from {incident.primary_source_ip} "
            f"affecting {target_count} target asset(s)."
        )
    return narrative


def correlate_alerts_into_incidents(
    alerts: List[Alert], config: Optional[CorrelationConfig] = None
) -> List[Incident]:
    """Cluster individual alerts into multi-event incidents based on entity and temporal proximity.

    Alerts are correlated if:
    1. They share the same initiating source IP, OR an alert's source/destination IP links
       directly to an existing target asset within the active cluster (pivot/lateral movement).
    2. The time elapsed since the cluster's most recent alert is within `config.correlation_window_sec`.

    Args:
        alerts: List of discrete Alert objects from detection engine.
        config: Optional CorrelationConfig overrides.

    Returns:
        List of correlated Incident objects, ordered chronologically by start_time.
    """
    if not alerts:
        return []

    cfg = config or CorrelationConfig()
    max_gap_sec = cfg.correlation_window_sec

    # Sort input alerts chronologically
    sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)

    clusters: List[Dict[str, Any]] = []

    for alert in sorted_alerts:
        alert_ts = _parse_ts(alert.timestamp)
        matched_cluster = None

        # Check existing open clusters
        for cluster in clusters:
            last_ts = cluster["last_ts"]
            time_delta = (alert_ts - last_ts).total_seconds()

            if time_delta <= max_gap_sec:
                # Entity link check: attacker matches primary, or IP overlaps with cluster entities
                cluster_ips = cluster["associated_ips"]
                has_entity_link = (
                    alert.src_ip in cluster_ips
                    or (alert.dst_ip is not None and alert.dst_ip in cluster_ips)
                    or alert.src_ip == cluster["primary_source_ip"]
                )
                if has_entity_link:
                    matched_cluster = cluster
                    break

        if matched_cluster is not None:
            # Merge alert into existing cluster
            matched_cluster["alerts"].append(alert)
            matched_cluster["last_ts"] = max(matched_cluster["last_ts"], alert_ts)
            matched_cluster["end_time_str"] = alert.timestamp
            matched_cluster["associated_ips"].add(alert.src_ip)
            if alert.dst_ip:
                matched_cluster["associated_ips"].add(alert.dst_ip)
        else:
            # Initialize new cluster
            initial_ips = {alert.src_ip}
            if alert.dst_ip:
                initial_ips.add(alert.dst_ip)

            clusters.append(
                {
                    "primary_source_ip": alert.src_ip,
                    "associated_ips": initial_ips,
                    "first_ts": alert_ts,
                    "last_ts": alert_ts,
                    "start_time_str": alert.timestamp,
                    "end_time_str": alert.timestamp,
                    "alerts": [alert],
                }
            )

    # Convert clusters into Incident objects
    incidents: List[Incident] = []
    for idx, c in enumerate(clusters, start=1):
        incident_id = f"INC-{idx:03d}"
        duration_sec = (c["last_ts"] - c["first_ts"]).total_seconds()

        # Aggregate unique contributing flow IDs
        all_flow_ids = []
        for a in c["alerts"]:
            for fid in a.contributing_flow_ids:
                if fid not in all_flow_ids:
                    all_flow_ids.append(fid)

        associated_list = sorted(list(c["associated_ips"]))

        inc = Incident(
            incident_id=incident_id,
            primary_source_ip=c["primary_source_ip"],
            associated_ips=associated_list,
            start_time=c["start_time_str"],
            end_time=c["end_time_str"],
            duration_sec=duration_sec,
            alerts=c["alerts"],
            alert_count=len(c["alerts"]),
            contributing_flow_ids=all_flow_ids,
        )
        inc.summary = _generate_incident_summary(inc)
        incidents.append(inc)

    return incidents
