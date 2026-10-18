"""Heuristic Threat Detection Engine for NetSleuth.

This module implements deterministic, explainable sliding-window detection rules:
- Rule 1: Vertical Port Scan Detection (`detect_port_scans`)
- Rule 2: Horizontal Host Scan Detection (`detect_host_scans`)
- Rule 3: Anomalous Outbound Volume Spike Detection (`detect_exfiltration_spikes`)

All heuristics operate strictly on flow telemetry (IPs, ports, timestamps, bytes,
actions, directions) without referencing ground-truth scenario or label fields.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional
import pandas as pd

from netsleuth.config import DetectionConfig


@dataclass
class Alert:
    """Structured representation of a single triggered threat detection alert."""

    alert_id: str
    rule_id: str
    rule_name: str
    timestamp: str  # ISO-8601 UTC string
    src_ip: str
    dst_ip: Optional[str]
    severity: str  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    evidence: Dict[str, Any]
    contributing_flow_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert Alert object to a plain dictionary."""
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "severity": self.severity,
            "evidence": self.evidence,
            "contributing_flow_ids": self.contributing_flow_ids,
        }


def _format_timestamp(ts: Any) -> str:
    """Format timestamp into ISO-8601 UTC string."""
    if isinstance(ts, pd.Timestamp):
        return ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(ts, datetime):
        return ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    return str(ts)


def detect_port_scans(
    df: pd.DataFrame, config: Optional[DetectionConfig] = None
) -> List[Alert]:
    """Detect vertical port scanning (1 source probing multiple ports on 1 target).

    Identifies instances where a single source IP contacts at least
    `config.port_scan_threshold` distinct destination ports on the same destination
    IP within a sliding time window of `config.port_scan_window_sec` seconds.

    Args:
        df: Clean, chronologically sorted flow DataFrame.
        config: Optional DetectionConfig overrides.

    Returns:
        List of Alert objects containing full forensic evidence.
    """
    if df is None or len(df) == 0:
        return []

    cfg = config or DetectionConfig()
    window_sec = cfg.port_scan_window_sec
    threshold = cfg.port_scan_threshold

    alerts: List[Alert] = []
    alert_counter = 1

    # Group by (src_ip, dst_ip)
    grouped = df.groupby(["src_ip", "dst_ip"], observed=True)

    for (src_ip, dst_ip), group in grouped:
        group_records = group.sort_values(by="timestamp").to_dict("records")
        n = len(group_records)
        if n < threshold:
            continue

        left = 0
        while left < n:
            right = left
            start_time = group_records[left]["timestamp"]

            # Advance right pointer within the time window
            while right < n:
                time_delta = (group_records[right]["timestamp"] - start_time).total_seconds()
                if time_delta > window_sec:
                    break
                right += 1

            # Sliced window is [left, right)
            window_slice = group_records[left:right]
            distinct_ports = {rec["dst_port"] for rec in window_slice}

            if len(distinct_ports) >= threshold:
                # Continuous scan trigger found
                end_time = window_slice[-1]["timestamp"]
                window_duration = (end_time - start_time).total_seconds()
                reject_count = sum(1 for r in window_slice if r.get("action") == "REJECT")
                accept_count = sum(1 for r in window_slice if r.get("action") == "ACCEPT")
                flow_ids = [r["event_id"] for r in window_slice]

                severity = "HIGH" if len(distinct_ports) >= threshold * 2 else "MEDIUM"

                alert = Alert(
                    alert_id=f"ALT-PORT-{alert_counter:04d}",
                    rule_id="RULE-PORT-SCAN",
                    rule_name="Vertical Port Scan",
                    timestamp=_format_timestamp(end_time),
                    src_ip=str(src_ip),
                    dst_ip=str(dst_ip),
                    severity=severity,
                    evidence={
                        "distinct_port_count": len(distinct_ports),
                        "threshold": threshold,
                        "ports_contacted": sorted(list(distinct_ports)),
                        "flow_count": len(window_slice),
                        "reject_count": reject_count,
                        "accept_count": accept_count,
                        "window_duration_sec": round(window_duration, 2),
                        "start_time": _format_timestamp(start_time),
                        "end_time": _format_timestamp(end_time),
                    },
                    contributing_flow_ids=flow_ids,
                )
                alerts.append(alert)
                alert_counter += 1
                # Advance left past this triggered scan burst
                left = right
            else:
                left += 1

    alerts.sort(key=lambda a: a.timestamp)
    return alerts


def detect_host_scans(
    df: pd.DataFrame, config: Optional[DetectionConfig] = None
) -> List[Alert]:
    """Detect horizontal host scanning / sweeps (1 source probing multiple target hosts).

    Identifies instances where a single source IP contacts at least
    `config.host_scan_threshold` distinct destination IPs within a sliding time
    window of `config.host_scan_window_sec` seconds.

    Args:
        df: Clean, chronologically sorted flow DataFrame.
        config: Optional DetectionConfig overrides.

    Returns:
        List of Alert objects containing full forensic evidence.
    """
    if df is None or len(df) == 0:
        return []

    cfg = config or DetectionConfig()
    window_sec = cfg.host_scan_window_sec
    threshold = cfg.host_scan_threshold

    alerts: List[Alert] = []
    alert_counter = 1

    # Group by initiating src_ip
    grouped = df.groupby("src_ip", observed=True)

    for src_ip, group in grouped:
        group_records = group.sort_values(by="timestamp").to_dict("records")
        n = len(group_records)
        if n < threshold:
            continue

        left = 0
        while left < n:
            right = left
            start_time = group_records[left]["timestamp"]

            # Advance right pointer within the time window
            while right < n:
                time_delta = (group_records[right]["timestamp"] - start_time).total_seconds()
                if time_delta > window_sec:
                    break
                right += 1

            window_slice = group_records[left:right]
            distinct_hosts = {rec["dst_ip"] for rec in window_slice}

            if len(distinct_hosts) >= threshold:
                end_time = window_slice[-1]["timestamp"]
                window_duration = (end_time - start_time).total_seconds()
                distinct_ports = {rec["dst_port"] for rec in window_slice}
                reject_count = sum(1 for r in window_slice if r.get("action") == "REJECT")
                accept_count = sum(1 for r in window_slice if r.get("action") == "ACCEPT")
                flow_ids = [r["event_id"] for r in window_slice]

                severity = "HIGH" if len(distinct_hosts) >= threshold * 2 else "MEDIUM"

                alert = Alert(
                    alert_id=f"ALT-HOST-{alert_counter:04d}",
                    rule_id="RULE-HOST-SCAN",
                    rule_name="Horizontal Host Scan",
                    timestamp=_format_timestamp(end_time),
                    src_ip=str(src_ip),
                    dst_ip=None,  # Swept multiple hosts
                    severity=severity,
                    evidence={
                        "distinct_host_count": len(distinct_hosts),
                        "threshold": threshold,
                        "hosts_contacted": sorted(list(distinct_hosts))[:50],  # sample top 50
                        "ports_targeted": sorted(list(distinct_ports)),
                        "flow_count": len(window_slice),
                        "reject_count": reject_count,
                        "accept_count": accept_count,
                        "window_duration_sec": round(window_duration, 2),
                        "start_time": _format_timestamp(start_time),
                        "end_time": _format_timestamp(end_time),
                    },
                    contributing_flow_ids=flow_ids,
                )
                alerts.append(alert)
                alert_counter += 1
                left = right
            else:
                left += 1

    alerts.sort(key=lambda a: a.timestamp)
    return alerts


def detect_exfiltration_spikes(
    df: pd.DataFrame, config: Optional[DetectionConfig] = None
) -> List[Alert]:
    """Detect abnormal spikes in outbound byte transfer volume.

    Identifies accepted outbound flows where the cumulative byte volume from a source
    to an external destination IP exceeds `config.exfil_byte_threshold` within
    `config.exfil_window_sec` seconds.

    Args:
        df: Clean, chronologically sorted flow DataFrame.
        config: Optional DetectionConfig overrides.

    Returns:
        List of Alert objects containing full forensic evidence.
    """
    if df is None or len(df) == 0:
        return []

    cfg = config or DetectionConfig()
    window_sec = cfg.exfil_window_sec
    byte_threshold = cfg.exfil_byte_threshold

    alerts: List[Alert] = []
    alert_counter = 1

    # Filter strictly for OUTBOUND ACCEPT flows
    outbound_df = df[(df["direction"] == "OUTBOUND") & (df["action"] == "ACCEPT")]
    if len(outbound_df) == 0:
        return []

    # Group by (src_ip, dst_ip)
    grouped = outbound_df.groupby(["src_ip", "dst_ip"], observed=True)

    for (src_ip, dst_ip), group in grouped:
        group_records = group.sort_values(by="timestamp").to_dict("records")
        n = len(group_records)

        left = 0
        while left < n:
            right = left
            start_time = group_records[left]["timestamp"]

            while right < n:
                time_delta = (group_records[right]["timestamp"] - start_time).total_seconds()
                if time_delta > window_sec:
                    break
                right += 1

            window_slice = group_records[left:right]
            total_bytes = sum(int(rec["bytes"]) for rec in window_slice)

            if total_bytes >= byte_threshold:
                end_time = window_slice[-1]["timestamp"]
                window_duration = (end_time - start_time).total_seconds()
                distinct_ports = {rec["dst_port"] for rec in window_slice}
                flow_ids = [r["event_id"] for r in window_slice]

                severity = "HIGH" if total_bytes >= byte_threshold * 2 else "MEDIUM"

                alert = Alert(
                    alert_id=f"ALT-EXFIL-{alert_counter:04d}",
                    rule_id="RULE-EXFIL-SPIKE",
                    rule_name="Outbound Volume Spike",
                    timestamp=_format_timestamp(end_time),
                    src_ip=str(src_ip),
                    dst_ip=str(dst_ip),
                    severity=severity,
                    evidence={
                        "total_bytes": total_bytes,
                        "total_bytes_mb": round(total_bytes / (1024 * 1024), 2),
                        "byte_threshold": byte_threshold,
                        "byte_threshold_mb": round(byte_threshold / (1024 * 1024), 2),
                        "flow_count": len(window_slice),
                        "destination_ports": sorted(list(distinct_ports)),
                        "window_duration_sec": round(window_duration, 2),
                        "start_time": _format_timestamp(start_time),
                        "end_time": _format_timestamp(end_time),
                    },
                    contributing_flow_ids=flow_ids,
                )
                alerts.append(alert)
                alert_counter += 1
                left = right
            else:
                left += 1

    alerts.sort(key=lambda a: a.timestamp)
    return alerts


def run_all_detectors(
    df: pd.DataFrame, config: Optional[DetectionConfig] = None
) -> List[Alert]:
    """Execute all active detection heuristics and aggregate resulting alerts chronologically.

    Args:
        df: Clean, chronologically sorted flow DataFrame.
        config: Optional DetectionConfig overrides.

    Returns:
        Consolidated list of Alert objects ordered ascending by timestamp.
    """
    if df is None or len(df) == 0:
        return []

    alerts: List[Alert] = []
    alerts.extend(detect_port_scans(df, config))
    alerts.extend(detect_host_scans(df, config))
    alerts.extend(detect_exfiltration_spikes(df, config))

    alerts.sort(key=lambda a: a.timestamp)
    return alerts
