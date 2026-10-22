"""Forensic Chronological Timeline Reconstruction Module.

This module merges raw contributing network flows with high-level alert inflection
points to assemble an ordered chronological narrative of an attack incident.
"""

from typing import List, Dict, Any, Optional
import pandas as pd

from netsleuth.correlation import Incident


def _classify_flow_category(flow_row: Dict[str, Any], alert_rules: List[str]) -> str:
    """Assign a human-readable forensic category to a flow event."""
    action = str(flow_row.get("action", "")).upper()
    direction = str(flow_row.get("direction", "")).upper()
    byte_count = int(flow_row.get("bytes", 0))

    if direction == "OUTBOUND" and byte_count > 1_000_000:
        return "EXFILTRATION_BURST"
    if "RULE-PORT-SCAN" in alert_rules and action == "REJECT":
        return "PORT_SCAN_PROBE"
    if "RULE-HOST-SCAN" in alert_rules and flow_row.get("dst_port") == 445:
        return "HOST_DISCOVERY_SWEEP"
    if direction == "INTERNAL" and byte_count > 500_000:
        return "LATERAL_TRANSFER"
    return "NETWORK_FLOW"


def build_incident_timeline(incident: Incident, flow_df: pd.DataFrame) -> pd.DataFrame:
    """Construct a chronologically sequenced DataFrame representing the incident narrative.

    Combines raw contributing flow records and high-level Alert trigger milestones
    into a unified chronological sequence.

    Args:
        incident: Correlated Incident object.
        flow_df: Full verified flow records DataFrame.

    Returns:
        DataFrame structured for timeline rendering, Plotly plotting, and forensic table review.
    """
    timeline_rows: List[Dict[str, Any]] = []
    contributing_ids = set(incident.contributing_flow_ids)
    alert_rules = [a.rule_id for a in incident.alerts]

    # 1. Ingest raw contributing flows
    if flow_df is not None and len(flow_df) > 0 and len(contributing_ids) > 0:
        incident_flows = flow_df[flow_df["event_id"].isin(contributing_ids)].copy()
        flow_records = incident_flows.to_dict("records")

        for f in flow_records:
            category = _classify_flow_category(f, alert_rules)
            src_str = f"{f['src_ip']}:{f['src_port']}"
            dst_str = f"{f['dst_ip']}:{f['dst_port']}"
            desc = (
                f"[{category}] {f['protocol']} flow {src_str} -> {dst_str} "
                f"({int(f['bytes']):,} bytes, {f['action']})"
            )

            timeline_rows.append(
                {
                    "event_id": f["event_id"],
                    "timestamp": pd.to_datetime(f["timestamp"], utc=True),
                    "event_type": "FLOW",
                    "category": category,
                    "source": str(f["src_ip"]),
                    "destination": str(f["dst_ip"]),
                    "port": int(f["dst_port"]),
                    "protocol": str(f["protocol"]),
                    "bytes": int(f["bytes"]),
                    "action": str(f["action"]),
                    "direction": str(f["direction"]),
                    "description": desc,
                    "is_alert": False,
                    "alert_id": None,
                    "incident_id": incident.incident_id,
                }
            )

    # 2. Ingest Alert trigger milestones
    for a in incident.alerts:
        alert_desc = (
            f"🚨 ALERT TRIGGERED: {a.rule_name} [{a.rule_id}] - "
            f"Severity: {a.severity} from {a.src_ip}"
        )
        if a.dst_ip:
            alert_desc += f" -> {a.dst_ip}"

        timeline_rows.append(
            {
                "event_id": a.alert_id,
                "timestamp": pd.to_datetime(a.timestamp, utc=True),
                "event_type": "ALERT_TRIGGER",
                "category": a.rule_id,
                "source": str(a.src_ip),
                "destination": str(a.dst_ip) if a.dst_ip else "Multiple Targets",
                "port": a.evidence.get("destination_ports", [None])[0] if "destination_ports" in a.evidence else None,
                "protocol": "ALERT",
                "bytes": int(a.evidence.get("total_bytes", 0)),
                "action": a.severity,
                "direction": "ALERT",
                "description": alert_desc,
                "is_alert": True,
                "alert_id": a.alert_id,
                "incident_id": incident.incident_id,
            }
        )

    if not timeline_rows:
        cols = [
            "event_id", "timestamp", "event_type", "category", "source",
            "destination", "port", "protocol", "bytes", "action",
            "direction", "description", "is_alert", "alert_id", "incident_id"
        ]
        return pd.DataFrame(columns=cols)

    df_timeline = pd.DataFrame(timeline_rows)
    df_timeline.sort_values(by=["timestamp", "is_alert"], ascending=[True, True], inplace=True)
    df_timeline.reset_index(drop=True, inplace=True)

    return df_timeline


def extract_timeline_events(timeline_df: pd.DataFrame) -> List[Dict[str, Any]]:
    """Convert a timeline DataFrame into a list of event dictionaries for Plotly visualization.

    Args:
        timeline_df: Chronologically sorted timeline DataFrame.

    Returns:
        List of event dictionaries with ISO timestamps and formatting ready for UI plotting.
    """
    if timeline_df is None or len(timeline_df) == 0:
        return []

    events = []
    for _, row in timeline_df.iterrows():
        ts_val = row["timestamp"]
        ts_str = ts_val.strftime("%Y-%m-%dT%H:%M:%SZ") if isinstance(ts_val, pd.Timestamp) else str(ts_val)

        events.append(
            {
                "event_id": str(row["event_id"]),
                "timestamp": ts_str,
                "event_type": str(row["event_type"]),
                "category": str(row["category"]),
                "source": str(row["source"]),
                "destination": str(row["destination"]),
                "port": row["port"],
                "protocol": str(row["protocol"]),
                "bytes": int(row["bytes"]) if pd.notna(row["bytes"]) else 0,
                "action": str(row["action"]),
                "direction": str(row["direction"]),
                "description": str(row["description"]),
                "is_alert": bool(row["is_alert"]),
                "alert_id": str(row["alert_id"]) if pd.notna(row["alert_id"]) else None,
                "incident_id": str(row["incident_id"]),
            }
        )
    return events
