"""Three simple rule-based detectors for network flow logs."""

import pandas as pd
from .config import (
    PORT_SCAN_WINDOW,
    PORT_SCAN_THRESHOLD,
    PORT_SCAN_SEVERITY,
    HOST_SCAN_WINDOW,
    HOST_SCAN_THRESHOLD,
    HOST_SCAN_SEVERITY,
    EXFIL_WINDOW,
    EXFIL_BYTES_THRESHOLD,
    EXFIL_SEVERITY,
)


def detect_port_scans(df: pd.DataFrame) -> list[dict]:
    """Find sources probing >= 10 distinct ports on a single host in 60s."""
    alerts = []
    # Group by source and target host
    for (src_ip, dst_ip), group in df.groupby(["src_ip", "dst_ip"]):
        group = group.sort_values(by="timestamp")
        n = len(group)
        i = 0
        while i < n:
            start_time = group.iloc[i]["timestamp"]
            end_limit = start_time + pd.Timedelta(seconds=PORT_SCAN_WINDOW)
            window = group[(group["timestamp"] >= start_time) & (group["timestamp"] <= end_limit)]
            unique_ports = window["dst_port"].unique()

            # Trigger alert if distinct port count meets threshold
            if len(unique_ports) >= PORT_SCAN_THRESHOLD:
                duration = max(1, int((window.iloc[-1]["timestamp"] - start_time).total_seconds()))
                alerts.append({
                    "rule": "port_scan",
                    "severity": PORT_SCAN_SEVERITY,
                    "src_ip": src_ip,
                    "target": dst_ip,
                    "start_time": start_time,
                    "end_time": window.iloc[-1]["timestamp"],
                    "reason": f"{src_ip} tried {len(unique_ports)} different ports on {dst_ip} in {duration} seconds",
                    "flow_indices": window.index.tolist(),
                    "bytes": int(window["bytes"].sum())
                })
                i += len(window)
            else:
                i += 1
    return alerts


def detect_host_scans(df: pd.DataFrame) -> list[dict]:
    """Find sources probing >= 5 distinct hosts on the same port in 60s."""
    alerts = []
    # Group by source host and destination port
    for (src_ip, dst_port), group in df.groupby(["src_ip", "dst_port"]):
        group = group.sort_values(by="timestamp")
        n = len(group)
        i = 0
        while i < n:
            start_time = group.iloc[i]["timestamp"]
            end_limit = start_time + pd.Timedelta(seconds=HOST_SCAN_WINDOW)
            window = group[(group["timestamp"] >= start_time) & (group["timestamp"] <= end_limit)]
            unique_hosts = window["dst_ip"].unique()

            # Trigger alert if distinct host count meets threshold
            if len(unique_hosts) >= HOST_SCAN_THRESHOLD:
                duration = max(1, int((window.iloc[-1]["timestamp"] - start_time).total_seconds()))
                alerts.append({
                    "rule": "host_scan",
                    "severity": HOST_SCAN_SEVERITY,
                    "src_ip": src_ip,
                    "target": f"{len(unique_hosts)} hosts (port {dst_port})",
                    "start_time": start_time,
                    "end_time": window.iloc[-1]["timestamp"],
                    "reason": f"{src_ip} probed {len(unique_hosts)} different hosts on port {dst_port} in {duration} seconds",
                    "flow_indices": window.index.tolist(),
                    "bytes": int(window["bytes"].sum())
                })
                i += len(window)
            else:
                i += 1
    return alerts


def detect_exfiltration(df: pd.DataFrame) -> list[dict]:
    """Find outbound transfers to an external host totaling >= 500,000 bytes in 120s."""
    alerts = []
    # Filter only outbound flows
    outbound_df = df[df["direction"].str.upper() == "OUTBOUND"]
    for (src_ip, dst_ip), group in outbound_df.groupby(["src_ip", "dst_ip"]):
        group = group.sort_values(by="timestamp")
        n = len(group)
        i = 0
        while i < n:
            start_time = group.iloc[i]["timestamp"]
            end_limit = start_time + pd.Timedelta(seconds=EXFIL_WINDOW)
            window = group[(group["timestamp"] >= start_time) & (group["timestamp"] <= end_limit)]
            total_bytes = int(window["bytes"].sum())

            # Trigger alert if total transferred volume meets threshold
            if total_bytes >= EXFIL_BYTES_THRESHOLD:
                duration = max(1, int((window.iloc[-1]["timestamp"] - start_time).total_seconds()))
                alerts.append({
                    "rule": "exfiltration",
                    "severity": EXFIL_SEVERITY,
                    "src_ip": src_ip,
                    "target": dst_ip,
                    "start_time": start_time,
                    "end_time": window.iloc[-1]["timestamp"],
                    "reason": f"{src_ip} sent {total_bytes:,} outbound bytes to {dst_ip} in {duration} seconds",
                    "flow_indices": window.index.tolist(),
                    "bytes": total_bytes
                })
                i += len(window)
            else:
                i += 1
    return alerts


def run_all_detectors(df: pd.DataFrame) -> list[dict]:
    """Execute all three detectors and return alerts sorted chronologically."""
    all_alerts = []
    all_alerts.extend(detect_port_scans(df))
    all_alerts.extend(detect_host_scans(df))
    all_alerts.extend(detect_exfiltration(df))

    # Sort alerts by start_time
    all_alerts.sort(key=lambda a: a["start_time"])

    # Assign sequential IDs
    for idx, alert in enumerate(all_alerts, start=1):
        alert["alert_id"] = f"ALERT-{idx:03d}"

    return all_alerts
