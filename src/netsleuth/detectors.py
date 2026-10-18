"""Heuristic Threat Detection Engine for NetSleuth.

This module implements deterministic, explainable sliding-window detection rules:
- Rule 1: Vertical Port Scan Detection (`detect_port_scans`)
- Rule 2: Horizontal Host Scan Detection (`detect_host_scans`)
- Rule 3: Anomalous Outbound Volume Spike Detection (`detect_exfiltration_spikes`)
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import pandas as pd

from netsleuth.config import DetectionConfig


@dataclass
class Alert:
    """Structured representation of a single triggered threat detection alert."""

    alert_id: str
    rule_id: str
    rule_name: str
    timestamp: str
    src_ip: str
    dst_ip: Optional[str]
    severity: str
    evidence: Dict[str, Any]
    contributing_flow_ids: List[str] = field(default_factory=list)


def detect_port_scans(
    df: pd.DataFrame, config: Optional[DetectionConfig] = None
) -> List[Alert]:
    """Detect vertical port scanning (1 source probing multiple ports on 1 target).

    TODO (Phase 3 Implementation):
    1. Group records by (src_ip, dst_ip).
    2. Slide a window of `config.port_scan_window_sec` seconds.
    3. Count distinct `dst_port` values.
    4. If distinct_ports >= `config.port_scan_threshold`, generate an Alert.

    Args:
        df: Clean, chronologically sorted flow DataFrame.
        config: Optional DetectionConfig overrides.

    Returns:
        List of Alert objects containing full evidence.

    Raises:
        NotImplementedError: Raised in Phase 1 placeholder state.
    """
    raise NotImplementedError(
        "detect_port_scans() is a Phase 1 interface placeholder. "
        "Detection algorithms will be implemented in Phase 3."
    )


def detect_host_scans(
    df: pd.DataFrame, config: Optional[DetectionConfig] = None
) -> List[Alert]:
    """Detect horizontal host scanning / sweeps (1 source probing multiple target hosts).

    TODO (Phase 3 Implementation):
    1. Group records by src_ip.
    2. Slide a window of `config.host_scan_window_sec` seconds.
    3. Count distinct `dst_ip` values.
    4. If distinct_hosts >= `config.host_scan_threshold`, generate an Alert.

    Args:
        df: Clean, chronologically sorted flow DataFrame.
        config: Optional DetectionConfig overrides.

    Returns:
        List of Alert objects containing full evidence.

    Raises:
        NotImplementedError: Raised in Phase 1 placeholder state.
    """
    raise NotImplementedError(
        "detect_host_scans() is a Phase 1 interface placeholder. "
        "Detection algorithms will be implemented in Phase 3."
    )


def detect_exfiltration_spikes(
    df: pd.DataFrame, config: Optional[DetectionConfig] = None
) -> List[Alert]:
    """Detect abnormal spikes in outbound byte transfer volume.

    TODO (Phase 3 Implementation):
    1. Filter records where direction == 'OUTBOUND' and action == 'ACCEPT'.
    2. Slide a window of `config.exfil_window_sec` seconds by (src_ip, dst_ip).
    3. Sum bytes; if total_bytes >= `config.exfil_byte_threshold`, generate an Alert.

    Args:
        df: Clean, chronologically sorted flow DataFrame.
        config: Optional DetectionConfig overrides.

    Returns:
        List of Alert objects containing full evidence.

    Raises:
        NotImplementedError: Raised in Phase 1 placeholder state.
    """
    raise NotImplementedError(
        "detect_exfiltration_spikes() is a Phase 1 interface placeholder. "
        "Detection algorithms will be implemented in Phase 3."
    )


def run_all_detectors(
    df: pd.DataFrame, config: Optional[DetectionConfig] = None
) -> List[Alert]:
    """Execute all active detection heuristics and aggregate resulting alerts."""
    raise NotImplementedError(
        "run_all_detectors() is a Phase 1 interface placeholder."
    )
