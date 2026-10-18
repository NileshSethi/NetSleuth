"""Central configuration module for NetSleuth.

This module provides structured, configurable detection thresholds, time windows,
scoring weights, and system defaults. All detection heuristics reference these
parameters rather than relying on unexplained hardcoded constants.
"""

from dataclasses import dataclass, field
from typing import Dict, Any


@dataclass(frozen=True)
class DetectionConfig:
    """Configurable thresholds and sliding time windows for threat detectors."""

    # Rule 1: Vertical Port Scan
    port_scan_window_sec: int = 60
    port_scan_threshold: int = 15

    # Rule 2: Horizontal Host Scan
    host_scan_window_sec: int = 120
    host_scan_threshold: int = 10

    # Rule 3: Outbound Data Volume Spike
    exfil_window_sec: int = 300
    exfil_byte_threshold: int = 52_428_800  # 50 Megabytes


@dataclass(frozen=True)
class CorrelationConfig:
    """Parameters controlling how individual alerts are clustered into incidents."""

    # Maximum time difference between alerts to be correlated into the same incident
    correlation_window_sec: int = 600  # 10 minutes


@dataclass(frozen=True)
class ScoringConfig:
    """Weights and multipliers for transparent, explainable incident priority scoring."""

    # Severity weights per alert type
    rule_weights: Dict[str, int] = field(
        default_factory=lambda: {
            "RULE-PORT-SCAN": 25,
            "RULE-HOST-SCAN": 35,
            "RULE-EXFIL-SPIKE": 40,
        }
    )
    max_score: int = 100


@dataclass
class NetSleuthConfig:
    """Master configuration container for NetSleuth runtime."""

    detection: DetectionConfig = field(default_factory=DetectionConfig)
    correlation: CorrelationConfig = field(default_factory=CorrelationConfig)
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    default_data_dir: str = "data/synthetic"

    # TODO (Phase 2): Add helper methods to export and import config to/from dict/JSON
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration settings to a dictionary."""
        return {
            "detection": {
                "port_scan_window_sec": self.detection.port_scan_window_sec,
                "port_scan_threshold": self.detection.port_scan_threshold,
                "host_scan_window_sec": self.detection.host_scan_window_sec,
                "host_scan_threshold": self.detection.host_scan_threshold,
                "exfil_window_sec": self.detection.exfil_window_sec,
                "exfil_byte_threshold": self.detection.exfil_byte_threshold,
            },
            "correlation": {
                "correlation_window_sec": self.correlation.correlation_window_sec,
            },
            "scoring": {
                "rule_weights": self.scoring.rule_weights,
                "max_score": self.scoring.max_score,
            },
            "default_data_dir": self.default_data_dir,
        }
