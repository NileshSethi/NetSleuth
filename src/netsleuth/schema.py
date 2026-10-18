"""Data schema definitions and validation contracts for network-flow records.

Defines allowable column names, data types, protocols, actions, directions,
and validation exception classes.
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional


class ProtocolEnum(str, Enum):
    """Allowed transport layer protocols."""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"


class ActionEnum(str, Enum):
    """Allowed network security policy actions."""
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"


class DirectionEnum(str, Enum):
    """Traffic boundary orientation relative to monitored cloud network."""
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"
    INTERNAL = "INTERNAL"


# List of columns that must be present in every valid network flow CSV
REQUIRED_COLUMNS: List[str] = [
    "event_id",
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "bytes",
    "action",
    "direction",
]

# Ground-truth evaluation columns (must be isolated from detection algorithms)
EVALUATION_COLUMNS: List[str] = [
    "scenario_id",
    "is_attack",
    "attack_type",
]


class SchemaValidationError(Exception):
    """Raised when an ingested flow record or dataset fails schema compliance."""
    pass


@dataclass(frozen=True)
class FlowRecord:
    """Strongly-typed representation of an individual network flow event."""
    event_id: str
    timestamp: str  # ISO-8601 UTC string (e.g., '2026-10-18T10:15:30Z')
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes: int
    action: str
    direction: str
    cloud_region: Optional[str] = None
    vpc_id: Optional[str] = None

    # TODO (Phase 2): Implement field-level validation methods (IP format, port bounds, byte limits)
