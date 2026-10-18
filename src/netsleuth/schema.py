"""Data schema definitions and validation contracts for network-flow records.

Defines allowable column names, data types, protocols, actions, directions,
and validation exception classes for NetSleuth.
"""

from dataclasses import dataclass
from enum import Enum
import ipaddress
from typing import List, Optional, Tuple, Dict, Any


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

# Canonical data types for parsed flow DataFrames
CANONICAL_DTYPES: Dict[str, Any] = {
    "event_id": "string",
    "src_ip": "string",
    "dst_ip": "string",
    "src_port": "int64",
    "dst_port": "int64",
    "protocol": "category",
    "bytes": "int64",
    "action": "category",
    "direction": "category",
}


class SchemaValidationError(Exception):
    """Raised when an ingested flow record or dataset fails schema compliance."""
    pass


def is_valid_ipv4(ip_str: str) -> bool:
    """Validate whether a string is a valid IPv4 address."""
    if not isinstance(ip_str, str):
        return False
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.version == 4
    except ValueError:
        return False


def is_valid_port(port: Any) -> bool:
    """Validate that port is an integer in range [1, 65535]."""
    try:
        p = int(port)
        return 1 <= p <= 65535
    except (ValueError, TypeError):
        return False


def is_valid_bytes(byte_count: Any) -> bool:
    """Validate that byte_count is a non-negative integer."""
    try:
        b = int(byte_count)
        return b >= 0
    except (ValueError, TypeError):
        return False


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

    def validate(self) -> Tuple[bool, List[str]]:
        """Validate individual record constraints.

        Returns:
            Tuple of (is_valid, list_of_error_reasons).
        """
        errors = []
        if not self.event_id or not isinstance(self.event_id, str):
            errors.append("Invalid or empty event_id")
        if not is_valid_ipv4(self.src_ip):
            errors.append(f"Invalid src_ip: {self.src_ip}")
        if not is_valid_ipv4(self.dst_ip):
            errors.append(f"Invalid dst_ip: {self.dst_ip}")
        if not is_valid_port(self.src_port):
            errors.append(f"Invalid src_port: {self.src_port}")
        if not is_valid_port(self.dst_port):
            errors.append(f"Invalid dst_port: {self.dst_port}")
        if not is_valid_bytes(self.bytes):
            errors.append(f"Invalid byte count: {self.bytes}")

        proto_upper = str(self.protocol).upper()
        if proto_upper not in {p.value for p in ProtocolEnum}:
            errors.append(f"Unsupported protocol: {self.protocol}")

        act_upper = str(self.action).upper()
        if act_upper not in {a.value for a in ActionEnum}:
            errors.append(f"Unsupported action: {self.action}")

        dir_upper = str(self.direction).upper()
        if dir_upper not in {d.value for d in DirectionEnum}:
            errors.append(f"Unsupported direction: {self.direction}")

        return (len(errors) == 0, errors)
