"""Loads, validates, and cleans network flow CSV files."""

import ipaddress
import pandas as pd
from .config import REQUIRED_COLUMNS


def is_valid_ipv4(ip_str: str) -> bool:
    """Return True if the given string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(str(ip_str).strip())
        return True
    except (ValueError, TypeError):
        return False


def load_flows(file_source) -> tuple[pd.DataFrame, int]:
    """Read a flow log CSV, validate rows, sort by time, and report dropped rows."""
    df = pd.read_csv(file_source)

    # Verify that all required columns are present
    missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns in CSV: {', '.join(missing)}")

    initial_count = len(df)

    # Convert timestamps to timezone-aware UTC datetime
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce")
    df["bytes"] = pd.to_numeric(df["bytes"], errors="coerce")

    # Filter out rows with invalid timestamps, negative bytes, or out-of-range ports
    valid_time = df["timestamp"].notna()
    valid_bytes = df["bytes"].notna() & (df["bytes"] >= 0)
    valid_ports = df["dst_port"].notna() & (df["dst_port"] >= 1) & (df["dst_port"] <= 65535)
    valid_src_ips = df["src_ip"].apply(is_valid_ipv4)
    valid_dst_ips = df["dst_ip"].apply(is_valid_ipv4)

    valid_mask = valid_time & valid_bytes & valid_ports & valid_src_ips & valid_dst_ips
    clean_df = df[valid_mask].copy()

    # Cast ports and bytes to integers
    clean_df["dst_port"] = clean_df["dst_port"].astype(int)
    clean_df["bytes"] = clean_df["bytes"].astype(int)

    # Sort chronologically and reset row index
    clean_df = clean_df.sort_values(by="timestamp").reset_index(drop=True)

    dropped_count = initial_count - len(clean_df)
    return clean_df, dropped_count
