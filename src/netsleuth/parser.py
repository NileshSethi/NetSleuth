"""CSV Ingestion, Schema Validation, and Timestamp Normalization Module.

This module is responsible for loading raw CSV network flow logs, validating
the required column schema, verifying data integrity (IPs, ports, non-negative bytes),
converting timestamps to UTC, and sorting records chronologically.
"""

from typing import Union, List, Tuple, Optional
from pathlib import Path
import pandas as pd

from netsleuth.schema import (
    REQUIRED_COLUMNS,
    SchemaValidationError,
    is_valid_ipv4,
    ProtocolEnum,
    ActionEnum,
    DirectionEnum,
)


def validate_schema(df: pd.DataFrame) -> Tuple[bool, List[str]]:
    """Validate that the input DataFrame contains all required flow log columns.

    Args:
        df: Input pandas DataFrame to check.

    Returns:
        A tuple of (is_valid, list_of_missing_columns).
    """
    if df is None:
        return (False, list(REQUIRED_COLUMNS))
    missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    return (len(missing) == 0, missing)


def _create_empty_flow_dataframe(include_eval_cols: bool = False) -> pd.DataFrame:
    """Create an empty DataFrame with the canonical flow schema."""
    cols = list(REQUIRED_COLUMNS)
    if include_eval_cols:
        cols.extend(["scenario_id", "is_attack", "attack_type"])
    df = pd.DataFrame(columns=cols)
    df["timestamp"] = pd.to_datetime([], utc=True)
    return df


def load_and_validate_flow_csv(
    file_source: Union[str, Path, object],
    strict_mode: bool = False,
) -> pd.DataFrame:
    """Load, validate, normalize, and sort a CSV file containing flow records.

    Performs:
    1. CSV ingestion with graceful handling of empty or unreadable files.
    2. Header inspection verifying all `REQUIRED_COLUMNS` exist.
    3. Timestamp parsing to ISO-8601 UTC with invalid dates filtered out.
    4. IPv4 format validation for both `src_ip` and `dst_ip`.
    5. Numeric validation ensuring ports are in range [1, 65535] and bytes >= 0.
    6. Protocol, action, and direction standardization to uppercase.
    7. Deduplication of identical `event_id` records.
    8. Strict ascending chronological ordering by UTC timestamp.

    Args:
        file_source: File path (str/Path) or file-like buffer (e.g. UploadedFile).
        strict_mode: If True, raises SchemaValidationError on any malformed rows.
                     If False (default), filters out malformed rows and logs warnings.

    Returns:
        A sanitized, UTC-sorted pandas DataFrame.

    Raises:
        FileNotFoundError: If the specified file path does not exist.
        SchemaValidationError: If required columns are missing or file is corrupted.
    """
    # 1. Path existence check
    if isinstance(file_source, (str, Path)):
        path_obj = Path(file_source)
        if not path_obj.exists():
            raise FileNotFoundError(f"Flow log file not found: {file_source}")

    # 2. Ingestion with empty file handling
    try:
        df = pd.read_csv(file_source)
    except pd.errors.EmptyDataError:
        return _create_empty_flow_dataframe()
    except Exception as e:
        raise SchemaValidationError(f"Failed to parse CSV file: {str(e)}") from e

    # 3. Schema column validation
    is_valid, missing_cols = validate_schema(df)
    if not is_valid:
        raise SchemaValidationError(
            f"Input CSV is missing required columns: {missing_cols}. "
            f"Required schema: {REQUIRED_COLUMNS}"
        )

    raw_row_count = len(df)
    if raw_row_count == 0:
        return _create_empty_flow_dataframe()

    initial_df = df.copy()

    # 4. Timestamp normalization (UTC)
    parsed_ts = pd.to_datetime(initial_df["timestamp"], utc=True, errors="coerce")
    valid_ts_mask = parsed_ts.notna()

    if strict_mode and not valid_ts_mask.all():
        invalid_ts_count = int((~valid_ts_mask).sum())
        raise SchemaValidationError(
            f"Found {invalid_ts_count} rows with invalid UTC timestamps in strict mode."
        )

    initial_df["timestamp"] = parsed_ts

    # 5. Numeric conversion & bounds checking
    src_ports = pd.to_numeric(initial_df["src_port"], errors="coerce")
    dst_ports = pd.to_numeric(initial_df["dst_port"], errors="coerce")
    byte_counts = pd.to_numeric(initial_df["bytes"], errors="coerce")

    valid_ports_mask = (
        src_ports.notna()
        & (src_ports >= 1)
        & (src_ports <= 65535)
        & dst_ports.notna()
        & (dst_ports >= 1)
        & (dst_ports <= 65535)
    )

    valid_bytes_mask = byte_counts.notna() & (byte_counts >= 0)

    # 6. IP address validation
    valid_src_ip_mask = initial_df["src_ip"].astype(str).map(is_valid_ipv4)
    valid_dst_ip_mask = initial_df["dst_ip"].astype(str).map(is_valid_ipv4)
    valid_ips_mask = valid_src_ip_mask & valid_dst_ip_mask

    # 7. Protocol, Action, Direction string standardization
    initial_df["protocol"] = initial_df["protocol"].astype(str).str.upper().str.strip()
    initial_df["action"] = initial_df["action"].astype(str).str.upper().str.strip()
    initial_df["direction"] = initial_df["direction"].astype(str).str.upper().str.strip()

    valid_protocols = {p.value for p in ProtocolEnum}
    valid_actions = {a.value for a in ActionEnum}
    valid_directions = {d.value for d in DirectionEnum}

    valid_enums_mask = (
        initial_df["protocol"].isin(valid_protocols)
        & initial_df["action"].isin(valid_actions)
        & initial_df["direction"].isin(valid_directions)
    )

    # Combine all validity masks
    valid_rows_mask = (
        valid_ts_mask
        & valid_ports_mask
        & valid_bytes_mask
        & valid_ips_mask
        & valid_enums_mask
    )

    if strict_mode and not valid_rows_mask.all():
        invalid_count = int((~valid_rows_mask).sum())
        raise SchemaValidationError(
            f"Found {invalid_count} malformed rows failing schema bounds in strict mode."
        )

    clean_df = initial_df[valid_rows_mask].copy()

    # Cast integer columns cleanly
    clean_df["src_port"] = src_ports[valid_rows_mask].astype("int64")
    clean_df["dst_port"] = dst_ports[valid_rows_mask].astype("int64")
    clean_df["bytes"] = byte_counts[valid_rows_mask].astype("int64")
    clean_df["event_id"] = clean_df["event_id"].astype(str).str.strip()

    # 8. Deduplicate on event_id (keep first)
    clean_df.drop_duplicates(subset=["event_id"], keep="first", inplace=True)

    # 9. Sort chronologically by timestamp
    clean_df.sort_values(by="timestamp", ascending=True, inplace=True)
    clean_df.reset_index(drop=True, inplace=True)

    # Attach parsing telemetry to DataFrame metadata
    clean_df.attrs["raw_row_count"] = raw_row_count
    clean_df.attrs["valid_row_count"] = len(clean_df)
    clean_df.attrs["dropped_row_count"] = raw_row_count - len(clean_df)

    return clean_df
