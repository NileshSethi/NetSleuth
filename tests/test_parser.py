"""Unit tests for NetSleuth CSV Ingestion, Validation, and Normalization Module.
"""

import io
from pathlib import Path
import pytest
import pandas as pd

from netsleuth.schema import (
    REQUIRED_COLUMNS,
    SchemaValidationError,
    is_valid_ipv4,
    is_valid_port,
    is_valid_bytes,
    FlowRecord,
)
from netsleuth.parser import (
    load_and_validate_flow_csv,
    validate_schema,
)


# ------------------------------------------------------------------------------
# Schema Helper Tests
# ------------------------------------------------------------------------------

def test_is_valid_ipv4():
    """Verify IPv4 string validation."""
    assert is_valid_ipv4("192.168.1.1") is True
    assert is_valid_ipv4("10.0.0.1") is True
    assert is_valid_ipv4("203.0.113.195") is True
    assert is_valid_ipv4("999.999.999.999") is False
    assert is_valid_ipv4("10.0.0") is False
    assert is_valid_ipv4("invalid_ip") is False
    assert is_valid_ipv4(None) is False
    assert is_valid_ipv4(12345) is False


def test_is_valid_port():
    """Verify TCP/UDP port range bounds (1 to 65535)."""
    assert is_valid_port(1) is True
    assert is_valid_port(80) is True
    assert is_valid_port(65535) is True
    assert is_valid_port("443") is True
    assert is_valid_port(0) is False
    assert is_valid_port(65536) is False
    assert is_valid_port(-1) is False
    assert is_valid_port("invalid") is False


def test_is_valid_bytes():
    """Verify byte count validation (non-negative integer)."""
    assert is_valid_bytes(0) is True
    assert is_valid_bytes(1024) is True
    assert is_valid_bytes("5000") is True
    assert is_valid_bytes(-1) is False
    assert is_valid_bytes("invalid") is False


def test_flow_record_validate_success():
    """Verify valid FlowRecord instance passes validation."""
    record = FlowRecord(
        event_id="flw-001",
        timestamp="2026-10-18T10:00:00Z",
        src_ip="10.0.1.5",
        dst_ip="10.0.0.10",
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        bytes=1024,
        action="ACCEPT",
        direction="INTERNAL",
    )
    is_valid, errors = record.validate()
    assert is_valid is True
    assert len(errors) == 0


def test_flow_record_validate_failure():
    """Verify invalid FlowRecord instance reports clear error reasons."""
    record = FlowRecord(
        event_id="",
        timestamp="2026-10-18T10:00:00Z",
        src_ip="invalid_ip",
        dst_ip="10.0.0.10",
        src_port=99999,
        dst_port=-1,
        protocol="HTTP",  # Not TCP/UDP/ICMP
        bytes=-50,
        action="DROP",    # Not ACCEPT/REJECT
        direction="SIDE", # Not INBOUND/OUTBOUND/INTERNAL
    )
    is_valid, errors = record.validate()
    assert is_valid is False
    assert len(errors) >= 5


# ------------------------------------------------------------------------------
# CSV Parser Tests
# ------------------------------------------------------------------------------

def test_load_valid_synthetic_scenario():
    """Verify parser successfully ingests generated synthetic dataset."""
    scenario_path = Path("data/synthetic/scenario_01_benign.csv")
    assert scenario_path.exists(), "Synthetic dataset must exist"

    df = load_and_validate_flow_csv(scenario_path)
    assert isinstance(df, pd.DataFrame)
    assert len(df) > 0
    for col in REQUIRED_COLUMNS:
        assert col in df.columns

    # Verify chronological ordering
    assert df["timestamp"].is_monotonic_increasing is True
    # Verify UTC timezone
    assert df["timestamp"].dt.tz is not None


def test_all_five_synthetic_scenarios_parse_cleanly():
    """Verify all 5 synthetic benchmark scenarios parse without dropped rows."""
    scenario_files = [
        "scenario_01_benign.csv",
        "scenario_02_port_scan.csv",
        "scenario_03_host_scan.csv",
        "scenario_04_exfiltration.csv",
        "scenario_05_blended_attack.csv",
    ]
    for filename in scenario_files:
        path = Path("data/synthetic") / filename
        assert path.exists(), f"Benchmark file {filename} must exist"
        df = load_and_validate_flow_csv(path, strict_mode=True)
        assert len(df) > 0, f"{filename} should contain rows"
        assert df.attrs["dropped_row_count"] == 0, f"{filename} should have 0 dropped rows"
        assert df["timestamp"].is_monotonic_increasing is True


def test_missing_required_column_raises_error(tmp_path):
    """Verify missing required column raises SchemaValidationError."""
    csv_content = """event_id,timestamp,src_ip,dst_ip,src_port,protocol,bytes,action,direction
flw-01,2026-10-18T10:00:00Z,10.0.1.1,10.0.0.2,50000,TCP,100,ACCEPT,INTERNAL
"""
    # dst_port is missing
    bad_csv = tmp_path / "missing_col.csv"
    bad_csv.write_text(csv_content)

    with pytest.raises(SchemaValidationError) as exc_info:
        load_and_validate_flow_csv(bad_csv)
    assert "missing required columns" in str(exc_info.value).lower()
    assert "dst_port" in str(exc_info.value)


def test_empty_csv_handling(tmp_path):
    """Verify empty CSV returns an empty DataFrame without raising an exception."""
    empty_csv = tmp_path / "empty.csv"
    empty_csv.write_text("")

    df = load_and_validate_flow_csv(empty_csv)
    assert isinstance(df, pd.DataFrame)
    assert len(df) == 0
    for col in REQUIRED_COLUMNS:
        assert col in df.columns


def test_header_only_csv_handling(tmp_path):
    """Verify header-only CSV returns an empty DataFrame with valid columns."""
    header_csv = tmp_path / "header_only.csv"
    header_csv.write_text(",".join(REQUIRED_COLUMNS) + "\n")

    df = load_and_validate_flow_csv(header_csv)
    assert isinstance(df, pd.DataFrame)
    assert len(df) == 0


def test_nonexistent_file_raises_error():
    """Verify nonexistent file path raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError):
        load_and_validate_flow_csv("data/nonexistent_file_12345.csv")


def test_malformed_rows_filtered_out():
    """Verify invalid IP, out-of-range port, negative bytes, and invalid dates are filtered."""
    csv_data = """event_id,timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,action,direction
flw-valid-01,2026-10-18T10:00:00Z,10.0.1.10,10.0.0.5,50000,80,TCP,1024,ACCEPT,INTERNAL
flw-bad-ip,2026-10-18T10:00:01Z,999.1.1.1,10.0.0.5,50000,80,TCP,1024,ACCEPT,INTERNAL
flw-bad-port,2026-10-18T10:00:02Z,10.0.1.10,10.0.0.5,50000,70000,TCP,1024,ACCEPT,INTERNAL
flw-bad-bytes,2026-10-18T10:00:03Z,10.0.1.10,10.0.0.5,50000,80,TCP,-500,ACCEPT,INTERNAL
flw-bad-time,invalid-timestamp,10.0.1.10,10.0.0.5,50000,80,TCP,1024,ACCEPT,INTERNAL
flw-bad-proto,2026-10-18T10:00:04Z,10.0.1.10,10.0.0.5,50000,80,XYZ,1024,ACCEPT,INTERNAL
flw-valid-02,2026-10-18T10:00:05Z,10.0.1.10,10.0.0.5,50000,443,TCP,2048,ACCEPT,INTERNAL
"""
    buffer = io.StringIO(csv_data)
    df = load_and_validate_flow_csv(buffer, strict_mode=False)

    # Only flw-valid-01 and flw-valid-02 should survive
    assert len(df) == 2
    assert list(df["event_id"]) == ["flw-valid-01", "flw-valid-02"]
    assert df.attrs["raw_row_count"] == 7
    assert df.attrs["dropped_row_count"] == 5


def test_strict_mode_raises_on_malformed_row():
    """Verify strict_mode=True raises SchemaValidationError on malformed records."""
    csv_data = """event_id,timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,action,direction
flw-valid-01,2026-10-18T10:00:00Z,10.0.1.10,10.0.0.5,50000,80,TCP,1024,ACCEPT,INTERNAL
flw-bad-ip,2026-10-18T10:00:01Z,not_an_ip,10.0.0.5,50000,80,TCP,1024,ACCEPT,INTERNAL
"""
    buffer = io.StringIO(csv_data)
    with pytest.raises(SchemaValidationError) as exc_info:
        load_and_validate_flow_csv(buffer, strict_mode=True)
    assert "strict mode" in str(exc_info.value)


def test_deduplication_of_event_id():
    """Verify duplicate event_ids are deduplicated, keeping the first occurrence."""
    csv_data = """event_id,timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,action,direction
flw-01,2026-10-18T10:00:00Z,10.0.1.10,10.0.0.5,50000,80,TCP,1024,ACCEPT,INTERNAL
flw-01,2026-10-18T10:00:01Z,10.0.1.10,10.0.0.5,50000,80,TCP,9999,ACCEPT,INTERNAL
flw-02,2026-10-18T10:00:02Z,10.0.1.10,10.0.0.5,50000,80,TCP,500,ACCEPT,INTERNAL
"""
    buffer = io.StringIO(csv_data)
    df = load_and_validate_flow_csv(buffer)

    assert len(df) == 2
    # The first occurrence of flw-01 had bytes=1024
    flw_01_row = df[df["event_id"] == "flw-01"].iloc[0]
    assert flw_01_row["bytes"] == 1024


def test_chronological_sorting():
    """Verify records are returned sorted ascending by UTC timestamp."""
    csv_data = """event_id,timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,action,direction
flw-03,2026-10-18T10:15:00Z,10.0.1.10,10.0.0.5,50000,80,TCP,100,ACCEPT,INTERNAL
flw-01,2026-10-18T10:05:00Z,10.0.1.10,10.0.0.5,50000,80,TCP,100,ACCEPT,INTERNAL
flw-02,2026-10-18T10:10:00Z,10.0.1.10,10.0.0.5,50000,80,TCP,100,ACCEPT,INTERNAL
"""
    buffer = io.StringIO(csv_data)
    df = load_and_validate_flow_csv(buffer)

    assert list(df["event_id"]) == ["flw-01", "flw-02", "flw-03"]
