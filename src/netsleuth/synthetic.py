"""Synthetic Network-Flow Dataset Generator.

Generates reproducible, RFC-compliant synthetic network-flow records modeling
cloud VPC flow logs for benign baselines and simulated cyber-attack scenarios:
- Scenario 1: Benign Enterprise Baseline
- Scenario 2: Vertical Port Scan Reconnaissance
- Scenario 3: Horizontal Host Sweep Discovery
- Scenario 4: Anomalous Outbound Data Exfiltration
- Scenario 5: Multi-Stage Blended Attack Kill Chain

All scenarios use fixed random seeds for strict determinism.
"""

import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
import pandas as pd

from netsleuth.schema import REQUIRED_COLUMNS, EVALUATION_COLUMNS


def _make_event_id() -> str:
    """Generate a unique flow event identifier."""
    return f"flw-{uuid.uuid4().hex[:10]}"


def _format_iso(dt: datetime) -> str:
    """Format datetime object into canonical ISO-8601 UTC string."""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_benign_flows(
    base_time: datetime,
    duration_minutes: int = 30,
    count: int = 500,
    seed: int = 42,
) -> List[Dict[str, Any]]:
    """Generate realistic benign enterprise network traffic."""
    rnd = random.Random(seed)
    flows = []

    internal_workstations = [f"10.0.1.{i}" for i in range(10, 30)]
    internal_servers = ["10.0.0.5", "10.0.0.10", "10.0.0.20"]
    external_web_ips = ["198.51.100.15", "198.51.100.42", "203.0.113.10", "203.0.113.55"]

    common_services = [
        (443, "TCP", "OUTBOUND"),
        (80, "TCP", "OUTBOUND"),
        (53, "UDP", "OUTBOUND"),
        (445, "TCP", "INTERNAL"),
        (22, "TCP", "INTERNAL"),
    ]

    for _ in range(count):
        offset_seconds = rnd.randint(0, duration_minutes * 60)
        ts = base_time + timedelta(seconds=offset_seconds)
        src = rnd.choice(internal_workstations)
        src_port = rnd.randint(49152, 65535)

        service_port, protocol, direction = rnd.choice(common_services)
        if direction == "INTERNAL":
            dst = rnd.choice(internal_servers)
        else:
            dst = rnd.choice(external_web_ips)

        # Benign bytes: HTTP/S between 1 KB and 300 KB; DNS small 60-500 bytes
        if service_port in (80, 443):
            byte_count = rnd.randint(1_024, 300_000)
        elif service_port == 53:
            byte_count = rnd.randint(64, 512)
        else:
            byte_count = rnd.randint(500, 50_000)

        action = "ACCEPT" if rnd.random() > 0.05 else "REJECT"

        flows.append(
            {
                "event_id": _make_event_id(),
                "timestamp": _format_iso(ts),
                "src_ip": src,
                "dst_ip": dst,
                "src_port": src_port,
                "dst_port": service_port,
                "protocol": protocol,
                "bytes": byte_count,
                "action": action,
                "direction": direction,
                "cloud_region": "us-east-1",
                "vpc_id": "vpc-0a1b2c3d",
                "scenario_id": "SCN-01-BENIGN",
                "is_attack": False,
                "attack_type": "benign",
            }
        )

    return flows


def generate_scenario_01_benign(output_path: Optional[Path] = None) -> pd.DataFrame:
    """Scenario 1: Pure benign baseline enterprise network traffic."""
    base_time = datetime(2026, 10, 18, 9, 0, 0, tzinfo=timezone.utc)
    flows = generate_benign_flows(base_time, duration_minutes=30, count=1000, seed=101)

    df = pd.DataFrame(flows)
    df.sort_values(by="timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False)
    return df


def generate_scenario_02_port_scan(output_path: Optional[Path] = None) -> pd.DataFrame:
    """Scenario 2: Vertical Port Scan against a single target internal host."""
    rnd = random.Random(202)
    base_time = datetime(2026, 10, 18, 10, 0, 0, tzinfo=timezone.utc)

    # 1. Background benign traffic
    flows = generate_benign_flows(base_time, duration_minutes=15, count=400, seed=203)
    for f in flows:
        f["scenario_id"] = "SCN-02-PORTSCAN"

    # 2. Attacker vertical port scan: 10.0.1.45 probes 10.0.0.15 on 40 distinct ports
    attacker_ip = "10.0.1.45"
    target_server = "10.0.0.15"
    scan_start = base_time + timedelta(minutes=5)

    ports_to_scan = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443,
        8888, 9000, 9200, 27017, 7001, 5000, 8081, 10000, 49152, 49153,
        49154, 49155, 49156, 49157
    ]

    for idx, port in enumerate(ports_to_scan):
        ts = scan_start + timedelta(seconds=idx * 1)  # 1 port per second (40s scan)
        src_port = rnd.randint(50000, 65000)
        # Target only has ports 80, 443 open; others rejected
        action = "ACCEPT" if port in (80, 443) else "REJECT"

        flows.append(
            {
                "event_id": _make_event_id(),
                "timestamp": _format_iso(ts),
                "src_ip": attacker_ip,
                "dst_ip": target_server,
                "src_port": src_port,
                "dst_port": port,
                "protocol": "TCP",
                "bytes": rnd.randint(40, 120),  # Small probe packets
                "action": action,
                "direction": "INTERNAL",
                "cloud_region": "us-east-1",
                "vpc_id": "vpc-0a1b2c3d",
                "scenario_id": "SCN-02-PORTSCAN",
                "is_attack": True,
                "attack_type": "port_scan",
            }
        )

    df = pd.DataFrame(flows)
    df.sort_values(by="timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False)
    return df


def generate_scenario_03_host_scan(output_path: Optional[Path] = None) -> pd.DataFrame:
    """Scenario 3: Horizontal Host Scan (Discovery sweep across 25 subnet hosts)."""
    rnd = random.Random(303)
    base_time = datetime(2026, 10, 18, 11, 0, 0, tzinfo=timezone.utc)

    # 1. Background benign traffic
    flows = generate_benign_flows(base_time, duration_minutes=15, count=400, seed=304)
    for f in flows:
        f["scenario_id"] = "SCN-03-HOSTSCAN"

    # 2. Attacker horizontal sweep: 10.0.1.77 probes port 445 across 10.0.2.1-10.0.2.25
    attacker_ip = "10.0.1.77"
    sweep_start = base_time + timedelta(minutes=4)
    target_hosts = [f"10.0.2.{i}" for i in range(1, 26)]  # 25 hosts

    for idx, target_ip in enumerate(target_hosts):
        ts = sweep_start + timedelta(seconds=idx * 2)  # probe every 2 seconds
        src_port = rnd.randint(49152, 65535)
        # Most internal hosts don't have SMB open
        action = "ACCEPT" if idx in (3, 12, 19) else "REJECT"

        flows.append(
            {
                "event_id": _make_event_id(),
                "timestamp": _format_iso(ts),
                "src_ip": attacker_ip,
                "dst_ip": target_ip,
                "src_port": src_port,
                "dst_port": 445,
                "protocol": "TCP",
                "bytes": rnd.randint(60, 140),
                "action": action,
                "direction": "INTERNAL",
                "cloud_region": "us-east-1",
                "vpc_id": "vpc-0a1b2c3d",
                "scenario_id": "SCN-03-HOSTSCAN",
                "is_attack": True,
                "attack_type": "host_scan",
            }
        )

    df = pd.DataFrame(flows)
    df.sort_values(by="timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False)
    return df


def generate_scenario_04_exfiltration(output_path: Optional[Path] = None) -> pd.DataFrame:
    """Scenario 4: High-volume outbound data exfiltration spike."""
    rnd = random.Random(404)
    base_time = datetime(2026, 10, 18, 14, 0, 0, tzinfo=timezone.utc)

    # 1. Background benign traffic
    flows = generate_benign_flows(base_time, duration_minutes=20, count=400, seed=405)
    for f in flows:
        f["scenario_id"] = "SCN-04-EXFIL"

    # 2. Outbound Exfiltration: Internal DB server transfers 80 MB to external IP
    db_server = "10.0.0.25"
    drop_point_ip = "203.0.113.88"  # RFC 5737 doc IP
    exfil_start = base_time + timedelta(minutes=8)

    # 8 flows of ~10 MB each over 2 minutes (Total ~80 MB)
    for i in range(8):
        ts = exfil_start + timedelta(seconds=i * 15)
        flows.append(
            {
                "event_id": _make_event_id(),
                "timestamp": _format_iso(ts),
                "src_ip": db_server,
                "dst_ip": drop_point_ip,
                "src_port": rnd.randint(49152, 65535),
                "dst_port": 443,
                "protocol": "TCP",
                "bytes": 10_485_760,  # Exactly 10 MB per flow
                "action": "ACCEPT",
                "direction": "OUTBOUND",
                "cloud_region": "us-east-1",
                "vpc_id": "vpc-0a1b2c3d",
                "scenario_id": "SCN-04-EXFIL",
                "is_attack": True,
                "attack_type": "exfiltration",
            }
        )

    df = pd.DataFrame(flows)
    df.sort_values(by="timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False)
    return df


def generate_scenario_05_blended_attack(output_path: Optional[Path] = None) -> pd.DataFrame:
    """Scenario 5: Multi-stage APT blended attack (Discovery -> Recon -> Pivot -> Exfil)."""
    rnd = random.Random(505)
    base_time = datetime(2026, 10, 18, 15, 0, 0, tzinfo=timezone.utc)

    # 1. Baseline enterprise traffic across 40 minutes
    flows = generate_benign_flows(base_time, duration_minutes=40, count=700, seed=506)
    for f in flows:
        f["scenario_id"] = "SCN-05-BLENDED"

    attacker_workstation = "10.0.1.100"
    file_server = "10.0.0.15"
    exfil_dest = "203.0.113.99"

    # Stage 1: Horizontal Host Sweep (Discovery) at T+5m
    stage1_time = base_time + timedelta(minutes=5)
    for i in range(15):
        ts = stage1_time + timedelta(seconds=i * 3)
        flows.append(
            {
                "event_id": _make_event_id(),
                "timestamp": _format_iso(ts),
                "src_ip": attacker_workstation,
                "dst_ip": f"10.0.0.{i+10}",
                "src_port": rnd.randint(50000, 60000),
                "dst_port": 445,
                "protocol": "TCP",
                "bytes": 96,
                "action": "ACCEPT" if i == 5 else "REJECT",  # Target 10.0.0.15 responds
                "direction": "INTERNAL",
                "cloud_region": "us-east-1",
                "vpc_id": "vpc-0a1b2c3d",
                "scenario_id": "SCN-05-BLENDED",
                "is_attack": True,
                "attack_type": "host_scan",
            }
        )

    # Stage 2: Vertical Port Scan on discovered file server (10.0.0.15) at T+12m
    stage2_time = base_time + timedelta(minutes=12)
    ports = [21, 22, 80, 135, 139, 443, 445, 1433, 3306, 3389, 8080, 8443, 9000, 5000, 8888, 2049, 5900, 6379, 9200, 27017]
    for idx, p in enumerate(ports):
        ts = stage2_time + timedelta(seconds=idx * 2)
        flows.append(
            {
                "event_id": _make_event_id(),
                "timestamp": _format_iso(ts),
                "src_ip": attacker_workstation,
                "dst_ip": file_server,
                "src_port": rnd.randint(50000, 60000),
                "dst_port": p,
                "protocol": "TCP",
                "bytes": 74,
                "action": "ACCEPT" if p in (80, 445) else "REJECT",
                "direction": "INTERNAL",
                "cloud_region": "us-east-1",
                "vpc_id": "vpc-0a1b2c3d",
                "scenario_id": "SCN-05-BLENDED",
                "is_attack": True,
                "attack_type": "port_scan",
            }
        )

    # Stage 3: Lateral Movement & Access at T+18m
    stage3_time = base_time + timedelta(minutes=18)
    flows.append(
        {
            "event_id": _make_event_id(),
            "timestamp": _format_iso(stage3_time),
            "src_ip": attacker_workstation,
            "dst_ip": file_server,
            "src_port": 54321,
            "dst_port": 445,
            "protocol": "TCP",
            "bytes": 2_500_000,  # 2.5 MB lateral file transfer
            "action": "ACCEPT",
            "direction": "INTERNAL",
            "cloud_region": "us-east-1",
            "vpc_id": "vpc-0a1b2c3d",
            "scenario_id": "SCN-05-BLENDED",
            "is_attack": True,
            "attack_type": "lateral_movement",
        }
    )

    # Stage 4: Outbound Exfiltration from file server at T+25m
    stage4_time = base_time + timedelta(minutes=25)
    for i in range(10):
        ts = stage4_time + timedelta(seconds=i * 12)
        flows.append(
            {
                "event_id": _make_event_id(),
                "timestamp": _format_iso(ts),
                "src_ip": file_server,
                "dst_ip": exfil_dest,
                "src_port": rnd.randint(49152, 65535),
                "dst_port": 443,
                "protocol": "TCP",
                "bytes": 10_000_000,  # 10 MB per burst (100 MB total)
                "action": "ACCEPT",
                "direction": "OUTBOUND",
                "cloud_region": "us-east-1",
                "vpc_id": "vpc-0a1b2c3d",
                "scenario_id": "SCN-05-BLENDED",
                "is_attack": True,
                "attack_type": "exfiltration",
            }
        )

    df = pd.DataFrame(flows)
    df.sort_values(by="timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False)
    return df


def generate_all_synthetic_datasets(target_dir: Union[str, Path] = "data/synthetic") -> Dict[str, Path]:
    """Generate and write all 5 canonical benchmark datasets to disk."""
    dir_path = Path(target_dir)
    dir_path.mkdir(parents=True, exist_ok=True)

    generators = {
        "scenario_01_benign.csv": generate_scenario_01_benign,
        "scenario_02_port_scan.csv": generate_scenario_02_port_scan,
        "scenario_03_host_scan.csv": generate_scenario_03_host_scan,
        "scenario_04_exfiltration.csv": generate_scenario_04_exfiltration,
        "scenario_05_blended_attack.csv": generate_scenario_05_blended_attack,
    }

    generated_paths = {}
    for filename, gen_func in generators.items():
        file_path = dir_path / filename
        gen_func(file_path)
        generated_paths[filename] = file_path

    return generated_paths


if __name__ == "__main__":
    paths = generate_all_synthetic_datasets()
    print(f"Successfully generated {len(paths)} synthetic datasets:")
    for name, p in paths.items():
        print(f" - {name} -> {p}")
