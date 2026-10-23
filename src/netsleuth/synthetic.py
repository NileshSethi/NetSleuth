"""Generates deterministic synthetic network flow datasets for benchmarking."""

import os
import random
from datetime import datetime, timedelta, timezone
import pandas as pd


def generate_benign_flows(start_time: datetime, count: int = 250, seed: int = 42) -> list[dict]:
    """Create realistic normal enterprise background traffic (web, DNS, email, SSH)."""
    random.seed(seed)
    flows = []
    internal_hosts = ["10.0.1.10", "10.0.1.20", "10.0.1.30", "10.0.1.40"]
    external_sites = ["93.184.216.34", "151.101.1.69", "172.217.16.206"]

    current_time = start_time
    for _ in range(count):
        current_time += timedelta(seconds=random.randint(2, 6))
        flow_type = random.choice(["web", "dns", "ssh", "email"])

        if flow_type == "web":
            src = random.choice(internal_hosts)
            dst = random.choice(external_sites)
            port = random.choice([80, 443])
            proto = "TCP"
            byte_count = random.randint(800, 15000)
            action = "ACCEPT"
            direction = "OUTBOUND"
        elif flow_type == "dns":
            src = random.choice(internal_hosts)
            dst = "10.0.0.2"
            port = 53
            proto = "UDP"
            byte_count = random.randint(64, 256)
            action = "ACCEPT"
            direction = "INTERNAL"
        elif flow_type == "ssh":
            src = "10.0.1.10"
            dst = "10.0.1.20"
            port = 22
            proto = "TCP"
            byte_count = random.randint(500, 3000)
            action = "ACCEPT"
            direction = "INTERNAL"
        else:  # email
            src = random.choice(internal_hosts)
            dst = "198.51.100.25"
            port = 587
            proto = "TCP"
            byte_count = random.randint(1200, 6000)
            action = "ACCEPT"
            direction = "OUTBOUND"

        flows.append({
            "timestamp": current_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "src_ip": src,
            "dst_ip": dst,
            "dst_port": port,
            "protocol": proto,
            "bytes": byte_count,
            "action": action,
            "direction": direction,
            "label": "normal"
        })
    return flows


def generate_scenario_1_port_scan(seed: int = 42) -> pd.DataFrame:
    """Generate scenario 1: External attacker scanning multiple ports on an internal host."""
    base_time = datetime(2026, 10, 20, 10, 0, 0, tzinfo=timezone.utc)
    flows = generate_benign_flows(base_time, count=220, seed=seed)

    # Attack burst: external attacker probes 18 distinct ports in 30 seconds
    attack_time = base_time + timedelta(seconds=120)
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 1433, 3306, 3389, 5432, 8080, 8443, 9000]
    for port in ports:
        attack_time += timedelta(seconds=1)
        flows.append({
            "timestamp": attack_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "src_ip": "198.51.100.55",
            "dst_ip": "10.0.1.20",
            "dst_port": port,
            "protocol": "TCP",
            "bytes": 64,
            "action": "REJECT" if port not in [80, 443] else "ACCEPT",
            "direction": "INBOUND",
            "label": "port_scan"
        })

    df = pd.DataFrame(flows).sort_values(by="timestamp").reset_index(drop=True)
    return df


def generate_scenario_2_host_scan(seed: int = 42) -> pd.DataFrame:
    """Generate scenario 2: Compromised host scanning internal subnet for SMB/port 445."""
    base_time = datetime(2026, 10, 20, 11, 0, 0, tzinfo=timezone.utc)
    flows = generate_benign_flows(base_time, count=220, seed=seed)

    # Attack burst: probes 12 distinct internal hosts on port 445 in 30 seconds
    attack_time = base_time + timedelta(seconds=120)
    target_hosts = [f"10.0.1.{i}" for i in range(21, 33)]
    for target in target_hosts:
        attack_time += timedelta(seconds=2)
        flows.append({
            "timestamp": attack_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "src_ip": "10.0.1.15",
            "dst_ip": target,
            "dst_port": 445,
            "protocol": "TCP",
            "bytes": 60,
            "action": "REJECT",
            "direction": "INTERNAL",
            "label": "host_scan"
        })

    df = pd.DataFrame(flows).sort_values(by="timestamp").reset_index(drop=True)
    return df


def generate_scenario_3_exfiltration(seed: int = 42) -> pd.DataFrame:
    """Generate scenario 3: Internal host exfiltrating large data volume outbound."""
    base_time = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)
    flows = generate_benign_flows(base_time, count=220, seed=seed)

    # Attack burst: 4 large flows totaling 2,400,000 bytes in 40 seconds
    attack_time = base_time + timedelta(seconds=150)
    for _ in range(4):
        attack_time += timedelta(seconds=8)
        flows.append({
            "timestamp": attack_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "src_ip": "10.0.1.45",
            "dst_ip": "203.0.113.88",
            "dst_port": 443,
            "protocol": "TCP",
            "bytes": 600000,
            "action": "ACCEPT",
            "direction": "OUTBOUND",
            "label": "exfiltration"
        })

    df = pd.DataFrame(flows).sort_values(by="timestamp").reset_index(drop=True)
    return df


def generate_scenario_4_multi_stage(seed: int = 42) -> pd.DataFrame:
    """Generate scenario 4: Multi-stage attack (port scan -> host scan -> exfiltration)."""
    base_time = datetime(2026, 10, 20, 14, 0, 0, tzinfo=timezone.utc)
    flows = generate_benign_flows(base_time, count=250, seed=seed)

    attacker = "10.0.1.99"

    # Stage 1: Port scan on 10.0.1.20 (at T + 60s)
    t1 = base_time + timedelta(seconds=60)
    ports = [21, 22, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 8080]
    for port in ports:
        t1 += timedelta(seconds=1)
        flows.append({
            "timestamp": t1.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "src_ip": attacker,
            "dst_ip": "10.0.1.20",
            "dst_port": port,
            "protocol": "TCP",
            "bytes": 64,
            "action": "REJECT",
            "direction": "INTERNAL",
            "label": "port_scan"
        })

    # Stage 2: Host scan on port 80 (at T + 180s, within 5 min window)
    t2 = base_time + timedelta(seconds=180)
    for host in [f"10.0.1.{i}" for i in range(30, 38)]:
        t2 += timedelta(seconds=2)
        flows.append({
            "timestamp": t2.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "src_ip": attacker,
            "dst_ip": host,
            "dst_port": 80,
            "protocol": "TCP",
            "bytes": 64,
            "action": "ACCEPT",
            "direction": "INTERNAL",
            "label": "host_scan"
        })

    # Stage 3: Large outbound exfiltration (at T + 300s, within 5 min window)
    t3 = base_time + timedelta(seconds=300)
    for _ in range(6):
        t3 += timedelta(seconds=6)
        flows.append({
            "timestamp": t3.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "src_ip": attacker,
            "dst_ip": "203.0.113.88",
            "dst_port": 443,
            "protocol": "TCP",
            "bytes": 1050000,
            "action": "ACCEPT",
            "direction": "OUTBOUND",
            "label": "exfiltration"
        })

    df = pd.DataFrame(flows).sort_values(by="timestamp").reset_index(drop=True)
    return df


def generate_scenario_5_benign(seed: int = 42) -> pd.DataFrame:
    """Generate scenario 5: Pure normal background traffic with 0 attacks."""
    base_time = datetime(2026, 10, 20, 16, 0, 0, tzinfo=timezone.utc)
    flows = generate_benign_flows(base_time, count=320, seed=seed)
    df = pd.DataFrame(flows).sort_values(by="timestamp").reset_index(drop=True)
    return df


def generate_scenario_6_persistent_threat(seed: int = 42) -> pd.DataFrame:
    """Generate scenario 6: Persistent threat actor re-attacking after quiet period (temporal splitting into 2 incidents)."""
    base_time = datetime(2026, 10, 20, 18, 0, 0, tzinfo=timezone.utc)
    flows = generate_benign_flows(base_time, count=240, seed=seed)
    attacker = "10.0.1.105"

    # Wave 1: Port scan on 10.0.1.30 (14 ports)
    t1 = base_time + timedelta(seconds=60)
    ports = [21, 22, 23, 25, 80, 110, 143, 443, 445, 1433, 3306, 3389, 8080, 8443]
    for p in ports:
        t1 += timedelta(seconds=1)
        flows.append({
            "timestamp": t1.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "src_ip": attacker,
            "dst_ip": "10.0.1.30",
            "dst_port": p,
            "protocol": "TCP",
            "bytes": 64,
            "action": "REJECT",
            "direction": "INTERNAL",
            "label": "port_scan"
        })

    # Quiet gap of 12 minutes (720s > 300s correlation window)
    # Wave 2: Host sweep across 8 hosts on port 445
    t2 = base_time + timedelta(seconds=820)
    for host in [f"10.0.1.{i}" for i in range(40, 48)]:
        t2 += timedelta(seconds=2)
        flows.append({
            "timestamp": t2.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "src_ip": attacker,
            "dst_ip": host,
            "dst_port": 445,
            "protocol": "TCP",
            "bytes": 64,
            "action": "REJECT",
            "direction": "INTERNAL",
            "label": "host_scan"
        })

    # Wave 2 follow-up: Moderate exfiltration (3 flows x 600KB = 1.8MB)
    t3 = t2 + timedelta(seconds=40)
    for _ in range(3):
        t3 += timedelta(seconds=6)
        flows.append({
            "timestamp": t3.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "src_ip": attacker,
            "dst_ip": "203.0.113.77",
            "dst_port": 443,
            "protocol": "TCP",
            "bytes": 600000,
            "action": "ACCEPT",
            "direction": "OUTBOUND",
            "label": "exfiltration"
        })

    df = pd.DataFrame(flows).sort_values(by="timestamp").reset_index(drop=True)
    return df


def generate_scenario_7_coordinated_attack(seed: int = 42) -> pd.DataFrame:
    """Generate scenario 7: Coordinated multi-threat actor intrusion (dual concurrent attackers)."""
    base_time = datetime(2026, 10, 20, 20, 0, 0, tzinfo=timezone.utc)
    flows = generate_benign_flows(base_time, count=250, seed=seed)

    # Attacker 1 (External perimeter scanner 198.51.100.77: 15 ports on 10.0.1.20)
    t1 = base_time + timedelta(seconds=45)
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5432, 8080]
    for p in ports:
        t1 += timedelta(seconds=1)
        flows.append({
            "timestamp": t1.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "src_ip": "198.51.100.77",
            "dst_ip": "10.0.1.20",
            "dst_port": p,
            "protocol": "TCP",
            "bytes": 64,
            "action": "REJECT",
            "direction": "INBOUND",
            "label": "port_scan"
        })

    # Attacker 2 (Compromised internal host 10.0.1.55: SSH sweep across 7 hosts + 3.5MB exfiltration)
    t2 = base_time + timedelta(seconds=70)
    for host in [f"10.0.1.{i}" for i in range(11, 18)]:
        t2 += timedelta(seconds=2)
        flows.append({
            "timestamp": t2.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "src_ip": "10.0.1.55",
            "dst_ip": host,
            "dst_port": 22,
            "protocol": "TCP",
            "bytes": 64,
            "action": "REJECT",
            "direction": "INTERNAL",
            "label": "host_scan"
        })

    t3 = base_time + timedelta(seconds=120)
    for _ in range(5):
        t3 += timedelta(seconds=7)
        flows.append({
            "timestamp": t3.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "src_ip": "10.0.1.55",
            "dst_ip": "198.51.100.90",
            "dst_port": 443,
            "protocol": "TCP",
            "bytes": 700000,
            "action": "ACCEPT",
            "direction": "OUTBOUND",
            "label": "exfiltration"
        })

    df = pd.DataFrame(flows).sort_values(by="timestamp").reset_index(drop=True)
    return df


def generate_scenario_8_cloud_data_breach(seed: int = 42) -> pd.DataFrame:
    """Generate scenario 8: High-volume enterprise database breach (12 MB exfiltration)."""
    base_time = datetime(2026, 10, 20, 22, 0, 0, tzinfo=timezone.utc)
    flows = generate_benign_flows(base_time, count=220, seed=seed)

    # Rogue database host 10.0.1.60 dumps 12 MB in 10 flows
    t1 = base_time + timedelta(seconds=90)
    for _ in range(10):
        t1 += timedelta(seconds=5)
        flows.append({
            "timestamp": t1.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "src_ip": "10.0.1.60",
            "dst_ip": "198.51.100.199",
            "dst_port": 443,
            "protocol": "TCP",
            "bytes": 1200000,
            "action": "ACCEPT",
            "direction": "OUTBOUND",
            "label": "exfiltration"
        })

    df = pd.DataFrame(flows).sort_values(by="timestamp").reset_index(drop=True)
    return df


def generate_all_datasets(output_dir: str = "data/synthetic") -> dict[str, pd.DataFrame]:
    """Generate all 8 canonical and extended scenarios and save them as CSV files."""
    os.makedirs(output_dir, exist_ok=True)
    datasets = {
        "Scenario 1 - Port Scan": generate_scenario_1_port_scan(),
        "Scenario 2 - Host Scan": generate_scenario_2_host_scan(),
        "Scenario 3 - Data Exfiltration": generate_scenario_3_exfiltration(),
        "Scenario 4 - Multi-Stage Attack": generate_scenario_4_multi_stage(),
        "Scenario 5 - Benign Baseline": generate_scenario_5_benign(),
        "Scenario 6 - Persistent Threat": generate_scenario_6_persistent_threat(),
        "Scenario 7 - Coordinated Attack": generate_scenario_7_coordinated_attack(),
        "Scenario 8 - Cloud Data Breach": generate_scenario_8_cloud_data_breach()
    }

    filenames = {
        "Scenario 1 - Port Scan": "scenario1_port_scan.csv",
        "Scenario 2 - Host Scan": "scenario2_host_scan.csv",
        "Scenario 3 - Data Exfiltration": "scenario3_data_exfiltration.csv",
        "Scenario 4 - Multi-Stage Attack": "scenario4_multi_stage.csv",
        "Scenario 5 - Benign Baseline": "scenario5_benign.csv",
        "Scenario 6 - Persistent Threat": "scenario6_persistent_threat.csv",
        "Scenario 7 - Coordinated Attack": "scenario7_coordinated_attack.csv",
        "Scenario 8 - Cloud Data Breach": "scenario8_cloud_data_breach.csv"
    }

    for name, df in datasets.items():
        filepath = os.path.join(output_dir, filenames[name])
        df.to_csv(filepath, index=False)

    return datasets


if __name__ == "__main__":
    generate_all_datasets()

