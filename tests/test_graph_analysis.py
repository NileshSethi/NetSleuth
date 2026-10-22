"""Unit tests for NetSleuth Network Topology and Graph Analysis Module.
"""

import pandas as pd
import networkx as nx
import plotly.graph_objects as go

from netsleuth.parser import load_and_validate_flow_csv
from netsleuth.graph_analysis import (
    is_private_ip,
    build_communication_graph,
    calculate_host_metrics,
    generate_network_graph_figure,
)


def test_is_private_ip():
    """Verify RFC 1918 private IP identification."""
    assert is_private_ip("10.0.1.10") is True
    assert is_private_ip("172.16.5.1") is True
    assert is_private_ip("192.168.1.100") is True
    assert is_private_ip("203.0.113.50") is False  # Documentation public
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("invalid") is False


def test_build_communication_graph_empty():
    """Verify empty DataFrame produces an empty NetworkX graph."""
    empty_df = pd.DataFrame()
    g = build_communication_graph(empty_df)
    assert isinstance(g, nx.DiGraph)
    assert len(g.nodes) == 0
    assert len(g.edges) == 0


def test_build_communication_graph_structure():
    """Verify nodes, directed edges, and weights are constructed correctly."""
    flows = pd.DataFrame([
        {
            "event_id": "flw-01",
            "timestamp": pd.Timestamp("2026-10-18 10:00:00", tz="UTC"),
            "src_ip": "10.0.1.10",
            "dst_ip": "10.0.0.5",
            "src_port": 50000,
            "dst_port": 80,
            "protocol": "TCP",
            "bytes": 1000,
            "action": "ACCEPT",
            "direction": "INTERNAL",
        },
        {
            "event_id": "flw-02",
            "timestamp": pd.Timestamp("2026-10-18 10:00:05", tz="UTC"),
            "src_ip": "10.0.1.10",
            "dst_ip": "10.0.0.5",
            "src_port": 50001,
            "dst_port": 443,
            "protocol": "TCP",
            "bytes": 2000,
            "action": "ACCEPT",
            "direction": "INTERNAL",
        },
        {
            "event_id": "flw-03",
            "timestamp": pd.Timestamp("2026-10-18 10:00:10", tz="UTC"),
            "src_ip": "10.0.0.5",
            "dst_ip": "203.0.113.88",
            "src_port": 49152,
            "dst_port": 443,
            "protocol": "TCP",
            "bytes": 50000,
            "action": "ACCEPT",
            "direction": "OUTBOUND",
        },
    ])

    g = build_communication_graph(flows, flagged_ips=["10.0.1.10"])
    assert len(g.nodes) == 3
    assert len(g.edges) == 2

    # Verify edge attributes between 10.0.1.10 and 10.0.0.5
    edge_data = g.get_edge_data("10.0.1.10", "10.0.0.5")
    assert edge_data["weight"] == 3000  # 1000 + 2000 bytes
    assert edge_data["flow_count"] == 2
    assert set(edge_data["ports"]) == {80, 443}

    # Verify node attributes
    node_a = g.nodes["10.0.1.10"]
    assert node_a["is_flagged"] is True
    assert node_a["is_internal"] is True
    assert node_a["out_degree"] == 1
    assert node_a["in_degree"] == 0

    node_c = g.nodes["203.0.113.88"]
    assert node_c["is_internal"] is False
    assert node_c["is_flagged"] is False


def test_calculate_host_metrics():
    """Verify calculation of host-level graph metrics."""
    flows = pd.DataFrame([
        {
            "event_id": "flw-01",
            "timestamp": pd.Timestamp("2026-10-18 10:00:00", tz="UTC"),
            "src_ip": "10.0.1.10",
            "dst_ip": "10.0.0.5",
            "src_port": 50000,
            "dst_port": 80,
            "protocol": "TCP",
            "bytes": 1048576,  # 1 MB
            "action": "ACCEPT",
            "direction": "INTERNAL",
        }
    ])
    g = build_communication_graph(flows)
    metrics = calculate_host_metrics(g)

    assert "10.0.1.10" in metrics
    assert "10.0.0.5" in metrics
    assert metrics["10.0.1.10"]["out_degree"] == 1
    assert metrics["10.0.1.10"]["total_bytes_mb"] == 1.0


def test_generate_network_graph_figure():
    """Verify Plotly figure generation for topology graph."""
    flows = pd.DataFrame([
        {
            "event_id": "flw-01",
            "timestamp": pd.Timestamp("2026-10-18 10:00:00", tz="UTC"),
            "src_ip": "10.0.1.10",
            "dst_ip": "10.0.0.5",
            "src_port": 50000,
            "dst_port": 80,
            "protocol": "TCP",
            "bytes": 1024,
            "action": "ACCEPT",
            "direction": "INTERNAL",
        }
    ])
    g = build_communication_graph(flows, flagged_ips=["10.0.1.10"])
    fig = generate_network_graph_figure(g)

    assert isinstance(fig, go.Figure)
    assert len(fig.data) >= 2  # Edge trace + Node traces


def test_graph_on_synthetic_scenario():
    """Verify graph construction on synthetic benchmark scenario."""
    df = load_and_validate_flow_csv("data/synthetic/scenario_02_port_scan.csv")
    g = build_communication_graph(df, flagged_ips=["10.0.1.45"])
    assert len(g.nodes) > 1
    assert len(g.edges) > 1
    assert g.nodes["10.0.1.45"]["is_flagged"] is True
