"""Network Topology & Host Communication Graph Analysis Module.

Constructs directed graph structures (NetworkX) from network flow records,
modeling communicating IP hosts, connection degrees, volume weights, and blast radius.
Includes Plotly interactive 2D network topology visualization.
"""

import ipaddress
from typing import List, Dict, Any, Optional
import networkx as nx
import pandas as pd
import plotly.graph_objects as go


def is_private_ip(ip_str: str) -> bool:
    """Check if an IPv4 address belongs strictly to an internal private network (RFC 1918)."""
    try:
        ip = ipaddress.ip_address(str(ip_str).strip())
        if ip.version != 4:
            return False
        rfc1918_subnets = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
        return any(ip in subnet for subnet in rfc1918_subnets)
    except (ValueError, TypeError):
        return False


def build_communication_graph(
    df: pd.DataFrame, flagged_ips: Optional[List[str]] = None
) -> nx.DiGraph:
    """Build a directed NetworkX graph representing host communications.

    Nodes represent communicating hosts (IPv4).
    Edges represent directed network flows (source -> destination) weighted by byte count.

    Args:
        df: Flow records DataFrame.
        flagged_ips: Optional list of IP addresses identified in alerts.

    Returns:
        Configured networkx.DiGraph instance.
    """
    graph = nx.DiGraph()

    if df is None or len(df) == 0:
        return graph

    flagged_set = set(flagged_ips or [])

    # Group flows by (src_ip, dst_ip)
    grouped = df.groupby(["src_ip", "dst_ip"], observed=True)

    for (src_ip, dst_ip), group in grouped:
        src = str(src_ip)
        dst = str(dst_ip)
        bytes_sum = int(group["bytes"].sum())
        flow_count = len(group)
        ports = sorted(list(set(group["dst_port"])))
        protocols = sorted(list(set(group["protocol"])))
        actions = sorted(list(set(group["action"])))

        graph.add_edge(
            src,
            dst,
            weight=bytes_sum,
            flow_count=flow_count,
            ports=ports[:20],  # sample up to 20 ports
            port_count=len(ports),
            protocols=protocols,
            actions=actions,
        )

    # Compute node attributes
    for node in graph.nodes():
        in_deg = graph.in_degree(node)
        out_deg = graph.out_degree(node)
        out_bytes = sum(d["weight"] for _, _, d in graph.out_edges(node, data=True))
        in_bytes = sum(d["weight"] for _, _, d in graph.in_edges(node, data=True))

        graph.nodes[node]["ip"] = node
        graph.nodes[node]["is_flagged"] = node in flagged_set
        graph.nodes[node]["is_internal"] = is_private_ip(node)
        graph.nodes[node]["in_degree"] = in_deg
        graph.nodes[node]["out_degree"] = out_deg
        graph.nodes[node]["total_out_bytes"] = out_bytes
        graph.nodes[node]["total_in_bytes"] = in_bytes
        graph.nodes[node]["total_bytes"] = out_bytes + in_bytes

    return graph


def calculate_host_metrics(graph: nx.DiGraph) -> Dict[str, Dict[str, Any]]:
    """Calculate graph-theoretic metrics (fan-out, fan-in, centrality) for each host node.

    Args:
        graph: Communicating hosts DiGraph.

    Returns:
        Dictionary mapping IP strings to metric dictionaries.
    """
    if len(graph) == 0:
        return {}

    degree_centrality = nx.degree_centrality(graph)
    in_degree_centrality = nx.in_degree_centrality(graph)
    out_degree_centrality = nx.out_degree_centrality(graph)

    metrics = {}
    for node in graph.nodes():
        attrs = graph.nodes[node]
        metrics[node] = {
            "ip": node,
            "is_flagged": attrs.get("is_flagged", False),
            "is_internal": attrs.get("is_internal", False),
            "in_degree": attrs.get("in_degree", 0),
            "out_degree": attrs.get("out_degree", 0),
            "total_bytes": attrs.get("total_bytes", 0),
            "total_bytes_mb": round(attrs.get("total_bytes", 0) / (1024 * 1024), 2),
            "degree_centrality": round(degree_centrality.get(node, 0.0), 4),
            "in_degree_centrality": round(in_degree_centrality.get(node, 0.0), 4),
            "out_degree_centrality": round(out_degree_centrality.get(node, 0.0), 4),
        }
    return metrics


def generate_network_graph_figure(
    graph: nx.DiGraph,
    title: str = "Host Communication Topology & Threat Graph",
    height: int = 650,
) -> go.Figure:
    """Generate an interactive Plotly 2D directed network graph visualization.

    Args:
        graph: Configured networkx.DiGraph.
        title: Chart title.
        height: Height in pixels.

    Returns:
        Interactive Plotly Figure object.
    """
    if len(graph) == 0:
        fig = go.Figure()
        fig.update_layout(
            title="Host Communication Topology (No Flow Data)",
            xaxis={"visible": False},
            yaxis={"visible": False},
            annotations=[
                {
                    "text": "No network flow records loaded.",
                    "xref": "paper",
                    "yref": "paper",
                    "showarrow": False,
                    "font": {"size": 16, "color": "gray"},
                }
            ],
            height=height,
        )
        return fig

    # Compute 2D node layout
    pos = nx.spring_layout(graph, seed=42, k=0.45, iterations=50)

    # Build Edge Trace
    edge_x = []
    edge_y = []
    edge_hover_x = []
    edge_hover_y = []
    edge_hover_text = []

    for u, v, data in graph.edges(data=True):
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

        # Midpoint for hover tooltip
        mid_x = (x0 + x1) / 2.0
        mid_y = (y0 + y1) / 2.0
        edge_hover_x.append(mid_x)
        edge_hover_y.append(mid_y)

        bytes_mb = round(data.get("weight", 0) / (1024 * 1024), 2)
        hover_str = (
            f"<b>Connection:</b> {u} &rarr; {v}<br>"
            f"<b>Flows:</b> {data.get('flow_count', 1):,}<br>"
            f"<b>Volume:</b> {bytes_mb} MB ({data.get('weight', 0):,} B)<br>"
            f"<b>Protocols:</b> {', '.join(data.get('protocols', []))}<br>"
            f"<b>Ports ({data.get('port_count', 1)}):</b> {', '.join(str(p) for p in data.get('ports', [])[:8])}"
        )
        edge_hover_text.append(hover_str)

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        line={"width": 1.2, "color": "rgba(160, 174, 192, 0.45)"},
        hoverinfo="none",
        mode="lines",
        name="Flow Connections",
    )

    edge_midpoint_trace = go.Scatter(
        x=edge_hover_x,
        y=edge_hover_y,
        mode="markers",
        marker={"size": 6, "color": "rgba(160, 174, 192, 0.0)"},
        hoverinfo="text",
        text=edge_hover_text,
        name="Flow Details",
        showlegend=False,
    )

    # Build Node Traces separated by category for distinct legend & styling
    categories = {
        "Suspicious / Flagged": {"color": "#FF4B4B", "nodes": [], "sizes": [], "texts": [], "x": [], "y": []},
        "Internal Host": {"color": "#00D4B2", "nodes": [], "sizes": [], "texts": [], "x": [], "y": []},
        "External IP": {"color": "#A855F7", "nodes": [], "sizes": [], "texts": [], "x": [], "y": []},
    }

    for node in graph.nodes():
        x, y = pos[node]
        attrs = graph.nodes[node]
        is_flagged = attrs.get("is_flagged", False)
        is_int = attrs.get("is_internal", False)

        if is_flagged:
            cat = "Suspicious / Flagged"
        elif is_int:
            cat = "Internal Host"
        else:
            cat = "External IP"

        total_mb = round(attrs.get("total_bytes", 0) / (1024 * 1024), 2)
        in_deg = attrs.get("in_degree", 0)
        out_deg = attrs.get("out_degree", 0)

        # Dynamic node size based on degree
        node_size = max(16, min(38, 16 + (in_deg + out_deg) * 1.5))

        hover_info = (
            f"<b>Host:</b> {node}<br>"
            f"<b>Status:</b> {'🚨 FLAGGED IN ALERT' if is_flagged else 'Normal Host'}<br>"
            f"<b>Classification:</b> {'Private Subnet (Internal)' if is_int else 'Public / External'}<br>"
            f"<b>Fan-Out (Out-Degree):</b> {out_deg} target(s)<br>"
            f"<b>Fan-In (In-Degree):</b> {in_deg} client(s)<br>"
            f"<b>Total Traffic:</b> {total_mb} MB"
        )

        categories[cat]["x"].append(x)
        categories[cat]["y"].append(y)
        categories[cat]["nodes"].append(node)
        categories[cat]["sizes"].append(node_size)
        categories[cat]["texts"].append(hover_info)

    node_traces = []
    for cat_name, cat_data in categories.items():
        if cat_data["x"]:
            trace = go.Scatter(
                x=cat_data["x"],
                y=cat_data["y"],
                mode="markers+text",
                text=[f"  {n}" for n in cat_data["nodes"]],
                textposition="top right",
                textfont={"size": 10, "color": "#E2E8F0"},
                hoverinfo="text",
                hovertext=cat_data["texts"],
                marker={
                    "size": cat_data["sizes"],
                    "color": cat_data["color"],
                    "line": {"width": 2, "color": "#FFFFFF"},
                    "opacity": 0.95,
                },
                name=cat_name,
            )
            node_traces.append(trace)

    fig = go.Figure(data=[edge_trace, edge_midpoint_trace] + node_traces)

    fig.update_layout(
        title={
            "text": f"<b>{title}</b>",
            "x": 0.02,
            "y": 0.96,
            "font": {"size": 18, "color": "#FFFFFF"},
        },
        showlegend=True,
        legend={
            "orientation": "h",
            "yanchor": "bottom",
            "y": 1.02,
            "xanchor": "right",
            "x": 1.0,
            "font": {"color": "#E2E8F0"},
        },
        hovermode="closest",
        margin={"b": 20, "l": 20, "r": 20, "t": 60},
        xaxis={"showgrid": False, "zeroline": False, "showticklabels": False},
        yaxis={"showgrid": False, "zeroline": False, "showticklabels": False},
        paper_bgcolor="rgba(15, 23, 42, 0.9)",
        plot_bgcolor="rgba(15, 23, 42, 0.9)",
        height=height,
    )

    return fig
