"""Builds and visualizes network topology graphs and traffic communication matrices."""

import networkx as nx
import pandas as pd
import plotly.graph_objects as go


def build_graph(df: pd.DataFrame) -> nx.DiGraph:
    """Create a directed NetworkX graph with edge weights representing flow counts and volume."""
    g = nx.DiGraph()
    # Group communications by source and destination
    flow_pairs = df.groupby(["src_ip", "dst_ip"]).agg(
        flow_count=("bytes", "count"),
        total_bytes=("bytes", "sum")
    ).reset_index()

    for _, row in flow_pairs.iterrows():
        g.add_edge(
            row["src_ip"],
            row["dst_ip"],
            weight=int(row["flow_count"]),
            bytes=int(row["total_bytes"])
        )
    return g


def plot_graph(df: pd.DataFrame, incidents: list[dict] = None) -> go.Figure:
    """Plot the host communication graph in Plotly with tactical SOC styling."""
    g = build_graph(df)
    if len(g.nodes) == 0:
        return go.Figure()

    # Identify attacker and victim IPs from incidents
    attacker_ips = set()
    victim_ips = set()
    if incidents:
        for inc in incidents:
            attacker_ips.add(inc["src_ip"])
            for alert in inc.get("alerts", []):
                target = alert.get("target", "")
                if target and "hosts" not in target:
                    victim_ips.add(target)

    # Compute 2D node layout positions with generous spacing
    pos = nx.spring_layout(g, seed=42, k=1.35, iterations=85)

    # Build line segments for directed edges
    edge_x = []
    edge_y = []
    for u, v in g.edges():
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        line=dict(width=1.8, color="rgba(148, 163, 184, 0.5)"),
        hoverinfo="none",
        mode="lines"
    )

    # Build node markers and metadata
    node_x = []
    node_y = []
    node_colors = []
    node_sizes = []
    node_text = []

    for node in g.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)

        deg_in = g.in_degree(node)
        deg_out = g.out_degree(node)

        if node in attacker_ips:
            node_colors.append("#EF4444")  # Red for Attacker
            node_sizes.append(30)
            role = "Threat Actor (Source IP)"
        elif node in victim_ips:
            node_colors.append("#F59E0B")  # Amber for Targeted Victim
            node_sizes.append(24)
            role = "Targeted Host (Victim)"
        else:
            node_colors.append("#38BDF8")  # Cyan for Normal Hosts
            node_sizes.append(18)
            role = "Normal Subnet Host"

        node_text.append(
            f"<b>Host IP:</b> <code>{node}</code><br>"
            f"<b>Classification:</b> {role}<br>"
            f"<b>Outbound Connections:</b> {deg_out}<br>"
            f"<b>Inbound Connections:</b> {deg_in}"
        )

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers+text",
        text=[n if (n in attacker_ips or n in victim_ips) else "" for n in g.nodes()],
        textfont=dict(color="#FFFFFF", size=12, family="monospace"),
        textposition="top center",
        hoverinfo="text",
        hovertext=node_text,
        marker=dict(
            color=node_colors,
            size=node_sizes,
            line=dict(width=2.5, color="#0B0F19")
        )
    )

    fig = go.Figure(
        data=[edge_trace, node_trace],
        layout=go.Layout(
            title=dict(
                text="<b>Network Host Topology & Communication Matrix</b>",
                font=dict(color="#F8FAFC", size=16)
            ),
            showlegend=False,
            hovermode="closest",
            margin=dict(b=20, l=20, r=20, t=50),
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            paper_bgcolor="rgba(15, 23, 42, 0.95)",
            plot_bgcolor="rgba(15, 23, 42, 0.95)"
        )
    )
    return fig


def get_top_communicators(df: pd.DataFrame, top_n: int = 10) -> pd.DataFrame:
    """Return top communicating IP pairs ordered by transferred volume."""
    matrix = df.groupby(["src_ip", "dst_ip", "direction"]).agg(
        flow_count=("bytes", "count"),
        total_bytes=("bytes", "sum"),
        protocols=("protocol", lambda s: ", ".join(sorted(set(s))))
    ).reset_index()

    matrix = matrix.sort_values(by="total_bytes", ascending=False).head(top_n)
    
    # Format bytes nicely for presentation
    def fmt_bytes(b):
        if b >= 1_000_000:
            return f"{b / 1_000_000:.2f} MB ({b:,} B)"
        elif b >= 1_000:
            return f"{b / 1_000:.1f} KB ({b:,} B)"
        return f"{b:,} B"

    matrix["Formatted Volume"] = matrix["total_bytes"].apply(fmt_bytes)
    matrix = matrix[["src_ip", "dst_ip", "direction", "flow_count", "Formatted Volume", "protocols"]]
    matrix.columns = ["Source IP", "Destination IP", "Direction", "Flows", "Transferred Volume", "Protocols"]
    return matrix
