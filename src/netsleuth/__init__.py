"""NetSleuth: Tactical Threat Intelligence & Forensic Analysis Platform."""

from .loader import load_flows
from .detectors import run_all_detectors
from .incidents import build_incidents, generate_forensic_dossier
from .graph import plot_graph, get_top_communicators
from .evaluation import evaluate_all_scenarios

__version__ = "1.0.0"

__all__ = [
    "load_flows",
    "run_all_detectors",
    "build_incidents",
    "generate_forensic_dossier",
    "plot_graph",
    "get_top_communicators",
    "evaluate_all_scenarios",
]
