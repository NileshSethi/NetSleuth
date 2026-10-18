"""Forensic Reporting and Export Module.

Generates structured Markdown and plain-text summary reports for security incidents,
timelines, and evaluation outcomes suitable for analyst review and academic presentation.
"""

from typing import Optional
from pathlib import Path

from netsleuth.correlation import Incident


def generate_incident_markdown_report(
    incident: Incident, output_path: Optional[Path] = None
) -> str:
    """Generate a clean, structured Markdown report detailing a security incident.

    TODO (Phase 5/7 Implementation):
    1. Render executive summary (incident ID, attacker IP, timeline boundaries, risk score).
    2. Format alert table with rule IDs, severities, and timestamps.
    3. Include chronological narrative of key actions.
    4. Provide recommended defensive follow-up actions.
    5. Optionally write to `output_path` (e.g., in `reports/generated/`).

    Args:
        incident: Correlated Incident object.
        output_path: Optional file path to save report.

    Returns:
        Rendered Markdown text string.

    Raises:
        NotImplementedError: Raised in Phase 1 placeholder state.
    """
    raise NotImplementedError(
        "generate_incident_markdown_report() is a Phase 1 interface placeholder. "
        "Reporting logic will be implemented in Phase 5."
    )
