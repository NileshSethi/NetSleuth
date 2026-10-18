"""Explainable Incident Priority Scoring Engine.

Calculates transparent, deterministic risk priority scores (0 to 100)
for correlated incidents using documented linear weighted risk models.
"""

from typing import Tuple, Dict, Any, Optional

from netsleuth.correlation import Incident
from netsleuth.config import ScoringConfig


def calculate_incident_score(
    incident: Incident, config: Optional[ScoringConfig] = None
) -> Tuple[float, Dict[str, Any]]:
    """Compute an explainable, auditable priority score for a security incident.

    TODO (Phase 4 Implementation):
    1. Score Rule Severities: sum base weights of triggered alert rules.
    2. Score Target Breadth: calculate points based on count of distinct target IPs.
    3. Score Volumetric Impact: calculate points based on total bytes transferred.
    4. Normalize final score within [0.0, 100.0].
    5. Return both the final score and a complete explainable factor breakdown dictionary.

    Args:
        incident: Correlated Incident object.
        config: Optional ScoringConfig overrides.

    Returns:
        A tuple of (numeric_score, explanation_breakdown_dict).

    Raises:
        NotImplementedError: Raised in Phase 1 placeholder state.
    """
    raise NotImplementedError(
        "calculate_incident_score() is a Phase 1 interface placeholder. "
        "Scoring logic will be implemented in Phase 4."
    )
