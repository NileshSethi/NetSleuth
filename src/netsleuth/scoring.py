"""Explainable Incident Priority Scoring Engine.

Calculates transparent, deterministic risk priority scores (0 to 100)
for correlated incidents using documented linear weighted risk models.
"""

from typing import Tuple, Dict, Any, Optional, List

from netsleuth.correlation import Incident
from netsleuth.config import ScoringConfig


def calculate_incident_score(
    incident: Incident, config: Optional[ScoringConfig] = None
) -> Tuple[float, Dict[str, Any]]:
    """Compute an explainable, auditable priority score (0-100) for a security incident.

    The scoring model evaluates three transparent dimensions:
    1. Alert Rule Severity & Diversity (0 to 40 points):
       Evaluates base threat severity for triggered rules plus a multi-stage diversity bonus.
    2. Target Breadth & Blast Radius (0 to 30 points):
       Measures the number of internal and external target assets involved.
    3. Volumetric & Impact Intensity (0 to 30 points):
       Measures data volume transferred and flow density.

    Args:
        incident: Correlated Incident object.
        config: Optional ScoringConfig overrides.

    Returns:
        A tuple of (numeric_score, explanation_breakdown_dict).
    """
    if not incident.alerts:
        return (0.0, {"final_score": 0.0, "severity_label": "LOW", "factors": {}})

    cfg = config or ScoringConfig()
    rule_weights = cfg.rule_weights

    # --------------------------------------------------------------------------
    # Factor 1: Rule Severity & Kill-Chain Diversity (Max: 40 points)
    # --------------------------------------------------------------------------
    distinct_rules = {a.rule_id for a in incident.alerts}
    rule_points = 0.0
    for rule_id in distinct_rules:
        rule_points += rule_weights.get(rule_id, 15)

    # High severity boost
    high_sev_count = sum(1 for a in incident.alerts if a.severity in ("HIGH", "CRITICAL"))
    rule_points += high_sev_count * 5.0

    # Multi-stage kill-chain bonus (e.g. reconnaissance + lateral + exfiltration)
    diversity_bonus = 0.0
    if len(distinct_rules) >= 3:
        diversity_bonus = 15.0
    elif len(distinct_rules) == 2:
        diversity_bonus = 10.0

    factor1_raw = rule_points + diversity_bonus
    factor1_points = min(40.0, factor1_raw)
    factor1_explanation = (
        f"Triggered {len(distinct_rules)} distinct threat rule(s) "
        f"({', '.join(distinct_rules)}) with {high_sev_count} high-severity alert(s) "
        f"and +{diversity_bonus:.0f} kill-chain progression bonus."
    )

    # --------------------------------------------------------------------------
    # Factor 2: Target Breadth & Blast Radius (Max: 30 points)
    # --------------------------------------------------------------------------
    target_count = max(0, len(incident.associated_ips) - 1)
    if target_count >= 10:
        factor2_points = 30.0
    elif target_count >= 5:
        factor2_points = 25.0
    elif target_count >= 2:
        factor2_points = 18.0
    elif target_count == 1:
        factor2_points = 10.0
    else:
        factor2_points = 0.0

    factor2_explanation = (
        f"Attack trajectory involves {target_count} unique target asset(s) in its blast radius."
    )

    # --------------------------------------------------------------------------
    # Factor 3: Volumetric & Impact Intensity (Max: 30 points)
    # --------------------------------------------------------------------------
    total_bytes = 0
    for a in incident.alerts:
        if a.rule_id == "RULE-EXFIL-SPIKE":
            total_bytes += int(a.evidence.get("total_bytes", 0))

    flow_count = len(incident.contributing_flow_ids)
    bytes_mb = round(total_bytes / (1024 * 1024), 2)

    if total_bytes >= 52_428_800:  # >= 50 MB
        factor3_points = 30.0
    elif total_bytes >= 10_485_760:  # >= 10 MB
        factor3_points = 20.0
    elif total_bytes > 0:
        factor3_points = 10.0
    elif flow_count >= 30:
        factor3_points = 12.0
    elif flow_count >= 10:
        factor3_points = 6.0
    else:
        factor3_points = 2.0

    factor3_explanation = (
        f"Exfiltrated volume: {bytes_mb} MB across {flow_count} contributing flow records."
    )

    # --------------------------------------------------------------------------
    # Final Score & Label
    # --------------------------------------------------------------------------
    final_score = round(min(100.0, factor1_points + factor2_points + factor3_points), 1)

    if final_score >= 80.0:
        severity_label = "CRITICAL"
    elif final_score >= 60.0:
        severity_label = "HIGH"
    elif final_score >= 35.0:
        severity_label = "MEDIUM"
    else:
        severity_label = "LOW"

    breakdown = {
        "final_score": final_score,
        "severity_label": severity_label,
        "factors": {
            "rule_severity_and_diversity": {
                "points": round(factor1_points, 1),
                "max_points": 40,
                "explanation": factor1_explanation,
            },
            "target_breadth": {
                "points": round(factor2_points, 1),
                "max_points": 30,
                "explanation": factor2_explanation,
            },
            "volumetric_impact": {
                "points": round(factor3_points, 1),
                "max_points": 30,
                "explanation": factor3_explanation,
            },
        },
        "formula": "Score = min(100.0, RulePoints + TargetPoints + VolumePoints)",
    }

    return (final_score, breakdown)


def score_incident(
    incident: Incident, config: Optional[ScoringConfig] = None
) -> Incident:
    """Calculate score and attach it directly to the Incident object."""
    score, breakdown = calculate_incident_score(incident, config)
    incident.risk_score = score
    incident.score_breakdown = breakdown
    return incident


def score_all_incidents(
    incidents: List[Incident], config: Optional[ScoringConfig] = None
) -> List[Incident]:
    """Score all incidents in a list and sort by risk_score descending."""
    scored = [score_incident(inc, config) for inc in incidents]
    scored.sort(key=lambda inc: inc.risk_score, reverse=True)
    return scored
