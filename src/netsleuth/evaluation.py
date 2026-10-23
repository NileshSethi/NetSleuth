"""Evaluates detection accuracy against ground-truth labels using flow-level metrics."""

import pandas as pd
from .detectors import run_all_detectors


def evaluate_single_scenario(df: pd.DataFrame, scenario_name: str) -> dict:
    """Compare alert flow indices against ground-truth labels for one scenario."""
    if "label" not in df.columns:
        raise ValueError(f"Ground-truth 'label' column missing in {scenario_name}")

    # A flow is detected if its row index appears in any alert
    alerts = run_all_detectors(df)
    detected_indices = set()
    for alert in alerts:
        detected_indices.update(alert.get("flow_indices", []))

    # True condition: anything not labeled 'normal' is an attack
    is_actual_attack = df["label"].astype(str).str.lower() != "normal"
    is_predicted_attack = df.index.isin(detected_indices)

    tp = int((is_predicted_attack & is_actual_attack).sum())
    fp = int((is_predicted_attack & (~is_actual_attack)).sum())
    fn = int(((~is_predicted_attack) & is_actual_attack).sum())

    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 1.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 1.0
    f1 = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) > 0 else 0.0

    return {
        "scenario": scenario_name,
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1
    }


def evaluate_all_scenarios(scenarios: dict[str, pd.DataFrame]) -> pd.DataFrame:
    """Run detection and evaluation across multiple scenarios and return a summary table."""
    records = []
    for name, df in scenarios.items():
        records.append(evaluate_single_scenario(df, name))
    return pd.DataFrame(records)
