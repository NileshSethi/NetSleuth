"""Detection Performance Evaluation and Benchmarking Module.

This module evaluates NetSleuth's detection efficacy against labeled ground-truth
synthetic datasets. It calculates Precision, Recall, F1 Score, and Confusion Matrix
while strictly isolating ground truth labels from the detection heuristics.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional, Union
import pandas as pd

from netsleuth.config import DetectionConfig
from netsleuth.detectors import Alert, run_all_detectors
from netsleuth.parser import load_and_validate_flow_csv


def calculate_metrics(tp: int, fp: int, fn: int, tn: int) -> Dict[str, float]:
    """Calculate standard information retrieval classification metrics.

    Args:
        tp: True Positives count.
        fp: False Positives count.
        fn: False Negatives count.
        tn: True Negatives count.

    Returns:
        Dictionary with precision, recall, f1_score, fpr, and accuracy.
    """
    total = tp + fp + fn + tn
    accuracy = (tp + tn) / total if total > 0 else 1.0

    # Precision = TP / (TP + FP)
    if tp + fp > 0:
        precision = tp / (tp + fp)
    else:
        precision = 1.0 if fn == 0 else 0.0

    # Recall = TP / (TP + FN)
    if tp + fn > 0:
        recall = tp / (tp + fn)
    else:
        recall = 1.0 if fp == 0 else 0.0

    # F1 Score = 2 * (P * R) / (P + R)
    if precision + recall > 0:
        f1 = 2 * (precision * recall) / (precision + recall)
    else:
        f1 = 0.0

    # False Positive Rate = FP / (FP + TN)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "accuracy": round(accuracy, 4),
    }


def evaluate_detection_performance(
    detected_alerts: List[Alert],
    ground_truth_df: pd.DataFrame,
    evaluation_level: str = "flow",
) -> Dict[str, Any]:
    """Calculate detection evaluation metrics against labeled benchmark flow data.

    Evaluates whether flows belonging to malicious activity windows were correctly
    identified by detection alerts without false alarm.

    Args:
        detected_alerts: List of Alert objects output by detectors.
        ground_truth_df: DataFrame containing flow records and 'is_attack' ground-truth.
        evaluation_level: 'flow' evaluation level.

    Returns:
        Dictionary of computed evaluation metrics, confusion matrix, and class breakdown.
    """
    if ground_truth_df is None or len(ground_truth_df) == 0:
        return {
            "status": "EMPTY_DATASET",
            "metrics": calculate_metrics(0, 0, 0, 0),
            "confusion_matrix": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
            "class_breakdown": {},
        }

    # Verify presence of ground-truth evaluation column
    if "is_attack" not in ground_truth_df.columns:
        return {
            "status": "UNLABELED_DATASET",
            "message": "Ground-truth 'is_attack' column not present in input dataset.",
            "metrics": {},
            "confusion_matrix": {},
            "class_breakdown": {},
        }

    # Collect unique flow IDs that contributed to any triggered detection alert
    flagged_flow_ids = set()
    for alert in detected_alerts:
        flagged_flow_ids.update(alert.contributing_flow_ids)

    # Ground truth vs Predicted
    actual_attack = ground_truth_df["is_attack"].astype(bool)
    predicted_attack = ground_truth_df["event_id"].isin(flagged_flow_ids)

    tp = int((actual_attack & predicted_attack).sum())
    fp = int((~actual_attack & predicted_attack).sum())
    fn = int((actual_attack & ~predicted_attack).sum())
    tn = int((~actual_attack & ~predicted_attack).sum())

    metrics = calculate_metrics(tp, fp, fn, tn)

    # Class breakdown per attack_type if available
    class_breakdown = {}
    if "attack_type" in ground_truth_df.columns:
        for attack_class, group in ground_truth_df.groupby("attack_type"):
            total_in_class = len(group)
            detected_in_class = int(group["event_id"].isin(flagged_flow_ids).sum())
            class_breakdown[str(attack_class)] = {
                "total_flows": total_in_class,
                "detected_flows": detected_in_class,
                "recall": round(detected_in_class / total_in_class, 4) if total_in_class > 0 else 1.0,
            }

    return {
        "status": "SUCCESS",
        "total_flows": len(ground_truth_df),
        "total_alerts": len(detected_alerts),
        "metrics": metrics,
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "class_breakdown": class_breakdown,
    }


def benchmark_scenario(
    scenario_csv_path: Union[str, Path],
    config: Optional[DetectionConfig] = None,
) -> Dict[str, Any]:
    """Execute end-to-end benchmark on a single labeled scenario file."""
    path_obj = Path(scenario_csv_path)
    if not path_obj.exists():
        raise FileNotFoundError(f"Scenario file not found: {scenario_csv_path}")

    # 1. Parse and sanitize flow data
    flow_df = load_and_validate_flow_csv(path_obj)

    # 2. Run detection heuristics blind to ground truth
    alerts = run_all_detectors(flow_df, config=config)

    # 3. Evaluate detection outputs against isolated ground truth
    eval_result = evaluate_detection_performance(alerts, flow_df)
    eval_result["scenario_file"] = path_obj.name
    eval_result["scenario_name"] = path_obj.stem.replace("scenario_", "").replace("_", " ").title()

    return eval_result


def benchmark_all_scenarios(
    data_dir: Union[str, Path] = "data/synthetic",
    config: Optional[DetectionConfig] = None,
) -> pd.DataFrame:
    """Benchmark all 5 canonical synthetic scenarios and compile comparison table.

    Args:
        data_dir: Path to directory containing synthetic scenarios.
        config: Optional detection configuration.

    Returns:
        Summary pandas DataFrame comparing Precision, Recall, F1 across all scenarios.
    """
    dir_path = Path(data_dir)
    scenario_files = [
        "scenario_01_benign.csv",
        "scenario_02_port_scan.csv",
        "scenario_03_host_scan.csv",
        "scenario_04_exfiltration.csv",
        "scenario_05_blended_attack.csv",
    ]

    records = []
    for filename in scenario_files:
        file_path = dir_path / filename
        if file_path.exists():
            res = benchmark_scenario(file_path, config=config)
            m = res.get("metrics", {})
            cm = res.get("confusion_matrix", {})
            records.append({
                "Scenario": res.get("scenario_name", filename),
                "Total Flows": res.get("total_flows", 0),
                "Alerts": res.get("total_alerts", 0),
                "True Pos (TP)": cm.get("tp", 0),
                "False Pos (FP)": cm.get("fp", 0),
                "False Neg (FN)": cm.get("fn", 0),
                "Precision": f"{m.get('precision', 0.0) * 100:.1f}%",
                "Recall": f"{m.get('recall', 0.0) * 100:.1f}%",
                "F1 Score": f"{m.get('f1_score', 0.0) * 100:.1f}%",
            })

    return pd.DataFrame(records)
