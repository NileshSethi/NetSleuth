"""Unit tests for NetSleuth Detection Performance Evaluation and Benchmarking Module.
"""

from pathlib import Path
import pandas as pd
import pytest

from netsleuth.detectors import Alert
from netsleuth.evaluation import (
    calculate_metrics,
    evaluate_detection_performance,
    benchmark_scenario,
    benchmark_all_scenarios,
)


def test_calculate_metrics_perfect():
    """Verify metrics calculation on perfect detection outcome."""
    m = calculate_metrics(tp=100, fp=0, fn=0, tn=900)
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0
    assert m["f1_score"] == 1.0
    assert m["false_positive_rate"] == 0.0
    assert m["accuracy"] == 1.0


def test_calculate_metrics_with_fp_and_fn():
    """Verify precision, recall, and F1 calculations with mixed false alarms and misses."""
    # TP=80, FP=20 -> Precision = 80 / 100 = 0.80
    # TP=80, FN=20 -> Recall = 80 / 100 = 0.80
    # F1 = 0.80
    m = calculate_metrics(tp=80, fp=20, fn=20, tn=880)
    assert m["precision"] == 0.80
    assert m["recall"] == 0.80
    assert m["f1_score"] == 0.80
    assert m["false_positive_rate"] == round(20 / 900, 4)


def test_calculate_metrics_zero_denominators():
    """Verify zero division is safely handled."""
    m = calculate_metrics(tp=0, fp=0, fn=0, tn=1000)
    assert m["precision"] == 1.0
    assert m["recall"] == 1.0
    assert m["f1_score"] == 1.0
    assert m["false_positive_rate"] == 0.0


def test_evaluate_detection_unlabeled_dataset():
    """Verify evaluation handles unlabeled datasets gracefully."""
    df_unlabeled = pd.DataFrame([
        {"event_id": "flw-01", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}
    ])
    res = evaluate_detection_performance([], df_unlabeled)
    assert res["status"] == "UNLABELED_DATASET"


def test_benchmark_scenario_01_benign():
    """Verify benchmark evaluation on Scenario 1 baseline (zero false positives)."""
    scenario_path = Path("data/synthetic/scenario_01_benign.csv")
    assert scenario_path.exists()

    res = benchmark_scenario(scenario_path)
    assert res["status"] == "SUCCESS"
    assert res["total_alerts"] == 0
    assert res["confusion_matrix"]["fp"] == 0  # Zero False Positives!
    assert res["metrics"]["false_positive_rate"] == 0.0
    assert res["metrics"]["precision"] == 1.0


def test_benchmark_scenario_02_port_scan():
    """Verify benchmark evaluation on Scenario 2 (high recall and precision on port scan)."""
    scenario_path = Path("data/synthetic/scenario_02_port_scan.csv")
    assert scenario_path.exists()

    res = benchmark_scenario(scenario_path)
    assert res["status"] == "SUCCESS"
    assert res["total_alerts"] >= 1
    assert res["confusion_matrix"]["tp"] > 0
    assert res["metrics"]["recall"] >= 0.80
    assert res["metrics"]["precision"] >= 0.80
    assert "port_scan" in res["class_breakdown"]


def test_benchmark_scenario_05_blended():
    """Verify benchmark evaluation on Scenario 5 multi-stage blended attack."""
    scenario_path = Path("data/synthetic/scenario_05_blended_attack.csv")
    assert scenario_path.exists()

    res = benchmark_scenario(scenario_path)
    assert res["status"] == "SUCCESS"
    assert res["total_alerts"] >= 3
    assert res["confusion_matrix"]["tp"] > 0
    assert res["metrics"]["f1_score"] >= 0.70


def test_benchmark_all_scenarios():
    """Verify batch benchmarking across all 5 synthetic scenarios."""
    summary_df = benchmark_all_scenarios("data/synthetic")
    assert isinstance(summary_df, pd.DataFrame)
    assert len(summary_df) == 5
    for col in ["Scenario", "Total Flows", "Alerts", "Precision", "Recall", "F1 Score"]:
        assert col in summary_df.columns
