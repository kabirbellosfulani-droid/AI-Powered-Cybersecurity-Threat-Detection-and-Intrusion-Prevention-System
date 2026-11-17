"""
evaluate.py
===========
PHASE 6 - honest, security-aware model evaluation.

Metrics used and WHY (this is what interviewers ask):

  Accuracy  : overall correctness - misleading on imbalanced security data.
  Precision : of everything we flagged, how much was really an attack?
              Low precision = alert fatigue for the SOC team.
  Recall    : of all real attacks, how many did we catch?
              Low recall = a breach got through.  <-- THE metric that matters
  F1-Score  : harmonic mean of the two; used to rank our models.
  ROC-AUC   : threshold-independent ranking quality (one-vs-rest here).
  FPR       : false-positive rate - how many normal flows we annoyed the
              analyst about (SOC teams target < 1%).

We evaluate the NSL-KDD official TEST split too, because KDDTest+ contains
17 attack types that are NOT in KDDTrain+ - a genuine generalisation test.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)

sys.path.append(str(Path(__file__).resolve().parent.parent))
from src.config import (  # noqa: E402
    ANOMALY_FILE, ATTACK_CLASSES, BASELINE_FILE, CLASSIFIER_FILE, METRICS_FILE,
    OUTPUTS_DIR,
)
from src.preprocess import prepare_training_data, transform_new  # noqa: E402
from src.data_loader import load_nsl_kdd  # noqa: E402


def _binary_metrics(y_true_bin, y_pred_bin, y_score=None) -> dict:
    """Precision / recall / F1 / FPR / AUC for the binary 'is_attack' framing."""
    tn, fp, fn, tp = confusion_matrix(y_true_bin, y_pred_bin, labels=[0, 1]).ravel()
    out = {
        "accuracy":  round(float(accuracy_score(y_true_bin, y_pred_bin)), 4),
        "precision": round(float(precision_score(y_true_bin, y_pred_bin, zero_division=0)), 4),
        "recall":    round(float(recall_score(y_true_bin, y_pred_bin, zero_division=0)), 4),
        "f1_score":  round(float(f1_score(y_true_bin, y_pred_bin, zero_division=0)), 4),
        "false_positive_rate": round(float(fp / (fp + tn)) if (fp + tn) else 0.0, 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "true_positives": int(tp), "false_positives": int(fp),
        "false_negatives": int(fn), "true_negatives": int(tn),
    }
    if y_score is not None:
        try:
            out["roc_auc"] = round(float(roc_auc_score(y_true_bin, y_score)), 4)
        except ValueError:
            out["roc_auc"] = None
    return out


def evaluate_classifier(model, X_test, y_test, name: str) -> dict:
    """Full multi-class + binary report for a supervised model."""
    y_pred = model.predict(X_test)
    proba = model.predict_proba(X_test)
    classes = list(model.classes_)
    attack_idx = [i for i, c in enumerate(classes) if c != "Normal"]

    y_true_bin = (y_test != "Normal").astype(int).values
    y_pred_bin = (y_pred != "Normal").astype(int)
    attack_prob = proba[:, attack_idx].sum(axis=1)   # P(any attack class)

    report = _binary_metrics(y_true_bin, y_pred_bin, attack_prob)
    report["model"] = name
    report["multiclass_accuracy"] = round(float(accuracy_score(y_test, y_pred)), 4)
    report["macro_f1"] = round(float(f1_score(y_test, y_pred, average="macro", zero_division=0)), 4)
    report["confusion_matrix_multiclass"] = confusion_matrix(
        y_test, y_pred, labels=ATTACK_CLASSES).tolist()
    report["labels"] = ATTACK_CLASSES
    # per-class precision/recall/f1/support (used by the dashboard table)
    report["per_class"] = classification_report(
        y_test, y_pred, labels=ATTACK_CLASSES, output_dict=True, zero_division=0)
    return report


def evaluate_anomaly_detector(model, X_test, y_test, name: str = "IsolationForest") -> dict:
    """Binary report for the unsupervised detector (anomaly = attack)."""
    score_all = -model.score_samples(X_test)
    thr = getattr(model, "alert_threshold_", None)
    if thr is None:
        thr = float(np.percentile(score_all, 99))
    y_pred_bin = (score_all > thr).astype(int)
    y_true_bin = (y_test != "Normal").astype(int).values
    score = -model.score_samples(X_test)     # higher = more anomalous

    report = _binary_metrics(y_true_bin, y_pred_bin, score)
    report["model"] = name
    report["note"] = "Unsupervised - trained only on normal traffic."
    report["anomaly_score_stats"] = {
        "mean_normal": round(float(score[y_true_bin == 0].mean()), 4),
        "mean_attack": round(float(score[y_true_bin == 1].mean()), 4),
    }
    return report


def run_full_evaluation() -> dict:
    """Evaluate every saved model on (a) held-out split and (b) KDDTest+."""
    print("=" * 62)
    print("  PHASE 6 - MODEL EVALUATION")
    print("=" * 62)

    X_train, X_test, y_train, y_test, _, preprocessor, _ = prepare_training_data("train")
    rf = joblib.load(CLASSIFIER_FILE)
    lr = joblib.load(BASELINE_FILE)
    iso = joblib.load(ANOMALY_FILE)

    results = {
        "holdout_random_split": {
            "random_forest": evaluate_classifier(rf, X_test, y_test, "RandomForest"),
            "logistic_regression": evaluate_classifier(lr, X_test, y_test, "LogisticRegression"),
            "isolation_forest": evaluate_anomaly_detector(iso, X_test, y_test),
        }
    }

    # ---- official NSL-KDD test split (contains UNSEEN attack types) -------
    print("\n[INFO] Evaluating on official KDDTest+ (17 unseen attack types)...")
    df_test = load_nsl_kdd("test")
    X_official = transform_new(df_test, preprocessor)
    y_official = df_test["attack_category"]
    results["official_kddtest_split"] = {
        "random_forest": evaluate_classifier(rf, X_official, y_official, "RandomForest"),
        "isolation_forest": evaluate_anomaly_detector(iso, X_official, y_official),
    }

    # ---- combined (supervised OR anomaly) SOC decision -------------------
    y_pred_rf = rf.predict(X_test)
    y_pred_iso = np.where(iso.predict(X_test) == -1, "Unknown-Anomaly", "Normal")
    y_hybrid = np.where((y_pred_rf != "Normal") | (y_pred_iso != "Normal"),
                        y_pred_rf, "Normal")
    y_true_bin = (y_test != "Normal").astype(int).values
    hybrid = _binary_metrics(y_true_bin, (y_hybrid != "Normal").astype(int),
                             rf.predict_proba(X_test)[:, [i for i, c in enumerate(rf.classes_) if c != "Normal"]].sum(axis=1))
    hybrid["model"] = "Hybrid (RandomForest OR IsolationForest)"
    hybrid["note"] = "OR-voting maximises recall - the SOC priority."
    results["hybrid_detector"] = {"hybrid_ml_or_anomaly": hybrid}

    with open(METRICS_FILE, "w") as f:
        json.dump(results, f, indent=2)

    # ---- pretty console report -------------------------------------------
    for scope, block in results.items():
        print("\n" + "-" * 62)
        print(f"  {scope.replace('_', ' ').upper()}")
        print("-" * 62)
        for key, r in block.items():
            print(f"  {r['model']:<38} acc={r['accuracy']:.3f} "
                  f"P={r['precision']:.3f} R={r['recall']:.3f} "
                  f"F1={r['f1_score']:.3f} FPR={r['false_positive_rate']:.3f} "
                  f"AUC={r.get('roc_auc') or 0:.3f}")

    # ---- save a flat comparison CSV for the README table ------------------
    rows = []
    for scope, block in results.items():
        for key, r in block.items():
            rows.append({"evaluation_scope": scope, "model": r["model"],
                         "accuracy": r["accuracy"], "precision": r["precision"],
                         "recall": r["recall"], "f1_score": r["f1_score"],
                         "false_positive_rate": r["false_positive_rate"],
                         "roc_auc": r.get("roc_auc")})
    pd.DataFrame(rows).to_csv(OUTPUTS_DIR / "model_comparison.csv", index=False)
    print(f"\n[OK] Metrics  -> {METRICS_FILE}")
    print(f"[OK] Comparison table -> outputs/model_comparison.csv")
    return results


if __name__ == "__main__":
    run_full_evaluation()
