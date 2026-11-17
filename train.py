"""
train.py
========
Trains the three-model "defence in depth" stack used by this project:

  MODEL 1  Logistic Regression  -> fast, explainable BASELINE
  MODEL 2  Random Forest        -> supervised MULTI-CLASS threat classifier
                                   (Normal / DoS / Probe / R2L / U2R)
  MODEL 3  Isolation Forest     -> UNSUPERVISED anomaly detector.
                                   Trained ONLY on normal traffic, so it can
                                   flag attacks the classifier has NEVER seen
                                   (this is the closest a student can get to
                                   "zero-day detection" without real data).

WHY THREE MODELS?
-----------------
Real SOC stacks are layered:
   rules -> baseline ML -> advanced ML -> anomaly detection -> human analyst.
A supervised model only knows the attacks in its training data. An anomaly
model knows what NORMAL looks like, so it screams when something is different.
Our SOC logic raises an alert when EITHER model is unhappy (OR-voting), which
maximises recall - the single most important metric in security
(a missed attack costs far more than a false alarm).
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression

sys.path.append(str(Path(__file__).resolve().parent.parent))
from src.config import (  # noqa: E402
    ANOMALY_FILE, ANOMALY_THRESHOLD_PERCENTILE, BASELINE_FILE, CLASSIFIER_FILE,
    IF_PARAMS, LR_PARAMS, METADATA_FILE, MODEL_VERSION, RF_PARAMS,
)
from src.preprocess import prepare_training_data  # noqa: E402


# ---------------------------------------------------------------------------
# 1. SUPERVISED CLASSIFIER (multi-class threat family)
# ---------------------------------------------------------------------------
def train_classifier(X_train, y_train, kind: str = "rf"):
    """Train Random Forest ('rf') or Logistic Regression ('lr')."""
    if kind == "rf":
        model = RandomForestClassifier(**RF_PARAMS)
    else:
        model = LogisticRegression(**LR_PARAMS)

    t0 = time.time()
    model.fit(X_train, y_train)
    print(f"[OK] {kind.upper()} trained on {X_train.shape[0]:,} samples "
          f"in {time.time() - t0:.1f}s")
    return model


# ---------------------------------------------------------------------------
# 2. UNSUPERVISED ANOMALY DETECTOR (Isolation Forest)
# ---------------------------------------------------------------------------
def train_anomaly_detector(X_train, y_train):
    """Fit IsolationForest on NORMAL traffic only.

    Idea: isolation trees split the space randomly; anomalies need fewer
    splits to be isolated -> shorter average path length -> negative score.
    """
    normal_mask = (y_train == "Normal").values
    X_normal = X_train[normal_mask]

    model = IsolationForest(**IF_PARAMS)
    t0 = time.time()
    model.fit(X_normal)
    # --- calibrate the alerting threshold on NORMAL traffic only ---------
    # A raw IsolationForest flags ~contamination% of EVERYTHING. For live
    # alerting we need a stricter bar, or the SOC drowns in false alarms.
    scores = -model.score_samples(X_normal)
    threshold = float(np.percentile(scores, ANOMALY_THRESHOLD_PERCENTILE))
    print(f"[OK] IsolationForest trained on {X_normal.shape[0]:,} NORMAL flows "
          f"in {time.time() - t0:.1f}s")
    print(f"[OK] Live alert threshold = {threshold:.4f} "
          f"(p{ANOMALY_THRESHOLD_PERCENTILE} of normal scores)")
    model.alert_threshold_ = threshold
    return model


# ---------------------------------------------------------------------------
# 3. FULL TRAINING PIPELINE
# ---------------------------------------------------------------------------
def train_all() -> dict:
    """Prepare data, train all three models, save artefacts + metadata."""
    print("=" * 62)
    print("  PHASE 5 - MODEL TRAINING")
    print("=" * 62)

    X_train, X_test, y_train, y_test, feature_names, _, _ = prepare_training_data("train")

    # --- sanity checks BEFORE wasting 10 minutes on training -------------
    assert len(X_train) == len(y_train), "X/y length mismatch - split bug!"
    assert X_train.shape[1] == len(feature_names), "feature name mismatch!"
    print(f"[CHECK] X_train {X_train.shape}  X_test {X_test.shape}")
    print(f"[CHECK] classes: {dict(y_train.value_counts())}")

    rf = train_classifier(X_train, y_train, "rf")
    lr = train_classifier(X_train, y_train, "lr")
    iso = train_anomaly_detector(X_train, y_train)

    # --- persist everything the inference layer needs --------------------
    joblib.dump(rf, CLASSIFIER_FILE)
    joblib.dump(lr, BASELINE_FILE)
    joblib.dump(iso, ANOMALY_FILE)

    metadata = {
        "model_version": MODEL_VERSION,
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "algorithm": "RandomForestClassifier",
        "anomaly_algorithm": "IsolationForest",
        "classes": list(rf.classes_),
        "n_features_encoded": int(X_train.shape[1]),
        "n_train_samples": int(X_train.shape[0]),
        "n_test_samples": int(X_test.shape[0]),
        "hyperparameters": {"random_forest": RF_PARAMS, "isolation_forest": IF_PARAMS},
        "anomaly_threshold": float(getattr(iso, "alert_threshold_", 0.0)),
        "anomaly_threshold_percentile": ANOMALY_THRESHOLD_PERCENTILE,
    }
    with open(METADATA_FILE, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"[OK] Saved -> {CLASSIFIER_FILE.name}, {BASELINE_FILE.name}, {ANOMALY_FILE.name}")
    print(f"[OK] Metadata -> {METADATA_FILE}")
    return metadata


if __name__ == "__main__":
    train_all()
