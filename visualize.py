"""
visualize.py
============
PHASE 8 - Turns numbers into evidence you can screenshot for GitHub.

Generates 8 report-quality figures into /images:

  01_dataset_class_distribution.png  - how imbalanced the data is
  02_attack_type_distribution.png    - top attack types in the corpus
  03_feature_importance.png          - what the model actually learned
  04_confusion_matrix_rf.png         - per-family detection quality
  05_model_comparison.png            - 3 models x 5 metrics
  06_anomaly_score_distribution.png  - normal vs attack separation
  07_roc_curve.png                   - binary detector ROC
  08_live_detection_timeline.png     - simulated attack timeline (SOC view)
  09_engineered_features.png         - why our new features matter
  10_risk_score_histogram.png        - alert severity spread
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import roc_curve, auc

sys.path.append(str(Path(__file__).resolve().parent.parent))
from src.config import (  # noqa: E402
    ANOMALY_FILE, ATTACK_CLASSES, CLASSIFIER_FILE, IMAGES_DIR, METRICS_FILE,
    OUTPUTS_DIR,
)
from src.preprocess import prepare_training_data  # noqa: E402
from src.detect import ThreatDetector  # noqa: E402
from src.simulate import TrafficSimulator  # noqa: E402
from src.feature_engineering import ENGINEERED_FEATURES  # noqa: E402

sns.set_theme(style="darkgrid", palette="viridis")
plt.rcParams.update({"figure.dpi": 130, "savefig.bbox": "tight", "font.size": 10})

PALETTE = {"Normal": "#2ecc71", "DoS": "#e74c3c", "Probe": "#f39c12",
           "R2L": "#9b59b6", "U2R": "#e67e22", "Unknown-Anomaly": "#1abc9c"}


def _save(fig, name: str):
    path = IMAGES_DIR / name
    fig.savefig(path)
    plt.close(fig)
    print(f"[OK] {name}")


# ---------------------------------------------------------------- 01
def fig_class_distribution(df: pd.DataFrame):
    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    counts = df["attack_category"].value_counts().reindex(ATTACK_CLASSES)
    axes[0].bar(counts.index, counts.values,
                color=[PALETTE[c] for c in counts.index])
    axes[0].set_title("Attack family distribution (KDDTrain+)")
    axes[0].set_ylabel("Connections")
    for i, v in enumerate(counts.values):
        axes[0].text(i, v, f"{v:,}", ha="center", va="bottom", fontsize=9)
    axes[1].pie(counts.values, labels=counts.index, autopct="%1.2f%%",
                colors=[PALETTE[c] for c in counts.index], startangle=90)
    axes[1].set_title("Share of traffic (imbalance check)")
    _save(fig, "01_dataset_class_distribution.png")


# ---------------------------------------------------------------- 02
def fig_attack_types(df: pd.DataFrame):
    top = df.loc[df.is_attack == 1, "label"].value_counts().head(14)
    fig, ax = plt.subplots(figsize=(9, 5))
    sns.barplot(x=top.values, y=top.index, hue=top.index, ax=ax,
                palette="rocket", legend=False)
    ax.set_title("Top 14 raw attack types in the dataset")
    ax.set_xlabel("Number of connections")
    for i, v in enumerate(top.values):
        ax.text(v, i, f" {v:,}", va="center", fontsize=8)
    _save(fig, "02_attack_type_distribution.png")


# ---------------------------------------------------------------- 03
def fig_feature_importance(model, feature_names):
    imp = pd.Series(model.feature_importances_, index=feature_names)
    top = imp.sort_values(ascending=False).head(20)[::-1]
    fig, ax = plt.subplots(figsize=(9, 7))
    colors = ["#00b894" if any(f.startswith(e) for e in ENGINEERED_FEATURES)
              else "#0984e3" for f in top.index]
    ax.barh(top.index, top.values, color=colors)
    ax.set_title("Top 20 features learned by Random Forest\n"
                 "(green = features WE engineered in Phase 4)")
    ax.set_xlabel("Gini importance")
    _save(fig, "03_feature_importance.png")


# ---------------------------------------------------------------- 04
def fig_confusion_matrix(metrics):
    cm = np.array(metrics["holdout_random_split"]["random_forest"]["confusion_matrix_multiclass"])
    fig, ax = plt.subplots(figsize=(6.5, 5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", cbar=False,
                xticklabels=ATTACK_CLASSES, yticklabels=ATTACK_CLASSES, ax=ax)
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual")
    ax.set_title("Confusion matrix - Random Forest (hold-out split)")
    _save(fig, "04_confusion_matrix_rf.png")


# ---------------------------------------------------------------- 05
def fig_model_comparison(metrics):
    rows = []
    for r in metrics["holdout_random_split"].values():
        rows.append({"model": r["model"], "Accuracy": r["accuracy"],
                     "Precision": r["precision"], "Recall": r["recall"],
                     "F1": r["f1_score"]})
    r = metrics["hybrid_detector"]["hybrid_ml_or_anomaly"]
    rows.append({"model": "Hybrid (ML OR Anomaly)", "Accuracy": r["accuracy"],
                 "Precision": r["precision"], "Recall": r["recall"], "F1": r["f1_score"]})
    df = pd.DataFrame(rows).melt(id_vars="model", var_name="metric", value_name="score")
    fig, ax = plt.subplots(figsize=(10, 5))
    sns.barplot(data=df, x="metric", y="score", hue="model", ax=ax, palette="mako")
    ax.set_ylim(0, 1.05); ax.set_title("Model comparison - hold-out test split")
    ax.legend(bbox_to_anchor=(1.02, 1), loc="upper left", fontsize=8)
    for c in ax.containers:
        ax.bar_label(c, fmt="%.2f", fontsize=7, padding=1)
    _save(fig, "05_model_comparison.png")


# ---------------------------------------------------------------- 06
def fig_anomaly_scores(iso, X_test, y_test):
    scores = -iso.score_samples(X_test)
    truth = (y_test != "Normal").values
    fig, ax = plt.subplots(figsize=(9, 5))
    sns.kdeplot(x=scores[~truth], fill=True, label="Normal traffic",
                color="#2ecc71", ax=ax, alpha=.6)
    sns.kdeplot(x=scores[truth], fill=True, label="Malicious traffic",
                color="#e74c3c", ax=ax, alpha=.6)
    ax.axvline(np.percentile(scores, 85), ls="--", color="white",
               label="Decision threshold (contamination=15%)")
    ax.set_title("Isolation Forest anomaly score separation\n"
                 "further right = stranger behaviour")
    ax.set_xlabel("Anomaly score (-score_samples)")
    ax.legend()
    _save(fig, "06_anomaly_score_distribution.png")


# ---------------------------------------------------------------- 07
def fig_roc(model, X_test, y_test):
    y_true = (y_test != "Normal").astype(int).values
    proba = model.predict_proba(X_test)
    attack_idx = [i for i, c in enumerate(model.classes_) if c != "Normal"]
    score = proba[:, attack_idx].sum(axis=1)
    fpr, tpr, _ = roc_curve(y_true, score)
    fig, ax = plt.subplots(figsize=(6.5, 5.5))
    ax.plot(fpr, tpr, lw=2.5, color="#e17055", label=f"Random Forest (AUC = {auc(fpr, tpr):.4f})")
    ax.plot([0, 1], [0, 1], "w--", lw=1, label="Random guess")
    ax.fill_between(fpr, tpr, alpha=.15, color="#e17055")
    ax.set_xlabel("False Positive Rate"); ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC curve - binary attack detection")
    ax.legend(loc="lower right")
    _save(fig, "07_roc_curve.png")


# ---------------------------------------------------------------- 08
def fig_live_timeline(detector, sim_result, scored):
    gt = sim_result["ground_truth"].copy()
    gt["timestamp"] = pd.to_datetime(gt["timestamp"])
    scored["timestamp"] = pd.to_datetime(scored["timestamp"])
    gt["minute"] = gt["timestamp"].dt.floor("min")

    fig, axes = plt.subplots(2, 1, figsize=(11, 7), sharex=True)
    by_min = gt.groupby("minute").agg(total=("is_attack_truth", "size"),
                                      attacks=("is_attack_truth", "sum"))
    axes[0].plot(by_min.index, by_min["total"], color="#74b9ff", lw=2, label="All flows")
    axes[0].plot(by_min.index, by_min["attacks"], color="#e74c3c", lw=2, label="True attacks")
    axes[0].fill_between(by_min.index, by_min["attacks"], color="#e74c3c", alpha=.25)
    axes[0].set_title("Simulated SOC timeline - traffic volume vs real attacks")
    axes[0].legend(); axes[0].set_ylabel("Events / minute")

    for fam in ["DoS", "Probe", "R2L", "U2R"]:
        sel = gt[gt["attack_family_truth"] == fam]
        if len(sel):
            axes[1].scatter(sel["timestamp"], [fam] * len(sel), s=18,
                            color=PALETTE[fam], alpha=.8, label=fam)
    det = scored[scored["is_attack"] == 1]
    axes[1].scatter(det["timestamp"], ["Detected"] * len(det), s=14, marker="x",
                    color="white", alpha=.7, label="Model alerts")
    axes[1].set_title("Detected attack families vs model alerts")
    axes[1].set_yticks(["U2R", "R2L", "Probe", "DoS", "Detected"])
    axes[1].legend(fontsize=8); axes[1].set_ylabel("Family")
    fig.autofmt_xdate()
    _save(fig, "08_live_detection_timeline.png")


# ---------------------------------------------------------------- 09
def fig_engineered_features(df: pd.DataFrame):
    feats = ["total_bytes", "bytes_ratio", "dos_intensity", "host_scan_ratio",
             "login_anomaly", "privilege_score"]
    fig, axes = plt.subplots(2, 3, figsize=(13, 6.5))
    classes = ["Normal", "DoS", "Probe", "R2L", "U2R"]
    for ax, f in zip(axes.ravel(), feats):
        long = pd.DataFrame({
            "value": np.log1p(df[f].clip(lower=0)),
            "family": df["attack_category"],
        })
        long = long[long["family"].isin(classes)]
        sns.boxplot(data=long, x="family", y="value", order=classes, ax=ax,
                    palette=[PALETTE[c] for c in classes], showfliers=False,
                    hue="family", legend=False)
        ax.set_xticks(range(5)); ax.set_xticklabels(["Nor", "DoS", "Prb", "R2L", "U2R"])
        ax.set_xlabel(""); ax.set_title(f, fontsize=10)
    fig.suptitle("Engineered features separate attack families from normal traffic "
                 "(log-scaled)", fontsize=12)
    fig.tight_layout()
    _save(fig, "09_engineered_features.png")


# ---------------------------------------------------------------- 10
def fig_risk_scores(scored: pd.DataFrame):
    fig, axes = plt.subplots(1, 2, figsize=(11, 4))
    sns.histplot(data=scored, x="risk_score", hue="is_attack", bins=30,
                 palette={0: "#2ecc71", 1: "#e74c3c"}, ax=axes[0], multiple="stack")
    axes[0].set_title("Risk score distribution (0-100)")
    axes[0].legend(title="Attack", labels=["Malicious", "Benign"])
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev = scored["severity"].value_counts().reindex(order).fillna(0)
    colors = {"CRITICAL": "#c0392b", "HIGH": "#e74c3c", "MEDIUM": "#f39c12",
              "LOW": "#f1c40f", "INFO": "#2ecc71"}
    axes[1].bar(sev.index, sev.values, color=[colors[s] for s in sev.index])
    axes[1].set_title("Alerts by severity")
    axes[1].set_ylabel("Events")
    for i, v in enumerate(sev.values):
        axes[1].text(i, v, f"{int(v)}", ha="center", va="bottom", fontsize=9)
    _save(fig, "10_risk_score_histogram.png")


# ---------------------------------------------------------------- main
def generate_all():
    print("=" * 62)
    print("  PHASE 8 - VISUALISATION")
    print("=" * 62)
    X_train, X_test, y_train, y_test, feature_names, _, df_rich = prepare_training_data("train")
    rf = joblib.load(CLASSIFIER_FILE)
    iso = joblib.load(ANOMALY_FILE)
    metrics = json.loads(Path(METRICS_FILE).read_text())

    fig_class_distribution(df_rich)
    fig_attack_types(df_rich)
    fig_feature_importance(rf, feature_names)
    fig_confusion_matrix(metrics)
    fig_model_comparison(metrics)
    fig_anomaly_scores(iso, X_test, y_test)
    fig_roc(rf, X_test, y_test)
    fig_engineered_features(df_rich)

    # live simulation figures
    detector = ThreatDetector()
    sim = TrafficSimulator().simulate(n_events=1200, attack_rate=0.15)
    scored = detector.predict(sim["traffic"])
    fig_live_timeline(detector, sim, scored)
    fig_risk_scores(scored)
    scored.to_csv(OUTPUTS_DIR / "simulation_scored_events.csv", index=False)
    print(f"[OK] Scored simulation -> outputs/simulation_scored_events.csv")
    print(f"\n[DONE] 10 figures written to {IMAGES_DIR}")


if __name__ == "__main__":
    generate_all()
