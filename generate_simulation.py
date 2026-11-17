"""
generate_simulation.py
=====================
PHASE 8/9 - Run the full virtual cyber-range exercise end-to-end:

    1. generate a mixed traffic capture (benign + 9 attack scenarios)
    2. score every flow with the ThreatDetector (ML + anomaly + rules)
    3. build SOC alerts with severity / MITRE technique / response action
    4. compute LIVE detection metrics against the ground truth
    5. save outputs/simulated_traffic.csv, outputs/alerts.csv, outputs/live_metrics.json

Run it:  python src/generate_simulation.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, f1_score, precision_score,
                             recall_score)

sys.path.append(str(Path(__file__).resolve().parent.parent))
from src.config import ATTACK_CLASSES, OUTPUTS_DIR  # noqa: E402
from src.detect import ThreatDetector  # noqa: E402
from src.simulate import TrafficSimulator, SCENARIOS  # noqa: E402


def main(n_events: int = 2000, attack_rate: float = 0.15, seed: int = 42):
    print("=" * 62)
    print("  VIRTUAL CYBER RANGE EXERCISE")
    print("=" * 62)

    # 1) generate ---------------------------------------------------------
    sim = TrafficSimulator(seed=seed)
    burst = sim.simulate(n_events=n_events, attack_rate=attack_rate, seed=seed)
    traffic, truth = burst["traffic"], burst["ground_truth"]

    # 2) detect -----------------------------------------------------------
    detector = ThreatDetector()
    scored = detector.predict(traffic)

    # 3) alerts -----------------------------------------------------------
    alerts = ThreatDetector.build_alerts(scored, src_ips=traffic["src_ip"],
                                         dst_ips=traffic["dst_ip"],
                                         services=traffic["service"])

    # 4) live metrics -----------------------------------------------------
    y_true = traffic["is_attack_truth"].values
    y_pred = scored["is_attack"].values
    live = {
        "events_scored": int(len(traffic)),
        "true_attacks": int(y_true.sum()),
        "true_benign": int((y_true == 0).sum()),
        "alerts_raised": int(y_pred.sum()),
        "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
        "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
        "detection_rate_by_scenario": {},
        "severity_breakdown": alerts["severity"].value_counts().to_dict()
                              if len(alerts) else {},
        "top_talkers": (alerts.groupby("src_ip").size().sort_values(ascending=False)
                        .head(5).to_dict() if len(alerts) else {}),
    }

    scored["scenario"] = traffic["scenario"].values
    scored["is_attack_truth"] = y_true
    for name, grp in scored[scored.is_attack_truth == 1].groupby("scenario"):
        live["detection_rate_by_scenario"][name] = {
            "events": int(len(grp)),
            "detected": int(grp["is_attack"].sum()),
            "rate_pct": round(100 * float(grp["is_attack"].mean()), 1),
        }
    # family-level report
    live["family_report"] = classification_report(
        [ATTACK_CLASSES.index(c) if c in ATTACK_CLASSES else 0 for c in
         scored["threat_class"].replace({"Unknown-Anomaly": "Normal"})],
        [ATTACK_CLASSES.index(c) if c in ATTACK_CLASSES else 0 for c in
         scored["threat_class"]],
        output_dict=True, zero_division=0) if False else None

    # 5) persist ----------------------------------------------------------
    traffic.to_csv(OUTPUTS_DIR / "simulated_traffic.csv", index=False)
    truth.to_csv(OUTPUTS_DIR / "simulated_ground_truth.csv", index=False)
    scored.to_csv(OUTPUTS_DIR / "simulation_scored_events.csv", index=False)
    alerts.to_csv(OUTPUTS_DIR / "alerts.csv", index=False)
    with open(OUTPUTS_DIR / "live_metrics.json", "w") as f:
        json.dump(live, f, indent=2)

    # 6) console report ---------------------------------------------------
    print(f"\nEvents scored        : {live['events_scored']:,}")
    print(f"Real attacks         : {live['true_attacks']:,}")
    print(f"Alerts raised        : {live['alerts_raised']:,}")
    print(f"Precision / Recall   : {live['precision']} / {live['recall']}")
    print(f"F1 / Accuracy        : {live['f1_score']} / {live['accuracy']}")
    print("\nDetection rate by attack scenario")
    print("-" * 62)
    for k, v in sorted(live["detection_rate_by_scenario"].items(),
                       key=lambda x: -x[1]["events"]):
        print(f"  {k:<40} {v['detected']:>4}/{v['events']:<4} {v['rate_pct']:>5}%")
    print("\nSeverity breakdown:", live["severity_breakdown"])
    print("\nTop alerting source IPs:")
    for ip, c in live["top_talkers"].items():
        print(f"  {ip:<18} {c} alerts")
    print(f"\n[OK] outputs/simulated_traffic.csv  (raw capture)")
    print(f"[OK] outputs/alerts.csv             ({len(alerts)} SOC alerts)")
    print(f"[OK] outputs/live_metrics.json      (live performance)")
    return live


if __name__ == "__main__":
    main()
