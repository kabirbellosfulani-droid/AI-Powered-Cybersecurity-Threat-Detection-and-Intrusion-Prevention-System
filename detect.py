"""
detect.py
=========
THE INFERENCE ENGINE - the "brain" of the SOC.

`ThreatDetector` wraps the trained models and turns raw network traffic into
an actionable ALERT, exactly the way a commercial IDS/NDR product does.

Decision logic (three layers -> OR voting):

  LAYER 1  ML classifier  : RandomForest predicts Normal/DoS/Probe/R2L/U2R
                            + probability (confidence).
  LAYER 2  Anomaly detector: IsolationForest flags flows that look nothing
                            like the normal baseline (unknown attacks).
  LAYER 3  Signature rules : transparent thresholds on raw fields
                            (e.g. num_failed_logins >= 5) that mirror real
                            Suricata/Snort rules. This gives the analyst a
                            human-readable reason for every alert.

Output per flow: category, is_attack, confidence, anomaly_score, risk_score
(0-100), severity (INFO/MEDIUM/HIGH/CRITICAL), MITRE technique, reason,
response playbook.
"""

from __future__ import annotations

import sys
import time
import uuid
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

sys.path.append(str(Path(__file__).resolve().parent.parent))
from src.config import (  # noqa: E402
    ANOMALY_FILE, CLASSIFIER_FILE, METADATA_FILE, METRICS_FILE, MITRE_MAP,
    RESPONSE_PLAYBOOK, SEVERITY_MAP,
)
from src.preprocess import transform_new  # noqa: E402


# ---------------------------------------------------------------------------
# LAYER 3 : transparent signature rules (mirror of real IDS rules)
# ---------------------------------------------------------------------------
def signature_rules(row: pd.Series) -> list[tuple[str, int]]:
    """Return [(human-readable reason, strength)] for a flow.

    strength 2 = strong / high-confidence indicator (one alone justifies an alert)
    strength 1 = supporting indicator (two or more are needed)

    Strengths are deliberately conservative: they are based on how often the
    pattern appears in benign enterprise traffic. This is the same trade-off a
    SOC makes when writing Suricata rules - precision vs. alert fatigue.
    """
    reasons: list[tuple[str, int]] = []
    add = lambda r, w: reasons.append((r, w))  # noqa: E731

    # ---------- credential / brute-force -------------------------------
    if row.get("num_failed_logins", 0) >= 3:
        add(f"Brute-force pattern: {int(row['num_failed_logins'])} failed logins", 2)
    elif row.get("num_failed_logins", 0) >= 1 and row.get("logged_in", 0) == 0:
        add("Failed authentication without an established session", 1)

    # ---------- privilege escalation (U2R) -----------------------------
    if row.get("root_shell", 0) == 1 or row.get("su_attempted", 0) == 2:
        add("Privilege-escalation artifacts (root shell / su attempt)", 2)
    if row.get("num_compromised", 0) > 0:
        add(f"Compromised filesystem objects: {int(row['num_compromised'])}", 2)
    if row.get("num_shells", 0) > 0 and row.get("num_root", 0) > 0:
        add("Multiple root-level shells opened on the host", 2)

    # ---------- DoS / flood --------------------------------------------
    if row.get("serror_rate", 0) > 0.8 and row.get("count", 0) > 100:
        add(f"SYN-flood signature: serror_rate={row['serror_rate']:.2f} "
            f"over {int(row['count'])} connections", 2)
    if row.get("rerror_rate", 0) > 0.75 and row.get("count", 0) > 100:
        add(f"Connection-rejection storm (rerror_rate={row['rerror_rate']:.2f})", 2)
    elif row.get("rerror_rate", 0) > 0.6:
        add(f"Elevated rejection rate ({row['rerror_rate']:.2f})", 1)

    # ---------- scanning / reconnaissance -------------------------------
    if row.get("diff_srv_rate", 0) > 0.7 and row.get("dst_host_count", 0) > 180:
        add("Sweeping many hosts and services - vertical port-scan behaviour", 2)
    # A /24 sweep touches nearly every host but only a few services per host.
    # (Popular benign servers also have dst_host_count=255, which is why the
    #  srv_count condition matters - this is FP-tuning in practice.)
    if (row.get("dst_host_count", 0) >= 250 and row.get("count", 0) >= 150
            and row.get("dst_host_srv_count", 0) <= 0.5 * row.get("dst_host_count", 1)):
        add("Blanket host sweep across an entire subnet (/24 discovery)", 2)
    if row.get("dst_host_diff_srv_rate", 0) > 0.8:
        add("Destination host contacted on many different services", 1)
    # ICMP sweep / flood. Justification (measured on KDDTrain+): this pattern
    # matches 3.8% of all malicious flows but only 1 in 67,343 benign flows
    # (0.0015%) - an excellent precision/recall trade-off for an IDS rule.
    if (row.get("protocol_type") == "icmp" and row.get("count", 0) >= 150
            and row.get("logged_in", 0) == 0):
        add(f"ICMP sweep/flood: {int(row['count'])} echo requests in one burst", 2)

    # ---------- data exfiltration / impact ------------------------------
    if row.get("src_bytes", 0) > 40_000 and row.get("dst_bytes", 0) < 10:
        add("Massive one-way outbound payload - possible data exfiltration", 2)
    if row.get("duration", 0) > 3000 and row.get("logged_in", 0) == 0:
        add("Long-lived unauthenticated session", 1)

    # ---------- web application probing (R2L) ---------------------------
    if row.get("hot", 0) >= 3 and row.get("num_access_files", 0) >= 2:
        add("Access to multiple sensitive files in one connection (injection probe)", 2)
    elif row.get("hot", 0) >= 3:
        add("Access to sensitive system files", 1)

    # ---------- malformed packets / evasion -----------------------------
    if row.get("land", 0) == 1 or row.get("wrong_fragment", 0) > 0:
        add("Malformed packet (land / wrong_fragment) - evasion attempt", 2)

    # ---------- guest / unusual auth -------------------------------------
    if row.get("is_guest_login", 0) == 1 and row.get("count", 0) > 50:
        add("Guest account used during a high-volume session", 1)

    return reasons


# ---------------------------------------------------------------------------
# THE DETECTOR
# ---------------------------------------------------------------------------
class ThreatDetector:
    """Loads all artefacts once and scores unlimited traffic batches."""

    def __init__(self):
        for f in (CLASSIFIER_FILE, ANOMALY_FILE):
            if not Path(f).exists():
                raise FileNotFoundError(f"Missing {f}. Run: python main.py train")
        self.classifier = joblib.load(CLASSIFIER_FILE)
        self.anomaly = joblib.load(ANOMALY_FILE)
        self.classes = list(self.classifier.classes_)
        self.attack_idx = [i for i, c in enumerate(self.classes) if c != "Normal"]
        self.metadata = {}
        if Path(METADATA_FILE).exists():
            import json
            self.metadata = json.loads(Path(METADATA_FILE).read_text())
        self.offline_metrics = {}
        if Path(METRICS_FILE).exists():
            import json
            self.offline_metrics = json.loads(Path(METRICS_FILE).read_text())

    # ---------------------------------------------------------------
    def predict(self, df_raw: pd.DataFrame) -> pd.DataFrame:
        """Score a DataFrame of raw traffic records (same schema as NSL-KDD)."""
        X = transform_new(df_raw)
        proba = self.classifier.predict_proba(X)
        pred = self.classifier.predict(X)

        attack_prob = proba[:, self.attack_idx].sum(axis=1)
        confidence = proba.max(axis=1)
        anomaly_score = -self.anomaly.score_samples(X)   # higher = weirder
        # Calibrated threshold (p99 of normal-traffic scores) instead of the
        # model's default contamination cut -> far fewer false alarms.
        threshold = getattr(self.anomaly, "alert_threshold_",
                            self.metadata.get("anomaly_threshold", None))
        if threshold is None:
            threshold = float(np.percentile(anomaly_score, 99))
        anomaly_raw = np.where(anomaly_score > threshold, -1, 1)

        out = df_raw.copy().reset_index(drop=True)
        out["prediction"] = pred
        out["confidence"] = np.round(confidence, 4)
        out["attack_probability"] = np.round(attack_prob, 4)
        out["anomaly_score"] = np.round(anomaly_score, 4)
        out["is_anomaly"] = (anomaly_raw == -1).astype(int)

        # ---- LAYER 3 + fusion ------------------------------------------
        reasons_col, severity_col, final_label, risk_col = [], [], [], []
        normalised = anomaly_score / (np.abs(anomaly_score).max() + 1e-9)  # 0..1

        for i, (_, row) in enumerate(out.iterrows()):
            triggers = signature_rules(row)
            rule_score = int(sum(w for _, w in triggers))
            reason_texts = [r for r, _ in triggers]

            ml_attack = pred[i] != "Normal"
            weird = bool(out["is_anomaly"].iloc[i] == 1)

            if ml_attack:
                label = pred[i]
            elif weird:
                label = "Unknown-Anomaly"
                reason_texts.append(f"Behavioural anomaly (score "
                                    f"{out['anomaly_score'].iloc[i]:.3f} > threshold)")
            else:
                label = "Normal"

            # Signature rules override the models when they are confident
            # (>=1 strong indicator, or >=2 supporting indicators).
            if label == "Normal" and rule_score >= 2:
                label = "Unknown-Anomaly"
                reason_texts.append("Signature-correlated flow (no matching ML class)")

            # ---- risk score 0-100 : confidence + weirdness + evidence ----
            prob_term = 45 * float(attack_prob[i])
            anom_term = 35 * float(max(normalised[i], 0))
            rule_term = 12 * min(rule_score, 4)
            trust_bonus = 8 if label not in ("Normal", "Unknown-Anomaly") else 0
            if label == "Normal":
                risk = 15 * float(attack_prob[i]) + 10 * float(max(normalised[i], 0)) \
                       + 6 * min(rule_score, 2)
            else:
                risk = prob_term + anom_term + rule_term + trust_bonus
            risk = float(np.clip(risk, 0, 100))

            severity = SEVERITY_MAP.get(label, "MEDIUM")
            if severity != "INFO" and risk < 35:
                severity = "LOW"           # low-confidence hunch -> queue, not page

            final_label.append(label)
            reasons_col.append("; ".join(reason_texts) if reason_texts
                               else "No signature match")
            severity_col.append(severity)
            risk_col.append(risk)

        out["threat_class"] = final_label
        out["is_attack"] = (out["threat_class"] != "Normal").astype(int)
        out["risk_score"] = np.round(risk_col, 2)
        out["severity"] = severity_col
        out["mitre_technique"] = [f"{MITRE_MAP[c]['id']} - {MITRE_MAP[c]['name']}"
                                  for c in out["threat_class"]]
        out["reason"] = reasons_col
        out["recommended_action"] = [RESPONSE_PLAYBOOK[c] for c in out["threat_class"]]
        return out

    # ---------------------------------------------------------------
    def predict_one(self, record: dict) -> dict:
        """Single-record API helper (used by /api/predict)."""
        df = pd.DataFrame([record])
        res = self.predict(df).iloc[0].to_dict()
        return {k: (v.item() if hasattr(v, "item") else v) for k, v in res.items()}

    # ---------------------------------------------------------------
    @staticmethod
    def build_alerts(scored: pd.DataFrame, src_ips=None, dst_ips=None,
                     services=None) -> pd.DataFrame:
        """Convert attack rows into SOC alerts with IDs + timestamps."""
        attacks = scored[scored["is_attack"] == 1].copy()
        if attacks.empty:
            return pd.DataFrame(columns=[
                "alert_id", "timestamp", "severity", "threat_class", "src_ip",
                "dst_ip", "service", "risk_score", "confidence", "mitre", "reason",
                "action"])

        now = time.time()
        n = len(attacks)
        attacks["alert_id"] = [f"ALT-{uuid.uuid4().hex[:8].upper()}" for _ in range(n)]
        # spread timestamps backwards so the table looks like a live feed
        attacks["timestamp"] = [
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - (n - i) * 1.5))
            for i in range(n)
        ]
        rng = np.random.default_rng(7)
        attacks["src_ip"] = src_ips if src_ips is not None else [
            f"{rng.integers(10, 223)}.{rng.integers(0, 255)}."
            f"{rng.integers(0, 255)}.{rng.integers(1, 254)}" for _ in range(n)]
        attacks["dst_ip"] = dst_ips if dst_ips is not None else [
            f"10.0.{rng.integers(0, 4)}.{rng.integers(1, 254)}" for _ in range(n)]
        attacks["service"] = services if services is not None else attacks.get("service", "-")

        return attacks[[
            "alert_id", "timestamp", "severity", "threat_class", "src_ip", "dst_ip",
            "service", "risk_score", "confidence", "mitre_technique", "reason",
            "recommended_action"]].rename(columns={
                "mitre_technique": "mitre", "recommended_action": "action"}).reset_index(drop=True)


# ---------------------------------------------------------------------------
# CLI demo
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    from src.data_loader import load_nsl_kdd
    from src.simulate import TrafficSimulator

    print("=" * 62)
    print("  PHASE 7 - THREAT DETECTION DEMO")
    print("=" * 62)
    det = ThreatDetector()

    # 1) Score real rows from the official test split
    df = load_nsl_kdd("test").sample(8, random_state=1)
    scored = det.predict(df)
    print("\nReal NSL-KDD flows scored by the engine:")
    print(scored[["label", "threat_class", "confidence", "risk_score",
                  "severity"]].to_string(index=False))

    # 2) Score a simulated live attack burst
    sim = TrafficSimulator().simulate(n_events=300, attack_rate=0.30)
    scored_sim = det.predict(sim["traffic"])
    alerts = ThreatDetector.build_alerts(scored_sim, src_ips=sim["traffic"]["src_ip"],
                                         dst_ips=sim["traffic"]["dst_ip"],
                                         services=sim["traffic"]["service"])
    print(f"\nSimulated burst: {len(scored_sim)} events -> {len(alerts)} alerts")
    print(alerts.head(8).to_string(index=False))
    print(f"\n[OK] Detection F1 on this burst: "
          f"{__import__('sklearn.metrics', fromlist=['f1_score']).f1_score(sim['traffic']['is_attack_truth'], scored_sim['is_attack'], zero_division=0):.3f}")
