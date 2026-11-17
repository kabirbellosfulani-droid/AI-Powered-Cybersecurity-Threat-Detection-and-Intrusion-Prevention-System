"""
test_pipeline.py
================
Automated tests - the difference between "a notebook" and "engineering".

Run:  python -m pytest tests/ -v     (or  python main.py test)

What we check:
  1. Dataset loads with the exact NSL-KDD schema (43 raw columns).
  2. Label mapping produces only the 5 known classes.
  3. Feature engineering creates the engineered columns and no NaNs/infs.
  4. Cleaning removes duplicates/NaNs without losing rows unexpectedly.
  5. The preprocessor output shape matches the model's expected input.
  6. The detector returns a well-formed verdict for a benign and an attack flow.
  7. Signature rules fire on a brute-force pattern and stay silent on normal.
  8. The simulator produces the requested volume and reproducible seeds.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

BASE = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE))

from src.config import ATTACK_CLASSES, NSL_KDD_COLUMNS  # noqa: E402
from src.data_loader import load_nsl_kdd  # noqa: E402
from src.feature_engineering import (ENGINEERED_FEATURES,  # noqa: E402
                                     add_engineered_features)
from src.preprocess import clean_dataframe  # noqa: E402
from src.simulate import TrafficSimulator  # noqa: E402

DATA_READY = (BASE / "data" / "raw" / "KDDTrain+.txt").exists()
MODELS_READY = (BASE / "models" / "threat_classifier.joblib").exists()

pytestmark = pytest.mark.skipif(not DATA_READY, reason="dataset not downloaded")


# --------------------------------------------------------------------- data
def test_schema_has_43_columns():
    df = load_nsl_kdd("train")
    assert len(NSL_KDD_COLUMNS) == 43
    assert df.shape[1] == 45          # 43 raw + attack_category + is_attack
    assert df["label"].notna().all()


def test_label_mapping_is_complete():
    df = load_nsl_kdd("train")
    assert set(df["attack_category"].unique()).issubset(set(ATTACK_CLASSES))
    assert df["is_attack"].isin([0, 1]).all()
    assert (df.loc[df.label == "normal", "attack_category"] == "Normal").all()


# ------------------------------------------------------- feature engineering
def test_engineered_features_exist_and_are_finite():
    df = add_engineered_features(load_nsl_kdd("train").head(2000))
    for col in ENGINEERED_FEATURES:
        assert col in df.columns, f"missing engineered feature {col}"
    block = df[ENGINEERED_FEATURES].to_numpy()
    assert np.isfinite(block).all(), "engineered features contain NaN/inf"


def test_dos_flows_have_higher_dos_intensity_than_normal():
    df = add_engineered_features(load_nsl_kdd("train").head(20000))
    dos = df.loc[df.attack_category == "DoS", "dos_intensity"].mean()
    normal = df.loc[df.attack_category == "Normal", "dos_intensity"].mean()
    assert dos > normal, "DoS intensity feature is not discriminative"


# ----------------------------------------------------------------- cleaning
def test_cleaning_is_lossless_for_valid_rows():
    df = load_nsl_kdd("train").head(5000)
    clean, report = clean_dataframe(df)
    assert report["rows_out"] <= report["rows_in"]
    assert clean.isnull().sum().sum() == 0
    assert "difficulty" not in clean.columns


# ------------------------------------------------------------------- engine
@pytest.mark.skipif(not MODELS_READY, reason="models not trained")
def test_detector_verdict_shape():
    from src.detect import ThreatDetector
    det = ThreatDetector()
    sim = TrafficSimulator(seed=5)
    res = sim.simulate(n_events=60, attack_rate=0.3, seed=5)
    scored = det.predict(res["traffic"])
    for col in ["threat_class", "is_attack", "risk_score", "severity",
                "mitre_technique", "reason", "recommended_action"]:
        assert col in scored.columns
    assert scored["is_attack"].isin([0, 1]).all()
    assert scored["risk_score"].between(0, 100).all()
    assert scored["threat_class"].isin(ATTACK_CLASSES + ["Unknown-Anomaly"]).all()


@pytest.mark.skipif(not MODELS_READY, reason="models not trained")
def test_signature_rules_fire_on_bruteforce():
    from src.detect import signature_rules
    attack = pd.Series({"num_failed_logins": 8, "logged_in": 0, "service": "ssh"})
    benign = pd.Series({"num_failed_logins": 0, "logged_in": 1, "src_bytes": 200,
                        "dst_bytes": 900, "count": 1, "srv_count": 1})
    reasons_attack = [r for r, w in signature_rules(attack)]
    assert reasons_attack and "Brute-force" in reasons_attack[0]
    assert sum(w for _, w in signature_rules(benign)) == 0


@pytest.mark.skipif(not MODELS_READY, reason="models not trained")
def test_zero_day_style_unknown_flows_get_flagged():
    """A flow that is weird on many axes must raise something, even if the
    supervised classifier has no matching class (the anomaly + rule layers)."""
    from src.detect import ThreatDetector
    det = ThreatDetector()
    weird = pd.DataFrame([{
        "duration": 5000, "protocol_type": "tcp", "service": "private",
        "flag": "REJ", "src_bytes": 200_000, "dst_bytes": 0,
        "count": 300, "srv_count": 5, "srv_diff_host_rate": 0.7,
        "serror_rate": 0.0, "rerror_rate": 0.82, "num_failed_logins": 0,
        "logged_in": 0, "root_shell": 0, "num_compromised": 0, "hot": 0,
        "diff_srv_rate": 0.9, "dst_host_count": 255, "dst_host_srv_count": 10,
        "dst_host_diff_srv_rate": 0.9,
    }])
    out = det.predict(weird).iloc[0]
    assert out["risk_score"] > 40, f"highly unusual flow should be high risk ({out['risk_score']})"
    assert out["is_attack"] == 1
    assert out["reason"] != "No signature match"


@pytest.mark.skipif(not MODELS_READY, reason="models not trained")
def test_benign_flow_is_not_flagged():
    """No alert fatigue: a clean web flow must come back Normal with low risk."""
    from src.detect import ThreatDetector
    det = ThreatDetector()
    good = pd.DataFrame([{
        "duration": 3, "protocol_type": "tcp", "service": "http", "flag": "SF",
        "src_bytes": 240, "dst_bytes": 5200, "count": 2, "srv_count": 2,
        "serror_rate": 0.0, "rerror_rate": 0.0, "num_failed_logins": 0,
        "logged_in": 1, "root_shell": 0, "num_compromised": 0, "hot": 0,
        "diff_srv_rate": 0.0, "dst_host_count": 6, "dst_host_srv_count": 6,
        "dst_host_diff_srv_rate": 0.0,
    }])
    out = det.predict(good).iloc[0]
    assert out["is_attack"] == 0, "benign web flow wrongly flagged"
    assert out["risk_score"] < 35


# ---------------------------------------------------------------- simulator
def test_simulator_volume_and_reproducibility():
    a = TrafficSimulator(seed=11).simulate(n_events=200, attack_rate=0.25, seed=11)
    b = TrafficSimulator(seed=11).simulate(n_events=200, attack_rate=0.25, seed=11)
    assert len(a["traffic"]) == 200
    assert a["traffic"]["is_attack_truth"].sum() >= 40
    assert (a["traffic"]["scenario"].values == b["traffic"]["scenario"].values).all()


def test_simulator_has_ground_truth_and_network_fields():
    res = TrafficSimulator(seed=3).simulate(n_events=120, attack_rate=0.3)
    for col in ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
                "scenario", "is_attack_truth", "attack_family_truth"]:
        assert col in res["traffic"].columns
    assert res["traffic"]["src_ip"].nunique() > 5
