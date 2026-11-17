"""
feature_engineering.py
======================
Turns the 41 raw NSL-KDD features into a richer, more "explanatory" feature
set - the same trick real SOC data-science teams use to help models AND
humans understand *why* a flow is suspicious.

WHY FEATURE ENGINEERING?
------------------------
Raw counters (src_bytes, dst_bytes, count, srv_count, serror_rate ...) are hard
for a model to combine. Ratio/interaction features encode domain knowledge:

  * An exfiltration attack sends far more bytes OUT than IN  -> bytes_ratio
  * A port scan hits MANY hosts but FEW services              -> host_scan_ratio
  * A SYN flood has a huge packet count with a huge error rate -> dos_intensity
  * Failed logins without a successful session = brute force   -> login_anomaly

None of these features leak the label: they are computed only from the
41 input columns, so there is no data leakage.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.append(str(Path(__file__).resolve().parent.parent))

# Names of every engineered column, so preprocessing knows what's numeric.
ENGINEERED_FEATURES = [
    "total_bytes",        # src + dst traffic volume
    "bytes_ratio",        # outbound/inbound balance  (exfiltration signal)
    "byte_asymmetry",     # |src - dst| / (src + dst)
    "dos_intensity",      # error rate x packet count  (flood signal)
    "host_scan_ratio",    # hosts touched vs services touched (scan signal)
    "service_concentration",  # how focused traffic is on one service
    "login_anomaly",      # failed logins without a session (brute-force signal)
    "privilege_score",    # root/compromise indicators (privilege-escalation)
    "payload_per_packet", # avg bytes per packet (data-dump signal)
    "traffic_entropy",    # diversity of the destination landscape
    "is_wellknown_port",  # targets a privileged service port
    "error_flag_count",   # flag-level anomalies (land, wrong_fragment, urgent)
    "critical_service",   # ssh/ftp/telnet/smtp target (credential attacks)
]


def add_engineered_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add ~13 domain-driven features. Pure function: returns a copy."""
    out = df.copy()
    eps = 1e-6  # avoid divide-by-zero

    # ---- 1. volume & direction ------------------------------------------
    out["total_bytes"] = out["src_bytes"] + out["dst_bytes"]
    out["bytes_ratio"] = out["src_bytes"] / (out["dst_bytes"] + eps)
    out["byte_asymmetry"] = (out["src_bytes"] - out["dst_bytes"]).abs() / (
        out["src_bytes"] + out["dst_bytes"] + eps
    )

    # ---- 2. flood / DoS signals -----------------------------------------
    #    both serror (SYN errors) and rerror (REJ errors) matter
    out["dos_intensity"] = (out["serror_rate"] + out["rerror_rate"]) * out["count"]
    out["payload_per_packet"] = out["total_bytes"] / (out["count"] + out["srv_count"] + eps)

    # ---- 3. scanning / probe signals ------------------------------------
    #    A scanner touches many destination hosts but few services per host.
    out["host_scan_ratio"] = out["dst_host_count"] / (out["dst_host_srv_count"] + eps)
    out["traffic_entropy"] = (
        out["diff_srv_rate"] + out["dst_host_diff_srv_rate"] + out["srv_diff_host_rate"]
    ) / 3.0
    out["service_concentration"] = out["same_srv_rate"] * out["dst_host_same_srv_rate"]

    # ---- 4. credential / brute-force signals ----------------------------
    out["login_anomaly"] = (
        (out["num_failed_logins"] > 0) & (out["logged_in"] == 0)
    ).astype(int)
    out["critical_service"] = out["service"].isin(
        ["ssh", "ftp", "ftp_data", "telnet", "smtp", "login", "rlogin", "imap", "pop_3"]
    ).astype(int)

    # ---- 5. privilege escalation (U2R) signals --------------------------
    out["privilege_score"] = (
        out["root_shell"] + out["su_attempted"] + out["num_root"]
        + out["num_compromised"] + out["num_file_creations"] + out["num_shells"]
    )

    # ---- 6. malformed-packet / port signals -----------------------------
    out["error_flag_count"] = out["land"] + out["wrong_fragment"] + (out["urgent"] > 0).astype(int)
    out["is_wellknown_port"] = (out["service"].isin(
        ["http", "https", "ftp", "ssh", "smtp", "domain", "telnet", "pop_3"]
    )).astype(int)

    # Infinity can appear from ratios when a denominator was 0 -> clean it
    out[ENGINEERED_FEATURES] = out[ENGINEERED_FEATURES].replace([np.inf, -np.inf], 0).fillna(0)
    return out


def select_model_features(df: pd.DataFrame, target_col: str = "attack_category") -> list[str]:
    """Return the feature columns fed to the model (everything except labels)."""
    drop = {target_col, "label", "is_attack", "difficulty"}
    return [c for c in df.columns if c not in drop]


def main() -> None:
    """Quick self-test on the real dataset."""
    from src.data_loader import load_nsl_kdd

    df = load_nsl_kdd("train")
    rich = add_engineered_features(df)
    feats = select_model_features(rich)
    print(f"[OK] Raw features       : {df.shape[1] - 3}")
    print(f"[OK] Total model features: {len(feats)}")
    print(f"[OK] New features        : {ENGINEERED_FEATURES}")
    print("\nSample of engineered values (attack vs normal means):")
    show = ["total_bytes", "bytes_ratio", "dos_intensity", "host_scan_ratio", "login_anomaly"]
    print(rich.groupby("attack_category")[show].mean().round(3).to_string())
    rich.to_csv("data/processed/features_preview.csv", index=False)
    print("\n[OK] Saved -> data/processed/features_preview.csv")


if __name__ == "__main__":
    main()
