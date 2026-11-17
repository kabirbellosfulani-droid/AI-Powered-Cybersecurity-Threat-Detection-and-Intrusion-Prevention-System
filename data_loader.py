"""
data_loader.py
==============
Loads the NSL-KDD intrusion-detection dataset and gives us a clean,
labelled pandas DataFrame.

WHAT IS NSL-KDD?
----------------
It is the de-facto academic benchmark for Network Intrusion Detection.
Every row = ONE network connection (a "flow") summarised by 41 features.
  * Basic features  : duration, protocol_type, src_bytes, dst_bytes ...
  * Content features: num_failed_logins, root_shell, logged_in ...
  * Traffic features: count, srv_count, serror_rate, dst_host_* ...
Label = 'normal' or one of 24 attack names (neptune, portsweep, guess_passwd...).

The file has no header -> we supply config.NSL_KDD_COLUMNS.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd

# Allow running this file directly: python src/data_loader.py
sys.path.append(str(Path(__file__).resolve().parent.parent))
from src.config import (  # noqa: E402
    NSL_KDD_COLUMNS, NSL_KDD_TEST_FILE, NSL_KDD_TRAIN_FILE,
    ATTACK_CATEGORY_MAP, ATTACK_CLASSES, DATA_PROCESSED_DIR, OUTPUTS_DIR,
)


def load_nsl_kdd(split: str = "train") -> pd.DataFrame:
    """Read KDDTrain+ / KDDTest+ into a DataFrame with proper column names.

    Parameters
    ----------
    split : {"train", "test"}
    """
    path = NSL_KDD_TRAIN_FILE if split == "train" else NSL_KDD_TEST_FILE
    if not Path(path).exists():
        raise FileNotFoundError(
            f"Dataset not found at {path}\n"
            "Run:  python scripts/download_datasets.py"
        )

    df = pd.read_csv(path, names=NSL_KDD_COLUMNS, header=None)

    # --- normalise the label column -------------------------------------
    df["label"] = df["label"].astype(str).str.strip().str.rstrip(".")

    # --- map 24 raw attack names -> 4 industry families + Normal --------
    df["attack_category"] = df["label"].map(ATTACK_CATEGORY_MAP).fillna("Normal")

    # --- binary target used by the anomaly detector & SOC alerts --------
    df["is_attack"] = (df["attack_category"] != "Normal").astype(int)
    return df


def dataset_summary(df: pd.DataFrame, name: str = "dataset") -> dict:
    """Compute the descriptive statistics we quote in the README/report."""
    summary = {
        "name": name,
        "rows": int(len(df)),
        "columns": int(df.shape[1]),
        "features": int(df.shape[1] - 3),          # minus label/category/is_attack
        "attack_rows": int(df["is_attack"].sum()),
        "normal_rows": int((df["is_attack"] == 0).sum()),
        "attack_ratio_pct": round(100 * df["is_attack"].mean(), 2),
        "missing_values": int(df.isnull().sum().sum()),
        "duplicate_rows": int(df.duplicated().sum()),
        "label_distribution": df["attack_category"].value_counts().to_dict(),
        "top_attack_types": df.loc[df.is_attack == 1, "label"]
                              .value_counts().head(10).to_dict(),
        "protocol_distribution": df["protocol_type"].value_counts().to_dict(),
    }
    return summary


def print_summary(summary: dict) -> None:
    """Pretty-print the summary dict to the console."""
    line = "=" * 62
    print(line)
    print(f"  DATASET SUMMARY - {summary['name']}")
    print(line)
    print(f"  Rows / Columns      : {summary['rows']:,} / {summary['columns']}")
    print(f"  Normal / Attack     : {summary['normal_rows']:,} / {summary['attack_rows']:,}")
    print(f"  Attack ratio        : {summary['attack_ratio_pct']}%")
    print(f"  Missing values      : {summary['missing_values']}")
    print(f"  Duplicate rows      : {summary['duplicate_rows']}")
    print("  Attack families     :")
    for k, v in sorted(summary["label_distribution"].items(), key=lambda x: -x[1]):
        print(f"      {k:<8} {v:>8,}")
    print("  Top attack types    :")
    for k, v in summary["top_attack_types"].items():
        print(f"      {k:<16} {v:>8,}")
    print(line)


def main() -> None:
    """Entry point: load both splits, print + save the summary."""
    train = load_nsl_kdd("train")
    test = load_nsl_kdd("test")

    s_train, s_test = dataset_summary(train, "NSL-KDD KDDTrain+"), dataset_summary(test, "NSL-KDD KDDTest+")
    print_summary(s_train)
    print_summary(s_test)

    # Save a small preview so you can screenshot it for your GitHub README
    preview = train.head(500)
    preview.to_csv(DATA_PROCESSED_DIR / "dataset_preview.csv", index=False)

    import json
    with open(OUTPUTS_DIR / "dataset_summary.json", "w") as f:
        json.dump({"train": s_train, "test": s_test}, f, indent=2)

    print(f"\n[OK] Preview saved  -> data/processed/dataset_preview.csv")
    print(f"[OK] Summary saved  -> outputs/dataset_summary.json")
    assert set(train["attack_category"]).issubset(set(ATTACK_CLASSES)), "Unknown attack family!"
    print("[OK] All labels mapped into:", ATTACK_CLASSES)


if __name__ == "__main__":
    main()
