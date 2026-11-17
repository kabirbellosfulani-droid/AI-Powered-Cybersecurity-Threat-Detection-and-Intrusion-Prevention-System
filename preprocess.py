"""
preprocess.py
=============
Everything that must happen BEFORE the model sees data:

  1. drop useless / leaky columns          (difficulty, raw 'label')
  2. remove duplicate rows                 (NSL-KDD ships duplicates)
  3. build the sklearn Pipeline:
        ColumnTransformer
          ├─ OneHotEncoder  -> protocol_type, service, flag  (categorical)
          ├─ StandardScaler -> all numeric features          (mean 0, std 1)
  4. stratified train/test split
  5. save the fitted preprocessor so the LIVE API transforms new traffic
     EXACTLY the same way as training data  (classic production mistake #1)

WHY A SAVED PIPELINE INSTEAD OF A LOOSE SCALER?
Because at inference time (Flask API / dashboard) you must apply identical
encoding + scaling. Fit once, save once, reuse everywhere.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

sys.path.append(str(Path(__file__).resolve().parent.parent))
from src.config import (  # noqa: E402
    CATEGORICAL_COLUMNS, DATA_PROCESSED_DIR, OUTPUTS_DIR, PREPROCESSOR_FILE,
    RANDOM_STATE, TEST_SIZE,
)
from src.data_loader import load_nsl_kdd  # noqa: E402
from src.feature_engineering import add_engineered_features, select_model_features  # noqa: E402


# ---------------------------------------------------------------------------
# 1. CLEANING
# ---------------------------------------------------------------------------
def clean_dataframe(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Clean the dataframe and return (df, cleaning_report)."""
    report: dict = {"rows_in": int(len(df))}

    # a) 'difficulty' is a meta-column about the record, not traffic -> drop
    df = df.drop(columns=["difficulty"], errors="ignore")

    # b) replace infinite values produced by ratio math
    num_cols = df.select_dtypes(include=[np.number]).columns
    df[num_cols] = df[num_cols].replace([np.inf, -np.inf], np.nan)

    # c) fill numeric NaNs with the median (robust to outliers)
    n_missing = int(df[num_cols].isnull().sum().sum())
    df[num_cols] = df[num_cols].fillna(df[num_cols].median(numeric_only=True))

    # d) categorical NaNs -> "unknown" so OneHotEncoder never crashes
    for c in CATEGORICAL_COLUMNS:
        if c in df.columns:
            df[c] = df[c].fillna("unknown").astype(str)

    # e) de-duplicate identical connection records
    before = len(df)
    df = df.drop_duplicates().reset_index(drop=True)
    report.update({
        "rows_out": int(len(df)),
        "missing_filled": n_missing,
        "duplicates_removed": int(before - len(df)),
    })
    return df, report


# ---------------------------------------------------------------------------
# 2. THE PREPROCESSING PIPELINE
# ---------------------------------------------------------------------------
def build_preprocessor(numeric_features: list[str]) -> ColumnTransformer:
    """OneHot for categoricals + StandardScaler for numerics."""
    categorical_pipe = Pipeline([
        ("onehot", OneHotEncoder(handle_unknown="ignore", sparse_output=False)),
    ])
    numeric_pipe = Pipeline([
        ("scaler", StandardScaler()),
    ])
    return ColumnTransformer(
        transformers=[
            ("cat", categorical_pipe, CATEGORICAL_COLUMNS),
            ("num", numeric_pipe, numeric_features),
        ],
        remainder="drop",
        verbose_feature_names_out=False,
    )


# ---------------------------------------------------------------------------
# 3. FULL DATA PREPARATION (used by training AND by the dashboard)
# ---------------------------------------------------------------------------
def prepare_training_data(split: str = "train", save: bool = True):
    """Load -> clean -> engineer -> split -> fit preprocessor.

    Returns
    -------
    X_train, X_test, y_train, y_test  : numpy / pandas objects ready for a model
    feature_names                     : list[str] of output columns
    preprocessor                      : fitted ColumnTransformer
    df_rich                           : the fully engineered dataframe (for EDA)
    """
    df = load_nsl_kdd(split)
    df, clean_report = clean_dataframe(df)
    df = add_engineered_features(df)

    features = select_model_features(df)
    numeric_features = [c for c in features if c not in CATEGORICAL_COLUMNS]

    preprocessor = build_preprocessor(numeric_features)
    X = preprocessor.fit_transform(df[features])
    feature_names = list(preprocessor.get_feature_names_out())

    y = df["attack_category"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )

    if save:
        joblib.dump(preprocessor, PREPROCESSOR_FILE)
        df.to_csv(DATA_PROCESSED_DIR / "nslkdd_engineered.csv", index=False)
        meta = {
            "clean_report": clean_report,
            "n_features_raw": len(features),
            "n_features_encoded": len(feature_names),
            "class_distribution": y.value_counts().to_dict(),
            "train_rows": int(len(X_train)),
            "test_rows": int(len(X_test)),
        }
        with open(OUTPUTS_DIR / "preprocessing_report.json", "w") as f:
            json.dump(meta, f, indent=2)
        print(f"[OK] Preprocessor saved -> {PREPROCESSOR_FILE}")
        print(f"[OK] Encoded feature matrix: {X.shape[0]:,} rows x {X.shape[1]} features")
        print(f"[OK] Cleaning report: {clean_report}")

    return X_train, X_test, y_train, y_test, feature_names, preprocessor, df


def load_preprocessor():
    """Load the fitted preprocessor for inference."""
    if not Path(PREPROCESSOR_FILE).exists():
        raise FileNotFoundError("Preprocessor missing - run `python main.py train` first.")
    return joblib.load(PREPROCESSOR_FILE)


def transform_new(df_raw: pd.DataFrame, preprocessor=None) -> np.ndarray:
    """Transform raw incoming traffic (e.g. from the API) into model input.

    This is THE function the live system uses, guaranteeing train/serve parity.

    Robustness matters in production: an analyst submitting a partial JSON body
    (or a Zeek log missing optional fields) must NOT crash the service. So we
    fill any missing RAW feature with a safe default BEFORE engineering
    features, then transform exactly as during training.
    """
    from src.feature_engineering import ENGINEERED_FEATURES

    preprocessor = preprocessor or load_preprocessor()
    expected = list(getattr(preprocessor, "feature_names_in_", []))
    if not expected:                                  # fallback for old pickles
        expected = select_model_features(add_engineered_features(df_raw))

    raw_required = [c for c in expected if c not in ENGINEERED_FEATURES]
    df = df_raw.copy()
    for col in raw_required:
        if col not in df.columns:
            df[col] = "unknown" if col in CATEGORICAL_COLUMNS else 0

    df, _ = clean_dataframe(df)
    df = add_engineered_features(df)

    # belt & braces: anything still missing (e.g. brand-new engineered col)
    for col in expected:
        if col not in df.columns:
            df[col] = 0

    return preprocessor.transform(df[expected])


if __name__ == "__main__":
    prepare_training_data("train")
