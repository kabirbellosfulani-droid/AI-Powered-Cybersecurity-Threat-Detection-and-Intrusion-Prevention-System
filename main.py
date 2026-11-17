"""
main.py  -  ONE COMMAND TO RUN THE WHOLE PROJECT
================================================
Usage
-----
  python main.py all          # download -> train -> evaluate -> figures -> simulate
  python main.py download     # fetch the NSL-KDD dataset
  python main.py train        # clean + feature-engineer + train 3 models
  python main.py evaluate     # metrics table (hold-out + official KDDTest+)
  python main.py figures      # build all 10 report figures into images/
  python main.py simulate     # run the virtual cyber range, write alerts.csv
  python main.py dashboard    # start the SOC web console on http://127.0.0.1:5000
  python main.py predict FILE # score a CSV of raw flows (JSON summary out)
  python main.py info         # print dataset/model status
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.append(str(BASE))

BANNER = r"""
  ____  _____ _   _ _____ ___ _   _ _     _____
 / ___|| ____| \ | |_   _|_ _| \ | | |   | ____|
 \___ \|  _| |  \| | | |  | ||  \| | |   |  _|
  ___) | |___| |\  | | |  | || |\  | |___| |___
 |____/|_____|_| \_| |_| |___|_| \_|_____|_____|

  AI-POWERED CYBERSECURITY THREAT DETECTION SYSTEM
  RandomForest + IsolationForest + signature rules  |  NSL-KDD benchmark
"""


def run(cmd: list[str]) -> None:
    print(f"\n$ {' '.join(cmd)}")
    subprocess.run(cmd, cwd=BASE, check=True)


def cmd_download(_args) -> None:
    run([sys.executable, "scripts/download_datasets.py"])


def cmd_train(_args) -> None:
    run([sys.executable, "src/train.py"])


def cmd_evaluate(_args) -> None:
    run([sys.executable, "src/evaluate.py"])


def cmd_figures(_args) -> None:
    run([sys.executable, "src/visualize.py"])


def cmd_simulate(_args) -> None:
    run([sys.executable, "src/generate_simulation.py"])


def cmd_test(_args) -> None:
    run([sys.executable, "-m", "pytest", "tests/", "-q"])


def cmd_dashboard(_args) -> None:
    print("\n[INFO] Starting the SOC console on http://127.0.0.1:5000 (Ctrl+C to stop)")
    run([sys.executable, "dashboard/app.py"])


def cmd_all(_args) -> None:
    cmd_download(None)
    cmd_train(None)
    cmd_evaluate(None)
    cmd_figures(None)
    cmd_simulate(None)
    print("\n" + "=" * 66)
    print("  PIPELINE COMPLETE - next steps:")
    print("    1. python main.py dashboard      -> live SOC console")
    print("    2. open images/ and screenshot the figures for your README")
    print("    3. git add . && git commit -m 'feat: complete detection pipeline'")
    print("=" * 66)


def cmd_predict(args) -> None:
    import pandas as pd
    from src.detect import ThreatDetector

    df = pd.read_csv(args.file)
    det = ThreatDetector()
    scored = det.predict(df)
    alerts = ThreatDetector.build_alerts(scored)
    out_csv = BASE / "outputs" / "predictions.csv"
    scored.to_csv(out_csv, index=False)
    if len(alerts):
        alerts.to_csv(BASE / "outputs" / "alerts_from_file.csv", index=False)
    summary = {
        "flows_scored": int(len(scored)),
        "attacks_detected": int(scored["is_attack"].sum()),
        "by_class": scored["threat_class"].value_counts().to_dict(),
        "by_severity": scored["severity"].value_counts().to_dict(),
        "avg_risk": round(float(scored["risk_score"].mean()), 2),
        "outputs": [str(out_csv.relative_to(BASE))],
    }
    print(json.dumps(summary, indent=2))


def cmd_info(_args) -> None:
    from src.config import (METADATA_FILE, METRICS_FILE, NSL_KDD_TEST_FILE,
                            NSL_KDD_TRAIN_FILE)
    print(BANNER)
    for name, p in [("KDDTrain+", NSL_KDD_TRAIN_FILE), ("KDDTest+", NSL_KDD_TEST_FILE)]:
        print(f"  dataset {name:<10}: {'FOUND  ' + str(round(p.stat().st_size/1e6,1)) + ' MB' if p.exists() else 'MISSING (run: python main.py download)'}")
    for name, p in [("classifier", BASE / "models/threat_classifier.joblib"),
                    ("anomaly", BASE / "models/anomaly_detector.joblib"),
                    ("preprocessor", BASE / "models/preprocessor.joblib")]:
        print(f"  model   {name:<12}: {'READY' if p.exists() else 'MISSING (run: python main.py train)'}")
    if METRICS_FILE.exists():
        m = json.loads(METRICS_FILE.read_text())
        rf = m["holdout_random_split"]["random_forest"]
        print(f"\n  benchmark : accuracy={rf['accuracy']} precision={rf['precision']} "
              f"recall={rf['recall']} f1={rf['f1_score']}")
    if METADATA_FILE.exists():
        md = json.loads(METADATA_FILE.read_text())
        print(f"  trained   : {md.get('trained_at')}  (v{md.get('model_version')})")


def main() -> None:
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="AI-Powered Cybersecurity Threat Detection System")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("download", help="download the NSL-KDD dataset")
    sub.add_parser("train", help="train the model stack")
    sub.add_parser("evaluate", help="evaluate all models")
    sub.add_parser("figures", help="generate report figures")
    sub.add_parser("simulate", help="run the virtual cyber range")
    sub.add_parser("dashboard", help="start the SOC web console")
    sub.add_parser("test", help="run the unit tests")
    sub.add_parser("all", help="run the full pipeline end to end")
    sub.add_parser("info", help="show dataset / model status")
    p_pred = sub.add_parser("predict", help="score a CSV of raw flows")
    p_pred.add_argument("file", help="path to a CSV containing NSL-KDD columns")

    actions = {"download": cmd_download, "train": cmd_train, "evaluate": cmd_evaluate,
               "figures": cmd_figures, "simulate": cmd_simulate, "dashboard": cmd_dashboard,
               "all": cmd_all, "predict": cmd_predict, "info": cmd_info, "test": cmd_test}
    args = parser.parse_args()          # parse once, then dispatch
    actions[args.command](args)


if __name__ == "__main__":
    main()
