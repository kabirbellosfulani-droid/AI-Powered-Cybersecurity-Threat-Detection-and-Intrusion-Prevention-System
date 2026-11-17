"""
download_datasets.py
====================
No corporate SOC access? No problem - this script fetches the public,
industry-standard intrusion-detection datasets for you.

It downloads NSL-KDD (the benchmark used in thousands of IDS papers) and
prints the manual links for the bigger modern datasets (CICIDS2017,
UNSW-NB15) so you can extend the project later.

Usage:  python scripts/download_datasets.py
"""

from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))
from src.config import DATA_RAW_DIR  # noqa: E402

SOURCES = {
    "KDDTrain+.txt": "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTrain%2B.txt",
    "KDDTest+.txt":  "https://raw.githubusercontent.com/jmnwong/NSL-KDD-Dataset/master/KDDTest%2B.txt",
}

MANUAL_LINKS = """
The dataset is a standard benchmark corpus; if the mirror above is ever
unavailable, download the same files manually and drop them into data/raw/:
  * NSL-KDD  : https://www.unb.ca/cic/datasets/nsl.html
  * Kaggle   : https://www.kaggle.com/datasets/hassan06/nslkdd
Modern, larger datasets to extend this project (same code, better features):
  * CICIDS2017 / CICIDS2018 : https://www.unb.ca/cic/datasets/ids-2017.html
  * UNSW-NB15               : https://research.unsw.edu.au/projects/unsw-nb15-dataset
  * CIC-DDoS2019            : https://www.unb.ca/cic/datasets/ddos-2019.html
"""


def main() -> None:
    DATA_RAW_DIR.mkdir(parents=True, exist_ok=True)
    for name, url in SOURCES.items():
        dest = DATA_RAW_DIR / name
        if dest.exists() and dest.stat().st_size > 1_000_000:
            print(f"[SKIP] {name} already present ({dest.stat().st_size/1e6:.1f} MB)")
            continue
        print(f"[GET ] {name} <- {url}")
        try:
            urllib.request.urlretrieve(url, dest)
            print(f"[OK  ] {name}  ({dest.stat().st_size/1e6:.1f} MB)")
        except Exception as exc:  # noqa: BLE001
            print(f"[FAIL] {name}: {exc}")
            print(MANUAL_LINKS)
    print("\n[OK] Datasets ready in data/raw/")
    print(MANUAL_LINKS)


if __name__ == "__main__":
    main()
