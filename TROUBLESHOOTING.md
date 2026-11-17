# 🧯 Troubleshooting & FAQ

Everything a student typically hits when running this project on their own machine — with exact fixes.

---

## Setup

**`python: command not found` / `python3` works but `python` doesn't**
Use `python3` everywhere, or install Python from python.org (Windows: tick *Add Python to PATH* during install).

**`Activate.ps1 cannot be loaded because running scripts is disabled`** (Windows)
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.venv\Scripts\Activate.ps1
```

**`pip install` installs into the global Python, not the venv**
Always activate first, then use `python -m pip install -r requirements.txt`. Check with `python -c "import sys; print(sys.executable)"` — it should point inside `.venv`.

**`ImportError: DLL load failed while importing ... An Application Control policy has blocked this file`** (Windows)
Windows Smart App Control or Defender Application Control often blocks newly installed `.pyd`/`.dll` binary extensions with a Mark-of-the-Web zone identifier. Unblock them with one command in PowerShell:
```powershell
Get-ChildItem -Path (python -c "import sys; print(sys.prefix)") -Recurse -Include '*.pyd','*.dll' | Unblock-File
```

**`ModuleNotFoundError: No module named 'src'`**
Run commands **from the project root** (`cd AI-Cybersecurity-Threat-Detection`). If you must run from elsewhere, add the root to `PYTHONPATH`, or run via `python -m src.train`. The modules already insert the project root into `sys.path`, so this only bites when the working directory or file path is unusual.

**`ModuleNotFoundError: No module named 'flask'`** → `pip install -r requirements.txt` (Flask is required for the dashboard only; everything else runs without it).

**scikit-learn / numpy version conflicts** → recreate cleanly:
```bash
rm -rf .venv && python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
```

---

## Dataset

**`FileNotFoundError: Dataset not found at .../KDDTrain+.txt`** → `python main.py download` (or `python scripts/download_datasets.py`).

**Download fails behind a corporate network/VPN/proxy** → turn off the VPN, or download manually and drop the two files into `data/raw/`:
* https://www.unb.ca/cic/datasets/nsl.html
* https://www.kaggle.com/datasets/hassan06/nslkdd
Rename them exactly `KDDTrain+.txt` and `KDDTest+.txt`.

**`data/raw` is empty after cloning someone's repo** → correct and intentional: datasets are git-ignored and recreated by the download script.

---

## Training & evaluation

**`Missing .../threat_classifier.joblib. Run: python main.py train`** → train before serving: `python main.py train`.

**Training takes minutes on Logistic Regression (~70 s)** → expected: it's a 135-dimensional, 100k-row problem with `max_iter=1000`. Random Forest is fast (~9 s). Skip LR with `--` if you're iterating: run `python -c "from src.train import train_all; train_all()"` is the full set; the baseline exists only for comparison.

**Memory error on a low-RAM laptop (≤4 GB)** → reduce the one-hot blowup by dropping rarely-used services, or train on a stratified subset:
```python
df = load_nsl_kdd("train").sample(60_000, random_state=42)
```
Metrics will shift slightly; document it.

**Metrics differ slightly from the README** → small differences are normal across library versions. The README numbers were produced with the versions in `requirements.txt` and `random_state=42`. Reproduce exactly with a fresh venv and the pinned requirements.

**U2R recall looks bad (0.70)** → known and documented; there are only 10 U2R samples in the hold-out. Report it honestly (see `MODEL_CARD.md`) — that answer earns more credit in interviews than a hidden weakness.

---

## Simulation & detection

**Every flow is classified Normal / no alerts appear** → you're probably not loading the models: confirm `python main.py info` shows `classifier: READY`. If you regenerate models, restart the dashboard process (models are loaded once at boot).

**Too many Unknown-Anomaly alerts** → the anomaly threshold is too low for your taste. Raise `ANOMALY_THRESHOLD_PERCENTILE` in `src/config.py` (e.g. 99 → 99.5), then `python main.py train` to recalibrate τ.

**A "Ping Sweep" scenario isn't detected** → ensure the ICMP rule is present in `src/detect.py` (`icmp and count >= 150 and logged_in == 0`). If you tuned the scenario's mutations (e.g. lowered `count`), the rule won't fire — that's by design; document the change.

**Simulation isn't reproducible** → pass a seed: `TrafficSimulator(seed=42).simulate(seed=42)`, or set **seed** in the `/range` form. Leaving it empty uses a random seed and each run differs (intentionally, for demos).

**`alerts.csv` grows forever** → it's overwritten on each `generate_simulation.py` run; `outputs/live_events.csv` (dashboard) is *appended*. Delete it if you want a clean session; it is git-ignored.

---

## Dashboard

**`Address already in use` (port 5000 busy)**
```bash
# macOS: AirPlay Receiver often owns 5000 → disable it, or run on another port:
python -c "import dashboard.app as a; a.app.run(host='0.0.0.0', port=5001)"
```

**Blank page / charts not rendering** → open the browser console (F12). The dashboard loads `/static/js/charts.js`; a 404 means you're running an old version of the app or serving from the wrong directory — restart with `python main.py dashboard` from the project root and hard-refresh (Ctrl+Shift+R).

**Alert feed empty but events flowing** → the severity filter may be set to something with no matches; switch it back to **All severities**.

**Dashboard shows stale data after I edited `src/detect.py`** → Flask runs with `debug=False` (no auto-reload). Stop it (Ctrl+C) and start again.

**`Empty reply from server` right after Ctrl+C** → you curled while the server was shutting down; start it again.

**Preview shows the dashboard but no live updates** → the auto-stream toggle may be paused; press **▶ Resume stream** (or the spacebar).

---

## Git & GitHub

**`git push` asks for a password and rejects it** → GitHub removed password auth. Create a Personal Access Token (Settings → Developer settings → Tokens, scope `repo`) and use it as the password, or set up SSH keys.

**`fatal: refusing to merge unrelated histories`** → you created the repo with a README on GitHub. Fix: `git pull origin main --allow-unrelated-histories`, resolve, then push.

**Accidentally committed a big dataset**
```bash
git rm --cached data/raw/KDDTrain+.txt
git commit -m "chore: stop tracking dataset (use download script)"
```
If the push already happened and the file is large, use `git filter-repo` or contact GitHub support (100 MB hard limit / 50 MB warning).

**`.venv` got committed** → `git rm -r --cached .venv && git commit -m "chore: remove virtualenv from tracking"` and confirm `.gitignore` contains `.venv/`.

**My commits are sparse/ugly** → don't rewrite history for appearances; make the *next* seven commits follow `docs/GITHUB_PLAYBOOK.md` §3 and keep pushing daily. Reviewers look at the final state and the README far more than old commit messages.

---

## Concept questions students ask

**Why does the model score 99.9% accuracy but only 73% on KDDTest+?**
Because KDDTest+ contains 17 attack types that never appear in training (e.g. `mscan`, `snmpguess`). The hold-out split is drawn from the *same distribution* as training, so it's easy; the official split is the honest generalisation test. Always report both.

**Why is U2R F1 0.737 while DoS is 1.000?**
Class imbalance: DoS has 45,927 training rows; U2R has **52**. Rare classes are simply harder — mitigated with class weights, per-class metrics and rule-based detection, and honestly documented.

**Why not deep learning?**
Flow records are tabular; gradient-boosted trees and random forests typically match or beat neural nets on tabular data, train in seconds on CPU, and are easier to explain. A deep model here would add complexity, not value — and would make the project harder for others to reproduce.

**Is the anomaly score a probability?**
No. It's a density-derived score from Isolation Forest (`-score_samples`), where higher = more unusual. A probability would require calibration against labelled anomalies — which, by definition, you don't have for novel attacks.

**Why are there both rules and ML?**
Rules give determinism and explanations (an analyst can audit them); ML gives generalisation to variations nobody wrote a rule for. Production stacks use both because their failure modes are different — that's defence in depth.

**Can I use this on my college network?**
Run the *detector* on exported flow logs (Zeek/NetFlow) only with explicit written permission. Never run the attack tools listed in the playbooks against networks you don't own — the playbooks are conceptual descriptions for the simulator, and legal trouble here can end a career before it starts.
