# 🐙 GitHub Proof Playbook

> Turning a finished project into **visible, verifiable proof of work** — repo setup, 7-day commit plan,
> screenshots, video, LinkedIn post and the placement pitch.

---

## 1. Repository setup (copy-paste)

### 1.1 Create the repo

1. github.com → **New repository**
2. **Name:** `AI-Cybersecurity-Threat-Detection`
3. **Description:** `AI-powered network intrusion detection: RandomForest + IsolationForest + signature rules, a virtual attack range with ground truth, and a live SOC dashboard. Trained on NSL-KDD.`
4. **Public** (prove the work) · do **not** initialise with README (you already have one)
5. **Topics** (Settings → Topics, or the gear next to About):
   ```
   cybersecurity  machine-learning  intrusion-detection  anomaly-detection
   scikit-learn  network-security  soc  threat-detection  nsl-kdd  ids
   random-forest  isolation-forest  mitre-attack  flask  python
   ```

### 1.2 Push from your machine

```bash
cd AI-Cybersecurity-Threat-Detection
git init
git branch -M main
git config user.name  "Your Name"
git config user.email "you@example.com"

git add .
git commit -m "feat: initial release - 3-layer AI threat detection system with virtual cyber range and SOC dashboard"
git remote add origin https://github.com/<your-username>/AI-Cybersecurity-Threat-Detection.git
git push -u origin main

git tag -a v1.0.0 -m "v1.0.0: complete detection pipeline, cyber range, live SOC console, docs, tests"
git push --tags
```

### 1.3 After pushing

* **About panel:** add the description above, the topics, and a website link (demo video or LinkedIn post).
* **Pin the repo** on your profile (Customize your pins).
* **Releases:** Releases → Draft a new release → choose tag `v1.0.0` → paste the changelog below → attach 2–3 screenshots.

<details>
<summary>Suggested v1.0.0 release notes (copy-paste)</summary>

```markdown
## 🛡️ v1.0.0 — First complete release

**Detection engine**
- Random Forest 5-class classifier (Normal / DoS / Probe / R2L / U2R)
- Isolation Forest anomaly layer trained on normal traffic only, alerting at the 99th percentile
- 14 weighted signature rules (Suricata-style) with measured false-positive justification
- Risk scoring 0–100, severity bands, MITRE ATT&CK mapping, response playbooks

**Results**
- Hold-out: F1 0.9986 · Precision 0.9995 · Recall 0.9977 · FPR 0.0004
- Official KDDTest+ (17 unseen attack types): F1 0.7351
- Live virtual cyber range (2,000 flows): F1 0.9136, 100% detection on all 9 attack playbooks

**Platform**
- Virtual cyber range: 9 attack playbooks + 5 benign profiles, with ground-truth labels
- Flask SOC console: live dashboard, cyber-range runner, model intelligence, manual threat-hunt playground
- 12 REST endpoints, 10 evidence figures, 11 passing tests, full documentation
```
</details>

---

## 2. What to commit and what never to commit

| ✅ Commit | ❌ Never commit |
|---|---|
| `src/`, `dashboard/`, `tests/`, `main.py`, `scripts/` | `data/raw/*.txt` / `*.csv` (22 MB+ — download script recreates them) |
| `requirements.txt`, `.gitignore`, `LICENSE`, README, `docs/` | `.venv/`, `__pycache__/`, `.ipynb_checkpoints/` |
| `images/*.png` (evidence figures) | `.env`, `secrets.json`, API keys |
| Small outputs: `metrics.json`, `live_metrics.json`, `model_comparison.csv`, `alerts.csv`, `dataset_summary.json` | Huge generated files (`simulated_traffic.csv` if > a few MB — it's git-ignored by default) |
| Model binaries `models/*.joblib` (optional, ~10 MB — the `.gitignore` keeps them; remove that line if you'd rather not) | Any personal or proprietary data |

---

## 3. The 7-day commit plan (expanded)

Each row is a real working session: build it, verify it, commit it, push it, screenshot it.

| Day | Build | Commands to verify | Commit message(s) | Proof to capture |
|---|---|---|---|---|
| **1** | Scaffold + data | `python main.py download` → `python src/data_loader.py` | `chore: project scaffold, config and gitignore` · `feat(data): NSL-KDD loader with attack-family taxonomy` | repo tree, `dataset_summary.json`, dataset preview head |
| **2** | Cleaning + features | `python src/feature_engineering.py` | `feat(preprocess): robust cleaning and ColumnTransformer pipeline` · `feat(features): 13 domain-driven network security features` | cleaning report, boxplots `09_engineered_features.png` |
| **3** | Models | `python main.py train` | `feat(model): RandomForest + LogisticRegression + IsolationForest stack` · `feat(model): calibrate anomaly alert threshold at p99 of normal` | training console output, `model_metadata.json` |
| **4** | Evaluation + figures | `python main.py evaluate && python main.py figures` | `feat(eval): hold-out and official KDDTest+ benchmarking` · `feat(viz): 10 report figures` · `docs: model card with honest limitations` | metrics table, confusion matrix, ROC, comparison chart |
| **5** | Cyber range + detection | `python src/simulate.py && python src/generate_simulation.py` | `feat(sim): 9-playbook virtual cyber range with ground truth` · `feat(detect): 3-layer fusion, risk scoring, MITRE mapping` · `fix(rules): tune /24 sweep rule to remove popular-server false positives` | `alerts.csv` with a CRITICAL row, per-scenario table, timeline figure |
| **6** | API + dashboard | `python main.py dashboard` | `feat(dashboard): live SOC console (4 pages, 12 endpoints)` · `feat(api): manual threat-hunt playground` | screenshots of `/`, `/range`, `/model`, `/docs` |
| **7** | Tests, docs, release | `python main.py test` | `test: pytest suite covering schema, features, engine and simulator` · `docs: project guide, architecture, simulation guide, interview Q&A` · `chore: tag v1.0.0` | `11 passed`, README preview, GitHub Release page |

**Commit hygiene rules:** one logical change per commit; present-tense imperative; no "final"/"asdf"; push daily (a green graph across the week proves consistency); never commit broken code to `main` — run `python main.py test` first.

---

## 4. Screenshots — exact list, naming and storage

Store in `docs/screenshots/`, then embed in the README:

```html
<img src="docs/screenshots/06-dashboard-live.png" width="900"/>
```

| # | File name | Capture | Notes |
|---|---|---|---|
| 1 | `01-dataset-preview.png` | pandas `head()` of KDDTrain+ + class counts | shows 43 columns and the imbalance |
| 2 | `02-training-logs.png` | terminal after `python main.py train` | includes the p99 threshold line |
| 3 | `03-metrics-tables.png` | terminal after `python main.py evaluate` | hold-out + official split |
| 4 | `04-simulation-run.png` | terminal after `python main.py simulate` | per-scenario table (100% rows) |
| 5 | `05-alert-csv.png` | `outputs/alerts.csv` with a CRITICAL row highlighted | VS Code or Excel |
| 6 | `06-dashboard-live.png` | the `/` console mid-stream | include KPIs + alert feed |
| 7 | `07-range-report.png` | `/range` after an exercise | per-scenario bars + verdict table |
| 8 | `08-threat-hunt.png` | `/docs` verdict panel after the SSH brute-force preset | shows evidence + playbook |
| 9 | `09-model-intel.png` | `/model` metric tables + feature importance | engineered features highlighted |
| 10 | `10-github-repo.png` | your repo home page | topics, description, pinned |

**Screenshot tips:** maximise the window, use a dark browser theme to match the dashboard, capture at 1920×1080 or wider, crop out bookmarks/personal tabs, and never include API keys or personal folders in the frame.

---

## 5. Demo video (60–90 s)

Full script: [SIMULATION_GUIDE.md §8](SIMULATION_GUIDE.md#8-screenshots--video-proof).

How to record: **Windows** → Win+G (Xbox Game Bar) or OBS · **macOS** → QuickTime screen recording · **Linux** → OBS/simplescreenrecorder. Host it on YouTube (unlisted) or Loom and put the link **at the top of the README** and in the repo's Website field.

Keep it under 90 seconds, speak over it, show *results* more than code, and never show a terminal with credentials.

---

## 6. LinkedIn post template (copy-paste, edit the brackets)

```
🛡️ I built an AI-powered Cybersecurity Threat Detection System — and it's live on GitHub.

Attackers use AI now; defences that rely only on static rules can't keep up. So I built a detector that thinks in three layers:

1️⃣ Random Forest — classifies network flows into DoS / Probe / R2L / U2R
2️⃣ Isolation Forest — trained only on normal traffic, so it flags behaviour nobody has seen before
3️⃣ Signature rules — explains *why* in plain English (brute force, SYN flood, scans, exfiltration)

Results I measured on the NSL-KDD benchmark:
• Hold-out: F1 0.9986 · Precision 0.9995 · Recall 0.9977 · FPR 0.0004
• Official KDDTest+ (17 unseen attack types): F1 0.7351 — reported honestly
• Virtual cyber range: 100% detection across 9 attack playbooks, F1 0.9136 live

It ships with a virtual attack lab (9 real-world playbooks — hping3 SYN flood, nmap scan, hydra brute force, privilege escalation, data exfiltration), a live SOC dashboard with alert triage by MITRE ATT&CK technique and response playbooks, 12 REST endpoints, 11 passing tests and full docs.

No corporate SOC? Build one. 🔗 [repo link]

#cybersecurity #machinelearning #intrusiondetection #soc #python #scikitlearn #threatdetection #recruitment
```

**Post timing:** weekday morning IST; attach 3–4 screenshots (dashboard, range report, alert evidence, metrics); reply to every comment; pin the post on your profile.

---

## 7. Placement pitch (35-second spoken version)

> "I built an AI-powered network intrusion detection system on the NSL-KDD benchmark. It runs three detection layers — a Random Forest that classifies DoS, Probe, R2L and U2R attacks, an Isolation Forest trained only on normal traffic so it catches unseen behaviour, and fourteen explainable signature rules. Every alert carries a risk score, severity, MITRE ATT&CK technique, evidence and a response playbook.
> On the held-out split it scores F1 0.9986 with a false-positive rate of 0.0004; on the harder official split with 17 unseen attack types, F1 0.735 — I report both because the second one is the realistic number.
> To prove the whole thing end-to-end, I built a virtual cyber range with nine attack playbooks and ground-truth labels, plus a live SOC dashboard where you can watch attacks stream in and be classified. It's on GitHub with tests, docs and reproducible metrics — I'd be glad to walk you through it."

**Resume one-liner:**
`AI Threat Detection System — 3-layer NIDS (RandomForest + IsolationForest + rules) on NSL-KDD; F1 0.9986 hold-out / 0.7351 official split; virtual attack range with ground truth + live SOC dashboard (Flask, 12 APIs). GitHub: <link>`

---

## 8. Final proof checklist

- [ ] Repo public, README with hero images, description + 15 topics, pinned on profile
- [ ] `python main.py all` reproduces every number in the README
- [ ] `python main.py test` → 11 passed, shown in a screenshot
- [ ] 10 screenshots in `docs/screenshots/` (list above)
- [ ] 60–90 s demo video linked at the top of the README
- [ ] Release `v1.0.0` published with changelog + screenshots
- [ ] LinkedIn post published with 3–4 images and the repo link
- [ ] Repo link on CV/resume and GitHub profile README
- [ ] 10 interview answers rehearsed ([INTERVIEW_QA.md](INTERVIEW_QA.md))
- [ ] Commit history shows the 7-day build (consistent green squares)
