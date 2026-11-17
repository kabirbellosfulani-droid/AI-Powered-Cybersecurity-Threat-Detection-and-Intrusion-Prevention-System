# 📘 The Complete Project Guide
## AI-Powered Cybersecurity Threat Detection System — from zero to a GitHub-ready proof-of-work project

> **Who this is for:** students who want a realistic, industry-aligned cybersecurity + AI/ML project
> without access to a corporate SOC. Everything here is grounded in what this repository actually
> does — every command, file and number can be reproduced on your laptop in ~2 minutes.

**Contents:** [A. Explanation](#a-project-explanation) · [B. Tech stack options](#b-tech-stack-options) · [C. Selected approach](#c-selected-approach) · [D. Architecture](#d-architecture) · [E. Folder structure](#e-folder-structure) · [F. Installation](#f-installation) · [G. Code](#g-code-walkthrough) · [H. Simulation](#h-virtual-cyber-threat-simulation) · [I. Execution](#i-how-to-run) · [J. GitHub steps](#j-github-upload-strategy) · [K. README](#k-readme-file-explained) · [L. Commit plan](#l-7-day-commit--proof-plan) · [M. Proof checklist](#m-proof-checklist)

---

## A. Project explanation

### A.1 In simple language

Imagine a company's office building. There's a security guard at the gate checking IDs. That guard works from a **list of rules**: "no ID? stop them." That is a **traditional firewall/antivirus** — it only catches what somebody already wrote a rule for.

Now imagine a new person walks in wearing a uniform nobody has seen before, carrying a bag that looks slightly odd. The rule-based guard says "their ID says employee, fine." A **trained human analyst** would get suspicious: *nobody wears that uniform, they're walking toward the server room, and they scanned the room while entering.* They'd stop them and check.

**AI-powered threat detection is that analyst, automated and running at machine speed.** It learns what *normal* looks like — usual volumes, usual destinations, usual login patterns — and raises a flag when behaviour deviates, even if the attacker uses a technique nobody has seen before.

This project builds that analyst. It watches network connections (each described by 41 numbers like connection duration, bytes sent, failed logins, error rates), and for each one it decides:

1. Is this **benign** or **malicious**?
2. If malicious, **which family** — DoS (flooding), Probe (scanning), R2L (remote intrusion), U2R (privilege escalation)?
3. **How risky** is it, 0–100?
4. **Why** does it look bad? (evidence, in plain English)
5. **What should the analyst do** about it? (response playbook)

### A.2 The problems it solves

| Problem in the real world | How this system addresses it |
|---|---|
| **Unknown attacks** — new malware/variants with no signature | Unsupervised **Isolation Forest** trained only on normal traffic → flags "never seen anything like this" |
| **Alert fatigue** — rule engines fire thousands of useless alerts | Risk scoring + calibrated thresholds (99th percentile) + evidence strings so analysts can triage fast |
| **Slow human review** — logs are too big for humans | Vectorised ML scoring of ~100k flows in seconds |
| **Flat, useless alerts** — "something happened" is not actionable | Every alert carries severity, MITRE ATT&CK technique, evidence, and a recommended response |
| **No visibility into WHY** — black-box models | Transparent signature rules run alongside ML, so each alert has a human-readable reason |
| **Rare attack types** (U2R: 0.04% of data) | Class weighting, per-class metrics, honest reporting of the weak spot |

### A.3 Why this matters in an AI-driven world

Attackers now use AI: automated phishing, LLM-written malware, adaptive scanning that mimics normal traffic. Defenders must match that speed. Static rules cannot keep up because *a rule must exist before it can catch anything*. ML-based detection inverts the problem: instead of enumerating bad, we model good, and treat deviation as suspicious. That is why every major security vendor (Microsoft Defender, Google Chronicle, CrowdStrike Falcon, Palo Alto Cortex, Splunk UBA, IBM QRadar) ships ML/behavioural analytics as a core layer — and why "AI + security" is one of the highest-demand skill intersections in the job market.

### A.4 In technical language

We solve **binary and multi-class classification of network flow records** derived from connection-level telemetry (the feature space of NSL-KDD: 41 features spanning basic flow attributes, content indicators and time-window traffic statistics).

Formally: learn `f: X → Y` where `X ⊂ ℝ⁴¹⁺` and `Y ∈ {Normal, DoS, Probe, R2L, U2R}`, plus an unsupervised density model `g: X → ℝ` estimating "normalness", plus a rule function `r: X → 2^R` (evidence set). The final decision is a **fusion** over model posteriors, anomaly scores and rule strengths, producing a calibrated risk score `ρ ∈ [0,100]` and severity band.

Key engineering properties:
* **Train/serve parity** via a serialised `ColumnTransformer` (OneHot + StandardScaler) reused by the API.
* **Class imbalance** handled with `class_weight='balanced_subsample'`, macro-averaged reporting and per-class recall.
* **Anomaly threshold calibration**: `τ = P99(scores of normal training traffic)`, trading recall for a 0.0103 false-positive rate.
* **Recall-optimised fusion** (OR-voting) with precision guarded by rule-strength gating (strong rule = weight 2, supporting = weight 1; alert needs ≥ 2).
* **Explainability** through rule attribution plus Gini feature importances, so every alert is auditable.

### A.5 How companies use such systems

| Sector | Use case | Where this project's concepts appear |
|---|---|---|
| **Banks / fintech** | Real-time fraud detection; anomalous transaction and login sequences; insider risk | Anomaly detection + risk scoring + explainable alerts |
| **IT services / MSSPs** | Multi-tenant NIDS/NDR: detect intrusions per customer, triage queues, SLAs | Layered detection + severity + MITRE mapping + dashboard |
| **Cloud/product companies** (Google, Microsoft, AWS) | Behaviour analytics on IAM/API telemetry; DDoS mitigation; malware classification | Unsupervised detection of "unknown unknowns", volumetric flood features, feature engineering |
| **Security vendors** (CrowdStrike, Palo Alto, Splunk) | Ship ML models as product features: detection rules + behavioural models + analyst UX | Model + rules fusion, alert enrichment, SOC UI |
| **Government / critical infrastructure** | OT/IT network monitoring, zero-day defence, forensic timelines | Anomaly-first detection, evidence trails, ground-truth-driven evaluation |

Real SOC escalation flow this project imitates:
`telemetry → detection (rules + ML) → risk/severity enrichment → alert queue → analyst triage → response playbook → post-incident report`.

### A.6 The complete workflow (what happens to a single flow)

```
1. DATA COLLECTION      Network flow records arrive (real: Zeek/Suricata logs, pcap → flow
                        tuples; here: NSL-KDD corpus + virtual cyber range).
2. VALIDATION           Schema check: 43 fields present, types correct, label mapped to a family.
3. PREPROCESSING        Drop 'difficulty' meta-column · inf→NaN · median imputation ·
                        categorical fill · de-duplicate · OneHot encode categoricals ·
                        StandardScaler on numerics → 135 model columns.
4. FEATURE ENGINEERING  13 domain features: total_bytes, bytes_ratio, byte_asymmetry,
                        dos_intensity, host_scan_ratio, service_concentration, login_anomaly,
                        privilege_score, payload_per_packet, traffic_entropy,
                        is_wellknown_port, error_flag_count, critical_service.
5. TRAINING             RandomForest (200 trees, class-balanced), LogisticRegression baseline,
                        IsolationForest (normal-only, contamination 0.15).
6. PREDICTION           Multi-class label + per-class probability + anomaly score.
7. FUSION/SCORING       risk = 45·P(attack) + 35·anomaly_norm + 12·rules + 8·class-trust → 0-100.
8. ALERT GENERATION     Severity band · MITRE technique · evidence string · response playbook ·
                        alert ID · timestamp · src/dst IP · service.
9. VISUALISATION        SOC dashboard (live KPIs, timeline, donut, heatmaps, alert feed) +
                        10 static evidence figures for reports.
10. FEEDBACK LOOP       Live precision/recall computed against ground truth; thresholds and rules
                        tuned from measured false-positive impact (e.g. the ICMP rule was adopted
                        after measuring 1 benign hit out of 67,343 flows).
```

---

## B. Tech stack options

### Option A — "Easiest" (weekend notebook)
* **Tools:** Python, pandas, NumPy, scikit-learn, Matplotlib, Jupyter/Colab
* **Dataset:** NSL-KDD (`KDDTrain+.txt`), binary label (normal vs attack)
* **Model:** Logistic Regression / Decision Tree / Isolation Forest
* **Difficulty:** ⭐☆☆☆☆ · **GPU:** not needed · **Time:** 4–8 hours
* **Output:** one notebook, ~90% accuracy, 2–3 plots
* **GitHub value:** low-medium (thousands of identical notebooks exist)

### Option B — "Intermediate" (what this repository is)
* **Tools:** Option A + modular `src/` package, RandomForest multi-class, IsolationForest, feature engineering, Flask REST API, live dashboard, pytest, docs
* **Dataset:** NSL-KDD (labelled, 4 attack families) + **virtual cyber-range simulator with ground truth**
* **Difficulty:** ⭐⭐⭐☆☆ · **GPU:** not needed · **Time:** 2–4 days
* **Output:** trained model artefacts, metrics tables, 10 figures, live SOC console, alerts.csv, README with real numbers
* **GitHub value:** **high** — looks like an engineering deliverable, not homework

### Option C — "Advanced" (capstone scale)
* **Tools:** Option B + XGBoost/LightGBM, PyTorch autoencoder or LSTM, SHAP explainability, Docker, GitHub Actions CI, MLflow/DVC model registry, Kafka/stream ingestion, Elasticsearch+Kibana or Grafana dashboard, cloud deployment (AWS/GCP/Azure)
* **Dataset:** CICIDS2017 + UNSW-NB15 (+ CIC-DDoS2019), Zeek/Suricata real captures, optional live Scapy sniffing
* **Difficulty:** ⭐⭐⭐⭐⭐ · **GPU:** optional (helps for deep models) · **Time:** 3–6 weeks
* **Output:** scalable NDR platform with drift monitoring, multi-dataset benchmarking, deployment pipeline
* **GitHub value:** very high, but only if finished and documented — many students abandon it half-done

---

## C. Selected approach

**Option B — Intermediate — is the right choice for a student optimising for placements.**

| Requirement | Why Option B wins |
|---|---|
| Strong GitHub proof | Modular code, tests, docs, real metrics, screenshots, working demo |
| Easy execution | CPU-only, ~2 minutes end-to-end, `python main.py all` |
| Practical understanding | You touch every stage: EDA → features → models → evaluation → serving → UI |
| Interview surface | Enough depth to discuss imbalance, anomaly detection, FP/FN trade-offs, architecture |
| Finishable | Complete in a week of evenings — finishing is what recruiters reward |

**Chosen stack (exactly what's in this repo):** Python 3.9+, pandas/NumPy, scikit-learn (RandomForest + IsolationForest + LogisticRegression baseline), matplotlib/seaborn, Flask + vanilla JS dashboard, pytest, Git/GitHub.

**Deliberate exclusions and why:** no deep learning (overkill for tabular flow data, hurts reproducibility on CPU), no live packet capture in the core path (permissions/driver issues would break the demo on other people's machines — it's documented as a roadmap item), no external CDNs (the dashboard must work offline/in sandboxes).

---

## D. Architecture

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the full diagram, module contracts and data-flow table. Short version:

```
Sources (NSL-KDD + Cyber Range)
   → Ingest & validate (43 fields)
   → Clean (dedupe, impute, type-normalise)
   → Feature engineering (+13 domain features)
   → Preprocessing pipeline (OneHot + Scaler, saved once)
   → ┌ RandomForest (5-class)  ┐
     │ IsolationForest (p99)    │ → Fusion & risk scoring → Alerts
     │ 14 signature rules       ┘        (severity, MITRE, evidence, playbook)
   → Outputs: dashboard · REST API · alerts.csv · metrics.json · figures
```

**Data flow (single flow, millisecond view):**

| Step | Module | Input | Output |
|---|---|---|---|
| Ingest | `data_loader` / `simulate` | raw 43-field record | typed DataFrame |
| Transform | `preprocess.transform_new` | raw features | 135-column vector |
| Classify | `detect.ThreatDetector.predict` | vector | class + probability |
| Anomaly | IsolationForest | vector | anomaly score vs τ |
| Evidence | `detect.signature_rules` | raw row | weighted reasons |
| Fuse | risk formula | all of the above | risk 0–100, severity |
| Alert | `build_alerts` | scored rows | alert row (ID, MITRE, action) |
| Serve | `dashboard/app.py` | alerts | JSON API + live console |

---

## E. Folder structure

Explained in depth in the [README](../README.md#-folder-structure). Design principles applied:

* `data/raw` is **git-ignored** (datasets are large; the downloader recreates them) while `data/processed` keeps small CSVs useful for reports.
* `src/` holds pure logic with **no Flask imports** → it can be unit-tested and reused in a notebook, a Lambda, or an Airflow DAG.
* `dashboard/` is a thin presentation layer over the REST API.
* `models/` stores versioned artefacts; `outputs/` stores evidence (metrics, alerts); `images/` stores figures referenced by the README.
* `docs/` separates the *engineering* docs (architecture, model card) from the *career* docs (interview Q&A, GitHub playbook).
* `tests/` proves the pipeline's contracts — a signal of engineering maturity.

---

## F. Installation

### F.1 Requirements

* Python **3.9 – 3.13** (tested on 3.13)
* ~500 MB disk (dataset 22 MB + environment)
* No GPU, no admin rights, no cloud account

### F.2 Steps (Windows)

```powershell
git clone https://github.com/<your-username>/AI-Cybersecurity-Threat-Detection.git
cd AI-Cybersecurity-Threat-Detection
python -m venv .venv
.venv\Scripts\Activate.ps1            # if blocked: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
python -m pip install --upgrade pip
pip install -r requirements.txt
python main.py info                   # should report dataset MISSING
python main.py download
python main.py all
python main.py dashboard
```

### F.3 Steps (macOS / Linux)

```bash
git clone https://github.com/<your-username>/AI-Cybersecurity-Threat-Detection.git
cd AI-Cybersecurity-Threat-Detection
python3 -m venv .venv && source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python main.py download && python main.py all
python main.py dashboard               # open http://127.0.0.1:5000
```

### F.4 Creating `requirements.txt` yourself

```bash
pip freeze > requirements.txt          # then trim the unrelated packages
```

Common setup traps: activating the venv **after** installing packages globally; running `pip` instead of `python -m pip` (wrong interpreter); forgetting to activate the venv in a new terminal; corporate proxies blocking the download (use the manual dataset links printed by `download_datasets.py`).

---

## G. Code walkthrough

Every file's purpose, key function and the concept it teaches:

| File | Key functions | What to learn from it |
|---|---|---|
| `src/config.py` | `NSL_KDD_COLUMNS`, `ATTACK_CATEGORY_MAP`, `SEVERITY_MAP`, `MITRE_MAP`, `RESPONSE_PLAYBOOK`, hyper-params | Central configuration; security taxonomy lives in data, not scattered through code |
| `src/data_loader.py` | `load_nsl_kdd`, `dataset_summary` | Reading headerless benchmark data, mapping 24 raw attacks → 4 families, dataset statistics |
| `src/feature_engineering.py` | `add_engineered_features` (13 features), `select_model_features` | Domain-driven feature design; avoiding data leakage (features use only input columns) |
| `src/preprocess.py` | `clean_dataframe`, `build_preprocessor`, `prepare_training_data`, `transform_new` | sklearn `ColumnTransformer`/`Pipeline`, train/serve parity, robust handling of partial input |
| `src/train.py` | `train_classifier`, `train_anomaly_detector`, `train_all` | Three-model design, class weighting, anomaly threshold calibration on normal-only scores |
| `src/evaluate.py` | `evaluate_classifier`, `evaluate_anomaly_detector`, `run_full_evaluation` | Precision/recall/F1/FPR/AUC, confusion matrices, hold-out **and** official split generalisation testing |
| `src/detect.py` | `ThreatDetector.predict`, `predict_one`, `signature_rules`, `build_alerts` | ⭐ The inference engine: layered detection, weighted rule evidence, risk fusion, alert construction |
| `src/simulate.py` | `TrafficSimulator.simulate`, `make_event`, `SCENARIOS`, `catalog` | ⭐ The cyber range: parameterising real records into named attack playbooks with ground truth |
| `src/generate_simulation.py` | `main` | Reproducible exercise runner; live metrics vs ground truth; writes `alerts.csv` |
| `src/visualize.py` | 10 `fig_*` functions | Communicating results: distribution, confusion matrix, ROC, importance, timelines |
| `dashboard/app.py` | `ingest`, `stream_events`, all `/api/*` routes | Stateful service design: locks, deques, warm-up, JSON-safe numpy handling |
| `dashboard/static/js/charts.js` | `lineChart`, `donut`, `hBars`, `heatmap`, `gauge` | Building SVG charts with zero dependencies |
| `tests/test_pipeline.py` | 11 tests | Contract testing: schema, features, engine behaviour, simulator reproducibility |
| `main.py` | subcommands | CLI orchestration; how a repo becomes usable by strangers |

**The most important 30 lines to understand** — the risk fusion in `src/detect.py`:

```python
if ml_attack:
    label = pred[i]                      # supervised model is confident
elif weird:
    label = "Unknown-Anomaly"            # anomaly layer: unseen behaviour
else:
    label = "Normal"

if label == "Normal" and rule_score >= 2:
    label = "Unknown-Anomaly"            # rules override the models

risk = (45 * attack_prob[i]              # model confidence
        + 35 * anomaly_norm[i]           # behavioural unusualness
        + 12 * min(rule_score, 4)        # strength of signature evidence
        + 8 * (label not in ("Normal", "Unknown-Anomaly")))  # known class bonus
```

### G.1 Beginner-friendly baseline version

If you're building this from scratch for the first time, start with this minimal script, then grow it into the full repository:

```python
"""minimal_threat_detector.py — the 30-line starting point."""
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report

COLS = [...]  # the 43 NSL-KDD column names (see src/config.py)

# 1. load
df = pd.read_csv("data/raw/KDDTrain+.txt", names=COLS, header=None)
df["is_attack"] = (df["label"].str.strip().str.rstrip(".") != "normal").astype(int)

# 2. prepare (drop non-numeric + label columns for a quick baseline)
X = df.drop(columns=["label", "difficulty"])
X = pd.get_dummies(X, columns=["protocol_type", "service", "flag"])
y = df["is_attack"]

# 3. split + scale
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2,
                                                    random_state=42, stratify=y)
sc = StandardScaler().fit(X_train)
X_train, X_test = sc.transform(X_train), sc.transform(X_test)

# 4. train
model = RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=42).fit(X_train, y_train)
print(classification_report(y_test, model.predict(X_test), digits=4))

# 5. unsupervised check on normal traffic only
iso = IsolationForest(contamination=0.15, random_state=42).fit(X_train[y_train == 0])
print("Isolation Forest agreement:",
      ((iso.predict(X_test) == -1).astype(int) == y_test).mean().round(4))
```

Then upgrade step by step: add the engineered features → save the pipeline → add the rule layer → add the simulator → add the API → add the dashboard. That progression is exactly the commit history recommended in [the 7-day plan](#l-7-day-commit--proof-plan).

---

## H. Virtual cyber-threat simulation

### H.1 How the dataset represents real traffic

Each NSL-KDD row is one **connection** summarised by 41 features — precisely the kind of tuple a flow exporter (Zeek `conn.log`, NetFlow) emits:

| Feature group | Examples | Security meaning |
|---|---|---|
| Basic | `duration`, `protocol_type`, `service`, `src_bytes`, `dst_bytes` | size/direction/target of a conversation |
| Content | `num_failed_logins`, `logged_in`, `root_shell`, `num_compromised`, `hot` | what happened inside the session |
| Traffic (window) | `count`, `srv_count`, `serror_rate`, `rerror_rate`, `diff_srv_rate`, `dst_host_*` | behaviour of the source over a recent window — the fingerprint of floods and scans |

### H.2 How attacks appear (and what the model keys on)

| Attack | Real-world shape | Feature fingerprint | Detection layer that catches it |
|---|---|---|---|
| **DoS** (neptune/smurf/back) | flood of half-open/rejected connections | `serror_rate≈1`, `count` 400–511, 0 bytes | RF class + SYN-flood rule |
| **Probe** (nmap/satan/portsweep) | scan across ports/hosts | `dst_host_count` high vs `srv_count` low, `diff_srv_rate` high | RF class + sweep rules |
| **R2L** (guess_passwd, warezmaster) | credential attacks / remote file access | `num_failed_logins`, `logged_in=0`, `hot`>0, `num_access_files`>0 | rules (models under-weight rare classes) + anomaly layer |
| **U2R** (buffer_overflow, rootkit) | local exploit → root | `root_shell=1`, `num_root`>0, `num_shells`>0, `num_compromised`>0 | rules dominate (only 52 training samples) + anomaly layer |

### H.3 Step-by-step simulation workflow

**Step 1 — Download the corpus** (`python main.py download`). This is the "intelligence database": 125,973 labelled connections showing what each attack family looks like on the wire.

**Step 2 — Train the engines** (`python main.py train`). RandomForest learns the families; IsolationForest learns only *normal*; the rule set is fixed and transparent.

**Step 3 — Choose a scenario mix.** 5 benign service profiles + 9 attack playbooks: SYN flood, HTTP flood, port scan, ping sweep, SSH brute force, FTP password guessing, web-injection probe, privilege escalation, data exfiltration.

**Step 4 — Generate a capture** (`python src/simulate.py` → `outputs/simulated_traffic.csv`). Attacks are scattered **randomly** across the timeline with burstiness (campaigns arrive in waves), because real adversaries don't queue politely.

**Step 5 — Score every flow** (`ThreatDetector.predict`). Each flow gets: class, confidence, anomaly score, risk, severity, MITRE technique, evidence, action.

**Step 6 — Build the incident queue** (`build_alerts`) → `outputs/alerts.csv`, enriched with alert IDs, timestamps and source/destination IPs.

**Step 7 — Measure honestly** (`src/generate_simulation.py`) → live precision/recall/F1 against the injected ground truth, plus a per-scenario detection table.

**Step 8 — Watch it live** (`python main.py dashboard` → `/range` and `/`). Stream events, inject a burst, filter by severity, read the evidence.

**Step 9 — Capture proof.** Screenshots + a 60–90s screen recording (script in [`SIMULATION_GUIDE.md`](SIMULATION_GUIDE.md)).

### H.4 What to generate, highlight and capture

* **Outputs to produce:** `simulated_traffic.csv`, `simulation_scored_events.csv`, `alerts.csv`, `live_metrics.json`, 10 PNG figures.
* **Graphs to create:** class distribution, attack-type distribution, feature importance, confusion matrix, model comparison, anomaly-score separation, ROC curve, live detection timeline, engineered-feature boxplots, risk histogram.
* **Anomalies to highlight:** the SYN-flood flow with `serror_rate=1.00`; the scan with `dst_host_count=255, srv_count=12`; the brute-force flow with 6 failed logins and no session; the exfiltration flow with 120 kB out / 8 bytes in; a privilege-escalation alert with `root_shell=1`.
* **Proof to capture:** dataset preview, training logs, metrics tables, alert table with evidence, dashboard screenshots per page, and the per-scenario 100% detection report.

---

## I. How to run

| Task | Command | Expected result |
|---|---|---|
| Check everything is present | `python main.py info` | dataset FOUND/READY, benchmark metrics line |
| Train | `python main.py train` | RF ~9 s, LR ~72 s, IF ~1 s; 3 `.joblib` files + metadata |
| Evaluate | `python main.py evaluate` | metrics table printed, `metrics.json`, `model_comparison.csv` |
| Figures | `python main.py figures` | 10 PNGs in `images/` |
| Simulate | `python main.py simulate` | 2,000 flows, ~434 alerts, precision 0.84 / recall 1.00 |
| Console | `python main.py dashboard` | live SOC UI at http://127.0.0.1:5000 |
| Score your own CSV | `python main.py predict myflows.csv` | `outputs/predictions.csv` + JSON summary |
| Tests | `python main.py test` | `11 passed` |

### What "successful detection" looks like

* **Training:** no NaN warnings; classes listed as `Normal/DoS/Probe/R2L/U2R`; anomaly threshold printed (≈0.5434 = p99 of normal scores).
* **Evaluation:** hold-out F1 ≈ 0.9986 (RF); official-split F1 ≈ 0.735 (harder); RF FPR ≈ 0.0004.
* **Live:** recall 1.00 and every scenario at 100% on the simulated range, with precision ≈ 0.84 (the 16% are the genuinely ambiguous Probe/sweep flows — documented, not hidden).
* **Alert feeding:** CRITICAL alerts contain privilege-escalation/exfiltration evidence; HIGH alerts contain flood/brute-force evidence.

Common mistakes to avoid: fitting the scaler on the full dataset before splitting (**leakage**); encoding categoricals *after* train/test split inconsistently (**mismatched columns**); using default IsolationForest thresholds for alerting (**alert fatigue**); reporting only accuracy on a 46%-attack dataset (**misleading**); forgetting `class_weight` (**minority classes vanish**); not saving the preprocessor (**train/serve skew**).

---

## J. GitHub upload strategy

### J.1 Repository naming, description, topics

* **Name:** `AI-Cybersecurity-Threat-Detection` (clear, searchable, matches the domain)
* **Description:** `AI-powered network intrusion detection: RandomForest + IsolationForest + signature rules, a virtual attack range with ground truth, and a live SOC dashboard. Trained on NSL-KDD.`
* **Topics:** `cybersecurity` `machine-learning` `intrusion-detection` `anomaly-detection` `scikit-learn` `network-security` `soc` `threat-detection` `nsl-kdd` `python` `flask` `random-forest` `isolation-forest` `ids` `mitre-attack`
* **Website field:** link to your LinkedIn post or demo video.
* **Pin it** on your profile; add the repo to your CV/resume project section.

### J.2 Push commands (first time)

```bash
cd AI-Cybersecurity-Threat-Detection
git init
git branch -M main
git add .
git commit -m "feat: initial commit - AI-powered threat detection system (model, cyber range, SOC dashboard)"
git remote add origin https://github.com/<your-username>/AI-Cybersecurity-Threat-Detection.git
git push -u origin main
```

Then each day follows the loop: `git add <files>` → `git commit -m "<type>: <what and why>"` → `git push`.

### J.3 Commit-message conventions (Conventional Commits)

`feat:` new capability · `fix:` bug fix · `docs:` documentation · `test:` tests · `refactor:` restructuring · `chore:` tooling/config · `perf:` performance.

Good: `feat(model): add IsolationForest layer with p99 anomaly threshold`
Bad: `update`, `changes`, `final`, `asdf`.

### J.4 Making uploads professional

* Commit **code, docs, tests, small outputs** (`metrics.json`, `alerts.csv` sample, `model_comparison.csv`) and **figures** — never raw datasets or `.venv`.
* Keep `models/*.joblib` committed only if you want instant-run demos; otherwise note in the README that `python main.py train` regenerates them.
* Add screenshots to `docs/screenshots/` and embed them in the README (`<img src="docs/screenshots/dashboard.png" width="800"/>`).
* Add a demo video (60–90 s, MP4/Loom/YouTube) and link it at the top of the README.
* Tag a release: `git tag -a v1.0.0 -m "First complete release" && git push --tags` → create a GitHub Release with a short changelog and screenshots.
* Turn on branch protection-free simplicity: keep `main` green by running `python main.py test` before pushing.

---

## K. README file explained

The repository's [`README.md`](../README.md) already implements this structure — recruiter-friendly order:

1. **Title + one-line pitch + badges** — what it is in 5 seconds.
2. **Hero images** — confusion matrix + live timeline (proof, immediately).
3. **Table of contents** — long READMEs need navigation.
4. **What this project is** — plain-English summary + the 3-layer detection table.
5. **Why it matters (industry relevance)** — banks/IT/product companies, mapping to the workflow they use.
6. **Key results** — accuracy/precision/recall/F1/FPR tables, per-scenario detection, feature-importance highlight. **Real numbers, reproducible commands.**
7. **Architecture** — ASCII diagram + link to the deep-dive doc.
8. **Virtual cyber range** — the 9 playbooks table (recruiters love this because it shows domain knowledge).
9. **SOC dashboard** — what each page does (with screenshots).
10. **Tech stack · Dataset · Folder structure** — the "can I run this?" section.
11. **Quick start + How to run** — copy-paste commands, Windows notes in a `<details>` block.
12. **API reference** — curl examples with real responses.
13. **Testing** — 11 passing tests.
14. **Design decisions** — *why* each choice was made (this is what separates you from tutorial copiers).
15. **Limitations & honest evaluation** — the mark of an engineer, and a great interview hook.
16. **Roadmap · Learning outcomes · Author · License.**

---

## L. 7-day commit & proof plan

| Day | Focus | Commit(s) | Proof to capture |
|---|---|---|---|
| **1** | Setup: repo, venv, folder skeleton, `config.py`, `data_loader.py`, dataset downloaded | `chore: project scaffold + config` · `feat(data): NSL-KDD loader with attack-family mapping` | repo tree screenshot, dataset preview (`dataset_preview.csv` head), `dataset_summary.json` |
| **2** | Preprocessing + feature engineering | `feat(preprocess): cleaning + ColumnTransformer pipeline` · `feat(features): 13 domain-driven security features` | cleaning report JSON, engineered-features table, boxplot figure `09_engineered_features.png` |
| **3** | Models + training | `feat(model): RandomForest + IsolationForest + LR baseline` · `feat(model): calibrate anomaly threshold at p99` | training logs (tree counts, timings, threshold), `model_metadata.json` |
| **4** | Evaluation | `feat(eval): hold-out + official KDDTest+ metrics` · `docs: add model card with honest limitations` | metrics tables, `04_confusion_matrix_rf.png`, `07_roc_curve.png`, `05_model_comparison.png` |
| **5** | Cyber range + detection engine | `feat(sim): 9-playbook virtual cyber range with ground truth` · `feat(detect): 3-layer fusion with risk scoring and MITRE mapping` | `simulated_traffic.csv` head, `alerts.csv` with CRITICAL rows, per-scenario detection table, `08_live_detection_timeline.png` |
| **6** | Dashboard + API | `feat(dashboard): live SOC console (4 pages, 12 API endpoints)` · `feat(api): manual threat-hunt playground` | screenshots of `/`, `/range`, `/model`, `/docs`; curl output of `/api/predict` |
| **7** | Polish, docs, release | `test: pytest suite (11 tests)` · `docs: README, project guide, interview Q&A, simulation guide` · `chore: tag v1.0.0` | test output (`11 passed`), README preview screenshot, GitHub Release page, LinkedIn post + demo video link |

Every commit should be **small, meaningful and pushed the same day** — a green commit graph across the week *is* the proof of consistent work.

---

## M. Proof checklist

**Repository essentials**
- [ ] README with hero figures, real metrics and copy-paste commands
- [ ] `requirements.txt`, `LICENSE` (MIT), `.gitignore` (no datasets/venv committed)
- [ ] Modular `src/`, working `main.py` CLI, tests passing
- [ ] 10 evidence figures in `images/`
- [ ] `docs/` — project guide, architecture, model card, simulation guide, interview Q&A, GitHub playbook, troubleshooting
- [ ] Repo topics + description + pinned on profile

**Screenshots to capture** (save into `docs/screenshots/`, name them exactly so the README works)

| File name | What to capture | How |
|---|---|---|
| `01-dataset-preview.png` | First rows of `KDDTrain+` + class counts | Jupyter/pandas `head()` |
| `02-training-logs.png` | Console output of `python main.py train` | terminal screenshot |
| `03-metrics-tables.png` | Hold-out + official-split tables | terminal or `/model` page |
| `04-confusion-matrix.png` | `images/04_confusion_matrix_rf.png` | already generated |
| `05-anomaly-separation.png` | `images/06_anomaly_score_distribution.png` | already generated |
| `06-dashboard-live.png` | `/` with KPIs, timeline, alert feed | browser screenshot |
| `07-range-report.png` | `/range` after an exercise (per-scenario 100%) | browser screenshot |
| `08-api-predict.png` | `/docs` verdict panel after "SSH brute force" preset | browser screenshot |
| `09-model-intel.png` | `/model` metric tables + feature importances | browser screenshot |
| `10-github-repo.png` | your repository home page | browser screenshot |

**Demo video script (60–90 seconds)**
1. (0–10 s) "This is an AI-powered network intrusion detection system — three detection layers, trained on NSL-KDD."
2. (10–25 s) `/range`: run a 1,500-flow exercise, show the per-scenario detection table.
3. (25–45 s) `/`: point at KPIs, live timeline spike, then the alert feed — read one CRITICAL alert's evidence out loud.
4. (45–60 s) `/docs`: score an SSH brute-force flow, show verdict → MITRE → recommended response.
5. (60–75 s) `/model`: show metric tables and "8 of the top 20 features are ones I engineered".
6. (75–90 s) Show the repo, tests passing, and the README. Close with what you'd add next (live capture, SHAP, SIEM integration).

**Placement artefacts**
- [ ] Repo link on resume/CV with one-line impact ("3-layer IDS, F1 0.9986 hold-out, live console")
- [ ] LinkedIn post: 3–4 screenshots, 5-line story, repo link, the results table
- [ ] Pinned repo + GitHub profile README mentioning it
- [ ] 10 interview answers rehearsed from [`INTERVIEW_QA.md`](INTERVIEW_QA.md)

---

*Related documents:* [Architecture](ARCHITECTURE.md) · [Simulation Guide](SIMULATION_GUIDE.md) · [Model Card](MODEL_CARD.md) · [Interview Q&A](INTERVIEW_QA.md) · [GitHub Playbook](GITHUB_PLAYBOOK.md) · [Troubleshooting](TROUBLESHOOTING.md)
