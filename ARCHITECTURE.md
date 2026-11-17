# 🏗 Architecture — AI-Powered Cybersecurity Threat Detection System

> Deep-dive design document. For a quick view see the [README](../README.md#-architecture).

## 1. System context

```
                    ┌─────────────────────────────┐
                    │   ANALYST (human)           │
                    │   triage · investigate · IR │
                    └──────────────┬──────────────┘
                                   │ reads alerts, evidence, playbooks
┌──────────────────────┐  ┌────────▼────────────────────────────┐
│  DATA / TELEMETRY    │  │   SENTINEL DETECTION PLATFORM        │
│  • NSL-KDD corpus    │─▶│   ingest → transform → detect →      │
│  • Virtual Cyber     │  │   enrich → alert → visualise         │
│    Range (playbooks) │  └────────┬────────────────────────────┘
│  • [future] Zeek /   │           │
│    Suricata / Scapy  │           ▼
└──────────────────────┘  ┌─────────────────────────────┐
                          │  DOWNSTREAM CONSUMERS        │
                          │  • SOC dashboard (browser)   │
                          │  • REST API clients          │
                          │  • CSV/JSON evidence files   │
                          │  • [future] SIEM / Slack     │
                          └─────────────────────────────┘
```

## 2. Component layout

| Module | Responsibility | Depends on | Stable contract |
|---|---|---|---|
| `src/config.py` | paths, schema, taxonomy, severity, MITRE, hyper-params | — | constants only |
| `src/data_loader.py` | load + label-map the benchmark | config | `DataFrame` with `label`, `attack_category`, `is_attack` |
| `src/feature_engineering.py` | 13 domain features | config | adds `ENGINEERED_FEATURES` columns, finite values |
| `src/preprocess.py` | clean + encode + scale + split | loader, features | fitted `ColumnTransformer`↔`transform_new` parity |
| `src/train.py` | train and persist 3 models | preprocess | `models/*.joblib`, `model_metadata.json` |
| `src/evaluate.py` | metrics, confusion matrices, ROC | train artefacts | `outputs/metrics.json`, `model_comparison.csv` |
| `src/detect.py` | inference, rules, fusion, alerts | artefacts, config | `predict(df) → scored df`, `build_alerts → alert table` |
| `src/simulate.py` | generate labelled traffic | loader, features | `simulate() → {traffic, ground_truth, mix}` |
| `src/generate_simulation.py` | run exercise + live metrics | simulate, detect | `alerts.csv`, `live_metrics.json` |
| `src/visualize.py` | 10 evidence figures | all of the above | `images/*.png` |
| `dashboard/app.py` | REST API + pages | detect, simulate | JSON endpoints, HTML pages |
| `tests/test_pipeline.py` | contract tests | all modules | pass/fail |

**Layering rule:** `src/` never imports Flask; the dashboard never re-implements detection logic. This keeps the engine reusable (Lambda, Airflow, notebook, batch job) and testable without a web server.

## 3. Data flow — batch training path

```
KDDTrain+.txt (125,973 × 43)
        │  load_nsl_kdd()
        ▼
DataFrame (+attack_category, +is_attack)
        │  clean_dataframe()      drop difficulty, inf→NaN, median fill, dedupe
        ▼
cleaned (125,973 × 44)
        │  add_engineered_features()   +13 features
        ▼
engineered (125,973 × 57)
        │  select_model_features()     drop label/targets → 54 input features
        │  ColumnTransformer.fit_transform()
        │     ├─ OneHot(protocol_type, service, flag)  → 81 sparse→dense cols
        │     └─ StandardScaler(51 numerics)
        ▼
encoded matrix (125,973 × 135)
        │  stratified 80/20 split
        ├── X_train (100,778)  ──► RandomForest.fit · LogisticRegression.fit · IsolationForest.fit(normal only)
        └── X_test  (25,195)   ──► evaluate.py
```

## 4. Data flow — production inference path (per flow)

```
raw record (43 fields, partial input tolerated)
   │ transform_new()  → same cleaning + features + saved encoder/scaler
   ▼ 135-dim vector
   ├─► RandomForest.predict_proba  → class posteriors  (P_attack, P_class)
   ├─► IsolationForest.score_samples → anomaly score   (compared to τ = p99 of normal)
   └─► signature_rules(raw row)     → [(reason, weight)]  rules read RAW values
   ▼
fusion: label selection + risk score (0-100) + severity band
   ▼
alert enrichment: MITRE technique · response playbook · alert ID · timestamp · src/dst IP
   ▼
outputs: API JSON · dashboard feed · alerts.csv
```

## 5. Detection layers in detail

### Layer 1 — Supervised multi-class classifier
* `RandomForestClassifier(n_estimators=200, class_weight='balanced_subsample')`
* 5 classes; probabilities give per-alert confidence.
* Chosen over boosting because: trains in ~9 s on CPU, is robust to feature scaling, handles mixed feature importance well, and provides interpretable Gini importances.

### Layer 2 — Unsupervised anomaly detector
* `IsolationForest(n_estimators=200, contamination=0.15)` trained **only** on normal flows.
* Decision rule at inference: `anomaly_score > τ` where `τ = P99(score_samples(normal train))` — a deliberately strict threshold that keeps the live false-positive rate ≈ 1%.
* Purpose: surface behaviour that the supervised model was never taught (unknown/novel attacks).

### Layer 3 — Signature correlation (transparent rules)
14 indicators with weights (2 = strong, 1 = supporting):

| Rule | Weight | Rationale |
|---|---|---|
| ≥3 failed logins | 2 | brute-force indicator |
| failed login without session | 1 | weaker credential signal |
| root shell / `su_attempted=2` | 2 | privilege escalation |
| `num_compromised > 0` | 2 | confirmed compromise |
| multiple root shells | 2 | post-exploitation |
| SYN-flood rate & volume | 2 | DoS fingerprint |
| rejection storm (`rerror_rate>0.75`, `count>100`) | 2 | scan/flood |
| elevated rejection rate | 1 | weak scan signal |
| host+service sweep | 2 | port-scan fingerprint |
| blanket /24 sweep (srv-count conditioned) | 2 | discovery scan — *tuned to avoid popular-server false positives* |
| many services on one host | 1 | weak scan signal |
| one-way exfiltration volume | 2 | impact stage |
| sensitive-file access burst (`hot≥3`, files≥2) | 2 | web exploitation |
| ICMP sweep/flood | 2 | *adopted after measuring 1 benign hit in 67,343 flows* |
| long unauthenticated session | 1 | weak signal |
| guest login in high-volume session | 1 | weak signal |

Alerting rule: **a strong rule alone, or two supporting rules, can flag a flow even when ML says Normal** — rules are the "auditor" of the models.

### Fusion & risk scoring

```
risk = 45·P(attack) + 35·normalised_anomaly + 12·min(rule_score,4) + 8·(known_class)
risk clipped to [0,100]; severity from class, downgraded to LOW when risk < 35
```

OR-voting is intentional: in security, **recall > precision** at the alerting stage, with precision recovered through risk bands (analysts can filter LOW), calibrated thresholds, and evidence strings.

## 6. Alerting model

| Field | Source | Example |
|---|---|---|
| `alert_id` | UUID short | `ALT-8DC79D9F` |
| `timestamp` | event time | `2026-10-14 11:19:01` |
| `severity` | class + risk | `CRITICAL` |
| `threat_class` | fusion | `U2R` |
| `src_ip` / `dst_ip` / `service` | telemetry | `203.0.113.198 → 10.0.4.22 · telnet` |
| `risk_score` / `confidence` | fusion / model | `87.04` / `0.535` |
| `mitre` | taxonomy map | `T1068 - Exploitation for Privilege Escalation` |
| `reason` | rule engine | *"Privilege-escalation artifacts (root shell / su attempt); Compromised filesystem objects: 3"* |
| `action` | playbook | *"Isolate host immediately, snapshot memory, escalate to Tier-3 IR team."* |

## 7. Dashboard architecture

```
Browser (vanilla JS, hand-written SVG charts)
   │  fetch() every 2.6 s  +  on-demand POSTs
   ▼
Flask app (threaded)
   ├── pages:  /  ·  /range  ·  /model  ·  /docs
   ├── api:    /api/{health,summary,alerts,events,series,model,features,scenarios}
   │           POST /api/{stream/next,simulate,predict,reset}
   ├── figures: /figures/<name>.png  (serves images/)
   └── state:  in-memory deques + threading.Lock  (events 4,000 · alerts 1,500 · series 90)
                ↓ best-effort append
           outputs/live_events.csv
```

Design notes: bounded memory (deques) prevents unbounded growth during long demos; a single lock serialises ingestion; models are loaded once at boot; a **warm-up** run seeds 260 events so the console is never empty; numpy scalars are converted to native Python types for JSON safety; no CDN dependencies so the UI works offline and inside sandboxed previews.

## 8. Extensibility points

| Want to… | Change only |
|---|---|
| Use real traffic | replace the `simulate` source with a Zeek/Suricata/Scapy adapter that yields the same 43 fields |
| Swap the model | `src/train.py` (e.g. XGBoost) + retrain; the API is model-agnostic |
| Add a rule | one `if` block in `signature_rules()` with a measured FP justification comment |
| Ship to a SIEM | consume `GET /api/alerts` or `outputs/alerts.csv`, map to ECS/Splunk HEC |
| Add a new dataset | write a loader that produces `attack_category` + `is_attack`; everything downstream is unchanged |
| Containerise | wrap `main.py` + `dashboard/app.py` in a Dockerfile (roadmap item) |

## 9. Non-functional properties

* **Performance:** full pipeline ≈ 2 min CPU; RF inference ≈ 25k flows/s (single core); dashboard API responses < 300 ms.
* **Reproducibility:** fixed `random_state=42`, seeds in the simulator, pinned requirements, persisted preprocessor + metadata.
* **Robustness:** partial input tolerated (`transform_new` fills missing raw features), inf/NaN eliminated, unseen categorical levels handled by `OneHotEncoder(handle_unknown='ignore')`.
* **Observability:** `/api/health`, boot logs, live metrics file, `print`-based stage reports with `[OK]/[CHECK]/[WARN]` prefixes.
* **Security hygiene:** no credentials in the repo, `.gitignore` blocks `.env`/secrets, dataset not committed, no PII (public benchmark only).
