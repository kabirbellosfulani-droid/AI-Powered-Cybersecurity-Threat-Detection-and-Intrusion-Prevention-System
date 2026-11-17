# 🧾 Model Card — Threat Detection Engine v1.0.0

Following the standard "model card" format (intended use → data → metrics → limitations → ethics).
This is the document that separates a data-science exercise from responsible engineering.

---

## 1. Model details

| Item | Value |
|---|---|
| **Model version** | 1.0.0 (see `models/model_metadata.json` for the training timestamp) |
| **Architecture** | Ensemble of three independently-explainable layers (see below) |
| **Framework** | scikit-learn 1.3+ (`RandomForestClassifier`, `IsolationForest`, `LogisticRegression`, `ColumnTransformer`) |
| **Input** | One network flow: 41 raw NSL-KDD features + 13 engineered features → 135-dimensional encoded vector |
| **Output** | `threat_class` (Normal/DoS/Probe/R2L/U2R/Unknown-Anomaly), `is_attack`, `risk_score` 0–100, `severity`, `confidence`, `anomaly_score`, MITRE technique, evidence, response playbook |
| **Training data** | NSL-KDD `KDDTrain+` — 125,973 labelled connections (67,343 normal / 58,630 malicious) |
| **Evaluation data** | Stratified 20% hold-out (25,195 flows) **and** the official `KDDTest+` split (22,544 flows, 17 unseen attack types) |
| **Training time / hardware** | ~90 seconds total on a 2-core CPU sandbox; no GPU |
| **License / contact** | MIT · see repository author section |

### Layer definitions

| Layer | Algorithm | Configuration | Trained on |
|---|---|---|---|
| L1 | RandomForestClassifier | 200 trees, `class_weight='balanced_subsample'`, unlimited depth | All 5 classes |
| L2 | IsolationForest | 200 estimators, `contamination=0.15`, alert threshold = **p99 of normal-traffic scores** (τ ≈ 0.5434) | **Normal traffic only** (53,874 flows) |
| L3 | Signature rules | 14 weighted indicators (2 = strong, 1 = supporting); alert if a strong rule fires or ≥2 supporting rules fire | None (expert-defined, measured against the corpus) |
| Fusion | Weighted risk + OR-voting | `45·P(attack) + 35·anomaly + 12·rules + 8·class-trust`, clipped 0–100 | — |

---

## 2. Intended use

**Primary:** an educational / portfolio demonstration of an end-to-end AI intrusion-detection pipeline, plus a teaching sandbox (the virtual cyber range) for learning SOC concepts: severity triage, MITRE ATT&CK mapping, false-positive tuning and response playbooks.

**Fits:** student projects, interview demonstrations, purple-team training exercises, prototyping alerting UX and detection-engineering workflows.

**Does not fit:** production enforcement decisions, safety-critical infrastructure, compliance evidence, or any setting where a false negative carries legal/ethical consequences without human review. Alerts are **advisory**; no automated blocking is performed.

---

## 3. Evaluation

### Hold-out split (25,195 flows, binary attack/no-attack framing)

| Model | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC |
|---|---|---|---|---|---|---|
| Logistic Regression (baseline) | 0.9692 | 0.9408 | 0.9967 | 0.9679 | 0.0546 | 0.9978 |
| Isolation Forest (unseen-family detector) | 0.9013 | 0.9854 | 0.7998 | 0.8830 | 0.0103 | 0.9743 |
| **Random Forest (primary)** | **0.9987** | **0.9995** | **0.9977** | **0.9986** | **0.0004** | **1.0000** |
| Hybrid (RF **or** IF) | 0.9987 | 0.9995 | 0.9977 | 0.9986 | 0.0004 | — |

**Per-family (Random Forest):**

| Family | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| Normal | 0.998 | 1.000 | 0.999 | 13,469 |
| DoS | 1.000 | 1.000 | 1.000 | 9,186 |
| Probe | 1.000 | 0.991 | 0.995 | 2,331 |
| R2L | 1.000 | 0.985 | 0.992 | 199 |
| U2R | 0.778 | 0.700 | 0.737 | **10** |

### Generalisation (official `KDDTest+`, 17 attack types absent from training)

| Model | Accuracy | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|
| Random Forest | 0.7568 | 0.9671 | 0.5929 | 0.7351 | 0.0267 |
| Isolation Forest | 0.7432 | 0.9804 | 0.5601 | 0.7129 | 0.0148 |

### Live virtual cyber range (2,000 generated flows, 18% malicious)

Precision **0.841** · Recall **1.000** · F1 **0.9136** · Accuracy 0.9655 · detection **100%** on all 9 attack playbooks.
Validated across seeds 11 / 22 / 33 (1,500 flows, 15% attacks): F1 0.921 / 0.912 / 0.917 — stable.

---

## 4. Known limitations & failure modes

1. **Optimistic live numbers.** The cyber range injects attack patterns drawn from the same corpus used for training, so it measures *pipeline correctness and recall behaviour*, not detection of genuinely novel adversaries. The `KDDTest+` recall (0.593) is the honest proxy for unseen attacks.
2. **Rare-class weakness.** U2R has 52 training samples; per-class F1 is 0.737 on a 10-sample test set. Any U2R metric here is statistically fragile; do not quote it as precise.
3. **Concept drift.** NSL-KDD reflects a pre-2000s attack mix. Modern traffic (API abuse, cloud IAM misuse, encrypted C2) is out of distribution. Retraining on CICIDS2017+/modern telemetry is required for real deployment.
4. **Single-flow blindness.** Volumetric campaigns (slow port sweeps, low-and-slow exfiltration) are only partially visible in one flow. The system approximates window correlation using NSL-KDD's `count`/`dst_host_*` statistics, but a real deployment needs an explicit time-window aggregation layer.
5. **False positives on busy servers.** High-fan-out internal servers resemble scanners; the `/24 sweep` rule was specifically conditioned (`dst_host_srv_count ≤ 0.5 × dst_host_count`) after this was measured. Precision on the live range settles at ≈0.84 largely because of such ambiguous Probe flows.
6. **Feature dependence.** Alerts assume the 43 input fields are correctly exported by the flow sensor. Garbage in, confident garbage out — validate upstream telemetry.

---

## 5. Ethical considerations

* **Human-in-the-loop:** the system recommends; it must not autonomously block or accuse. A blocked IP can disrupt business; an accusation can harm a person (insider-threat context).
* **Privacy:** the model consumes flow *metadata* only — no payload inspection, no decryption, no personal content. This is a deliberate privacy-preserving design choice.
* **Bias:** the training corpus reflects the traffic of one academic testbed; detection quality may vary across networks, languages of service names, and traffic mixes. Validate on your own distribution before trusting thresholds.
* **Dual use:** the attack playbooks describe techniques at a conceptual level for defensive training (purple teaming). Do not run real attack tools against systems you do not own or have written authorisation to test.
* **Transparency:** every alert exposes its evidence and rule weights so decisions can be audited and appealed. No opaque single-score verdicts.

---

## 6. Reproducibility

```bash
python main.py download      # dataset (public mirror + manual links printed)
python main.py all           # train → evaluate → figures → simulate  (~2 min, CPU only)
python main.py test          # 11 contract tests
```

Determinism: `random_state=42` for model/split; simulator seeds are explicit; `requirements.txt` pins major versions; the fitted preprocessor, classifier and metadata are persisted so any metric in the README can be traced to a concrete artefact.
