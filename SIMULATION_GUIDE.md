# ⚔ Virtual Cyber Range — Simulation Guide

> How to run a realistic, **measured** cyber-attack simulation without access to a corporate network,
> what to capture as proof, and the exact demo-video script.

---

## 1. Why simulate instead of using real traffic?

| Option | Reality for a student |
|---|---|
| Real corporate SOC telemetry | ❌ You don't have access — and you never will before employment |
| Live packet capture on your own laptop | ⚠️ Possible, but noisy (your own traffic only), permission-heavy, and breaks on other machines |
| **Labelled benchmark + parameterised attack playbooks** | ✅ Reproducible, legal, safe, fast, and — crucially — **ground truth is known**, so you can *measure* detection quality |

The last row is what this project does. Real SOC analysts also work this way during onboarding: they replay historical captures and known attack campaigns through the detection stack before trusting it on live traffic ("purple teaming").

---

## 2. What the simulator actually builds

`src/simulate.py` defines **9 attack playbooks** and **5 benign service profiles**. For each event it:

1. samples a genuine record of the right family from the NSL-KDD corpus (so the flow stays plausible),
2. applies the playbook's `mutations` — the fields a real tool would produce,
3. attaches network-layer fields: `timestamp`, `src_ip`, `dst_ip`, `src_port`, `dst_port`,
4. writes the ground truth: `scenario`, `attack_tool`, `attack_family_truth`, `is_attack_truth`, `severity_truth`.

Attacks are scattered **randomly** across the timeline with burstiness, because campaigns arrive in waves rather than politely queueing.

### The playbooks

| # | Scenario | Tool | Key mutations | Truth family |
|---|---|---|---|---|
| 1 | SYN Flood | `hping3 -S --flood -p 80` | `flag=S0`, `serror_rate=1.0`, `count=511`, 0 bytes | DoS |
| 2 | HTTP Flood / CC | slowloris, LOIC | `rerror_rate=0.85`, `count=480`, http, 1.2 kB | DoS |
| 3 | Stealth Port Scan | `nmap -sS -T4` | `dst_host_count=255`, `srv_count=12`, `diff_srv_rate=0.92`, REJ | Probe |
| 4 | Ping Sweep | `nmap -sn`, `fping` | ICMP, `count=200`, `dst_host_count=255` | Probe |
| 5 | SSH Brute Force | `hydra -l root -P rockyou.txt` | `num_failed_logins=6`, `logged_in=0`, ssh | R2L |
| 6 | FTP Password Guessing | `medusa -M ftp` | `num_failed_logins=3`, ftp, `hot=1` | R2L |
| 7 | Web Injection Probe | `sqlmap`, `nikto` | `hot=4`, `num_access_files=3`, http, 4.8 kB | R2L |
| 8 | Local Privilege Escalation | exploit-db PoC | `root_shell=1`, `num_root=4`, `num_shells=2`, `num_compromised=3` | U2R |
| 9 | Data Exfiltration | `rclone`/`scp` to C2 | `src_bytes=120000`, `dst_bytes=8`, `duration=3600` | U2R |

Benign mix: HTTPS browsing, SMTP mail relay, DNS resolution, nightly backup, DB query — so precision is measured against realistic noise, not a toxically clean baseline.

---

## 3. Detection worked example (SYN flood)

```
Generated flow (ground truth: DoS)
  protocol=tcp  service=http  flag=S0
  serror_rate=1.00  srv_serror_rate=1.00  count=511  srv_count=511
  src_bytes=0  dst_bytes=0  duration=0

Engine output
  Layer 1 (RF)        → DoS                 (probability 0.99)
  Layer 2 (IF)        → anomaly score 0.62  (> τ=0.5434 → anomalous)
  Layer 3 (rules)     → "SYN-flood signature: serror_rate=1.00 over 511 connections" (weight 2)

Fused verdict
  threat_class = DoS      risk_score = 96.0     severity = HIGH
  MITRE = T1499 Endpoint Denial of Service
  action = "Enable DDoS scrubbing / upstream filtering; throttle the destination
            service; page on-call."
```

## 4. Detection worked example (SSH brute force — a case where rules beat ML)

```
Generated flow (ground truth: R2L)
  service=ssh  flag=S0  num_failed_logins=6  logged_in=0
  src_bytes=120  dst_bytes=60  count=20  srv_count=20

Engine output
  Layer 1 (RF)    → Normal  (rare class: only 995 R2L of 125,973 training rows)
  Layer 2 (IF)    → anomaly 0.449 (< τ → not anomalous alone)
  Layer 3 (rules) → "Brute-force pattern: 6 failed logins" (weight 2) → fires

Fused verdict
  threat_class = Unknown-Anomaly  risk 64.2  severity HIGH
  reason = "Brute-force pattern: 6 failed logins; Signature-correlated flow (no matching ML class)"
```

**Teaching point to say in interviews:** this is exactly why production stacks combine ML *and* deterministic rules — the model has seen too few brute-force samples to be confident, but a rules-based check catches it deterministically, and the anomaly layer provides the third safety net.

---

## 5. Step-by-step simulation workflow

```bash
# STEP 1 — get the intelligence corpus (one time)
python main.py download

# STEP 2 — train the three detection layers
python main.py train
#   → RandomForest ~9s · LogisticRegression ~72s · IsolationForest ~1s
#   → prints: "Live alert threshold = 0.5434 (p99 of normal scores)"

# STEP 3 — inspect what can be simulated
python -c "from src.simulate import SCENARIOS; [print(k, '->', v.name) for k,v in SCENARIOS.items()]"

# STEP 4 — generate a capture (2,000 flows, 15% malicious)
python src/simulate.py
#   → outputs/simulated_traffic.csv (raw), outputs/simulated_ground_truth.csv

# STEP 5-7 — score, alert, measure (full exercise)
python src/generate_simulation.py
#   → outputs/simulation_scored_events.csv
#   → outputs/alerts.csv          (~430 alerts with evidence + MITRE + playbook)
#   → outputs/live_metrics.json   (precision 0.841 / recall 1.000 / F1 0.9136)

# STEP 8 — watch it live
python main.py dashboard
#   → http://127.0.0.1:5000/range  → "Run cyber-range exercise"
#   → http://127.0.0.1:5000        → live stream, "⚡ Inject attack burst"
```

---

## 6. What the outputs look like

**`outputs/alerts.csv` (top rows, abbreviated)**

| severity | threat_class | src_ip → dst_ip | service | risk | mitre | reason |
|---|---|---|---|---|---|---|
| CRITICAL | U2R | 203.0.113.198 → 10.0.4.22 | telnet | 87.0 | T1068 | Privilege-escalation artifacts; Compromised filesystem objects: 3 |
| HIGH | DoS | 172.16.0.189 → 10.0.3.14 | http | 96.0 | T1499 | SYN-flood signature: serror_rate=1.00 over 511 connections |
| MEDIUM | Probe | 192.168.1.48 → 10.0.5.9 | private | 94.9 | T1046 | High rejection rate (0.70); Sweeping many hosts/services |
| HIGH | Unknown-Anomaly | 203.0.113.3 → 10.0.4.22 | http | 77.6 | T1204 | SYN-flood signature; High rejection rate (0.85) |

**`outputs/live_metrics.json`**

```json
{
  "events_scored": 2000, "true_attacks": 365, "alerts_raised": 434,
  "precision": 0.841, "recall": 1.0, "f1_score": 0.9136, "accuracy": 0.9655,
  "detection_rate_by_scenario": { "SYN Flood (DoS)": {"detected": 57, "events": 57, "rate_pct": 100.0}, "...": {} },
  "severity_breakdown": {"HIGH": 339, "MEDIUM": 80, "CRITICAL": 13, "LOW": 2}
}
```

---

## 7. Graphs and anomalies to highlight

| Figure | File | What to point at |
|---|---|---|
| Attack timeline | `images/08_live_detection_timeline.png` | traffic volume vs true attacks; model alerts overlay |
| Risk distribution | `images/10_risk_score_histogram.png` | clean separation of benign (left) vs malicious (right) |
| Anomaly separation | `images/06_anomaly_score_distribution.png` | normal vs malicious score densities + threshold line |
| Confusion matrix | `images/04_confusion_matrix_rf.png` | near-perfect diagonal; U2R the visible weak cell |
| Model comparison | `images/05_model_comparison.png` | why RF was chosen over the LR baseline |

**Anomalies worth zooming into during a demo:** the SYN-flood row (`serror_rate=1.00`, `count=511`), the port-scan row (`dst_host_count=255` vs `srv_count=12`), the brute-force row (6 failed logins, no session), the exfiltration row (120 kB out / 8 bytes in), and any CRITICAL privilege-escalation alert (`root_shell=1`).

---

## 8. Screenshots & video proof

**Capture these (see the full checklist in [PROJECT_GUIDE.md §M](PROJECT_GUIDE.md#m-proof-checklist)):**

1. `python src/generate_simulation.py` console output — the per-scenario detection table.
2. `outputs/alerts.csv` opened in Excel/VS Code — highlight one CRITICAL row.
3. `/range` page after an exercise — per-scenario bars + confusion matrix + verdict table.
4. `/` dashboard mid-stream — KPIs, timeline spike, alert feed with evidence.
5. `/docs` verdict panel for the SSH brute-force preset.

**60–90 second demo video script**

| Time | Show | Say |
|---|---|---|
| 0:00–0:10 | Repo open in browser | "An AI-powered network intrusion detection system with three detection layers, trained on the NSL-KDD benchmark." |
| 0:10–0:25 | `/range`, run exercise | "This is my virtual cyber range — nine real attack playbooks. Each generated flow carries a ground-truth label, so detection quality is measured, not guessed." |
| 0:25–0:45 | `/`, then an alert row | "Live console. Here's a SYN flood — 511 connections at 100% error rate — flagged HIGH risk 96, mapped to MITRE T1499, with the response playbook." |
| 0:45–1:05 | `/docs` SSH preset | "Manual threat hunt: six failed SSH logins → alert with evidence. The random forest alone would have missed this rare class — that's why rules and anomaly detection exist." |
| 1:05–1:20 | `/model` | "Hold-out F1 0.9986; on the harder official split, 0.735 — I report both. Eight of the top twenty features are ones I engineered." |
| 1:20–1:30 | Repo + tests | "Eleven tests passing, full docs, and the next steps are live capture, SHAP explanations and SIEM integration." |

---

## 9. Ethics & safety

* Never run attack tools (`hping3`, `hydra`, `nmap`) against systems you do not own or have written authorisation to test.
* This project's "attacks" are **simulated at the data level** — they exercise the *detection* logic, not any real network. That is deliberate and is why the project is safe to demo anywhere.
* Datasets are public academic benchmarks containing no personal data.
* If you later add live capture, restrict it to your own lab subnet and log only metadata, not payloads (privacy/GDPR considerations).
