# 🎤 Interview Preparation — AI-Powered Cybersecurity Threat Detection

> 35 questions with rehearsed answers, grouped by theme. Answers reference *your actual project*
> so you can speak from evidence, not theory.

---

## A. Project fundamentals

**1. What is your project in one sentence?**
"An AI-powered network intrusion detection system that analyses network flow records, decides whether each flow is a cyber-attack, classifies the attack family, scores its risk, maps it to MITRE ATT&CK, and raises an actionable SOC alert — plus a virtual cyber range and a live console to demonstrate and measure it."

**2. What problem does it solve?**
Traditional signature-based security tools only detect attacks somebody already wrote a rule for, and they drown analysts in low-quality alerts. My system adds behavioural ML on top of rules: an unsupervised anomaly layer catches never-before-seen behaviour, and every alert carries severity, evidence and a recommended response so analysts can triage fast. It measurably reduces alert fatigue — false-positive rate 0.0004 on the held-out set — while keeping recall ≈ 99.8%.

**3. What data did you use?**
NSL-KDD, the standard academic intrusion-detection benchmark: 125,973 labelled training connections, 22,544 test connections with 17 attack types absent from training, described by 41 features — flow basics like duration/protocol/bytes, content indicators like failed logins and root-shell flags, and window statistics like error rates and host-scan counts. I group 24 raw attack names into the four industry families: DoS, Probe, R2L, U2R.

**4. What was the biggest challenge?**
Class imbalance. U2R has just 52 training samples out of 125,973 (0.04%) while DoS has 45,927. I handled it three ways: `class_weight='balanced_subsample'`, macro-averaged and per-class metrics instead of a single accuracy number, and a rule layer that catches rare attacks deterministically when the model isn't confident. I also report the weak spot honestly — U2R F1 is 0.737 with only 10 test samples — instead of hiding it.

**5. What would you do differently with more time?**
Add time-window correlation (per-IP campaign detection — a single ICMP echo is indistinguishable from a legitimate ping; only aggregating over a window reveals a sweep), live packet capture with Scapy/Zeek, SHAP explanations per alert, and drift monitoring. Those are all documented in my README roadmap.

---

## B. Machine learning decisions

**6. Why Random Forest?**
It's strong on tabular data, robust to feature scaling and outliers, handles mixed feature types, trains in ~9 seconds on CPU, and gives interpretable Gini feature importances which I use for explainability. I benchmarked it against a Logistic Regression baseline: F1 0.9986 vs 0.9679 on the hold-out — so the extra complexity is justified, and I can quote the baseline number in interviews.

**7. Why also Isolation Forest?**
A supervised model can only detect attacks it was trained on — that's the known weakness of the NSL-KDD test split where recall drops to 0.59 on unseen attack types. Isolation Forest is trained only on normal traffic, learns what "normal" looks like, and flags deviations. That's the closest a student project gets to zero-day detection, and the anomaly-score separation plot shows it works: the mean score for malicious flows is clearly higher with AUC 0.974.

**8. How does Isolation Forest work?**
It builds an ensemble of random binary trees that split the data on random features and random thresholds. Anomalies are "few and different", so they get isolated in fewer splits — a shorter average path length from root to leaf. The score is derived from that path length. I threshold at the 99th percentile of normal-traffic scores (τ = 0.5434) instead of relying on the default contamination cut, because production alerting needs a strict bar — that moved the false-positive rate from 0.148 to 0.0103.

**9. What features did you engineer and why?**
Thirteen, encoding security domain knowledge: byte asymmetry and one-way outbound volume (exfiltration), DoS intensity = error rate × packet count (floods), host-scan ratio (scans touch many hosts but few services per host), payload-per-packet, login anomaly (failed logins with no session = brute force), privilege score (root shell + su + compromised files), traffic entropy/diversity, and critical-service flags. Evidence it matters: 8 of the top-20 features the Random Forest relies on are features I engineered — `total_bytes` is literally #1.

**10. How did you evaluate?**
Binary framing for alerting: accuracy, precision, recall, F1, false-positive rate and ROC-AUC. Plus multi-class per-class precision/recall (because macro-F1 hides rare-class failure). I evaluated on both a stratified 20% hold-out and the official KDDTest+ split. Hold-out: RF accuracy 0.9987, precision 0.9995, recall 0.9977, F1 0.9986, FPR 0.0004. Official split: F1 0.735 — the honest generalisation number, since that split contains 17 unseen attack types.

**11. Why is recall more important than precision here?**
A false negative is a breach — data loss, downtime, regulatory fines. A false positive is analyst time. So the fusion is OR-voting (any layer can alert), tuned for recall. But I don't ignore precision: I calibrated the anomaly threshold, weighted the rules, and report FPR explicitly, because alert fatigue destroys SOC trust — analysts stop reading alerts when too many are junk. The balance I landed on: live precision 0.84 / recall 1.00 on the simulated range, FPR 0.0004 on hold-out.

**12. How does your three-layer fusion work?**
Layer 1 (Random Forest) gives the class and probability. Layer 2 (Isolation Forest) gives an anomaly score versus the p99 threshold. Layer 3 (14 weighted signature rules) reads raw field values and produces human-readable evidence — rules with weight 2 are strong enough to alert alone; weight 1 rules need a second trigger. Final risk = 45 × P(attack) + 35 × normalised anomaly + 12 × rule strength + 8 × known-class bonus, clipped 0–100; severity comes from the class and is downgraded to LOW below risk 35. That keeps high-recall behaviour while letting analysts sort by risk.

**13. How did you avoid data leakage?**
Three ways: (1) I split *after* cleaning but fit the scaler/encoder only on the training portion inside `prepare_training_data`; (2) my engineered features are computed only from the 41 input columns — never from the label — and I dropped the `difficulty` meta-column; (3) the same saved preprocessor is reused at inference with `transform_new`, so there's no train/serve skew. I also explicitly reasoned about it in the docs so a reviewer can check.

**14. What is train/serve skew and how did you prevent it?**
It's when the data transformation at inference differs from training — e.g. a scaler fitted on the training set but a *new* scaler fitted on incoming data at serving time. I prevent it by serialising the fitted `ColumnTransformer` (OneHot + StandardScaler) to `models/preprocessor.joblib` and calling it in exactly one place (`transform_new`) for both the API and the dashboard. It's the #1 production ML bug and my tests cover partial-input robustness too.

**15. How does the system handle attacks it has never seen?**
Two ways. The anomaly layer flags deviations from the learned normal baseline without needing any label. And the rule layer encodes attack semantics that generalise across variants — "5+ failed logins with no session" catches any brute-force tool, not just the specific hydra parameters in the training data. That's also why I report the official KDDTest+ number: it's my measurement of exactly this property.

---

## C. Cybersecurity domain

**16. What are DoS, Probe, R2L and U2R?**
DoS — Denial of Service: floods that exhaust a resource (`neptune`, `smurf`); Probe — reconnaissance: scanning hosts/ports (`nmap`, `satan`); R2L — Remote to Local: an attacker without an account gains access, typically via credential attacks or remote exploits (`guess_passwd`, `warezmaster`); U2R — User to Root: privilege escalation from a normal account to root (`buffer_overflow`, `rootkit`). This four-family taxonomy is the standard way the IDS literature and most benchmark papers group the 24 NSL-KDD attack names.

**17. What is MITRE ATT&CK and why map to it?**
It's a public knowledge base of adversary tactics and techniques observed in the real world. I map each detected class to a technique — Probe → T1046 Network Service Discovery, DoS → T1499 Endpoint Denial of Service, credential/remote access → T1110 Brute Force, U2R → T1068 Exploitation for Privilege Escalation. It matters because it turns an ML label into shared threat-intelligence language: SOC teams, threat hunters and CTI analysts all speak ATT&CK, and it lets you pivot from an alert to known adversary behaviour and mitigations.

**18. What would a real SOC workflow look like with your alerts?**
Detection in my engine → alert with severity/risk/MITRE/evidence → analyst triage queue sorted by risk → enrichment (who owns that IP? is it internal? any similar alerts?) → containment via the playbook (block IP at the firewall, force credential reset, isolate host) → escalation to Tier-3/IR for U2R → post-incident review. In production I'd ship alerts to a SIEM (Elastic/Splunk/Wazuh) and wire Slack/PagerDuty webhooks for CRITICAL only.

**19. How is this different from a firewall or antivirus?**
A firewall enforces policy on connections (allow/deny by IP/port/protocol) and an antivirus uses signatures on files. This system is behavioural detection on network *flows*: it doesn't block by itself — it detects, scores and explains, then hands the decision and playbook to a human or an automated response layer (SOAR). In production, detection informs enforcement rather than replacing it.

**20. How do you tune false positives in a rule like the ICMP sweep?**
By measuring, not guessing. Before adding the rule I ran it over the whole training corpus: `icmp AND count ≥ 150` matched 3.8% of malicious flows (2,227 rows) but only 1 of 67,343 benign flows — 0.0015%. An excellent trade-off, so I added it with weight 2 and documented the measurement in a code comment. I did the same exercise for the blanket /24 sweep rule, adding a `srv_count` condition to stop popular servers (dst_host_count = 255, the max) from generating false alerts — precision went from 0.72 to 0.84 in the live runs.

**21. What about encrypted traffic / payload-based detection?**
I deliberately detect on **flow metadata**, not payloads, which works with TLS because I never need to decrypt anything — timing, volume, direction, service and error statistics are visible on encrypted sessions too. That's the principle behind NetFlow/Zeek-based NDR products. A payload-based complement (YARA rules, DPI) would add value for malware and exfiltration content, but that's a roadmap item requiring a different data source.

**22. What is the difference between IDS and IPS?**
An IDS detects and alerts (out-of-band, passive); an IPS sits inline and can drop/block malicious traffic in real time. My project is an IDS with an IPS-style recommendation field (the playbook). Turning it into an IPS requires inline throughput and low latency — you'd deploy the model behind a fast pre-filter (rules first, ML as a second stage) to avoid becoming a bottleneck.

---

## D. Engineering & system design

**23. Describe your architecture.**
Four layers: a data layer (loader + cyber range), a feature/transform layer (cleaning, 13 engineered features, saved ColumnTransformer producing a 135-dim vector), a detection layer (RandomForest + IsolationForest + rule engine + fusion), and a serving layer (Flask REST API with 12 endpoints plus a four-page dashboard). `src/` has no web dependencies, so the engine runs standalone in tests, batch jobs or a notebook; the dashboard is a thin client over the API.

**24. How does the live dashboard work?**
The browser polls `/api/stream/next` every 2.6 s, the server generates and scores a batch of events, appends them to in-memory deques under a lock, and returns updated KPIs, series and alerts. Bounded deques prevent uncontrolled memory growth during long demos; the models are loaded once at boot and a warm-up run seeds 260 events so the UI is never empty. The charts are hand-written SVG — zero CDN calls — so it works offline and in sandboxed environments.

**25. How would you deploy this for real?**
Containerise (`Dockerfile`), run the training as a scheduled job (Airflow/GitHub Actions), serve the API with Gunicorn behind Nginx, and put the models in object storage or an MLflow registry with versioned metadata. Ingestion would come from Kafka or a Zeek pcap pipeline, and I'd add monitoring: prediction distribution drift, alert volume, precision/recall on a labelled sample, and latency percentiles. Autoscaling for the scoring workers, and blue/green model rollout.

**26. How would you handle 1 million events per second?**
Two-stage design: a cheap rules/pre-filter stage (regex and threshold rules, Bloom-filter lookups) to discard the ~90% obviously benign traffic, then ML scoring only on survivors — vectorised batch inference (scikit-learn on batches, or ONNX Runtime/Triton for GPU) with horizontal scaling by partitioning on flow hash. Streaming aggregation state (per-IP windows) lives in Redis/Flink rather than in-process. The pattern is exactly "rules to filter, ML to decide".

**27. What about concept drift?**
Attackers change tactics and enterprise traffic changes over time, so a static model decays. I'd monitor: PSI/KL-divergence between live feature distributions and training, alert-rate spikes, precision on labelled samples, and anomaly-score distribution shifts. On drift, retrain on a rolling window with human-confirmed labels (analyst feedback loop), and keep the anomaly layer, which self-adapts by learning the new normal.

**28. What did you do about reproducibility?**
Fixed random seeds, stratified splits, pinned requirements, persisted models and metadata with a version and timestamp, deterministic simulator seeds (I validated precision/recall across seeds 11/22/33), a single CLI (`python main.py all`) that rebuilds everything, and a test suite that checks contracts rather than just "it runs".

**29. How did you test it?**
Eleven pytest cases: schema correctness (43 columns, label mapping), feature engineering (columns exist, no NaN/inf, and DoS intensity is genuinely discriminative between classes), cleaning behaviour, detector output contracts, that the brute-force rule fires and the benign flow is *not* flagged, that a multi-signal weird flow still gets flagged, and simulator volume/reproducibility/ground-truth fields. Running tests before every push to main keeps the repo trustworthy.

**30. Why did you commit the generated images and CSVs?**
Figures and small outputs are the project's *evidence* — reviewers and recruiters shouldn't have to run anything to see results, and my README embeds them. Datasets and virtual environments stay out of the repo via `.gitignore`; model binaries are a documented choice (small enough to commit for instant demos, regenerable with one command).

---

## E. HR / behavioural

**31. Why should we hire you based on this project?**
Because it shows the full loop, not a fragment: I framed a real security problem, engineered domain features instead of dumping raw columns into a model, benchmarked three approaches, measured honestly — including publishing the number that looks worse — built a working product around the model with an API and a UI, wrote tests and documentation, and planned the next iterations. That's how I'd work on your team.

**32. What was the hardest bug you hit?**
Train/serve skew. My API crashed with a `KeyError` on `dst_host_diff_srv_rate` when an analyst submitted a partial JSON body — the model expected a feature the request didn't contain. I fixed it properly rather than patching the endpoint: `transform_new` now fills any missing raw feature with a safe default *before* feature engineering, so partial input is tolerated end-to-end, and I added a regression test for exactly that case.

**33. Explain this project to a non-technical person.**
"I built a system that watches network activity and flags anything suspicious, like a security guard who's learnt what normal looks like. Instead of only checking IDs against a rulebook, it notices odd behaviour — someone trying hundreds of passwords, a computer suddenly scanning all the others, or huge amounts of data leaving the network at 2 a.m. — and it raises a clear alert with the evidence and what to do about it."

**34. What did you learn from this project?**
Three things beyond the ML: (1) measurement discipline — reporting the harder official-split number taught me more than the flattering hold-out; (2) that domain knowledge drives feature quality, because my engineered security features dominated the model's top features; (3) that a model in a notebook is not a product — the API, the dashboard, the tests and the docs are what make it usable by someone else.

**35. Where do you want to take this next?**
Time-window correlation for campaign-level detection, live capture with Zeek/Scapy, SHAP-based per-alert explanations, SIEM/webhook integration, and a multi-dataset evaluation (CICIDS2017, UNSW-NB15) with drift monitoring. Longer term I want to work on detection engineering where ML, adversary behaviour and analyst workflow meet.
