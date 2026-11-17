# 🚀 MASTER PROMPT — Reusable, Upgraded Version

> The original brief, rewritten as a **precision engineering prompt**. Paste this into any AI assistant
> (or use it as your own project blueprint) whenever you want to rebuild or extend this system.
> It is deliberately specific about *outputs*, *evidence*, and *acceptance criteria* — that's what
> turns a vague request into a portfolio-grade build.

---

## THE PROMPT (copy everything below the line)

---

**ROLE**
You are a senior team combining: Cybersecurity Engineer (SOC/blue team), AI/ML Engineer, Threat-Intelligence
Analyst, Python Developer, Data Analyst, and GitHub Mentor for students targeting placements.

**MISSION**
Build a complete, runnable, industry-aligned project titled
**"AI-Powered Cybersecurity Threat Detection System"** that a student can publish on GitHub as proof of work —
using only **public datasets + a virtual cyber range** (no corporate SOC access), executed on a **CPU-only laptop**
in **under 5 minutes**, with **reproducible metrics** and a **live demo interface**.

**NON-NEGOTIABLE ACCEPTANCE CRITERIA**
1. `python main.py all` runs end-to-end with zero manual edits: download → train → evaluate → figures → simulate.
2. `python main.py dashboard` serves a working analyst console with a live alert feed.
3. `python main.py test` passes an automated test suite (≥10 tests, all green).
4. Every claim in the README is **reproducible** and backed by a file in `outputs/` or `images/`.
5. Performance is reported on **both** an easy split and a **hard generalisation split** (unseen attack types).
6. No secret, dataset, or virtualenv committed; `.gitignore` + `requirements.txt` + `LICENSE` present.

**DELIVERABLES (produce ALL of them)**
A. **Explanation** — the problem, in plain language *and* technical language; who uses this (banks, IT services, product companies); the full workflow (collect → clean → features → train → predict → alert → visualise).
B. **Tech-stack options** — (A) easiest notebook, (B) intermediate modular project, (C) advanced platform — each with tools, dataset, difficulty, expected output, GPU need. Then **select one** and justify it for a student optimising for placements.
C. **Architecture** — text block diagram, module contracts, and a data-flow table covering both batch training and per-flow inference.
D. **Folder structure** — professional, git-ready, every folder explained in one line.
E. **Installation** — Windows + macOS/Linux commands, venv, pinned requirements, common traps.
F. **Code** — modular, heavily commented, beginner-readable. Required components:
   - dataset loader with attack-family taxonomy (24 raw attack names → DoS/Probe/R2L/U2R)
   - cleaning + imputation + de-duplication
   - **domain feature engineering** (byte asymmetry, DoS intensity, host-scan ratio, login anomaly, privilege score, payload-per-packet, traffic entropy …)
   - saved preprocessing pipeline (train/serve parity — no leakage)
   - three detection layers: **supervised classifier**, **unsupervised anomaly detector** (normal-only training, calibrated threshold), **transparent weighted signature rules**
   - risk fusion (0–100) + severity bands + MITRE ATT&CK mapping + response playbooks
   - metrics: accuracy, precision, recall, F1, FPR, ROC-AUC, per-class report, confusion matrices
   - visualisation: ≥8 report-quality figures
G. **Virtual cyber range** — ≥8 real-world attack playbooks (SYN flood, HTTP flood, port scan, ping sweep, SSH brute force, FTP guessing, web-injection probe, privilege escalation, data exfiltration) with the *observable indicators* each tool produces, benign service profiles for realism, random scattering + burstiness, and **ground-truth labels** on every generated flow.
H. **Live SOC interface** — a polished dark-themed dashboard: KPI tiles, streaming timeline chart, threat-mix donut, severity bars, live confusion matrix, alert feed with severity chips + MITRE + evidence, a cyber-range runner showing per-scenario detection rates, a model-intelligence page, and a **manual threat-hunt playground** where a user crafts a flow and sees the verdict. No external CDNs (must work offline/sandboxed). Provide a REST API with ≥10 endpoints.
I. **Measurement** — compute live precision/recall against ground truth during simulation; validate stability across ≥3 random seeds; publish the per-scenario detection table.
J. **Documentation set** — README (recruiter-facing, real numbers, hero images, limitations section), Project Guide (A–M), Architecture, Simulation Guide, Model Card, Interview Q&A (≥30 questions with answers), GitHub Playbook, Troubleshooting.
K. **GitHub strategy** — repo name, description, 15 topics, first-push commands, Conventional Commit examples, release notes, and a **7-day commit plan** where each day lists what to build, the exact commit messages, and the screenshot to capture.
L. **Proof checklist** — exact screenshot list with file names, a 60–90 s demo-video script, a LinkedIn post template, a 35-second spoken pitch, and a resume one-liner.
M. **Honesty layer** — a limitations section (imbalance effects, dataset age, single-flow blindness, optimistic simulation recall) and explicit rules: never claim unmeasured numbers; never run real attack tools against third-party systems; keep a human in the loop for any blocking decision.

**QUALITY BAR**
- Beginner-executable, interview-defensible, engineer-auditable.
- Every design choice accompanied by a one-line *why*.
- Code comments explain **security reasoning**, not syntax.
- Anything ambiguous → choose the option that produces stronger, verifiable evidence.

**OUTPUT ORDER**: A → B → C → D → E → F → G → H → I → J → K → L → M.
Begin.

---

## How to use this prompt well

| Situation | What to add to the prompt |
|---|---|
| You want a different dataset | "Swap NSL-KDD for CICIDS2017; keep the same interfaces and keep the ground-truth simulation." |
| You have a GPU / more time | "Upgrade layer 1 to XGBoost and add a PyTorch autoencoder; report both against the existing baseline table." |
| You want deployment proof | "Add a Dockerfile, GitHub Actions CI (train → test → publish artefacts), and a `/health` readiness probe." |
| You want explainability depth | "Add SHAP per-alert explanations and expose them in the dashboard alert drawer." |
| You want a different domain | "Keep the entire architecture and swap the dataset/taxonomy layer to credit-card fraud (ULB dataset) — prove the fusion engine is domain-agnostic." |

**Why this version works better than the original brief**

1. **It defines done.** Acceptance criteria replace "make it good" — the output can be verified, not just admired.
2. **It forces evidence.** Every metric must trace to a file; both an easy and a hard evaluation split are mandatory, so inflated numbers can't hide.
3. **It demands the hard parts of ML engineering** — train/serve parity, imbalance handling, calibration, honest limitations — which is exactly what interviewers probe.
4. **It specifies the interface** (offline-capable, no CDNs, live streaming, playground) so the demo is presentable in any environment.
5. **It ships with the career layer** (commit plan, screenshots, video script, pitch, resume line) because the project's value is realised only when someone sees it.
