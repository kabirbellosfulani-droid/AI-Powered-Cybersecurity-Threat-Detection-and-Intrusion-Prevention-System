"""
config.py
=========
Central configuration for the AI-Powered Cybersecurity Threat Detection System.

WHY THIS FILE EXISTS
--------------------
Every other file imports paths, column names and label maps from here.
If you ever move the project or rename a folder, you edit ONE file instead of ten.
This is exactly how real production codebases are organised.
"""
import os
from pathlib import Path

# Guarantee bounded thread memory for OpenBLAS / OpenMP across OS runtimes
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")

# --------------------------------------------------------------------------
# 1. PROJECT PATHS  (all paths are built relative to the project root,
#    so the project runs identically on Windows, Mac and Linux)
# --------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent

DATA_RAW_DIR        = BASE_DIR / "data" / "raw"          # untouched downloads
DATA_PROCESSED_DIR  = BASE_DIR / "data" / "processed"    # cleaned/feature data
MODELS_DIR          = BASE_DIR / "models"                # .joblib artefacts
OUTPUTS_DIR         = BASE_DIR / "outputs"               # csv / json results
IMAGES_DIR          = BASE_DIR / "images"                # report figures
DASHBOARD_DIR       = BASE_DIR / "dashboard"
DOCS_DIR            = BASE_DIR / "docs"

# Create them if they don't exist (safe to call repeatedly)
for _d in (DATA_RAW_DIR, DATA_PROCESSED_DIR, MODELS_DIR, OUTPUTS_DIR, IMAGES_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# --------------------------------------------------------------------------
# 2. DATASET FILE NAMES
# --------------------------------------------------------------------------
NSL_KDD_TRAIN_FILE = DATA_RAW_DIR / "KDDTrain+.txt"
NSL_KDD_TEST_FILE  = DATA_RAW_DIR / "KDDTest+.txt"

# --------------------------------------------------------------------------
# 3. NSL-KDD SCHEMA
#    The raw file has NO header row, so we must supply the official 43
#    column names in the exact published order.
# --------------------------------------------------------------------------
NSL_KDD_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty",
]

TARGET_COLUMN   = "attack_category"   # multi-class target we train on
BINARY_TARGET   = "is_attack"         # 0 = normal, 1 = malicious
CATEGORICAL_COLUMNS = ["protocol_type", "service", "flag"]

# --------------------------------------------------------------------------
# 4. ATTACK TAXONOMY
#    NSL-KDD has 24+ raw attack names. Industry practice is to group them
#    into the 4 classic families. This ONE dict powers training, the
#    dashboard labels and the MITRE ATT&CK mapping.
# --------------------------------------------------------------------------
ATTACK_CATEGORY_MAP = {
    # ---- DoS : Denial of Service -------------------------------------------
    "back": "DoS", "land": "DoS", "neptune": "DoS", "pod": "DoS",
    "smurf": "DoS", "teardrop": "DoS", "mailbomb": "DoS", "apache2": "DoS",
    "processtable": "DoS", "udpstorm": "DoS", "worm": "DoS",
    # ---- Probe : scanning / reconnaissance ---------------------------------
    "satan": "Probe", "ipsweep": "Probe", "nmap": "Probe", "portsweep": "Probe",
    "mscan": "Probe", "saint": "Probe",
    # ---- R2L : Remote-to-Local (credential / remote exploitation) ----------
    "guess_passwd": "R2L", "ftp_write": "R2L", "imap": "R2L", "phf": "R2L",
    "multihop": "R2L", "warezmaster": "R2L", "warezclient": "R2L", "spy": "R2L",
    "xlock": "R2L", "xsnoop": "R2L", "snmpguess": "R2L", "snmpgetattack": "R2L",
    "httptunnel": "R2L", "sendmail": "R2L", "named": "R2L",
    # ---- U2R : User-to-Root (privilege escalation) -------------------------
    "buffer_overflow": "U2R", "loadmodule": "U2R", "rootkit": "U2R",
    "perl": "U2R", "sqlattack": "U2R", "xterm": "U2R", "ps": "U2R",
    "normal": "Normal",
}

ATTACK_CLASSES = ["Normal", "DoS", "Probe", "R2L", "U2R"]

# Severity + MITRE ATT&CK technique per detected class.
# Recruiters love this: it shows you understand SOC workflows, not just ML.
SEVERITY_MAP = {
    "Normal": "INFO",
    "Probe":  "MEDIUM",
    "DoS":    "HIGH",
    "R2L":    "CRITICAL",
    "U2R":    "CRITICAL",
    "Unknown-Anomaly": "HIGH",
}

MITRE_MAP = {
    "Probe":  {"id": "T1046", "name": "Network Service Discovery"},
    "DoS":    {"id": "T1499", "name": "Endpoint Denial of Service"},
    "R2L":    {"id": "T1110", "name": "Brute Force / Remote Access"},
    "U2R":    {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
    "Normal": {"id": "-",     "name": "No technique"},
    "Unknown-Anomaly": {"id": "T1204", "name": "Suspicious Behaviour (unclassified)"},
}

# Response playbooks shown in the SOC dashboard (incident-response realism)
RESPONSE_PLAYBOOK = {
    "Probe":  "Rate-limit & block source IP at the edge firewall; verify no open management ports.",
    "DoS":    "Enable DDoS scrubbing / upstream filtering; throttle the destination service; page on-call.",
    "R2L":    "Force credential reset, revoke sessions, check auth logs for lateral movement.",
    "U2R":    "Isolate host immediately, snapshot memory, escalate to Tier-3 IR team.",
    "Normal": "No action required - continue monitoring.",
    "Unknown-Anomaly": "Analyst triage required - behaviour deviates from the learned baseline.",
}

# --------------------------------------------------------------------------
# 5. MODEL HYPER-PARAMETERS  (kept here so experiments are reproducible)
# --------------------------------------------------------------------------
RANDOM_STATE = 42
TEST_SIZE    = 0.20
RF_PARAMS = {
    "n_estimators": 200,
    "max_depth": None,
    "min_samples_split": 2,
    "min_samples_leaf": 1,
    "n_jobs": -1,
    "class_weight": "balanced_subsample",
    "random_state": RANDOM_STATE,
}
LR_PARAMS = {"max_iter": 1000, "class_weight": "balanced", "random_state": RANDOM_STATE}
IF_PARAMS = {"n_estimators": 200, "contamination": 0.15, "random_state": RANDOM_STATE,
             "n_jobs": -1}

# Live alerting threshold for the anomaly detector: a flow is treated as
# anomalous only if its score exceeds the Nth percentile of scores observed on
# NORMAL training traffic. Raising this cuts false positives (alert fatigue) -
# exactly how production NDR tools tune their "risk threshold".
ANOMALY_THRESHOLD_PERCENTILE = 99

# --------------------------------------------------------------------------
# 6. MODEL ARTEFACT NAMES
# --------------------------------------------------------------------------
PREPROCESSOR_FILE = MODELS_DIR / "preprocessor.joblib"
CLASSIFIER_FILE   = MODELS_DIR / "threat_classifier.joblib"
BASELINE_FILE     = MODELS_DIR / "baseline_logreg.joblib"
ANOMALY_FILE      = MODELS_DIR / "anomaly_detector.joblib"
METADATA_FILE     = MODELS_DIR / "model_metadata.json"

METRICS_FILE      = OUTPUTS_DIR / "metrics.json"
ALERTS_FILE       = OUTPUTS_DIR / "alerts.csv"
LIVE_EVENTS_FILE  = OUTPUTS_DIR / "live_events.csv"

MODEL_VERSION = "1.0.0"
