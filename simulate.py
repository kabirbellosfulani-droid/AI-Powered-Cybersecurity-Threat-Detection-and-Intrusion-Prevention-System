"""
simulate.py  -  THE VIRTUAL CYBER RANGE
=======================================
You don't own a corporate SOC, so we BUILD one - logically.

HOW THIS WORKS (read this twice, it's the heart of the project)
---------------------------------------------------------------
1. We take real NSL-KDD connection records as the "ground truth" of what a
   benign flow and each attack family actually look like on the wire.
2. `TrafficSimulator` samples a real record of the requested family and then
   *parameterises* it into a named scenario (SYN flood, port scan, SSH brute
   force, privilege escalation...) by setting exactly the fields that a real
   tool would produce:
        hping3 -S --flood        -> serror_rate≈1.0, huge count, tiny payload
        nmap -sS 10.0.0.0/24     -> many dst hosts, diff_srv_rate high
        hydra -L users -P pw ssh -> num_failed_logins >= 5, logged_in=0
        exploit + root shell     -> root_shell=1, num_root>0, num_shells>0
3. Every event is stamped with a timestamp, source/destination IP and port,
   so the output looks like a real IDS feed (Zeek/Suricata style).
4. `is_attack_truth` is kept alongside the prediction -> that's how we compute
   live precision/recall for the dashboard.

TRAFFIC MIX: ~85% normal business traffic, ~15% attacks, matching typical
enterprise baselines. You can change `attack_rate` in the dashboard.
"""

from __future__ import annotations

import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import numpy as np
import pandas as pd

sys.path.append(str(Path(__file__).resolve().parent.parent))
from src.data_loader import load_nsl_kdd  # noqa: E402
from src.feature_engineering import add_engineered_features  # noqa: E402
from src.preprocess import clean_dataframe  # noqa: E402

ASSET_IPS = ["10.0.0.10", "10.0.0.20", "10.0.0.31", "10.0.1.5", "10.0.2.7",
             "10.0.3.14", "10.0.4.22", "10.0.5.9"]          # internal servers
CLIENT_SUBNETS = ["172.16.0.", "192.168.1.", "203.0.113."]
SERVICES = ["http", "https", "ssh", "ftp", "smtp", "dns", "telnet", "sql"]


@dataclass
class Scenario:
    """A named attack playbook with its observable indicators."""
    key: str
    name: str
    family: str
    tool: str
    description: str
    indicators: list[str] = field(default_factory=list)
    mutations: dict = field(default_factory=dict)
    severity: str = "HIGH"


SCENARIOS: dict[str, Scenario] = {
    # ------------------------------- DoS ---------------------------------
    "syn_flood": Scenario(
        "syn_flood", "SYN Flood (DoS)", "DoS", "hping3 -S --flood -p 80",
        "Sends thousands of half-open TCP connections to exhaust the server's "
        "connection table so genuine users can't connect.",
        ["serror_rate ≈ 1.0", "count in the hundreds", "tiny payload (0-40 B)",
         "very short duration"],
        {"protocol_type": "tcp", "service": "http", "flag": "S0", "serror_rate": 1.0,
         "srv_serror_rate": 1.0, "count": 511, "srv_count": 511, "src_bytes": 0,
         "dst_bytes": 0, "duration": 0, "logged_in": 0, "same_srv_rate": 1.0},
        "HIGH"),
    "http_flood": Scenario(
        "http_flood", "HTTP Flood / CC Attack (DoS)", "DoS", "slowloris / LOIC",
        "A botnet hammers an application endpoint with valid-looking requests "
        "until the web tier is starved of workers.",
        ["high request count", "high rerror_rate", "uniform service (http)",
         "moderate payloads"],
        {"protocol_type": "tcp", "service": "http", "flag": "REJ", "count": 480,
         "srv_count": 470, "rerror_rate": 0.85, "srv_rerror_rate": 0.85,
         "src_bytes": 1200, "dst_bytes": 300, "duration": 1},
        "HIGH"),
    # ------------------------------ Probe --------------------------------
    "port_scan": Scenario(
        "port_scan", "Stealth Port Scan (Probe)", "Probe", "nmap -sS -T4",
        "Reconnaissance: thousands of TCP SYN probes across many ports to map "
        "the attack surface before exploitation.",
        ["many destination hosts (dst_host_count high)", "high diff_srv_rate",
         "rejected connections", "short durations"],
        {"protocol_type": "tcp", "service": "private", "flag": "REJ",
         "dst_host_count": 255, "dst_host_srv_count": 12, "diff_srv_rate": 0.92,
         "dst_host_diff_srv_rate": 0.95, "srv_diff_host_rate": 0.6,
         "rerror_rate": 0.7, "count": 250, "srv_count": 12, "src_bytes": 0,
         "dst_bytes": 0, "duration": 0},
        "MEDIUM"),
    "ping_sweep": Scenario(
        "ping_sweep", "Ping Sweep / Host Discovery (Probe)", "Probe",
        "nmap -sn / fping",
        "Sweeps a /24 to find live hosts; low noise per host but huge fan-out.",
        ["very high dst_host_count", "uniform small payload", "icmp protocol"],
        {"protocol_type": "icmp", "service": "eco_i", "flag": "SF",
         "dst_host_count": 255, "dst_host_srv_count": 255, "count": 200,
         "srv_count": 200, "src_bytes": 32, "dst_bytes": 0, "duration": 0},
        "MEDIUM"),
    # ------------------------------- R2L ---------------------------------
    "ssh_bruteforce": Scenario(
        "ssh_bruteforce", "SSH Brute Force (R2L)", "R2L", "hydra -l root -P rockyou.txt",
        "Repeated authentication attempts against SSH until a credential sticks "
        "- the classic first step of a remote intrusion.",
        ["num_failed_logins >= 5", "logged_in = 0", "ssh service",
         "consistent connection attempts"],
        {"protocol_type": "tcp", "service": "ssh", "flag": "S0",
         "num_failed_logins": 6, "logged_in": 0, "src_bytes": 120, "dst_bytes": 60,
         "duration": 2, "count": 20, "srv_count": 20},
        "CRITICAL"),
    "ftp_password": Scenario(
        "ftp_password", "FTP Password Guessing (R2L)", "R2L", "medusa -M ftp",
        "Guessing weak FTP credentials to gain file-level access.",
        ["num_failed_logins >= 1", "ftp service", "no session established"],
        {"protocol_type": "tcp", "service": "ftp", "flag": "SF",
         "num_failed_logins": 3, "logged_in": 0, "src_bytes": 90, "dst_bytes": 45,
         "duration": 5, "hot": 1},
        "HIGH"),
    "web_probe_exploit": Scenario(
        "web_probe_exploit", "Web App Probe / Injection (R2L)", "R2L", "sqlmap / nikto",
        "Automated web scanner probing for injection, traversal and file-read "
        "vulnerabilities on the public web tier.",
        ["hot indicators (sensitive file access)", "num_access_files > 0",
         "http service", "large request bodies"],
        {"protocol_type": "tcp", "service": "http", "flag": "SF", "hot": 4,
         "num_access_files": 3, "num_file_creations": 1, "src_bytes": 4800,
         "dst_bytes": 250, "duration": 12, "count": 30},
        "HIGH"),
    # ------------------------------- U2R ---------------------------------
    "priv_escalation": Scenario(
        "priv_escalation", "Local Privilege Escalation (U2R)", "U2R",
        "exploit-db / dirty-pipe class exploit",
        "After landing on a host, the attacker exploits a vulnerable service to "
        "obtain root - the highest-severity event in any SOC.",
        ["root_shell = 1", "num_root > 0", "num_shells > 0",
         "num_compromised > 0", "privileged service"],
        {"protocol_type": "tcp", "service": "telnet", "flag": "SF", "root_shell": 1,
         "su_attempted": 2, "num_root": 4, "num_shells": 2, "num_compromised": 3,
         "num_file_creations": 5, "logged_in": 1, "src_bytes": 2600,
         "dst_bytes": 900, "duration": 180},
        "CRITICAL"),
    "data_exfil": Scenario(
        "data_exfil", "Data Exfiltration Burst (U2R)", "U2R", "rclone / scp to C2",
        "Mass outbound transfer of sensitive data to an external collector - "
        "the 'impact' stage of an attack kill-chain.",
        ["huge src_bytes with tiny dst_bytes", "long duration", "no auth noise"],
        {"protocol_type": "tcp", "service": "ftp_data", "flag": "SF",
         "src_bytes": 120_000, "dst_bytes": 8, "duration": 3600, "logged_in": 1,
         "num_root": 1, "root_shell": 1, "count": 5},
        "CRITICAL"),
}

BENIGN_SCENARIOS = {
    "web_browsing": ("Normal", "Employee browsing HTTPS", "https"),
    "smtp_mail": ("Normal", "Corporate mail relay", "smtp"),
    "dns_lookup": ("Normal", "Internal DNS resolution", "domain"),
    "backup_job": ("Normal", "Nightly backup transfer", "ftp_data"),
    "db_query": ("Normal", "Application → DB query", "sql_net"),
}


class TrafficSimulator:
    """Generates realistic mixed traffic streams from the NSL-KDD corpus."""

    def __init__(self, seed: int = 42):
        df = load_nsl_kdd("train")
        df, _ = clean_dataframe(df)
        self.df = add_engineered_features(df)
        self.rng = np.random.default_rng(seed)
        # pre-index the labelled corpus per family for fast sampling
        self.pools = {
            cat: self.df[self.df["attack_category"] == cat]
            for cat in ["Normal", "DoS", "Probe", "R2L", "U2R"]
        }
        self.normal_pool = self.pools["Normal"]
        # mapping of scenario key -> family, used when sampling the base row
        self._family_of = {k: s.family for k, s in SCENARIOS.items()}

    # ------------------------------------------------------------------
    def _random_ip(self, internal: bool = False) -> str:
        if internal:
            return str(self.rng.choice(ASSET_IPS))
        return f"{self.rng.choice(CLIENT_SUBNETS)}{self.rng.integers(2, 254)}"

    # ------------------------------------------------------------------
    def _base_row(self, family: str) -> dict:
        """Pick a real record of this family so the flow stays plausible."""
        pool = self.pools.get(family, self.normal_pool)
        row = pool.sample(1, random_state=int(self.rng.integers(0, 10_000))).iloc[0]
        return row.to_dict()

    # ------------------------------------------------------------------
    def make_event(self, scenario_key: str | None = None,
                   timestamp: float | None = None) -> dict:
        """Build ONE traffic event.

        scenario_key=None -> benign business traffic.
        scenario_key in SCENARIOS -> that attack playbook.
        """
        if scenario_key is None:
            name, desc, svc = list(BENIGN_SCENARIOS.values())[
                int(self.rng.integers(0, len(BENIGN_SCENARIOS)))]
            row = self._base_row("Normal")
            row["service"] = svc
            family, truth, sev = "Normal", 0, "INFO"
            tool = "-"
        else:
            sc = SCENARIOS[scenario_key]
            row = self._base_row(sc.family)
            row.update(sc.mutations)
            family, truth, sev = sc.family, 1, sc.severity
            name, desc, tool = sc.name, sc.description, sc.tool

        # --- add network-layer presentation fields ----------------------
        row["timestamp"] = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(timestamp or time.time()))
        row["src_ip"] = self._random_ip()
        row["dst_ip"] = self._random_ip(internal=True)
        row["src_port"] = int(self.rng.integers(1024, 65535))
        row["dst_port"] = int(self._dst_port(row.get("service", "http")))
        row["scenario"] = name
        row["attack_tool"] = tool
        row["attack_family_truth"] = family
        row["is_attack_truth"] = truth
        row["severity_truth"] = sev
        return row

    def _dst_port(self, service: str) -> int:
        return {"http": 80, "https": 443, "ssh": 22, "ftp": 21, "ftp_data": 20,
                "smtp": 25, "domain": 53, "telnet": 23, "sql_net": 1521,
                "private": int(self.rng.integers(1024, 65535))}.get(
                    service, int(self.rng.integers(1, 1024)))

    # ------------------------------------------------------------------
    def simulate(self, n_events: int = 1000, attack_rate: float = 0.15,
                 seed: int | None = None, spread_seconds: float = 900.0) -> dict:
        """Generate a full mixed traffic capture.

        Returns dict with:
            traffic      : DataFrame of raw events (ready for ThreatDetector)
            ground_truth : DataFrame with the truth labels per event
            mix          : scenario distribution actually generated
        """
        if seed is not None:
            self.rng = np.random.default_rng(seed)
        n_attacks = int(round(n_events * attack_rate))
        keys = list(SCENARIOS.keys())
        weights = np.array([2.0, 1.4, 2.2, 1.2, 1.8, 1.0, 1.3, 0.9, 0.5])
        weights = weights / weights.sum()

        # Attacks are scattered RANDOMLY across the timeline (not clustered),
        # because real adversaries do not politely wait their turn. This is
        # also what makes the SOC timeline graph look realistic.
        attack_positions = set(
            self.rng.choice(n_events, size=n_attacks, replace=False).tolist()
        )
        # Add burstiness: DoS/probe campaigns arrive in waves, not one by one.
        for _ in range(max(1, n_attacks // 12)):
            centre = int(self.rng.integers(0, n_events))
            for off in range(1, 4):
                if centre + off < n_events:
                    attack_positions.add(centre + off)

        start = time.time() - spread_seconds
        events = []
        for i in range(n_events):
            key = str(self.rng.choice(keys, p=weights)) if i in attack_positions else None
            ts = start + i * (spread_seconds / max(n_events, 1))
            events.append(self.make_event(key, timestamp=ts))

        traffic = pd.DataFrame(events)
        truth = traffic[["timestamp", "src_ip", "dst_ip", "scenario",
                         "attack_family_truth", "is_attack_truth",
                         "severity_truth"]].copy()
        mix = traffic["scenario"].value_counts().to_dict()
        print(f"[SIM] Generated {n_events} events "
              f"({n_attacks} malicious / {n_events - n_attacks} benign) "
              f"across {len(mix)} scenarios")
        return {"traffic": traffic, "ground_truth": truth, "mix": mix}

    # ------------------------------------------------------------------
    @staticmethod
    def catalog() -> list[dict]:
        """Scenario metadata for the dashboard's Attack Library page."""
        out = [{
            "key": s.key, "name": s.name, "family": s.family, "tool": s.tool,
            "description": s.description, "indicators": s.indicators,
            "severity": s.severity} for s in SCENARIOS.values()]
        out += [{
            "key": k, "name": v[1], "family": "Normal", "tool": "-",
            "description": f"Benign traffic: {v[1]} ({v[2]})",
            "indicators": ["Baseline behaviour"], "severity": "INFO"}
            for k, v in BENIGN_SCENARIOS.items()]
        return out


if __name__ == "__main__":
    sim = TrafficSimulator()
    burst = sim.simulate(n_events=2000, attack_rate=0.15)
    burst["traffic"].to_csv("outputs/simulated_traffic.csv", index=False)
    burst["ground_truth"].to_csv("outputs/simulated_ground_truth.csv", index=False)
    print("\nScenario mix generated:")
    for k, v in sorted(burst["mix"].items(), key=lambda x: -x[1]):
        print(f"   {k:<42} {v:>5}")
    print("\n[OK] Saved -> outputs/simulated_traffic.csv (2000 events, real NSL-KDD schema)")
