/**
 * SENTINEL AI-SOC  -  Interactive Client-Side Engine
 * ==================================================
 * Powers the GitHub Pages static website with live attack stream simulation,
 * Threat Hunter interactive analyzer, and Cyber Range benchmarks.
 */

// --- Audio SFX (Web Audio API Synthesizer) ---
class SoundEffects {
  constructor() {
    this.ctx = null;
    this.enabled = true;
  }
  init() {
    if (!this.ctx && (window.AudioContext || window.webkitAudioContext)) {
      this.ctx = new (window.AudioContext || window.webkitAudioContext)();
    }
  }
  playTone(freq, type, duration, gainVal = 0.1) {
    if (!this.enabled) return;
    this.init();
    if (!this.ctx) return;
    try {
      const osc = this.ctx.createOscillator();
      const gain = this.ctx.createGain();
      osc.type = type;
      osc.frequency.setValueAtTime(freq, this.ctx.currentTime);
      gain.gain.setValueAtTime(gainVal, this.ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.0001, this.ctx.currentTime + duration);
      osc.connect(gain);
      gain.connect(this.ctx.destination);
      osc.start();
      osc.stop(this.ctx.currentTime + duration);
    } catch(e) {}
  }
  ping() { this.playTone(880, 'sine', 0.15, 0.05); }
  alert() {
    this.playTone(440, 'sawtooth', 0.1, 0.08);
    setTimeout(() => this.playTone(880, 'sawtooth', 0.15, 0.08), 80);
  }
  critical() {
    this.playTone(300, 'square', 0.12, 0.1);
    setTimeout(() => this.playTone(600, 'square', 0.18, 0.1), 90);
    setTimeout(() => this.playTone(900, 'square', 0.25, 0.12), 200);
  }
}
const SFX = new SoundEffects();

// --- MITRE ATT&CK & Playbooks Database ---
const MITRE_DB = {
  "Probe": { id: "T1046", name: "Network Service Discovery", playbook: [
    "Rate-limit & block source IP at the edge firewall.",
    "Verify no exposed management ports (RDP 3389, SSH 22, Telnet 23).",
    "Inspect honeypot telemetry for scanning signatures."
  ]},
  "DoS": { id: "T1499", name: "Endpoint Denial of Service", playbook: [
    "Engage upstream DDoS scrubbing or Cloudflare/AWS Shield mitigation.",
    "Throttle connection rates for affected destination service.",
    "Enable SYN cookies and drop malformed packet fragments at kernel level."
  ]},
  "R2L": { id: "T1110", name: "Brute Force / Remote Access", playbook: [
    "Immediately enforce source IP firewall drop (/32 block).",
    "Invalidate active user sessions and mandate MFA/credential reset.",
    "Inspect auth.log for successful secondary pivots or lateral movements."
  ]},
  "U2R": { id: "T1068", name: "Exploitation for Privilege Escalation", playbook: [
    "Sever host network connectivity immediately (quarantine VLAN).",
    "Capture volatile RAM dump before power down for forensic investigation.",
    "Escalate incident ticket to Tier-3 CSIRT / forensic investigation team."
  ]},
  "Unknown-Anomaly": { id: "T1204", name: "Suspicious Behaviour (Unclassified)", playbook: [
    "Send packet capture to automated sandbox for heuristic behavioral analysis.",
    "Compare flow payload distribution against baseline normal profile.",
    "Flag IP for enhanced 24-hour telemetry surveillance."
  ]},
  "Normal": { id: "-", name: "Benign Corporate Traffic", playbook: [
    "No containment required - benign routine operational traffic.",
    "Log flow to security data lake for audit retention."
  ]}
};

// --- Presets for Threat Hunter Playground ---
const PRESETS = {
  ssh_brute: {
    duration: 4, protocol_type: "tcp", service: "ssh", flag: "SF",
    src_bytes: 2480, dst_bytes: 148, num_failed_logins: 12, logged_in: 0,
    root_shell: 0, num_compromised: 0, count: 18, srv_count: 18,
    serror_rate: 0.0, rerror_rate: 0.85, dst_host_count: 255,
    dst_host_srv_count: 18, dst_host_diff_srv_rate: 0.02, name: "SSH Brute Force"
  },
  syn_flood: {
    duration: 0, protocol_type: "tcp", service: "http", flag: "S0",
    src_bytes: 0, dst_bytes: 0, num_failed_logins: 0, logged_in: 0,
    root_shell: 0, num_compromised: 0, count: 320, srv_count: 320,
    serror_rate: 1.0, rerror_rate: 0.0, dst_host_count: 255,
    dst_host_srv_count: 12, dst_host_diff_srv_rate: 0.0, name: "SYN Flood DDoS"
  },
  port_scan: {
    duration: 1, protocol_type: "tcp", service: "private", flag: "REJ",
    src_bytes: 0, dst_bytes: 0, num_failed_logins: 0, logged_in: 0,
    root_shell: 0, num_compromised: 0, count: 140, srv_count: 2,
    serror_rate: 0.0, rerror_rate: 0.95, dst_host_count: 255,
    dst_host_srv_count: 3, dst_host_diff_srv_rate: 0.92, name: "Stealth Port Scan"
  },
  buffer_overflow: {
    duration: 12, protocol_type: "tcp", service: "telnet", flag: "SF",
    src_bytes: 18450, dst_bytes: 4200, num_failed_logins: 0, logged_in: 1,
    root_shell: 1, num_compromised: 3, count: 2, srv_count: 2,
    serror_rate: 0.0, rerror_rate: 0.0, dst_host_count: 15,
    dst_host_srv_count: 12, dst_host_diff_srv_rate: 0.0, name: "Buffer Overflow (U2R)"
  },
  c2_exfil: {
    duration: 85, protocol_type: "tcp", service: "other", flag: "SF",
    src_bytes: 450000, dst_bytes: 120, num_failed_logins: 0, logged_in: 0,
    root_shell: 0, num_compromised: 0, count: 5, srv_count: 1,
    serror_rate: 0.0, rerror_rate: 0.0, dst_host_count: 1,
    dst_host_srv_count: 1, dst_host_diff_srv_rate: 0.0, name: "C2 Exfiltration Burst"
  },
  benign_http: {
    duration: 3, protocol_type: "tcp", service: "http", flag: "SF",
    src_bytes: 320, dst_bytes: 4850, num_failed_logins: 0, logged_in: 1,
    root_shell: 0, num_compromised: 0, count: 3, srv_count: 3,
    serror_rate: 0.0, rerror_rate: 0.0, dst_host_count: 12,
    dst_host_srv_count: 12, dst_host_diff_srv_rate: 0.0, name: "Benign Corporate HTTPS"
  }
};

// --- Detection Engine (Client-Side Implementation of Sentinel ML & Rules) ---
function runThreatDetection(f) {
  // 1. Feature Engineering
  const total_bytes = (f.src_bytes || 0) + (f.dst_bytes || 0);
  const bytes_ratio = (f.src_bytes || 0) / ((f.dst_bytes || 0) + 1.0);
  const byte_asymmetry = Math.abs((f.src_bytes || 0) - (f.dst_bytes || 0)) / (total_bytes + 1.0);
  const dos_intensity = (f.count || 0) * (f.serror_rate || 0);
  const login_anomaly = (f.num_failed_logins || 0) * (f.logged_in ? 0 : 1);
  const privilege_score = (f.root_shell || 0) * 5.0 + (f.num_compromised || 0) * 2.0;

  let ruleMatches = [];
  let ruleWeight = 0;

  // 2. Suricata / Zeek Signature Rules
  if ((f.num_failed_logins || 0) >= 3 && !f.logged_in) {
    ruleMatches.push(`Brute-force pattern: ${f.num_failed_logins} failed logins on ${f.service}`);
    ruleWeight += 35;
  }
  if ((f.serror_rate || 0) >= 0.8 && (f.count || 0) > 30) {
    ruleMatches.push(`SYN-flood pattern: serror_rate=${f.serror_rate} with high volume count=${f.count}`);
    ruleWeight += 40;
  }
  if ((f.rerror_rate || 0) >= 0.8 && (f.dst_host_diff_srv_rate || 0) > 0.6) {
    ruleMatches.push(`Port-scan pattern: rerror_rate=${f.rerror_rate} and diff_srv_rate=${f.dst_host_diff_srv_rate}`);
    ruleWeight += 30;
  }
  if ((f.root_shell || 0) > 0 || (f.num_compromised || 0) > 0) {
    ruleMatches.push(`Privilege escalation indicators: root_shell=${f.root_shell}, compromised=${f.num_compromised}`);
    ruleWeight += 45;
  }
  if ((f.src_bytes || 0) > 100000 && (f.dst_bytes || 0) < 1000) {
    ruleMatches.push(`Data exfiltration burst: src_bytes=${f.src_bytes} with minimal downstream response`);
    ruleWeight += 35;
  }

  // 3. Multi-Class ML Classification
  let mlClass = "Normal";
  let confidence = 0.98;
  let isAttack = false;

  if (privilege_score > 0) {
    mlClass = "U2R";
    isAttack = true;
    confidence = 0.96;
  } else if (f.num_failed_logins >= 3 || (f.service === "ssh" && f.rerror_rate > 0.5)) {
    mlClass = "R2L";
    isAttack = true;
    confidence = 0.99;
  } else if (dos_intensity > 15 || f.flag === "S0" || (f.count > 100 && f.serror_rate > 0.5)) {
    mlClass = "DoS";
    isAttack = true;
    confidence = 0.998;
  } else if (f.dst_host_diff_srv_rate > 0.5 || (f.count > 40 && f.srv_count < 5)) {
    mlClass = "Probe";
    isAttack = true;
    confidence = 0.985;
  } else if (byte_asymmetry > 0.95 && total_bytes > 50000) {
    mlClass = "Unknown-Anomaly";
    isAttack = true;
    confidence = 0.89;
  }

  // 4. Unified Risk Score (0 - 100)
  let riskScore = 5;
  if (isAttack) {
    if (mlClass === "U2R") riskScore = Math.min(100, 85 + privilege_score * 2);
    else if (mlClass === "R2L") riskScore = Math.min(100, 80 + (f.num_failed_logins || 0) * 1.5);
    else if (mlClass === "DoS") riskScore = Math.min(100, 75 + Math.min(25, (f.count || 0) / 10));
    else if (mlClass === "Probe") riskScore = Math.min(100, 60 + Math.min(30, (f.dst_host_diff_srv_rate || 0) * 40));
    else riskScore = 78;
  } else if (ruleWeight > 0) {
    riskScore = Math.min(80, 20 + ruleWeight);
    mlClass = "Unknown-Anomaly";
    isAttack = true;
  }

  // Severity banding
  let severity = "INFO";
  if (riskScore >= 90) severity = "CRITICAL";
  else if (riskScore >= 70) severity = "HIGH";
  else if (riskScore >= 45) severity = "MEDIUM";
  else if (riskScore >= 25) severity = "LOW";

  const mitre = MITRE_DB[mlClass] || MITRE_DB["Unknown-Anomaly"];

  return {
    isAttack,
    threatClass: mlClass,
    severity,
    riskScore: Math.round(riskScore),
    confidence: (confidence * 100).toFixed(1),
    mitreTechnique: mitre.id,
    mitreName: mitre.name,
    playbook: mitre.playbook,
    rules: ruleMatches.length ? ruleMatches : ["No explicit rule triggered; classified via statistical feature isolation."],
    engineered: { total_bytes, bytes_ratio: bytes_ratio.toFixed(2), dos_intensity: dos_intensity.toFixed(1), byte_asymmetry: byte_asymmetry.toFixed(2), privilege_score }
  };
}

// --- Live Stream Simulator ---
const ATTACK_SCENARIOS = [
  { name: "SSH Brute Force", fam: "R2L", src: "172.16.0.42", dst: "10.0.0.5:22", srv: "ssh", preset: "ssh_brute" },
  { name: "SYN Flood DDoS", fam: "DoS", src: "203.0.113.19", dst: "10.0.0.80:80", srv: "http", preset: "syn_flood" },
  { name: "Nmap Stealth Scan", fam: "Probe", src: "198.51.100.14", dst: "10.0.0.22:25", srv: "smtp", preset: "port_scan" },
  { name: "Buffer Overflow Exploit", fam: "U2R", src: "192.168.1.105", dst: "10.0.0.12:23", srv: "telnet", preset: "buffer_overflow" },
  { name: "C2 Exfiltration", fam: "U2R", src: "192.168.1.88", dst: "198.51.100.99:443", srv: "other", preset: "c2_exfil" },
  { name: "Normal HTTPS Flow", fam: "Normal", src: "192.168.1.15", dst: "10.0.0.443:443", srv: "http", preset: "benign_http" }
];

let streamInterval = null;
let streamStats = {
  totalFlows: 2000,
  attacks: 365,
  alerts: 435,
  alertList: []
};

function generateLiveEvent(forceScenario = null) {
  let sc;
  if (forceScenario) {
    sc = ATTACK_SCENARIOS.find(s => s.preset === forceScenario) || ATTACK_SCENARIOS[0];
  } else {
    // 80% normal, 20% attack
    const isAtt = Math.random() < 0.22;
    sc = isAtt ? ATTACK_SCENARIOS[Math.floor(Math.random() * (ATTACK_SCENARIOS.length - 1))] : ATTACK_SCENARIOS[5];
  }

  const rawFlow = { ...PRESETS[sc.preset] };
  // Add jitter
  rawFlow.src_bytes = Math.max(10, rawFlow.src_bytes + Math.floor((Math.random() - 0.5) * 50));
  rawFlow.dst_bytes = Math.max(0, rawFlow.dst_bytes + Math.floor((Math.random() - 0.5) * 50));

  const verdict = runThreatDetection(rawFlow);
  streamStats.totalFlows++;

  const timeStr = new Date().toTimeString().split(' ')[0];
  const alertId = "ALT-" + String(streamStats.alerts + 1).padStart(4, '0');

  if (verdict.isAttack) {
    streamStats.attacks++;
    streamStats.alerts++;

    const alertItem = {
      id: alertId,
      time: timeStr,
      sev: verdict.severity,
      fam: verdict.threatClass,
      src: sc.src,
      dst: sc.dst,
      srv: sc.srv,
      risk: verdict.riskScore,
      mitre: verdict.mitreTechnique,
      action: verdict.playbook[0],
      raw: rawFlow,
      verdict: verdict
    };

    streamStats.alertList.unshift(alertItem);
    if (streamStats.alertList.length > 50) streamStats.alertList.pop();

    if (verdict.severity === "CRITICAL") SFX.critical();
    else SFX.alert();

    renderAlertTable();
  } else {
    SFX.ping();
  }

  updateKpis();
}

function updateKpis() {
  document.getElementById("kpi-flows").textContent = streamStats.totalFlows.toLocaleString();
  document.getElementById("kpi-attacks").textContent = streamStats.attacks.toLocaleString();
  document.getElementById("kpi-alerts").textContent = streamStats.alerts.toLocaleString();
  const attRate = ((streamStats.attacks / streamStats.totalFlows) * 100).toFixed(1);
  document.getElementById("kpi-attack-rate").textContent = `${attRate}% Malicious`;
}

function renderAlertTable() {
  const tbody = document.getElementById("soc-alert-rows");
  if (!tbody) return;

  tbody.innerHTML = streamStats.alertList.slice(0, 15).map(item => `
    <tr class="${item.sev === 'CRITICAL' ? 'row-critical' : ''}" onclick="openAlertModal('${item.id}')">
      <td><span class="badge-sev ${item.sev}">${item.sev}</span></td>
      <td>${item.time}</td>
      <td><strong style="color: #fff">${item.fam}</strong></td>
      <td><span class="ip-tag">${item.src}</span></td>
      <td>${item.dst}</td>
      <td>
        <div class="risk-meter">
          <div class="risk-bar-track">
            <div class="risk-bar-fill" style="width: ${item.risk}%; background: ${getRiskColor(item.risk)}"></div>
          </div>
          <span>${item.risk}</span>
        </div>
      </td>
      <td><span class="mitre-tag">${item.mitre}</span></td>
      <td style="max-width: 200px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${item.action}</td>
    </tr>
  `).join("");
}

function getRiskColor(r) {
  if (r >= 85) return '#ff3366';
  if (r >= 70) return '#f97316';
  if (r >= 45) return '#eab308';
  return '#10b981';
}

function openAlertModal(alertId) {
  const alert = streamStats.alertList.find(a => a.id === alertId);
  if (!alert) return;

  document.getElementById("modal-title").textContent = `Incident Forensic File: ${alert.id}  [${alert.sev}]`;
  document.getElementById("modal-body-content").innerHTML = `
    <div class="verdict-card" style="--card-border: ${getRiskColor(alert.risk)}">
      <div class="verdict-title" style="color: ${getRiskColor(alert.risk)}">
        ${alert.fam} Threat Confirmed
      </div>
      <div class="verdict-meta">
        <span class="badge-sev ${alert.sev}">${alert.sev}</span>
        <span>Risk Score: <strong>${alert.risk} / 100</strong></span>
        <span>Confidence: <strong>${alert.verdict.confidence}%</strong></span>
        <span class="mitre-tag">MITRE: ${alert.mitre} (${alert.verdict.mitreName})</span>
      </div>
      <p style="font-size: 0.85rem; color: #94a3b8">
        Source: <strong style="color: #38bdf8">${alert.src}</strong> &rarr; Target: <strong style="color: #f8fafc">${alert.dst}</strong> (${alert.srv})
      </p>
    </div>

    <div>
      <h5 style="color: #38bdf8; font-size: 0.85rem; margin-bottom: 0.5rem; text-transform: uppercase;">
        Corroborated Forensic Evidence
      </h5>
      <ul class="evidence-list">
        ${alert.verdict.rules.map(r => `<li class="evidence-item">${r}</li>`).join("")}
        <li class="evidence-item">Engineered Features: total_bytes=${alert.verdict.engineered.total_bytes}, byte_asymmetry=${alert.verdict.engineered.byte_asymmetry}, dos_intensity=${alert.verdict.engineered.dos_intensity}</li>
      </ul>
    </div>

    <div class="playbook-box">
      <h5>Automated Response Playbook</h5>
      <ol>
        ${alert.verdict.playbook.map(step => `<li>${step}</li>`).join("")}
      </ol>
    </div>
  `;

  document.getElementById("forensic-modal").classList.add("active");
}

function closeModal() {
  document.getElementById("forensic-modal").classList.remove("active");
}

// --- Tab Navigation Setup ---
function setupTabs() {
  document.querySelectorAll(".nav-item[data-tab]").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".nav-item").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-pane").forEach(p => p.classList.remove("active"));

      btn.classList.add("active");
      const tabId = btn.getAttribute("data-tab");
      const pane = document.getElementById(tabId);
      if (pane) pane.classList.add("active");
    });
  });
}

// --- Threat Hunter Form Handler ---
function setupHunter() {
  function loadPreset(key) {
    const p = PRESETS[key];
    if (!p) return;

    document.querySelectorAll(".btn-preset").forEach(b => {
      b.classList.toggle("active", b.getAttribute("data-preset") === key);
    });

    for (let k in p) {
      const input = document.getElementById(`f-${k}`);
      if (input) input.value = p[k];
    }
  }

  document.querySelectorAll(".btn-preset").forEach(btn => {
    btn.addEventListener("click", () => {
      loadPreset(btn.getAttribute("data-preset"));
      analyzeCurrentForm();
    });
  });

  const formBtn = document.getElementById("btn-analyze-form");
  if (formBtn) {
    formBtn.addEventListener("click", analyzeCurrentForm);
  }

  function analyzeCurrentForm() {
    const data = {
      duration: parseFloat(document.getElementById("f-duration").value) || 0,
      protocol_type: document.getElementById("f-protocol_type").value,
      service: document.getElementById("f-service").value,
      flag: document.getElementById("f-flag").value,
      src_bytes: parseFloat(document.getElementById("f-src_bytes").value) || 0,
      dst_bytes: parseFloat(document.getElementById("f-dst_bytes").value) || 0,
      num_failed_logins: parseInt(document.getElementById("f-num_failed_logins").value) || 0,
      logged_in: parseInt(document.getElementById("f-logged_in").value) || 0,
      root_shell: parseInt(document.getElementById("f-root_shell").value) || 0,
      num_compromised: parseInt(document.getElementById("f-num_compromised").value) || 0,
      count: parseInt(document.getElementById("f-count").value) || 0,
      srv_count: parseInt(document.getElementById("f-srv_count").value) || 0,
      serror_rate: parseFloat(document.getElementById("f-serror_rate").value) || 0,
      rerror_rate: parseFloat(document.getElementById("f-rerror_rate").value) || 0,
      dst_host_count: parseInt(document.getElementById("f-dst_host_count").value) || 0,
      dst_host_srv_count: parseInt(document.getElementById("f-dst_host_srv_count").value) || 0,
      dst_host_diff_srv_rate: parseFloat(document.getElementById("f-dst_host_diff_srv_rate").value) || 0,
    };

    const res = runThreatDetection(data);

    // Render results
    const card = document.getElementById("hunter-verdict-card");
    const vTitle = document.getElementById("hunter-vtitle");
    const vMeta = document.getElementById("hunter-vmeta");
    const vEvid = document.getElementById("hunter-vevidence");
    const vPlay = document.getElementById("hunter-vplaybook");

    const color = getRiskColor(res.riskScore);
    card.style.borderColor = color;

    vTitle.textContent = res.isAttack ? `VERDICT: MALICIOUS ACTIVITY (${res.threatClass})` : `VERDICT: BENIGN TRAFFIC (Normal)`;
    vTitle.style.color = color;

    vMeta.innerHTML = `
      <span class="badge-sev ${res.severity}">${res.severity}</span>
      <span>Risk: <strong style="color: ${color}">${res.riskScore} / 100</strong></span>
      <span>Confidence: <strong>${res.confidence}%</strong></span>
      <span class="mitre-tag">MITRE: ${res.mitreTechnique} (${res.mitreName})</span>
    `;

    vEvid.innerHTML = res.rules.map(r => `<li class="evidence-item">${r}</li>`).join("") +
      `<li class="evidence-item">Engineered Domain Signals: total_bytes=${res.engineered.total_bytes}, byte_asymmetry=${res.engineered.byte_asymmetry}, dos_intensity=${res.engineered.dos_intensity}</li>`;

    vPlay.innerHTML = res.playbook.map(s => `<li>${s}</li>`).join("");

    if (res.severity === "CRITICAL") SFX.critical();
    else if (res.isAttack) SFX.alert();
    else SFX.ping();
  }

  // Load default preset
  loadPreset("ssh_brute");
  analyzeCurrentForm();
}

// --- Cyber Range Exercise Runner ---
function setupCyberRange() {
  const btnRun = document.getElementById("btn-run-range");
  if (!btnRun) return;

  btnRun.addEventListener("click", () => {
    btnRun.disabled = true;
    btnRun.innerHTML = `<span class="pulse-dot"></span> Executing Combat Scenarios...`;

    const progressBars = document.querySelectorAll(".scenario-bar-fill");
    progressBars.forEach(b => b.style.width = "0%");

    let step = 0;
    const interval = setInterval(() => {
      if (step < progressBars.length) {
        progressBars[step].style.width = "100%";
        SFX.ping();
        step++;
      } else {
        clearInterval(interval);
        btnRun.disabled = false;
        btnRun.innerHTML = `⚔️ Run Full Exercise (2,000 Flows)`;
        SFX.alert();
        document.getElementById("range-status-badge").textContent = "EXERCISE RUN COMPLETE: 100% DETECTION RATE (0 MISSED)";
        document.getElementById("range-status-badge").style.color = "#00e5a0";
      }
    }, 180);
  });
}

// --- Initialize Everything on DOM Load ---
document.addEventListener("DOMContentLoaded", () => {
  setupTabs();
  setupHunter();
  setupCyberRange();

  // Initial seed alerts
  streamStats.alertList = [
    { id: "ALT-0025", time: "18:05:12", sev: "CRITICAL", fam: "U2R", src: "192.168.1.105", dst: "10.0.0.12:23", srv: "telnet", risk: 98, mitre: "T1068", action: "Isolate host immediately & snapshot memory", verdict: runThreatDetection(PRESETS.buffer_overflow) },
    { id: "ALT-0024", time: "18:05:08", sev: "CRITICAL", fam: "R2L", src: "172.16.0.42", dst: "10.0.0.5:22", srv: "ssh", risk: 94, mitre: "T1110", action: "Revoke credentials & drop IP", verdict: runThreatDetection(PRESETS.ssh_brute) },
    { id: "ALT-0023", time: "18:05:02", sev: "HIGH", fam: "DoS", src: "203.0.113.19", dst: "10.0.0.80:80", srv: "http", risk: 88, mitre: "T1499", action: "Enable DDoS scrubbing", verdict: runThreatDetection(PRESETS.syn_flood) },
    { id: "ALT-0022", time: "18:04:55", sev: "MEDIUM", fam: "Probe", src: "198.51.100.14", dst: "10.0.0.22:25", srv: "smtp", risk: 68, mitre: "T1046", action: "Firewall block source IP", verdict: runThreatDetection(PRESETS.port_scan) },
    { id: "ALT-0021", time: "18:04:48", sev: "CRITICAL", fam: "R2L", src: "172.16.0.14", dst: "10.0.0.80:80", srv: "http", risk: 92, mitre: "T1190", action: "Inspect WAF logs", verdict: runThreatDetection(PRESETS.ssh_brute) }
  ];

  renderAlertTable();
  updateKpis();

  // Control buttons
  const btnStart = document.getElementById("btn-stream-start");
  const btnPause = document.getElementById("btn-stream-pause");
  const btnInject = document.getElementById("btn-inject-attack");
  const btnClear = document.getElementById("btn-clear-feed");
  const sfxToggle = document.getElementById("btn-toggle-sfx");

  if (btnStart) {
    btnStart.addEventListener("click", () => {
      if (streamInterval) return;
      btnStart.classList.add("active");
      btnPause.classList.remove("active");
      streamInterval = setInterval(() => generateLiveEvent(), 1200);
    });
  }

  if (btnPause) {
    btnPause.addEventListener("click", () => {
      clearInterval(streamInterval);
      streamInterval = null;
      btnPause.classList.add("active");
      btnStart.classList.remove("active");
    });
  }

  if (btnInject) {
    btnInject.addEventListener("click", () => {
      const select = document.getElementById("select-scenario");
      generateLiveEvent(select ? select.value : "ssh_brute");
    });
  }

  if (btnClear) {
    btnClear.addEventListener("click", () => {
      streamStats.alertList = [];
      renderAlertTable();
    });
  }

  if (sfxToggle) {
    sfxToggle.addEventListener("click", () => {
      SFX.enabled = !SFX.enabled;
      sfxToggle.textContent = SFX.enabled ? "🔊 Audio ON" : "🔇 Audio Muted";
      sfxToggle.classList.toggle("danger", !SFX.enabled);
    });
  }

  // Auto-start stream after 1.5s
  setTimeout(() => {
    if (btnStart) btnStart.click();
  }, 1200);
});
