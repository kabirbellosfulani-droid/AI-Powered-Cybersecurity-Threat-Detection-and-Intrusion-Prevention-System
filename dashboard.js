/* =========================================================================
   dashboard.js - live SOC console logic
   Polls the API, renders KPIs + charts + the alert feed, and runs the
   streaming simulation ("Inject attack burst" / auto-stream toggle).
   ========================================================================= */
let streaming = true;
let attackRate = 0.18;
let timer = null;

/* ------------------------------------------------------------- rendering */
function renderKPIs(s) {
  $('#k-events').textContent  = nf(s.events_scanned);
  $('#k-attacks').textContent = nf(s.attacks_detected);
  $('#k-alerts').textContent  = nf(s.alerts_raised);
  $('#k-recall').textContent  = s.recall ? pct(s.recall, 1) : '—';
  $('#k-pf').textContent      = s.precision ? `${pct(s.precision,1)} / ${pct(s.f1_score,1)}` : '—';
  const sev = s.by_severity || {};
  $('#k-alerts-sub').textContent =
    `critical: ${sev.CRITICAL || 0} · high: ${sev.HIGH || 0} · medium: ${sev.MEDIUM || 0}`;
  $('#k-attacks-sub').textContent = `${s.attack_rate_pct}% of all traffic is malicious`;
  $('#k-events-sub').textContent  = `avg risk score ${s.avg_risk_score} · uptime ${Math.round(s.uptime_seconds)}s`;

  $('#k-risk').textContent = s.avg_risk_score;
  $('#k-tp').textContent = nf(s.confusion_matrix.tp);
  $('#k-fp').textContent = nf(s.confusion_matrix.fp);
  $('#k-fn').textContent = nf(s.confusion_matrix.fn);

  gauge($('#g-precision'), s.precision, 'Precision', {color:'#4da3ff'});
  gauge($('#g-recall'),    s.recall,    'Recall',    {color:'#00e5a0'});
  gauge($('#g-f1'),        s.f1_score,  'F1 score',  {color:'#ffb020'});

  const fam = Object.entries(s.by_family || {})
    .filter(([, v]) => v > 0).map(([label, value]) => ({label, value}));
  donut($('#chart-family'), fam, {centreLabel:'flows scored'});

  const sevRows = ['CRITICAL','HIGH','MEDIUM','LOW','INFO']
    .map(k => ({label:k, value: sev[k] || 0, color: SEV_COLORS[k]}))
    .filter(r => r.value > 0);
  hBars($('#chart-severity'), sevRows);

  hBars($('#chart-srcip'), (s.top_source_ips || []).map(([label, value]) => ({label, value})), {});
  hBars($('#chart-dstip'), (s.top_target_assets || []).map(([label, value]) => ({label, value, color:'#22d3ee'})), {});

  const cm = s.confusion_matrix;
  heatmap($('#chart-cm'), [[cm.tn, cm.fp], [cm.fn, cm.tp]], ['Benign', 'Attack'], ['Benign','Attack']);
}

function renderSeries(series) {
  if (!series.length) return;
  lineChart($('#chart-timeline'), [
    {name:'Flows',  color:C.blue,   data: series.map(x => x.events)},
    {name:'True attacks', color:C.red, data: series.map(x => x.attacks), fill:false},
    {name:'Model alerts', color:C.amber, data: series.map(x => x.alerts), fill:false, dashed:true},
  ], {labels: series.map(x => x.t), height:250});
}

const seenAlerts = new Set();
function renderAlerts(alerts, announce = false) {
  const body = $('#alert-body');
  const filter = $('#sev-filter').value;
  let rows = alerts;
  if (filter !== 'ALL') rows = rows.filter(a => a.severity === filter);
  if (!rows.length) { body.innerHTML = '<tr><td colspan="9" class="empty">No alerts match this filter yet.</td></tr>'; return; }

  body.innerHTML = rows.slice(0, 60).map(a => {
    const fresh = !seenAlerts.has(a.alert_id);
    return `<tr class="row-attack ${fresh ? 'flash' : ''}" title="${esc(a.action)}">
      <td class="mono mini">${esc(shortTime(a.timestamp))}</td>
      <td>${chip(a.severity)}</td>
      <td>${classTag(a.threat_class)}</td>
      <td class="mono mini">${esc(a.src_ip)} → ${esc(a.dst_ip)}</td>
      <td><span class="tag">${esc(a.service)}</span></td>
      <td>${riskBar(a.risk_score)}</td>
      <td class="mono mini">${(100 * a.confidence).toFixed(0)}%</td>
      <td class="mini">${esc(a.mitre)}</td>
      <td class="mini" style="max-width:320px">${esc(a.reason)}</td>
    </tr>`;
  }).join('');

  rows.slice(0, 6).forEach(a => {
    if (!seenAlerts.has(a.alert_id)) {
      seenAlerts.add(a.alert_id);
      if (announce && (a.severity === 'CRITICAL' || a.severity === 'HIGH')) {
        toast(`${a.severity} ${a.threat_class}`, `${a.src_ip} → ${a.dst_ip} (${a.service}) · ${a.reason.split(';')[0]}`, SEV_COLORS[a.severity]);
      }
    }
  });
}

function renderEvents(events) {
  $('#event-body').innerHTML = events.slice(0, 40).map(e => `<tr>
    <td class="mono mini">${esc(shortTime(e.timestamp))}</td>
    <td class="mono mini">${esc(e.src_ip)}</td>
    <td class="mono mini">${esc(e.dst_ip)}</td>
    <td><span class="tag">${esc(e.service)}</span></td>
    <td class="mono mini">${nf(e.src_bytes)} / ${nf(e.dst_bytes)}</td>
    <td>${e.is_attack ? classTag(e.threat_class) : '<span class="cls-Normal">benign</span>'}</td>
    <td>${riskBar(e.risk_score)}</td></tr>`).join('')
    || '<tr><td colspan="7" class="empty">No flows yet</td></tr>';
}

/* ------------------------------------------------------------- workflow */
async function refresh(withStream) {
  try {
    const [summary, series, alerts, events] = await Promise.all([
      api('/api/summary'), api('/api/series'),
      api('/api/alerts?limit=60'), api('/api/events?limit=40')
    ]);
    renderKPIs(summary);
    renderSeries(series.series);
    renderAlerts(alerts.alerts, withStream);
    renderEvents(events.events);
    const sc = {};
    events.events.forEach(e => { sc[e.scenario] = (sc[e.scenario] || 0) + 1; });
    hBars($('#chart-scenario'), Object.entries(sc).sort((a, b) => b[1] - a[1]).slice(0, 9)
      .map(([label, value]) => ({label, value, color:'#a97bff'})));
  } catch (err) { console.error(err); }
}

async function tick() {
  if (!streaming) return;
  try { await post('/api/stream/next', {n: 12, attack_rate: attackRate}); } catch (e) { console.error(e); }
  await refresh(true);
}

/* ---------------------------------------------------------------- events */
$('#toggle-stream').onclick = () => {
  streaming = !streaming;
  $('#toggle-stream').innerHTML = streaming ? '⏸ Pause stream' : '▶ Resume stream';
  $('#stream-label').textContent = streaming ? 'streaming' : 'paused';
  $('#stream-pill').className = 'pill ' + (streaming ? 'live' : 'paused');
};
$('#burst-btn').onclick = async () => {
  const btn = $('#burst-btn'); btn.disabled = true; btn.textContent = '⚡ injecting…';
  try {
    await post('/api/stream/next', {n: 45, attack_rate: 0.42});
    await refresh(true);
    toast('Attack burst injected', '45 flows · 42% malicious — watch the alert feed and gauges move.', '#ffb020');
  } finally { btn.disabled = false; btn.textContent = '⚡ Inject attack burst'; }
};
$('#sev-filter').onchange = () => refresh(false);
$('#refresh-btn').onclick = () => refresh(false);
$('#reset-btn').onclick = async () => {
  if (!confirm('Clear all live state (events, alerts, KPIs)?')) return;
  await post('/api/reset'); seenAlerts.clear(); await refresh(false);
  toast('State reset', 'Live counters cleared — the engine keeps running.', '#4da3ff');
};

/* auto-tuning: keyboard shortcut */
document.addEventListener('keydown', e => {
  if (e.key === ' ') { $('#toggle-stream').click(); e.preventDefault(); }
});

refresh(false);
timer = setInterval(tick, 2600);
