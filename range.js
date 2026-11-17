/* =========================================================================
   range.js - Virtual Cyber Range page
   Runs a full, reproducible attack simulation and renders an honest report
   (ground truth vs. model decision, per scenario).
   ========================================================================= */
const rateEl = $('#attack-rate');
rateEl.oninput = () => $('#rate-label').textContent = rateEl.value + '%';
$('#random-seed').onclick = () => $('#seed').value = Math.floor(Math.random() * 99999);

async function runExercise() {
  const btn = $('#run-btn');
  btn.disabled = true; btn.textContent = '⏳ generating, scoring, correlating…';
  $('#run-status').textContent = 'working…';
  const t0 = performance.now();
  try {
    const res = await post('/api/simulate', {
      n_events: parseInt($('#n-events').value, 10),
      attack_rate: parseInt(rateEl.value, 10) / 100,
      seed: $('#seed').value
    });
    render(res);
    const secs = ((performance.now() - t0) / 1000).toFixed(1);
    $('#run-status').innerHTML = `<span class="hl">✓ completed in ${secs}s</span>`;
    toast('Exercise complete', `${nf(res.summary.true_attacks)} attacks generated · ${nf(res.summary.alerts)} alerts · recall ${pct(res.summary.recall)}`, '#00e5a0');
  } catch (e) {
    console.error(e); $('#run-status').textContent = 'failed — see console';
    toast('Exercise failed', String(e), '#ff4d5e');
  } finally {
    btn.disabled = false; btn.textContent = '▶ Run cyber-range exercise';
  }
}

function render(res) {
  const s = res.summary;
  $('#r-precision').textContent = pct(s.precision);
  $('#r-recall').textContent = pct(s.recall);
  $('#r-f1').textContent = pct(s.f1_score);
  $('#r-events').textContent = nf(res.config.n_events);
  $('#r-truth').textContent = nf(s.true_attacks);
  $('#r-alerts').textContent = nf(s.alerts);

  const cm = s.confusion_matrix;
  heatmap($('#r-cm'), [[cm.tn, cm.fp], [cm.fn, cm.tp]], ['Benign', 'Attack'], ['Benign', 'Attack']);

  // per-scenario detection bars (colour-coded by quality)
  const wrap = $('#r-scenarios'); wrap.innerHTML = '';
  res.per_scenario.forEach(r => {
    const good = r.detection_rate_pct >= 95, mid = r.detection_rate_pct >= 70;
    const color = good ? '#00e5a0' : mid ? '#ffb020' : '#ff4d5e';
    const d = document.createElement('div'); d.className = 'bar-row';
    d.style.gridTemplateColumns = '280px 1fr 190px';
    d.innerHTML = `<span class="mini">${esc(r.scenario)}</span>
      <span class="bar-track" title="${r.detected}/${r.events} detected">
        <i class="bar-fill" style="width:${r.detection_rate_pct}%;background:linear-gradient(90deg,${color}99,${color})"></i></span>
      <b class="mono" style="font-size:11.5px">${r.detection_rate_pct}% <span style="color:#5f7398">(${r.detected}/${r.events})</span> · risk ${r.avg_risk}</b>`;
    wrap.appendChild(d);
  });

  // verdict sample
  $('#r-verdicts').innerHTML = res.verdicts.map(v => {
    const good = v.truth === v.predicted;
    const mark = good ? (v.truth ? '✓' : '·') : (v.truth ? '✗' : '⚠');
    const color = good ? (v.truth ? '#00e5a0' : '#4d5f80') : '#ff4d5e';
    const time = (v.timestamp || '').split(' ')[1] || '';
    return `<tr class="${v.predicted ? 'row-attack' : ''}">
      <td class="mono mini">${esc(time)}</td>
      <td class="mono mini">${esc(v.src_ip)}</td>
      <td class="mono mini">${esc(v.dst_ip)}</td>
      <td><span class="tag">${esc(v.service)}</span></td>
      <td class="mini">${esc(v.scenario)}</td>
      <td class="mini mono" style="color:${v.truth ? '#ff8ea1' : '#8ff0d2'}">${v.truth ? 'ATTACK' : 'benign'}</td>
      <td>${v.predicted ? classTag(v.threat_class) : '<span class="mini">benign</span>'} <b style="color:${color}">${mark}</b></td>
      <td>${riskBar(v.risk)}</td>
      <td class="mono mini">${v.anomaly_score}</td>
      <td class="mini" style="max-width:330px">${esc(v.reason)}</td></tr>`;
  }).join('');
}

$('#run-btn').onclick = runExercise;
// auto-run one exercise when the page opens so students immediately see data
setTimeout(runExercise, 400);
