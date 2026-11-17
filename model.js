/* =========================================================================
   model.js - Model Intelligence page: reads the artefacts written by
   train.py / evaluate.py and renders them for recruiters and analysts.
   ========================================================================= */
const ENG = ['total_bytes','bytes_ratio','byte_asymmetry','dos_intensity','host_scan_ratio',
             'service_concentration','login_anomaly','privilege_score','payload_per_packet',
             'traffic_entropy','is_wellknown_port','error_flag_count','critical_service'];

function metricRow(r) {
  return `<tr>
    <td><b>${esc(r.model)}</b>${r.note ? `<div class="mini">${esc(r.note)}</div>` : ''}</td>
    <td class="mono">${r.accuracy.toFixed(4)}</td>
    <td class="mono">${r.precision.toFixed(4)}</td>
    <td class="mono" style="color:#00e5a0">${r.recall.toFixed(4)}</td>
    <td class="mono" style="color:#ffb020">${r.f1_score.toFixed(4)}</td>
    <td class="mono">${(r.false_positive_rate ?? 0).toFixed(4)}</td>
    <td class="mono">${r.roc_auc != null ? r.roc_auc.toFixed(4) : '—'}</td></tr>`;
}

(async function main() {
  const [m, f] = await Promise.all([api('/api/model'), api('/api/features')]);
  const meta = m.metadata || {};
  $('#m-ver').textContent = 'v' + (meta.model_version || '—');
  $('#m-trees').textContent = (meta.hyperparameters?.random_forest?.n_estimators) || '200';
  $('#m-rows').textContent = nf(meta.n_train_samples) + ' (+ ' + nf(meta.n_test_samples) + ' test)';
  $('#m-feats').textContent = nf(meta.n_features_encoded) + ' encoded features';
  $('#m-thr').textContent = (meta.anomaly_threshold ?? '—') +
    ` (p${meta.anomaly_threshold_percentile || 99} of normal scores)`;

  const om = m.offline_metrics || {};
  if (om.holdout_random_split) {
    $('#t-holdout tbody').innerHTML =
      Object.values(om.holdout_random_split).map(metricRow).join('') +
      (om.hybrid_detector ? metricRow(om.hybrid_detector.hybrid_ml_or_anomaly) : '');
  }
  if (om.official_kddtest_split) {
    $('#t-official tbody').innerHTML =
      Object.values(om.official_kddtest_split).map(metricRow).join('');
  }

  // per-class bars
  const pc = om.holdout_random_split?.random_forest?.per_class || {};
  const rows = ['Normal','DoS','Probe','R2L','U2R'].filter(k => pc[k]).map(k => ({
    label: `${k} — ${nf(pc[k].support)} flows`, value: 100 * pc[k].recall,
    color: {Normal:'#00e5a0',DoS:'#ff4d5e',Probe:'#ffb020',R2L:'#a97bff',U2R:'#ff6ba9'}[k]
  }));
  hBars($('#perclass'), rows, {pct:true});

  // feature importance (flag engineered ones)
  hBars($('#features'), (f.features || []).map(x => ({
    label: x.feature,
    value: Math.round(x.importance * 10000),
    color: ENG.includes(x.feature) ? '#00e5a0' : '#4da3ff'
  })));

  // figures gallery
  const figs = ['01_dataset_class_distribution','02_attack_type_distribution','03_feature_importance',
    '04_confusion_matrix_rf','05_model_comparison','06_anomaly_score_distribution','07_roc_curve',
    '08_live_detection_timeline','09_engineered_features','10_risk_score_histogram'];
  $('#gallery').innerHTML = figs.map(n => `
    <div class="card" style="padding:10px">
      <img src="/figures/${n}.png" alt="${n}" style="width:100%;border-radius:8px;border:1px solid #1e2c46"/>
      <div class="mini mono" style="margin-top:8px">images/${n}.png</div>
    </div>`).join('');
})();
