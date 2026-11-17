/* =========================================================================
   common.js - shared helpers for every page
   ========================================================================= */
const $  = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));

async function api(path, opts) {
  const res = await fetch(path, Object.assign({
    headers: {'Content-Type': 'application/json'}
  }, opts || {}));
  if (!res.ok) throw new Error(`${path} -> HTTP ${res.status}`);
  return res.json();
}
const post = (p, body) => api(p, {method:'POST', body: JSON.stringify(body || {})});

const esc = s => String(s == null ? '' : s)
  .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const nf  = (n, d = 0) => Number(n || 0).toLocaleString(undefined,
  {minimumFractionDigits:d, maximumFractionDigits:d});
const pct = (n, d = 1) => (100 * Number(n || 0)).toFixed(d) + '%';
const shortTime = t => String(t || '').split(' ')[1] || t || '';

function toast(title, msg, color) {
  const w = $('#toasts'); if (!w) return;
  const d = document.createElement('div');
  d.className = 'toast';
  d.style.borderLeftColor = color || '#ff4d5e';
  d.innerHTML = `<b style="color:${color || '#ff4d5e'}">${esc(title)}</b>${esc(msg)}`;
  w.appendChild(d);
  setTimeout(() => d.remove(), 6000);
  while (w.children.length > 5) w.firstChild.remove();
}

function chip(sev) { return `<span class="chip sev-${esc(sev)}">${esc(sev)}</span>`; }
function classTag(c) { return `<span class="cls-${esc(c)}" style="font-weight:700">${esc(c)}</span>`; }
function riskBar(v) { return `<span class="riskbar"><i style="width:${Math.min(100, v)}%"></i></span>
  <b class="mono" style="font-size:11px;margin-left:6px">${Number(v).toFixed(0)}</b>`; }

/* ---- live clock in the topbar ----------------------------------------- */
setInterval(() => {
  const c = $('#clock');
  if (c) c.textContent = new Date().toLocaleTimeString('en-GB');
}, 1000);

/* ---- load global health into the sidebar ------------------------------ */
(async function health() {
  try {
    const h = await api('/api/health');
    const v = $('#model-ver'); if (v) v.textContent = h.model_version || 'n/a';
    const s = $('#health-status');
    if (s) s.textContent = `engine online · ${nf(h.events_processed)} events`;
  } catch (e) { const s = $('#health-status'); if (s) s.textContent = 'engine offline'; }
})();
