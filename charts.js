/* =========================================================================
   charts.js - a tiny dependency-free SVG chart library
   Written from scratch so the dashboard loads with ZERO external requests
   (works offline, inside sandboxes, and on a plane).
   Charts: line/area (multi-series), donut, horizontal bars, heatmap, gauge,
           sparkline.
   ========================================================================= */
const C = {
  green:'#00e5a0', red:'#ff4d5e', amber:'#ffb020', blue:'#4da3ff',
  purple:'#a97bff', teal:'#22d3ee', pink:'#ff6ba9', grid:'#1e2c46',
  txt:'#8ea3c4', dim:'#5f7398'
};
const FAMILY_COLORS = {
  Normal:C.green, DoS:C.red, Probe:C.amber, R2L:C.purple, U2R:C.pink,
  'Unknown-Anomaly':C.teal, Critical:C.red, High:'#ff8a3d', Medium:'#ffd23f',
  Low:'#7bb8ff', Info:'#3fd6a8'
};
const SEV_COLORS = {CRITICAL:'#ff3b5c',HIGH:'#ff8a3d',MEDIUM:'#ffd23f',LOW:'#7bb8ff',INFO:'#3fd6a8'};

const el = (tag, attrs = {}, kids = []) => {
  const n = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs)) if (v !== null && v !== undefined) n.setAttribute(k, v);
  (Array.isArray(kids) ? kids : [kids]).forEach(k => k && n.appendChild(k));
  return n;
};
const txt = (x, y, t, o = {}) => {
  const n = el('text', Object.assign({x, y, fill:o.fill||C.txt, 'font-size':o.size||10,
    'text-anchor':o.anchor||'start','font-family':'Inter,sans-serif','font-weight':o.weight||500}, o.extra));
  n.textContent = t; return n;
};

/* --------------------------------------------------------------- line/area */
function lineChart(node, series, opts = {}) {
  node.innerHTML = '';
  const W = opts.width || node.clientWidth || 640, H = opts.height || 240;
  const P = {t:16, r:14, b:26, l:44};
  const svg = el('svg', {viewBox:`0 0 ${W} ${H}`, width:'100%', height:H});
  const iw = W - P.l - P.r, ih = H - P.t - P.b;
  let max = 1;
  series.forEach(s => s.data.forEach(v => { if (v > max) max = v; }));
  max = Math.max(max * 1.15, 5);
  const n = Math.max(...series.map(s => s.data.length), 2);

  // grid + y axis
  for (let i = 0; i <= 4; i++) {
    const y = P.t + ih * i / 4, val = Math.round(max * (1 - i / 4));
    svg.appendChild(el('line', {x1:P.l, y1:y, x2:W - P.r, y2:y, stroke:C.grid, 'stroke-width':1}));
    svg.appendChild(txt(P.l - 8, y + 3, val.toLocaleString(), {anchor:'end', fill:C.dim, size:9.5}));
  }
  const X = i => P.l + (n === 1 ? iw : iw * i / (n - 1));
  const Y = v => P.t + ih - ih * (v / max);

  series.forEach((s, si) => {
    if (!s.data.length) return;
    const color = s.color || C.green;
    const pts = s.data.map((v, i) => `${X(i)},${Y(v)}`).join(' ');
    if (s.fill !== false) {
      const gid = `g${Math.random().toString(36).slice(2, 8)}`;
      svg.appendChild(el('defs', {}, el('linearGradient', {id:gid, x1:0, y1:0, x2:0, y2:1}, [
        el('stop', {offset:'0%', 'stop-color':color, 'stop-opacity':.38}),
        el('stop', {offset:'100%', 'stop-color':color, 'stop-opacity':0})
      ])));
      svg.appendChild(el('polygon', {points:`${P.l},${P.t + ih} ${pts} ${X(n - 1)},${P.t + ih}`,
        fill:`url(#${gid})`, stroke:'none'}));
    }
    svg.appendChild(el('polyline', {points:pts, fill:'none', stroke:color, 'stroke-width':2.2,
      'stroke-linejoin':'round', 'stroke-linecap':'round',
      'stroke-dasharray': s.dashed ? '5 4' : null}));
    s.data.forEach((v, i) => {
      if (i === s.data.length - 1)
        svg.appendChild(el('circle', {cx:X(i), cy:Y(v), r:3.6, fill:color, stroke:'#08101d', 'stroke-width':2}));
    });
  });
  // x labels
  const labels = opts.labels || [];
  if (labels.length) {
    [0, Math.floor(labels.length / 2), labels.length - 1].forEach(i =>
      labels[i] && svg.appendChild(txt(X(i), H - 8, labels[i], {anchor:'middle', fill:C.dim, size:9.5})));
  }
  node.appendChild(svg);
  if (opts.legend !== false) {
    const lg = document.createElement('div'); lg.className = 'legend';
    series.forEach(s => {
      const sp = document.createElement('span');
      sp.innerHTML = `<i class="sw" style="background:${s.color || C.green}"></i>${s.name}`;
      lg.appendChild(sp);
    });
    node.appendChild(lg);
  }
}

/* ------------------------------------------------------------------- donut */
function donut(node, data, opts = {}) {
  node.innerHTML = '';
  const R = opts.size || 132, r = R * 0.62, cx = R, cy = R;
  const svg = el('svg', {viewBox:`0 0 ${R * 2} ${R * 2}`, width:R * 2, height:R * 2});
  const total = data.reduce((a, b) => a + b.value, 0) || 1;
  let ang = -Math.PI / 2;
  data.forEach(d => {
    const slice = (d.value / total) * Math.PI * 2;
    if (slice <= 0) return;
    const a2 = ang + slice;
    const p = (a, rad) => [cx + Math.cos(a) * rad, cy + Math.sin(a) * rad];
    const [x1, y1] = p(ang, R), [x2, y2] = p(a2, R), [x3, y3] = p(a2, r), [x4, y4] = p(ang, r);
    const big = slice > Math.PI ? 1 : 0;
    svg.appendChild(el('path', {
      d:`M ${x1} ${y1} A ${R} ${R} 0 ${big} 1 ${x2} ${y2} L ${x3} ${y3} A ${r} ${r} 0 ${big} 0 ${x4} ${y4} Z`,
      fill:d.color || FAMILY_COLORS[d.label] || C.blue, stroke:'#0b1322', 'stroke-width':2, opacity:.95
    }));
    ang = a2;
  });
  const centre = el('text', {x:cx, y:cy - 2, 'text-anchor':'middle', fill:'#e8eefc',
    'font-size':26, 'font-weight':800, 'font-family':'monospace'});
  centre.textContent = total.toLocaleString();
  svg.appendChild(centre);
  svg.appendChild(txt(cx, cy + 18, opts.centreLabel || 'events', {anchor:'middle', fill:C.dim, size:10}));
  node.appendChild(svg);
  const lg = document.createElement('div'); lg.className = 'legend';
  if (opts.legend !== false) {
    data.forEach(d => {
      const sp = document.createElement('span');
      const pct = (100 * d.value / total).toFixed(1);
      sp.innerHTML = `<i class="sw" style="background:${d.color || FAMILY_COLORS[d.label] || C.blue}"></i>${d.label} <b class="mono" style="color:#e8eefc">${d.value.toLocaleString()}</b> <span style="color:#5f7398">${pct}%</span>`;
      lg.appendChild(sp);
    });
  }
  node.appendChild(lg);
}

/* --------------------------------------------------------- horizontal bars */
function hBars(node, rows, opts = {}) {
  node.innerHTML = '';
  const max = Math.max(...rows.map(r => r.value), 1);
  rows.forEach(r => {
    const wrap = document.createElement('div'); wrap.className = 'bar-row';
    const color = r.color || FAMILY_COLORS[r.label] || C.blue;
    wrap.innerHTML = `<span class="mini" title="${r.label}">${r.label}</span>
      <span class="bar-track"><i class="bar-fill" style="width:${(100 * r.value / max).toFixed(1)}%;background:linear-gradient(90deg,${color}aa,${color})"></i></span>
      <b class="mono" style="font-size:11.5px;text-align:right">${opts.pct ? r.value.toFixed(1) + '%' : r.value.toLocaleString()}</b>`;
    node.appendChild(wrap);
  });
  if (!rows.length) node.innerHTML = '<div class="empty">No data yet</div>';
}

/* ---------------------------------------------------------------- heatmap */
function heatmap(node, matrix, rowLabels, colLabels) {
  node.innerHTML = '';
  const max = Math.max(...matrix.flat(), 1);
  const t = document.createElement('table'); t.className = 'heat';
  const thead = document.createElement('thead');
  thead.innerHTML = `<tr><th></th>${colLabels.map(c => `<th style="text-align:center">${c}</th>`).join('')}</tr>`;
  t.appendChild(thead);
  const tb = document.createElement('tbody');
  matrix.forEach((row, i) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td style="text-align:left;color:#8ea3c4;font-family:Inter">${rowLabels[i]}</td>` +
      row.map((v, j) => {
        const a = 0.08 + 0.85 * (v / max);
        const col = i === j ? `rgba(0,229,160,${a})` : `rgba(255,77,94,${a * 0.9})`;
        const fg = a > .5 ? '#04121c' : '#c9dcff';
        return `<td style="background:${col};color:${fg}">${v.toLocaleString()}</td>`;
      }).join('');
    tb.appendChild(tr);
  });
  t.appendChild(tb); node.appendChild(t);
}

/* ----------------------------------------------------------------- gauge */
function gauge(node, value, label, opts = {}) {
  node.innerHTML = '';
  const R = 62, cx = R + 8, cy = R + 8;
  const svg = el('svg', {viewBox:`0 0 ${(R + 8) * 2} ${R + 26}`, width:'100%', height:150});
  const start = Math.PI * 0.75, end = Math.PI * 2.25;
  const arc = (a1, a2, rad, color, w) => {
    const p = a => [cx + Math.cos(a) * rad, cy + Math.sin(a) * rad];
    const [x1, y1] = p(a1), [x2, y2] = p(a2);
    svg.appendChild(el('path', {d:`M ${x1} ${y1} A ${rad} ${rad} 0 ${a2 - a1 > Math.PI ? 1 : 0} 1 ${x2} ${y2}`,
      fill:'none', stroke:color, 'stroke-width':w, 'stroke-linecap':'round'}));
  };
  arc(start, end, R, '#16223a', 12);
  const v = Math.max(0, Math.min(1, value));
  arc(start, start + (end - start) * v, R, opts.color || C.green, 12);
  svg.appendChild(txt(cx, cy + 4, (v * 100).toFixed(opts.decimals ?? 1) + '%',
    {anchor:'middle', fill:'#e8eefc', size:24, weight:800, extra:{'font-family':'monospace'}}));
  svg.appendChild(txt(cx, cy + 26, label, {anchor:'middle', fill:C.dim, size:10}));
  node.appendChild(svg);
}

/* -------------------------------------------------------------- sparkline */
function sparkline(node, values, color = C.green) {
  node.innerHTML = '';
  if (!values.length) return;
  const W = 120, H = 30, max = Math.max(...values, 1);
  const pts = values.map((v, i) => `${(W * i / (values.length - 1 || 1)).toFixed(1)},${(H - H * v / max).toFixed(1)}`).join(' ');
  const svg = el('svg', {viewBox:`0 0 ${W} ${H}`, width:'100%', height:H});
  svg.appendChild(el('polyline', {points:pts, fill:'none', stroke:color, 'stroke-width':1.8}));
  node.appendChild(svg);
}
