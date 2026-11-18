'use strict';
const $ = (id) => document.getElementById(id);
let S = {}, api = null, jobs = [], recording = false, lastFrame = null, plotPending = false;
const CONST_LIMIT = 3, CSI_MIN_DB = -40, CSI_MAX_DB = 40, SNR_MIN_DB = -10, SNR_MAX_DB = 40;
const ACTIVE = ['queued', 'replaying', 'compiling', 'classifying'];

const FIELDS = ['earfcns', 'rf_args', 'nof_rx_ant', 'timeout',
  'listen', 'out_dir', 'binary'];
const NUMERIC = new Set(['nof_rx_ant', 'timeout', 'listen']);
const RULE_NUM = ['auth_threshold_pct', 'min_ues', 'min_dcis_per_rnti', 'min_total_tbs'];
const RULE_ON = ['min_ues_on', 'min_dcis_on', 'min_tbs_on'];

const LABEL = { unknown: 'UNKNOWN', legitimate: 'LEGITIMATE', insufficient: 'INSUFFICIENT DATA' };
const lname = (l) => LABEL[l] || l;
function esc(s) { return String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }
function save() { api.save_state(S); }

/* ---------------------------------------------------------------- init */
window.addEventListener('pywebviewready', async () => {
  api = window.pywebview.api;
  const b = await api.bootstrap();
  S = b.state; jobs = b.jobs || [];
  for (const k of FIELDS) {
    const el = $(k); el.value = S[k] ?? '';
    el.addEventListener('change', () => { S[k] = NUMERIC.has(k) ? Number(el.value) : el.value; save(); if (k === 'earfcns') hintEarfcns(); if (k === 'binary') binaryHint(); });
  }
  $('binary-hint').textContent = b.binary.path ? `Using ${b.binary.path} (${b.binary.source})` : 'ngscope not found';
  $('binary-hint').className = 'hint' + (b.binary.path ? '' : ' err');
  S.rules = S.rules || {};
  for (const k of RULE_NUM) { const el = $(k); el.value = S.rules[k]; el.onchange = () => { S.rules[k] = Number(el.value); save(); }; }
  for (const k of RULE_ON) { const el = $(k); el.checked = !!S.rules[k]; el.onchange = () => { S.rules[k] = el.checked; save(); }; }
  $('pause_for_replay').checked = !!S.pause_for_replay;
  $('pause_for_replay').onchange = (e) => { S.pause_for_replay = e.target.checked; save(); };
  setMode(S.mode || 'record');
  renderFiles(); renderJobs(); hintEarfcns(); renderResult(); updateUI();
});

$('tabs').addEventListener('click', (e) => { const m = e.target.dataset.mode; if (m) { setMode(m); save(); } });
function setMode(m) {
  S.mode = m;
  document.querySelectorAll('#tabs button').forEach((b) => b.classList.toggle('on', b.dataset.mode === m));
  $('card-record').hidden = m !== 'record';
  $('card-replay').hidden = m !== 'replay';
  $('btn-start').textContent = m === 'record' ? 'Start recording' : 'Replay & classify';
  if (m === 'record') requestAnimationFrame(renderPlots);
}

async function binaryHint() {
  const r = await api.save_state(S); // persist before resolving
  const b = await api.bootstrap();
  $('binary-hint').textContent = b.binary.path ? `Using ${b.binary.path} (${b.binary.source})` : 'ngscope not found';
  $('binary-hint').className = 'hint' + (b.binary.path ? '' : ' err');
}
async function hintEarfcns() {
  const r = await api.parse_earfcn_list($('earfcns').value);
  const h = $('earfcn-hint');
  if (r.errors.length) { h.textContent = r.errors.join('; '); h.className = 'hint err'; return; }
  h.className = 'hint';
  h.textContent = r.count ? `${r.count} channel(s): ` + r.preview.map((p) => `${p.earfcn} (B${p.band}, ${p.mhz.toFixed(1)} MHz)`).join(', ') + (r.count > 6 ? ' …' : '') : '';
}

/* ---------------------------------------------------------------- buttons */
$('btn-out').onclick = async () => { const p = await api.pick_dir(S.out_dir); if (p) { S.out_dir = p; $('out_dir').value = p; save(); } };
$('btn-add-files').onclick = async () => {
  const f = await api.pick_replay_files(); if (!f) return;
  S.replay_files = [...new Set([...(S.replay_files || []), ...f])]; save(); renderFiles();
};
$('btn-clear-files').onclick = () => { S.replay_files = []; save(); renderFiles(); };
function renderFiles() {
  $('file-list').innerHTML = (S.replay_files || []).map((f, i) =>
    `<li><span>${esc(f)}</span><button data-i="${i}" title="Remove">✕</button></li>`).join('') || '<li class="hint">No recordings chosen.</li>';
}
$('file-list').onclick = (e) => { const i = e.target.dataset.i; if (i !== undefined) { S.replay_files.splice(+i, 1); save(); renderFiles(); } };

$('btn-clear-jobs').onclick = async () => { jobs = await api.clear_jobs(); renderJobs(); };
$('btn-clear-console').onclick = () => { $('console').textContent = ''; };

$('btn-start').onclick = async () => {
  await api.save_state(S);
  let r;
  if (S.mode === 'record') {
    r = await api.start_record(S.earfcns, S.listen, 20, S.rf_args, S.nof_rx_ant, 5);
    if (r.ok) { recording = true; lastFrame = null; }
  } else {
    r = await api.start_replay(S.replay_files);
  }
  if (!r.ok) alert(r.error || (r.errors || []).map((e) => e.message).join('\n'));
  updateUI();
};
$('btn-stop').onclick = async () => { await api.stop(); updateUI(); };

/* ---------------------------------------------------------------- callbacks */
window.appendLines = (lines) => {
  const c = $('console');
  const frag = document.createDocumentFragment();
  for (const l of lines) {
    const d = document.createElement('div');
    if (l.cls) d.className = l.cls;
    d.textContent = l.text; frag.appendChild(d);
  }
  c.appendChild(frag);
  while (c.childElementCount > 5000) c.removeChild(c.firstChild);
  if ($('follow').checked) c.scrollTop = c.scrollHeight;
};
window.onSweepProgress = (s) => {
  recording = s.active;
  const cur = s.current;
  if (s.active && s.phase === 'paused') setStatus('busy', `Sweep paused — waiting for replay (next: ${s.index + 1}/${s.total})`);
  else if (s.active && cur) setStatus('rec', `Recording EARFCN ${cur.earfcn} (${s.index + 1}/${s.total}) · ${s.phase}`);
  updateUI();
};
window.onJob = (job) => {
  const i = jobs.findIndex((j) => j.id === job.id);
  if (i >= 0) jobs[i] = job; else jobs.push(job);
  renderJobs(); renderResult(); updateUI();
};

function setStatus(state, text) { $('status').dataset.state = state; $('status-text').textContent = text; }
function updateUI() {
  const busy = jobs.some((j) => ACTIVE.includes(j.status));
  $('btn-stop').disabled = !(recording || busy);
  $('btn-start').disabled = recording;
  if (recording) return;
  if (busy) { const j = jobs.find((x) => ACTIVE.includes(x.status)); setStatus('busy', `${j.status} ${shortName(j.recording)}`); }
  else setStatus(jobs.some((j) => j.status === 'done') ? 'done' : 'idle', jobs.some((j) => j.status === 'done') ? 'Done' : 'Idle');
}
function shortName(p) { const parts = p.split('/'); return parts.length > 2 ? parts.slice(-2).join('/') : p; }

/* ---------------------------------------------------------------- results */
const pct = (x) => (x === null || x === undefined ? '' : (x * 100).toFixed(1) + ' %');
function renderJobs() {
  $('jobs').querySelector('tbody').innerHTML = [...jobs].reverse().map((j) => {
    const lab = j.label ? `<span class="lab-${j.label}">${lname(j.label)}</span>` : '';
    const st = j.status === 'error' ? `<span class="st-error" title="${esc(j.error)}">error</span>` : j.status;
    return `<tr><td class="rec" title="${esc(j.recording)}">${esc(shortName(j.recording))}</td><td>${esc(j.source)}</td><td>${st}</td><td>${lab}</td><td>${pct(j.auth_frac)}</td></tr>`;
  }).join('');
}
function renderResult() {
  const body = $('result-body');
  const done = [...jobs].reverse().find((j) => j.status === 'done');
  const err = [...jobs].reverse().find((j) => j.status === 'error');
  const act = [...jobs].reverse().find((j) => ACTIVE.includes(j.status));
  if (!done && !act && !err) { body.className = 'empty'; body.textContent = 'No result yet.'; return; }
  body.className = '';
  let html = '';
  if (act) html += `<div class="meta">${esc(act.status)} ${esc(shortName(act.recording))}…</div>`;
  if (done) {
    html += `<div class="verdict"><span class="big ${done.label}">${lname(done.label)}</span>
      <span class="meta">${pct(done.auth_frac)} of UEs authenticated (threshold ${S.rules.auth_threshold_pct} %) · ${done.windows.length} window(s) · EARFCN ${done.earfcn} · ${esc(shortName(done.recording))}</span></div>`;
    html += '<table style="margin-top:8px"><thead><tr><th>Cell</th><th>Duration</th><th>UEs</th><th>Authenticated</th><th>Checks</th><th>Label</th></tr></thead><tbody>' +
      done.windows.map((w) => `<tr><td>${w.cell_id}</td><td>${w.duration}s${w.partial ? ' (partial)' : ''}</td><td>${w.ue_count}</td><td>${pct(w.auth_frac)}</td><td>${(w.checks || []).map((c) => `<span class="${c.ok ? '' : 'chk-fail'}">${esc(c.name)} ${esc(c.value)} (${esc(c.need)}) ${c.ok ? '✓' : '✗'}</span>`).join('<br>')}</td><td class="lab-${w.label}">${lname(w.label)}</td></tr>`).join('') + '</tbody></table>';
    const names = Object.keys(done.windows[0].features);
    html += '<h2 style="margin-top:12px">Cell feature vector</h2><table><thead><tr><th>Feature</th>' +
      done.windows.map((w) => `<th>cell ${w.cell_id} · ${w.duration}s</th>`).join('') + '</tr></thead><tbody>' +
      names.map((n) => `<tr><td>${n}</td>` + done.windows.map((w) => `<td>${w.features[n]}</td>`).join('') + '</tr>').join('') + '</tbody></table>';
    html += `<div class="hint" style="margin-top:6px"><a href="#" onclick="api.open_path('${esc(done.work_dir)}');return false">Open work folder</a></div>`;
  } else if (err && !act) html += `<div class="hint err">${esc(err.error)}</div>`;
  body.innerHTML = html;
}

/* ---------------------------------------------------------------- plots */
function css(n) { return getComputedStyle(document.documentElement).getPropertyValue(n).trim(); }
function prep(c) {
  const r = window.devicePixelRatio || 1, rect = c.getBoundingClientRect();
  const w = Math.max(1, Math.round(rect.width * r)), h = Math.max(1, Math.round(rect.height * r));
  if (c.width !== w || c.height !== h) { c.width = w; c.height = h; }
  const ctx = c.getContext('2d'); ctx.setTransform(r, 0, 0, r, 0, 0); ctx.clearRect(0, 0, rect.width, rect.height);
  return { ctx, w: rect.width, h: rect.height };
}
function drawConst(points, id) {
  const { ctx, w, h } = prep($(id)), pad = { l: 28, r: 8, t: 8, b: 18 };
  const side = Math.min(w - pad.l - pad.r, h - pad.t - pad.b);
  const ox = pad.l + (w - pad.l - pad.r - side) / 2, oy = pad.t + (h - pad.t - pad.b - side) / 2;
  const cx = ox + side / 2, cy = oy + side / 2;
  ctx.strokeStyle = css('--border'); ctx.beginPath(); ctx.moveTo(cx, oy); ctx.lineTo(cx, oy + side); ctx.moveTo(ox, cy); ctx.lineTo(ox + side, cy); ctx.stroke();
  ctx.strokeStyle = css('--border-str'); ctx.strokeRect(ox + .5, oy + .5, side - 1, side - 1);
  ctx.fillStyle = css('--text-faint'); ctx.font = '10px system-ui'; ctx.fillText(String(CONST_LIMIT), ox - 14, oy + 9); ctx.fillText('-' + CONST_LIMIT, ox - 17, oy + side);
  if (!points || !points.length) return;
  ctx.fillStyle = css('--accent'); ctx.globalAlpha = .55;
  const sc = side / (2 * CONST_LIMIT);
  for (let i = 0; i < points.length; i += 2) {
    const x = cx + points[i] * sc, y = cy - points[i + 1] * sc;
    if (x < ox || x > ox + side || y < oy || y > oy + side) continue;
    ctx.fillRect(x - 1, y - 1, 2, 2);
  }
  ctx.globalAlpha = 1;
}
function drawLine(vals, id, lo, hi, step, label) {
  const { ctx, w, h } = prep($(id)), pad = { l: 30, r: 8, t: 8, b: 18 };
  const iw = w - pad.l - pad.r, ih = h - pad.t - pad.b;
  ctx.strokeStyle = css('--border'); ctx.fillStyle = css('--text-faint'); ctx.font = '10px system-ui'; ctx.beginPath();
  for (let db = lo; db <= hi; db += step) { const y = pad.t + ih * (1 - (db - lo) / (hi - lo)); ctx.moveTo(pad.l, y); ctx.lineTo(pad.l + iw, y); ctx.fillText(String(db), 4, y + 3); }
  ctx.stroke(); ctx.strokeStyle = css('--border-str'); ctx.strokeRect(pad.l + .5, pad.t + .5, iw - 1, ih - 1);
  ctx.fillText(label, pad.l + iw / 2 - 38, pad.t + ih + 14);
  if (!vals || !vals.length) return;
  ctx.strokeStyle = css('--ok'); ctx.beginPath();
  vals.forEach((v, i) => { const x = pad.l + iw * i / Math.max(1, vals.length - 1), y = pad.t + ih * (1 - (Math.min(hi, Math.max(lo, v)) - lo) / (hi - lo)); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
  ctx.stroke();
}
function renderPlots() {
  plotPending = false;
  const f = lastFrame;
  drawConst(f && f.iq_pdcch, 'plot-pdcch-const');
  drawConst(f && f.iq_pdsch_cw1, 'plot-pdsch-1-const');
  drawConst(f && f.iq_pdsch_cw2, 'plot-pdsch-2-const');
  drawLine(f && f.snr, 'plot-snr', SNR_MIN_DB, SNR_MAX_DB, 10, 'Rx Channel');
  drawLine(f && f.csi, 'plot-csi', CSI_MIN_DB, CSI_MAX_DB, 20, 'Subcarrier Index');
}
window.onPlotFrame = (frame) => {
  lastFrame = frame;
  $('plots-note').textContent = `${frame.nof_const_pdcch} PDCCH · ${frame.nof_const_pdsch} PDSCH symbols · ${frame.nof_csi} subcarriers`;
  if (!plotPending) { plotPending = true; requestAnimationFrame(renderPlots); }
};
window.onPlotsReset = () => { lastFrame = null; $('plots-note').textContent = 'Waiting for ngscope…'; requestAnimationFrame(renderPlots); };
window.addEventListener('resize', () => requestAnimationFrame(renderPlots));
