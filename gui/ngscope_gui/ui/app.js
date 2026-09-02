/* NG-Scope GUI frontend.
 *
 * The form is rendered from the schema shipped by schema.py, which mirrors the X-macro
 * tables in ngscope/hdr/dciLib/load_config.h. Adding a setting on the C side plus a line
 * in schema.py makes it appear here -- FIELD_GROUPS below only decides placement, and any
 * key it does not mention still gets rendered, in the "More options" group.
 */

'use strict';

const MAX_CONSOLE_LINES = 5000;
const SAVE_DEBOUNCE_MS = 400;

const MODE_NORMAL = 0, MODE_RECORD = 1, MODE_REPLAY = 2;

/* Placement only. Keys absent from these lists are appended automatically. */
const FIELD_GROUPS = {
  cellPrimary: ['mode', 'rf_freq', 'rf_args', 'N_id_2', 'nof_thread'],
  cellToggles: ['decode_pdcch', 'log_dl', 'log_ul', 'log_phich', 'disable_plot', 'debug', 'silent'],
  topNumbers: ['rnti'],
  /* Promoted out of the Decoding list into their own card: these two decide what reaches
     the logs at all, and rach_filter_only silently forces decode_RAR on. */
  rachPrimary: ['decode_RAR', 'rach_filter_only'],
  rachDependent: ['rar_seed_tracker'],
  /* Its own card: it is the only setting that decodes UE payload rather than just
     filtering or logging what the DCI search already found. */
  securityPrimary: ['mark_security_phase'],
  /* Sub-options of the security scan that the C side ANDs with mode == REPLAY, so they are
     shown only when a cell is actually replaying. */
  securityReplay: ['rlc_reassembly', 'qam_retry'],
  topToggles: ['decode_single_ue', 'decode_SIB', 'remote_enable'],
};

/* Chips carry the one fact about a setting that is not obvious from its name -- a cost, or
   a dependency on another setting. What a setting does belongs in the help text. */
const IMPACT = {
  decode_RAR: [{ text: '+25% decode time', kind: 'cost' }],
  rach_filter_only: [{ text: 'implies Decode RAR', kind: 'link' }],
  rar_seed_tracker: [{ text: 'measured effect: none', kind: 'muted' }],
  mark_security_phase: [
    { text: 'implies Decode RAR', kind: 'link' },
    { text: 'decodes UE RRC', kind: 'muted' },
  ],
};

let api = null;          // window.pywebview.api
let SCHEMA = null;
let S = null;            // persisted state
let running = false;
let stopping = false;
let runDir = null;
let saveTimer = null;

const $ = (id) => document.getElementById(id);

/* WebKit has no visible console here, so keep failures where they can be inspected from
   Python with evaluate_js('window.__jsErrors'). */
window.__jsErrors = [];
window.addEventListener('error', (e) => window.__jsErrors.push(String(e.message)));
window.addEventListener('unhandledrejection', (e) => window.__jsErrors.push(String(e.reason)));

/* ------------------------------------------------------------------ helpers */

function escapeHtml(text) {
  return String(text).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
  ));
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function fieldByKey(fields, key) {
  return fields.find((f) => f.key === key);
}

function orderedFields(fields, preferred) {
  const known = preferred.map((k) => fieldByKey(fields, k)).filter(Boolean);
  const rest = fields.filter((f) => !preferred.includes(f.key));
  return { known, rest };
}

function scheduleSave() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    if (api) api.save_state(S);
  }, SAVE_DEBOUNCE_MS);
}

function toast(message, kind = 'info', items = null, ttl = 6000) {
  const node = el('div', `toast ${kind}`);
  node.appendChild(el('div', 'toast-title', message));
  if (items && items.length) {
    const list = el('ul');
    items.slice(0, 8).forEach((it) => list.appendChild(el('li', null, it)));
    node.appendChild(list);
  }
  $('toasts').appendChild(node);
  setTimeout(() => {
    node.classList.add('leaving');
    setTimeout(() => node.remove(), 200);
  }, ttl);
}

/* ------------------------------------------------------------ field widgets */

function makeSwitch(checked, onChange, disabled) {
  const wrap = el('span', 'switch');
  const input = document.createElement('input');
  input.type = 'checkbox';
  input.checked = !!checked;
  input.disabled = !!disabled;
  input.addEventListener('change', () => onChange(input.checked));
  wrap.appendChild(input);
  wrap.appendChild(el('span', 'track'));
  wrap.appendChild(el('span', 'thumb'));
  return wrap;
}

function toggleRow(field, value, onChange, opts = {}) {
  const row = el('label', 'toggle');
  if (opts.prominent) row.classList.add('prominent');
  if (opts.disabled) row.classList.add('is-disabled');

  const head = el('span', 'toggle-head');
  head.appendChild(el('span', 'toggle-label', field.label));
  (IMPACT[field.key] || []).forEach((chip) => {
    head.appendChild(el('span', `chip ${chip.kind}`, chip.text));
  });
  row.appendChild(head);

  row.appendChild(makeSwitch(value, onChange, opts.disabled));
  if (field.help) row.appendChild(el('p', 'help', opts.help || field.help));
  return row;
}

function numberField(field, value, onChange, errorKey) {
  const wrap = el('div', 'field');
  const id = `f-${errorKey.replace(/\./g, '-')}`;
  const label = el('label', null, field.label);
  label.htmlFor = id;
  wrap.appendChild(label);

  const input = document.createElement('input');
  input.type = 'number';
  input.id = id;
  input.value = value;
  if (field.min !== undefined) input.min = field.min;
  if (field.max !== undefined) input.max = field.max;
  input.addEventListener('input', () => {
    const parsed = parseInt(input.value, 10);
    onChange(Number.isNaN(parsed) ? field.default : parsed);
  });
  wrap.appendChild(input);

  /* rf_freq is entered in Hz because that is what the config takes; the MHz echo is
     there so a mistyped digit is obvious at a glance. */
  if (field.key === 'rf_freq') {
    const hint = el('p', 'hint');
    const update = () => {
      const hz = parseInt(input.value, 10);
      hint.textContent = Number.isNaN(hz) || hz <= 0 ? '' : `${(hz / 1e6).toFixed(3)} MHz`;
    };
    input.addEventListener('input', update);
    update();
    wrap.appendChild(hint);
  }

  if (field.help) wrap.appendChild(el('p', 'help', field.help));
  wrap.appendChild(errorSlot(errorKey));
  return wrap;
}

function textField(field, value, onChange, errorKey) {
  const wrap = el('div', 'field');
  const id = `f-${errorKey.replace(/\./g, '-')}`;
  const label = el('label', null, field.label);
  label.htmlFor = id;
  wrap.appendChild(label);

  const input = document.createElement('input');
  input.type = 'text';
  input.id = id;
  input.value = value || '';
  input.spellcheck = false;
  if (field.maxlen) input.maxLength = field.maxlen;
  input.addEventListener('input', () => onChange(input.value));
  wrap.appendChild(input);

  if (field.help) wrap.appendChild(el('p', 'help', field.help));
  wrap.appendChild(errorSlot(errorKey));
  return wrap;
}

function pathField(field, value, onChange, errorKey, browse) {
  const wrap = el('div', 'field');
  wrap.appendChild(el('label', null, field.label));

  const row = el('div', 'path-row');
  const input = document.createElement('input');
  input.type = 'text';
  input.value = value || '';
  input.spellcheck = false;
  input.placeholder = 'Choose a file…';
  input.addEventListener('input', () => onChange(input.value));
  row.appendChild(input);

  const button = el('button', 'btn ghost small', 'Browse');
  button.addEventListener('click', async () => {
    const picked = await browse(input.value);
    if (picked) {
      input.value = picked;
      onChange(picked);
    }
  });
  row.appendChild(button);
  wrap.appendChild(row);

  if (field.help) wrap.appendChild(el('p', 'help', field.help));
  wrap.appendChild(errorSlot(errorKey));
  return wrap;
}

function segmentedField(field, value, onChange, options) {
  const wrap = el('div', 'field');
  wrap.appendChild(el('label', null, field.label));

  const group = el('div', 'segmented');
  options.forEach((opt) => {
    const button = el('button', null, opt.label);
    button.type = 'button';
    button.setAttribute('aria-pressed', String(opt.value === value));
    button.addEventListener('click', () => onChange(opt.value));
    group.appendChild(button);
  });
  wrap.appendChild(group);
  if (field.help) wrap.appendChild(el('p', 'help', field.help));
  return wrap;
}

function errorSlot(key) {
  const node = el('p', 'field-error');
  node.dataset.errorFor = key;
  return node;
}

function renderField(field, value, onChange, errorKey) {
  switch (field.type) {
    case 'bool':  return toggleRow(field, value, onChange);
    case 'int':
    case 'int64': return numberField(field, value, onChange, errorKey);
    case 'path':  return pathField(field, value, onChange, errorKey,
                                   (cur) => api.pick_replay_file(cur));
    default:      return textField(field, value, onChange, errorKey);
  }
}

/* -------------------------------------------------------------- tuning field */

/* The config has only rf_freq, so EARFCN is a GUI-side entry mode: the user picks one or
   the other, and the EARFCN is converted to rf_freq before anything is written. The
   conversion lives in Python (earfcn.py, mirroring srsRAN's own band table) so the GUI and
   ngscope agree on what an EARFCN means. */
function tuningField(cell, index) {
  const wrap = el('div', 'field');
  const byEarfcn = cell.gui_freq_mode === 'earfcn';

  const head = el('div', 'field-head');
  head.appendChild(el('label', null, 'Tuning'));

  const modes = el('div', 'segmented compact');
  [['hz', 'Frequency'], ['earfcn', 'EARFCN']].forEach(([value, label]) => {
    const button = el('button', null, label);
    button.type = 'button';
    button.setAttribute('aria-pressed', String((cell.gui_freq_mode || 'hz') === value));
    button.addEventListener('click', async () => {
      if ((cell.gui_freq_mode || 'hz') === value) return;
      cell.gui_freq_mode = value;
      /* Switching to EARFCN: only prefill when the frequency is unambiguous. Bands
         overlap, so 2130 MHz is a valid centre in bands 1, 4 and 66 -- guessing one
         would quietly change which band the user is on. */
      if (value === 'earfcn' && !cell.gui_earfcn && cell.rf_freq) {
        const cands = await api.earfcns_for_freq(cell.rf_freq);
        if (cands.length === 1) cell.gui_earfcn = cands[0].earfcn;
        else if (cands.length > 1) {
          toast(`${(cell.rf_freq / 1e6).toFixed(1)} MHz is valid in `
            + `${cands.length} bands (${cands.map((c) => c.band).join(', ')}) — `
            + 'enter the EARFCN for the one you want.', 'info');
        }
      }
      renderCells();
      scheduleSave();
    });
    modes.appendChild(button);
  });
  head.appendChild(modes);
  wrap.appendChild(head);

  const input = document.createElement('input');
  input.type = 'number';
  input.id = `f-cells-${index}-tuning`;
  const hint = el('p', 'hint');
  const errKey = byEarfcn ? `cells.${index}.gui_earfcn` : `cells.${index}.rf_freq`;

  async function refresh() {
    if (byEarfcn) {
      const info = await api.earfcn_info(input.value);
      if (!info) { hint.textContent = ''; hint.className = 'hint'; return; }
      if (!info.ok) {
        hint.textContent = `Not a valid EARFCN (0–${info.max}).`;
        hint.className = 'hint bad';
        return;
      }
      hint.textContent = `${info.mhz.toFixed(1)} MHz · Band ${info.band}`;
      hint.className = 'hint';
    } else {
      const hz = parseInt(input.value, 10);
      hint.className = 'hint';
      hint.textContent = Number.isNaN(hz) || hz <= 0 ? '' : `${(hz / 1e6).toFixed(3)} MHz`;
    }
  }

  if (byEarfcn) {
    input.value = cell.gui_earfcn === '' || cell.gui_earfcn == null ? '' : cell.gui_earfcn;
    input.min = 0;
    input.placeholder = 'e.g. 66636';
    input.addEventListener('input', async () => {
      const n = parseInt(input.value, 10);
      cell.gui_earfcn = Number.isNaN(n) ? '' : n;
      const info = Number.isNaN(n) ? null : await api.earfcn_info(n);
      // rf_freq stays the single source of truth for what gets written.
      cell.rf_freq = info && info.ok ? info.freq_hz : 0;
      await refresh();
      scheduleSave();
    });
  } else {
    input.value = cell.rf_freq;
    input.min = 0;
    input.addEventListener('input', () => {
      const hz = parseInt(input.value, 10);
      cell.rf_freq = Number.isNaN(hz) ? 0 : hz;
      refresh();
      scheduleSave();
    });
  }

  wrap.appendChild(input);
  wrap.appendChild(hint);
  wrap.appendChild(el('p', 'help', byEarfcn
    ? 'Downlink EARFCN. The centre frequency shown above is what gets written as rf_freq.'
    : 'Downlink centre frequency in Hz. Two cells may not share a frequency.'));
  wrap.appendChild(errorSlot(errKey));
  refresh();
  return wrap;
}

/* --------------------------------------------------------------- cell panel */

function renderCellTabs() {
  const tabs = $('cell-tabs');
  tabs.innerHTML = '';
  const cells = S.config.cells;

  cells.forEach((cell, i) => {
    const tab = el('button', 'tab', `Cell ${i + 1}`);
    tab.type = 'button';
    tab.setAttribute('role', 'tab');
    tab.setAttribute('aria-selected', String(i === S.active_cell));
    tab.addEventListener('click', () => {
      S.active_cell = i;
      renderCells();
      scheduleSave();
    });
    tabs.appendChild(tab);
  });

  if (cells.length > 1) {
    const remove = el('button', 'tab remove', 'Remove');
    remove.type = 'button';
    remove.title = `Remove cell ${S.active_cell + 1}`;
    remove.addEventListener('click', () => {
      S.config.cells.splice(S.active_cell, 1);
      S.active_cell = Math.max(0, S.active_cell - 1);
      renderCells();
      scheduleSave();
    });
    tabs.appendChild(remove);
  }

  if (cells.length < SCHEMA.limits.max_cells) {
    const add = el('button', 'tab add', '+');
    add.type = 'button';
    add.title = 'Add a cell';
    add.addEventListener('click', () => {
      const fresh = {};
      SCHEMA.rf_dev.forEach((f) => { fresh[f.key] = f.default; });
      S.config.cells.push(fresh);
      S.active_cell = S.config.cells.length - 1;
      renderCells();
      scheduleSave();
    });
    tabs.appendChild(add);
  }
}

function renderCells() {
  renderCellTabs();

  const body = $('cell-body');
  body.innerHTML = '';

  const index = Math.min(S.active_cell, S.config.cells.length - 1);
  S.active_cell = index;
  const cell = S.config.cells[index];
  const set = (key) => (value) => {
    cell[key] = value;
    scheduleSave();
    // Turning plotting off should take the panel away immediately, not at next launch.
    if (key === 'disable_plot') syncPlotsVisibility();
  };

  const { known, rest } = orderedFields(SCHEMA.rf_dev, [
    ...FIELD_GROUPS.cellPrimary, ...FIELD_GROUPS.cellToggles, 'replay_fname',
  ]);

  const modeField = fieldByKey(SCHEMA.rf_dev, 'mode');
  body.appendChild(segmentedField(modeField, cell.mode, (value) => {
    cell.mode = value;
    renderCells();
    renderSecurity();   /* the replay-only sub-options turn on and off with this */
    scheduleSave();
  }, SCHEMA.modes));

  /* Record has no destination of its own: ngscope_main.c:113 always writes
     <out_path>/<timestamp>/recorded-samples.bin. Say so rather than offering a picker
     that would not be honoured. */
  if (cell.mode === MODE_RECORD) {
    const note = el('div', 'callout info');
    note.innerHTML = 'IQ is written to <code>&lt;output directory&gt;/&lt;timestamp&gt;/'
      + 'recorded-samples.bin</code> — set the directory under <b>Run</b>.';
    body.appendChild(note);
  }
  if (cell.mode === MODE_REPLAY) {
    const replay = fieldByKey(SCHEMA.rf_dev, 'replay_fname');
    body.appendChild(pathField(replay, cell.replay_fname, set('replay_fname'),
      `cells.${index}.replay_fname`, (cur) => api.pick_replay_file(cur)));
  }

  /* While a sweep is armed it supplies cell 1's frequency, so editing it here would be
     misleading -- say what is driving it instead. */
  if (index === 0 && sweepOn()) {
    const note = el('div', 'callout info');
    note.innerHTML = 'Tuning for this cell is driven by the <b>EARFCN sweep</b> above.';
    body.appendChild(note);
  } else {
    body.appendChild(tuningField(cell, index));
  }

  const grid = el('div', 'grid-2');
  ['nof_thread', 'N_id_2'].forEach((key) => {
    const field = fieldByKey(SCHEMA.rf_dev, key);
    if (field) grid.appendChild(renderField(field, cell[key], set(key), `cells.${index}.${key}`));
  });
  body.appendChild(grid);

  const rfArgs = fieldByKey(SCHEMA.rf_dev, 'rf_args');
  body.appendChild(renderField(rfArgs, cell.rf_args, set('rf_args'), `cells.${index}.rf_args`));

  const toggles = el('div', 'toggles');
  FIELD_GROUPS.cellToggles.forEach((key) => {
    const field = fieldByKey(SCHEMA.rf_dev, key);
    if (field) toggles.appendChild(toggleRow(field, cell[key], set(key)));
  });
  body.appendChild(toggles);

  appendLeftovers(body, rest, cell, set, `cells.${index}`);
}

/* Anything the layout above does not name still has to appear, or a new schema key
   would silently become un-settable. */
function appendLeftovers(parent, fields, values, setFactory, prefix) {
  const extra = fields.filter((f) => f.key !== 'mode');
  if (!extra.length) return;

  const details = el('details', 'advanced');
  details.appendChild(el('summary', null, 'More options'));
  const toggles = el('div', 'toggles');
  extra.forEach((field) => {
    const set = setFactory(field.key);
    if (field.type === 'bool') {
      toggles.appendChild(toggleRow(field, values[field.key], set));
    } else {
      details.appendChild(renderField(field, values[field.key], set, `${prefix}.${field.key}`));
    }
  });
  if (toggles.childElementCount) details.appendChild(toggles);
  parent.appendChild(details);
}

/* --------------------------------------------------- top level and logging */

/* The RACH card. Kept separate from Decoding because these settings decide what reaches
   the logs at all, and because they are coupled: rach_filter_only implies decode_RAR
   (ngscope forces it in ngscope_config_finalize), and rar_seed_tracker is meaningless
   without it. Showing them together is what makes the coupling visible. */
function renderRach() {
  const body = $('rach-body');
  body.innerHTML = '';
  const top = S.config.top;
  const set = (key) => (value) => {
    top[key] = value;
    scheduleSave();
    renderRach();       // the coupling below depends on both values
    renderTopLevel();
  };

  const primary = el('div', 'toggles');
  FIELD_GROUPS.rachPrimary.forEach((key) => {
    const field = fieldByKey(SCHEMA.top_level, key);
    if (field) primary.appendChild(toggleRow(field, top[key], set(key), { prominent: true }));
  });
  body.appendChild(primary);

  if (top.rach_filter_only && !top.decode_RAR) {
    const note = el('div', 'callout info');
    note.innerHTML = '<b>RACH filter</b> builds its RNTI set from decoded RARs, so ngscope '
      + 'will enable <code>decode_RAR</code> for this run.';
    body.appendChild(note);
  } else if (top.rach_filter_only) {
    const note = el('div', 'callout info');
    note.innerHTML = 'Applies to the <code>.dciLog</code> files, <code>cell_status</code> and '
      + 'the remote sink. <code>dci-decode-debug-*.csv</code> is always written unfiltered, '
      + 'with a <code>rach_ok</code> column marking what the filter excluded.';
    body.appendChild(note);
  }

  /* Depends on decode_RAR: with it off there are no RACH-assigned RNTIs to seed with. */
  const dependent = el('div', 'sub-options');
  FIELD_GROUPS.rachDependent.forEach((key) => {
    const field = fieldByKey(SCHEMA.top_level, key);
    if (!field) return;
    const off = !top.decode_RAR;
    dependent.appendChild(toggleRow(field, top[key], set(key), {
      disabled: off,
      help: off ? 'Needs Decode RAR: without it there are no RACH-assigned RNTIs to seed with.'
                : field.help,
    }));
  });
  body.appendChild(dependent);
}

/* The Security context card. Separate from RACH because it does something different in
   kind: it decodes the UE's own transport blocks to find securityModeCommand, rather than
   filtering the DCI stream. It still depends on decode_RAR for the per-RNTI anchor. */
function renderSecurity() {
  const body = $('security-body');
  body.innerHTML = '';
  const top = S.config.top;

  const field = fieldByKey(SCHEMA.top_level, 'mark_security_phase');
  if (!field) return;

  const toggles = el('div', 'toggles');
  toggles.appendChild(toggleRow(field, top.mark_security_phase, (value) => {
    top.mark_security_phase = value;
    scheduleSave();
    renderSecurity();
    renderRach();       // it forces decode_RAR on, which that card reports
    renderTopLevel();
  }, { prominent: true }));
  body.appendChild(toggles);

  if (!top.mark_security_phase) return;

  if (!top.decode_RAR) {
    const note = el('div', 'callout info');
    note.innerHTML = 'The boundary is anchored on each UE\'s RAR, so ngscope will enable '
      + '<code>decode_RAR</code> for this run.';
    body.appendChild(note);
  }

  /* What it actually produces, and the one thing a user has to know to read it correctly:
     the per-DCI label understates the pre-security population. */
  const out = el('div', 'callout good');
  out.innerHTML = 'Writes <code>security_log-&lt;rf&gt;.csv</code>, one row per observed '
    + 'boundary. Join it with <code>security_phase_join.py</code> rather than reading '
    + 'the per-DCI <code>security_phase</code> directly &mdash; the live label is stamped '
    + 'before the boundary is known, so it marks only a fraction of the pre-security DCIs.';
  body.appendChild(out);

  const caveat = el('p', 'help');
  caveat.innerHTML = 'Security truly activates at <b>SecurityModeComplete</b>, which is '
    + 'uplink and invisible here, so the boundary is the <b>SecurityModeCommand</b> a few '
    + 'milliseconds earlier. While this is on, srsRAN PHY errors are routed to srslog: '
    + 'probing UE transport blocks provokes thousands of them.';
  body.appendChild(caveat);

  /* Replay-only sub-options. Disabled rather than hidden, following the RACH card: a setting
     that vanishes looks like it was never there, whereas a disabled one with a reason tells
     the user what to change. The C side enforces this independently -- task_scheduler.c ANDs
     each with mode == REPLAY -- so the gate here is guidance, not the guarantee. */
  const replaying = (S.config.cells || []).some((c) => c.mode === MODE_REPLAY);
  const replayOpts = el('div', 'sub-options');
  FIELD_GROUPS.securityReplay.forEach((key) => {
    const f = fieldByKey(SCHEMA.top_level, key);
    if (!f) return;
    replayOpts.appendChild(toggleRow(f, top[key], (value) => {
      top[key] = value;
      scheduleSave();
    }, {
      disabled: !replaying,
      help: replaying ? f.help
                      : 'Replay only \u2014 set a cell to Replay mode to use this. Holding '
                        + 'partial RLC state, or spending a second decode, is sound only '
                        + 'where the scheduler blocks instead of dropping subframes.',
    }));
  });
  body.appendChild(replayOpts);

  /* A post-run action, not a decode setting, so it is GUI-side state rather than a config
     key. It lives on this card because it is only meaningful with the security scan on, and
     because forgetting it is the quiet way to under-report: the label ngscope stamps during
     the run marks only a fraction of the pre-security DCIs. */
  const joinField = {
    key: 'join_after_run',
    label: 'Join after the run',
    help: 'When ngscope exits, run tools/security_phase_join.py over the run directory, '
      + 'writing security_phase.csv, dci_output_joined/ and pcap_joined/. Progress appears '
      + 'in the console. These joined files are the authoritative labelling: the per-DCI '
      + 'security_phase written during the run can only mark a fraction of the pre-security '
      + 'DCIs, because a UE\u2019s boundary arrives after the DCIs it bounds.',
  };
  const joinBox = el('div', 'sub-options');
  joinBox.appendChild(toggleRow(joinField, !!S.join_after_run, (value) => {
    S.join_after_run = value;
    scheduleSave();
  }));
  body.appendChild(joinBox);
}

function renderTopLevel() {
  const body = $('top-body');
  body.innerHTML = '';
  const top = S.config.top;
  const set = (key) => (value) => {
    top[key] = value;
    scheduleSave();
  };

  FIELD_GROUPS.topNumbers.forEach((key) => {
    const field = fieldByKey(SCHEMA.top_level, key);
    if (field) body.appendChild(renderField(field, top[key], set(key), `top.${key}`));
  });

  const toggles = el('div', 'toggles');
  FIELD_GROUPS.topToggles.forEach((key) => {
    const field = fieldByKey(SCHEMA.top_level, key);
    if (field) toggles.appendChild(toggleRow(field, top[key], set(key)));
  });
  body.appendChild(toggles);

  /* The RACH keys live in their own card, so exclude them here or they would show up a
     second time under "More options". */
  const { rest } = orderedFields(SCHEMA.top_level, [
    ...FIELD_GROUPS.topNumbers, ...FIELD_GROUPS.topToggles,
    ...FIELD_GROUPS.rachPrimary, ...FIELD_GROUPS.rachDependent,
    ...FIELD_GROUPS.securityPrimary, ...FIELD_GROUPS.securityReplay,
  ]);
  appendLeftovers(body, rest, top, set, 'top');
}

function renderLog() {
  const body = $('log-body');
  body.innerHTML = '';
  const log = S.config.log;
  SCHEMA.log.forEach((field) => {
    body.appendChild(renderField(field, log[field.key], (value) => {
      log[field.key] = value;
      scheduleSave();
    }, `log.${field.key}`));
  });
}

function renderAll() {
  renderCells();
  renderRach();
  renderSecurity();
  renderTopLevel();
  renderLog();
  $('out-dir').value = S.out_dir || '';
  $('binary').value = S.binary || '';
  $('max-cells').textContent = SCHEMA.limits.max_cells;
  $('opt-autoscroll').checked = S.console.autoscroll !== false;
  $('opt-wrap').checked = !!S.console.wrap;
  $('console').classList.toggle('wrap', !!S.console.wrap);
  $('plots').classList.toggle('collapsed', !!S.console.plotsCollapsed);
  $('btn-plots-toggle').textContent = S.console.plotsCollapsed ? 'Show' : 'Hide';
  $('sweep-enabled').checked = sweepOn();
  $('sweep-earfcns').value = S.sweep.earfcns || '';
  $('sweep-dwell').value = S.sweep.dwell;
  $('sweep-acquire').value = S.sweep.acquire;
  $('sweep-repeat').checked = !!S.sweep.repeat;
  refreshSweepFields();
  syncPlotsVisibility();
}

/* ------------------------------------------------------------- validation */

function clearErrors() {
  document.querySelectorAll('.field-error').forEach((node) => {
    node.classList.remove('show', 'warn');
    node.textContent = '';
  });
  document.querySelectorAll('input.invalid').forEach((n) => n.classList.remove('invalid'));
}

function showIssues(issues, kind) {
  const unplaced = [];
  issues.forEach((issue) => {
    const slot = document.querySelector(`[data-error-for="${CSS.escape(issue.where)}"]`);
    if (slot) {
      slot.textContent = issue.message;
      slot.classList.add('show');
      if (kind === 'warn') slot.classList.add('warn');
      const input = slot.parentElement.querySelector('input');
      if (input && kind !== 'warn') input.classList.add('invalid');
    } else {
      unplaced.push(issue.message);
    }
  });
  return unplaced;
}

/* Errors on a cell that is not on screen would otherwise be invisible. */
function focusFirstErroringCell(issues) {
  for (const issue of issues) {
    const match = /^cells\.(\d+)\./.exec(issue.where);
    if (match) {
      const index = parseInt(match[1], 10);
      if (index !== S.active_cell && index < S.config.cells.length) {
        S.active_cell = index;
        renderCells();
        return true;
      }
      return false;
    }
  }
  return false;
}

/* ---------------------------------------------------------------- console */

const consoleEl = () => $('console');
let lineCount = 0;

/* The backend already reads severity off srsRAN's ANSI colours; this is the fallback for
   the lines it does not colour. */
function classify(text) {
  if (text.startsWith('[gui]')) return 'gui';
  if (/(error|ERROR|failed|Failed|cannot|[Cc]ould not|refusing|crashed|Segmentation)/.test(text)) return 'err';
  if (/(warning|WARNING|Warning|WARN|not found)/.test(text)) return 'warn';
  if (/^config:/.test(text)) return 'cfg';
  return '';
}

window.appendLines = function appendLines(lines) {
  if (!lines || !lines.length) return;
  const box = consoleEl();
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 60;
  const filter = $('console-filter').value.trim().toLowerCase();

  const frag = document.createDocumentFragment();
  lines.forEach((entry) => {
    /* Entries arrive as {text, cls} from the runner and as plain strings from anything
       the frontend logs itself. */
    const text = typeof entry === 'string' ? entry : entry.text;
    const cls = (typeof entry === 'string' ? null : entry.cls) || classify(text);
    const node = el('div', `line ${cls}`.trim(), text);
    node.dataset.raw = text;
    if (filter && !text.toLowerCase().includes(filter)) node.classList.add('hidden');
    frag.appendChild(node);
  });
  box.appendChild(frag);
  lineCount += lines.length;

  /* Ring buffer: the debug setting emits thousands of lines a second, and an unbounded
     DOM would take the window down with it. */
  let overflow = box.childElementCount - MAX_CONSOLE_LINES;
  while (overflow-- > 0 && box.firstChild) box.removeChild(box.firstChild);

  $('console-empty').classList.add('hidden');
  updateLineCount();
  if ($('opt-autoscroll').checked && atBottom) box.scrollTop = box.scrollHeight;
};

function updateLineCount() {
  const shown = consoleEl().childElementCount;
  const capped = lineCount > shown ? ` (last ${shown.toLocaleString()})` : '';
  $('line-count').textContent = `${lineCount.toLocaleString()} lines${capped}`;
}

function applyFilter() {
  const term = $('console-filter').value.trim().toLowerCase();
  consoleEl().querySelectorAll('.line').forEach((node) => {
    const raw = node.dataset.raw || '';
    if (!term) {
      node.classList.remove('hidden');
      node.textContent = raw;
      return;
    }
    const idx = raw.toLowerCase().indexOf(term);
    if (idx < 0) {
      node.classList.add('hidden');
      return;
    }
    node.classList.remove('hidden');
    node.innerHTML = escapeHtml(raw.slice(0, idx))
      + '<mark>' + escapeHtml(raw.slice(idx, idx + term.length)) + '</mark>'
      + escapeHtml(raw.slice(idx + term.length));
  });
}

function clearConsole() {
  consoleEl().innerHTML = '';
  lineCount = 0;
  updateLineCount();
  $('console-empty').classList.remove('hidden');
}

function consoleText() {
  return Array.from(consoleEl().querySelectorAll('.line'))
    .map((n) => n.dataset.raw || '').join('\n');
}

/* What the user can actually see -- respects an active filter. */
function visibleConsoleText() {
  return Array.from(consoleEl().querySelectorAll('.line:not(.hidden)'))
    .map((n) => n.dataset.raw || '').join('\n');
}

/* ------------------------------------------------------------------- sweep */

let sweepState = null;      // last onSweepProgress payload
let sweepSummary = null;    // path of the summary CSV for the current sweep

function sweepOn() {
  return !!(S.sweep && S.sweep.enabled);
}

async function refreshSweepFields() {
  const on = sweepOn();
  $('sweep-fields').hidden = !on;
  if (!on) return;

  const parsed = await api.parse_earfcn_list(S.sweep.earfcns || '');
  const slot = document.querySelector('[data-error-for="sweep.earfcns"]');
  if (parsed.errors.length) {
    slot.textContent = parsed.errors[0];
    slot.classList.add('show');
    $('sweep-count').textContent = '';
    $('sweep-total').textContent = '';
    return;
  }
  slot.classList.remove('show');
  slot.textContent = '';

  const shown = parsed.preview
    .map((p) => `${p.earfcn} (b${p.band}, ${p.mhz.toFixed(1)})`)
    .join(', ');
  const more = parsed.count > parsed.preview.length ? `, +${parsed.count - parsed.preview.length} more` : '';
  $('sweep-count').textContent = parsed.count
    ? `${parsed.count} channel${parsed.count === 1 ? '' : 's'}: ${shown}${more}`
    : '';

  /* A pass is bounded, not fixed: a channel that locks immediately costs the listen time,
     one with no cell costs the give-up time. Quote the range rather than a fake single
     number. */
  const dwell = Number(S.sweep.dwell) || 0;
  const acquire = Number(S.sweep.acquire) || 0;
  if (parsed.count && dwell && acquire) {
    const fmt = (s) => (s >= 60 ? `${Math.floor(s / 60)}m ${s % 60}s` : `${s}s`);
    $('sweep-total').textContent =
      `one pass: ${fmt(parsed.count * dwell)} if every channel locks at once, `
      + `up to ${fmt(parsed.count * (dwell + acquire))} in the worst case`;
  } else {
    $('sweep-total').textContent = '';
  }
}

function sweepRow(entry, cls) {
  const tr = el('tr', cls);
  const mhz = entry.freq_hz ? (entry.freq_hz / 1e6).toFixed(1) : '';
  const noCell = !entry.locked;
  const cells = [
    { v: entry.earfcn },
    { v: entry.band == null ? '' : `b${entry.band}` },
    { v: mhz },
    { v: entry.pci == null ? '—' : entry.pci, dim: entry.pci == null },
    { v: entry.prb == null ? '—' : entry.prb, dim: entry.prb == null },
    // Lock: how long cell search took, or that it never did.
    { v: entry.lock_s == null ? (noCell ? 'no cell' : '—') : `${entry.lock_s}s`, dim: noCell },
    { v: entry.listen_s == null ? '—' : `${entry.listen_s}s`, dim: entry.listen_s == null },
  ];
  cells.forEach(({ v, dim }) => tr.appendChild(el('td', dim ? 'nocell' : null, String(v))));
  return tr;
}

window.onSweepProgress = function onSweepProgress(state) {
  sweepState = state;
  $('sweep-progress').hidden = false;

  const rows = $('sweep-rows');
  rows.innerHTML = '';
  state.results.forEach((r) => rows.appendChild(sweepRow(r, null)));
  if (state.current) rows.appendChild(sweepRow(state.current, 'current'));

  if (state.active) {
    const pass = state.repeat ? ` · pass ${state.cycle}` : '';
    const where = state.current ? ` · EARFCN ${state.current.earfcn}` : '';
    const what = { acquiring: ' · searching', listening: ' · listening', 'no-cell': ' · no cell' };
    setStatus(state.phase === 'stopping' || state.phase === 'no-cell' ? 'stopping' : 'running',
              `Sweep ${state.index + 1}/${state.total}${where}${what[state.phase] || ''}${pass}`);
    return;
  }

  running = false;
  stopping = false;
  syncButtons();
  const found = state.results.filter((r) => r.locked).length;
  if (state.phase === 'error') {
    setStatus('error', state.error || 'Sweep failed');
    toast(state.error || 'Sweep failed', 'error');
  } else {
    const verb = state.phase === 'cancelled' ? 'Sweep stopped' : 'Sweep complete';
    setStatus('ok', `${verb} — ${found}/${state.results.length} with a cell`);
    toast(`${verb}: ${found} of ${state.results.length} channels had a cell.`, 'ok',
          sweepSummary ? [sweepSummary] : null);
  }
  if (sweepSummary) {
    $('sweep-summary-row').hidden = false;
    $('sweep-summary-path').textContent = sweepSummary;
  }
};

/* ------------------------------------------------------------------- plots */

/* Renders the two series ngscope streams from status_plot.c. The axis scales are the ones
   srsGUI is given there -- the constellation is fixed to +/-3 and the channel response to
   -40..40 dB -- so what shows here is the same view, not a rescaled one. */
const CONST_LIMIT = 3;      // plot_scatter_setXAxisScale(&pdcch, -3, 3)
const CSI_MIN_DB = -40;     // plot_real_setYAxisScale(&csi, -40, 40)
const CSI_MAX_DB = 40;

let lastFrame = null;
let plotPending = false;
let framesSeen = 0;
let runPlotsEnabled = null;   // what the running process was launched with; null when idle

function css(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

/* Sizes the backing store to the device pixel ratio; without this every line is blurry. */
function prepCanvas(canvas) {
  const ratio = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const w = Math.max(1, Math.round(rect.width * ratio));
  const h = Math.max(1, Math.round(rect.height * ratio));
  if (canvas.width !== w || canvas.height !== h) {
    canvas.width = w;
    canvas.height = h;
  }
  const ctx = canvas.getContext('2d');
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  ctx.clearRect(0, 0, rect.width, rect.height);
  return { ctx, w: rect.width, h: rect.height };
}

function drawFrame(ctx, w, h, pad) {
  ctx.strokeStyle = css('--border-str');
  ctx.lineWidth = 1;
  ctx.strokeRect(pad.l + 0.5, pad.t + 0.5, w - pad.l - pad.r - 1, h - pad.t - pad.b - 1);
}

function drawConstellation(points) {
  const canvas = $('plot-const');
  const { ctx, w, h } = prepCanvas(canvas);
  const pad = { l: 28, r: 8, t: 8, b: 18 };

  /* I and Q share the same +/-3 scale, so the plot area has to be square or the
     constellation comes out stretched. Fit the largest square inside the padded box and
     centre it horizontally; the canvas itself stays the width of its grid cell. */
  const side = Math.min(w - pad.l - pad.r, h - pad.t - pad.b);
  const ox = pad.l + (w - pad.l - pad.r - side) / 2;
  const oy = pad.t + (h - pad.t - pad.b - side) / 2;
  const cx = ox + side / 2;
  const cy = oy + side / 2;

  // Axes through the origin.
  ctx.strokeStyle = css('--border');
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(cx, oy); ctx.lineTo(cx, oy + side);
  ctx.moveTo(ox, cy); ctx.lineTo(ox + side, cy);
  ctx.stroke();

  ctx.strokeStyle = css('--border-str');
  ctx.strokeRect(ox + 0.5, oy + 0.5, side - 1, side - 1);

  ctx.fillStyle = css('--text-faint');
  ctx.font = '10px system-ui, sans-serif';
  ctx.fillText(`${CONST_LIMIT}`, ox - 14, oy + 9);
  ctx.fillText(`-${CONST_LIMIT}`, ox - 17, oy + side);
  ctx.fillText('I', ox + side - 6, oy + side + 13);
  ctx.save();
  ctx.translate(ox - 12, cy); ctx.rotate(-Math.PI / 2);
  ctx.fillText('Q', 0, 0);
  ctx.restore();

  if (!points || !points.length) return;
  ctx.fillStyle = css('--accent');
  ctx.globalAlpha = 0.55;
  const scale = side / (2 * CONST_LIMIT);   // one scale: equal aspect by construction
  for (let i = 0; i < points.length; i += 2) {
    const x = cx + points[i] * scale;
    const y = cy - points[i + 1] * scale;
    if (x < ox || x > ox + side || y < oy || y > oy + side) continue;
    ctx.fillRect(x - 1, y - 1, 2, 2);
  }
  ctx.globalAlpha = 1;
}

function drawChannelResponse(csi) {
  const canvas = $('plot-csi');
  const { ctx, w, h } = prepCanvas(canvas);
  const pad = { l: 30, r: 8, t: 8, b: 18 };
  const iw = w - pad.l - pad.r;
  const ih = h - pad.t - pad.b;

  ctx.strokeStyle = css('--border');
  ctx.fillStyle = css('--text-faint');
  ctx.font = '10px system-ui, sans-serif';
  ctx.beginPath();
  for (let db = CSI_MIN_DB; db <= CSI_MAX_DB; db += 20) {
    const y = pad.t + ih * (1 - (db - CSI_MIN_DB) / (CSI_MAX_DB - CSI_MIN_DB));
    ctx.moveTo(pad.l, y); ctx.lineTo(pad.l + iw, y);
    ctx.fillText(String(db), 4, y + 3);
  }
  ctx.stroke();
  drawFrame(ctx, w, h, pad);
  ctx.fillText('Subcarrier Index', pad.l + iw / 2 - 38, pad.t + ih + 14);

  if (!csi || !csi.length) return;
  ctx.strokeStyle = css('--ok');
  ctx.lineWidth = 1;
  ctx.beginPath();
  for (let i = 0; i < csi.length; i++) {
    const x = pad.l + (iw * i) / Math.max(1, csi.length - 1);
    const clamped = Math.min(CSI_MAX_DB, Math.max(CSI_MIN_DB, csi[i]));
    const y = pad.t + ih * (1 - (clamped - CSI_MIN_DB) / (CSI_MAX_DB - CSI_MIN_DB));
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  }
  ctx.stroke();
}

function renderPlots() {
  plotPending = false;
  if ($('plots').classList.contains('collapsed')) return;
  drawConstellation(lastFrame && lastFrame.iq);
  drawChannelResponse(lastFrame && lastFrame.csi);
}

/* Frames arrive up to 20/s; coalesce onto the frame clock so a slow paint cannot queue up. */
window.onPlotFrame = function onPlotFrame(frame) {
  lastFrame = frame;
  framesSeen++;
  $('plots-note').textContent =
    `${frame.nof_const} symbols · ${frame.nof_csi} subcarriers · frame ${framesSeen}`;
  if (!plotPending) {
    plotPending = true;
    requestAnimationFrame(renderPlots);
  }
};

/* Whether ngscope will stream anything at all. Mirrors dci_decoder.c:673, which only
   starts the plot thread when a cell leaves disable_plot off. */
function plotsEnabled() {
  // Mid-run, what matters is the config ngscope was actually launched with -- toggling
  // the setting during a run must not hide a panel that is still being drawn to.
  if (running && runPlotsEnabled !== null) return runPlotsEnabled;
  return S.config.cells.some((c) => !c.disable_plot);
}

function syncPlotsVisibility() {
  const on = plotsEnabled();
  $('plots').classList.toggle('unavailable', !on);
  if (!on) return;
  if (!lastFrame) $('plots-note').textContent = 'Waiting for ngscope…';
  renderPlots();
}

/* ------------------------------------------------------------------ status */

function setStatus(state, text) {
  $('status').dataset.state = state;
  $('status-text').textContent = text;
}

function syncButtons() {
  $('btn-start').disabled = running || stopping;
  $('btn-stop').disabled = !running || stopping;
  $('btn-load').disabled = running;
}

window.onRunDir = function onRunDir(path) {
  runDir = path;
  $('btn-run-dir').disabled = false;
  $('btn-run-dir').title = path;
};

window.onExit = function onExit(info) {
  running = false;
  stopping = false;
  runPlotsEnabled = null;
  syncPlotsVisibility();
  syncButtons();
  setStatus(info.kind === 'ok' ? 'ok' : info.kind === 'warn' ? 'idle' : 'error',
            `ngscope ${info.message}`);
  window.appendLines([`[gui] ngscope ${info.message}`]);
  toast(`ngscope ${info.message}`, info.kind === 'ok' ? 'ok' : info.kind);
};

window.onJoinDone = function onJoinDone(info) {
  if (info && info.ok) {
    toast('Security phase join finished', 'ok');
  } else {
    toast('Security phase join failed \u2014 see the console', 'error');
  }
};

/* ------------------------------------------------------------------ actions */

async function start() {
  clearErrors();
  const result = sweepOn()
    ? await api.sweep_start(S.config, S.out_dir, S.sweep.earfcns, S.sweep.dwell,
                            S.sweep.acquire, !!S.sweep.repeat, S.binary)
    : await api.start(S.config, S.out_dir, S.binary);

  if (!result.ok) {
    if (result.errors) {
      if (focusFirstErroringCell(result.errors)) clearErrors();
      const unplaced = showIssues(result.errors, 'error');
      toast('Cannot start', 'error', result.errors.map((e) => e.message));
      if (unplaced.length) console.warn('unplaced errors', unplaced);
    } else {
      toast(result.error, 'error');
    }
    return;
  }

  if (result.warnings && result.warnings.length) {
    showIssues(result.warnings, 'warn');
    toast('Started with warnings', 'warn', result.warnings.map((w) => w.message));
  }

  running = true;
  stopping = false;
  runDir = null;
  lastFrame = null;
  framesSeen = 0;
  runPlotsEnabled = S.config.cells.some((c) => !c.disable_plot);
  syncPlotsVisibility();
  $('btn-run-dir').disabled = true;
  syncButtons();
  if (sweepOn()) {
    $('sweep-rows').innerHTML = '';
    sweepSummary = result.summary || null;
    setStatus('running', `Sweep 1/${result.earfcns.length}`);
  } else {
    setStatus('running', 'Running');
  }
}

async function stop() {
  const result = await api.stop();
  if (!result.ok) {
    toast(result.error, 'warn');
    return;
  }
  stopping = true;
  syncButtons();
  setStatus('stopping', 'Stopping…');
}

async function refreshBinaryHelp() {
  const info = await api.resolve_binary(S.binary || '');
  const help = $('binary-help');
  if (info.path) {
    help.textContent = `Using ${info.path} (${info.source}).`;
    help.style.color = '';
  } else {
    help.textContent = 'No ngscope executable found — build the project or set the path here.';
    help.style.color = 'var(--danger)';
  }
}

/* ------------------------------------------------------------------- wiring */

function bind() {
  $('btn-start').addEventListener('click', start);
  $('btn-stop').addEventListener('click', stop);

  $('btn-out-dir').addEventListener('click', async () => {
    const picked = await api.pick_out_dir(S.out_dir || '');
    if (picked) {
      S.out_dir = picked;
      $('out-dir').value = picked;
      scheduleSave();
    }
  });
  $('out-dir').addEventListener('input', (e) => { S.out_dir = e.target.value; scheduleSave(); });

  $('btn-binary').addEventListener('click', async () => {
    const picked = await api.pick_binary(S.binary || '');
    if (picked) {
      S.binary = picked;
      $('binary').value = picked;
      scheduleSave();
      refreshBinaryHelp();
    }
  });
  $('binary').addEventListener('input', (e) => {
    S.binary = e.target.value;
    scheduleSave();
    refreshBinaryHelp();
  });

  $('btn-load').addEventListener('click', async () => {
    const result = await api.load_toml();
    if (!result) return;
    if (!result.ok) { toast(result.error, 'error'); return; }
    S.config = result.config;
    S.active_cell = 0;
    clearErrors();
    renderAll();
    scheduleSave();
    toast(`Loaded ${result.path}`, 'ok');
  });

  $('btn-save-as').addEventListener('click', async () => {
    const result = await api.save_toml_as(S.config);
    if (!result) return;
    toast(result.ok ? `Saved ${result.path}` : result.error, result.ok ? 'ok' : 'error');
  });

  /* Copies the selection if there is one, otherwise everything currently shown -- which
     with a filter applied means just the matching lines. */
  $('btn-copy').addEventListener('click', async () => {
    const selected = String(window.getSelection() || '');
    const text = selected.trim() ? selected : visibleConsoleText();
    if (!text) { toast('Nothing to copy.', 'warn'); return; }
    try {
      await navigator.clipboard.writeText(text);
      const lines = text.split('\n').length;
      toast(selected.trim() ? 'Selection copied.' : `Copied ${lines.toLocaleString()} lines.`, 'ok');
    } catch (err) {
      toast(`Could not copy: ${err}`, 'error');
    }
  });

  $('btn-clear').addEventListener('click', clearConsole);
  $('btn-save-console').addEventListener('click', async () => {
    const result = await api.save_console(consoleText());
    if (!result) return;
    toast(result.ok ? `Saved ${result.path}` : result.error, result.ok ? 'ok' : 'error');
  });
  $('btn-run-dir').addEventListener('click', async () => {
    if (!runDir) return;
    const result = await api.open_path(runDir);
    if (!result.ok) toast(result.error, 'warn');
  });

  $('sweep-enabled').addEventListener('change', (e) => {
    S.sweep.enabled = e.target.checked;
    scheduleSave();
    refreshSweepFields();
    renderCells();     // cell 1's tuning field is driven by the sweep while it is on
  });
  $('sweep-earfcns').addEventListener('input', (e) => {
    S.sweep.earfcns = e.target.value;
    scheduleSave();
    refreshSweepFields();
  });
  $('sweep-dwell').addEventListener('input', (e) => {
    const n = parseInt(e.target.value, 10);
    S.sweep.dwell = Number.isNaN(n) ? '' : n;
    scheduleSave();
    refreshSweepFields();
  });
  $('sweep-acquire').addEventListener('input', (e) => {
    const n = parseInt(e.target.value, 10);
    S.sweep.acquire = Number.isNaN(n) ? '' : n;
    scheduleSave();
    refreshSweepFields();
  });
  $('sweep-repeat').addEventListener('change', (e) => {
    S.sweep.repeat = e.target.checked;
    scheduleSave();
  });

  $('btn-plots-toggle').addEventListener('click', () => {
    const collapsed = $('plots').classList.toggle('collapsed');
    $('btn-plots-toggle').textContent = collapsed ? 'Show' : 'Hide';
    S.console.plotsCollapsed = collapsed;
    scheduleSave();
    if (!collapsed) renderPlots();
  });

  $('console-filter').addEventListener('input', applyFilter);
  $('opt-autoscroll').addEventListener('change', (e) => {
    S.console.autoscroll = e.target.checked;
    if (e.target.checked) consoleEl().scrollTop = consoleEl().scrollHeight;
    scheduleSave();
  });
  $('opt-wrap').addEventListener('change', (e) => {
    S.console.wrap = e.target.checked;
    consoleEl().classList.toggle('wrap', e.target.checked);
    scheduleSave();
  });

  window.addEventListener('resize', () => {
    S.window = { width: window.outerWidth, height: window.outerHeight };
    scheduleSave();
    renderPlots();   // canvases are sized from their laid-out box
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && !running) start();
    if (e.key === 'Escape' && running && !stopping) stop();
  });
}

async function init() {
  api = window.pywebview.api;
  const boot = await api.bootstrap();
  SCHEMA = boot.schema;
  S = boot.state;

  if (!S.config || !S.config.cells || !S.config.cells.length) {
    toast('Saved settings were unreadable — starting from defaults.', 'warn');
  }

  renderAll();
  bind();
  await refreshBinaryHelp();
  updateLineCount();
  $('state-note').textContent = `Settings saved to ${boot.config_path}`;
  setStatus('idle', 'Idle');
  syncButtons();
}

window.addEventListener('pywebviewready', init);
