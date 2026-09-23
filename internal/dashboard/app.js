/* ==========================================================================
   STATE
   ========================================================================== */
var S = {
  snapshot: {},
  run: { status: 'idle', progress: 0, config: null, elapsed: '0s', duration: 0 },
  history: [],
  rpsHist: [],
  latAvgHist: [],
  latP50Hist: [],
  latP95Hist: [],
  latP99Hist: [],
  errHist: [],
  userHist: [],
  connected: false,
  starting: false,      // start request currently in flight (spinner)
  stopArmed: false,     // two-step stop confirm: first press arms, second stops
  stopArmTimer: null,
  summaryVisible: false
};
var MAX_HIST = 120;
var ws = null;
var API = location.origin;

/* Demo target shipped with the repo (examples/demo_server.go). */
var DEMO_URL = 'http://127.0.0.1:8080/health';

/* localStorage keys */
var OB_KEY = 'ss_onboarding_dismissed';
var CFG_KEY = 'ss_last_config';

/* ==========================================================================
   SAFE localStorage (CSP + privacy: never throw, never block)
   ========================================================================== */
function lsGet(k) {
  try { return window.localStorage.getItem(k); } catch (e) { return null; }
}
function lsSet(k, v) {
  try { window.localStorage.setItem(k, v); } catch (e) { /* storage full / blocked — ignore */ }
}

/* ==========================================================================
   WEBSOCKET
   ========================================================================== */
var wsRetryTimer = null;

function connect() {
  if (wsRetryTimer) { clearTimeout(wsRetryTimer); wsRetryTimer = null; }
  var url = API.replace(/^http/, 'ws') + '/ws';
  var sock;
  try { sock = new WebSocket(url); } catch (e) { scheduleReconnect(); return; }
  ws = sock;
  ws.onopen = function() {
    S.connected = true;
    updateConnStatus();
    toast('Connected to dashboard', 'success');
  };
  ws.onmessage = function(e) {
    var msg;
    try { msg = JSON.parse(e.data); } catch (err) { return; }
    if (msg.type === 'init') {
      S.run = msg.state || S.run;
      S.history = msg.history || [];
      renderHistory();
      syncOnboarding();
    } else if (msg.type === 'snapshot') {
      var d = msg.data;
      S.snapshot = d;
      pushHist('rpsHist', d.rps || 0);
      pushHist('latAvgHist', d.avg_latency_ms || 0);
      pushHist('latP50Hist', d.p50_latency_ms || 0);
      pushHist('latP95Hist', d.p95_latency_ms || 0);
      pushHist('latP99Hist', d.p99_latency_ms || 0);
      pushHist('errHist', d.error_rate || 0);
      pushHist('userHist', d.active_users || 0);
    } else if (msg.type === 'run_state') {
      var prev = S.run.status;
      var st = (msg.data && msg.data.status) || '';
      S.run = msg.data;
      if (st === 'running') {
        if (prev !== 'running') {
          S.starting = false;
          hideSummary();
          disarmStop();
          dismissOnboarding(); // first run started -> guide goes away for good
        }
      }
      if (prev !== 'completed' && st === 'completed') {
        S.starting = false;
        toast('Run completed!', 'success');
        refreshHistory();
        showSummary('completed');
      }
      if (prev !== 'failed' && st === 'failed') {
        S.starting = false;
        toast(S.run.error ? ('Run failed: ' + S.run.error) : 'Run failed!', 'error');
        refreshHistory();
        showSummary('failed');
      }
      if (prev !== 'stopped' && st === 'stopped') {
        S.starting = false;
        toast('Run stopped', 'info');
        refreshHistory();
        showSummary('stopped');
      }
    }
    render();
  };
  ws.onclose = function() {
    S.connected = false;
    updateConnStatus();
    scheduleReconnect();
  };
  ws.onerror = function() {};
}

function scheduleReconnect() {
  if (wsRetryTimer) return;
  wsRetryTimer = setTimeout(function() { wsRetryTimer = null; connect(); }, 2000);
}

// Re-fetch run history after a run finishes. The server only sends history in
// the WS "init" message, so a completed run would otherwise stay invisible in
// the table until the page is reloaded.
function refreshHistory() {
  fetch(API + '/api/history').then(function(r) { return r.json(); }).then(function(h) {
    S.history = h || [];
    renderHistory();
    syncOnboarding();
  }).catch(function() {});
}

function pushHist(arr, val) {
  S[arr].push(val);
  if (S[arr].length > MAX_HIST) S[arr].shift();
}

/* ==========================================================================
   FORM — validation helpers
   ========================================================================== */
function validUrl(v) {
  v = (v || '').trim();
  if (!v) return false;
  if (!/^https?:\/\/.+/i.test(v)) return false;
  try {
    var u = new URL(v);
    return !!u.host;
  } catch (e) { return false; }
}

function setUrlError(msg) {
  var f = document.getElementById('urlError');
  var i = document.getElementById('inpUrl');
  if (!f || !i) return;
  if (msg) {
    if (f.textContent !== msg) f.textContent = msg;
    i.setAttribute('aria-invalid', 'true');
    i.classList.add('invalid');
  } else {
    if (f.textContent) f.textContent = '';
    i.removeAttribute('aria-invalid');
    i.classList.remove('invalid');
  }
}

function setObError(msg) {
  var f = document.getElementById('obError');
  var i = document.getElementById('obUrl');
  if (!f || !i) return;
  if (msg) {
    f.textContent = msg;
    i.setAttribute('aria-invalid', 'true');
    i.classList.add('invalid');
  } else {
    f.textContent = '';
    i.removeAttribute('aria-invalid');
    i.classList.remove('invalid');
  }
}

/* ==========================================================================
   ACTIONS
   ========================================================================== */
function collectConfig() {
  return {
    target_url: document.getElementById('inpUrl').value.trim() || 'http://localhost:8080/health',
    users: parseInt(document.getElementById('inpUsers').value, 10) || 10,
    duration_seconds: parseInt(document.getElementById('inpDuration').value, 10) || 30,
    method: document.getElementById('inpMethod').value || 'GET',
    rate_limit: parseInt(document.getElementById('inpRate').value, 10) || 0,
    profile: document.getElementById('inpProfile').value || 'steady',
    tls_fingerprint: document.getElementById('inpFingerprint').value || ''
  };
}

function startRun() {
  if (S.starting) return;
  if (S.run && S.run.status === 'running') {
    toast('A run is already in progress', 'info');
    return;
  }
  var url = (document.getElementById('inpUrl').value || '').trim();
  if (!url) {
    setUrlError('Target URL is required. Example: ' + DEMO_URL);
    document.getElementById('inpUrl').focus();
    return;
  }
  if (!validUrl(url)) {
    setUrlError('Enter a full http(s) URL, e.g. ' + DEMO_URL);
    document.getElementById('inpUrl').focus();
    return;
  }
  setUrlError('');

  var cfg = collectConfig();
  S.starting = true;
  updateStartButton();

  fetch(API + '/api/run/start', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(cfg)
  }).then(function(r) {
    if (!r.ok) throw new Error('server returned ' + r.status);
    return r.json();
  }).then(function() {
    toast('Run started!', 'info');
    saveLastConfig(cfg);
    dismissOnboarding(); // first run started -> guide hides automatically
    hideSummary();
  }).catch(function(err) {
    toast('Failed to start run' + (err && err.message ? ': ' + err.message : ''), 'error');
  }).then(function() {
    // Runs in both success and error paths (ES5-friendly "finally").
    S.starting = false;
    updateStartButton();
  });
}

function stopRun() {
  fetch(API + '/api/run/stop', { method: 'POST' }).then(function(r) {
    if (!r.ok) throw new Error('server returned ' + r.status);
    return r.json();
  }).then(function() { toast('Run stopped', 'error'); })
    .catch(function() { toast('Failed to stop run', 'error'); });
}

/* Two-step stop: first press arms the button, a second press (within 3s)
   actually stops the run. Escape or the run finishing disarms it. */
function requestStop() {
  if (!S.run || S.run.status !== 'running') return;
  if (S.stopArmed) {
    disarmStop();
    stopRun();
    return;
  }
  S.stopArmed = true;
  var b = document.getElementById('btnStop');
  var l = document.getElementById('btnStopLabel');
  if (b) {
    b.classList.add('armed');
    b.setAttribute('aria-label', 'Confirm stop: press again to stop the run');
  }
  if (l) l.textContent = 'Confirm stop';
  S.stopArmTimer = setTimeout(disarmStop, 3000);
}

function disarmStop() {
  if (!S.stopArmed && !S.stopArmTimer) return;
  S.stopArmed = false;
  if (S.stopArmTimer) { clearTimeout(S.stopArmTimer); S.stopArmTimer = null; }
  var b = document.getElementById('btnStop');
  var l = document.getElementById('btnStopLabel');
  if (b) {
    b.classList.remove('armed');
    b.setAttribute('aria-label', 'Stop the current run. Press twice to confirm.');
  }
  if (l) l.textContent = 'Stop';
}

function updateStartButton() {
  var b = document.getElementById('btnStart');
  if (!b) return;
  var running = S.run && S.run.status === 'running';
  b.disabled = running || S.starting;
  b.classList.toggle('loading', !!S.starting);
  b.setAttribute('aria-busy', S.starting ? 'true' : 'false');
}

/* Remember the last run so the next visit starts pre-filled. */
function saveLastConfig(cfg) {
  lsSet(CFG_KEY, JSON.stringify({
    target_url: cfg.target_url,
    users: cfg.users,
    duration_seconds: cfg.duration_seconds,
    method: cfg.method,
    rate_limit: cfg.rate_limit,
    profile: cfg.profile,
    tls_fingerprint: cfg.tls_fingerprint
  }));
}
function restoreLastConfig() {
  var raw = lsGet(CFG_KEY);
  if (!raw) return;
  var c;
  try { c = JSON.parse(raw); } catch (e) { return; }
  if (!c || typeof c !== 'object') return;
  if (typeof c.target_url === 'string' && validUrl(c.target_url)) {
    document.getElementById('inpUrl').value = c.target_url;
  }
  if (typeof c.users === 'number' && c.users > 0) {
    document.getElementById('inpUsers').value = c.users;
    document.getElementById('rngUsers').value = clampSlider('rngUsers', c.users);
  }
  if (typeof c.duration_seconds === 'number' && c.duration_seconds > 0) {
    document.getElementById('inpDuration').value = c.duration_seconds;
    document.getElementById('rngDuration').value = clampSlider('rngDuration', c.duration_seconds);
  }
  if (typeof c.method === 'string' && selectHasOption('inpMethod', c.method)) {
    document.getElementById('inpMethod').value = c.method;
  }
  if (typeof c.rate_limit === 'number' && c.rate_limit >= 0) {
    document.getElementById('inpRate').value = c.rate_limit;
  }
  if (typeof c.profile === 'string' && selectHasOption('inpProfile', c.profile)) {
    document.getElementById('inpProfile').value = c.profile;
  }
  if (typeof c.tls_fingerprint === 'string' && selectHasOption('inpFingerprint', c.tls_fingerprint)) {
    document.getElementById('inpFingerprint').value = c.tls_fingerprint;
  }
  updateFieldHints();
}
function clampSlider(id, v) {
  var s = document.getElementById(id);
  if (!s) return v;
  var min = parseInt(s.min, 10) || 0, max = parseInt(s.max, 10) || 100;
  v = parseInt(v, 10);
  if (isNaN(v)) return s.value;
  if (v < min) return min;
  if (v > max) return max;
  return v;
}
function selectHasOption(id, val) {
  var s = document.getElementById(id);
  if (!s) return false;
  for (var i = 0; i < s.options.length; i++) {
    if (s.options[i].value === val || s.options[i].text === val) return true;
  }
  return false;
}

/* ==========================================================================
   ONBOARDING (first-run empty state)
   ========================================================================== */
function shouldShowOnboarding() {
  if (lsGet(OB_KEY) === '1') return false;
  if (S.history && S.history.length > 0) return false;
  var st = S.run && S.run.status;
  if (st === 'running' || st === 'completed' || st === 'stopped' || st === 'failed') return false;
  return true;
}
function syncOnboarding() {
  var el = document.getElementById('onboarding');
  if (!el) return;
  var show = shouldShowOnboarding();
  if (show && el.classList.contains('hidden')) el.classList.remove('hidden');
  if (!show && !el.classList.contains('hidden')) el.classList.add('hidden');
}
function dismissOnboarding() {
  lsSet(OB_KEY, '1');
  var el = document.getElementById('onboarding');
  if (el && !el.classList.contains('hidden')) el.classList.add('hidden');
}

/* Load demo target into both URL fields. */
function loadDemoUrl() {
  var ob = document.getElementById('obUrl');
  var main = document.getElementById('inpUrl');
  if (ob) { ob.value = DEMO_URL; setObError(''); }
  if (main) { main.value = DEMO_URL; setUrlError(''); }
  toast('Demo URL loaded: ' + DEMO_URL, 'info');
}

function obSubmit(e) {
  if (e) e.preventDefault();
  var ob = document.getElementById('obUrl');
  if (!ob) return;
  var v = (ob.value || '').trim();
  if (!v) {
    setObError('Target URL is required.');
    ob.focus();
    return;
  }
  if (!validUrl(v)) {
    setObError('Enter a full http(s) URL, e.g. ' + DEMO_URL);
    ob.focus();
    return;
  }
  setObError('');
  document.getElementById('inpUrl').value = v;
  startRun();
}

/* ==========================================================================
   RUN SUMMARY (shown after a run ends)
   ========================================================================== */
function sumStat(label, value, cls) {
  var d = document.createElement('div');
  d.className = 'sum-stat';
  var l = document.createElement('span');
  l.className = 'sum-label';
  l.textContent = label;
  var v = document.createElement('span');
  v.className = 'sum-value' + (cls ? ' ' + cls : '');
  v.textContent = value;
  d.appendChild(l);
  d.appendChild(v);
  return d;
}
function buildNote(lead) {
  var note = document.createElement('span');
  note.textContent = lead;
  var code = document.createElement('code');
  code.textContent = 'reports/';
  note.appendChild(code);
  note.appendChild(document.createTextNode(' (CLI mode) \u00b7 Run History below refreshed automatically.'));
  return note;
}
function showSummary(kind) {
  var el = document.getElementById('runSummary');
  if (!el) return;
  el.classList.remove('warn', 'error');
  var title = document.getElementById('summaryTitle');
  var note = document.getElementById('summaryNote');
  var stats = document.getElementById('summaryStats');
  if (!title || !note || !stats) return;

  var s = S.snapshot || {};
  var r = S.run || {};

  if (kind === 'completed') {
    title.textContent = 'Test complete';
    note.textContent = '';
    note.appendChild(buildNote('Results available below \u00b7 JSON/TXT copies written to '));
  } else if (kind === 'stopped') {
    el.classList.add('warn');
    title.textContent = 'Run stopped';
    note.textContent = '';
    note.appendChild(buildNote('Partial results below \u00b7 JSON/TXT copies written to '));
  } else {
    el.classList.add('error');
    title.textContent = 'Run failed';
    note.textContent = (r.error ? String(r.error) : 'The run ended with an error. No report was written.');
  }

  stats.textContent = '';
  if (kind !== 'failed') {
    var errPct = s.error_rate || 0;
    stats.appendChild(sumStat('RPS', String(Math.round(s.rps || 0)), 't-green'));
    stats.appendChild(sumStat('P50', fmtMs(s.p50_latency_ms)));
    stats.appendChild(sumStat('P99', fmtMs(s.p99_latency_ms), 't-strong'));
    stats.appendChild(sumStat('Requests', fmt(s.total_requests || 0)));
    stats.appendChild(sumStat('Errors', fmt(s.total_errors || 0) + ' (' + errPct.toFixed(1) + '%)',
      errPct > 5 ? 't-red' : (errPct > 1 ? 't-yellow' : '')));
  }

  el.classList.remove('hidden');
  S.summaryVisible = true;
}
function hideSummary() {
  var el = document.getElementById('runSummary');
  if (el && !el.classList.contains('hidden')) el.classList.add('hidden');
  S.summaryVisible = false;
}
function viewReport() {
  var sec = document.getElementById('historySection');
  if (!sec || sec.classList.contains('hidden')) {
    toast('No history yet — reports appear here after a run', 'info');
    return;
  }
  sec.scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth', block: 'start' });
  sec.classList.add('flash');
  var panel = sec.querySelector('.panel');
  if (panel) { panel.setAttribute('tabindex', '-1'); panel.focus({ preventScroll: true }); }
  setTimeout(function() { sec.classList.remove('flash'); }, 1800);
}
function reducedMotion() {
  try {
    return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  } catch (e) { return false; }
}

/* ==========================================================================
   TOAST
   ========================================================================== */
function toast(msg, type) {
  var c = document.getElementById('toasts');
  var t = document.createElement('div');
  t.className = 'toast ' + (type || 'info');
  t.textContent = msg;
  c.appendChild(t);
  setTimeout(function() { t.classList.add('out'); setTimeout(function() { t.remove(); }, 320); }, 3000);
}

/* ==========================================================================
   SLIDERS (users / duration) + field hints
   ========================================================================== */
function fmtUsersHint(v) { v = parseInt(v, 10); return isNaN(v) ? '' : v + ' users'; }
function fmtDurationHint(v) { v = parseInt(v, 10); return isNaN(v) ? '' : formatDuration(v); }

function bindSlider(numId, rngId, hintId, fmtHint) {
  var n = document.getElementById(numId);
  var r = document.getElementById(rngId);
  var h = document.getElementById(hintId);
  if (!n || !r) return;
  r.addEventListener('input', function() {
    n.value = r.value;
    if (h) h.textContent = fmtHint(r.value);
  });
  n.addEventListener('input', function() {
    var v = parseInt(n.value, 10);
    if (isNaN(v)) return;
    r.value = clampSlider(rngId, v);
    if (h) h.textContent = fmtHint(n.value);
  });
}

function syncSliderFromInput(numId, rngId, hintId, fmtHint) {
  var n = document.getElementById(numId);
  var r = document.getElementById(rngId);
  var h = document.getElementById(hintId);
  if (!n || !r) return;
  var v = parseInt(n.value, 10);
  if (!isNaN(v)) r.value = clampSlider(rngId, v);
  if (h) h.textContent = fmtHint(n.value || 0);
}

function updateFieldHints() {
  setHint('hintUsers', fmtUsersHint(document.getElementById('inpUsers').value));
  setHint('hintDuration', fmtDurationHint(document.getElementById('inpDuration').value));
  syncSliderFromInput('inpUsers', 'rngUsers', null, fmtUsersHint);
  syncSliderFromInput('inpDuration', 'rngDuration', null, fmtDurationHint);
}
function setHint(id, txt) {
  var h = document.getElementById(id);
  if (h && h.textContent !== txt) h.textContent = txt;
}

/* ==========================================================================
   RENDER
   ========================================================================== */
function render() {
  var s = S.snapshot || {};
  var r = S.run || {};
  var running = r.status === 'running';
  var elapsed = r.elapsed || 0;
  var duration = (r.config && r.config.duration_seconds) || (S.run.duration || 30);
  if (typeof elapsed === 'number') elapsed = elapsed / 1e9; // nanoseconds to seconds
  var elapsedNum = parseFloat(elapsed) || 0;
  var progress = r.progress || 0;

  // Status badge
  var badge = document.getElementById('statusBadge');
  if (badge && badge.getAttribute('data-status') !== (r.status || 'idle')) {
    badge.setAttribute('data-status', r.status || 'idle');
    badge.className = 'badge badge-' + (r.status || 'idle');
    badge.textContent = (r.status || 'idle');
  }

  // Buttons
  updateStartButton();
  document.getElementById('btnStop').disabled = !running;
  if (!running) disarmStop();
  var cf = document.getElementById('controlsForm');
  if (cf) cf.classList.toggle('is-running', !!running);

  // Progress
  var pf = document.getElementById('progressFill');
  if (pf) {
    pf.style.width = progress + '%';
    pf.className = 'progress-fill' + (running ? ' active' : '');
  }
  var remain = Math.max(0, duration - elapsedNum);
  var ptext = progress.toFixed(0) + '% | ' + formatDuration(elapsedNum) + ' / ' + formatDuration(duration) + ' | ' + formatDuration(remain) + ' left';
  var pt = document.getElementById('progressText');
  if (pt && pt.textContent !== ptext) pt.textContent = ptext;
  var pbar = document.getElementById('progressBar');
  if (pbar) {
    pbar.setAttribute('aria-valuenow', String(Math.round(progress)));
    pbar.setAttribute('aria-valuetext', formatDuration(elapsedNum) + ' of ' + formatDuration(duration));
  }

  // Populate inputs from config when running (guards: skip the field the user
  // is actively editing, including the linked sliders)
  if (r.config) {
    if (document.activeElement.id !== 'inpUrl') document.getElementById('inpUrl').value = r.config.target_url || '';
    if (document.activeElement.id !== 'inpUsers' && document.activeElement.id !== 'rngUsers') document.getElementById('inpUsers').value = r.config.users || 10;
    if (document.activeElement.id !== 'inpDuration' && document.activeElement.id !== 'rngDuration') document.getElementById('inpDuration').value = r.config.duration_seconds || 30;
    if (document.activeElement.id !== 'inpMethod') document.getElementById('inpMethod').value = r.config.method || 'GET';
    if (document.activeElement.id !== 'inpRate') document.getElementById('inpRate').value = r.config.rate_limit || 0;
    if (document.activeElement.id !== 'inpProfile' && r.config.profile) document.getElementById('inpProfile').value = r.config.profile;
    if (document.activeElement.id !== 'inpFingerprint' && r.config.tls_fingerprint) document.getElementById('inpFingerprint').value = r.config.tls_fingerprint;
  }
  updateFieldHints();

  // Config meta + live latency strip
  document.getElementById('metaProfile').textContent = (r.config && r.config.profile) || '\u2014';
  document.getElementById('metaRate').textContent = (r.config && r.config.rate_limit) ? r.config.rate_limit + ' req/s' : '\u2014';
  document.getElementById('metaFingerprint').textContent = (r.config && r.config.tls_fingerprint) || '\u2014';
  document.getElementById('metaP50').textContent = (s.p50_latency_ms || 0).toFixed(1) + ' ms';
  document.getElementById('metaP95').textContent = (s.p95_latency_ms || 0).toFixed(1) + ' ms';
  document.getElementById('metaP99').textContent = (s.p99_latency_ms || 0).toFixed(1) + ' ms';
  document.getElementById('metaAvg').textContent = (s.avg_latency_ms || 0).toFixed(1) + ' ms';
  document.getElementById('metaMax').textContent = (s.max_latency_ms || 0).toFixed(1) + ' ms';

  // Metric cards
  var rps = s.rps || 0;
  document.getElementById('valRPS').textContent = Math.round(rps);
  document.getElementById('subRPS').textContent = fmt(s.total_requests || 0) + ' total requests';

  var avg = s.avg_latency_ms || 0;
  document.getElementById('valAvg').innerHTML = avg.toFixed(1) + ' <small>ms</small>';
  document.getElementById('subLatency').textContent =
    'P50: ' + (s.p50_latency_ms || 0).toFixed(1) + ' \u00b7 P95: ' + (s.p95_latency_ms || 0).toFixed(1) + ' \u00b7 P99: ' + (s.p99_latency_ms || 0).toFixed(1) + ' ms';

  var errRate = s.error_rate || 0;
  var errEl = document.getElementById('valErrors');
  errEl.style.color = errRate > 5 ? 'var(--red)' : errRate > 1 ? 'var(--yellow)' : 'var(--green)';
  errEl.innerHTML = errRate.toFixed(2) + ' <small>%</small>';
  document.getElementById('subErrors').textContent = fmt(s.total_errors || 0) + ' errors / ' + fmt(s.total_requests || 0) + ' total';

  document.getElementById('valUsers').textContent = s.active_users || 0;

  // Latency detail cards
  document.getElementById('latP50').textContent = (s.p50_latency_ms || 0).toFixed(1);
  document.getElementById('latP95').textContent = (s.p95_latency_ms || 0).toFixed(1);
  document.getElementById('latP99').textContent = (s.p99_latency_ms || 0).toFixed(1);

  // Status codes
  renderStatusCodes(s.status_codes || {});

  // Workers
  renderWorkers(s.workers || []);

  // Charts
  drawSparkline('sparkRPS', S.rpsHist, 'rgba(0,232,123,0.6)');
  drawSparkline('sparkLatency', S.latAvgHist, 'rgba(59,130,246,0.6)');
  drawSparkline('sparkErrors', S.errHist, errRate > 5 ? 'rgba(239,68,68,0.6)' : 'rgba(0,232,123,0.6)');
  drawSparkline('sparkUsers', S.userHist, 'rgba(245,158,11,0.6)');
  drawTimelineChart('chartRPS', [
    { data: S.rpsHist, color: '#00e87b', label: 'RPS' }
  ]);
  drawTimelineChart('chartLatency', [
    { data: S.latP50Hist, color: '#00e87b', label: 'P50' },
    { data: S.latP95Hist, color: '#f59e0b', label: 'P95' },
    { data: S.latP99Hist, color: '#ef4444', label: 'P99' }
  ]);
  drawMiniLine('chartP50', S.latP50Hist, '#00e87b');
  drawMiniLine('chartP95', S.latP95Hist, '#f59e0b');
  drawMiniLine('chartP99', S.latP99Hist, '#ef4444');

  syncOnboarding();
}

/* ==========================================================================
   STATUS CODES (DOM-built — CSP-safe, no style="" attributes)
   ========================================================================== */
function emptyNote(text) {
  var d = document.createElement('div');
  d.className = 'empty-note';
  d.textContent = text;
  return d;
}
function renderStatusCodes(codes) {
  var el = document.getElementById('statusBars');
  if (!el) return;
  var keys = Object.keys(codes).sort();
  el.textContent = '';
  if (keys.length === 0) {
    el.appendChild(emptyNote('No data yet'));
    return;
  }
  var total = 0, k;
  for (var i = 0; i < keys.length; i++) { total += codes[keys[i]]; }
  keys.forEach(function(kStr) {
    var kn = parseInt(kStr, 10);
    var v = codes[kStr];
    var pct = total > 0 ? (v / total * 100) : 0;
    var cls = kn < 300 ? 'c2xx' : kn < 400 ? 'c3xx' : kn < 500 ? 'c4xx' : 'c5xx';
    var row = document.createElement('div'); row.className = 'status-row';
    var code = document.createElement('span');
    code.className = 'status-code ' + cls;
    code.textContent = kStr;
    var bg = document.createElement('div'); bg.className = 'status-bar-bg';
    var bar = document.createElement('div');
    bar.className = 'status-bar ' + cls;
    bar.style.width = pct + '%';
    bg.appendChild(bar);
    var cnt = document.createElement('span');
    cnt.className = 'status-count';
    cnt.textContent = fmt(v) + ' (' + pct.toFixed(1) + '%)';
    row.appendChild(code); row.appendChild(bg); row.appendChild(cnt);
    el.appendChild(row);
  });
}

/* ==========================================================================
   WORKERS (DOM-built, textContent-escaped)
   ========================================================================== */
function renderWorkers(workers) {
  var section = document.getElementById('workersSection');
  if (!section) return;
  if (!workers || workers.length === 0) {
    section.classList.add('hidden');
    return;
  }
  section.classList.remove('hidden');
  var body = document.getElementById('workersBody');
  if (!body) return;
  body.textContent = '';
  workers.forEach(function(w) {
    var isActive = w.status === 'running' || w.status === 'active';
    var tr = document.createElement('tr');
    var tdId = document.createElement('td');
    var strong = document.createElement('strong');
    strong.textContent = w.id;
    tdId.appendChild(strong);
    var tdAddr = document.createElement('td');
    tdAddr.className = 't-dim';
    tdAddr.textContent = w.address;
    var tdStatus = document.createElement('td');
    var span = document.createElement('span'); span.className = 'worker-status';
    var dot = document.createElement('span');
    dot.className = 'worker-dot ' + (isActive ? 'active' : 'idle');
    var st = document.createTextNode(String(w.status));
    span.appendChild(dot); span.appendChild(st);
    tdStatus.appendChild(span);
    var tdRps = document.createElement('td'); tdRps.textContent = (w.rps || 0).toFixed(0);
    var tdLat = document.createElement('td'); tdLat.textContent = (w.latency_ms || 0).toFixed(1) + ' ms';
    var tdErr = document.createElement('td'); tdErr.textContent = fmt(w.errors || 0);
    tr.appendChild(tdId); tr.appendChild(tdAddr); tr.appendChild(tdStatus);
    tr.appendChild(tdRps); tr.appendChild(tdLat); tr.appendChild(tdErr);
    body.appendChild(tr);
  });
}

/* ==========================================================================
   HISTORY (DOM-built, all values textContent-escaped)
   ========================================================================== */
function renderHistory() {
  var section = document.getElementById('historySection');
  if (!section) return;
  if (!S.history || S.history.length === 0) {
    section.classList.add('hidden');
    return;
  }
  section.classList.remove('hidden');
  var body = document.getElementById('historyBody');
  if (!body) return;
  body.textContent = '';

  S.history.forEach(function(h) {
    var cfg = h.config || {};
    var res = h.result || {};
    var tr = document.createElement('tr');

    var tdId = document.createElement('td'); tdId.className = 't-dim'; tdId.textContent = h.id;
    var tdTime = document.createElement('td');
    try { tdTime.textContent = new Date(h.timestamp).toLocaleTimeString(); } catch (e) { tdTime.textContent = '-'; }
    var tdUrl = document.createElement('td'); tdUrl.textContent = cfg.target_url || '-';
    var tdUsers = document.createElement('td'); tdUsers.textContent = cfg.users || '-';
    var tdDur = document.createElement('td'); tdDur.textContent = (cfg.duration_seconds || '-') + 's';
    var tdRps = document.createElement('td'); tdRps.className = 't-green'; tdRps.textContent = (res.rps || 0).toFixed(0);
    var tdP50 = document.createElement('td'); tdP50.textContent = (res.p50_latency || 0).toFixed(1) + 'ms';
    var tdP99 = document.createElement('td'); tdP99.textContent = (res.p99_latency || 0).toFixed(1) + 'ms';
    var tdErr = document.createElement('td'); tdErr.className = 't-red'; tdErr.textContent = String(res.total_errors || 0);

    tr.appendChild(tdId); tr.appendChild(tdTime); tr.appendChild(tdUrl); tr.appendChild(tdUsers);
    tr.appendChild(tdDur); tr.appendChild(tdRps); tr.appendChild(tdP50); tr.appendChild(tdP99); tr.appendChild(tdErr);
    body.appendChild(tr);
  });
}

/* ==========================================================================
   CANVAS CHARTS
   ========================================================================== */
function drawSparkline(id, data, color) {
  var canvas = document.getElementById(id);
  if (!canvas) return;
  var dpr = window.devicePixelRatio || 1;
  var rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  var ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  var w = rect.width, h = rect.height;
  ctx.clearRect(0, 0, w, h);
  if (!data || data.length < 2) return;
  var max = Math.max.apply(null, data.concat([1]));
  var step = w / (MAX_HIST - 1);
  var startIdx = MAX_HIST - data.length;
  ctx.beginPath();
  ctx.moveTo(0, h);
  for (var i = 0; i < data.length; i++) {
    var x = (startIdx + i) * step;
    var y = h - (data[i] / max) * (h - 4);
    ctx.lineTo(x, y);
  }
  ctx.lineTo((startIdx + data.length - 1) * step, h);
  ctx.closePath();
  var grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, color);
  grad.addColorStop(1, 'transparent');
  ctx.fillStyle = grad;
  ctx.fill();
  // Line on top
  ctx.beginPath();
  for (var i = 0; i < data.length; i++) {
    var x = (startIdx + i) * step;
    var y = h - (data[i] / max) * (h - 4);
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  }
  ctx.strokeStyle = color.replace('0.6', '1');
  ctx.lineWidth = 1.5;
  ctx.stroke();
}

function drawTimelineChart(id, series) {
  var canvas = document.getElementById(id);
  if (!canvas) return;
  var dpr = window.devicePixelRatio || 1;
  var rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  var ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  var w = rect.width, h = rect.height;
  var pad = { top: 10, right: 10, bottom: 24, left: 50 };
  var cw = w - pad.left - pad.right;
  var ch = h - pad.top - pad.bottom;
  ctx.clearRect(0, 0, w, h);

  // Find max across all series
  var allMax = 1;
  series.forEach(function(s) {
    var m = Math.max.apply(null, s.data.concat([1]));
    if (m > allMax) allMax = m;
  });

  // Grid lines
  ctx.strokeStyle = '#1e1e30';
  ctx.lineWidth = 1;
  for (var i = 0; i <= 4; i++) {
    var y = pad.top + (ch / 4) * i;
    ctx.beginPath(); ctx.moveTo(pad.left, y); ctx.lineTo(w - pad.right, y); ctx.stroke();
    ctx.fillStyle = '#8585a0'; /* audit: #484860 = 2.2:1 -> 5.2:1 (WCAG AA) */
    ctx.font = '10px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
    ctx.textAlign = 'right';
    ctx.fillText(fmtSmart(allMax * (1 - i / 4)), pad.left - 8, y + 4);
  }

  // Time labels
  ctx.fillStyle = '#8585a0'; /* audit: axis time labels, 2.2:1 -> 5.2:1 */
  ctx.textAlign = 'center';
  ctx.font = '10px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
  var maxLen = 0;
  series.forEach(function(s) { if (s.data.length > maxLen) maxLen = s.data.length; });
  if (maxLen > 1) {
    for (var i = 0; i <= 4; i++) {
      var idx = Math.floor((maxLen - 1) * i / 4);
      var x = pad.left + (cw * i / 4);
      ctx.fillText('-' + (maxLen - 1 - idx) + 's', x, h - 6);
    }
  }

  // Draw each series
  series.forEach(function(s) {
    if (s.data.length < 2) return;
    var step = cw / (MAX_HIST - 1);
    var startIdx = MAX_HIST - s.data.length;
    // Fill
    ctx.beginPath();
    ctx.moveTo(pad.left + startIdx * step, pad.top + ch);
    for (var i = 0; i < s.data.length; i++) {
      var x = pad.left + (startIdx + i) * step;
      var y = pad.top + ch - (s.data[i] / allMax) * ch;
      ctx.lineTo(x, y);
    }
    ctx.lineTo(pad.left + (startIdx + s.data.length - 1) * step, pad.top + ch);
    ctx.closePath();
    var grad = ctx.createLinearGradient(0, pad.top, 0, pad.top + ch);
    grad.addColorStop(0, s.color + '33');
    grad.addColorStop(1, 'transparent');
    ctx.fillStyle = grad;
    ctx.fill();
    // Line
    ctx.beginPath();
    for (var i = 0; i < s.data.length; i++) {
      var x = pad.left + (startIdx + i) * step;
      var y = pad.top + ch - (s.data[i] / allMax) * ch;
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    }
    ctx.strokeStyle = s.color;
    ctx.lineWidth = 2;
    ctx.stroke();
    // End dot
    if (s.data.length > 0) {
      var lastI = s.data.length - 1;
      var lx = pad.left + (startIdx + lastI) * step;
      var ly = pad.top + ch - (s.data[lastI] / allMax) * ch;
      ctx.beginPath();
      ctx.arc(lx, ly, 4, 0, Math.PI * 2);
      ctx.fillStyle = s.color;
      ctx.fill();
      ctx.beginPath();
      ctx.arc(lx, ly, 7, 0, Math.PI * 2);
      ctx.strokeStyle = s.color + '44';
      ctx.lineWidth = 2;
      ctx.stroke();
    }
  });

  // Legend
  if (series.length > 1) {
    var lx = pad.left;
    series.forEach(function(s, i) {
      ctx.fillStyle = s.color;
      ctx.fillRect(lx, 2, 8, 8);
      ctx.fillStyle = '#9494ad'; /* audit: legend text, 4.1:1 -> 6.6:1 */
      ctx.font = '10px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
      ctx.textAlign = 'left';
      ctx.fillText(s.label, lx + 12, 10);
      lx += ctx.measureText(s.label).width + 24;
    });
  }
}

function drawMiniLine(id, data, color) {
  var canvas = document.getElementById(id);
  if (!canvas) return;
  var dpr = window.devicePixelRatio || 1;
  var rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * dpr;
  canvas.height = rect.height * dpr;
  var ctx = canvas.getContext('2d');
  ctx.scale(dpr, dpr);
  var w = rect.width, h = rect.height;
  ctx.clearRect(0, 0, w, h);
  if (!data || data.length < 2) return;
  var max = Math.max.apply(null, data.concat([1]));
  var step = w / (MAX_HIST - 1);
  var startIdx = MAX_HIST - data.length;
  ctx.beginPath();
  for (var i = 0; i < data.length; i++) {
    var x = (startIdx + i) * step;
    var y = h - (data[i] / max) * (h - 4);
    if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
  }
  ctx.strokeStyle = color;
  ctx.lineWidth = 2;
  ctx.stroke();
}

/* ==========================================================================
   HELPERS
   ========================================================================== */
function formatDuration(sec) {
  sec = Math.round(sec || 0);
  if (sec < 60) return sec + 's';
  var m = Math.floor(sec / 60);
  var s = sec % 60;
  return m + 'm ' + s + 's';
}
function fmt(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
  return String(n);
}
function fmtSmart(n) {
  if (n >= 1e6) return (n / 1e6).toFixed(0) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(0) + 'K';
  return String(Math.round(n));
}
function fmtMs(v) { return (v || 0).toFixed(1) + ' ms'; }
function esc(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function updateConnStatus() {
  var dot = document.getElementById('connDot');
  var label = document.getElementById('connLabel');
  if (!dot || !label) return;
  if (S.connected) {
    dot.className = 'conn-dot connected';
    label.textContent = '';
    label.appendChild(dot);
    label.appendChild(document.createTextNode(' Connected'));
    label.style.color = 'var(--green)';
  } else {
    dot.className = 'conn-dot disconnected';
    label.textContent = '';
    label.appendChild(dot);
    label.appendChild(document.createTextNode(' Disconnected'));
    label.style.color = 'var(--red)';
  }
}

/* ==========================================================================
   POLLING FALLBACK (for when the WebSocket is down)
   ========================================================================== */
setInterval(function() {
  if (!S.connected && S.run && S.run.status === 'running') {
    fetch(API + '/api/snapshot').then(function(r) { return r.json(); }).then(function(d) {
      S.snapshot = d;
      pushHist('rpsHist', d.rps || 0);
      pushHist('latAvgHist', d.avg_latency_ms || 0);
      pushHist('latP50Hist', d.p50_latency_ms || 0);
      pushHist('latP95Hist', d.p95_latency_ms || 0);
      pushHist('latP99Hist', d.p99_latency_ms || 0);
      pushHist('errHist', d.error_rate || 0);
      pushHist('userHist', d.active_users || 0);
      render();
    }).catch(function() {});
  }
}, 1000);

/* ==========================================================================
   KEYBOARD SHORTCUTS
   S -> start, E/X -> stop (two-step confirm), Esc -> cancel confirm.
   Ignored while typing in inputs/selects or when a modifier is held.
   ========================================================================== */
document.addEventListener('keydown', function(e) {
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.repeat || e.defaultPrevented) return;
  var t = e.target;
  if (t && (t.tagName === 'INPUT' || t.tagName === 'SELECT' || t.tagName === 'TEXTAREA' || t.isContentEditable)) return;
  var k = (e.key || '').toLowerCase();
  if (k === 's') { e.preventDefault(); startRun(); }
  else if (k === 'e' || k === 'x') { e.preventDefault(); requestStop(); }
  else if (k === 'escape') { disarmStop(); }
});

/* ==========================================================================
   INIT
   ========================================================================== */
restoreLastConfig();
connect();
render();

/* ---- Controls wired via addEventListener (strict CSP: no inline handlers) ---- */
var _cf = document.getElementById('controlsForm');
if (_cf) _cf.addEventListener('submit', function(e) { e.preventDefault(); startRun(); });
var _btnStart = document.getElementById('btnStart');
if (_btnStart) _btnStart.addEventListener('click', startRun);
var _btnStop = document.getElementById('btnStop');
if (_btnStop) _btnStop.addEventListener('click', requestStop);
var _inpUrl = document.getElementById('inpUrl');
if (_inpUrl) _inpUrl.addEventListener('input', function() { setUrlError(''); });

/* ---- Onboarding ---- */
var _obForm = document.getElementById('onboardingForm');
if (_obForm) _obForm.addEventListener('submit', obSubmit);
var _obClose = document.getElementById('onboardingClose');
if (_obClose) _obClose.addEventListener('click', dismissOnboarding);
var _obDemo = document.getElementById('btnLoadDemo');
if (_obDemo) _obDemo.addEventListener('click', loadDemoUrl);

/* ---- Summary ---- */
var _sumClose = document.getElementById('summaryClose');
if (_sumClose) _sumClose.addEventListener('click', hideSummary);
var _viewReport = document.getElementById('btnViewReport');
if (_viewReport) _viewReport.addEventListener('click', viewReport);
var _runAgain = document.getElementById('btnRunAgain');
if (_runAgain) _runAgain.addEventListener('click', startRun);

/* ---- Sliders ---- */
bindSlider('inpUsers', 'rngUsers', 'hintUsers', fmtUsersHint);
bindSlider('inpDuration', 'rngDuration', 'hintDuration', fmtDurationHint);
updateFieldHints();