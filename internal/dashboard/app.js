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
  summaryVisible: false,
  locked: false,        // control API rejected auth (401/403) — lock overlay shown
  everOpened: false     // WS handshake succeeded at least once in this attempt
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
  S.everOpened = false;
  ws.onopen = function() {
    S.connected = true;
    S.everOpened = true;
    if (S.locked) closeLocked();
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
      pushHist('latP95Hist', d.p99_latency_ms || 0);
      pushHist('latP99Hist', d.p99_latency_ms || 0);
      pushHist('errHist', d.error_rate || 0);
      pushHist('userHist', d.active_users || 0);
      try { render(); } catch (e) { logRenderError(e); }
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
      if (st === 'completed' || st === 'stopped') {
        fetchAttestation();
      }
    }
    try { render(); } catch (e) { logRenderError(e); }
  };
  ws.onclose = function() {
    S.connected = false;
    updateConnStatus();
    if (S.locked) return;                        // already locked — no retry
    if (!S.everOpened) { probeAuth(); return; }  // handshake never opened — could be auth
    scheduleReconnect();
  };
  ws.onerror = function(e) {
    updateConnStatus();
    toast('WebSocket error — reconnecting…', 'error');
  };
}

function scheduleReconnect() {
  if (S.locked) return;
  if (wsRetryTimer) return;
  wsRetryTimer = setTimeout(function() { wsRetryTimer = null; connect(); }, 2000);
}

/* Control-API auth: the server may require a bearer token / API key
   (-auth-token / -auth-api-key). The browser cannot read the WebSocket
   handshake status code, so after a handshake that never opened we probe a
   protected HTTP endpoint: 401/403 means "locked" — stop retrying and show a
   clear state instead of an infinite "Connecting..." loop. Anything else is a
   plain connectivity issue and keeps the normal retry path. */
var authProbeTimer = null;

function probeAuth() {
  if (S.locked) return;
  if (authProbeTimer) return;                    // one probe at a time
  authProbeTimer = setTimeout(function() {
    authProbeTimer = null;
    fetch(API + '/api/history')
      .then(function(r) {
        if (guardStatus(r)) return;              // 401/403 -> lock
        scheduleReconnect();
      })
      .catch(function() { scheduleReconnect(); }); // network error -> normal retry
  }, 250);
}

function guardStatus(r) {
  if (r && (r.status === 401 || r.status === 403)) { setLocked(); return true; }
  return false;
}

function setLocked() {
  if (S.locked) return;
  S.locked = true;
  S.connected = false;
  if (wsRetryTimer) { clearTimeout(wsRetryTimer); wsRetryTimer = null; }
  if (authProbeTimer) { clearTimeout(authProbeTimer); authProbeTimer = null; }
  if (ws) {
    try { ws.onclose = null; ws.close(); } catch (e) {}
    ws = null;
  }
  updateConnStatus();
  var ov = document.getElementById('lockOverlay');
  if (ov) {
    ov.classList.remove('hidden');
    var app = document.getElementById('app');
    if (app) app.setAttribute('aria-hidden', 'true');
    var first = ov.querySelector('button');
    if (first) first.focus();
  }
  toast('Access locked — authentication required', 'error');
}

function closeLocked() {
  S.locked = false;
  var ov = document.getElementById('lockOverlay');
  if (ov && !ov.classList.contains('hidden')) ov.classList.add('hidden');
  var app = document.getElementById('app');
  if (app) app.removeAttribute('aria-hidden');
}

// Re-fetch run history after a run finishes. The server only sends history in
// the WS "init" message, so a completed run would otherwise stay invisible in
// the table until the page is reloaded.
function refreshHistory() {
  fetch(API + '/api/history').then(function(r) {
    if (guardStatus(r)) return null;
    return r.json();
  }).then(function(h) {
    if (S.locked) return;
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
  if (S.locked) return;
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
    if (guardStatus(r)) throw new Error('authentication required');
    if (!r.ok) throw new Error('server returned ' + r.status);
    return r.json();
  }).then(function() {
    toast('Run started!', 'info');
    saveLastConfig(cfg);
    dismissOnboarding(); // first run started -> guide hides automatically
    hideSummary();
  }).catch(function(err) {
    // guardStatus already raised the lock overlay; don't double-toast.
    if (!S.locked) {
      toast('Failed to start run' + (err && err.message ? ': ' + err.message : ''), 'error');
    }
  }).then(function() {
    // Runs in both success and error paths (ES5-friendly "finally").
    S.starting = false;
    updateStartButton();
  });
}

function stopRun() {
  fetch(API + '/api/run/stop', { method: 'POST' }).then(function(r) {
    if (guardStatus(r)) throw new Error('authentication required');
    if (!r.ok) throw new Error('server returned ' + r.status);
    return r.json();
  }).then(function() { toast('Run stopped', 'error'); })
    .catch(function() { if (!S.locked) toast('Failed to stop run', 'error'); });
}

/* Two-step stop: first press arms the button, a second press (within 3s)
   actually stops the run. Escape or the run finishing disarms it. */
function requestStop() {
  if (S.locked) return;
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
function logRenderError(e) {
  try { console.error('[stress-strike] render error:', e); } catch (_) {}
}
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
  var btnStop = document.getElementById('btnStop');
  if (btnStop) btnStop.disabled = !running;
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
    var inpUrl = document.getElementById('inpUrl');
    if (inpUrl && document.activeElement.id !== 'inpUrl') inpUrl.value = r.config.target_url || '';
    var inpUsers = document.getElementById('inpUsers');
    if (inpUsers && document.activeElement.id !== 'inpUsers' && document.activeElement.id !== 'rngUsers') inpUsers.value = r.config.users || 10;
    var inpDuration = document.getElementById('inpDuration');
    if (inpDuration && document.activeElement.id !== 'inpDuration' && document.activeElement.id !== 'rngDuration') inpDuration.value = r.config.duration_seconds || 30;
    var inpMethod = document.getElementById('inpMethod');
    if (inpMethod && document.activeElement.id !== 'inpMethod') inpMethod.value = r.config.method || 'GET';
    var inpRate = document.getElementById('inpRate');
    if (inpRate && document.activeElement.id !== 'inpRate') inpRate.value = r.config.rate_limit || 0;
    var inpProfile = document.getElementById('inpProfile');
    if (inpProfile && document.activeElement.id !== 'inpProfile' && r.config.profile) inpProfile.value = r.config.profile;
    var inpFingerprint = document.getElementById('inpFingerprint');
    if (inpFingerprint && document.activeElement.id !== 'inpFingerprint' && r.config.tls_fingerprint) inpFingerprint.value = r.config.tls_fingerprint;
  }
  updateFieldHints();

  // Config meta + live latency strip
  var metaProfile = document.getElementById('metaProfile');
  if (metaProfile) metaProfile.textContent = (r.config && r.config.profile) || '\u2014';
  var metaRate = document.getElementById('metaRate');
  if (metaRate) metaRate.textContent = (r.config && r.config.rate_limit) ? r.config.rate_limit + ' req/s' : '\u2014';
  var metaFingerprint = document.getElementById('metaFingerprint');
  if (metaFingerprint) metaFingerprint.textContent = (r.config && r.config.tls_fingerprint) || '\u2014';
  var metaP50 = document.getElementById('metaP50');
  if (metaP50) metaP50.textContent = (s.p50_latency_ms || 0).toFixed(1) + ' ms';
  var metaP95 = document.getElementById('metaP95');
  if (metaP95) metaP95.textContent = (s.p95_latency_ms || 0).toFixed(1) + ' ms';
  var metaP99 = document.getElementById('metaP99');
  if (metaP99) metaP99.textContent = (s.p99_latency_ms || 0).toFixed(1) + ' ms';
  var metaAvg = document.getElementById('metaAvg');
  if (metaAvg) metaAvg.textContent = (s.avg_latency_ms || 0).toFixed(1) + ' ms';
  var metaMax = document.getElementById('metaMax');
  if (metaMax) metaMax.textContent = (s.max_latency_ms || 0).toFixed(1) + ' ms';

  // Metric cards
  var rps = s.rps || 0;
  var valRPS = document.getElementById('valRPS');
  if (valRPS) valRPS.textContent = Math.round(rps);
  var subRPS = document.getElementById('subRPS');
  if (subRPS) subRPS.textContent = fmt(s.total_requests || 0) + ' total requests';

  var avg = s.avg_latency_ms || 0;
  var valAvg = document.getElementById('valAvg');
  if (valAvg) valAvg.textContent = avg.toFixed(1) + ' ms';
  var subLatency = document.getElementById('subLatency');
  if (subLatency) subLatency.textContent =
    'P50: ' + (s.p50_latency_ms || 0).toFixed(1) + ' \u00b7 P95: ' + (s.p95_latency_ms || 0).toFixed(1) + ' \u00b7 P99: ' + (s.p99_latency_ms || 0).toFixed(1) + ' ms';

  var errRate = s.error_rate || 0;
  var errEl = document.getElementById('valErrors');
  if (errEl) {
    errEl.style.color = errRate > 5 ? 'var(--red)' : errRate > 1 ? 'var(--yellow)' : 'var(--green)';
    errEl.textContent = errRate.toFixed(2) + ' %';
  }
  var subErrors = document.getElementById('subErrors');
  if (subErrors) subErrors.textContent = fmt(s.total_errors || 0) + ' errors / ' + fmt(s.total_requests || 0) + ' total';

  var valUsers = document.getElementById('valUsers');
  if (valUsers) valUsers.textContent = s.active_users || 0;

  // Latency detail cards
  var latP50 = document.getElementById('latP50');
  if (latP50) latP50.textContent = (s.p50_latency_ms || 0).toFixed(1);
  var latP95 = document.getElementById('latP95');
  if (latP95) latP95.textContent = (s.p95_latency_ms || 0).toFixed(1);
  var latP99 = document.getElementById('latP99');
  if (latP99) latP99.textContent = (s.p99_latency_ms || 0).toFixed(1);

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
  if (S.locked) {
    dot.className = 'conn-dot locked';
    label.textContent = '';
    label.appendChild(dot);
    label.appendChild(document.createTextNode(' Access locked'));
    label.style.color = 'var(--yellow)';
    return;
  }
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
  if (S.locked) return;
  if (!S.connected && S.run && S.run.status === 'running') {
    fetch(API + '/api/snapshot').then(function(r) {
      if (guardStatus(r)) return null;
      return r.json();
    }).then(function(d) {
      if (!d || S.locked) return;
      S.snapshot = d;
      pushHist('rpsHist', d.rps || 0);
      pushHist('latAvgHist', d.avg_latency_ms || 0);
      pushHist('latP50Hist', d.p50_latency_ms || 0);
      pushHist('latP95Hist', d.p95_latency_ms || 0);
      pushHist('latP99Hist', d.p99_latency_ms || 0);
      pushHist('errHist', d.error_rate || 0);
      pushHist('userHist', d.active_users || 0);
      try { render(); } catch (e) { logRenderError(e); }
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
try { render(); } catch (e) { logRenderError(e); }
refreshDemoStore();

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

/* ---- Demo store launcher (bundled VoltStore + VeriGate) ---- */
var _btnDemoStore = document.getElementById('btnDemoStore');
var _btnDemoLabel = document.getElementById('btnDemoLabel');

function refreshDemoStore() {
  if (!_btnDemoStore) return;
  fetch(API + '/api/demo-store/status').then(function(r) {
    if (guardStatus(r)) return null;
    return r.json();
  }).then(function(d) {
    if (!d || S.locked) return;
    if (d && d.running) {
      _btnDemoLabel.textContent = 'Open Demo Store';
      _btnDemoStore.classList.add('demo-running');
      _btnDemoStore.title = 'VoltStore demo is running — open it in a new tab.';
    } else {
      _btnDemoLabel.textContent = 'Launch Demo Store';
      _btnDemoStore.classList.remove('demo-running');
      _btnDemoStore.title = 'Launch the bundled VoltStore demo (VeriGate protection ON) and open it in a new tab.';
    }
  }).catch(function() {});
}

function demoStoreClick() {
  if (!_btnDemoStore) return;
  _btnDemoStore.classList.add('loading');
  // Open the tab synchronously inside the user gesture so popup blockers
  // allow it; it is pointed at the store URL once the launcher confirms
  // the store is up (Start only returns when the store accepts requests).
  var win = null;
  try { win = window.open('', '_blank'); } catch (e) { win = null; }
  fetch(API + '/api/demo-store/start', { method: 'POST' })
    .then(function(r) {
      return r.json().then(function(d) { return { status: r.status, data: d }; });
    })
    .then(function(res) {
      _btnDemoStore.classList.remove('loading');
      if (guardStatus({ status: res.status })) {
        if (win) { try { win.close(); } catch (e) {} }
        return;
      }
      if (res.status !== 200 || !res.data.ok) {
        toast('Demo store: ' + ((res.data && res.data.error) || 'failed to start'), 'error');
        if (win) { try { win.close(); } catch (e) {} }
        return;
      }
      toast('VoltStore demo ' + (res.data.already_running ? 'already running — ' : 'launched — ') + res.data.url, 'success');
      if (win) {
        win.location = res.data.url;
      } else {
        var fallback = window.open(res.data.url, '_blank', 'noopener');
        if (!fallback) toast('Popup blocked — open ' + res.data.url + ' manually', 'info');
      }
      refreshDemoStore();
    })
    .catch(function() {
      _btnDemoStore.classList.remove('loading');
      toast('Demo store: request failed', 'error');
      if (win) { try { win.close(); } catch (e) {} }
    });
}

if (_btnDemoStore) _btnDemoStore.addEventListener('click', demoStoreClick);

/* ---- OWASP Top 10 security scan ---- */
var _owaspForm     = document.getElementById('owaspForm');
var _owaspBtn      = document.getElementById('btnOwaspRun');
var _owaspStatus   = document.getElementById('owaspStatus');
var _owaspResults  = document.getElementById('owaspResults');
var _owaspBody     = document.getElementById('owaspBody');
var _owaspMeta     = document.getElementById('owaspMeta');
var _owaspFindWrap = document.getElementById('owaspFindingsWrap');
var _owaspFindings = document.getElementById('owaspFindings');
/* Structural sibling of the list, never recreated - see owaspRender(). */
var _owaspSubtitle = document.querySelector('#owaspFindingsWrap > .owasp-subtitle');
var _owaspGate     = document.getElementById('owaspGate');
var _owaspNotes    = document.getElementById('owaspNotes');

function owaspClear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }

function owaspSplitList(v) {
  return String(v || '').split(',').map(function(s) { return s.trim(); }).filter(Boolean);
}

function owaspStatusSet(msg, cls) {
  if (!_owaspStatus) return;
  _owaspStatus.textContent = msg || '';
  _owaspStatus.className = 'owasp-status' + (cls ? ' ' + cls : '');
}

function owaspStatusClass(st) {
  if (st === 'PASS') return 'ok';
  if (st === 'FAIL') return 'bad';
  if (st === 'WARNING') return 'warn';
  return 'skip'; /* NOT TESTED is not a pass */
}

function owaspAddRow(cat) {
  var tr = document.createElement('tr');

  var tdId = document.createElement('td');
  tdId.className = 'owasp-id';
  tdId.textContent = cat.id || '';

  var tdName = document.createElement('td');
  tdName.textContent = cat.name || '';

  var tdStatus = document.createElement('td');
  var badge = document.createElement('span');
  badge.className = 'owasp-badge owasp-badge--' + owaspStatusClass(cat.status);
  badge.textContent = String(cat.status || '');
  tdStatus.appendChild(badge);

  var tdSeen = document.createElement('td');
  var seen = cat.findings || [];
  if (seen.length) {
    var ul = document.createElement('ul');
    ul.className = 'owasp-cell-list';
    seen.slice(0, 4).forEach(function(f) {
      var li = document.createElement('li');
      li.textContent = f;
      ul.appendChild(li);
    });
    if (seen.length > 4) {
      var more = document.createElement('li');
      more.className = 'owasp-more';
      more.textContent = '+' + (seen.length - 4) + ' more';
      ul.appendChild(more);
    }
    tdSeen.appendChild(ul);
  } else {
    tdSeen.textContent = '\u2014';
  }

  tr.appendChild(tdId);
  tr.appendChild(tdName);
  tr.appendChild(tdStatus);
  tr.appendChild(tdSeen);
  _owaspBody.appendChild(tr);
}

/* Evidence and titles come from the target server, so everything is written
   with textContent — never innerHTML. */
function owaspAddFinding(f) {
  var li = document.createElement('li');
  li.className = 'owasp-finding owasp-finding--' + String(f.severity || 'info').toLowerCase();

  var head = document.createElement('div');
  head.className = 'owasp-finding-head';
  head.textContent = [f.id, f.severity, f.parameter ? 'param ' + f.parameter : '']
    .filter(Boolean).join(' \u00b7 ');

  var title = document.createElement('div');
  title.className = 'owasp-finding-title';
  title.textContent = f.title || '';

  var body = document.createElement('div');
  body.className = 'owasp-finding-body';
  body.textContent = (f.confidence ? 'confidence: ' + f.confidence + ' \u2014 ' : '') +
    (f.evidence || '') + (f.cwe ? ' [' + f.cwe + ']' : '');

  li.appendChild(head);
  li.appendChild(title);
  li.appendChild(body);
  _owaspFindings.appendChild(li);
}

function owaspChip(text) {
  var s = document.createElement('span');
  s.className = 'owasp-chip';
  s.textContent = text;
  _owaspMeta.appendChild(s);
}

function owaspRender(d) {
  owaspStatusSet('Scan complete.', 'ok');
  _owaspResults.classList.remove('hidden');

  owaspClear(_owaspBody);
  (d.categories || []).forEach(owaspAddRow);

  owaspClear(_owaspMeta);
  owaspChip('Target: ' + d.target);
  owaspChip('Scope: ' + (d.scope || []).join(', '));
  owaspChip('Score: ' + d.score + '/100 (grade ' + (d.grade || '\u2014') + ')');
  owaspChip('Covered ' + d.tested + ' of ' + d.total + ' categories');

  var g = d.gate || {};
  owaspChip('Requests sent: ' + (g.requests_sent || 0));

  /* The wrap owns two structural children - the subtitle and #owaspFindings -
     so it is never cleared. Clearing it detaches the list that owaspAddFinding
     appends to, and every finding afterwards is written into an orphaned node:
     the panel then shows a heading and no findings, on the first scan and on
     every scan after it. Only the list is cleared; the subtitle is updated in
     place. */
  var fs = d.findings || [];
  if (fs.length) {
    _owaspFindWrap.classList.remove('hidden');
    _owaspSubtitle.textContent = 'Findings (' + fs.length + ')';
  } else {
    _owaspFindWrap.classList.add('hidden');
    _owaspSubtitle.textContent = 'Findings';
  }
  owaspClear(_owaspFindings);
  fs.forEach(owaspAddFinding);

  _owaspGate.textContent = 'Gate: ' + (g.requests_sent || 0) + ' sent \u00b7 ' +
    (g.requests_refused || 0) + ' refused (out-of-scope ' + (g.refused_out_of_scope || 0) +
    ', intrusive off ' + (g.refused_intrusive || 0) +
    ', budget ' + (g.refused_budget || 0) +
    ', rate ' + (g.refused_rate || 0) +
    ', dry-run ' + (g.refused_dry_run || 0) + ')';

  owaspClear(_owaspNotes);
  (d.notes || []).forEach(function(n) {
    var li = document.createElement('li');
    li.textContent = n;
    _owaspNotes.appendChild(li);
  });

  toast('OWASP scan finished \u2014 ' + d.tested + '/' + d.total + ' categories covered', 'ok');
}

function owaspRun(ev) {
  if (ev) ev.preventDefault();
  if (!_owaspForm || _owaspBtn.classList.contains('loading')) return;

  var target = document.getElementById('owaspTarget').value.trim();
  if (!target) {
    owaspStatusSet('Enter a target URL first.', 'err');
    return;
  }

  var payload = {
    target: target,
    paths: owaspSplitList(document.getElementById('owaspPaths').value),
    passive: document.getElementById('owaspPassive').checked,
    intrusive: document.getElementById('owaspIntrusive').checked,
    dryRun: document.getElementById('owaspDryRun').checked
  };

  _owaspBtn.classList.add('loading');
  _owaspResults.classList.add('hidden');
  owaspStatusSet('Scanning ' + target + ' \u2014 every probe passes the scope gate.', '');

  fetch(API + '/api/owasp/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }).then(function(r) {
    /* A 401 is a session problem. A 403 here is the authorization policy
       refusing this target, which is an answer, not a lockout. */
    if (r.status === 401) { setLocked(); throw new Error('locked'); }
    return r.json().then(function(d) { return { r: r, d: d }; });
  }).then(function(x) {
    if (!x) return;
    if (!x.r.ok) {
      var msg = (x.d && (x.d.reason || x.d.error)) || ('HTTP ' + x.r.status);
      owaspStatusSet(msg, x.d && x.d.denied ? 'warn' : 'err');
      toast('OWASP scan refused: ' + msg, 'error');
      return;
    }
    owaspRender(x.d);
  }).catch(function(e) {
    if (String(e) === 'Error: locked') return;
    owaspStatusSet('Scan failed: ' + e, 'err');
    toast('OWASP scan failed', 'error');
  }).then(function() {
    _owaspBtn.classList.remove('loading');
  });
}

if (_owaspForm) _owaspForm.addEventListener('submit', owaspRun);

/* ---- Pentest (offensive security scan) ---- */
var _pentestForm     = document.getElementById('pentestForm');
var _pentestBtn      = document.getElementById('btnPentestRun');
var _pentestStatus   = document.getElementById('pentestStatus');
var _pentestResults  = document.getElementById('pentestResults');
var _pentestBody     = document.getElementById('pentestBody');
var _pentestMeta     = document.getElementById('pentestMeta');
var _pentestVulnWrap = document.getElementById('pentestVulnsWrap');
var _pentestSubtitle = document.querySelector('#pentestVulnsWrap > .pentest-subtitle');
var _pentestVulns    = document.getElementById('pentestVulns');
var _pentestGate     = document.getElementById('pentestGate');
var _pentestCert     = document.getElementById('pentestCert');
var _pentestNotes    = document.getElementById('pentestNotes');

function pentestClear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }

function pentestSplitList(v) {
  return String(v || '').split(',').map(function(s) { return s.trim(); }).filter(Boolean);
}

function pentestStatusSet(msg, cls) {
  if (!_pentestStatus) return;
  _pentestStatus.textContent = msg || '';
  _pentestStatus.className = 'pentest-status' + (cls ? ' ' + cls : '');
}

function pentestStatusClass(st) {
  if (st === 'PASS') return 'ok';
  if (st === 'FAIL') return 'bad';
  if (st === 'WARNING') return 'warn';
  return 'skip'; /* NOT TESTED is not a pass */
}

function pentestAddRow(cat) {
  var tr = document.createElement('tr');

  var tdId = document.createElement('td');
  tdId.className = 'pentest-id';
  tdId.textContent = cat.id || '';

  var tdName = document.createElement('td');
  tdName.textContent = cat.name || '';

  var tdStatus = document.createElement('td');
  var badge = document.createElement('span');
  badge.className = 'pentest-badge pentest-badge--' + pentestStatusClass(cat.status);
  badge.textContent = String(cat.status || '');
  tdStatus.appendChild(badge);

  var tdSeen = document.createElement('td');
  var seen = cat.findings || [];
  if (seen.length) {
    var ul = document.createElement('ul');
    ul.className = 'pentest-cell-list';
    seen.slice(0, 4).forEach(function(f) {
      var li = document.createElement('li');
      li.textContent = f;
      ul.appendChild(li);
    });
    if (seen.length > 4) {
      var more = document.createElement('li');
      more.className = 'pentest-more';
      more.textContent = '+' + (seen.length - 4) + ' more';
      ul.appendChild(more);
    }
    tdSeen.appendChild(ul);
  } else {
    tdSeen.textContent = '\u2014';
  }

  tr.appendChild(tdId);
  tr.appendChild(tdName);
  tr.appendChild(tdStatus);
  tr.appendChild(tdSeen);
  _pentestBody.appendChild(tr);
}

/* Evidence and titles come from the target server, so everything is written
   with textContent — never innerHTML. */
function pentestAddVuln(v) {
  var li = document.createElement('li');
  li.className = 'pentest-vuln pentest-vuln--' + String(v.severity || 'info').toLowerCase();

  var head = document.createElement('div');
  head.className = 'pentest-vuln-head';
  head.textContent = [v.id, v.severity, v.category ? 'cat ' + v.category : '']
    .filter(Boolean).join(' \u00b7 ');

  var title = document.createElement('div');
  title.className = 'pentest-vuln-title';
  title.textContent = v.title || '';

  var body = document.createElement('div');
  body.className = 'pentest-vuln-body';
  body.textContent = (v.confidence ? 'confidence: ' + v.confidence + ' \u2014 ' : '') +
    (v.evidence || '') + (v.cwe ? ' [' + v.cwe + ']' : '');

  li.appendChild(head);
  li.appendChild(title);
  li.appendChild(body);
  _pentestVulns.appendChild(li);
}

function pentestChip(text) {
  var s = document.createElement('span');
  s.className = 'pentest-chip';
  s.textContent = text;
  _pentestMeta.appendChild(s);
}

function pentestRender(d) {
  pentestStatusSet('Pentest complete.', 'ok');
  _pentestResults.classList.remove('hidden');

  pentestClear(_pentestBody);
  (d.categories || []).forEach(pentestAddRow);

  pentestClear(_pentestMeta);
  pentestChip('Target: ' + d.target);
  pentestChip('Scope: ' + (d.scope || []).join(', '));
  pentestChip('Depth: ' + (d.depth || '\u2014'));
  pentestChip('Score: ' + d.score + '/100 (grade ' + (d.grade || '\u2014') + ')');
  pentestChip('Covered ' + d.tested + ' of ' + d.total + ' categories');

  var g = d.gate || {};
  pentestChip('Requests sent: ' + (g.requests_sent || 0));

  var vs = d.vulnerabilities || [];
  if (vs.length) {
    _pentestVulnWrap.classList.remove('hidden');
    _pentestSubtitle.textContent = 'Vulnerabilities (' + vs.length + ')';
  } else {
    _pentestVulnWrap.classList.add('hidden');
    _pentestSubtitle.textContent = 'Vulnerabilities';
  }
  pentestClear(_pentestVulns);
  vs.forEach(pentestAddVuln);

  _pentestGate.textContent = 'Gate: ' + (g.requests_sent || 0) + ' sent \u00b7 ' +
    (g.requests_refused || 0) + ' refused (out-of-scope ' + (g.refused_out_of_scope || 0) +
    ', intrusive off ' + (g.refused_intrusive || 0) +
    ', budget ' + (g.refused_budget || 0) +
    ', rate ' + (g.refused_rate || 0) +
    ', dry-run ' + (g.refused_dry_run || 0) + ')';

  pentestClear(_pentestNotes);
  (d.notes || []).forEach(function(n) {
    var li = document.createElement('li');
    li.textContent = n;
    _pentestNotes.appendChild(li);
  });

  /* Every finished pentest is sealed into a certificate. Say what happened:
     either the id that was issued, or the reason none was. */
  var pc = d.certificate || {};
  if (_pentestCert) {
    if (pc.issued) {
      _pentestCert.className = 'cert-status ok';
      _pentestCert.textContent = 'Certificate ' + pc.certificate_id +
        ' was sealed automatically \u2014 open the Certificate page to view or download it.';
    } else {
      _pentestCert.className = 'cert-status';
      _pentestCert.textContent = pc.note || '';
    }
  }

  toast('Pentest finished \u2014 ' + d.tested + '/' + d.total + ' categories covered', 'ok');
}

function pentestRun(ev) {
  if (ev) ev.preventDefault();
  if (!_pentestForm || _pentestBtn.classList.contains('loading')) return;

  var target = document.getElementById('pentestTarget').value.trim();
  if (!target) {
    pentestStatusSet('Enter a target URL first.', 'err');
    return;
  }

  var ticket = (document.getElementById('pentestTicket') || {}).value || '';
  var payload = {
    target: target,
    depth: parseInt(document.getElementById('pentestDepth').value, 10) || 2,
    paths: pentestSplitList(document.getElementById('pentestPaths').value),
    passive: document.getElementById('pentestPassive').checked,
    intrusive: document.getElementById('pentestIntrusive').checked,
    dryRun: document.getElementById('pentestDryRun').checked,
    authorized: ticket.trim()
  };

  _pentestBtn.classList.add('loading');
  _pentestResults.classList.add('hidden');
  pentestStatusSet('Pentesting ' + target + ' \u2014 every probe passes the scope gate.', '');

  fetch(API + '/api/pentest/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }).then(function(r) {
    /* A 401 is a session problem. A 403 here is the authorization policy
       refusing this target, which is an answer, not a lockout. */
    if (r.status === 401) { setLocked(); throw new Error('locked'); }
    return r.json().then(function(d) { return { r: r, d: d }; });
  }).then(function(x) {
    if (!x) return;
    if (!x.r.ok) {
      var msg = (x.d && (x.d.reason || x.d.error)) || ('HTTP ' + x.r.status);
      pentestStatusSet(msg, x.d && x.d.denied ? 'warn' : 'err');
      toast('Pentest refused: ' + msg, 'error');
      return;
    }
    pentestRender(x.d);
  }).catch(function(e) {
    if (String(e) === 'Error: locked') return;
    pentestStatusSet('Pentest failed: ' + e, 'err');
    toast('Pentest failed', 'error');
  }).then(function() {
    _pentestBtn.classList.remove('loading');
  });
}

if (_pentestForm) _pentestForm.addEventListener('submit', pentestRun);

/* ---- Crawler (katana-like site spider) ---- */
var _crawlForm     = document.getElementById('crawlForm');
var _crawlBtn      = document.getElementById('btnCrawlRun');
var _crawlStatus   = document.getElementById('crawlStatus');
var _crawlResults  = document.getElementById('crawlResults');
var _crawlBody     = document.getElementById('crawlBody');
var _crawlMeta     = document.getElementById('crawlMeta');
var _crawlGate     = document.getElementById('crawlGate');
var _crawlNotes    = document.getElementById('crawlNotes');

function crawlClear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }

function crawlStatusSet(msg, cls) {
  if (!_crawlStatus) return;
  _crawlStatus.textContent = msg || '';
  _crawlStatus.className = 'crawl-status' + (cls ? ' ' + cls : '');
}

function crawlAddRow(ep) {
  var tr = document.createElement('tr');

  var tdUrl = document.createElement('td');
  tdUrl.className = 'crawl-url';
  tdUrl.textContent = ep.url || '';

  var tdMethod = document.createElement('td');
  tdMethod.className = 'crawl-method';
  tdMethod.textContent = ep.method || '';

  var tdParams = document.createElement('td');
  tdParams.className = 'crawl-params';
  tdParams.textContent = (ep.params && ep.params.length ? ep.params.join(', ') : '\u2014');

  var tdKind = document.createElement('td');
  tdKind.className = 'crawl-kind';
  tdKind.textContent = ep.kind || '';

  var tdFound = document.createElement('td');
  tdFound.className = 'crawl-found';
  tdFound.textContent = ep.found_at || '';

  tr.appendChild(tdUrl);
  tr.appendChild(tdMethod);
  tr.appendChild(tdParams);
  tr.appendChild(tdKind);
  tr.appendChild(tdFound);
  _crawlBody.appendChild(tr);
}

function crawlChip(text) {
  var s = document.createElement('span');
  s.className = 'crawl-chip';
  s.textContent = text;
  _crawlMeta.appendChild(s);
}

function crawlRender(d) {
  crawlStatusSet('Crawl complete.', 'ok');
  _crawlResults.classList.remove('hidden');

  crawlClear(_crawlBody);
  (d.discovered || []).forEach(crawlAddRow);

  crawlClear(_crawlMeta);
  crawlChip('Target: ' + d.target);
  crawlChip('Scope: ' + (d.scope || []).join(', '));
  crawlChip('Pages fetched: ' + d.pages);
  crawlChip('Endpoints found: ' + d.endpoints);
  crawlChip('Duration: ' + (d.duration_sec || 0).toFixed(1) + 's');

  var g = d.gate || {};
  crawlChip('Requests sent: ' + (g.requests_sent || 0));

  crawlClear(_crawlGate);
  crawlGate.textContent = 'Gate: ' + (g.requests_sent || 0) + ' sent \u00b7 ' +
    (g.requests_refused || 0) + ' refused (out-of-scope ' + (g.refused_out_of_scope || 0) +
    ', intrusive off ' + (g.refused_intrusive || 0) +
    ', budget ' + (g.refused_budget || 0) +
    ', rate ' + (g.refused_rate || 0) +
    ', dry-run ' + (g.refused_dry_run || 0) + ')';

  crawlClear(_crawlNotes);
  (d.notes || []).forEach(function(n) {
    var li = document.createElement('li');
    li.textContent = n;
    _crawlNotes.appendChild(li);
  });

  toast('Crawl finished \u2014 ' + d.pages + ' pages, ' + d.endpoints + ' endpoints', 'ok');
}

function crawlRun(ev) {
  if (ev) ev.preventDefault();
  if (!_crawlForm || _crawlBtn.classList.contains('loading')) return;

  var target = document.getElementById('crawlTarget').value.trim();
  if (!target) {
    crawlStatusSet('Enter a target URL first.', 'err');
    return;
  }

  var payload = {
    target: target,
    depth: parseInt(document.getElementById('crawlDepth').value, 10) || 3,
    pages: parseInt(document.getElementById('crawlPages').value, 10) || 100,
    concurrency: parseInt(document.getElementById('crawlConcur').value, 10) || 5,
    offsite: document.getElementById('crawlOffsite').checked,
    dryRun: document.getElementById('crawlDryRun').checked
  };

  _crawlBtn.classList.add('loading');
  _crawlResults.classList.add('hidden');
  crawlStatusSet('Crawling ' + target + ' \u2014 every hop passes the scope gate.', '');

  fetch(API + '/api/crawl/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }).then(function(r) {
    if (r.status === 401) { setLocked(); throw new Error('locked'); }
    return r.json().then(function(d) { return { r: r, d: d }; });
  }).then(function(x) {
    if (!x) return;
    if (!x.r.ok) {
      var msg = (x.d && (x.d.reason || x.d.error)) || ('HTTP ' + x.r.status);
      crawlStatusSet(msg, x.d && x.d.denied ? 'warn' : 'err');
      toast('Crawl refused: ' + msg, 'error');
      return;
    }
    crawlRender(x.d);
  }).catch(function(e) {
    if (String(e) === 'Error: locked') return;
    crawlStatusSet('Crawl failed: ' + e, 'err');
    toast('Crawl failed', 'error');
  }).then(function() {
    _crawlBtn.classList.remove('loading');
  });
}

if (_crawlForm) _crawlForm.addEventListener('submit', crawlRun);

/* ---- Fuzz (HTTP fuzzer) ---- */
var _fuzzForm     = document.getElementById('fuzzForm');
var _fuzzBtn      = document.getElementById('btnFuzzRun');
var _fuzzStatus   = document.getElementById('fuzzStatus');
var _fuzzResults  = document.getElementById('fuzzResults');
var _fuzzBody     = document.getElementById('fuzzBody');
var _fuzzMeta     = document.getElementById('fuzzMeta');
var _fuzzGate     = document.getElementById('fuzzGate');
var _fuzzNotes    = document.getElementById('fuzzNotes');

function fuzzClear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }

function fuzzStatusSet(msg, cls) {
  if (!_fuzzStatus) return;
  _fuzzStatus.textContent = msg || '';
  _fuzzStatus.className = 'fuzz-status' + (cls ? ' ' + cls : '');
}

function fuzzAddRow(f) {
  var tr = document.createElement('tr');
  var tdMethod = document.createElement('td'); tdMethod.textContent = f.method || '';
  var tdUrl = document.createElement('td'); tdUrl.textContent = f.url || '';
  var tdStatus = document.createElement('td'); tdStatus.textContent = f.status_code || '';
  var tdBody = document.createElement('td'); tdBody.textContent = (f.body_len || 0) + ' B';
  var tdMutation = document.createElement('td'); tdMutation.textContent = f.mutation || '';
  var tdReason = document.createElement('td'); tdReason.textContent = f.reason || '';
  tr.appendChild(tdMethod); tr.appendChild(tdUrl); tr.appendChild(tdStatus); tr.appendChild(tdBody); tr.appendChild(tdMutation); tr.appendChild(tdReason);
  _fuzzBody.appendChild(tr);
}

function fuzzChip(text) {
  var s = document.createElement('span'); s.className = 'fuzz-chip'; s.textContent = text; _fuzzMeta.appendChild(s);
}

function fuzzRender(d) {
  fuzzStatusSet('Fuzz complete.', 'ok');
  _fuzzResults.classList.remove('hidden');
  fuzzClear(_fuzzBody);
  (d.findings || []).forEach(fuzzAddRow);
  fuzzClear(_fuzzMeta);
  fuzzChip('Target: ' + d.target);
  fuzzChip('Scope: ' + (d.scope || []).join(', '));
  fuzzChip('Sent: ' + d.sent + '  Refused: ' + d.refused + '  Interesting: ' + d.interesting);
  var g = d.gate || {};
  fuzzChip('Gate sent: ' + (g.requests_sent || 0) + ' refused: ' + (g.requests_refused || 0));
  fuzzClear(_fuzzGate);
  _fuzzGate.textContent = 'Gate: ' + (g.requests_sent || 0) + ' sent · ' +
    (g.requests_refused || 0) + ' refused (out-of-scope ' + (g.refused_out_of_scope || 0) +
    ', intrusive off ' + (g.refused_intrusive || 0) + ', budget ' + (g.refused_budget || 0) +
    ', rate ' + (g.refused_rate || 0) + ')';
  fuzzClear(_fuzzNotes);
  (d.notes || []).forEach(function(n) { var li = document.createElement('li'); li.textContent = n; _fuzzNotes.appendChild(li); });
  toast('Fuzz finished — ' + d.interesting + ' interesting responses', 'ok');
}

function fuzzRun(ev) {
  if (ev) ev.preventDefault();
  if (!_fuzzForm || _fuzzBtn.classList.contains('loading')) return;
  var target = document.getElementById('fuzzTarget').value.trim();
  if (!target) { fuzzStatusSet('Enter a target URL first.', 'err'); return; }
  var payload = {
    target: target,
    paths: (document.getElementById('fuzzPaths').value || '').split(',').map(function(s){return s.trim();}).filter(Boolean),
    mutations: parseInt(document.getElementById('fuzzMutations').value, 10) || 100,
    intrusive: document.getElementById('fuzzIntrusive').checked
  };
  _fuzzBtn.classList.add('loading');
  _fuzzResults.classList.add('hidden');
  fuzzStatusSet('Fuzzing ' + target + ' — every mutation passes the scope gate.', '');
  fetch(API + '/api/fuzz/scan', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }).then(function(r) {
    if (r.status === 401) { setLocked(); throw new Error('locked'); }
    return r.json().then(function(d) { return { r: r, d: d }; });
  }).then(function(x) {
    if (!x) return;
    if (!x.r.ok) {
      var msg = (x.d && (x.d.reason || x.d.error)) || ('HTTP ' + x.r.status);
      fuzzStatusSet(msg, x.d && x.d.denied ? 'warn' : 'err');
      toast('Fuzz refused: ' + msg, 'error');
      return;
    }
    fuzzRender(x.d);
  }).catch(function(e) {
    if (String(e) === 'Error: locked') return;
    fuzzStatusSet('Fuzz failed: ' + e, 'err');
    toast('Fuzz failed', 'error');
  }).then(function() { _fuzzBtn.classList.remove('loading'); });
}

if (_fuzzForm) _fuzzForm.addEventListener('submit', fuzzRun);

/* ---- Subdomain enumeration ---- */
var _subdomainForm     = document.getElementById('subdomainForm');
var _subdomainBtn      = document.getElementById('btnSubdomainRun');
var _subdomainStatus   = document.getElementById('subdomainStatus');
var _subdomainResults  = document.getElementById('subdomainResults');
var _subdomainBody     = document.getElementById('subdomainBody');
var _subdomainMeta     = document.getElementById('subdomainMeta');
var _subdomainNotes    = document.getElementById('subdomainNotes');

function subdomainClear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }

function subdomainStatusSet(msg, cls) {
  if (!_subdomainStatus) return;
  _subdomainStatus.textContent = msg || '';
  _subdomainStatus.className = 'subdomain-status' + (cls ? ' ' + cls : '');
}

function subdomainAddRow(s) {
  var tr = document.createElement('tr');
  var tdName = document.createElement('td'); tdName.textContent = s.name || '';
  var tdIPs = document.createElement('td'); tdIPs.textContent = (s.ips && s.ips.length ? s.ips.join(', ') : '—');
  var tdSource = document.createElement('td'); tdSource.textContent = s.source || '';
  var tdMethods = document.createElement('td'); tdMethods.textContent = (s.methods && s.methods.length ? s.methods.join(', ') : '—');
  tr.appendChild(tdName); tr.appendChild(tdIPs); tr.appendChild(tdSource); tr.appendChild(tdMethods);
  _subdomainBody.appendChild(tr);
}

function subdomainChip(text) {
  var s = document.createElement('span'); s.className = 'subdomain-chip'; s.textContent = text; _subdomainMeta.appendChild(s);
}

function subdomainRender(d) {
  subdomainStatusSet('Enumeration complete.', 'ok');
  _subdomainResults.classList.remove('hidden');
  subdomainClear(_subdomainBody);
  (d.subdomains || []).forEach(subdomainAddRow);
  subdomainClear(_subdomainMeta);
  subdomainChip('Target: ' + d.target);
  subdomainChip('Found: ' + d.found + '  Resolved: ' + d.resolved);
  subdomainClear(_subdomainNotes);
  (d.notes || []).forEach(function(n) { var li = document.createElement('li'); li.textContent = n; _subdomainNotes.appendChild(li); });
  toast('Subdomain enumeration complete — ' + d.found + ' found', 'ok');
}

function subdomainRun(ev) {
  if (ev) ev.preventDefault();
  if (!_subdomainForm || _subdomainBtn.classList.contains('loading')) return;
  var target = document.getElementById('subdomainTarget').value.trim();
  if (!target) { subdomainStatusSet('Enter a target domain first.', 'err'); return; }
  var payload = { target: target };
  _subdomainBtn.classList.add('loading');
  _subdomainResults.classList.add('hidden');
  subdomainStatusSet('Enumerating ' + target + '...', '');
  fetch(API + '/api/subdomain/scan', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }).then(function(r) {
    if (r.status === 401) { setLocked(); throw new Error('locked'); }
    return r.json().then(function(d) { return { r: r, d: d }; });
  }).then(function(x) {
    if (!x) return;
    if (!x.r.ok) {
      var msg = (x.d && (x.d.reason || x.d.error)) || ('HTTP ' + x.r.status);
      subdomainStatusSet(msg, x.d && x.d.denied ? 'warn' : 'err');
      toast('Enumeration refused: ' + msg, 'error');
      return;
    }
    subdomainRender(x.d);
  }).catch(function(e) {
    if (String(e) === 'Error: locked') return;
    subdomainStatusSet('Enumeration failed: ' + e, 'err');
    toast('Enumeration failed', 'error');
  }).then(function() { _subdomainBtn.classList.remove('loading'); });
}

if (_subdomainForm) _subdomainForm.addEventListener('submit', subdomainRun);

/* ---- Port scan ---- */
var _portscanForm     = document.getElementById('portscanForm');
var _portscanBtn      = document.getElementById('btnPortscanRun');
var _portscanStatus   = document.getElementById('portscanStatus');
var _portscanResults  = document.getElementById('portscanResults');
var _portscanBody     = document.getElementById('portscanBody');
var _portscanMeta     = document.getElementById('portscanMeta');
var _portscanNotes    = document.getElementById('portscanNotes');

function portscanClear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }

function portscanStatusSet(msg, cls) {
  if (!_portscanStatus) return;
  _portscanStatus.textContent = msg || '';
  _portscanStatus.className = 'portscan-status' + (cls ? ' ' + cls : '');
}

function portscanAddRow(p) {
  var tr = document.createElement('tr');
  var tdPort = document.createElement('td'); tdPort.textContent = p.port || '';
  var tdState = document.createElement('td'); tdState.textContent = p.state || '';
  var tdService = document.createElement('td'); tdService.textContent = p.service || '';
  var tdBanner = document.createElement('td'); tdBanner.textContent = p.banner || '';
  tr.appendChild(tdPort); tr.appendChild(tdState); tr.appendChild(tdService); tr.appendChild(tdBanner);
  _portscanBody.appendChild(tr);
}

function portscanChip(text) {
  var s = document.createElement('span'); s.className = 'portscan-chip'; s.textContent = text; _portscanMeta.appendChild(s);
}

function portscanRender(d) {
  portscanStatusSet('Port scan complete.', 'ok');
  _portscanResults.classList.remove('hidden');
  portscanClear(_portscanBody);
  (d.ports || []).forEach(portscanAddRow);
  portscanClear(_portscanMeta);
  portscanChip('Target: ' + d.target);
  portscanChip('Opened: ' + d.opened + '  Closed: ' + d.closed);
  portscanClear(_portscanNotes);
  (d.notes || []).forEach(function(n) { var li = document.createElement('li'); li.textContent = n; _portscanNotes.appendChild(li); });
  toast('Port scan complete — ' + d.opened + ' open', 'ok');
}

function portscanRun(ev) {
  if (ev) ev.preventDefault();
  if (!_portscanForm || _portscanBtn.classList.contains('loading')) return;
  var target = document.getElementById('portscanTarget').value.trim();
  if (!target) { portscanStatusSet('Enter a target host first.', 'err'); return; }
  var payload = {
    target: target,
    ports: (document.getElementById('portscanPorts').value || '').split(',').map(function(s){return parseInt(s.trim(), 10);}).filter(function(n){return !isNaN(n);})
  };
  _portscanBtn.classList.add('loading');
  _portscanResults.classList.add('hidden');
  portscanStatusSet('Scanning ' + target + '...', '');
  fetch(API + '/api/portscan', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }).then(function(r) {
    if (r.status === 401) { setLocked(); throw new Error('locked'); }
    return r.json().then(function(d) { return { r: r, d: d }; });
  }).then(function(x) {
    if (!x) return;
    if (!x.r.ok) {
      var msg = (x.d && (x.d.reason || x.d.error)) || ('HTTP ' + x.r.status);
      portscanStatusSet(msg, x.d && x.d.denied ? 'warn' : 'err');
      toast('Port scan refused: ' + msg, 'error');
      return;
    }
    portscanRender(x.d);
  }).catch(function(e) {
    if (String(e) === 'Error: locked') return;
    portscanStatusSet('Port scan failed: ' + e, 'err');
    toast('Port scan failed', 'error');
  }).then(function() { _portscanBtn.classList.remove('loading'); });
}

if (_portscanForm) _portscanForm.addEventListener('submit', portscanRun);

/* ---- Dir bust ---- */
var _dirbustForm     = document.getElementById('dirbustForm');
var _dirbustBtn      = document.getElementById('btnDirbustRun');
var _dirbustStatus   = document.getElementById('dirbustStatus');
var _dirbustResults  = document.getElementById('dirbustResults');
var _dirbustBody     = document.getElementById('dirbustBody');
var _dirbustMeta     = document.getElementById('dirbustMeta');
var _dirbustNotes    = document.getElementById('dirbustNotes');

function dirbustClear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }

function dirbustStatusSet(msg, cls) {
  if (!_dirbustStatus) return;
  _dirbustStatus.textContent = msg || '';
  _dirbustStatus.className = 'dirbust-status' + (cls ? ' ' + cls : '');
}

function dirbustAddRow(e) {
  var tr = document.createElement('tr');
  var tdUrl = document.createElement('td'); tdUrl.textContent = e.url || '';
  var tdStatus = document.createElement('td'); tdStatus.textContent = e.status_code || '';
  var tdSize = document.createElement('td'); tdSize.textContent = (e.size || 0) + ' B';
  var tdTitle = document.createElement('td'); tdTitle.textContent = e.title || '';
  tr.appendChild(tdUrl); tr.appendChild(tdStatus); tr.appendChild(tdSize); tr.appendChild(tdTitle);
  _dirbustBody.appendChild(tr);
}

function dirbustChip(text) {
  var s = document.createElement('span'); s.className = 'dirbust-chip'; s.textContent = text; _dirbustMeta.appendChild(s);
}

function dirbustRender(d) {
  dirbustStatusSet('Brute-force complete.', 'ok');
  _dirbustResults.classList.remove('hidden');
  dirbustClear(_dirbustBody);
  (d.entries || []).forEach(dirbustAddRow);
  dirbustClear(_dirbustMeta);
  dirbustChip('Target: ' + d.target);
  dirbustChip('Found: ' + d.found);
  dirbustClear(_dirbustNotes);
  (d.notes || []).forEach(function(n) { var li = document.createElement('li'); li.textContent = n; _dirbustNotes.appendChild(li); });
  toast('Dir bust complete — ' + d.found + ' found', 'ok');
}

function dirbustRun(ev) {
  if (ev) ev.preventDefault();
  if (!_dirbustForm || _dirbustBtn.classList.contains('loading')) return;
  var target = document.getElementById('dirbustTarget').value.trim();
  if (!target) { dirbustStatusSet('Enter a target URL first.', 'err'); return; }
  var payload = {
    target: target,
    paths: (document.getElementById('dirbustPaths').value || '').split(',').map(function(s){return s.trim();}).filter(Boolean)
  };
  _dirbustBtn.classList.add('loading');
  _dirbustResults.classList.add('hidden');
  dirbustStatusSet('Brute-forcing ' + target + '...', '');
  fetch(API + '/api/dirbust', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }).then(function(r) {
    if (r.status === 401) { setLocked(); throw new Error('locked'); }
    return r.json().then(function(d) { return { r: r, d: d }; });
  }).then(function(x) {
    if (!x) return;
    if (!x.r.ok) {
      var msg = (x.d && (x.d.reason || x.d.error)) || ('HTTP ' + x.r.status);
      dirbustStatusSet(msg, x.d && x.d.denied ? 'warn' : 'err');
      toast('Brute-force refused: ' + msg, 'error');
      return;
    }
    dirbustRender(x.d);
  }).catch(function(e) {
    if (String(e) === 'Error: locked') return;
    dirbustStatusSet('Brute-force failed: ' + e, 'err');
    toast('Brute-force failed', 'error');
  }).then(function() { _dirbustBtn.classList.remove('loading'); });
}

if (_dirbustForm) _dirbustForm.addEventListener('submit', dirbustRun);

/* ---- SSL/TLS scan ---- */
var _sslscanForm     = document.getElementById('sslscanForm');
var _sslscanBtn      = document.getElementById('btnSSLScanRun');
var _sslscanStatus   = document.getElementById('sslscanStatus');
var _sslscanResults  = document.getElementById('sslscanResults');
var _sslscanMeta     = document.getElementById('sslscanMeta');
var _sslscanNotes    = document.getElementById('sslscanNotes');

function sslscanClear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }

function sslscanStatusSet(msg, cls) {
  if (!_sslscanStatus) return;
  _sslscanStatus.textContent = msg || '';
  _sslscanStatus.className = 'sslscan-status' + (cls ? ' ' + cls : '');
}

function sslscanChip(text) {
  var s = document.createElement('span'); s.className = 'sslscan-chip'; s.textContent = text; _sslscanMeta.appendChild(s);
}

function sslscanRender(d) {
  sslscanStatusSet('TLS inspection complete.', 'ok');
  _sslscanResults.classList.remove('hidden');
  sslscanClear(_sslscanMeta);
  sslscanChip('Target: ' + d.target);
  sslscanChip('Valid: ' + d.valid + '  Expired: ' + d.expired);
  sslscanChip('Issuer: ' + (d.issuer || '—'));
  sslscanChip('Version: ' + (d.version || '—') + '  Cipher: ' + (d.cipher || '—'));
  sslscanClear(_sslscanNotes);
  (d.issues || []).forEach(function(n) { var li = document.createElement('li'); li.textContent = n; _sslscanNotes.appendChild(li); });
  toast('TLS inspection complete', 'ok');
}

function sslscanRun(ev) {
  if (ev) ev.preventDefault();
  if (!_sslscanForm || _sslscanBtn.classList.contains('loading')) return;
  var target = document.getElementById('sslscanTarget').value.trim();
  if (!target) { sslscanStatusSet('Enter a target host first.', 'err'); return; }
  var payload = { target: target };
  _sslscanBtn.classList.add('loading');
  _sslscanResults.classList.add('hidden');
  sslscanStatusSet('Inspecting TLS ' + target + '...', '');
  fetch(API + '/api/sslscan', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }).then(function(r) {
    if (r.status === 401) { setLocked(); throw new Error('locked'); }
    return r.json().then(function(d) { return { r: r, d: d }; });
  }).then(function(x) {
    if (!x) return;
    if (!x.r.ok) {
      var msg = (x.d && (x.d.reason || x.d.error)) || ('HTTP ' + x.r.status);
      sslscanStatusSet(msg, x.d && x.d.denied ? 'warn' : 'err');
      toast('TLS inspection refused: ' + msg, 'error');
      return;
    }
    sslscanRender(x.d);
  }).catch(function(e) {
    if (String(e) === 'Error: locked') return;
    sslscanStatusSet('TLS inspection failed: ' + e, 'err');
    toast('TLS inspection failed', 'error');
  }).then(function() { _sslscanBtn.classList.remove('loading'); });
}

if (_sslscanForm) _sslscanForm.addEventListener('submit', sslscanRun);

/* ---- JWT analyzer ---- */
var _jwtForm     = document.getElementById('jwtForm');
var _jwtBtn      = document.getElementById('btnJWTRun');
var _jwtStatus   = document.getElementById('jwtStatus');
var _jwtResults  = document.getElementById('jwtResults');
var _jwtMeta     = document.getElementById('jwtMeta');
var _jwtNotes    = document.getElementById('jwtNotes');

function jwtClear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }

function jwtStatusSet(msg, cls) {
  if (!_jwtStatus) return;
  _jwtStatus.textContent = msg || '';
  _jwtStatus.className = 'jwt-status' + (cls ? ' ' + cls : '');
}

function jwtChip(text) {
  var s = document.createElement('span'); s.className = 'jwt-chip'; s.textContent = text; _jwtMeta.appendChild(s);
}

function jwtRender(d) {
  jwtStatusSet('JWT analysis complete.', 'ok');
  _jwtResults.classList.remove('hidden');
  jwtClear(_jwtMeta);
  jwtChip('Valid: ' + d.valid + '  Algo confusion: ' + d.algo_confusion);
  jwtClear(_jwtNotes);
  (d.issues || []).forEach(function(n) { var li = document.createElement('li'); li.textContent = n; _jwtNotes.appendChild(li); });
  toast('JWT analysis complete', 'ok');
}

function jwtRun(ev) {
  if (ev) ev.preventDefault();
  if (!_jwtForm || _jwtBtn.classList.contains('loading')) return;
  var token = document.getElementById('jwtToken').value.trim();
  if (!token) { jwtStatusSet('Enter a JWT token first.', 'err'); return; }
  var payload = { token: token };
  _jwtBtn.classList.add('loading');
  _jwtResults.classList.add('hidden');
  jwtStatusSet('Analyzing JWT...', '');
  fetch(API + '/api/jwt/scan', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }).then(function(r) {
    if (r.status === 401) { setLocked(); throw new Error('locked'); }
    return r.json().then(function(d) { return { r: r, d: d }; });
  }).then(function(x) {
    if (!x) return;
    if (!x.r.ok) {
      var msg = (x.d && (x.d.reason || x.d.error)) || ('HTTP ' + x.r.status);
      jwtStatusSet(msg, x.d && x.d.denied ? 'warn' : 'err');
      toast('JWT analysis refused: ' + msg, 'error');
      return;
    }
    jwtRender(x.d);
  }).catch(function(e) {
    if (String(e) === 'Error: locked') return;
    jwtStatusSet('JWT analysis failed: ' + e, 'err');
    toast('JWT analysis failed', 'error');
  }).then(function() { _jwtBtn.classList.remove('loading'); });
}

if (_jwtForm) _jwtForm.addEventListener('submit', jwtRun);

/* ---- GraphQL scanner ---- */
var _graphqlForm     = document.getElementById('graphqlForm');
var _graphqlBtn      = document.getElementById('btnGraphQLRun');
var _graphqlStatus   = document.getElementById('graphqlStatus');
var _graphqlResults  = document.getElementById('graphqlResults');
var _graphqlBody     = document.getElementById('graphqlBody');
var _graphqlMeta     = document.getElementById('graphqlMeta');
var _graphqlNotes    = document.getElementById('graphqlNotes');

function graphqlClear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }

function graphqlStatusSet(msg, cls) {
  if (!_graphqlStatus) return;
  _graphqlStatus.textContent = msg || '';
  _graphqlStatus.className = 'graphql-status' + (cls ? ' ' + cls : '');
}

function graphqlAddRow(t) {
  var tr = document.createElement('tr');
  var tdType = document.createElement('td'); tdType.textContent = t || '';
  tr.appendChild(tdType);
  _graphqlBody.appendChild(tr);
}

function graphqlChip(text) {
  var s = document.createElement('span'); s.className = 'graphql-chip'; s.textContent = text; _graphqlMeta.appendChild(s);
}

function graphqlRender(d) {
  graphqlStatusSet('GraphQL probe complete.', 'ok');
  _graphqlResults.classList.remove('hidden');
  graphqlClear(_graphqlBody);
  (d.types || []).forEach(graphqlAddRow);
  graphqlClear(_graphqlMeta);
  graphqlChip('Target: ' + d.endpoint);
  graphqlChip('Reachable: ' + d.reachable + '  Introspection: ' + d.introspection);
  graphqlClear(_graphqlNotes);
  (d.issues || []).forEach(function(n) { var li = document.createElement('li'); li.textContent = n; _graphqlNotes.appendChild(li); });
  toast('GraphQL probe complete', 'ok');
}

function graphqlRun(ev) {
  if (ev) ev.preventDefault();
  if (!_graphqlForm || _graphqlBtn.classList.contains('loading')) return;
  var target = document.getElementById('graphqlTarget').value.trim();
  if (!target) { graphqlStatusSet('Enter a GraphQL endpoint first.', 'err'); return; }
  var payload = { endpoint: target };
  _graphqlBtn.classList.add('loading');
  _graphqlResults.classList.add('hidden');
  graphqlStatusSet('Probing ' + target + '...', '');
  fetch(API + '/api/graphql/scan', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }).then(function(r) {
    if (r.status === 401) { setLocked(); throw new Error('locked'); }
    return r.json().then(function(d) { return { r: r, d: d }; });
  }).then(function(x) {
    if (!x) return;
    if (!x.r.ok) {
      var msg = (x.d && (x.d.reason || x.d.error)) || ('HTTP ' + x.r.status);
      graphqlStatusSet(msg, x.d && x.d.denied ? 'warn' : 'err');
      toast('GraphQL probe refused: ' + msg, 'error');
      return;
    }
    graphqlRender(x.d);
  }).catch(function(e) {
    if (String(e) === 'Error: locked') return;
    graphqlStatusSet('GraphQL probe failed: ' + e, 'err');
    toast('GraphQL probe failed', 'error');
  }).then(function() { _graphqlBtn.classList.remove('loading'); });
}

if (_graphqlForm) _graphqlForm.addEventListener('submit', graphqlRun);

/* ---- WebSocket security ---- */
var _websocketForm     = document.getElementById('websocketForm');
var _websocketBtn      = document.getElementById('btnWebSocketRun');
var _websocketStatus   = document.getElementById('websocketStatus');
var _websocketResults  = document.getElementById('websocketResults');
var _websocketMeta     = document.getElementById('websocketMeta');
var _websocketNotes    = document.getElementById('websocketNotes');

function websocketClear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }

function websocketStatusSet(msg, cls) {
  if (!_websocketStatus) return;
  _websocketStatus.textContent = msg || '';
  _websocketStatus.className = 'websocket-status' + (cls ? ' ' + cls : '');
}

function websocketChip(text) {
  var s = document.createElement('span'); s.className = 'websocket-chip'; s.textContent = text; _websocketMeta.appendChild(s);
}

function websocketRender(d) {
  websocketStatusSet('WebSocket test complete.', 'ok');
  _websocketResults.classList.remove('hidden');
  websocketClear(_websocketMeta);
  websocketChip('Target: ' + d.url);
  websocketChip('Connected: ' + d.connected + '  Subprotocol: ' + (d.subprotocol || '—'));
  websocketClear(_websocketNotes);
  (d.issues || []).forEach(function(n) { var li = document.createElement('li'); li.textContent = n; _websocketNotes.appendChild(li); });
  toast('WebSocket test complete', 'ok');
}

function websocketRun(ev) {
  if (ev) ev.preventDefault();
  if (!_websocketForm || _websocketBtn.classList.contains('loading')) return;
  var target = document.getElementById('websocketTarget').value.trim();
  if (!target) { websocketStatusSet('Enter a WebSocket URL first.', 'err'); return; }
  var payload = { url: target };
  _websocketBtn.classList.add('loading');
  _websocketResults.classList.add('hidden');
  websocketStatusSet('Testing ' + target + '...', '');
  fetch(API + '/api/websocket/scan', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  }).then(function(r) {
    if (r.status === 401) { setLocked(); throw new Error('locked'); }
    return r.json().then(function(d) { return { r: r, d: d }; });
  }).then(function(x) {
    if (!x) return;
    if (!x.r.ok) {
      var msg = (x.d && (x.d.reason || x.d.error)) || ('HTTP ' + x.r.status);
      websocketStatusSet(msg, x.d && x.d.denied ? 'warn' : 'err');
      toast('WebSocket test refused: ' + msg, 'error');
      return;
    }
    websocketRender(x.d);
  }).catch(function(e) {
    if (String(e) === 'Error: locked') return;
    websocketStatusSet('WebSocket test failed: ' + e, 'err');
    toast('WebSocket test failed', 'error');
  }).then(function() { _websocketBtn.classList.remove('loading'); });
}

if (_websocketForm) _websocketForm.addEventListener('submit', websocketRun);

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

/* ---- Lock overlay buttons ---- */
var _lockRetry = document.getElementById('btnLockRetry');
if (_lockRetry) {
  _lockRetry.addEventListener('click', function() {
    closeLocked();
    S.everOpened = false;
    connect();
  });
}
var _lockRefresh = document.getElementById('btnLockRefresh');
if (_lockRefresh) {
  _lockRefresh.addEventListener('click', function() {
    try { window.location.reload(); } catch (e) {}
  });
}

/* ---- Ops endpoints (/healthz /readyz /metrics are auth-exempt): show a
       small hint in the footer only when the server actually exposes them. ---- */
fetch(API + '/healthz').then(function(r) {
  if (!r.ok) return;
  var ops = document.getElementById('opsLinks');
  if (ops) ops.classList.remove('hidden');
}).catch(function() {});


/* ---- Attestation ---- */
function fetchAttestation() {
  fetch(API + '/api/attestation').then(function(r) {
    if (guardStatus && guardStatus(r)) return null;
    return r.json();
  }).then(function(d) {
    if (!d) return;
    renderAttestation(d);
  }).catch(function() {});
}

function renderAttestation(d) {
  var card = document.getElementById('attestationCard');
  var fp = document.getElementById('attestFingerprint');
  var bs = document.getElementById('attestBundleStatus');
  var st = document.getElementById('attestVerifyStatus');
  if (!d.exists) {
    if (card) card.classList.add('hidden');
    return;
  }
  if (card) card.classList.remove('hidden');
  if (fp) fp.textContent = d.fingerprint || d.pubKeyHex || '—';
  if (bs) bs.textContent = 'exists';
  var pc = document.getElementById('attestPercentiles');
  if (pc) pc.textContent = d.coCorrected ? 'coordinated-omission corrected' : 'raw (uncorrected)';
  if (st) { st.textContent = '—'; st.className = 'attest-status'; }
  var b = document.getElementById('btnAttestDownloadBundle');
  var sbtn = document.getElementById('btnAttestDownloadSamples');
  if (b) { b.disabled = false; b.onclick = function() { window.location = API + '/api/attestation/download?type=bundle'; }; }
  if (sbtn) { sbtn.disabled = false; sbtn.onclick = function() { window.location = API + '/api/attestation/download?type=samples'; }; }
}

function refreshAttestation() {
  fetchAttestation();
}

var _btnAttestVerify = document.getElementById('btnAttestVerify');
if (_btnAttestVerify) {
  _btnAttestVerify.addEventListener('click', function() {
    var st = document.getElementById('attestVerifyStatus');
    if (st) { st.textContent = 'Verifying...'; st.className = 'attest-status'; }
    fetch(API + '/api/attestation/verify', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({})
    }).then(function(r) {
      if (guardStatus && guardStatus(r)) return null;
      return r.json();
    }).then(function(res) {
      if (!res) return;
      var st = document.getElementById('attestVerifyStatus');
      if (!st) return;
      if (res.valid) {
        st.textContent = 'valid';
        st.className = 'attest-status attest-ok';
      } else {
        var reason = res.reason || 'invalid';
        st.textContent = 'invalid: ' + reason;
        st.className = 'attest-status attest-bad';
      }
    }).catch(function() {
      var st = document.getElementById('attestVerifyStatus');
      if (st) { st.textContent = 'verify error'; st.className = 'attest-status attest-bad'; }
    });
  });
}

setInterval(refreshAttestation, 2000);

/* ==========================================================================
   SHELL — sidebar view switching
   ========================================================================== */
var VIEW_KEY = 'ss_view';
var VIEW_IDS = ['viewOverview', 'viewSecurity', 'viewCertificate', 'viewHistory', 'viewAdmin'];

function rememberView(id) {
  try { localStorage.setItem(VIEW_KEY, id); } catch (e) {}
}
function savedView() {
  try {
    var v = localStorage.getItem(VIEW_KEY);
    if (v && VIEW_IDS.indexOf(v) >= 0) return v;
  } catch (e) {}
  return '';
}

function showView(id, opts) {
  opts = opts || {};
  if (VIEW_IDS.indexOf(id) < 0) return;

  VIEW_IDS.forEach(function(v) {
    var el = document.getElementById(v);
    if (!el) return;
    if (v === id) el.classList.remove('hidden');
    else el.classList.add('hidden');
  });

  var links = document.querySelectorAll('.sb-link[data-view]');
  for (var i = 0; i < links.length; i++) {
    if (links[i].getAttribute('data-view') === id) links[i].classList.add('active');
    else links[i].classList.remove('active');
  }

  if (!opts.silent) rememberView(id);

  if (id === 'viewHistory') {
    renderHistory();
    var sec = document.getElementById('historySection');
    if (sec) sec.classList.remove('hidden');
    var body = document.getElementById('historyBody');
    if (body && (!S.history || S.history.length === 0) && body.children.length === 0) {
      var tr = document.createElement('tr');
      var td = document.createElement('td');
      td.colSpan = 9;
      td.className = 'empty-note';
      td.textContent = 'No runs yet — start one from Overview.';
      tr.appendChild(td);
      body.appendChild(tr);
    }
  }
  if (id === 'viewCertificate') {
    certRefreshReset();
    certLoadLatest();
  }
  if (id === 'viewAdmin') adminStart();
  else adminStop();
}

function wireNav() {
  var links = document.querySelectorAll('.sb-link[data-view]');
  for (var i = 0; i < links.length; i++) {
    links[i].addEventListener('click', function(ev) {
      ev.preventDefault();
      showView(this.getAttribute('data-view'));
    });
  }

  // Alt+1..4 / Alt+A. Alt avoids fighting the existing S/E run shortcuts and
  // normal typing inside the URL and token fields.
  document.addEventListener('keydown', function(ev) {
    if (!ev.altKey || ev.ctrlKey || ev.metaKey) return;
    var map = { '1': 'viewOverview', '2': 'viewSecurity', '3': 'viewCertificate', '4': 'viewHistory' };
    var id = map[String(ev.key).toLowerCase()];
    if (!id) return;
    ev.preventDefault();
    showView(id);
  });
}

/* ==========================================================================
   SHELL — hidden admin reveal via secret hash (#slasz#)
   ========================================================================== */
var adminRevealed = false;

function revealAdmin(open) {
  if (!adminRevealed) {
    adminRevealed = true;
    var nav = document.getElementById('navAdmin');
    if (nav) nav.classList.remove('hidden');
    try { sessionStorage.setItem('ss_admin_revealed', '1'); } catch (e) {}
  }
  if (open) showView('viewAdmin');
}

function wireAdminReveal() {
  try { if (sessionStorage.getItem('ss_admin_revealed') === '1') revealAdmin(false); } catch (e) {}

  // Browsers may encode '#' as '%23', so match on the secret substring instead.
  function hashIsAdmin(h) { return h.indexOf('slasz') >= 0; }

  if (hashIsAdmin(location.hash)) revealAdmin(true);
  window.addEventListener('hashchange', function() {
    if (hashIsAdmin(location.hash)) revealAdmin(true);
  });
}

/* ==========================================================================
   CERTIFICATE PAGE — drop one file, issue or verify
   ========================================================================== */
var certState = { cert: null, html: '', kind: '', fileName: '' };

function certStatus(msg, cls) {
  var el = document.getElementById('certStatus');
  if (!el) return;
  el.textContent = msg || '';
  el.className = 'cert-status' + (cls ? ' ' + cls : '');
}

function certClear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }

function certFact(label, value) {
  var box = document.createElement('div');
  box.className = 'cert-fact';
  var l = document.createElement('span');
  l.className = 'cert-fact-label';
  l.textContent = label;
  var v = document.createElement('span');
  v.className = 'cert-fact-value';
  v.textContent = value === undefined || value === null || value === '' ? '—' : String(value);
  box.appendChild(l);
  box.appendChild(v);
  return box;
}

function certRefreshReset() {
  if (certState.cert || certState.html) return;
  certStatus('Waiting for a file — a pentest report or a certificate.', '');
}

function certShowResult(kind, cert, rawText) {
  var wrap = document.getElementById('certResult');
  var title = document.getElementById('certResultTitle');
  var verdict = document.getElementById('certVerdict');
  var facts = document.getElementById('certFacts');
  if (!wrap || !verdict || !facts) return;

  certClear(facts);
  var a = (cert && cert.assessment) || null;

  if (kind === 'verify-valid') {
    verdict.className = 'cert-verdict ok';
    verdict.textContent = 'VALID — this certificate was not edited after signing.';
    if (title) title.textContent = 'Verified certificate';
  } else if (kind === 'verify-invalid') {
    verdict.className = 'cert-verdict bad';
    verdict.textContent = 'INVALID — ' + (certState.reason || 'verification failed.');
    if (title) title.textContent = 'Verification failed';
  } else if (kind === 'issued') {
    verdict.className = 'cert-verdict ok';
    verdict.textContent = 'ISSUED — sealed with the host signing key.';
    if (title) title.textContent = 'New certificate';
  } else {
    verdict.className = 'cert-verdict';
    verdict.textContent = kind;
    if (title) title.textContent = 'Result';
  }

  if (a) {
    facts.appendChild(certFact('Target', a.target));
    facts.appendChild(certFact('Grade', a.grade));
    facts.appendChild(certFact('Verdict', a.verdict));
    facts.appendChild(certFact('Risk', (a.risk_score === 0 || a.risk_score ? a.risk_score : '—') + '/100'));
    var c = a.counts || {};
    facts.appendChild(certFact('Findings', [c.critical || 0, c.high || 0, c.medium || 0, c.low || 0, c.info || 0].join(' · ')));
    facts.appendChild(certFact('Signer', (cert.public_key || '').slice(0, 16) + '…'));
    facts.appendChild(certFact('Signed at', cert.signed_at));
    if (a.covered && a.covered.length) facts.appendChild(certFact('Coverage', a.covered.join(', ')));
  }

  var findingsWrap = document.getElementById('certFindingsWrap');
  var findings = document.getElementById('certFindings');
  if (findings) certClear(findings);
  var list = (a && a.findings) || [];
  if (findingsWrap && findings) {
    if (list.length) {
      findingsWrap.classList.remove('hidden');
      list.forEach(function(f) {
        var li = document.createElement('li');
        var sev = document.createElement('span');
        sev.className = 'cert-sev cert-sev--' + String(f.severity || 'info').toLowerCase();
        sev.textContent = f.severity || 'info';
        var txt = document.createElement('span');
        txt.textContent = (f.id ? f.id + ' · ' : '') + (f.title || '');
        li.appendChild(sev);
        li.appendChild(txt);
        findings.appendChild(li);
      });
    } else {
      findingsWrap.classList.add('hidden');
    }
  }

  var htmlWrap = document.getElementById('certHtmlWrap');
  var frame = document.getElementById('certHtmlFrame');
  var html = certState.html || '';
  if (htmlWrap && frame) {
    if (html) {
      htmlWrap.classList.remove('hidden');
      frame.srcdoc = html;
    } else {
      htmlWrap.classList.add('hidden');
      frame.removeAttribute('srcdoc');
    }
  }

  var actions = document.getElementById('certActions');
  if (actions) {
    if (certState.cert || certState.html) actions.classList.remove('hidden');
    else actions.classList.add('hidden');
  }
  wrap.classList.remove('hidden');
}

function certReset() {
  certState = { cert: null, html: '', kind: '', fileName: '' };
  certStatus('Waiting for a file — a pentest report or a certificate.', '');
  var wrap = document.getElementById('certResult');
  if (wrap) wrap.classList.add('hidden');
  var actions = document.getElementById('certActions');
  if (actions) actions.classList.add('hidden');
  var input = document.getElementById('certFile');
  if (input) input.value = '';
}

function certEnv(err) {
  certStatus(err && err.error ? err.error : 'Request failed.', 'bad');
}

function certVerify(raw, obj) {
  certStatus('Checking the signature…', 'busy');
  fetch(API + '/api/certificate/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: raw
  }).then(function(r) { return r.json(); }).then(function(res) {
    certState.cert = obj;
    certState.html = obj.html || '';
    certState.certId = res.certificate_id || '';
    if (String(res.valid) === 'true') {
      certStatus('Valid certificate.', 'ok');
      certShowResult('verify-valid', obj);
      toast('Certificate is valid', 'ok');
    } else {
      certState.reason = res.detail || 'signature mismatch';
      certStatus('Invalid: ' + certState.reason, 'bad');
      certShowResult('verify-invalid', obj);
    }
  }).catch(function() {
    certStatus('Could not reach the dashboard API.', 'bad');
  });
}

// Verifies a load-run attestation bundle (the JSON the Overview card hands
// out). The bundle carries the coordinator signature, the per-worker commit
// signatures and the aggregates, so it can be audited on its own; without the
// sample sidecar the per-record replay is skipped and reported as such.
function certVerifyAttestation(raw) {
  certStatus('Checking the bundle signature…', 'busy');
  fetch(API + '/api/attestation/verify-upload', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: raw
  }).then(function(r) {
    return r.json().then(function(body) {
      if (!r.ok) throw body;
      return body;
    });
  }).then(function(res) {
    certShowAttestation(res);
  }).catch(function(err) {
    certStatus((err && err.reason) || 'Could not verify this bundle.', 'bad');
  });
}

function certShowAttestation(res) {
  var wrap = document.getElementById('certResult');
  var title = document.getElementById('certResultTitle');
  var verdict = document.getElementById('certVerdict');
  var facts = document.getElementById('certFacts');
  if (!wrap || !verdict || !facts) return;

  certClear(facts);
  var ok = !!res.valid;
  verdict.className = 'cert-verdict ' + (ok ? 'ok' : 'bad');
  if (ok) {
    verdict.textContent = 'VALID — the bundle signature and its internal cross-sums check out.';
    certStatus('Attestation bundle verified.', 'ok');
  } else {
    verdict.textContent = 'INVALID — ' + (res.reason || 'verification failed.');
    certStatus('Attestation bundle failed verification.', 'bad');
  }
  if (title) title.textContent = 'Attestation bundle';

  var s = res.summary || {};
  facts.appendChild(certFact('Workers', (s.workers || res.workers || 0) + ' · ' + (s.workersOK || 0) + ' verified, ' + (s.workersFailed || 0) + ' failed'));
  facts.appendChild(certFact('Checks', (s.checksRun || 0) + ' run · ' + (s.checksFailed || 0) + ' failed'));
  facts.appendChild(certFact('Bundle digest', res.bundleDigest ? String(res.bundleDigest).slice(0, 32) + '…' : '\u2014'));
  if (res.samplesAbsent) {
    facts.appendChild(certFact('Sample evidence', 'not supplied — per-record replay skipped'));
  }

  var findingsWrap = document.getElementById('certFindingsWrap');
  if (findingsWrap) findingsWrap.classList.add('hidden');
  var htmlWrap = document.getElementById('certHtmlWrap');
  if (htmlWrap) htmlWrap.classList.add('hidden');
  var actions = document.getElementById('certActions');
  if (actions) actions.classList.add('hidden');

  wrap.classList.remove('hidden');
  toast(ok ? 'Attestation bundle is valid' : 'Attestation bundle is invalid', ok ? 'ok' : 'error');
}

/* --------------------------------------------------------------------------
   Latest pentest -> certificate.

   The dashboard seals a certificate as soon as a pentest finishes, and
   remembers the scan. This card puts that result one click away on the
   Certificate page: no file to hunt for, no JSON to export first.
   -------------------------------------------------------------------------- */
var certLatest = null;

function certLatestStatus(msg, cls) {
  var el = document.getElementById('certLatestStatus');
  if (!el) return;
  el.textContent = msg || '';
  el.className = 'cert-status' + (cls ? ' ' + cls : '');
}

function certLoadLatest() {
  var wrap = document.getElementById('certLatest');
  if (!wrap) return;
  fetch(API + '/api/pentest/latest', { headers: { 'Accept': 'application/json' } })
    .then(function(r) { return r.json(); })
    .then(function(d) {
      if (!d || !d.exists) {
        certLatest = null;
        wrap.classList.add('hidden');
        return;
      }
      certLatest = d;
      certRenderLatest(d);
      wrap.classList.remove('hidden');
    })
    .catch(function() {
      certLatest = null;
      wrap.classList.add('hidden');
    });
}

function certRenderLatest(d) {
  var facts = document.getElementById('certLatestFacts');
  var note = document.getElementById('certLatestNote');
  if (facts) {
    certClear(facts);
    facts.appendChild(certFact('Target', d.target));
    facts.appendChild(certFact('Scanned', d.scanned_at));
    facts.appendChild(certFact('Grade', (d.grade || '\u2014') + ' \u00b7 risk ' + (d.risk_score || 0) + '/100'));
    facts.appendChild(certFact('Coverage', (d.tested || 0) + ' of ' + (d.total || 0) + ' categories'));
    facts.appendChild(certFact('Findings', (d.findings || 0) + ' \u2014 ' +
      (d.critical || 0) + ' critical, ' + (d.high || 0) + ' high, ' +
      (d.medium || 0) + ' medium, ' + (d.low || 0) + ' low, ' + (d.info || 0) + ' info'));
    facts.appendChild(certFact('Certificate', d.certificate_id || 'not issued'));
  }
  if (note) {
    note.textContent = d.certificate_note ||
      (d.dry_run ? 'This was a dry run \u2014 nothing was sent, so there is no evidence to certify.' : '');
  }

  var issued = !!d.certificate_id;
  var issue = document.getElementById('btnCertLatestIssue');
  var view = document.getElementById('btnCertLatestView');
  var pdf = document.getElementById('btnCertLatestPdf');
  var html = document.getElementById('btnCertLatestHtml');
  if (issue) issue.classList.toggle('hidden', issued);
  if (view) view.classList.toggle('hidden', !issued);
  if (pdf) pdf.classList.toggle('hidden', !issued);
  if (html) html.classList.toggle('hidden', !issued);
}

/* Issue a certificate from the remembered scan. The report travels as the
   request body, exactly like a dropped file would. */
function certIssueLatest() {
  if (!certLatest || !certLatest.report) {
    certLatestStatus('There is no pentest report to certify.', 'bad');
    return;
  }
  var issuer = document.getElementById('certIssuer') ? document.getElementById('certIssuer').value : '';
  var experimentRef = document.getElementById('certExperiment') ? document.getElementById('certExperiment').value : '';
  certLatestStatus('Issuing a certificate for the last pentest\u2026', 'busy');
  certIssueApi(JSON.stringify(certLatest.report), issuer, experimentRef);
}

/* Open the certificate that belongs to the last pentest in the result panel. */
function certViewLatest() {
  if (!certLatest || !certLatest.certificate_id) return;
  var id = certLatest.certificate_id;
  certLatestStatus('Loading certificate ' + id + '\u2026', 'busy');
  fetch(API + '/api/certificate/download/' + encodeURIComponent(id) + '?format=json')
    .then(function(r) { return r.json(); })
    .then(function(cert) {
      certState.cert = cert;
      certState.certId = cert.certificate_id || id;
      certState.html = cert.html || '';
      certState.fileName = id + '.json';
      certLatestStatus('Certificate ' + id + ' issued from the last pentest.', 'ok');
      certStatus('Certificate issued from the last pentest.', 'ok');
      certShowResult('issued', cert);
      var actions = document.getElementById('certActions');
      if (actions) actions.classList.remove('hidden');
    })
    .catch(function() {
      certLatestStatus('Could not load the certificate.', 'bad');
    });
}

function certHandleFile(file) {
  if (!file) return;
  certState.fileName = file.name || 'certificate';
  certStatus('Reading ' + certState.fileName + '…', 'busy');
  var reader = new FileReader();
  reader.onload = function() {
    var raw = String(reader.result || '');
    var obj;
    try {
      obj = JSON.parse(raw);
    } catch (e) {
      certStatus('That file is not JSON — expected a pentest report or a certificate.', 'bad');
      return;
    }
    if (!obj || typeof obj !== 'object') {
      certStatus('That file is not a pentest report or a certificate.', 'bad');
      return;
    }
    if (obj.assessment && obj.signature) {
      certVerify(raw, obj);
      return;
    }
    // The Overview Attestation card downloads a signed load-run bundle. It is
    // not a certificate, but it is verifiable evidence — check it here instead
    // of telling the operator their own file is "not a certificate".
    if (obj.format === 'vpmp/v1' || (obj.workers && obj.aggregate && obj.signature && obj.signature.sig)) {
      certVerifyAttestation(raw);
      return;
    }
    if (obj.target) {
      var issuer = document.getElementById('certIssuer') ? document.getElementById('certIssuer').value : 'stress-strike assessment';
      var experimentRef = document.getElementById('certExperiment') ? document.getElementById('certExperiment').value : '';
      certIssueApi(raw, issuer, experimentRef);
      return;
    }
    certStatus('JSON, but not a file we can verify — expected a pentest report ("target"), a certificate ("assessment" + "signature"), or an attestation bundle ("format": "vpmp/v1").', 'bad');
  };
  reader.onerror = function() { certStatus('Could not read the file.', 'bad'); };
  reader.readAsText(file);
}

function certDownload(name, text, type) {
  var blob = new Blob([text], { type: type || 'application/octet-stream' });
  var url = URL.createObjectURL(blob);
  var a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(function() { URL.revokeObjectURL(url); }, 2000);
}

function wireCertificate() {
  var drop = document.getElementById('certDrop');
  var input = document.getElementById('certFile');
  var pick = document.getElementById('btnCertPick');
  if (!drop || !input) return;

  var openPicker = function(ev) {
    if (ev) { ev.preventDefault(); ev.stopPropagation(); }
    input.click();
  };
  drop.addEventListener('click', openPicker);
  drop.addEventListener('keydown', function(ev) {
    if (ev.key === 'Enter' || ev.key === ' ') openPicker(ev);
  });
  if (pick) pick.addEventListener('click', openPicker);
  input.addEventListener('change', function() {
    if (input.files && input.files[0]) certHandleFile(input.files[0]);
  });

  ['dragenter', 'dragover'].forEach(function(name) {
    drop.addEventListener(name, function(ev) {
      ev.preventDefault();
      drop.classList.add('is-over');
    });
  });
  ['dragleave', 'drop'].forEach(function(name) {
    drop.addEventListener(name, function(ev) {
      ev.preventDefault();
      drop.classList.remove('is-over');
    });
  });
  drop.addEventListener('drop', function(ev) {
    var files = ev.dataTransfer && ev.dataTransfer.files;
    if (files && files[0]) certHandleFile(files[0]);
  });

  var dlJson = document.getElementById('btnCertDownloadJson');
  if (dlJson) dlJson.addEventListener('click', function() {
    if (!certState.certId) return;
    certDownloadApi(certState.certId, 'json');
  });
  var dlHtml = document.getElementById('btnCertDownloadHtml');
  if (dlHtml) dlHtml.addEventListener('click', function() {
    if (!certState.certId) return;
    certDownloadApi(certState.certId, 'html');
  });
  var dlPdf = document.getElementById('btnCertDownloadPdf');
  if (dlPdf) dlPdf.addEventListener('click', function() {
    if (!certState.certId) return;
    certDownloadApi(certState.certId, 'pdf');
  });
  var reset = document.getElementById('btnCertReset');
  if (reset) reset.addEventListener('click', certReset);

  /* ---- Latest pentest ---- */
  var latestIssue = document.getElementById('btnCertLatestIssue');
  if (latestIssue) latestIssue.addEventListener('click', certIssueLatest);
  var latestView = document.getElementById('btnCertLatestView');
  if (latestView) latestView.addEventListener('click', certViewLatest);
  var latestPdf = document.getElementById('btnCertLatestPdf');
  if (latestPdf) latestPdf.addEventListener('click', function() {
    if (certLatest && certLatest.certificate_id) certDownloadApi(certLatest.certificate_id, 'pdf');
  });
  var latestHtml = document.getElementById('btnCertLatestHtml');
  if (latestHtml) latestHtml.addEventListener('click', function() {
    if (certLatest && certLatest.certificate_id) certDownloadApi(certLatest.certificate_id, 'html');
  });

  /* ---- Tabs ---- */
  var tabs = document.querySelectorAll('.cert-tab');
  var panels = document.querySelectorAll('.cert-panel');
  function showTab(name) {
    tabs.forEach(function(t) {
      t.classList.toggle('active', t.id === 'tabCert' + name);
    });
    panels.forEach(function(p) {
      p.classList.toggle('active', p.id === 'panelCert' + name);
    });
    if (name === 'History') certLoadHistory();
  }
  tabs.forEach(function(t) {
    t.addEventListener('click', function() {
      showTab(t.id.replace('tabCert', ''));
    });
  });

  /* ---- Verify drop zone ---- */
  var vdrop = document.getElementById('certVerifyDrop');
  var vinput = document.getElementById('certVerifyFile');
  var vpick = document.getElementById('btnCertVerifyPick');
  if (vdrop && vinput) {
    var vopen = function(ev) {
      if (ev) { ev.preventDefault(); ev.stopPropagation(); }
      vinput.click();
    };
    vdrop.addEventListener('click', vopen);
    vdrop.addEventListener('keydown', function(ev) {
      if (ev.key === 'Enter' || ev.key === ' ') vopen(ev);
    });
    if (vpick) vpick.addEventListener('click', vopen);
    vinput.addEventListener('change', function() {
      if (vinput.files && vinput.files[0]) certVerifyFile(vinput.files[0]);
    });
    ['dragenter', 'dragover'].forEach(function(name) {
      vdrop.addEventListener(name, function(ev) {
        ev.preventDefault();
        vdrop.classList.add('is-over');
      });
    });
    ['dragleave', 'drop'].forEach(function(name) {
      vdrop.addEventListener(name, function(ev) {
        ev.preventDefault();
        vdrop.classList.remove('is-over');
      });
    });
    vdrop.addEventListener('drop', function(ev) {
      var files = ev.dataTransfer && ev.dataTransfer.files;
      if (files && files[0]) certVerifyFile(files[0]);
    });
  }
}

/* ---- Issue: POST /api/certificate/generate ---- */
function certIssueApi(raw, issuer, experimentRef) {
  certStatus('Issuing signed certificate…', 'busy');
  var body = JSON.stringify({ report: raw, issuer: issuer, experiment_reference: experimentRef });
  fetch(API + '/api/certificate/generate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body
  }).then(function(r) {
    return r.json().then(function(j) { return { ok: r.ok, body: j }; });
  }).then(function(res) {
    if (!res.ok) {
      certStatus((res.body && res.body.error) || 'Could not issue certificate.', 'bad');
      return;
    }
    if (!res.body || !res.body.certificate_id) {
      certStatus('Server returned no certificate.', 'bad');
      return;
    }
    certState.cert = res.body;
    certState.certId = res.body.certificate_id;
    certState.html = res.body.html || '';
    certStatus('Certificate issued.', 'ok');
    certShowResult('issued', res.body);
    toast('Certificate issued', 'ok');
    // The latest-pentest card may now have a certificate to show.
    certLoadLatest();
    var actions = document.getElementById('certActions');
    if (actions) actions.classList.remove('hidden');

    // Auto-download certificate files
    if (certState.certId) {
      // Download JSON
      var urlJson = API + '/api/certificate/download/' + encodeURIComponent(certState.certId) + '?format=json';
      var aJson = document.createElement('a');
      aJson.href = urlJson;
      aJson.download = certState.certId + '.json';
      document.body.appendChild(aJson);
      aJson.click();
      document.body.removeChild(aJson);

      // Download HTML
      var urlHtml = API + '/api/certificate/download/' + encodeURIComponent(certState.certId) + '?format=html';
      var aHtml = document.createElement('a');
      aHtml.href = urlHtml;
      aHtml.download = certState.certId + '.html';
      document.body.appendChild(aHtml);
      aHtml.click();
      document.body.removeChild(aHtml);

      // Download PDF
      var urlPdf = API + '/api/certificate/download/' + encodeURIComponent(certState.certId) + '?format=pdf';
      var aPdf = document.createElement('a');
      aPdf.href = urlPdf;
      aPdf.download = certState.certId + '.pdf';
      document.body.appendChild(aPdf);
      aPdf.click();
      document.body.removeChild(aPdf);
    }
  }).catch(function() {
    certStatus('Could not reach the dashboard API.', 'bad');
  });
}

/* ---- Download: GET /api/certificate/download/:id?format=json|html|pdf ---- */
function certDownloadApi(id, format) {
  var url = API + '/api/certificate/download/' + encodeURIComponent(id) + '?format=' + format;
  var a = document.createElement('a');
  a.href = url;
  a.download = id + '.' + format;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}

/* ---- Verify: POST /api/certificate/verify ---- */
function certVerifyFile(file) {
  if (!file) return;
  var reader = new FileReader();
  reader.onload = function() {
    var raw = String(reader.result || '');
    var obj;
    try { obj = JSON.parse(raw); } catch (e) {
      certVerifyStatusMsg('That file is not JSON.', 'bad');
      return;
    }
    fetch(API + '/api/certificate/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: raw
    }).then(function(r) { return r.json(); }).then(function(res) {
      var wrap = document.getElementById('certVerifyResult');
      var verdict = document.getElementById('certVerifyVerdict');
      var facts = document.getElementById('certVerifyFacts');
      var chain = document.getElementById('certVerifyChain');
      if (!wrap || !verdict || !facts) return;
      while (facts.firstChild) facts.removeChild(facts.firstChild);
      while (chain.firstChild) chain.removeChild(chain.firstChild);
      wrap.classList.remove('hidden');
      if (res.valid) {
        verdict.className = 'cert-verdict ok';
        verdict.textContent = 'VALID — signature and document hash match.';
        certAppendFact(facts, 'Certificate ID', res.certificate_id);
        certAppendFact(facts, 'Target', res.target);
        certAppendFact(facts, 'Grade', res.grade);
        certAppendFact(facts, 'Verdict', res.verdict);
        certAppendFact(facts, 'Risk score', res.risk_score + '/100');
        certAppendFact(facts, 'Signed at', res.signed_at);
        certAppendFact(facts, 'Experiment', res.experiment_reference || '—');
        certAppendFact(facts, 'Findings', res.findings_count);
        certAppendFact(facts, 'Covered', (res.covered || []).join(', ') || '—');
        certState.certId = res.certificate_id || '';
        var chainEl = document.createElement('div');
        chainEl.className = 'chain-ok';
        chainEl.textContent = 'Hash chain: ' + (res.chain_intact ? 'INTACT' : 'BROKEN');
        chain.appendChild(chainEl);
        certVerifyStatusMsg('Certificate is valid.', 'ok');
        toast('Certificate verified — VALID', 'ok');
      } else {
        verdict.className = 'cert-verdict bad';
        verdict.textContent = 'INVALID — ' + (res.reason || 'verification failed.');
        certVerifyStatusMsg('Certificate is invalid.', 'bad');
        toast('Certificate verification failed', 'error');
      }
    }).catch(function() {
      certVerifyStatusMsg('Could not reach the dashboard API.', 'bad');
    });
  };
  reader.readAsText(file);
}

function certVerifyStatusMsg(msg, cls) {
  var el = document.getElementById('certVerifyStatus');
  if (!el) return;
  el.textContent = msg || '';
  el.className = 'cert-status' + (cls ? ' ' + cls : '');
}

function certAppendFact(parent, label, value) {
  var row = document.createElement('div');
  row.style.display = 'flex';
  row.style.justifyContent = 'space-between';
  row.style.borderBottom = '1px solid var(--border)';
  row.style.padding = '6px 0';
  var lb = document.createElement('span');
  lb.textContent = label;
  lb.style.color = 'var(--text-2)';
  lb.style.fontFamily = 'var(--font-mono)';
  lb.style.fontSize = '12px';
  var vb = document.createElement('span');
  vb.textContent = value === undefined || value === null ? '—' : String(value);
  vb.style.color = 'var(--text-0)';
  vb.style.fontFamily = 'var(--font-mono)';
  vb.style.fontSize = '12px';
  row.appendChild(lb);
  row.appendChild(vb);
  parent.appendChild(row);
}

/* ---- History: GET /api/certificate/history ---- */
function certLoadHistory() {
  var body = document.getElementById('certHistoryBody');
  var chainStatus = document.getElementById('certChainStatus');
  if (!body) return;
  body.textContent = '';
  if (chainStatus) chainStatus.textContent = 'Loading…';
  fetch(API + '/api/certificate/history', { cache: 'no-store' })
    .then(function(r) { return r.json(); })
    .then(function(res) {
      var certs = res.certificates || [];
      if (chainStatus) chainStatus.textContent = 'Certificates: ' + res.count;
      certs.forEach(function(c) {
        var tr = document.createElement('tr');
        var tdId = document.createElement('td'); tdId.textContent = c.certificate_id;
        var tdTarget = document.createElement('td'); tdTarget.textContent = c.target;
        var tdGrade = document.createElement('td'); tdGrade.textContent = c.grade;
        var tdVerdict = document.createElement('td'); tdVerdict.textContent = c.verdict;
        var tdRisk = document.createElement('td'); tdRisk.textContent = c.risk_score + '/100';
        var tdSigned = document.createElement('td'); tdSigned.textContent = c.signed_at;
        var tdDl = document.createElement('td');
        var btn = document.createElement('button');
        btn.className = 'btn btn-ghost';
        btn.textContent = 'JSON';
        btn.addEventListener('click', function() { certDownloadApi(c.certificate_id, 'json'); });
        tdDl.appendChild(btn);
        tr.appendChild(tdId); tr.appendChild(tdTarget); tr.appendChild(tdGrade);
        tr.appendChild(tdVerdict); tr.appendChild(tdRisk); tr.appendChild(tdSigned);
        tr.appendChild(tdDl);
        body.appendChild(tr);
      });
    }).catch(function() {
      if (chainStatus) chainStatus.textContent = 'Failed to load history.';
    });
}

/* ==========================================================================
   ADMIN PAGE — status, unlock, lock, countdown
   ========================================================================== */
var adminStatusTimer = null;
var adminTickTimer = null;
var adminExpiresMs = 0;

function adminSetStatus(msg, cls) {
  var el = document.getElementById('adminStatus');
  if (!el) return;
  el.textContent = msg || '';
  el.className = 'admin-status' + (cls ? ' ' + cls : '');
}

function adminWarning(msg) {
  var el = document.getElementById('adminWarning');
  if (!el) return;
  if (msg) { el.textContent = msg; el.classList.remove('hidden'); }
  else { el.textContent = ''; el.classList.add('hidden'); }
}

function adminRenderStatus(st) {
  var value = document.getElementById('adminStateValue');
  var countdown = document.getElementById('adminCountdown');
  if (!value) return;
  if (st && st.active) {
    value.textContent = 'ON — authorization bypassed';
    value.className = 'admin-state-value on';
    adminExpiresMs = st.expires_at ? Date.parse(st.expires_at) : 0;
    if (countdown) countdown.classList.remove('hidden');
    adminTick();
  } else {
    value.textContent = 'OFF — authorization enforced';
    value.className = 'admin-state-value off';
    adminExpiresMs = 0;
    if (countdown) { countdown.classList.add('hidden'); countdown.textContent = ''; }
  }
}

function adminTick() {
  var countdown = document.getElementById('adminCountdown');
  if (!countdown) return;
  if (!adminExpiresMs) { countdown.classList.add('hidden'); return; }
  var left = Math.max(0, Math.round((adminExpiresMs - Date.now()) / 1000));
  if (left <= 0) {
    countdown.textContent = 'Bypass expired — authorization is enforced again.';
    countdown.classList.remove('hidden');
    adminFetchStatus();
    return;
  }
  var m = Math.floor(left / 60);
  var s = left % 60;
  countdown.textContent = 'Bypass active — ' + m + 'm ' + (s < 10 ? '0' : '') + s + 's left';
  countdown.classList.remove('hidden');
}

function adminFetchStatus() {
  fetch(API + '/api/admin/status', { cache: 'no-store' })
    .then(function(r) { return r.json(); })
    .then(function(st) { adminRenderStatus(st); })
    .catch(function() { adminSetStatus('Could not read the admin status.', 'bad'); });
}

function adminStart() {
  if (adminStatusTimer) return;
  adminFetchStatus();
  adminStatusTimer = setInterval(adminFetchStatus, 10000);
  adminTickTimer = setInterval(adminTick, 1000);
}

function adminStop() {
  if (adminStatusTimer) { clearInterval(adminStatusTimer); adminStatusTimer = null; }
  if (adminTickTimer) { clearInterval(adminTickTimer); adminTickTimer = null; }
}

function wireAdmin() {
  var form = document.getElementById('adminForm');
  var lock = document.getElementById('btnAdminLock');
  if (form) form.addEventListener('submit', function(ev) {
    ev.preventDefault();
    var minutes = parseInt((document.getElementById('adminMinutes') || {}).value || '15', 10);
    if (!minutes || minutes < 1) minutes = 15;
    var codeInput = document.getElementById('adminCode');
    var code = ((codeInput || {}).value || '').trim();
    if (!code) {
      adminSetStatus('Enter the admin code shown by `stress-strike admin code`.', 'bad');
      adminWarning('Admin bypass is OFF. Authorization is enforced.');
      return;
    }
    adminSetStatus('Opening the bypass window…', '');
    fetch(API + '/api/admin/unlock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: code, minutes: minutes })
    }).then(function(r) {
      return r.json().then(function(j) { return { ok: r.ok, body: j }; });
    }).then(function(res) {
      if (!res.ok) {
        adminSetStatus((res.body && res.body.error) || 'The code was rejected.', 'bad');
        adminWarning('Admin bypass is OFF. Authorization is enforced.');
        return;
      }
      var st = res.body.status || {};
      adminRenderStatus(st);
      adminSetStatus('Bypass is ON. Turn it off as soon as the work is done.', 'ok');
      adminWarning(res.body.warning || '');
      var input = document.getElementById('adminCode');
      if (input) input.value = '';
      toast('Admin bypass is ON', 'ok');
    }).catch(function() {
      adminSetStatus('Could not reach the dashboard API.', 'bad');
    });
  });

  if (lock) lock.addEventListener('click', function() {
    adminSetStatus('Closing the bypass window…', '');
    fetch(API + '/api/admin/lock', { method: 'POST' })
      .then(function(r) { return r.json(); })
      .then(function(res) {
        adminRenderStatus(res.status || {});
        adminSetStatus('Bypass is OFF. Authorization is enforced.', 'ok');
        adminWarning('');
        toast('Admin bypass is OFF', 'ok');
      })
      .catch(function() { adminSetStatus('Could not reach the dashboard API.', 'bad'); });
  });
}

/* ---- Boot the shell ---- */
wireNav();
wireAdminReveal();
wireCertificate();
wireAdmin();

// The sidebar prints the build it is talking to, so "did I just install the
// new binary?" is answerable without opening a terminal.
(function bootVersion() {
  var el = document.getElementById('sbVersion');
  if (!el) return;
  fetch(API + '/api/version', { cache: 'no-store' })
    .then(function(r) { return r.json(); })
    .then(function(res) {
      if (res && res.version) el.textContent = res.version;
    })
    .catch(function() { el.textContent = '?'; });
})();

(function bootView() {
  var v = savedView();
  if (!v) return;
  if (v === 'viewAdmin') revealAdmin(false);
  showView(v, { silent: true });
})();
