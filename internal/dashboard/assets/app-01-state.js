/* ==========================================================================
   app-01-state.js — part 01 of 14 of the dashboard bundle.

   STATE, safe localStorage, WebSocket

   Every file in this directory is concatenated, in name order, into the
   single /app.js the page loads. They share one global scope, so a
   function declared here is visible to later parts — order matters.
   Keep one feature per file: a part that grows past ~900 lines is a
   signal to split it, not to let it grow (see assets_test.go).
   ========================================================================== */

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
