/* ==========================================================================
   app-03-actions.js — part 03 of 13 of the dashboard bundle.

   ACTIONS — run control over the control API

   Every file in this directory is concatenated, in name order, into the
   single /app.js the page loads. They share one global scope, so a
   function declared here is visible to later parts — order matters.
   Keep one feature per file: a part that grows past ~900 lines is a
   signal to split it, not to let it grow (see assets_test.go).
   ========================================================================== */

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
