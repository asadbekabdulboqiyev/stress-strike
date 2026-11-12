/* ==========================================================================
   app-04-onboarding.js — part 04 of 13 of the dashboard bundle.

   ONBOARDING, run summary, toast, sliders

   Every file in this directory is concatenated, in name order, into the
   single /app.js the page loads. They share one global scope, so a
   function declared here is visible to later parts — order matters.
   Keep one feature per file: a part that grows past ~900 lines is a
   signal to split it, not to let it grow (see assets_test.go).
   ========================================================================== */

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
