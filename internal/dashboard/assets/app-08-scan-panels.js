/* ==========================================================================
   app-08-scan-panels.js — part 08 of 13 of the dashboard bundle.

   Scan panels — OWASP Top 10, demo store

   Every file in this directory is concatenated, in name order, into the
   single /app.js the page loads. They share one global scope, so a
   function declared here is visible to later parts — order matters.
   Keep one feature per file: a part that grows past ~900 lines is a
   signal to split it, not to let it grow (see assets_test.go).
   ========================================================================== */

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
