/* ==========================================================================
   app-10-scanners.js — part 10 of 14 of the dashboard bundle.

   Crawler, fuzz, subdomain, port, dir, TLS, JWT, GraphQL, WebSocket

   Every file in this directory is concatenated, in name order, into the
   single /app.js the page loads. They share one global scope, so a
   function declared here is visible to later parts — order matters.
   Keep one feature per file: a part that grows past ~900 lines is a
   signal to split it, not to let it grow (see assets_test.go).
   ========================================================================== */

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
