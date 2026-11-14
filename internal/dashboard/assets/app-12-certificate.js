/* ==========================================================================
   app-12-certificate.js — part 12 of 14 of the dashboard bundle.

   CERTIFICATE page — issue, verify, history

   Every file in this directory is concatenated, in name order, into the
   single /app.js the page loads. They share one global scope, so a
   function declared here is visible to later parts — order matters.
   Keep one feature per file: a part that grows past ~900 lines is a
   signal to split it, not to let it grow (see assets_test.go).
   ========================================================================== */

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
      certState.reason = res.reason || res.detail || 'signature mismatch';
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
      var issuer = document.getElementById('certIssuer') ? document.getElementById('certIssuer').value : 'Sift assessment';
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
  var reportObj;
  try {
    reportObj = (typeof raw === 'string') ? JSON.parse(raw) : raw;
  } catch (e) {
    certStatus('That file is not valid JSON.', 'bad');
    return;
  }
  var body = JSON.stringify({ report: reportObj, issuer: issuer, experiment_reference: experimentRef });
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
