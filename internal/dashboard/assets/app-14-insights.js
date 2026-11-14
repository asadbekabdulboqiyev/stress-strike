/* ==========================================================================
   app-14-insights.js — part 14 of 14 of the dashboard bundle.

   INSIGHTS — Digital Twin, Host X-Ray, and Bounty triage helpers

   Every file in this directory is concatenated, in name order, into the
   single /app.js the page loads. They share one global scope, so a
   function declared here is visible to later parts — order matters.
   Keep one feature per file: a part that grows past ~900 lines is a
   signal to split it, not to let it grow (see assets_test.go).
   ========================================================================== */

/* app-14-insights.js — Insights view (twin/xray/bounty helpers) */

(function () {
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/\x22/g, '&quot;');
  }

  function setOut(id, html, cls) {
    var el = document.getElementById(id);
    if (!el) return;
    el.className = 'ins-out' + (cls ? ' ' + cls : '');
    el.innerHTML = html;
  }

  function setText(id, text, cls) {
    var el = document.getElementById(id);
    if (!el) return;
    el.className = 'ins-out' + (cls ? ' ' + cls : '');
    el.textContent = text || '';
  }

  async function api(path, opts) {
    var r = await fetch(API + path, opts || {});
    if (typeof guardStatus === 'function' && guardStatus(r)) throw new Error('locked');
    var ct = (r.headers.get('content-type') || '');
    var data = ct.indexOf('application/json') >= 0 ? await r.json() : { ok: r.ok, error: await r.text() };
    if (!r.ok && data && !data.error) data.error = 'HTTP ' + r.status;
    return data;
  }

  async function loadXrayCaps() {
    setOut('xrayCapsOut', 'Loading…');
    try {
      var d = await api('/api/insights/xray/capabilities');
      if (!d || d.ok === false) throw new Error((d && d.error) || 'failed');
      var c = d.capabilities || {};
      var rows = [
        ['Platform', (c.os || '?') + '/' + (c.arch || '?')],
        ['Evidence source', c.source || '—'],
        ['/proc available', c.proc_available ? 'yes' : 'no'],
        ['Load avg', c.proc_loadavg ? 'yes' : 'no'],
        ['Meminfo', c.proc_meminfo ? 'yes' : 'no'],
        ['Net dev', c.proc_netdev ? 'yes' : 'no'],
        ['Stat', c.proc_stat ? 'yes' : 'no'],
        ['Pressure (PSI)', c.proc_pressure ? 'yes' : 'no'],
        ['BTF vmlinux', c.btf_vmlinux ? 'yes' : 'no'],
        ['Deep eBPF ready', (c.deep_tracing_possible ? 'yes' : 'no') + ' (informational; never loaded)']
      ];
      var html = '<table class="ins-table"><tbody>' + rows.map(function (r) {
        return '<tr><th>' + esc(r[0]) + '</th><td>' + esc(r[1]) + '</td></tr>';
      }).join('') + '</tbody></table>';
      if (c.notes && c.notes.length) {
        html += '<ul class="ins-notes">' + c.notes.map(function (n) { return '<li>' + esc(n) + '</li>'; }).join('') + '</ul>';
      }
      if (d.note) html += '<p class="ins-note">' + esc(d.note) + '</p>';
      setOut('xrayCapsOut', html, 'ok');
    } catch (e) {
      if (e && e.message === 'locked') return;
      setText('xrayCapsOut', 'Error: ' + (e && e.message ? e.message : String(e)), 'err');
    }
  }

  function parseJSONFrom(id) {
    var el = document.getElementById(id);
    var txt = el ? (el.value || '').trim() : '';
    if (!txt) throw new Error('input is empty');
    return JSON.parse(txt);
  }

  async function doTwinFit() {
    setOut('twinFitOut', 'Fitting model…');
    try {
      var report = parseJSONFrom('twinReportJson');
      var target = parseFloat((document.getElementById('twinTargetP99') || {}).value || '0') || 0;
      var d = await api('/api/insights/twin/fit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ report: report, target_p99_ms: target })
      });
      if (!d || d.ok === false) throw new Error((d && d.error) || 'fit failed');
      var m = d.model || {};
      var w = m.workload || {}, c = m.curve || {};
      var html = '<div class="ins-kv">' +
        kv('Confidence', m.confidence) +
        kv('Observed RPS', num(w.rps)) +
        kv('Concurrency (est.)', num(w.concurrency)) +
        kv('Error rate', num(w.error_rate_pct) + '%') +
        kv('Baseline p99', num(c && c.baseline ? c.baseline.p99_ms : null) + ' ms') +
        kv('Capacity (est.)', num(c.capacity_rps) + ' rps') +
        '</div>';
      if (d.note) html += '<p class="ins-note">' + esc(d.note) + '</p>';
      html += '<details class="ins-details"><summary>Model JSON</summary><pre>' + esc(JSON.stringify(m, null, 2)) + '</pre></details>';
      setOut('twinFitOut', html, 'ok');
      window.__twinLastModel = m;
    } catch (e) {
      if (e && e.message === 'locked') return;
      setText('twinFitOut', 'Error: ' + (e && e.message ? e.message : String(e)), 'err');
    }
  }

  function kv(k, v) {
    return '<div class="ins-kv-row"><span class="k">' + esc(k) + '</span><span class="v">' + esc(v == null || v === '' ? '—' : v) + '</span></div>';
  }
  function num(v) {
    if (v == null || !isFinite(v)) return '—';
    var n = Number(v);
    return Math.abs(n) >= 100 ? n.toFixed(1) : n.toFixed(2);
  }

  async function doTwinSim() {
    setOut('twinSimOut', 'Simulating…');
    try {
      var model = parseJSONFrom('twinModelJson');
      var scenario = (document.getElementById('twinScenario') || {}).value || 'likely';
      var rps = parseFloat((document.getElementById('twinRps') || {}).value || '0') || 0;
      var iters = parseInt((document.getElementById('twinIters') || {}).value || '200', 10) || 200;
      var payload = { model: model, scenario: scenario, iterations: iters, seed: 42 };
      if (rps > 0) payload.target_rps = rps;
      var d = await api('/api/insights/twin/simulate', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
      });
      if (!d || d.ok === false && !d.result) throw new Error((d && d.error) || 'simulation failed');
      var res = d.result || {};
      var sum = res.summary || {};
      var html = '<div class="ins-kv">' +
        kv('Scenario', res.scenario ? res.scenario.name : scenario) +
        kv('Risk', sum.risk_level) +
        kv('Breach probability', pct(sum.sla_probability_breach)) +
        kv('Predicted p99 (median)', num(sum.p99_ms ? sum.p99_ms.p50 : null) + ' ms') +
        kv('Predicted p99 (p95)', num(sum.p99_ms ? sum.p99_ms.p95 : null) + ' ms') +
        kv('Achieved RPS (median)', num(sum.achieved_rps ? sum.achieved_rps.p50 : null)) +
        kv('Utilization (median)', num(sum.utilization ? sum.utilization.p50 : null)) +
        '</div>';
      if (d.breach_gate) html += '<p class="ins-note err">Breach-probability gate tripped.</p>';
      if (d.note) html += '<p class="ins-note">' + esc(d.note) + '</p>';
      html += '<details class="ins-details"><summary>Result JSON</summary><pre>' + esc(JSON.stringify(res, null, 2)) + '</pre></details>';
      setOut('twinSimOut', html, d.breach_gate ? 'warn' : 'ok');
    } catch (e) {
      if (e && e.message === 'locked') return;
      setText('twinSimOut', 'Error: ' + (e && e.message ? e.message : String(e)), 'err');
    }
  }

  function pct(v) {
    if (v == null || !isFinite(v)) return '—';
    return (Number(v) * 100).toFixed(1) + '%';
  }

  async function doBountyValidate() {
    setOut('bountyValidateOut', 'Validating…');
    try {
      var manifest = parseJSONFrom('bountyManifestJson');
      var d = await api('/api/insights/bounty/validate', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ manifest: manifest })
      });
      if (!d) throw new Error('no response');
      var checks = d.checks || [];
      var html = '<div class="ins-kv">' + kv('Verdict', d.verdict) + kv('Package ID', d.package_id) + '</div>';
      if (checks.length) { html += renderChecks(checks); }
      if (d.reasons && d.reasons.length) html += '<ul class="ins-notes err"><li>' + d.reasons.map(esc).join('</li><li>') + '</li></ul>';
      if (d.notes && d.notes.length) html += '<ul class="ins-notes">' + d.notes.map(esc).join('</li><li>') + '</li></ul>';
      var cls = d.verdict === 'failed' ? 'err' : (d.verdict === 'verified' ? 'ok' : 'warn');
      setOut('bountyValidateOut', html, cls);
    } catch (e) {
      if (e && e.message === 'locked') return;
      setText('bountyValidateOut', 'Error: ' + (e && e.message ? e.message : String(e)), 'err');
    }
  }

  async function doBountyStatus() {
    setOut('bountyStatusOut', 'Replaying…');
    try {
      var events = parseJSONFrom('bountyEventsJson');
      if (!Array.isArray(events)) throw new Error('events must be a JSON array');
      var d = await api('/api/insights/bounty/status', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ events: events })
      });
      if (!d || d.ok === false) throw new Error((d && d.error) || 'failed');
      var html = '<div class="ins-kv">' + kv('Current state', d.state) + kv('Events', d.events) + '</div>';
      if (d.last) {
        html += '<div class="ins-kv" style="margin-top:8px">' + kv('Last actor', (d.last.actor || '') + ' (' + (d.last.role || '') + ')') + kv('Reason', d.last.reason || '—') + '</div>';
      }
      if (d.note) html += '<p class="ins-note">' + esc(d.note) + '</p>';
      setOut('bountyStatusOut', html, 'ok');
    } catch (e) {
      if (e && e.message === 'locked') return;
      setText('bountyStatusOut', 'Error: ' + (e && e.message ? e.message : String(e)), 'err');
    }
  }

  function renderChecks(checks) {
    checks = checks || [];
    if (!checks.length) return '';
    return '<table class="ins-table"><thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead><tbody>' +
      checks.map(function (c) { return '<tr><td>' + esc(c.name) + '</td><td class="st-' + esc(c.status) + '">' + esc(c.status) + '</td><td>' + esc(c.detail || '') + '</td></tr>'; }).join('') +
      '</tbody></table>';
  }

  async function doBountyVerifyUpload() {
    setOut('bountyValidateOut', 'Running full verification…');
    try {
      var mf = document.getElementById('bountyManifestFile');
      var af = document.getElementById('bountyArtifactFiles');
      var manifestText = '';
      if (mf && mf.files && mf.files[0]) {
        manifestText = await mf.files[0].text();
      } else {
        var ta = document.getElementById('bountyManifestJson');
        manifestText = ta ? (ta.value || '').trim() : '';
      }
      if (!manifestText) throw new Error('manifest JSON is required (paste or upload manifest file)');

      var fd = new FormData();
      fd.append('manifest', manifestText);
      var files = (af && af.files) ? af.files : [];
      for (var i = 0; i < files.length; i++) {
        // Use filename (may include relative path in some browsers); server sanitizes.
        fd.append('files', files[i], files[i].name);
      }
      var target = (document.getElementById('bountyTarget') || {}).value || '';
      var key = (document.getElementById('bountyKey') || {}).value || '';
      var skipCI = (document.getElementById('bountySkipCI') || {}).checked;
      if (target) fd.append('target', target);
      if (key) fd.append('key', key);
      if (skipCI) fd.append('skip_ci_check', 'true');

      var r = await fetch(API + '/api/insights/bounty/verify-upload', { method: 'POST', body: fd });
      if (typeof guardStatus === 'function' && guardStatus(r)) throw new Error('locked');
      var ct = (r.headers.get('content-type') || '');
      var d = ct.indexOf('application/json') >= 0 ? await r.json() : { ok: r.ok, error: await r.text() };
      if (!d) throw new Error('no response');

      var report = d.report || {};
      var verdict = d.verdict || report.verdict || 'unknown';
      var html = '<div class="ins-kv">' + kv('Verdict', verdict) + kv('Package ID', report.package_id || d.package_id) + kv('Uploaded files', d.uploaded_artifacts) + '</div>';
      html += renderChecks(report.checks || d.checks || []);
      if (report.reasons && report.reasons.length) html += '<ul class="ins-notes err"><li>' + report.reasons.map(esc).join('</li><li>') + '</li></ul>';
      var notes = (report.notes || []).concat(d.note ? [d.note] : []);
      if (notes.length) html += '<ul class="ins-notes">' + notes.map(esc).join('</li><li>') + '</li></ul>';
      if (report.attest) {
        html += '<details class="ins-details"><summary>Attestation summary</summary><pre>' + esc(JSON.stringify(report.attest, null, 2)) + '</pre></details>';
      }
      html += '<details class="ins-details"><summary>Verification report JSON</summary><pre>' + esc(JSON.stringify(report, null, 2)) + '</pre></details>';
      var cls = verdict === 'failed' ? 'err' : (verdict === 'verified' ? 'ok' : 'warn');
      setOut('bountyValidateOut', html, cls);
    } catch (e) {
      if (e && e.message === 'locked') return;
      setText('bountyValidateOut', 'Error: ' + (e && e.message ? e.message : String(e)), 'err');
    }
  }

  function parseDurationToNs(s) {
    if (s == null) return 0;
    if (typeof s === 'number' && isFinite(s)) return Math.round(s * 1e9);
    s = String(s).trim();
    if (!s) return 0;
    // Go duration string: e.g. 30s, 1m30s, 500ms
    var re = /(\d+(?:\.\d+)?)(ns|us|µs|μs|ms|s|m|h)/g, m, total = 0, found = false;
    while ((m = re.exec(s)) !== null) {
      found = true;
      var v = parseFloat(m[1]); var u = m[2];
      var mul = 1;
      if (u === 'ns') mul = 1;
      else if (u === 'us' || u === 'µs' || u === 'μs') mul = 1e3;
      else if (u === 'ms') mul = 1e6;
      else if (u === 's') mul = 1e9;
      else if (u === 'm') mul = 60e9;
      else if (u === 'h') mul = 3600e9;
      total += v * mul;
    }
    if (found) return Math.round(total);
    var n = parseFloat(s);
    if (isFinite(n)) return Math.round(n * 1e9);
    return 0;
  }

  function historyToReport(h) {
    h = h || {};
    var cfg = h.config || {};
    var res = h.result || {};
    var durSec = Number(cfg.duration_seconds || 0);
    var durNs = durSec > 0 ? Math.round(durSec * 1e9) : parseDurationToNs(h.duration);
    if (durNs <= 0) durNs = 1e9;
    var total = Number(res.total_requests || 0);
    var errs = Number(res.total_errors || 0);
    var rps = Number(res.rps || 0);
    if (rps <= 0 && total > 0) rps = total / (durNs / 1e9);
    var errPct = total > 0 ? (errs / total * 100) : 0;
    function msToNs(v) { v = Number(v || 0); return Math.round(v * 1e6); }
    var p50 = msToNs(res.p50_latency);
    var p95 = msToNs(res.p95_latency || res.p50_latency);
    var p99 = msToNs(res.p99_latency || res.p95_latency || res.p50_latency);
    var avg = msToNs(res.avg_latency || res.p50_latency);
    var max = msToNs(res.max_latency || res.p99_latency || res.p95_latency || res.p50_latency);
    if (p50 <= 0) p50 = 1e6; if (p95 < p50) p95 = p50; if (p99 < p95) p99 = p95; if (avg <= 0) avg = p50; if (max < p99) max = p99;
    var ts = h.timestamp ? String(h.timestamp) : new Date().toISOString();
    return {
      name: h.id || cfg.target_url || 'run',
      base_url: cfg.target_url || '',
      load_profile: cfg.profile || 'steady',
      target_rps: cfg.rate_limit || 0,
      started_at: ts,
      ended_at: ts,
      duration: durNs,
      active_users: cfg.users || 0,
      total_requests: total,
      total_errors: errs,
      error_rate_pct: errPct,
      rps: rps,
      status_codes: res.status_codes || {},
      errors: {},
      gate: false,
      overall: {
        name: 'overall',
        requests: total,
        errors: errs,
        status_codes: res.status_codes || {},
        error_types: {},
        min: p50,
        avg: avg,
        max: max,
        p50: p50,
        p95: p95,
        p99: p99
      },
      steps: []
    };
  }

  async function doTwinLoadLatest() {
    setOut('twinFitOut', 'Loading latest run…');
    try {
      var d = await api('/api/history');
      var hist = Array.isArray(d) ? d : (d && d.history ? d.history : (S && S.history ? S.history : []));
      if (!hist || !hist.length) throw new Error('no completed runs found in history');
      var latest = hist[hist.length - 1];
      var rep = historyToReport(latest);
      var ta = document.getElementById('twinReportJson');
      if (ta) ta.value = JSON.stringify(rep, null, 2);
      setOut('twinFitOut', 'Latest run loaded into Report JSON. Click <strong>Fit model</strong> to build a capacity model.', 'ok');
    } catch (e) {
      if (e && e.message === 'locked') return;
      setText('twinFitOut', 'Error: ' + (e && e.message ? e.message : String(e)), 'err');
    }
  }

  async function doXrayCorrelate() {
    setOut('xrayCorrelateOut', 'Correlating…');
    try {
      var samples = parseJSONFrom('xraySamplesJson');
      var signals = parseJSONFrom('xraySignalsJson');
      if (!Array.isArray(samples)) throw new Error('samples must be a JSON array');
      if (!Array.isArray(signals)) throw new Error('signals must be a JSON array');
      var win = (document.getElementById('xrayWindow') || {}).value || '';
      var payload = { samples: samples, signals: signals };
      if (String(win).trim()) payload.window = String(win).trim();
      var d = await api('/api/insights/xray/correlate', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload)
      });
      if (!d || d.ok === false) throw new Error((d && d.error) || 'correlation failed');
      var indicators = d.indicators || [];
      var html = '<div class="ins-kv">' + kv('Indicators', indicators.length) + kv('Samples', samples.length) + kv('Signals', signals.length) + '</div>';
      if (indicators.length) {
        html += '<table class="ins-table"><thead><tr><th>Type</th><th>Severity</th><th>Summary</th></tr></thead><tbody>' +
          indicators.map(function (it) {
            return '<tr><td>' + esc(it.kind || it.type || '') + '</td><td>' + esc(it.severity || '') + '</td><td>' + esc(it.summary || it.detail || it.message || JSON.stringify(it)) + '</td></tr>';
          }).join('') + '</tbody></table>';
      } else {
        html += '<p class="ins-note">No indicators produced for the provided window/data.</p>';
      }
      if (d.note) html += '<p class="ins-note">' + esc(d.note) + '</p>';
      html += '<details class="ins-details"><summary>Indicators JSON</summary><pre>' + esc(JSON.stringify(indicators, null, 2)) + '</pre></details>';
      setOut('xrayCorrelateOut', html, 'ok');
    } catch (e) {
      if (e && e.message === 'locked') return;
      setText('xrayCorrelateOut', 'Error: ' + (e && e.message ? e.message : String(e)), 'err');
    }
  }

  function wire() {
    var b;
    b = document.getElementById('btnXrayCaps'); if (b) b.addEventListener('click', loadXrayCaps);
    b = document.getElementById('btnTwinFit'); if (b) b.addEventListener('click', doTwinFit);
    b = document.getElementById('btnTwinLoadLatest'); if (b) b.addEventListener('click', doTwinLoadLatest);
    b = document.getElementById('btnTwinSim'); if (b) b.addEventListener('click', doTwinSim);
    b = document.getElementById('btnBountyValidate'); if (b) b.addEventListener('click', doBountyValidate);
    b = document.getElementById('btnBountyVerifyUpload'); if (b) b.addEventListener('click', doBountyVerifyUpload);
    b = document.getElementById('btnBountyStatus'); if (b) b.addEventListener('click', doBountyStatus);
    b = document.getElementById('btnXrayCorrelate'); if (b) b.addEventListener('click', doXrayCorrelate);
    b = document.getElementById('btnTwinUseModel'); if (b) b.addEventListener('click', function () {
      if (window.__twinLastModel) {
        var ta = document.getElementById('twinModelJson');
        if (ta) ta.value = JSON.stringify(window.__twinLastModel, null, 2);
        setText('twinSimOut', 'Fitted model copied. Choose a scenario and click Simulate.', 'ok');
      } else {
        setText('twinFitOut', 'Fit a model first.', 'warn');
      }
    });
  }

  // Load capabilities when Insights view is opened; also wire once.
  var wired = false;
  var capsLoaded = false;
  function onShow() {
    if (!wired) { wire(); wired = true; }
    if (!capsLoaded) { capsLoaded = true; loadXrayCaps(); }
  }

  // Hook into view switching (app-11 defines showView earlier in bundle).
  if (typeof showView === 'function') {
    var _origShowView = showView;
    showView = function (id, opts) {
      var r = _origShowView(id, opts);
      if (id === 'viewInsights') onShow();
      return r;
    };
    window.showView = showView;
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire);
  else wire();
})();
