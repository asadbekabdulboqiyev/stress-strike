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
      if (checks.length) {
        html += '<table class="ins-table"><thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead><tbody>' +
          checks.map(function (c) { return '<tr><td>' + esc(c.name) + '</td><td class="st-' + esc(c.status) + '">' + esc(c.status) + '</td><td>' + esc(c.detail || '') + '</td></tr>'; }).join('') +
          '</tbody></table>';
      }
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

  function wire() {
    var b;
    b = document.getElementById('btnXrayCaps'); if (b) b.addEventListener('click', loadXrayCaps);
    b = document.getElementById('btnTwinFit'); if (b) b.addEventListener('click', doTwinFit);
    b = document.getElementById('btnTwinSim'); if (b) b.addEventListener('click', doTwinSim);
    b = document.getElementById('btnBountyValidate'); if (b) b.addEventListener('click', doBountyValidate);
    b = document.getElementById('btnBountyStatus'); if (b) b.addEventListener('click', doBountyStatus);
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
