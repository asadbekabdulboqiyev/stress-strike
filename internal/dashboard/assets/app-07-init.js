/* ==========================================================================
   app-07-init.js — part 07 of 13 of the dashboard bundle.

   POLLING FALLBACK, keyboard shortcuts, init

   Every file in this directory is concatenated, in name order, into the
   single /app.js the page loads. They share one global scope, so a
   function declared here is visible to later parts — order matters.
   Keep one feature per file: a part that grows past ~900 lines is a
   signal to split it, not to let it grow (see assets_test.go).
   ========================================================================== */

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
