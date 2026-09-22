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
  connected: false
};
var MAX_HIST = 120;
var ws = null;
var API = location.origin;

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
  ws.onopen = function() {
    S.connected = true;
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
    } else if (msg.type === 'snapshot') {
      var d = msg.data;
      S.snapshot = d;
      pushHist('rpsHist', d.rps || 0);
      pushHist('latAvgHist', d.avg_latency_ms || 0);
      pushHist('latP50Hist', d.p50_latency_ms || 0);
      pushHist('latP95Hist', d.p95_latency_ms || 0);
      pushHist('latP99Hist', d.p99_latency_ms || 0);
      pushHist('errHist', d.error_rate || 0);
      pushHist('userHist', d.active_users || 0);
    } else if (msg.type === 'run_state') {
      var prev = S.run.status;
      S.run = msg.data;
      var st = (S.run && S.run.status) || '';
      if (prev !== 'completed' && st === 'completed') {
        toast('Run completed!', 'success');
        refreshHistory();
      }
      if (prev !== 'failed' && st === 'failed') {
        toast(S.run.error ? ('Run failed: ' + S.run.error) : 'Run failed!', 'error');
        refreshHistory();
      }
      if (prev !== 'stopped' && st === 'stopped') {
        toast('Run stopped', 'info');
        refreshHistory();
      }
    }
    render();
  };
  ws.onclose = function() {
    S.connected = false;
    updateConnStatus();
    scheduleReconnect();
  };
  ws.onerror = function() {};
}

function scheduleReconnect() {
  if (wsRetryTimer) return;
  wsRetryTimer = setTimeout(function() { wsRetryTimer = null; connect(); }, 2000);
}

// Re-fetch run history after a run finishes. The server only sends history in
// the WS "init" message, so a completed run would otherwise stay invisible in
// the table until the page is reloaded.
function refreshHistory() {
  fetch(API + '/api/history').then(function(r) { return r.json(); }).then(function(h) {
    S.history = h || [];
    renderHistory();
  }).catch(function() {});
}

function pushHist(arr, val) {
  S[arr].push(val);
  if (S[arr].length > MAX_HIST) S[arr].shift();
}

/* ==========================================================================
   ACTIONS
   ========================================================================== */
function startRun() {
  var cfg = {
    target_url: document.getElementById('inpUrl').value || 'http://localhost:8080/health',
    users: parseInt(document.getElementById('inpUsers').value) || 10,
    duration_seconds: parseInt(document.getElementById('inpDuration').value) || 30,
    method: document.getElementById('inpMethod').value || 'GET',
    rate_limit: parseInt(document.getElementById('inpRate').value) || 0,
    profile: document.getElementById('inpProfile').value || 'steady',
    tls_fingerprint: document.getElementById('inpFingerprint').value || ''
  };
  fetch(API + '/api/run/start', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(cfg)
  }).then(function(r) {
    if (!r.ok) throw new Error('server returned ' + r.status);
    return r.json();
  }).then(function() { toast('Run started!', 'info'); })
    .catch(function() { toast('Failed to start run', 'error'); });
}

function stopRun() {
  fetch(API + '/api/run/stop', { method: 'POST' }).then(function(r) {
    if (!r.ok) throw new Error('server returned ' + r.status);
    return r.json();
  }).then(function() { toast('Run stopped', 'error'); })
    .catch(function() { toast('Failed to stop run', 'error'); });
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
  setTimeout(function() { t.style.opacity = '0'; t.style.transition = '0.3s'; setTimeout(function() { t.remove(); }, 300); }, 3000);
}

/* ==========================================================================
   RENDER
   ========================================================================== */
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
  if (badge.getAttribute('data-status') !== (r.status || 'idle')) {
    badge.setAttribute('data-status', r.status || 'idle');
    badge.className = 'badge badge-' + (r.status || 'idle');
    badge.textContent = (r.status || 'idle');
  }

  // Buttons
  document.getElementById('btnStart').disabled = running;
  document.getElementById('btnStop').disabled = !running;

  // Progress
  var pf = document.getElementById('progressFill');
  pf.style.width = progress + '%';
  pf.className = 'progress-fill' + (running ? ' active' : '');
  var remain = Math.max(0, duration - elapsedNum);
  document.getElementById('progressText').textContent =
    progress.toFixed(0) + '% | ' + formatDuration(elapsedNum) + ' / ' + formatDuration(duration) + ' | ' + formatDuration(remain) + ' left';

  // Populate inputs from config when running
  if (r.config) {
    if (document.activeElement.id !== 'inpUrl') document.getElementById('inpUrl').value = r.config.target_url || '';
    if (document.activeElement.id !== 'inpUsers') document.getElementById('inpUsers').value = r.config.users || 10;
    if (document.activeElement.id !== 'inpDuration') document.getElementById('inpDuration').value = r.config.duration_seconds || 30;
    if (document.activeElement.id !== 'inpMethod') document.getElementById('inpMethod').value = r.config.method || 'GET';
    if (document.activeElement.id !== 'inpRate') document.getElementById('inpRate').value = r.config.rate_limit || 0;
    if (document.activeElement.id !== 'inpProfile' && r.config.profile) document.getElementById('inpProfile').value = r.config.profile;
    if (document.activeElement.id !== 'inpFingerprint' && r.config.tls_fingerprint) document.getElementById('inpFingerprint').value = r.config.tls_fingerprint;
  }

  // Config meta + live latency strip
  document.getElementById('metaProfile').textContent = (r.config && r.config.profile) || '\u2014';
  document.getElementById('metaRate').textContent = (r.config && r.config.rate_limit) ? r.config.rate_limit + ' req/s' : '\u2014';
  document.getElementById('metaFingerprint').textContent = (r.config && r.config.tls_fingerprint) || '\u2014';
  document.getElementById('metaP50').textContent = (s.p50_latency_ms || 0).toFixed(1) + ' ms';
  document.getElementById('metaP95').textContent = (s.p95_latency_ms || 0).toFixed(1) + ' ms';
  document.getElementById('metaP99').textContent = (s.p99_latency_ms || 0).toFixed(1) + ' ms';
  document.getElementById('metaAvg').textContent = (s.avg_latency_ms || 0).toFixed(1) + ' ms';
  document.getElementById('metaMax').textContent = (s.max_latency_ms || 0).toFixed(1) + ' ms';

  // Metric cards
  var rps = s.rps || 0;
  document.getElementById('valRPS').textContent = Math.round(rps);
  document.getElementById('subRPS').textContent = fmt(s.total_requests || 0) + ' total requests';

  var avg = s.avg_latency_ms || 0;
  document.getElementById('valAvg').innerHTML = avg.toFixed(1) + ' <small style="font-size:14px;font-weight:400">ms</small>';
  document.getElementById('subLatency').textContent =
    'P50: ' + (s.p50_latency_ms||0).toFixed(1) + ' \u00b7 P95: ' + (s.p95_latency_ms||0).toFixed(1) + ' \u00b7 P99: ' + (s.p99_latency_ms||0).toFixed(1) + ' ms';

  var errRate = s.error_rate || 0;
  var errEl = document.getElementById('valErrors');
  errEl.style.color = errRate > 5 ? 'var(--red)' : errRate > 1 ? 'var(--yellow)' : 'var(--green)';
  errEl.innerHTML = errRate.toFixed(2) + ' <small style="font-size:14px;font-weight:400">%</small>';
  document.getElementById('subErrors').textContent = fmt(s.total_errors || 0) + ' errors / ' + fmt(s.total_requests || 0) + ' total';

  document.getElementById('valUsers').textContent = s.active_users || 0;

  // Latency detail cards
  document.getElementById('latP50').textContent = (s.p50_latency_ms||0).toFixed(1);
  document.getElementById('latP95').textContent = (s.p95_latency_ms||0).toFixed(1);
  document.getElementById('latP99').textContent = (s.p99_latency_ms||0).toFixed(1);

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
}

/* ==========================================================================
   STATUS CODES
   ========================================================================== */
function renderStatusCodes(codes) {
  var el = document.getElementById('statusBars');
  var keys = Object.keys(codes).sort();
  if (keys.length === 0) {
    el.innerHTML = '<div style="text-align:center;color:var(--text-3);padding:40px 0;font-size:13px">No data yet</div>';
    return;
  }
  var total = 0;
  keys.forEach(function(k) { total += codes[k]; });
  var html = '';
  keys.forEach(function(k) {
    var v = codes[k];
    var pct = total > 0 ? (v / total * 100) : 0;
    var cls = k < 300 ? 'c2xx' : k < 400 ? 'c3xx' : k < 500 ? 'c4xx' : 'c5xx';
    html += '<div class="status-row">' +
      '<span class="status-code ' + cls + '">' + k + '</span>' +
      '<div class="status-bar-bg"><div class="status-bar ' + cls + '" style="width:' + pct + '%"></div></div>' +
      '<span class="status-count">' + fmt(v) + ' (' + pct.toFixed(1) + '%)</span></div>';
  });
  el.innerHTML = html;
}

/* ==========================================================================
   WORKERS
   ========================================================================== */
function renderWorkers(workers) {
  var section = document.getElementById('workersSection');
  if (!workers || workers.length === 0) {
    section.classList.add('hidden');
    return;
  }
  section.classList.remove('hidden');
  var body = document.getElementById('workersBody');
  var html = '';
  workers.forEach(function(w) {
    var isActive = w.status === 'running' || w.status === 'active';
    html += '<tr>' +
      '<td><strong>' + esc(w.id) + '</strong></td>' +
      '<td style="color:var(--text-1)">' + esc(w.address) + '</td>' +
      '<td><span class="worker-status"><span class="worker-dot ' + (isActive ? 'active' : 'idle') + '"></span>' + esc(w.status) + '</span></td>' +
      '<td>' + (w.rps || 0).toFixed(0) + '</td>' +
      '<td>' + (w.latency_ms || 0).toFixed(1) + ' ms</td>' +
      '<td>' + fmt(w.errors || 0) + '</td></tr>';
  });
  body.innerHTML = html;
}

/* ==========================================================================
   HISTORY
   ========================================================================== */
function renderHistory() {
  var section = document.getElementById('historySection');
  if (S.history.length === 0) { section.style.display = 'none'; return; }
  section.style.display = '';
  var body = document.getElementById('historyBody');
  var html = '';
  S.history.forEach(function(h) {
    html += '<tr>' +
      '<td style="color:var(--text-1)">' + esc(h.id) + '</td>' +
      '<td>' + new Date(h.timestamp).toLocaleTimeString() + '</td>' +
      '<td>' + esc((h.config && h.config.target_url) || '-') + '</td>' +
      '<td>' + ((h.config && h.config.users) || '-') + '</td>' +
      '<td>' + ((h.config && h.config.duration_seconds) || '-') + 's</td>' +
      '<td style="color:var(--green);font-weight:600">' + ((h.result && h.result.rps) || 0).toFixed(0) + '</td>' +
      '<td>' + ((h.result && h.result.p50_latency) || 0).toFixed(1) + 'ms</td>' +
      '<td>' + ((h.result && h.result.p99_latency) || 0).toFixed(1) + 'ms</td>' +
      '<td style="color:var(--red)">' + ((h.result && h.result.total_errors) || 0) + '</td></tr>';
  });
  body.innerHTML = html;
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
    ctx.font = '10px Inter, system-ui, sans-serif';
    ctx.textAlign = 'right';
    ctx.fillText(fmtSmart(allMax * (1 - i / 4)), pad.left - 8, y + 4);
  }

  // Time labels
  ctx.fillStyle = '#8585a0'; /* audit: axis time labels, 2.2:1 -> 5.2:1 */
  ctx.textAlign = 'center';
  ctx.font = '10px Inter, system-ui, sans-serif';
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
      ctx.font = '10px Inter, system-ui, sans-serif';
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
function esc(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function updateConnStatus() {
  var dot = document.getElementById('connDot');
  var label = document.getElementById('connLabel');
  if (!dot || !label) return;
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
  if (!S.connected && S.run && S.run.status === 'running') {
    fetch(API + '/api/snapshot').then(function(r) { return r.json(); }).then(function(d) {
      S.snapshot = d;
      pushHist('rpsHist', d.rps || 0);
      pushHist('latAvgHist', d.avg_latency_ms || 0);
      pushHist('latP50Hist', d.p50_latency_ms || 0);
      pushHist('latP95Hist', d.p95_latency_ms || 0);
      pushHist('latP99Hist', d.p99_latency_ms || 0);
      pushHist('errHist', d.error_rate || 0);
      pushHist('userHist', d.active_users || 0);
      render();
    }).catch(function() {});
  }
}, 1000);

/* ==========================================================================
   KEYBOARD SHORTCUTS
   ========================================================================== */
document.addEventListener('keydown', function(e) {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') return;
  if (e.key === 's' || e.key === 'S') { e.preventDefault(); if (!S.run || S.run.status !== 'running') startRun(); }
  if (e.key === 'x' || e.key === 'X') { e.preventDefault(); if (S.run && S.run.status === 'running') stopRun(); }
});

/* ==========================================================================
   INIT
   ========================================================================== */
connect();
render();

/* Controls wired via addEventListener (strict CSP: no inline handlers) */
var _btnStart = document.getElementById("btnStart");
if (_btnStart) _btnStart.addEventListener("click", startRun);
var _btnStop = document.getElementById("btnStop");
if (_btnStop) _btnStop.addEventListener("click", stopRun);
