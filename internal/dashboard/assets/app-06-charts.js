/* ==========================================================================
   app-06-charts.js — part 06 of 13 of the dashboard bundle.

   CANVAS CHARTS, helpers

   Every file in this directory is concatenated, in name order, into the
   single /app.js the page loads. They share one global scope, so a
   function declared here is visible to later parts — order matters.
   Keep one feature per file: a part that grows past ~900 lines is a
   signal to split it, not to let it grow (see assets_test.go).
   ========================================================================== */

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
    ctx.font = '10px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
    ctx.textAlign = 'right';
    ctx.fillText(fmtSmart(allMax * (1 - i / 4)), pad.left - 8, y + 4);
  }

  // Time labels
  ctx.fillStyle = '#8585a0'; /* audit: axis time labels, 2.2:1 -> 5.2:1 */
  ctx.textAlign = 'center';
  ctx.font = '10px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
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
      ctx.font = '10px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace';
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
function fmtMs(v) { return (v || 0).toFixed(1) + ' ms'; }
function esc(s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function updateConnStatus() {
  var dot = document.getElementById('connDot');
  var label = document.getElementById('connLabel');
  if (!dot || !label) return;
  if (S.locked) {
    dot.className = 'conn-dot locked';
    label.textContent = '';
    label.appendChild(dot);
    label.appendChild(document.createTextNode(' Access locked'));
    label.style.color = 'var(--yellow)';
    return;
  }
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
