/* ==========================================================================
   app-13-admin.js — part 13 of 14 of the dashboard bundle.

   ADMIN page — status, unlock, lock, countdown

   Every file in this directory is concatenated, in name order, into the
   single /app.js the page loads. They share one global scope, so a
   function declared here is visible to later parts — order matters.
   Keep one feature per file: a part that grows past ~900 lines is a
   signal to split it, not to let it grow (see assets_test.go).
   ========================================================================== */

/* ==========================================================================
   ADMIN PAGE — status, unlock, lock, countdown
   ========================================================================== */
var adminStatusTimer = null;
var adminTickTimer = null;
var adminExpiresMs = 0;

function adminSetStatus(msg, cls) {
  var el = document.getElementById('adminStatus');
  if (!el) return;
  el.textContent = msg || '';
  el.className = 'admin-status' + (cls ? ' ' + cls : '');
}

function adminWarning(msg) {
  var el = document.getElementById('adminWarning');
  if (!el) return;
  if (msg) { el.textContent = msg; el.classList.remove('hidden'); }
  else { el.textContent = ''; el.classList.add('hidden'); }
}

function adminRenderStatus(st) {
  var value = document.getElementById('adminStateValue');
  var countdown = document.getElementById('adminCountdown');
  if (!value) return;
  if (st && st.active) {
    value.textContent = 'ON — authorization bypassed';
    value.className = 'admin-state-value on';
    adminExpiresMs = st.expires_at ? Date.parse(st.expires_at) : 0;
    if (countdown) countdown.classList.remove('hidden');
    adminTick();
  } else {
    value.textContent = 'OFF — authorization enforced';
    value.className = 'admin-state-value off';
    adminExpiresMs = 0;
    if (countdown) { countdown.classList.add('hidden'); countdown.textContent = ''; }
  }
}

function adminTick() {
  var countdown = document.getElementById('adminCountdown');
  if (!countdown) return;
  if (!adminExpiresMs) { countdown.classList.add('hidden'); return; }
  var left = Math.max(0, Math.round((adminExpiresMs - Date.now()) / 1000));
  if (left <= 0) {
    countdown.textContent = 'Bypass expired — authorization is enforced again.';
    countdown.classList.remove('hidden');
    adminFetchStatus();
    return;
  }
  var m = Math.floor(left / 60);
  var s = left % 60;
  countdown.textContent = 'Bypass active — ' + m + 'm ' + (s < 10 ? '0' : '') + s + 's left';
  countdown.classList.remove('hidden');
}

function adminFetchStatus() {
  fetch(API + '/api/admin/status', { cache: 'no-store' })
    .then(function(r) { return r.json(); })
    .then(function(st) { adminRenderStatus(st); })
    .catch(function() { adminSetStatus('Could not read the admin status.', 'bad'); });
}

function adminStart() {
  if (adminStatusTimer) return;
  adminFetchStatus();
  adminStatusTimer = setInterval(adminFetchStatus, 10000);
  adminTickTimer = setInterval(adminTick, 1000);
}

function adminStop() {
  if (adminStatusTimer) { clearInterval(adminStatusTimer); adminStatusTimer = null; }
  if (adminTickTimer) { clearInterval(adminTickTimer); adminTickTimer = null; }
}

function wireAdmin() {
  var form = document.getElementById('adminForm');
  var lock = document.getElementById('btnAdminLock');
  if (form) form.addEventListener('submit', function(ev) {
    ev.preventDefault();
    var minutes = parseInt((document.getElementById('adminMinutes') || {}).value || '15', 10);
    if (!minutes || minutes < 1) minutes = 15;
    var codeInput = document.getElementById('adminCode');
    var code = ((codeInput || {}).value || '').trim();
    if (!code) {
      adminSetStatus('Enter the admin code shown by `Sift admin code`.', 'bad');
      adminWarning('Admin bypass is OFF. Authorization is enforced.');
      return;
    }
    adminSetStatus('Opening the bypass window…', '');
    fetch(API + '/api/admin/unlock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: code, minutes: minutes })
    }).then(function(r) {
      return r.json().then(function(j) { return { ok: r.ok, body: j }; });
    }).then(function(res) {
      if (!res.ok) {
        adminSetStatus((res.body && res.body.error) || 'The code was rejected.', 'bad');
        adminWarning('Admin bypass is OFF. Authorization is enforced.');
        return;
      }
      var st = res.body.status || {};
      adminRenderStatus(st);
      adminSetStatus('Bypass is ON. Turn it off as soon as the work is done.', 'ok');
      adminWarning(res.body.warning || '');
      var input = document.getElementById('adminCode');
      if (input) input.value = '';
      toast('Admin bypass is ON', 'ok');
    }).catch(function() {
      adminSetStatus('Could not reach the dashboard API.', 'bad');
    });
  });

  if (lock) lock.addEventListener('click', function() {
    adminSetStatus('Closing the bypass window…', '');
    fetch(API + '/api/admin/lock', { method: 'POST' })
      .then(function(r) { return r.json(); })
      .then(function(res) {
        adminRenderStatus(res.status || {});
        adminSetStatus('Bypass is OFF. Authorization is enforced.', 'ok');
        adminWarning('');
        toast('Admin bypass is OFF', 'ok');
      })
      .catch(function() { adminSetStatus('Could not reach the dashboard API.', 'bad'); });
  });
}

/* ---- Boot the shell ---- */
wireNav();
wireAdminReveal();
wireCertificate();
wireAdmin();

// The sidebar prints the build it is talking to, so "did I just install the
// new binary?" is answerable without opening a terminal.
(function bootVersion() {
  var el = document.getElementById('sbVersion');
  if (!el) return;
  fetch(API + '/api/version', { cache: 'no-store' })
    .then(function(r) { return r.json(); })
    .then(function(res) {
      if (res && res.version) el.textContent = res.version;
    })
    .catch(function() { el.textContent = '?'; });
})();

(function bootView() {
  var v = savedView();
  if (!v) return;
  if (v === 'viewAdmin') revealAdmin(false);
  showView(v, { silent: true });
})();
