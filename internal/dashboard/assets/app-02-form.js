/* ==========================================================================
   app-02-form.js — part 02 of 14 of the dashboard bundle.

   FORM — validation helpers

   Every file in this directory is concatenated, in name order, into the
   single /app.js the page loads. They share one global scope, so a
   function declared here is visible to later parts — order matters.
   Keep one feature per file: a part that grows past ~900 lines is a
   signal to split it, not to let it grow (see assets_test.go).
   ========================================================================== */

/* ==========================================================================
   FORM — validation helpers
   ========================================================================== */
function validUrl(v) {
  v = (v || '').trim();
  if (!v) return false;
  if (!/^https?:\/\/.+/i.test(v)) return false;
  try {
    var u = new URL(v);
    return !!u.host;
  } catch (e) { return false; }
}

function setUrlError(msg) {
  var f = document.getElementById('urlError');
  var i = document.getElementById('inpUrl');
  if (!f || !i) return;
  if (msg) {
    if (f.textContent !== msg) f.textContent = msg;
    i.setAttribute('aria-invalid', 'true');
    i.classList.add('invalid');
  } else {
    if (f.textContent) f.textContent = '';
    i.removeAttribute('aria-invalid');
    i.classList.remove('invalid');
  }
}

function setObError(msg) {
  var f = document.getElementById('obError');
  var i = document.getElementById('obUrl');
  if (!f || !i) return;
  if (msg) {
    f.textContent = msg;
    i.setAttribute('aria-invalid', 'true');
    i.classList.add('invalid');
  } else {
    f.textContent = '';
    i.removeAttribute('aria-invalid');
    i.classList.remove('invalid');
  }
}
