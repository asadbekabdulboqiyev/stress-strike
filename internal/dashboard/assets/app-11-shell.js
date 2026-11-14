/* ==========================================================================
   app-11-shell.js — part 11 of 14 of the dashboard bundle.

   SHELL — view switching and the hidden admin reveal

   Every file in this directory is concatenated, in name order, into the
   single /app.js the page loads. They share one global scope, so a
   function declared here is visible to later parts — order matters.
   Keep one feature per file: a part that grows past ~900 lines is a
   signal to split it, not to let it grow (see assets_test.go).
   ========================================================================== */

/* ==========================================================================
   SHELL — sidebar view switching
   ========================================================================== */
var VIEW_KEY = 'ss_view';
var VIEW_IDS = ['viewOverview', 'viewSecurity', 'viewCertificate', 'viewInsights', 'viewHistory', 'viewAdmin'];

function rememberView(id) {
  try { localStorage.setItem(VIEW_KEY, id); } catch (e) {}
}
function savedView() {
  try {
    var v = localStorage.getItem(VIEW_KEY);
    if (v && VIEW_IDS.indexOf(v) >= 0) return v;
  } catch (e) {}
  return '';
}

function showView(id, opts) {
  opts = opts || {};
  if (VIEW_IDS.indexOf(id) < 0) return;

  VIEW_IDS.forEach(function(v) {
    var el = document.getElementById(v);
    if (!el) return;
    if (v === id) el.classList.remove('hidden');
    else el.classList.add('hidden');
  });

  var links = document.querySelectorAll('.sb-link[data-view]');
  for (var i = 0; i < links.length; i++) {
    if (links[i].getAttribute('data-view') === id) links[i].classList.add('active');
    else links[i].classList.remove('active');
  }

  if (!opts.silent) rememberView(id);

  if (id === 'viewHistory') {
    renderHistory();
  }
  if (id === 'viewCertificate') {
    certRefreshReset();
    certLoadLatest();
  }
  if (id === 'viewAdmin') adminStart();
  else adminStop();
}

function wireNav() {
  var links = document.querySelectorAll('.sb-link[data-view]');
  for (var i = 0; i < links.length; i++) {
    links[i].addEventListener('click', function(ev) {
      ev.preventDefault();
      showView(this.getAttribute('data-view'));
    });
  }

  // Security quick-nav: switch view then scroll to the selected scanner panel.
  var secLinks = document.querySelectorAll('.sec-chip[href^="#"]');
  for (var j = 0; j < secLinks.length; j++) {
    secLinks[j].addEventListener('click', function(ev) {
      var href = this.getAttribute('href') || '';
      if (href.charAt(0) !== '#') return;
      var target = document.querySelector(href);
      if (!target) return;
      ev.preventDefault();
      showView('viewSecurity');
      window.setTimeout(function() {
        try {
          target.scrollIntoView({ behavior: reducedMotion ? 'auto' : 'smooth', block: 'start' });
        } catch (e) {
          target.scrollIntoView();
        }
      }, 40);
    });
  }

  // Alt+1..5 / Alt+A. Alt avoids fighting the existing S/E run shortcuts and
  // normal typing inside the URL and token fields.
  document.addEventListener('keydown', function(ev) {
    if (!ev.altKey || ev.ctrlKey || ev.metaKey) return;
    var map = { '1': 'viewOverview', '2': 'viewSecurity', '3': 'viewCertificate', '4': 'viewHistory', '5': 'viewInsights' };
    var id = map[String(ev.key).toLowerCase()];
    if (!id) return;
    ev.preventDefault();
    showView(id);
  });
}

/* ==========================================================================
   SHELL — hidden admin reveal via secret hash (#slasz#)
   ========================================================================== */
var adminRevealed = false;

function revealAdmin(open) {
  if (!adminRevealed) {
    adminRevealed = true;
    var nav = document.getElementById('navAdmin');
    if (nav) nav.classList.remove('hidden');
    try { sessionStorage.setItem('ss_admin_revealed', '1'); } catch (e) {}
  }
  if (open) showView('viewAdmin');
}

function wireAdminReveal() {
  try { if (sessionStorage.getItem('ss_admin_revealed') === '1') revealAdmin(false); } catch (e) {}

  // Browsers may encode '#' as '%23', so match on the secret substring instead.
  function hashIsAdmin(h) { return h.indexOf('slasz') >= 0; }

  if (hashIsAdmin(location.hash)) revealAdmin(true);
  window.addEventListener('hashchange', function() {
    if (hashIsAdmin(location.hash)) revealAdmin(true);
  });
}
