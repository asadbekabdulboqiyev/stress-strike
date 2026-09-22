(() => {
  'use strict';

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ---------- theme ---------- */
  /* Sayt doim dark (VeriGate bilan teng premium, dual-mode rejim olib
     tashlandi). Toggle/override yo'q — `:root` da faqat dark token'lar. */

  /* ---------- mobile nav toggle ---------- */
  const navToggle = $('#navToggle');
  const mobileNav = $('#mobileNav');
  if (navToggle && mobileNav) {
    navToggle.addEventListener('click', () => {
      const open = mobileNav.classList.toggle('open');
      navToggle.setAttribute('aria-expanded', String(open));
      navToggle.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
    });
    /* ESC closes the mobile menu; focus returns to the toggle for keyboard users */
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && mobileNav.classList.contains('open')) {
        mobileNav.classList.remove('open');
        navToggle.setAttribute('aria-expanded', 'false');
        navToggle.setAttribute('aria-label', 'Open menu');
        navToggle.focus();
      }
    });
  }

  /* ---------- copy ---------- */
  $$('.copy').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const text = btn.dataset.copy || '';
      let ok = false;
      try {
        await navigator.clipboard.writeText(text);
        ok = true;
      } catch (_) {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        ok = document.execCommand('copy');
        ta.remove();
      }
      if (!ok) return;
      const prev = btn.textContent;
      btn.textContent = 'copied';
      btn.classList.add('done');
      btn.disabled = true;
      setTimeout(() => {
        btn.textContent = prev;
        btn.classList.remove('done');
        btn.disabled = false;
      }, 1400);
    });
  });

  /* ---------- tabs ---------- */
  const tabs = $$('.tabs');
  tabs.forEach((group) => {
    const tabList = $('.tablist', group);
    const buttons = $$('[role="tab"]', tabList);
    buttons.forEach((btn) => {
      if (btn.dataset.handled) return;
      btn.dataset.handled = '1';
      btn.addEventListener('click', () => {
        buttons.forEach((b) => {
          b.classList.toggle('active', b === btn);
          b.setAttribute('aria-selected', String(b === btn));
        });
        const panelId = btn.getAttribute('aria-controls');
        $$('[role="tabpanel"]', group).forEach((pan) => {
          const show = pan.id === panelId;
          pan.hidden = !show;
          pan.classList.toggle('active', show);
        });
      });
    });
    /* ARIA tabs pattern — arrow keys / Home / End rotate focus like native tabs */
    tabList.addEventListener('keydown', (e) => {
      const idx = buttons.indexOf(document.activeElement);
      if (idx < 0) return;
      let next = null;
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') next = buttons[(idx + 1) % buttons.length];
      else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') next = buttons[(idx - 1 + buttons.length) % buttons.length];
      else if (e.key === 'Home') next = buttons[0];
      else if (e.key === 'End') next = buttons[buttons.length - 1];
      else return;
      e.preventDefault();
      next.focus();
      next.click();
    });
  });

  /* ---------- accordion ---------- */
  $$('[data-acc]').forEach((acc) => {
    $$('.acc-q', acc).forEach((q, i) => {
      q.addEventListener('click', () => {
        const item = q.closest('.acc-item');
        const open = item.classList.toggle('open');
        q.setAttribute('aria-expanded', String(open));
        const a = $('.acc-a', item);
        if (a) {
          a.hidden = !open;
          if (!q.id) q.id = `acc-q-${i}`;
          if (!a.id) a.id = `acc-a-${i}`;
          q.setAttribute('aria-controls', a.id);
        }
      });
    });
  });

  /* ---------- terminal type ---------- */
  (function typeHero() {
    const body = $('#heroTerm');
    if (!body) return;
    const lines = body.innerText.split('\n');
    const delay = reduced ? 0 : 26;
    body.classList.add('typing');
    body.innerText = '';
    lines.forEach((raw, i) => {
      const ln = document.createElement('div');
      ln.className = 't-ln';
      ln.style.animationDelay = `${i * delay}ms`;
      if (raw.startsWith('$ ')) ln.classList.add('t-cmd');
      ln.textContent = raw;
      body.appendChild(ln);
    });
  })();

  /* ---------- fade / reveal on scroll ---------- */
  if (!reduced) {
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((e) => {
          if (e.isIntersecting) {
            e.target.classList.add('in');
            io.unobserve(e.target);
          }
        });
      },
      { threshold: 0.12, rootMargin: '0px 0px -8% 0px' }
    );
    const reveal = (sel) => {
      const el = $(sel);
      if (!el) return;
      io.observe(el);
      el.classList.add('rv');
    };
    reveal('.statement');
    reveal('.term-wrap');
    reveal('.compare-table');
  }
})();