// page-glue.js — the interface for the VeriBench verifier page.
//
// This file is inlined *after* vpmp.mjs inside one <script type="module">, so it
// can call the verifier's functions directly (same module scope). It is kept in
// its own file so a linter and `node --check` can see it, and so the page
// generator can hash it.

/* global verifyBundle, bundleDigestHex, sha256, bytesToHex, loadSamples */

const els = {
  dropBundle: document.getElementById('drop-bundle'),
  dropSidecar: document.getElementById('drop-sidecar'),
  inputBundle: document.getElementById('file-bundle'),
  inputSidecar: document.getElementById('file-sidecar'),
  run: document.getElementById('run'),
  reset: document.getElementById('reset'),
  result: document.getElementById('result'),
  body: document.getElementById('result-body'),
  status: document.getElementById('status'),
};

const state = {
  bundleText: null,
  bundleName: '',
  samplesText: null,
  samplesName: '',
  busy: false,
};

const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// setStatus writes its prose into the DOM, and that prose can quote bundle
// content — worker ids and check names come from the file under verification and
// are therefore attacker-controlled. Escaping happens *here*, at the sink, so
// every caller passes plain text and can never inject markup by accident.
function setStatus(kind, badge, text) {
  els.status.classList.remove('pass', 'fail', 'work');
  els.status.classList.add(kind);
  els.status.textContent = badge;
  els.result.hidden = false;
  els.body.innerHTML = `<p class="summary">${esc(text)}</p>`;
}

function refreshDrop(box, name) {
  box.classList.toggle('filled', !!name);
  const slot = box.querySelector('.file');
  slot.textContent = name || '';
  els.run.disabled = !state.bundleText || state.busy;
}

async function loadInto(kind, file) {
  if (!file) return;
  const text = await file.text();
  if (kind === 'bundle') {
    state.bundleText = text;
    state.bundleName = file.name;
    refreshDrop(els.dropBundle, file.name);
    // Be helpful: if the sidecar box is still empty, look for a companion name.
  } else {
    state.samplesText = text;
    state.samplesName = file.name;
    refreshDrop(els.dropSidecar, file.name);
  }
}

function wireDrop(box, input, kind) {
  box.addEventListener('click', () => input.click());
  input.addEventListener('change', () => loadInto(kind, input.files[0]));
  box.addEventListener('dragover', (e) => {
    e.preventDefault();
    box.classList.add('over');
  });
  box.addEventListener('dragleave', () => box.classList.remove('over'));
  box.addEventListener('drop', (e) => {
    e.preventDefault();
    box.classList.remove('over');
    loadInto(kind, e.dataTransfer.files[0]);
  });
}

wireDrop(els.dropBundle, els.inputBundle, 'bundle');
wireDrop(els.dropSidecar, els.inputSidecar, 'sidecar');

/* ------------------------------- rendering -------------------------------- */

function metaRows(r) {
  const rows = [
    ['format', r.format || '(missing)'],
    ['bundle digest', r.bundle_digest || '(unavailable)'],
    ['samples', r.samples_absent ? 'absent — signatures and internal consistency only' : `${r.samples_total.toLocaleString()} records`],
    ['checks', `${r.checks_run} run, ${r.checks_failed} failed`],
  ];
  if (r.proofs_verified) rows.push(['inclusion proofs', `${r.proofs_verified} verified`]);
  if (r.aggregate) {
    rows.push([
      'p50 / p95 / p99',
      `${r.aggregate.p50_ns} / ${r.aggregate.p95_ns} / ${r.aggregate.p99_ns} ns`,
    ]);
    if (r.co_corrected) rows.push(['p99 95% interval', `[${r.aggregate.ci_low_ns}, ${r.aggregate.ci_high_ns}] ns`]);
  }
  return rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('');
}

function checksTable(r) {
  if (!r.checks.length) return '';
  const rows = r.checks
    .map(
      (c) =>
        `<tr><td class="${c.ok ? 'ok' : 'no'}">${c.ok ? 'pass' : 'FAIL'}</td><td class="mono">${esc(c.name)}</td>` +
        `<td>${c.worker ? `<span class="mono">${esc(c.worker)}</span> — ` : ''}${esc(c.detail)}</td></tr>`,
    )
    .join('');
  return (
    '<h2>Every check</h2><table><thead><tr><th>result</th><th>check</th><th>detail</th></tr></thead>' +
    `<tbody>${rows}</tbody></table>`
  );
}

function errorsBlock(r) {
  if (!r.errors.length) return '';
  const items = r.errors
    .map(
      (e) =>
        `<li><b>${esc(e.check)}</b>${e.worker ? ` [${esc(e.worker)}]` : ''}` +
        `${e.index !== null && e.index !== undefined ? ` @leaf ${esc(e.index)}` : ''}: ${esc(e.detail)}</li>`,
    )
    .join('');
  return `<h2>What failed</h2><ul class="errs">${items}</ul>`;
}

function warnsBlock(r) {
  if (!r.warnings.length) return '';
  const items = r.warnings.map((w) => `<li>${esc(w)}</li>`).join('');
  return `<h2>Warnings (do not affect the verdict)</h2><ul class="warns">${items}</ul>`;
}

function honestyBlock(r) {
  const lines = [];
  if (r.co_corrected) {
    lines.push(
      '<strong>These percentiles are coordinated-omission corrected.</strong> When a paced generator is blocked waiting for slow responses, the naive measurement records only the fast service time and hides how long users actually waited. This bundle corrects for that, and the correction is recomputed here from the raw records — it is not trusted from the file.',
    );
  } else {
    lines.push(
      '<strong>These percentiles are raw service times.</strong> The run did not claim a coordinated-omission correction, so the reported percentiles are the measured response times as-is.',
    );
  }
  lines.push(
    'The bundle proves <strong>which measurements are behind the numbers</strong> and that no byte changed after the run. It is not a claim that the system under test is fast, or that the load profile matched production.',
  );
  return `<h2>What this does and does not prove</h2><div class="honest">${lines.join('<br><br>')}</div>`;
}

function plainSummary(r) {
  if (r.valid && !r.samples_absent) {
    return 'Every file checks out: the numbers were signed by the machine that produced them, every recorded request is accounted for in the fingerprint, the recomputed statistics match the claimed ones, and no byte has been altered.';
  }
  if (r.valid && r.samples_absent) {
    return 'The bundle itself is internally consistent and correctly signed. The raw request records were not supplied, so this is a weaker check: it cannot recompute the statistics from the source measurements.';
  }
  const first = r.errors[0];
  return `The evidence does not hold up. ${r.errors.length} check(s) failed; the first was ${first.check}${first.worker ? ` in worker ${first.worker}` : ''}. Treat the reported numbers as unverified.`;
}

/* --------------------------------- action --------------------------------- */

els.run.addEventListener('click', async () => {
  if (!state.bundleText || state.busy) return;
  state.busy = true;
  els.run.disabled = true;
  els.dropBundle.classList.remove('filled');
  els.status.hidden = false;
  setStatus('work', 'CHECKING', 'Recomputing the fingerprint, the signatures and the statistics from the raw records. For a large run this can take a few seconds.');

  try {
    const r = await verifyBundle(state.bundleText, state.samplesText);
    setStatus(r.valid ? 'pass' : 'fail', r.valid ? 'PASS' : 'FAIL', plainSummary(r));
    els.body.innerHTML +=
      `<dl class="meta">${metaRows(r)}</dl>` +
      errorsBlock(r) +
      warnsBlock(r) +
      honestyBlock(r) +
      checksTable(r);
  } catch (e) {
    setStatus('fail', 'ERROR', `The verifier could not run: ${e && e.message ? e.message : e}`);
  } finally {
    state.busy = false;
    els.dropBundle.classList.add('filled');
    els.run.disabled = false;
  }
});

els.reset.addEventListener('click', () => {
  state.bundleText = null;
  state.bundleName = '';
  state.samplesText = null;
  state.samplesName = '';
  els.inputBundle.value = '';
  els.inputSidecar.value = '';
  refreshDrop(els.dropBundle, '');
  refreshDrop(els.dropSidecar, '');
  els.result.hidden = true;
  els.body.innerHTML = '';
  els.status.className = 'badge';
  els.status.textContent = '…';
});

// Automation hook: lets a headless browser (or the parity script) drive the
// verifier with the same code path a user does.
globalThis.veriBench = {
  verifyBundle,
  bundleDigestHex,
  sha256,
  bytesToHex,
  loadSamples,
  version: 'vpmp/v1',
};
