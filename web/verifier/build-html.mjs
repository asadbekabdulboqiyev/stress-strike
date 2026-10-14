// build-html.mjs — assembles docs/VERIFIER.html from the tested verifier module.
//
// The shipped page must contain exactly the code that the test suite exercises,
// so this generator inlines `vpmp.mjs` verbatim between two marker comments and
// records its SHA-256 in the page footer. `--check` re-derives the page and
// fails if the file on disk has drifted from the module, which is what CI runs.
//
//   node web/verifier/build-html.mjs            # write docs/VERIFIER.html
//   node web/verifier/build-html.mjs --check    # fail if the page is stale

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..', '..');

const paths = {
  module: join(here, 'vpmp.mjs'),
  css: join(here, 'page.css'),
  glue: join(here, 'page-glue.js'),
  out: join(repo, 'docs', 'VERIFIER.html'),
};

const BEGIN = '/* ==== BEGIN vpmp-verifier (inlined verbatim from web/verifier/vpmp.mjs) ==== */';
const END = '/* ==== END vpmp-verifier ==== */';

function sha256Hex(s) {
  return createHash('sha256').update(s).digest('hex');
}

function build() {
  const mod = readFileSync(paths.module, 'utf8');
  const css = readFileSync(paths.css, 'utf8');
  const glue = readFileSync(paths.glue, 'utf8');

  for (const [name, src] of [
    ['vpmp.mjs', mod],
    ['page-glue.js', glue],
  ]) {
    if (src.includes('</script')) {
      throw new Error(`${name} contains "</script" and cannot be inlined into HTML`);
    }
    if (src.includes(BEGIN) || src.includes(END)) {
      throw new Error(`${name} contains a drift marker; refusing to build`);
    }
  }

  const modHash = sha256Hex(mod);
  const glueHash = sha256Hex(glue);

  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VeriBench — verify load-test evidence offline</title>
<meta name="description" content="An offline, dependency-free verifier for vpmp/v1 load-test evidence bundles. Drop the bundle and its raw request log; the page recomputes the fingerprint, checks the signatures and re-derives the statistics in your browser.">
<style>
${css.trim()}
</style>
</head>
<body>
<div class="wrap">
<header>
  <div class="tag">vpmp/v1 · runs entirely in this page · nothing is uploaded</div>
  <h1>Verify load-test evidence</h1>
  <p class="lead">
    A VeriBench bundle is a signed claim about a load test: which requests were measured, how long
    they took, and what the summary numbers are. This page re-derives all of that from the files
    themselves. If a single byte of the records, the statistics or the signatures has changed since
    the run, the check fails — and it says exactly which check failed.
  </p>
</header>

<div class="panel">
  <div class="drops">
    <div class="drop" id="drop-bundle">
      <div class="label">1. Evidence bundle</div>
      <div class="hint">the <code>.json</code> file, e.g. <code>run.json</code><br>drag it here or click to choose</div>
      <div class="file"></div>
      <input type="file" id="file-bundle" accept=".json,application/json">
    </div>
    <div class="drop" id="drop-sidecar">
      <div class="label">2. Raw requests (optional)</div>
      <div class="hint">the <code>.samples.jsonl</code> file next to it<br>without it the check is weaker</div>
      <div class="file"></div>
      <input type="file" id="file-sidecar" accept=".jsonl,.json,text/plain">
    </div>
  </div>
  <div class="actions">
    <button class="primary" id="run" disabled>Verify evidence</button>
    <button class="ghost" id="reset">Clear</button>
    <span class="subtle">Recommended: supply both files. With the bundle alone, only the signatures and the bundle's internal consistency can be checked.</span>
  </div>
</div>

<div class="panel" id="result" hidden>
  <div class="verdict"><span class="badge" id="status">…</span></div>
  <div id="result-body"></div>
</div>

<footer>
  <p>
    <strong>Offline and auditable.</strong> This file has no network access, no third-party code and no build
    step: it uses the browser's own SHA-256 and Ed25519. The verification module below is inlined
    verbatim from the repository and is covered by unit tests plus a parity test that compares its
    verdicts, check by check, with the Go implementation of the same protocol.
  </p>
  <p>
    If the Ed25519 signature checks report that WebCrypto is unavailable, your browser has disabled
    it for <code>file://</code> pages; serve the folder from a local web server
    (<code>python3 -m http.server</code>) and open it over <code>http://localhost</code>.
  </p>
  <p>
    <strong>Honesty limits.</strong> A valid bundle proves the numbers are the measured ones and that
    nothing changed afterwards. It does not prove the system under test is fast, that the load profile
    matches production, or that the coordinated-omission correction was appropriate for the run — only
    that the correction, if claimed, is exactly the one recomputed from the raw records.
  </p>
  <p class="subtle">
    vpmp/v1 verifier module SHA-256: <code>${modHash}</code><br>
    page interface SHA-256: <code>${glueHash}</code>
  </p>
</footer>
</div>

<script type="module">
${BEGIN}
${mod.trim()}
${END}

/* ==== page interface (inlined verbatim from web/verifier/page-glue.js) ==== */
${glue.trim()}
</script>
</body>
</html>
`;

  return { html, modHash, glueHash };
}

const check = process.argv.includes('--check');
const { html, modHash } = build();

if (check) {
  if (!existsSync(paths.out)) {
    console.error('build-html: docs/VERIFIER.html is missing; run: node web/verifier/build-html.mjs');
    process.exit(1);
  }
  const onDisk = readFileSync(paths.out, 'utf8');
  if (onDisk !== html) {
    console.error('build-html: docs/VERIFIER.html does not match the verifier module.');
    console.error('The page must be regenerated so the shipped code is the tested code:');
    console.error('  node web/verifier/build-html.mjs');
    process.exit(1);
  }
  console.log(`build-html: docs/VERIFIER.html is up to date (module sha256 ${modHash.slice(0, 16)}…)`);
} else {
  writeFileSync(paths.out, html);
  console.log(`build-html: wrote docs/VERIFIER.html (${html.length} bytes, module sha256 ${modHash.slice(0, 16)}…)`);
}
