#!/usr/bin/env node
// verify-cli.mjs — a command-line front end for the JavaScript verifier.
//
// It exists so that the browser verifier and the Go verifier can be compared
// mechanically (scripts/verify-html-parity.sh) without a browser in the loop.
// It is also useful on its own: it verifies a bundle on any machine that has
// Node, with no Go toolchain and no network access.
//
// Usage:
//   node web/verifier/verify-cli.mjs --bundle <bundle.json> [--samples <sidecar.jsonl>] [--json] [--skip-ci]
//
// Exit code: 0 when the evidence is valid, 1 when it is not, 2 on a usage
// error. With neither --samples nor a sibling sidecar it checks the bundle's
// internal consistency and signatures only.

import { readFileSync, existsSync } from 'node:fs';
import { verifyBundle } from './vpmp.mjs';

function usage(msg) {
  if (msg) console.error(`verify-cli: ${msg}`);
  console.error('usage: verify-cli.mjs --bundle <bundle.json> [--samples <sidecar.jsonl>] [--json] [--skip-ci]');
  process.exit(2);
}

const args = process.argv.slice(2);
let bundlePath = '';
let samplesPath = '';
let json = false;
let skipCi = false;

for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === '--bundle') bundlePath = args[++i] ?? '';
  else if (a === '--samples') samplesPath = args[++i] ?? '';
  else if (a === '--json') json = true;
  else if (a === '--skip-ci') skipCi = true;
  else if (a === '--help' || a === '-h') usage();
  else usage(`unknown argument ${a}`);
}

if (!bundlePath) usage('--bundle is required');
if (!existsSync(bundlePath)) usage(`bundle not found: ${bundlePath}`);

// Default to the sidecar convention <bundle>.samples.jsonl when present.
if (!samplesPath) {
  const guess = bundlePath.replace(/\.json$/, '') + '.samples.jsonl';
  if (existsSync(guess)) samplesPath = guess;
}
if (samplesPath && !existsSync(samplesPath)) usage(`sidecar not found: ${samplesPath}`);

const bundleText = readFileSync(bundlePath, 'utf8');
const samplesText = samplesPath ? readFileSync(samplesPath, 'utf8') : null;

const r = await verifyBundle(bundleText, samplesText, { skipCi });

if (json) {
  console.log(
    JSON.stringify(
      {
        valid: r.valid,
        format: r.format,
        bundle: bundlePath,
        bundle_digest: r.bundle_digest,
        sidecar: samplesPath || null,
        samples_absent: r.samples_absent,
        workers: r.workers.length,
        samples_total: r.samples_total,
        checks_run: r.checks_run,
        checks_failed: r.checks_failed,
        proofs_verified: r.proofs_verified,
        co_corrected: r.co_corrected === true,
        errors: r.errors,
        warnings: r.warnings,
      },
      null,
      2,
    ),
  );
} else {
  const verdict = r.valid ? 'PASS' : 'FAIL';
  console.log(`${verdict}  ${bundlePath}`);
  console.log(`  format          ${r.format || '(missing)'}`);
  console.log(`  bundle digest   ${r.bundle_digest || '(unavailable)'}`);
  console.log(`  samples         ${r.samples_absent ? 'absent (signatures + internal consistency only)' : r.samples_total}`);
  console.log(`  checks          ${r.checks_run} run, ${r.checks_failed} failed`);
  if (r.proofs_verified) console.log(`  proofs verified ${r.proofs_verified}`);
  if (r.aggregate) {
    console.log(`  aggregate       count ${r.aggregate.count}, p50 ${r.aggregate.p50_ns} ns, p95 ${r.aggregate.p95_ns} ns, p99 ${r.aggregate.p99_ns} ns`);
    if (r.co_corrected) {
      console.log(`  p99 95% CI      [${r.aggregate.ci_low_ns}, ${r.aggregate.ci_high_ns}] ns`);
    }
  }
  for (const w of r.warnings) console.log(`  warning         ${w}`);
  for (const e of r.errors) {
    console.log(`  FAIL            ${e.check}${e.worker ? ` [${e.worker}]` : ''}${e.index !== null && e.index !== undefined ? ` @leaf ${e.index}` : ''}: ${e.detail}`);
  }
}

process.exit(r.valid ? 0 : 1);
