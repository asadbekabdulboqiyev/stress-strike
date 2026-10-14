// vpmp.test.mjs — unit tests for the independent JavaScript verifier.
//
// Run with:  node --test web/verifier/vpmp.test.mjs
//
// These tests treat Node's own crypto as an oracle: the SHA-256 and Merkle
// implementations here are compared against an independently written
// node:crypto implementation, so a bug in one is very unlikely to be mirrored
// in the other. The end-to-end agreement with the Go verifier is asserted
// separately by scripts/verify-html-parity.sh.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';

import {
  sha256,
  utf8,
  bytesToHex,
  hexToBytes,
  encodeCanonical,
  parseJSONStrict,
  merkleRootHex,
  percentile,
  sortBigAsc,
  ci95OrderStatistic,
  ci95Bootstrap,
  loadSamples,
  verifyBundle,
} from './vpmp.mjs';

const dec = (b) => new TextDecoder().decode(b);
const nodeSha = (buf) => createHash('sha256').update(buf).digest('hex');

/* ------------------------------- SHA-256 --------------------------------- */

test('sha256 matches the published NIST vectors', () => {
  assert.equal(
    bytesToHex(sha256(utf8(''))),
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  );
  assert.equal(
    bytesToHex(sha256(utf8('abc'))),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  );
  assert.equal(
    bytesToHex(sha256(utf8('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))),
    '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
  );
});

test('sha256 matches node:crypto across lengths and block boundaries', () => {
  // 55/56/57/63/64/65 bytes straddle the padding edges.
  for (const n of [0, 1, 55, 56, 57, 63, 64, 65, 127, 128, 1000, 100000]) {
    const buf = randomBytes(n);
    assert.equal(bytesToHex(sha256(new Uint8Array(buf))), nodeSha(buf), `length ${n}`);
  }
  // A single million-byte block-exact input.
  const big = new Uint8Array(1_000_000).fill(0x61);
  assert.equal(bytesToHex(sha256(big)), nodeSha(Buffer.from(big)));
});

/* --------------------------- canonical encoder ---------------------------- */

test('canonical encoder sorts object keys', () => {
  assert.equal(dec(encodeCanonical({ z: 1n, a: 2n, m: 3n })), '{"a":2,"m":3,"z":1}');
  assert.equal(dec(encodeCanonical({})), '{}');
  assert.equal(dec(encodeCanonical([])), '[]');
});

test('canonical encoder escapes exactly like Go: C0 controls, quote, backslash', () => {
  // a " b \ c LF d TAB e U+0001 f
  const s = 'a"b\\c\nd\te\u0001f';
  assert.equal(dec(encodeCanonical({ s })), '{"s":"a\\"b\\\\c\\nd\\te\\u0001f"}');
  // DEL (0x7f) is NOT escaped, and non-ASCII UTF-8 passes through verbatim.
  assert.equal(dec(encodeCanonical({ s: '\u007f' })), '{"s":"\u007f"}');
  assert.equal(dec(encodeCanonical({ s: 'é—😀' })), '{"s":"é—😀"}');
});

test('canonical encoder emits booleans and nested structures', () => {
  const v = { t: true, f: false, arr: [1n, { b: 2n }], o: { k: 'v' } };
  assert.equal(dec(encodeCanonical(v)), '{"arr":[1,{"b":2}],"f":false,"o":{"k":"v"},"t":true}');
});

test('canonical encoder rejects floats by construction (only bigint is numeric)', () => {
  assert.throws(() => encodeCanonical({ n: 1.5 }), /unsupported value type/);
});

/* ----------------------- strict JSON reader (BigInt) ---------------------- */

test('parseJSONStrict preserves integers beyond 2^53', () => {
  const big = '123456789012345678901234567890';
  const v = parseJSONStrict(`{"start_ns":${big}}`);
  assert.equal(v.start_ns, BigInt(big));
  assert.equal(typeof v.start_ns, 'bigint');
});

test('parseJSONStrict rejects floats and trailing data', () => {
  assert.throws(() => parseJSONStrict('{"a":1.5}'), /floating point/);
  assert.throws(() => parseJSONStrict('{"a":1e3}'), /floating point/);
  assert.throws(() => parseJSONStrict('{"a":1} extra'), /trailing data/);
  assert.throws(() => parseJSONStrict('{"a":}'), /unexpected token/);
});

test('parseJSONStrict decodes escapes and keeps booleans/null', () => {
  const v = parseJSONStrict('{"a":"x\\u00e9\\n\\"","b":true,"c":null,"d":[]}');
  assert.equal(v.a, 'xé\n"');
  assert.equal(v.b, true);
  assert.equal(v.c, null);
  assert.deepEqual(v.d, []);
});

/* -------------------------------- Merkle --------------------------------- */

// An independent oracle, written differently from vpmp.mjs on purpose.
function oracleLeaf(i, data) {
  const pre = Buffer.alloc(9);
  pre[0] = 0x00;
  pre.writeBigUInt64BE(BigInt(i), 1);
  return createHash('sha256').update(Buffer.concat([pre, Buffer.from(data)])).digest();
}
function oracleNode(l, r) {
  return createHash('sha256').update(Buffer.concat([Buffer.from([0x01]), l, r])).digest();
}
function oracleRoot(leaves) {
  if (leaves.length === 0) return createHash('sha256').update(Buffer.alloc(0)).digest();
  let cur = leaves.map((l, i) => oracleLeaf(i, l));
  while (cur.length > 1) {
    const next = [];
    for (let j = 0; j * 2 < cur.length; j++) {
      const left = cur[2 * j];
      const right = 2 * j + 1 < cur.length ? cur[2 * j + 1] : left; // duplicate the last
      next.push(oracleNode(left, right));
    }
    cur = next;
  }
  return cur[0];
}

test('merkle root: empty tree is SHA-256("")', () => {
  assert.equal(merkleRootHex([]), nodeSha(Buffer.alloc(0)));
  assert.equal(
    merkleRootHex([]),
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  );
});

test('merkle root matches an independent oracle for many sizes', () => {
  for (let n = 1; n <= 40; n++) {
    const leaves = Array.from({ length: n }, (_, i) => utf8(`leaf-${i}`));
    assert.equal(merkleRootHex(leaves), oracleRoot(leaves).toString('hex'), `n=${n}`);
  }
});

test('merkle root duplicates the last node at an odd level', () => {
  const l = [utf8('a'), utf8('b'), utf8('c')];
  // root = H( H(0x01|H(l0)|H(l1)) , H(0x01|H(l2)|H(l2)) )
  const h0 = oracleLeaf(0, l[0]);
  const h1 = oracleLeaf(1, l[1]);
  const h2 = oracleLeaf(2, l[2]);
  const left = oracleNode(h0, h1);
  const right = oracleNode(h2, h2);
  assert.equal(merkleRootHex(l), oracleNode(left, right).toString('hex'));
});

test('merkle index binding: swapping two equal leaves changes the root', () => {
  const a = merkleRootHex([utf8('x'), utf8('x')]);
  const b = merkleRootHex([utf8('x')]);
  assert.notEqual(a, b);
});

/* ------------------------------ percentiles ------------------------------ */

test('percentile uses the nearest-rank definition, clamped', () => {
  const v = sortBigAsc([40n, 10n, 30n, 20n]);
  assert.deepEqual(v, [10n, 20n, 30n, 40n]);
  assert.equal(percentile(v, 500_000), 20n); // ceil(0.5*4)=2 -> v[1]
  assert.equal(percentile(v, 990_000), 40n); // ceil(0.99*4)=4 -> v[3]
  assert.equal(percentile(v, 0), 10n);
  assert.equal(percentile(v, 1_000_000), 40n);
  assert.equal(percentile([], 500_000), 0n);
  assert.equal(percentile([7n], 990_000), 7n);
});

test('percentile of 100 samples at p99 is the 99th smallest', () => {
  const v = sortBigAsc(Array.from({ length: 100 }, (_, i) => BigInt(i + 1)));
  assert.equal(percentile(v, 990_000), 99n);
  assert.equal(percentile(v, 950_000), 95n);
});

/* ------------------------------ statistics ------------------------------- */

test('order-statistic interval brackets the point estimate', () => {
  const v = sortBigAsc(Array.from({ length: 1000 }, (_, i) => BigInt(i + 1)));
  const [lo, hi] = ci95OrderStatistic(v, 990_000);
  assert.ok(lo <= hi, 'lo <= hi');
  assert.ok(lo <= 990n && hi >= 990n, `interval [${lo}, ${hi}] should bracket the p99 rank`);
  assert.ok(lo >= 900n && hi <= 1000n, `interval [${lo}, ${hi}] should stay in the upper tail`);
});

test('bootstrap CI is deterministic and brackets the point estimate', () => {
  const v = sortBigAsc(Array.from({ length: 500 }, (_, i) => BigInt((i * 37) % 1000)));
  const a = ci95Bootstrap(v, 990_000, 400, 0x9e3779b97f4a7c15n);
  const b = ci95Bootstrap(v, 990_000, 400, 0x9e3779b97f4a7c15n);
  assert.deepEqual(a, b, 'same seed -> same bounds');
  assert.ok(a[0] <= a[1], 'low <= high');
  const p99 = percentile(v, 990_000);
  assert.ok(a[0] <= p99 && p99 <= a[1], `p99 ${p99} should lie inside [${a}]`);
});

test('bootstrap CI responds to the seed on a spread-out sample', () => {
  // A heavy-tailed sample where the resampled p99 genuinely varies run to run.
  const v = sortBigAsc(Array.from({ length: 2000 }, (_, i) => BigInt(Math.floor((i + 1) ** 2))));
  const a = ci95Bootstrap(v, 990_000, 400, 0x9e3779b97f4a7c15n);
  const b = ci95Bootstrap(v, 990_000, 400, 0x1234567890abcdefn);
  assert.notDeepEqual(a, b, 'a different seed should move the resampled bounds');
});

/* ------------------------------- sidecar --------------------------------- */

const L1 = '{"bytes":100,"latency_ns":50,"seq":1,"start_ns":1000,"status":200,"worker":"w1"}';
const L2 = '{"bytes":100,"latency_ns":60,"seq":2,"start_ns":2000,"status":200,"worker":"w1"}';
const L3 = '{"bytes":100,"latency_ns":70,"seq":1,"start_ns":1000,"status":200,"worker":"w2"}';

test('loadSamples groups by worker and counts records', () => {
  const r = loadSamples([L1, L2, L3].join('\n') + '\n');
  assert.equal(r.error, null);
  assert.equal(r.total, 3);
  assert.equal(r.grouped.get('w1').length, 2);
  assert.equal(r.grouped.get('w2').length, 1);
  assert.equal(r.grouped.get('w1')[0].record.latency_ns, 50n);
});

test('loadSamples tolerates CRLF and blank lines', () => {
  const r = loadSamples(`${L1}\r\n\r\n${L2}\r\n`);
  assert.equal(r.error, null);
  assert.equal(r.total, 2);
});

test('loadSamples rejects a repeated sequence number inside one worker', () => {
  const r = loadSamples([L1, L1].join('\n'));
  assert.match(r.error, /repeats seq 1/);
});

test('loadSamples rejects malformed and out-of-range records', () => {
  assert.match(loadSamples('{"bytes":1}').error, /worker id is empty/);
  assert.match(loadSamples('{"bytes":1,"latency_ns":1,"start_ns":0,"status":200,"worker":"w"}').error, /seq must be >= 1/);
  assert.match(loadSamples('{"bytes":1,"latency_ns":-1,"seq":1,"start_ns":0,"status":200,"worker":"w"}').error, /latency_ns is negative/);
  assert.match(loadSamples('{"bytes":1,"latency_ns":1,"seq":1,"start_ns":0,"status":1000,"worker":"w"}').error, /status is out of range/);
  assert.match(loadSamples('not json').error, /not a valid record/);
});

/* --------------------- verifier hardening (parity/DoS) -------------------- */

test('strict reader keeps "__proto__" as an own property, never the prototype', () => {
  const o = parseJSONStrict('{"__proto__":{"polluted":true},"id":"w1"}');
  assert.equal(Object.getPrototypeOf(o), null, 'parsed objects must have no prototype');
  assert.deepEqual(Object.keys(o).sort(), ['__proto__', 'id']);
  assert.equal({}.polluted, undefined, 'Object.prototype must not be polluted');
  assert.equal(o.id, 'w1');
});

test('loadSamples rejects a line whose fields hide behind "__proto__"', () => {
  // Go's struct decode sees an empty worker and refuses this file. Without the
  // null-prototype reader the fields stay readable through the prototype chain,
  // so the JS verifier accepted a file the Go verifier rejected — and two
  // byte-distinct files shared one canonical digest.
  const line = '{"__proto__":{"bytes":10,"latency_ns":1,"seq":1,"start_ns":1000,"status":200,"worker":"w1"}}';
  const r = loadSamples(line + '\n');
  assert.match(r.error, /worker id is empty/);
  assert.equal(r.total, 0);
});

test('loadSamples enforces the 16 KiB per-line limit, like the Go loader', () => {
  const padded =
    '{"bytes":10,"latency_ns":1,"seq":1,"start_ns":1000,"status":200,"worker":"w1","pad":"' +
    'x'.repeat(20000) +
    '"}';
  const r = loadSamples(padded + '\n');
  assert.match(r.error, /exceeds the 16384 byte limit/);
});

test('loadSamples rejects integer values outside the ranges Go decodes', () => {
  // Also the DoS regression: an unbounded BigInt latency used to be pushed
  // through a per-bit bucketing loop (~0.6 s for a 100k-digit value, and the
  // cost grows quadratically). It is rejected in O(1) now.
  const tooBig = (1n << 64n).toString();
  const line = `{"bytes":0,"latency_ns":${tooBig},"seq":1,"start_ns":0,"status":200,"worker":"w1"}`;
  assert.match(loadSamples(line + '\n').error, /latency_ns is negative or missing/);
  const maxSeq = (1n << 64n).toString();
  const l2 = `{"bytes":0,"latency_ns":1,"seq":${maxSeq},"start_ns":0,"status":200,"worker":"w1"}`;
  assert.match(loadSamples(l2 + '\n').error, /seq must be >= 1/);
});

test('loadSamples counts non-canonical lines but still accepts them', () => {
  const canonical = '{"bytes":10,"latency_ns":1,"seq":1,"start_ns":1000,"status":200,"worker":"w1"}';
  const padded = '{"bytes":11,"latency_ns":2,"seq":2,"start_ns":2000,"status":200,"worker":"w1","pad":1}';
  const r = loadSamples(`${canonical}\n${padded}\n`);
  assert.equal(r.error, null);
  assert.equal(r.total, 2);
  assert.equal(r.nonCanonical, 1);
});

test('verifyBundle never throws: a bundle with no commit object is invalid, not a crash', async () => {
  const key = 'aa'.repeat(32);
  const bundle = JSON.stringify({
    format: 'vpmp/v1',
    run: {},
    workers: [{ id: 'w1', public_key: key }],
    aggregate: {},
    integrity: {},
    signature: {},
  });
  const r = await verifyBundle(bundle, null);
  assert.equal(r.valid, false);
  assert.ok(r.errors.length >= 1, 'must record at least one failure');
  assert.ok(r.errors.some((e) => e.check === 'bundle-schema'), 'schema failure must be reported');
});

test('verifyBundle reports a verdict for a hostile aggregate count instead of hanging', async () => {
  // 2^62 samples: Go used to size an allocation from this claim and panic.
  const key = 'aa'.repeat(32);
  const bundle = JSON.stringify({
    format: 'vpmp/v1',
    run: { target: 'http://127.0.0.1:8080/', profile: 'constant-rps', duration_ns: 1000000000n.toString(), planned_rps: '1000.000' },
    workers: [
      {
        id: 'w1',
        public_key: key,
        commit: { merkle_root: key, sample_count: '4611686018427387904', window_start_ns: 0, window_end_ns: 1, signature: 'bb'.repeat(64) },
        aggregate: { count: '4611686018427387904', sum_latency_ns: 0, min_ns: 0, max_ns: 0, hist: { 1: '4611686018427387904' } },
      },
    ],
    aggregate: { count: '4611686018427387904', sum_latency_ns: 0, p50_ns: 0, p95_ns: 0, p99_ns: 0, rps: '1000.000', co_corrected: false, co_ci95_ns: { low_ns: 0, high_ns: 0 } },
    integrity: { schedule_accuracy_ppm: 1000000, dropped_samples: 0, achieved_rps: '1000.000', planned_rps: '1000.000' },
    signature: { alg: 'ed25519', key, sig: 'bb'.repeat(64), covers: 'sha256(canonical-bundle-without-signature)' },
  });
  const sidecar = '{"bytes":1,"latency_ns":2,"seq":1,"start_ns":0,"status":200,"worker":"w1"}\n';
  const r = await verifyBundle(bundle, sidecar);
  assert.equal(r.valid, false);
});

/* ------------------------------- helpers --------------------------------- */

test('hex helpers round-trip', () => {
  const b = randomBytes(32);
  assert.deepEqual(hexToBytes(bytesToHex(new Uint8Array(b))), new Uint8Array(b));
  assert.throws(() => hexToBytes('abc'), /odd length/);
  assert.throws(() => hexToBytes('zz'), /invalid digit/);
});
