// vpmp.mjs — an independent, dependency-free implementation of the VeriBench
// bundle verification algorithm (format `vpmp/v1`) in JavaScript.
//
// This is the browser/Node mirror of the Go verifier in internal/attest. It is
// deliberately a *re-implementation*, not a port of Go code: if both agree on a
// bundle, the agreement is evidence that the format is precisely specified.
//
// What it reproduces, bit for bit:
//
//   - the canonical JSON encoder (sorted keys, minimal RFC 8259 escaping,
//     integers only — no floating point anywhere in the protocol);
//   - the Merkle tree: LeafHash(i, leaf) = SHA-256(0x00 || uint64_be(i) || leaf),
//     NodeHash(l, r) = SHA-256(0x01 || l || r), odd level repeats its last node,
//     empty tree = SHA-256("");
//   - the SHA-256 digest of the canonical bundle without its signature, and the
//     Ed25519 signature over that digest;
//   - each worker's commit digest and Ed25519 commit signature;
//   - the run-wide aggregates, including the coordinated-omission correction
//     (integer-only) and the splitmix64 bootstrap confidence interval.
//
// Numbers: every integer in a bundle is parsed as a BigInt. `start_ns` is about
// 1.8e18, far beyond the 2^53 exact-integer range of a JS Number, so parsing
// these with JSON.parse would silently corrupt them. This module therefore uses
// its own JSON reader that yields BigInt for integers and refuses floats.
//
// Ed25519 verification uses WebCrypto (`crypto.subtle`), available in every
// current browser and in Node >= 20. No other external API is used.

/* -------------------------------------------------------------------------- */
/* small byte helpers                                                          */
/* -------------------------------------------------------------------------- */

const te = new TextEncoder();

/** utf8 encodes s to a Uint8Array. */
export function utf8(s) {
  return te.encode(s);
}

/** Decodes lowercase/uppercase hex to bytes. Throws on a malformed string. */
export function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0) {
    throw new Error('hex: odd length');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const b = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(b)) throw new Error('hex: invalid digit');
    out[i] = b;
  }
  return out;
}

/** Encodes bytes as lowercase hex. */
export function bytesToHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

function concat(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

/* -------------------------------------------------------------------------- */
/* SHA-256 (synchronous, pure JS)                                              */
/* -------------------------------------------------------------------------- */

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

function rotr(x, n) {
  return (x >>> n) | (x << (32 - n));
}

/**
 * sha256 returns the 32-byte SHA-256 digest of data (a Uint8Array).
 */
export function sha256(data) {
  const H = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);

  const bitLen = data.length * 8;
  // Padding: 0x80, then zeros, then the 64-bit big-endian length.
  const padded = new Uint8Array((((data.length + 9) + 63) & ~63));
  padded.set(data);
  padded[data.length] = 0x80;
  const dv = new DataView(padded.buffer);
  // Length fits in 53 bits for any realistic input; write it as two 32-bit words.
  dv.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000), false);
  dv.setUint32(padded.length - 4, bitLen >>> 0, false);

  const w = new Uint32Array(64);
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[i] + w[i]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0;
      d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
    H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) odv.setUint32(i * 4, H[i] >>> 0, false);
  return out;
}

/* -------------------------------------------------------------------------- */
/* strict JSON reader with BigInt integers                                     */
/* -------------------------------------------------------------------------- */

/**
 * parseJSONStrict parses JSON text into a tree in which every integer is a
 * BigInt. Floats are rejected: vpmp/v1 has no floating point, so a float in a
 * bundle is a malformed bundle, not a value to round.
 */
export function parseJSONStrict(text) {
  let i = 0;
  const n = text.length;

  function ws() {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  }

  function fail(msg) {
    throw new Error(`${msg} at offset ${i}`);
  }

  function parseValue() {
    ws();
    if (i >= n) fail('unexpected end of input');
    const c = text[i];
    if (c === '{') return parseObject();
    if (c === '[') return parseArray();
    if (c === '"') return parseString();
    if (c === '-' || (c >= '0' && c <= '9')) return parseNumber();
    if (text.startsWith('true', i)) { i += 4; return true; }
    if (text.startsWith('false', i)) { i += 5; return false; }
    if (text.startsWith('null', i)) { i += 4; return null; }
    fail('unexpected token');
  }

  function parseObject() {
    i++; // {
    const out = {};
    ws();
    if (text[i] === '}') { i++; return out; }
    for (;;) {
      ws();
      if (text[i] !== '"') fail('expected object key');
      const k = parseString();
      ws();
      if (text[i] !== ':') fail('expected colon');
      i++;
      out[k] = parseValue();
      ws();
      if (text[i] === ',') { i++; continue; }
      if (text[i] === '}') { i++; return out; }
      fail('expected , or }');
    }
  }

  function parseArray() {
    i++; // [
    const out = [];
    ws();
    if (text[i] === ']') { i++; return out; }
    for (;;) {
      out.push(parseValue());
      ws();
      if (text[i] === ',') { i++; continue; }
      if (text[i] === ']') { i++; return out; }
      fail('expected , or ]');
    }
  }

  function parseString() {
    i++; // opening quote
    let out = '';
    for (;;) {
      if (i >= n) fail('unterminated string');
      const ch = text[i];
      if (ch === '"') { i++; return out; }
      if (ch === '\\') {
        i++;
        const e = text[i++];
        switch (e) {
          case '"': out += '"'; break;
          case '\\': out += '\\'; break;
          case '/': out += '/'; break;
          case 'b': out += '\b'; break;
          case 'f': out += '\f'; break;
          case 'n': out += '\n'; break;
          case 'r': out += '\r'; break;
          case 't': out += '\t'; break;
          case 'u': {
            const hex = text.slice(i, i + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail('bad \\u escape');
            out += String.fromCharCode(parseInt(hex, 16));
            i += 4;
            break;
          }
          default: fail('bad escape');
        }
        continue;
      }
      out += ch;
      i++;
    }
  }

  function parseNumber() {
    const start = i;
    if (text[i] === '-') i++;
    while (i < n && text[i] >= '0' && text[i] <= '9') i++;
    let isFloat = false;
    if (text[i] === '.') { isFloat = true; i++; while (i < n && text[i] >= '0' && text[i] <= '9') i++; }
    if (text[i] === 'e' || text[i] === 'E') { isFloat = true; i++; if (text[i] === '+' || text[i] === '-') i++; while (i < n && text[i] >= '0' && text[i] <= '9') i++; }
    const lexeme = text.slice(start, i);
    if (isFloat) fail('floating point is not allowed in vpmp/v1');
    return BigInt(lexeme);
  }

  const v = parseValue();
  ws();
  if (i !== n) fail('trailing data');
  return v;
}

/* -------------------------------------------------------------------------- */
/* canonical encoder (mirrors internal/attest/canonical.go)                    */
/* -------------------------------------------------------------------------- */

// Canonical JSON string escaping, byte for byte identical to Go's
// appendJSONString: quote, backslash, \b \f \n \r \t, and other C0 controls as
// \u00xx; every other byte (including all non-ASCII UTF-8) is emitted verbatim.
const HEX_LOWER = '0123456789abcdef';

function appendJSONString(out, s) {
  out.push(0x22); // "
  const bytes = te.encode(s);
  for (let i = 0; i < bytes.length; i++) {
    const c = bytes[i];
    if (c === 0x22) { out.push(0x5c, 0x22); continue; }
    if (c === 0x5c) { out.push(0x5c, 0x5c); continue; }
    if (c === 0x0a) { out.push(0x5c, 0x6e); continue; }
    if (c === 0x0d) { out.push(0x5c, 0x72); continue; }
    if (c === 0x09) { out.push(0x5c, 0x74); continue; }
    if (c === 0x08) { out.push(0x5c, 0x62); continue; }
    if (c === 0x0c) { out.push(0x5c, 0x66); continue; }
    if (c < 0x20) {
      out.push(0x5c, 0x75, 0x30, 0x30, HEX_LOWER.charCodeAt(c >> 4), HEX_LOWER.charCodeAt(c & 0x0f));
      continue;
    }
    out.push(c);
  }
  out.push(0x22); // "
}

function writeCanonical(out, v) {
  if (typeof v === 'bigint') {
    for (const ch of v.toString()) out.push(ch.charCodeAt(0));
    return;
  }
  if (typeof v === 'boolean') {
    for (const ch of (v ? 'true' : 'false')) out.push(ch.charCodeAt(0));
    return;
  }
  if (typeof v === 'string') {
    appendJSONString(out, v);
    return;
  }
  if (Array.isArray(v)) {
    out.push(0x5b); // [
    for (let i = 0; i < v.length; i++) {
      if (i > 0) out.push(0x2c);
      writeCanonical(out, v[i]);
    }
    out.push(0x5d); // ]
    return;
  }
  if (v && typeof v === 'object') {
    out.push(0x7b); // {
    const keys = Object.keys(v).sort();
    for (let i = 0; i < keys.length; i++) {
      if (i > 0) out.push(0x2c);
      appendJSONString(out, keys[i]);
      out.push(0x3a); // :
      writeCanonical(out, v[keys[i]]);
    }
    out.push(0x7d); // }
    return;
  }
  throw new Error(`canonical: unsupported value type ${typeof v}`);
}

/** encodeCanonical renders a canonical value tree to bytes. */
export function encodeCanonical(v) {
  const out = [];
  writeCanonical(out, v);
  return Uint8Array.from(out);
}

/* -------------------------------------------------------------------------- */
/* shared validation helpers                                                   */
/* -------------------------------------------------------------------------- */

const FORMAT_ID = 'vpmp/v1';
const BUNDLE_COVERS = 'sha256(canonical-bundle-without-signature)';
const EMPTY_ROOT_HEX = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const MAX_WORKER_ID_LEN = 128;
const MAX_STATUS = 999;
const MAX_SAMPLES_PER_WORKER = 5_000_000;
const MAX_SAMPLES_TOTAL = 10_000_000;
const PROOF_SAMPLE_WIDTH = 256;
const BOOTSTRAP_ITERATIONS = 400;
const BOOTSTRAP_SEED = 0x9E3779B97F4A7C15n;
const PPM_SCALE = 1_000_000n;

function isHexFixed(s, hexLen) {
  return typeof s === 'string' && hexLen % 2 === 0 && s.length === hexLen && /^[0-9a-f]*$/.test(s);
}

function isValidUTF8String(s) {
  if (typeof s !== 'string') return false;
  // Reject lone surrogates: Go's utf8.ValidString would reject them, and
  // TextEncoder would silently replace them.
  return !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(s);
}

function validTextField(name, v) {
  if (typeof v !== 'string' || v === '') return `${name} is empty`;
  if (!isValidUTF8String(v)) return `${name} is not valid UTF-8`;
  if (te.encode(v).length > MAX_WORKER_ID_LEN * 8) return `${name} is implausibly long`;
  return null;
}

/** decimalMilli validates a canonical Decimal and returns value*1000 as BigInt. */
function decimalMilli(s) {
  if (typeof s !== 'string') return null;
  let dot = -1;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '.') {
      if (dot >= 0) return null;
      dot = i;
    } else if (!(c >= '0' && c <= '9')) {
      return null;
    }
  }
  if (dot < 0) return null;
  const whole = s.slice(0, dot);
  const frac = s.slice(dot + 1);
  if (frac.length !== 3 || whole.length === 0) return null;
  if (whole.length > 1 && whole[0] === '0') return null;
  const v = BigInt(whole);
  const f = BigInt(frac);
  if (v > (1n << 62n) / 1000n) return null;
  return v * 1000n + f;
}

function isDecimal(s) {
  return decimalMilli(s) !== null;
}

/** parseBucketUpperNS insists a histogram key is exactly 2^k - 1. */
function parseBucketUpperNS(key) {
  if (!/^(0|[1-9][0-9]*)$/.test(key)) return null;
  const v = BigInt(key);
  if (v > (1n << 63n) - 1n) return null;
  const u = v + 1n;
  if (u === 0n || (u & (u - 1n)) !== 0n) return null;
  return v;
}

/* -------------------------------------------------------------------------- */
/* Merkle tree (mirrors internal/attest/merkle.go)                             */
/* -------------------------------------------------------------------------- */

function leafHash(index, data) {
  const pre = new Uint8Array(9);
  pre[0] = 0x00;
  new DataView(pre.buffer).setBigUint64(1, BigInt(index), false);
  return sha256(concat(pre, data));
}

function nodeHash(l, r) {
  return sha256(concat(new Uint8Array([0x01]), l, r));
}

function levelHashes(leaves) {
  if (leaves.length === 0) return sha256(new Uint8Array(0));
  let cur = leaves.map((leaf, i) => leafHash(i, leaf));
  while (cur.length > 1) {
    const next = [];
    for (let j = 0; j * 2 < cur.length; j++) {
      const left = cur[2 * j];
      const right = 2 * j + 1 < cur.length ? cur[2 * j + 1] : left;
      next.push(nodeHash(left, right));
    }
    cur = next;
  }
  return cur[0];
}

/** merkleRootHex recomputes the committed Merkle root from ordered leaves. */
export function merkleRootHex(leaves) {
  return bytesToHex(levelHashes(leaves));
}

function merkleProof(leaves, index) {
  const n = leaves.length;
  if (index < 0 || index >= n) throw new Error('merkle: leaf index out of range');
  let cur = leaves.map((leaf, i) => leafHash(i, leaf));
  const proof = [];
  let pos = index;
  while (cur.length > 1) {
    let sibling = pos ^ 1;
    if (sibling >= cur.length) sibling = cur.length - 1;
    proof.push(cur[sibling]);
    const next = [];
    for (let j = 0; j * 2 < cur.length; j++) {
      const left = cur[2 * j];
      const right = 2 * j + 1 < cur.length ? cur[2 * j + 1] : left;
      next.push(nodeHash(left, right));
    }
    cur = next;
    pos >>= 1;
  }
  return proof;
}

function verifyProof(root, leaf, index, proof) {
  if (index < 0 || root.length !== 32) return false;
  let acc = leafHash(index, leaf);
  let pos = index;
  for (const sibling of proof) {
    if (sibling.length !== 32) return false;
    acc = pos & 1 ? nodeHash(sibling, acc) : nodeHash(acc, sibling);
    pos >>= 1;
  }
  if (pos !== 0) return false;
  return bytesEqual(acc, root);
}

function spreadIndices(n, width) {
  if (n <= 0) return [];
  if (width <= 1 || n === 1) return [0];
  const out = [];
  const seen = new Set();
  for (let k = 0; k < width; k++) {
    const idx = Math.floor((k * (n - 1)) / (width - 1));
    if (!seen.has(idx)) {
      seen.add(idx);
      out.push(idx);
    }
  }
  return out;
}

/* -------------------------------------------------------------------------- */
/* exact integer statistics (mirrors internal/honesty)                         */
/* -------------------------------------------------------------------------- */

export function sortBigAsc(v) {
  return v.slice().sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

/** percentile returns the nearest-rank quantile; ppm is parts per million. */
export function percentile(sorted, ppm) {
  const n = sorted.length;
  if (n === 0) return 0n;
  if (ppm <= 0) return sorted[0];
  if (ppm >= Number(PPM_SCALE)) return sorted[n - 1];
  let rank = (BigInt(ppm) * BigInt(n) + PPM_SCALE - 1n) / PPM_SCALE;
  if (rank < 1n) rank = 1n;
  if (rank > BigInt(n)) rank = BigInt(n);
  return sorted[Number(rank) - 1];
}

const MASK64 = (1n << 64n) - 1n;

class SplitMix64 {
  constructor(seed) {
    this.state = BigInt(seed) & MASK64;
  }
  next() {
    this.state = (this.state + 0x9E3779B97F4A7C15n) & MASK64;
    let z = this.state;
    z = ((z ^ (z >> 30n)) * 0xBF58476D1CE4E5B9n) & MASK64;
    z = ((z ^ (z >> 27n)) * 0x94D049BB133111EBn) & MASK64;
    return (z ^ (z >> 31n)) & MASK64;
  }
  intn(n) {
    return Number(this.next() % BigInt(n));
  }
}

function subsample(sorted, m) {
  const n = sorted.length;
  if (m >= n) return sorted.slice();
  const out = new Array(m);
  for (let i = 0; i < m; i++) {
    let idx = Math.floor((i * n) / m);
    if (idx >= n) idx = n - 1;
    out[i] = sorted[idx];
  }
  return out;
}

/**
 * ci95Bootstrap reproduces the producer's percentile bootstrap exactly: the
 * splitmix64 stream is fixed, so the bounds are byte-identical to the Go
 * verifier's.
 */
export function ci95Bootstrap(sorted, ppm, iterations, seed) {
  if (sorted.length === 0) return [0n, 0n];
  const work = sorted.length > 10_000 ? subsample(sorted, 10_000) : sorted;
  const m = work.length;
  if (m === 1) return [work[0], work[0]];
  const iters = iterations > 0 ? iterations : BOOTSTRAP_ITERATIONS;
  const rng = new SplitMix64(seed);
  const quants = new Array(iters);
  const buf = new Array(m);
  for (let it = 0; it < iters; it++) {
    for (let i = 0; i < m; i++) buf[i] = work[rng.intn(m)];
    buf.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    quants[it] = percentile(buf, ppm);
  }
  quants.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  let lo = percentile(quants, 25_000);
  let hi = percentile(quants, 975_000);
  if (lo > hi) [lo, hi] = [hi, lo];
  return [lo, hi];
}

function isqrt(x) {
  if (x === 0n) return 0n;
  let guess = 1n << BigInt(Math.floor((bitLength(x) + 1) / 2));
  for (;;) {
    const next = (guess + x / guess) / 2n;
    if (next >= guess) return guess;
    guess = next;
  }
}

function bitLength(x) {
  let n = 0;
  while (x > 0n) {
    x >>= 1n;
    n++;
  }
  return n;
}

/** ci95OrderStatistic mirrors the distribution-free cross-check interval. */
export function ci95OrderStatistic(sorted, ppm) {
  const n = sorted.length;
  if (n === 0) return [0n, 0n];
  if (n === 1) return [sorted[0], sorted[0]];
  if (ppm <= 0) return [sorted[0], sorted[0]];
  if (ppm >= Number(PPM_SCALE)) return [sorted[n - 1], sorted[n - 1]];
  const nn = BigInt(n);
  const fp = BigInt(ppm);
  const meanS = nn * fp;
  const varSq = nn * fp * (PPM_SCALE - fp);
  const sdS = isqrt(varSq);
  const z95 = 1_959_964n;
  const delta = (z95 * sdS + PPM_SCALE / 2n) / PPM_SCALE;
  const ceilScale = (s) => (s + PPM_SCALE - 1n) / PPM_SCALE;
  let loRank = ceilScale(meanS - delta);
  let hiRank = ceilScale(meanS + delta);
  const clamp = (v) => (v < 1n ? 1n : v > nn ? nn : v);
  loRank = clamp(loRank);
  hiRank = clamp(hiRank);
  return [sorted[Number(loRank) - 1], sorted[Number(hiRank) - 1]];
}

/* -------------------------------------------------------------------------- */
/* Ed25519 (WebCrypto)                                                         */
/* -------------------------------------------------------------------------- */

async function ed25519Verify(pubHex, msg, sigHex) {
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  if (!subtle) throw new Error('WebCrypto is unavailable: Ed25519 cannot be checked here');
  const key = await subtle.importKey('raw', hexToBytes(pubHex), { name: 'Ed25519' }, false, ['verify']);
  return subtle.verify({ name: 'Ed25519' }, key, hexToBytes(sigHex), msg);
}

/* -------------------------------------------------------------------------- */
/* digest construction (mirrors canonicalValue / CommitDigest)                 */
/* -------------------------------------------------------------------------- */

function digestHex(bytes) {
  return bytesToHex(sha256(bytes));
}

function commitCanonicalUnsigned(c) {
  return {
    merkle_root: c.merkle_root,
    sample_count: c.sample_count,
    window_start_ns: c.window_start_ns,
    window_end_ns: c.window_end_ns,
  };
}

function commitCanonical(c) {
  return { ...commitCanonicalUnsigned(c), signature: c.signature };
}

function bundleCanonical(b, withSig) {
  const workers = b.workers
    .slice()
    .sort((x, y) => (x.id < y.id ? -1 : x.id > y.id ? 1 : 0))
    .map((w) => {
      const hist = {};
      for (const k of Object.keys(w.aggregate.hist)) hist[k] = w.aggregate.hist[k];
      return {
        id: w.id,
        public_key: w.public_key,
        commit: commitCanonical(w.commit),
        aggregate: {
          count: w.aggregate.count,
          sum_latency_ns: w.aggregate.sum_latency_ns,
          min_ns: w.aggregate.min_ns,
          max_ns: w.aggregate.max_ns,
          hist,
        },
      };
    });
  const obj = {
    format: b.format,
    created_at: b.created_at,
    tool: { name: b.tool.name, version: b.tool.version },
    run: {
      target: b.run.target,
      profile: b.run.profile,
      duration_ns: b.run.duration_ns,
      planned_rps: b.run.planned_rps,
    },
    aggregate: {
      count: b.aggregate.count,
      sum_latency_ns: b.aggregate.sum_latency_ns,
      p50_ns: b.aggregate.p50_ns,
      p95_ns: b.aggregate.p95_ns,
      p99_ns: b.aggregate.p99_ns,
      rps: b.aggregate.rps,
      co_corrected: b.aggregate.co_corrected,
      co_ci95_ns: { low_ns: b.aggregate.co_ci95_ns.low_ns, high_ns: b.aggregate.co_ci95_ns.high_ns },
    },
    integrity: {
      schedule_accuracy_ppm: b.integrity.schedule_accuracy_ppm,
      dropped_samples: b.integrity.dropped_samples,
      achieved_rps: b.integrity.achieved_rps,
      planned_rps: b.integrity.planned_rps,
    },
    workers,
  };
  if (withSig) {
    obj.signature = {
      alg: b.signature.alg,
      key: b.signature.key,
      sig: b.signature.sig,
      covers: b.signature.covers,
    };
  }
  return obj;
}

/** bundleDigestHex returns SHA-256(canonical bundle without its signature). */
export function bundleDigestHex(b) {
  return digestHex(encodeCanonical(bundleCanonical(b, false)));
}

/* -------------------------------------------------------------------------- */
/* the verifier                                                                */
/* -------------------------------------------------------------------------- */

function fmtBig(v) {
  return typeof v === 'bigint' ? v.toString() : String(v);
}

function shortHex(h) {
  if (typeof h !== 'string' || h.length <= 24) return h;
  return `${h.slice(0, 16)}…`;
}

/**
 * verifyBundle checks a bundle (and optionally its sidecar).
 *
 * @param {string} bundleText  the JSON text of the bundle.
 * @param {string|null} samplesText  the JSONL sidecar text, or null to verify
 *        the bundle's internal consistency and signatures only.
 * @param {object} [opts]
 * @returns {Promise<object>} a report; `valid` is true iff no check failed.
 */
export async function verifyBundle(bundleText, samplesText, opts = {}) {
  const skipCi = !!opts.skipCi;
  const errors = [];
  const warnings = [];
  const checks = [];
  const report = {
    valid: false,
    format: '',
    bundle_digest: '',
    samples_absent: samplesText == null,
    workers: [],
    samples_total: 0,
    proofs_verified: 0,
    checks_run: 0,
    checks_failed: 0,
    aggregate: null,
    errors,
    warnings,
    checks,
  };

  const pass = (name, detail, worker = '') => checks.push({ name, ok: true, detail, worker });
  const fail = (name, detail, worker = '', index = null) => {
    checks.push({ name, ok: false, detail, worker });
    errors.push({ check: name, worker, detail, index });
  };
  const warn = (msg) => warnings.push(msg);

  // 1. parse
  let b;
  try {
    b = parseJSONStrict(bundleText);
  } catch (e) {
    fail('bundle-json', `bundle is not valid JSON: ${e.message}`);
    return finalize();
  }
  if (!b || typeof b !== 'object' || Array.isArray(b)) {
    fail('bundle-json', 'bundle is not a JSON object');
    return finalize();
  }

  // 2. format
  report.format = typeof b.format === 'string' ? b.format : '';
  if (b.format === FORMAT_ID) pass('format', `format is ${FORMAT_ID}`);
  else fail('format', `format is ${JSON.stringify(b.format)}, want ${FORMAT_ID}`);

  // 3. structural validation (mirrors attest.Bundle.Validate)
  const schemaErr = validateBundle(b);
  if (schemaErr) fail('bundle-schema', schemaErr);
  else pass('bundle-schema', 'structure, cross-sums, rate identities and pacing bookkeeping hold');

  // 4. digest (for reporting)
  try {
    report.bundle_digest = bundleDigestHex(b);
  } catch { /* reported via the signature check */ }

  // 5. coordinator signature
  try {
    const digest = sha256(encodeCanonical(bundleCanonical(b, false)));
    const ok = await ed25519Verify(b.signature.key, digest, b.signature.sig);
    if (ok) pass('bundle-signature', `Ed25519 signature verifies over ${shortHex(report.bundle_digest)}`);
    else fail('bundle-signature', 'Ed25519 signature does not verify against the canonical bundle');
  } catch (e) {
    fail('bundle-signature', e.message);
  }

  // 6. duplicate worker ids
  {
    const seen = new Map();
    let dup = false;
    const ws = Array.isArray(b.workers) ? b.workers : [];
    for (let i = 0; i < ws.length; i++) {
      const id = ws[i] && ws[i].id;
      if (seen.has(id)) {
        fail('worker-id', `duplicate worker id ${JSON.stringify(id)} at positions ${seen.get(id)} and ${i}`);
        dup = true;
      } else {
        seen.set(id, i);
      }
    }
    if (!dup) pass('worker-id', `${seen.size} distinct worker ids`);
  }

  // 7. rate identity + pacing bookkeeping (no sidecar needed)
  verifyRateIdentity();
  verifyIntegrity();

  // 8. load the sidecar, if present
  let samples = null; // Map<workerID, Record[]>
  if (samplesText != null) {
    const loaded = loadSamples(samplesText);
    if (loaded.error) {
      fail('samples-load', loaded.error);
    } else {
      samples = loaded.grouped;
      report.samples_total = loaded.total;
      for (const w of loaded.warnings) warn(w);
    }
  }

  // 9. workers
  let total = 0;
  const ws = Array.isArray(b.workers) ? b.workers : [];
  for (const w of ws) {
    const n = await verifyWorker(w, samples);
    total += n;
  }
  if (samples != null && total > MAX_SAMPLES_TOTAL) {
    fail('samples-limit', `${total} records exceed the ${MAX_SAMPLES_TOTAL} record limit`);
  }

  // 10. run-wide aggregate
  if (samples != null) {
    verifyGlobalAggregate(samples);
  }

  return finalize();

  /* ----------------------------- closures --------------------------------- */

  function finalize() {
    report.checks_run = checks.length;
    report.checks_failed = errors.length;
    report.valid = errors.length === 0;
    report.workers_ok = 0;
    report.workers_count = wsOf(b).length;
    report.proofs_verified = report.proofs_verified || 0;
    report.co_corrected = b && b.aggregate ? b.aggregate.co_corrected === true : false;
    if (b && b.aggregate) {
      report.aggregate = {
        count: fmtBig(b.aggregate.count),
        p50_ns: fmtBig(b.aggregate.p50_ns),
        p95_ns: fmtBig(b.aggregate.p95_ns),
        p99_ns: fmtBig(b.aggregate.p99_ns),
        ci_low_ns: fmtBig(b.aggregate.co_ci95_ns ? b.aggregate.co_ci95_ns.low_ns : 0n),
        ci_high_ns: fmtBig(b.aggregate.co_ci95_ns ? b.aggregate.co_ci95_ns.high_ns : 0n),
      };
    }
    return report;
  }

  function wsOf(bundle) {
    return bundle && Array.isArray(bundle.workers) ? bundle.workers : [];
  }

  function verifyRateIdentity() {
    const count = num(b, ['aggregate', 'count']);
    const durNS = num(b, ['run', 'duration_ns']);
    if (count === null || durNS === null || durNS <= 0n) return;
    const achievedMilli = mulDivRound(count, 1_000_000_000n * 1000n, durNS);
    const want = decimalFromMilli(achievedMilli);
    const got = b.aggregate && b.aggregate.rps;
    if (want === null) return;
    if (want !== got) {
      fail('aggregate-rate', `aggregate.rps ${JSON.stringify(got)} does not equal ${count} requests over ${durNS} ns (${want})`);
      return;
    }
    pass('aggregate-rate', `aggregate.rps ${JSON.stringify(got)} equals ${count} requests over ${durNS} ns`);
  }

  function verifyIntegrity() {
    const plannedMilli = typeof b.integrity?.planned_rps === 'string' ? decimalMilli(b.integrity.planned_rps) : null;
    const achievedMilli = typeof b.integrity?.achieved_rps === 'string' ? decimalMilli(b.integrity.achieved_rps) : null;
    const durNS = num(b, ['run', 'duration_ns']);
    const count = num(b, ['aggregate', 'count']);
    if (plannedMilli === null || achievedMilli === null || durNS === null || count === null) return;
    const wantDropped = droppedSamples(plannedMilli, durNS, count);
    if (b.integrity.dropped_samples !== wantDropped) {
      fail('integrity', `dropped_samples ${fmtBig(b.integrity.dropped_samples)} does not equal the ${wantDropped} planned slots left empty`);
      return;
    }
    const wantAccuracy = scheduleAccuracyPPM(plannedMilli, achievedMilli);
    if (b.integrity.schedule_accuracy_ppm !== wantAccuracy) {
      fail('integrity', `schedule_accuracy_ppm ${fmtBig(b.integrity.schedule_accuracy_ppm)} does not equal the ${wantAccuracy} recomputed from the rates`);
      return;
    }
    pass('integrity', `dropped_samples ${wantDropped} and schedule_accuracy_ppm ${wantAccuracy} reproduce from the rates`);
  }

  async function verifyWorker(w, map) {
    const wr = { id: w.id, public_key: w.public_key, samples: -1, checks: [], errors: [] };
    report.workers.push(wr);
    const wp = (name, detail) => { wr.checks.push({ name, ok: true, detail }); pass(name, detail, w.id); };
    const wf = (name, detail, index = null) => {
      wr.checks.push({ name, ok: false, detail });
      wr.errors.push({ name, detail, index });
      fail(name, detail, w.id, index);
    };

    let keyOK = true;
    if (!isHexFixed(w.public_key, 64)) {
      wf('worker-key', 'public key is not a 64-character lowercase hex string');
      keyOK = false;
    } else {
      wp('worker-key', 'public key is a 32-byte Ed25519 key');
    }

    if (keyOK) {
      try {
        const digest = sha256(encodeCanonical(commitCanonicalUnsigned(w.commit)));
        const ok = await ed25519Verify(w.public_key, digest, w.commit.signature);
        if (ok) wp('commit-signature', 'Ed25519 commit signature verifies');
        else wf('commit-signature', 'commit signature does not verify for this worker key');
      } catch (e) {
        wf('commit-signature', e.message);
      }
    }

    if (map === null) {
      wp('samples', 'sidecar absent: signature and internal consistency only');
      return 0;
    }

    const recs = map.get(w.id);
    if (recs === undefined && w.commit.sample_count === 0n) {
      wp('samples', 'no samples expected and none provided');
      return 0;
    }
    if (recs === undefined) {
      wf('samples', `no sidecar records for a worker that committed ${w.commit.sample_count} samples`);
      return 0;
    }
    if (recs.length === 0) {
      wr.samples = 0;
      if (w.commit.sample_count === 0n) {
        wp('samples', 'empty sidecar for a worker that committed nothing');
        return 0;
      }
      wf('samples', `sidecar is empty but the commit claims ${w.commit.sample_count} samples`);
      return 0;
    }
    if (recs.length > MAX_SAMPLES_PER_WORKER) {
      wr.samples = recs.length;
      wf('samples-limit', `${recs.length} records exceed the ${MAX_SAMPLES_PER_WORKER} record per-worker limit`);
      return 0;
    }
    wr.samples = recs.length;

    // record-level validity / identity
    for (let i = 0; i < recs.length; i++) {
      const e = recs[i];
      if (e.validateErr) { wf('sample-validate', e.validateErr, i); return recs.length; }
      if (e.record.worker !== w.id) {
        wf('sample-worker', `record worker is ${JSON.stringify(e.record.worker)}, want ${JSON.stringify(w.id)}`, i);
        return recs.length;
      }
    }
    if (!recordsInFileOrder(recs)) {
      warn(`worker ${JSON.stringify(w.id)}: sidecar records are not in canonical (start_ns, seq) order`);
    }

    const ordered = sortRecords(recs);
    const leaves = ordered.map((e) => encodeCanonical(recordCanonical(e.record)));

    // commit count
    if (w.commit.sample_count === BigInt(recs.length)) {
      wp('commit-count', `${recs.length} records match commit.sample_count`);
    } else {
      wf('commit-count', `sidecar has ${recs.length} records but commit.sample_count is ${w.commit.sample_count}`);
    }

    // commit root
    const recomputed = merkleRootHex(leaves);
    if (recomputed === w.commit.merkle_root) {
      wp('commit-root', `${leaves.length} leaves reproduce the committed Merkle root ${shortHex(recomputed)}`);
      report.proofs_verified += verifySpreadProofs(w, leaves, w.commit.merkle_root);
    } else {
      const found = findFirstFailingLeaf(w.commit.merkle_root, leaves);
      let detail = `recomputed Merkle root ${shortHex(recomputed)} does not match the committed root ${shortHex(w.commit.merkle_root)}`;
      if (found.index !== null) {
        detail += `; ${found.fails} of ${leaves.length} inclusion proofs fail against the signed root, first at leaf ${found.index}`;
      }
      wf('commit-root', detail, found.index);
    }

    // worker aggregate (raw latencies)
    const stats = aggregateRecords(ordered, 0n, false, 0n);
    const aggErr = compareWorkerAgg(stats, w.aggregate);
    if (aggErr) {
      wf('worker-aggregate', aggErr);
      return recs.length;
    }
    wp('worker-aggregate', `count ${stats.count}, sum ${stats.sum}, min ${stats.min}, max ${stats.max} and histogram reproduce`);
    return recs.length;
  }

  function verifySpreadProofs(w, leaves, rootHex) {
    const root = hexToBytes(rootHex);
    const n = leaves.length;
    if (n === 0 || root.length !== 32) return 0;
    let width = Math.min(PROOF_SAMPLE_WIDTH, Math.max(1, Math.floor(25_000_000 / Math.max(1, n))));
    let checked = 0;
    for (const i of spreadIndices(n, Math.min(width, n))) {
      const proof = merkleProof(leaves, i);
      if (!verifyProof(root, leaves[i], i, proof)) {
        fail('proofs', 'inclusion proof does not verify against the committed root', w.id, i);
        return checked;
      }
      checked++;
    }
    pass('proofs', `${checked} inclusion proofs verify against the committed root`, w.id);
    return checked;
  }

  function findFirstFailingLeaf(rootHex, leaves) {
    let root;
    try {
      root = hexToBytes(rootHex);
    } catch {
      return { index: null, fails: 0 };
    }
    if (root.length !== 32 || leaves.length === 0) return { index: null, fails: 0 };
    const n = leaves.length;
    const cost = n * Math.ceil(Math.log2(Math.max(2, n)));
    if (cost > 25_000_000) return { index: null, fails: 0 };
    let fails = 0;
    let first = -1;
    for (let i = 0; i < n; i++) {
      if (!verifyProof(root, leaves[i], i, merkleProof(leaves, i))) {
        fails++;
        if (first < 0) first = i;
      }
    }
    return { index: first < 0 ? null : first, fails };
  }

  function verifyGlobalAggregate(map) {
    const plannedMilli = decimalMilli(b.run.planned_rps);
    if (plannedMilli === null) {
      fail('aggregate-percentiles', 'planned_rps: not a canonical decimal');
      return;
    }
    const co = b.aggregate.co_corrected === true;
    const ws = Array.isArray(b.workers) ? b.workers : [];
    for (const w of ws) {
      if (!map.has(w.id)) {
        warn(`global aggregate not recomputed: worker ${JSON.stringify(w.id)} has no sidecar records`);
        return;
      }
    }

    const values = [];
    let count = 0n;
    let sum = 0n;
    for (const w of ws) {
      const ordered = sortRecords(map.get(w.id));
      const windowStart = w.commit.window_start_ns;
      for (const e of ordered) {
        const r = e.record;
        sum += r.latency_ns;
        count += 1n;
        let val = r.latency_ns;
        if (co) {
          const corrected = correctedLatencyNS(r.start_ns, r.latency_ns, windowStart, r.seq, plannedMilli);
          if (corrected === null) {
            fail('aggregate-percentiles', 'coordinated-omission correction: overflow or bad schedule');
            return;
          }
          val = corrected;
        }
        values.push(val);
      }
    }

    if (count !== b.aggregate.count) {
      fail('aggregate-count', `sidecar holds ${count} records but aggregate.count is ${b.aggregate.count}`);
    } else {
      pass('aggregate-count', `${count} records match aggregate.count`);
    }
    if (sum !== b.aggregate.sum_latency_ns) {
      fail('aggregate-sum', `sidecar latencies sum to ${sum} but aggregate.sum_latency_ns is ${b.aggregate.sum_latency_ns}`);
    }

    const sorted = sortBigAsc(values);
    const p50 = percentile(sorted, 500_000);
    const p95 = percentile(sorted, 950_000);
    const p99 = percentile(sorted, 990_000);
    if (p50 !== b.aggregate.p50_ns || p95 !== b.aggregate.p95_ns || p99 !== b.aggregate.p99_ns) {
      fail('aggregate-percentiles', `recomputed p50/p95/p99 ${p50}/${p95}/${p99} do not match the claimed ${b.aggregate.p50_ns}/${b.aggregate.p95_ns}/${b.aggregate.p99_ns}`);
    } else {
      const label = co ? 'coordinated-omission-corrected' : 'raw';
      pass('aggregate-percentiles', `${label} p50/p95/p99 ${p50}/${p95}/${p99} reproduce exactly`);
    }

    verifyGlobalCI(sorted, co);
  }

  function verifyGlobalCI(sorted, co) {
    const ci = b.aggregate.co_ci95_ns;
    if (!co) {
      if (ci.low_ns !== 0n || ci.high_ns !== 0n) {
        fail('aggregate-ci', 'co_corrected is false but co_ci95_ns is not the zero interval');
      }
      return;
    }
    if (sorted.length === 0) return;
    const [lo, hi] = ci95OrderStatistic(sorted, 990_000);
    if (lo <= 0n && hi <= 0n) return;
    if (skipCi) {
      warn(`confidence interval not recomputed (skipCi): committed [${ci.low_ns}, ${ci.high_ns}], order-statistic [${lo}, ${hi}]`);
      return;
    }
    const [blo, bhi] = ci95Bootstrap(sorted, 990_000, BOOTSTRAP_ITERATIONS, BOOTSTRAP_SEED);
    if (blo !== ci.low_ns || bhi !== ci.high_ns) {
      fail('aggregate-ci', `recomputed bootstrap interval [${blo}, ${bhi}] does not match the committed [${ci.low_ns}, ${ci.high_ns}]`);
      return;
    }
    pass('aggregate-ci', `bootstrap interval [${blo}, ${bhi}] reproduces`);
    if (ci.high_ns < lo || ci.low_ns > hi) {
      warn(`committed confidence interval [${ci.low_ns}, ${ci.high_ns}] does not overlap the order-statistic interval [${lo}, ${hi}]`);
    }
  }
}

/* -------------------------------------------------------------------------- */
/* record helpers                                                              */
/* -------------------------------------------------------------------------- */

function recordCanonical(r) {
  return {
    bytes: r.bytes,
    latency_ns: r.latency_ns,
    seq: r.seq,
    start_ns: r.start_ns,
    status: r.status,
    worker: r.worker,
  };
}

function recordsInFileOrder(entries) {
  for (let i = 1; i < entries.length; i++) {
    const a = entries[i - 1].record;
    const c = entries[i].record;
    if (a.start_ns > c.start_ns) return false;
    if (a.start_ns === c.start_ns && a.seq > c.seq) return false;
  }
  return true;
}

function sortRecords(entries) {
  return entries
    .slice()
    .sort((x, y) => {
      const a = x.record;
      const c = y.record;
      if (a.start_ns !== c.start_ns) return a.start_ns < c.start_ns ? -1 : 1;
      if (a.seq !== c.seq) return a.seq < c.seq ? -1 : 1;
      return 0;
    });
}

function validateRecord(r) {
  if (typeof r.worker !== 'string' || r.worker === '') return 'record: worker id is empty';
  if (te.encode(r.worker).length > MAX_WORKER_ID_LEN) return 'record: worker id is too long';
  if (!isValidUTF8String(r.worker)) return 'record: worker id is not valid UTF-8';
  if (typeof r.seq !== 'bigint' || r.seq <= 0n) return 'record: seq must be >= 1';
  if (typeof r.start_ns !== 'bigint' || r.start_ns < 0n) return 'record: start_ns is negative or missing';
  if (typeof r.latency_ns !== 'bigint' || r.latency_ns < 0n) return 'record: latency_ns is negative or missing';
  if (typeof r.bytes !== 'bigint' || r.bytes < 0n) return 'record: bytes is negative or missing';
  if (typeof r.status !== 'bigint' || r.status < 0n || r.status > BigInt(MAX_STATUS)) return 'record: status is out of range';
  return null;
}

/**
 * loadSamples parses a sidecar JSONL text into a Map<workerID, entry[]>.
 * Entry = { record, rawLine, validateErr }.
 */
export function loadSamples(text) {
  const grouped = new Map();
  const warnings = [];
  const seenSeq = new Map();
  let total = 0;
  const lines = text.split('\n');
  for (let ln = 0; ln < lines.length; ln++) {
    const line = lines[ln].replace(/\r$/, '');
    if (line.trim() === '') continue;
    let rec;
    try {
      rec = parseJSONStrict(line);
    } catch (e) {
      return { error: `samples: line ${ln + 1} is not a valid record: ${e.message}`, grouped, warnings, total };
    }
    if (!rec || typeof rec !== 'object' || Array.isArray(rec)) {
      return { error: `samples: line ${ln + 1} is not a JSON object`, grouped, warnings, total };
    }
    const err = validateRecord(rec);
    if (err) return { error: `samples: line ${ln + 1}: ${err}`, grouped, warnings, total };
    if (seenSeq.get(rec.worker)?.has(rec.seq)) {
      return { error: `samples: line ${ln + 1}: worker ${JSON.stringify(rec.worker)} repeats seq ${rec.seq}`, grouped, warnings, total };
    }
    if (!seenSeq.has(rec.worker)) seenSeq.set(rec.worker, new Set());
    seenSeq.get(rec.worker).add(rec.seq);
    total++;
    if (total > MAX_SAMPLES_TOTAL) {
      return { error: `samples: file exceeds the ${MAX_SAMPLES_TOTAL} record limit`, grouped, warnings, total };
    }
    if (!grouped.has(rec.worker)) grouped.set(rec.worker, []);
    if (grouped.get(rec.worker).length >= MAX_SAMPLES_PER_WORKER) {
      return { error: `samples: worker ${JSON.stringify(rec.worker)} exceeds the ${MAX_SAMPLES_PER_WORKER} record limit`, grouped, warnings, total };
    }
    grouped.get(rec.worker).push({ record: rec, rawLine: line, validateErr: null });
  }
  return { error: null, grouped, warnings, total };
}

/* -------------------------------------------------------------------------- */
/* bundle schema validation (mirrors attest.Bundle.Validate)                   */
/* -------------------------------------------------------------------------- */

function num(root, path) {
  let cur = root;
  for (const k of path) {
    if (!cur || typeof cur !== 'object') return null;
    cur = cur[k];
  }
  return typeof cur === 'bigint' ? cur : null;
}

function decimalFromMilli(milli) {
  if (typeof milli !== 'bigint' || milli < 0n) return null;
  const w = milli / 1000n;
  const f = milli % 1000n;
  return `${w}.${f.toString().padStart(3, '0')}`;
}

function mulDivRound(a, b, d) {
  if (d === 0n) return null;
  const prod = a * b;
  const q = (prod + d / 2n) / d;
  return q;
}

function plannedSlots(plannedMilli, durationNS) {
  return mulDivRound(plannedMilli, durationNS, 1_000_000_000n * 1000n);
}

function droppedSamples(plannedMilli, durationNS, count) {
  const slots = plannedSlots(plannedMilli, durationNS);
  if (slots === null) return null;
  return count >= slots ? 0n : slots - count;
}

function scheduleAccuracyPPM(plannedMilli, achievedMilli) {
  if (plannedMilli <= 0n) return achievedMilli <= 0n ? PPM_SCALE : 0n;
  const diff = achievedMilli >= plannedMilli ? achievedMilli - plannedMilli : plannedMilli - achievedMilli;
  const deviation = mulDivRound(diff, PPM_SCALE, plannedMilli);
  if (deviation === null || deviation >= PPM_SCALE) return 0n;
  return PPM_SCALE - deviation;
}

function intendedStartNS(windowStartNS, seq, rpsMilli) {
  if (rpsMilli <= 0n || windowStartNS < 0n) return null;
  const slot = seq > 0n ? seq - 1n : 0n;
  const offset = mulDivRound(slot, 1_000_000_000n * 1000n, rpsMilli);
  if (offset === null) return null;
  return windowStartNS + offset;
}

function correctedLatencyNS(startNS, latencyNS, windowStartNS, seq, rpsMilli) {
  if (latencyNS < 0n) return null;
  const intended = intendedStartNS(windowStartNS, seq, rpsMilli);
  if (intended === null) return null;
  const wait = startNS > intended ? startNS - intended : 0n;
  return latencyNS + wait;
}

function bucketUpperNS(v) {
  if (v <= 0n) return 0n;
  let k = 0n;
  let x = v;
  while (x > 0n) {
    x >>= 1n;
    k += 1n;
  }
  return (1n << k) - 1n;
}

function aggregateRecords(entries, windowStartNS, co, rpsMilli) {
  const hist = new Map();
  let count = 0n;
  let sum = 0n;
  let min = 0n;
  let max = 0n;
  const values = [];
  for (const e of entries) {
    const r = e.record;
    let val = r.latency_ns;
    if (co) {
      val = correctedLatencyNS(r.start_ns, r.latency_ns, windowStartNS, r.seq, rpsMilli);
      if (val === null) return null;
    }
    if (count === 0n) {
      min = val;
      max = val;
    } else {
      if (val < min) min = val;
      if (val > max) max = val;
    }
    count += 1n;
    sum += val;
    const key = bucketUpperNS(val).toString();
    hist.set(key, (hist.get(key) || 0n) + 1n);
    values.push(val);
  }
  values.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return { count, sum, min, max, hist, values };
}

function compareWorkerAgg(stats, claim) {
  if (stats === null) return 'aggregate: recomputation failed';
  if (stats.count !== claim.count) return `aggregate: count ${stats.count} does not match the claimed ${claim.count}`;
  if (stats.sum !== claim.sum_latency_ns) return `aggregate: sum_latency_ns ${stats.sum} does not match the claimed ${claim.sum_latency_ns}`;
  if (stats.min !== claim.min_ns) return `aggregate: min_ns ${stats.min} does not match the claimed ${claim.min_ns}`;
  if (stats.max !== claim.max_ns) return `aggregate: max_ns ${stats.max} does not match the claimed ${claim.max_ns}`;
  const claimKeys = Object.keys(claim.hist);
  if (stats.hist.size !== claimKeys.length) {
    return `aggregate: histogram does not match the claim (${stats.hist.size} vs ${claimKeys.length} buckets)`;
  }
  for (const k of claimKeys) {
    if (stats.hist.get(k) !== claim.hist[k]) return `aggregate: histogram bucket ${k} disagrees`;
  }
  return null;
}

function validateBundle(b) {
  if (b.format !== FORMAT_ID) return `bundle: format is ${JSON.stringify(b.format)}, want ${JSON.stringify(FORMAT_ID)}`;
  if (typeof b.created_at !== 'string' || !isRFC3339(b.created_at)) return `bundle: created_at ${JSON.stringify(b.created_at)} is not RFC3339`;
  if (!b.tool || typeof b.tool !== 'object') return 'bundle: tool is missing';
  {
    const e = validTextField('tool.name', b.tool.name);
    if (e) return `bundle: ${e.replace('tool.name', 'tool.name')}`;
  }
  if (typeof b.tool.version !== 'string' || b.tool.version === '') return 'bundle: tool.version is empty';
  if (!b.run || typeof b.run !== 'object') return 'bundle: run is missing';
  {
    const e = validTextField('run.target', b.run.target);
    if (e) return `bundle: ${e}`;
  }
  if (typeof b.run.profile !== 'string' || b.run.profile === '') return 'bundle: run.profile is empty';
  if (num(b, ['run', 'duration_ns']) === null || b.run.duration_ns <= 0n) return `bundle: run.duration_ns ${fmtBig(b.run.duration_ns)} must be positive`;
  if (!isDecimal(b.run.planned_rps)) return `bundle: run.planned_rps ${JSON.stringify(b.run.planned_rps)} is not a canonical decimal`;
  const workers = b.workers;
  if (!Array.isArray(workers) || workers.length === 0) return 'bundle: workers is empty';

  const seen = new Set();
  let sumCount = 0n;
  let sumLatency = 0n;
  for (const w of workers) {
    if (seen.has(w.id)) return `bundle: duplicate worker id ${JSON.stringify(w.id)}`;
    seen.add(w.id);
    const we = validateWorker(w);
    if (we) return we;
    sumCount += w.aggregate.count;
    sumLatency += w.aggregate.sum_latency_ns;
  }
  const ae = validateAggregate(b.aggregate);
  if (ae) return ae;
  if (b.aggregate.count !== sumCount) {
    return `bundle: aggregate.count ${b.aggregate.count} does not match the ${sumCount} requests summed over workers`;
  }
  if (b.aggregate.sum_latency_ns !== sumLatency) {
    return `bundle: aggregate.sum_latency_ns ${b.aggregate.sum_latency_ns} does not match the ${sumLatency} summed over workers`;
  }
  const ie = validateIntegrity(b.integrity, b.run, b.aggregate);
  if (ie) return ie;
  const se = validateSignature(b.signature);
  if (se) return se;
  return null;
}

function validateWorker(w) {
  const e = validTextField('worker.id', w.id);
  if (e) return `bundle: ${e}`;
  if (!isHexFixed(w.public_key, 64)) return `bundle: worker ${JSON.stringify(w.id)} public_key is not a 64-character lowercase hex string`;
  const ce = validateCommit(w.commit);
  if (ce) return `bundle: worker ${JSON.stringify(w.id)}: ${ce}`;
  if (w.commit.sample_count !== w.aggregate.count) {
    return `bundle: worker ${JSON.stringify(w.id)} commit.sample_count ${w.commit.sample_count} does not match aggregate.count ${w.aggregate.count}`;
  }
  const ae = validateWorkerAgg(w.aggregate);
  if (ae) return `bundle: worker ${JSON.stringify(w.id)}: ${ae}`;
  return null;
}

function validateCommit(c) {
  if (!isHexFixed(c.merkle_root, 64)) return 'commit: merkle_root is not a 64-character lowercase hex string';
  if (typeof c.window_start_ns !== 'bigint' || c.window_start_ns < 0n) return 'commit: window_start_ns is negative';
  if (typeof c.window_end_ns !== 'bigint' || c.window_end_ns < c.window_start_ns) return 'commit: window_end_ns precedes window_start_ns';
  if (c.sample_count === 0n && c.merkle_root !== EMPTY_ROOT_HEX) return `commit: zero samples must commit to the empty root ${EMPTY_ROOT_HEX}`;
  if (c.sample_count > 0n && c.merkle_root === EMPTY_ROOT_HEX) return `commit: ${c.sample_count} samples cannot commit to the empty root`;
  if (!isHexFixed(c.signature, 128)) return 'commit: signature is not a 128-character lowercase hex string';
  return null;
}

function validateWorkerAgg(a) {
  if (a.count === 0n) {
    if (a.sum_latency_ns !== 0n || a.min_ns !== 0n || a.max_ns !== 0n) return 'aggregate: zero count must have zero sum, min and max';
    if (Object.keys(a.hist).length !== 0) return 'aggregate: zero count must have an empty histogram';
    return null;
  }
  if (typeof a.min_ns !== 'bigint' || a.min_ns < 0n) return 'aggregate: min_ns is negative';
  if (a.max_ns < a.min_ns) return 'aggregate: max_ns is below min_ns';
  const keys = Object.keys(a.hist);
  if (keys.length === 0) return 'aggregate: non-zero count must have a histogram';
  let histTotal = 0n;
  for (const k of keys) {
    if (parseBucketUpperNS(k) === null) return `aggregate: histogram key ${JSON.stringify(k)} is not of the form 2^k-1`;
    const v = a.hist[k];
    if (typeof v !== 'bigint' || v === 0n) return `aggregate: histogram key ${JSON.stringify(k)} has a zero or invalid count`;
    histTotal += v;
  }
  if (histTotal !== a.count) return `aggregate: histogram counts sum to ${histTotal}, want ${a.count}`;
  return null;
}

function validateAggregate(a) {
  if (a.count === 0n) {
    if (a.sum_latency_ns !== 0n || a.p50_ns !== 0n || a.p95_ns !== 0n || a.p99_ns !== 0n) {
      return 'bundle: zero aggregate.count must have zero latencies';
    }
  } else if (a.p50_ns < 0n || a.p95_ns < a.p50_ns || a.p99_ns < a.p95_ns) {
    return `bundle: percentiles must satisfy 0 <= p50 <= p95 <= p99 (got ${a.p50_ns}, ${a.p95_ns}, ${a.p99_ns})`;
  }
  if (!isDecimal(a.rps)) return `bundle: aggregate.rps ${JSON.stringify(a.rps)} is not a canonical decimal`;
  if (a.co_ci95_ns.low_ns < 0n || a.co_ci95_ns.high_ns < a.co_ci95_ns.low_ns) {
    return `bundle: co_ci95_ns must satisfy 0 <= low <= high (got ${a.co_ci95_ns.low_ns}, ${a.co_ci95_ns.high_ns})`;
  }
  return null;
}

function validateIntegrity(inr, run, agg) {
  if (inr.planned_rps !== run.planned_rps) {
    return `bundle: integrity.planned_rps ${JSON.stringify(inr.planned_rps)} does not match run.planned_rps ${JSON.stringify(run.planned_rps)}`;
  }
  if (!isDecimal(inr.achieved_rps)) return `bundle: integrity.achieved_rps ${JSON.stringify(inr.achieved_rps)} is not a canonical decimal`;
  if (inr.achieved_rps !== agg.rps) {
    return `bundle: integrity.achieved_rps ${JSON.stringify(inr.achieved_rps)} does not match aggregate.rps ${JSON.stringify(agg.rps)}`;
  }
  if (inr.schedule_accuracy_ppm < 0n || inr.schedule_accuracy_ppm > PPM_SCALE) {
    return `bundle: integrity.schedule_accuracy_ppm ${inr.schedule_accuracy_ppm} is outside 0..${PPM_SCALE}`;
  }
  return null;
}

function validateSignature(s) {
  if (!s || typeof s !== 'object') return 'bundle: signature is missing';
  if (s.alg !== 'ed25519') return `bundle: signature.alg ${JSON.stringify(s.alg)} is not supported`;
  if (!isHexFixed(s.key, 64)) return 'bundle: signature.key is not a 64-character lowercase hex string';
  if (!isHexFixed(s.sig, 128)) return 'bundle: signature.sig is not a 128-character lowercase hex string';
  if (s.covers !== BUNDLE_COVERS) return `bundle: signature.covers ${JSON.stringify(s.covers)} is not ${JSON.stringify(BUNDLE_COVERS)}`;
  return null;
}

function isRFC3339(s) {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(s)) return false;
  const t = Date.parse(s);
  return !Number.isNaN(t);
}
