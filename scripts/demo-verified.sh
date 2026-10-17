#!/usr/bin/env bash
#
# VeriBench demo — "your load-test report is now a receipt".
#
# What this proves, mechanically and checkably:
#   1. A vpmp/v1 measurement bundle VERIFIES (signature + Merkle root + claims
#      recomputation + per-sample consistency)              -> PASS, exit 0
#   2. Exactly ONE byte of that bundle is altered           -> detected
#   3. The verifier REFUSES the altered bundle              -> FAIL, exit 1
#   4. Restoring the byte restores the verdict              -> PASS, exit 0
#
# Two modes, chosen automatically:
#   LIVE      — the real CLI, end to end:
#                 stress-strike keygen --out <key>
#                 stress-strike run --url <t> --rps 300 --users 30 --duration 10 \
#                                    --coordinated-omission --allow-private \
#                                    --emit-bundle <b> --bundle-key <key>
#                 stress-strike verify --bundle <b> --samples <b.samples.jsonl>
#               The binary is taken from STRESS_STRIKE_BIN, ./stress-strike, or
#               PATH; failing all of those, this script builds it from the
#               checkout, so a fresh clone with Go installed runs LIVE.
#   REFERENCE — only when no binary can be found *and* none can be built. Then
#               this script says so out loud and emits a spec-conformant bundle
#               from the embedded reference implementation, so the VERIFICATION
#               half of the demo is real even there. In REFERENCE mode NO load
#               is generated and NO traffic reaches any target.
#
# Idempotent: every run uses a fresh temp dir and removes it on exit.
#
# Env overrides:
#   STRESS_STRIKE_BIN   path to the binary to probe
#   DEMO_URL            target URL                (default http://127.0.0.1:8090/)
#   DEMO_DURATION       seconds, "10s" also works (default 10s)
#   DEMO_RPS            LIVE pacing cap, rps       (default 300)
#   DEMO_USERS          LIVE concurrent users     (default 30)
#   DEMO_ALLOW_PRIVATE=1  also allow --allow-private for a non-loopback target
#   DEMO_COUNT          samples in REFERENCE mode (default 1500)
#   VERIBENCH_KEEP=1    keep the temp dir instead of deleting it
#   NO_COLOR=1          disable ANSI colour
#
set -euo pipefail

# ─────────────────────────────── presentation ────────────────────────────────
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  R=$'\033[0m'; B=$'\033[1m'; DIM=$'\033[2m'
  RED=$'\033[1;31m'; GRN=$'\033[1;32m'; YEL=$'\033[1;33m'; CYN=$'\033[1;36m'
else
  R=; B=; DIM=; RED=; GRN=; YEL=; CYN=
fi

say()  { printf '%s\n' "$*"; }
step() { printf '\n%s\n' "${CYN}${B}── $* ──${R}"; }
ok()   { printf '%s\n' "${GRN}PASS${R}  $*"; }
bad()  { printf '%s\n' "${RED}FAIL${R}  $*"; }
warn() { printf '%s\n' "${YEL}NOTE${R}  $*"; }
note() { printf '%s\n' "${DIM}$*${R}"; }

banner() {
  say "${B}VeriBench — verifiable measurement demo${R}"
  say "${DIM}format vpmp/v1 · Ed25519 seal · Merkle-locked samples · offline verify${R}"
}

# ─────────────────────────────── environment ─────────────────────────────────
URL="${DEMO_URL:-http://127.0.0.1:8090/health}"
DURATION="${DEMO_DURATION:-10s}"
COUNT="${DEMO_COUNT:-1500}"
# Live-mode knobs. The load is a steady profile with a fixed --rps cap on
# purpose: that is the one schedule shape whose coordinated-omission correction
# this tool will claim (see coCorrectionGate in cmd/stress-strike/cmd_run.go),
# so the demo shows a corrected tail with its 95% interval rather than a
# withheld claim.
RPS="${DEMO_RPS:-300}"
USERS="${DEMO_USERS:-30}"
# `run` accepts an integer number of seconds; the demo also accepts the "10s"
# spelling in DEMO_DURATION for readability.
DURATION_SECS="${DURATION%s}"
# `run` refuses private/loopback targets unless told otherwise. Only the
# loopback case is auto-allowed here, so the flag keeps its meaning for a real
# target; a private-LAN address needs DEMO_ALLOW_PRIVATE=1.
case "${URL}" in
  http://127.0.0.1:*|http://localhost:*|http://\[::1\]:*) PRIVATE_OK="--allow-private" ;;
  *) PRIVATE_OK="${DEMO_ALLOW_PRIVATE:+--allow-private}" ;;
esac

TMPROOT="${TMPDIR:-/tmp}"
TMPROOT="${TMPROOT%/}"
WORK="$(mktemp -d "${TMPROOT}/veribench-demo.XXXXXX")"
cleanup() {
  if [ "${VERIBENCH_KEEP:-0}" = "1" ]; then
    note "temp dir kept: ${WORK}"
  else
    rm -rf "${WORK}"
  fi
}
trap cleanup EXIT

KEY="${WORK}/veribench.key"
BUNDLE="${WORK}/veribench-bundle.json"
SAMPLES="${BUNDLE%.json}.samples.jsonl"
REF="${WORK}/veribench_ref.py"

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1;  then shasum -a 256 "$1" | awk '{print $1}'
  else python3 - "$1" <<'PY'
import hashlib,sys
print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())
PY
  fi
}

# ──────────────────────────── CLI capability probe ───────────────────────────
# find_bin — the binary to drive. A candidate is accepted only if it exposes the
# VeriBench surface: a stale ./stress-strike left over from an older build
# predates `keygen`/`--emit-bundle`, and accepting one silently downgraded this
# demo to synthetic data once already. If nothing usable is found, build from
# this checkout (so a fresh clone with Go installed runs LIVE); failing that,
# return 1 and let the caller fall back to the reference implementation.
find_bin() {
  local cand root
  for cand in "${STRESS_STRIKE_BIN:-}" "./stress-strike" "$(command -v stress-strike 2>/dev/null || true)"; do
    if [ -n "${cand}" ] && [ -x "${cand}" ] && "$cand" run --help 2>&1 | grep -q -- '--emit-bundle'; then
      printf '%s' "${cand}"
      return 0
    fi
  done
  root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
  if [ -f "${root}/cmd/stress-strike/main.go" ] && command -v go >/dev/null 2>&1; then
    if (cd "${root}" && go build -o "${WORK}/stress-strike" ./cmd/stress-strike) >/dev/null 2>&1; then
      printf '%s' "${WORK}/stress-strike"
      return 0
    fi
  fi
  return 1
}

# probe_sub <name> — true if the binary implements the subcommand.
# We look for "unknown command" rather than grepping help text, because the
# current help output already contains the words "verify" (authorize verify /
# audit verify) and would produce false positives.
probe_sub() {
  local out
  out="$("$BIN" "$1" --veribench-probe 2>&1 || true)"
  case "${out}" in *"unknown command"*) return 1 ;; *) return 0 ;; esac
}

# probe_emit_bundle — true if `run` can seal a bundle. Ask the subcommand
# itself: the top-level help lists commands, not their flags, so grepping it
# reports the capability missing on a build that has it.
probe_emit_bundle() {
  local out
  out="$("$BIN" run --help 2>&1 || true)"
  case "${out}" in *"--emit-bundle"*) return 0 ;; *) return 1 ;; esac
}

# ─────────────────────────────── reference impl ──────────────────────────────
# A self-contained implementation of the vpmp/v1 specification documented in
# docs/INVENTION.md: pure-stdlib Ed25519 (RFC 8032 shape), RFC-6962-style
# domain-separated Merkle tree with "odd node promoted", nearest-rank
# percentiles over honest latency, and a seeded bootstrap 95% confidence
# interval. It exists so this demo is runnable and honest before the CLI
# integration lands, and so the verifier is independently re-implementable.
write_reference() {
  cat > "${REF}" <<'PYEOF'
#!/usr/bin/env python3
"""Reference implementation of vpmp/v1 (VeriBench). Stdlib only."""
import base64, datetime, hashlib, json, math, os, random, sys, time

# ------------------------------- Ed25519 -------------------------------------
P = 2**255 - 19
Q = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)


def _H(m):
    return hashlib.sha512(m).digest()


def _inv(x):
    return pow(x, P - 2, P)


def _xrecover(y):
    xx = (y * y - 1) * _inv(D * y * y + 1)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if x % 2 != 0:
        x = P - x
    return x


_By = (4 * _inv(5)) % P
_Bx = _xrecover(_By)
_B = (_Bx % P, _By % P, 1, (_Bx * _By) % P)


def _edwards(p1, p2):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + D * t1 * t2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - D * t1 * t2)
    z3 = z1 * z2
    return (x3 % P, y3 % P, z3 % P, (x3 * y3) % P)


def _scalarmult(pt, e):
    res = (0, 1, 1, 0)
    base = pt
    while e > 0:
        if e & 1:
            res = _edwards(res, base)
        base = _edwards(base, base)
        e >>= 1
    return res


def _encodepoint(pt):
    x, y, z, _t = pt
    zi = _inv(z)
    x = (x * zi) % P
    y = (y * zi) % P
    bits = [(y >> i) & 1 for i in range(255)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(32))


def _bit(h, i):
    return (h[i // 8] >> (i % 8)) & 1


def _expand(sk):
    h = _H(sk)
    a = 2**254 + sum(2**i * _bit(h, i) for i in range(3, 254))
    return a, h[32:64]


def _publickey(sk):
    a, _ = _expand(sk)
    return _encodepoint(_scalarmult(_B, a))


def _hint(m):
    h = _H(m)
    return sum(2**i * _bit(h, i) for i in range(512))


def _sign(m, sk):
    a, prefix = _expand(sk)
    pk = _encodepoint(_scalarmult(_B, a))
    r = _hint(prefix + m)
    R = _scalarmult(_B, r)
    S = (r + _hint(_encodepoint(R) + pk + m) * a) % Q
    return _encodepoint(R) + S.to_bytes(32, "little")


def _isoncurve(pt):
    x, y, z, t = pt
    return (-x * x + y * y - z * z - D * t * t) % P == 0


def _decodepoint(s):
    if len(s) != 32:
        raise ValueError("bad point length")
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != (s[31] >> 7):
        x = P - x
    pt = (x, y, 1, (x * y) % P)
    if not _isoncurve(pt):
        raise ValueError("point not on curve")
    return pt


def _verify_sig(sig, m, pk):
    if len(sig) != 64:
        return False
    try:
        R = _decodepoint(sig[:32])
        A = _decodepoint(pk)
    except ValueError:
        return False
    S = int.from_bytes(sig[32:], "little")
    if S >= Q:
        return False
    h = _hint(sig[:32] + pk + m)
    return _scalarmult(_B, S) == _edwards(R, _scalarmult(A, h))


# --------------------------- canonicalisation --------------------------------
def b64d(s):
    return base64.b64decode(s)


def b64e(b):
    return base64.b64encode(b).decode("ascii")


def canon(obj):
    """json-sort-keys-compact-utf8 — the norm defined in docs/INVENTION.md 5.3."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


# ------------------------------- Merkle --------------------------------------
# Leaf hashes bind the leaf's index:  LeafHash(i, data) = SHA-256(0x00 || be64(i) || data)
# This removes the [a,b,c] vs [a,b,c,c] ambiguity that a bare leaf hash admits
# (the CVE-2012-2459 class of defect). The leaf list is padded to a power of two
# by repeating the last leaf, so index binding keeps the duplicate distinct.
def _leaf_hash(index, data):
    return hashlib.sha256(b"\x00" + index.to_bytes(8, "big") + data).digest()


def _node_hash(l, r):
    return hashlib.sha256(b"\x01" + l + r).digest()


def merkle_root(leaves):
    if not leaves:
        return hashlib.sha256(b"").digest()
    n = 1
    while n < len(leaves):
        n *= 2
    level = [_leaf_hash(i, leaves[i] if i < len(leaves) else leaves[-1])
             for i in range(n)]
    while len(level) > 1:
        level = [_node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


# ------------------------------ statistics -----------------------------------
# No float ever enters the protocol: latency is carried as integer nanoseconds,
# percentiles and error rates as parts-per-million, rates as milli-units. A
# float has no single textual rendering (0.1 / 0.10 / 1e-1 all parse alike), so
# a producer and a verifier could disagree on the bytes; integers cannot.
def percentile_ns(sorted_ns, p_ppm):
    """Nearest-rank percentile. p_ppm is the percentile in parts-per-million."""
    n = len(sorted_ns)
    if n == 0:
        return 0
    idx = (p_ppm * n + 999_999) // 1_000_000 - 1
    return int(sorted_ns[min(max(idx, 0), n - 1)])


def bootstrap_ci_ns(values_ns, p_ppm, level_ppm, resamples, seed):
    rnd = random.Random(seed)
    n = len(values_ns)
    if n == 0:
        return [0, 0]
    draws = []
    for _ in range(resamples):
        draws.append(percentile_ns(sorted(rnd.choices(values_ns, k=n)), p_ppm))
    draws.sort()
    alpha = 1_000_000 - level_ppm
    lo = (alpha * resamples) // 2_000_000
    hi = resamples - 1 - lo
    return [int(draws[lo]), int(draws[hi])]


# ------------------------------ time helpers ---------------------------------
def iso(ns):
    dt = datetime.datetime.fromtimestamp(ns / 1e9, datetime.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s):
    dt = datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
    return int(dt.replace(tzinfo=datetime.timezone.utc).timestamp() * 1e9)


# --------------------------- recompute claims --------------------------------
# Integer-only claim block. Every value is exactly reproducible by any verifier
# in any language; there is no rounding rule to disagree about.
def recompute(samples, duration_s, method):
    total = len(samples)
    errors = sum(1 for s in samples if not s["ok"])
    honest = sorted(int(s["lat_ns"]) + int(s["co_extra_ns"]) for s in samples)
    ci = bootstrap_ci_ns(honest, 990_000, method["confidence_interval"]["level_ppm"],
                         method["confidence_interval"]["resamples"],
                         method["confidence_interval"]["seed"])
    dur = max(1, int(duration_s))
    return {
        "total_requests": total,
        "errors": errors,
        "error_rate_ppm": (errors * 1_000_000) // total if total else 0,
        "rps_milli": (total * 1000 + dur // 2) // dur,
        "p50_ns": percentile_ns(honest, 500_000),
        "p95_ns": percentile_ns(honest, 950_000),
        "p99_ns": percentile_ns(honest, 990_000),
        "p99_ns_ci95": ci,
        "co_corrected_samples": sum(1 for s in samples if int(s["co_extra_ns"]) > 0),
    }


# -------------------------------- commands -----------------------------------
def cmd_keygen(out):
    sk = os.urandom(32)
    pk = _publickey(sk)
    key_id = hashlib.sha256(pk).hexdigest()
    doc = {"alg": "Ed25519", "protocol": "vpmp/v1",
           "private_key_b64": b64e(sk), "public_key_b64": b64e(pk), "key_id": key_id}
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(doc, f, sort_keys=True, indent=2)
        f.write("\n")
    print(key_id)
    return 0


def emit_samples(count, seed, base_ns, duration_ns):
    """Place `count` samples evenly inside the declared run window.

    Samples are laid out on a fixed cadence (constant-rate arrival schedule, the
    realistic model for a paced constant-rps run) so the stream always fits
    inside [started_at, ended_at] regardless of sample count. Sequential
    "t = t + latency + gap" pacing would drift past the window as soon as
    count x mean-latency exceeded the duration.
    """
    rnd = random.Random(seed)
    lats = []
    for _ in range(count):
        lat_ms = min(rnd.lognormvariate(math.log(3.0), 0.7), 500.0)
        lats.append(int(lat_ms * 1e6))

    margin = 200_000_000  # 200 ms of head-room on each side
    span = duration_ns - 2 * margin - (max(lats) if lats else 0)
    step = max(1, span // max(1, count))

    out = []
    for i, lat_ns in enumerate(lats):
        t_start = base_ns + margin + i * step
        co_extra = 0
        if rnd.random() < 0.02:
            co_extra = int(rnd.expovariate(1.0 / (20.0 * 1e6)))  # saturation skew
        status = 200
        if rnd.random() < 0.002:
            status = 500
        out.append({
            "seq": i, "step": "quick-test",
            "t_start_ns": t_start, "t_end_ns": t_start + lat_ns, "lat_ns": lat_ns,
            "co_extra_ns": co_extra, "status": status, "ok": status < 400,
            "epoch_nonce": None,
        })
    last_end = out[-1]["t_end_ns"] if out else base_ns
    ended_ns = max(base_ns + duration_ns, last_end + margin)
    return out, ended_ns


def cmd_emit(out, samples_path, count, duration_s, target, seed):
    key = json.load(open(os.environ["VERIBENCH_KEY"]))
    sk = b64d(key["private_key_b64"])
    pk = b64d(key["public_key_b64"])
    duration_ns = int(duration_s) * 1_000_000_000
    base_ns = int(time.time()) * 1_000_000_000  # aligned to a whole second

    samples, ended_ns = emit_samples(count, seed, base_ns, duration_ns)
    duration_decl = max(1, int(round((ended_ns - base_ns) / 1e9)))
    rps = max(1, int(round(count / duration_decl)))
    with open(samples_path, "w") as f:
        for s in samples:
            f.write(json.dumps(s, sort_keys=True, separators=(",", ":")) + "\n")

    method = {
        "coordinated_omission": True,
        "percentile_method": "nearest-rank",
        "latency_unit": "nanoseconds",
        "rate_unit": "milli-requests-per-second",
        "error_rate_unit": "parts-per-million",
        "percentile_unit": "parts-per-million",
        "float_encoding": "forbidden",
        "confidence_interval": {"method": "bootstrap", "level_ppm": 950_000,
                                "resamples": 1000, "seed": 0x76706D70,
                                "seed_declared": True},
    }
    claims = recompute(samples, duration_decl, method)
    root = merkle_root([canon(s) for s in samples]).hex()

    manifest = {
        "format": "vpmp/v1",
        "bundle_id": "vb-" + hashlib.sha256(
            b64d(key["public_key_b64"]) + str(base_ns).encode()).hexdigest()[:12],
        "created_at": iso(base_ns),
        "tool": {"name": "VeriBench", "binary": "stress-strike",
                 "version": "0.14.5", "protocol": "vpmp/v1"},
        "signer": {"alg": "Ed25519", "key_id": key["key_id"],
                   "public_key_b64": key["public_key_b64"]},
        "target": {"url_origin": target, "tls_fingerprint": None},
        "scenario_hash": {
            "alg": "sha256",
            "value": hashlib.sha256(canon({
                "url": target, "duration_seconds": duration_decl,
                "profile": "constant-rps", "target_rps": rps,
            })).hexdigest(),
            "canonicalization": "json-sort-keys-compact-utf8"},
        "run": {"started_at": iso(base_ns),
                "ended_at": iso(ended_ns),
                "duration_seconds": duration_decl, "profile": "constant-rps",
                "target_rps": rps},
        "method": method,
        "claims": claims,
        "samples": {"path": os.path.basename(samples_path), "count": len(samples),
                    "encoding": "jsonl",
                    "leaf_canonicalization": "json-sort-keys-compact-utf8",
                    "merkle": {"alg": "sha256",
                               "leaf": "sha256(0x00 || be64(index) || canonical_record)",
                               "node": "sha256(0x01 || left || right)",
                               "padding": "repeat-last-leaf-to-power-of-two",
                               "empty_root": 'sha256("")', "root": root}},
        "signature": {"alg": "Ed25519", "value_b64": "",
                      "signed_payload": "manifest-minus-signature-canonicalised"},
        "extensions": {"challenge_response": None, "audit_anchor": None},
    }
    payload = dict(manifest)
    payload.pop("signature")
    sig = _sign(canon(payload), sk)
    manifest["signature"]["value_b64"] = b64e(sig)

    with open(out, "w") as f:
        f.write(json.dumps(manifest, sort_keys=True, separators=(",", ":")))
        f.write("\n")
    return 0


# -------------------------------- verifier -----------------------------------
class Checks:
    def __init__(self):
        self.fails = []
        self.color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    def _c(self, s, code):
        return "\033[%sm%s\033[0m" % (code, s) if self.color else s

    def check(self, name, cond, detail=""):
        if cond:
            print("  %s %s" % (self._c("[PASS]", "1;32"), name))
        else:
            extra = (" — " + detail) if detail else ""
            print("  %s %s%s" % (self._c("[FAIL]", "1;31"), name, extra))
            self.fails.append(name)
        return cond


def cmd_verify(bundle_path, samples_path):
    c = Checks()
    print("veribench verify (vpmp/v1)")
    try:
        m = json.load(open(bundle_path))
    except Exception as exc:
        print("  %s manifest is not readable JSON: %s" % (c._c("[FAIL]", "1;31"), exc))
        print("VERDICT: %s" % c._c("FAIL", "1;31"))
        return 1

    if not c.check("format identifier is vpmp/v1",
                   m.get("format") == "vpmp/v1", "got %r" % m.get("format")):
        print("VERDICT: %s" % c._c("FAIL", "1;31"))
        return 1

    pk = b64d(m["signer"]["public_key_b64"])
    c.check("key_id binds to the embedded public key",
            hashlib.sha256(pk).hexdigest() == m["signer"]["key_id"])

    payload = dict(m)
    payload.pop("signature", None)
    c.check("Ed25519 signature over the manifest",
            _verify_sig(b64d(m["signature"]["value_b64"]), canon(payload), pk),
            "manifest bytes do not match the signed payload")

    if not os.path.exists(samples_path):
        c.check("samples file present", False, samples_path)
    lines = []
    if os.path.exists(samples_path):
        with open(samples_path) as f:
            for ln in f:
                ln = ln.strip()
                if ln:
                    lines.append(json.loads(ln))

    c.check("sample count matches the manifest",
            len(lines) == m["samples"]["count"],
            "%d lines vs manifest %s" % (len(lines), m["samples"]["count"]))

    root = merkle_root([canon(s) for s in lines]).hex()
    c.check("Merkle root matches the recomputed tree",
            root == m["samples"]["merkle"]["root"],
            "recomputed %s… vs manifest %s…" % (root[:16], m["samples"]["merkle"]["root"][:16]))

    want = m["claims"]
    got = recompute(lines, m["run"]["duration_seconds"], m["method"])
    mismatches = []
    for k, v in sorted(got.items()):
        if want.get(k) != v:
            mismatches.append("%s: manifest %r vs recomputed %r" % (k, want.get(k), v))
    c.check("claims match the recomputed statistics",
            not mismatches, "; ".join(mismatches))

    win_s = parse_iso(m["run"]["started_at"]) - 2_000_000_000
    win_e = parse_iso(m["run"]["ended_at"]) + 2_000_000_000
    problems = []
    prev = -1
    for s in lines:
        if s["seq"] != prev + 1:
            problems.append("seq %s out of order" % s["seq"])
        prev = s["seq"]
        if s["t_end_ns"] < s["t_start_ns"]:
            problems.append("seq %s time reversal" % s["seq"])
        if s["lat_ns"] != s["t_end_ns"] - s["t_start_ns"]:
            problems.append("seq %s lat_ns != t_end_ns - t_start_ns" % s["seq"])
        if s["t_start_ns"] < win_s or s["t_end_ns"] > win_e:
            problems.append("seq %s outside the declared run window" % s["seq"])
        if bool(s["ok"]) != (int(s["status"]) < 400):
            problems.append("seq %s ok/status disagree" % s["seq"])
        if problems:
            break
    c.check("per-sample internal consistency", not problems,
            problems[0] if problems else "")

    if c.fails:
        print("VERDICT: %s — %d check(s) failed" %
              (c._c("FAIL", "1;31"), len(c.fails)))
        return 1
    print("VERDICT: %s" % c._c("PASS", "1;32"))
    return 0


def main(argv):
    if len(argv) < 2:
        print("usage: veribench_ref.py <keygen|emit|verify> ...", file=sys.stderr)
        return 2
    cmd = argv[1]
    args = {}
    i = 2
    while i < len(argv):
        if argv[i].startswith("--") and i + 1 < len(argv):
            args[argv[i][2:]] = argv[i + 1]
            i += 2
        else:
            i += 1
    if cmd == "keygen":
        return cmd_keygen(args["out"])
    if cmd == "emit":
        return cmd_emit(args["out"], args["samples"], int(args.get("count", 1500)),
                        args.get("duration", 10), args.get("target", "http://127.0.0.1:8090/"),
                        int(args.get("seed", 424242)))
    if cmd == "verify":
        return cmd_verify(args["bundle"], args["samples"])
    print("unknown subcommand %r" % cmd, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
PYEOF
}

# ────────────────────────────────── main ─────────────────────────────────────
banner

BIN=""
if BIN="$(find_bin)"; then
  note "binary: ${BIN}"
else
  note "binary: not found (set STRESS_STRIKE_BIN to point at one)"
fi

MODE="reference"
if [ -n "${BIN}" ] && probe_sub keygen && probe_sub verify && probe_emit_bundle; then
  MODE="live"
fi

step "1/5  Mode"
if [ "${MODE}" = "live" ]; then
  say "LIVE — this build exposes keygen / verify / --emit-bundle."
  say "       Running the real end-to-end contract against ${URL}"
else
  warn "REFERENCE mode — no stress-strike binary was found or could be built."
  say  "       Missing surface is at least one of:"
  probe_sub keygen            || say "         · stress-strike keygen --out <key>        [unavailable]"
  probe_sub verify            || say "         · stress-strike verify --bundle …        [unavailable]"
  probe_emit_bundle           || say "         · stress-strike run --emit-bundle <b>    [unavailable]"
  say  "       The real thing ships in this repo (cmd/stress-strike): set"
  say  "       STRESS_STRIKE_BIN to a built binary, or install Go so this script"
  say  "       can build one itself."
  say  "       So: NO load is generated here. Instead a spec-conformant vpmp/v1"
  say  "       bundle is emitted by the embedded reference implementation, and the"
  say  "       VERIFICATION half of this demo runs for real."
fi

# A live run that cannot reach its target still seals a bundle — the CLI always
# writes what it measured — and that bundle verifies perfectly, because its
# records honestly say every request failed. The demo would look like a success
# while proving nothing, so check reachability first and refuse to continue.
# An error status (4xx/5xx) is only a warning: some targets answer 404 on one
# path and 200 on another, and a sealed pile of errors is still honest evidence.
if [ "${MODE}" = "live" ] && command -v curl >/dev/null 2>&1; then
  code="$(curl -s -o /dev/null -m 5 -w '%{http_code}' "${URL}" || true)"
  if [ "${code}" = "000" ] || [ -z "${code}" ]; then
    bad "no target reachable at ${URL}"
    say "       Start one first, e.g.:"
    say "         go run ./examples/demo_server.go 127.0.0.1:8090 &"
    say "         DEMO_URL=http://127.0.0.1:8090/health $0"
    exit 3
  fi
  case "${code}" in
    2*) note "target ${URL} answered HTTP ${code}" ;;
    *)  warn "target ${URL} answered HTTP ${code} — is DEMO_URL the right endpoint?" ;;
  esac
fi

command -v perl >/dev/null 2>&1 || { bad "perl is required to flip the demo byte"; exit 3; }

if [ "${MODE}" = "reference" ]; then
  command -v python3 >/dev/null 2>&1 || { bad "python3 is required in REFERENCE mode"; exit 3; }
  write_reference
fi

step "2/5  keygen — create the digital seal (Ed25519)"
if [ "${MODE}" = "live" ]; then
  # `keygen` writes a PEM keypair to --out and prints the public key; the
  # fingerprint is that printed key, not a field inside the file.
  KEYGEN_OUT="$("$BIN" keygen --out "${KEY}")"
  printf '%s\n' "${KEYGEN_OUT}" | sed 's/^/       /'
  KEY_ID="$(printf '%s' "${KEYGEN_OUT}" | sed -n 's/^public key: *\(.*\)$/\1/p')"
  [ -n "${KEY_ID}" ] || { bad "could not read the public key from keygen output"; exit 3; }
else
  python3 "${REF}" keygen --out "${KEY}"
  KEY_ID="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["key_id"])' "${KEY}")"
fi
say "${DIM}private key: ${KEY} (mode 0600) · never leaves this host${R}"
say "key_id (public fingerprint): ${KEY_ID}"

step "3/5  run — produce the measurement bundle"
if [ "${MODE}" = "live" ]; then
  # The real contract: a paced steady run against ${URL}, sealed with the key
  # minted above. --bundle-key is what binds this bundle to KEY_ID; without it
  # the CLI mints an ephemeral signing key and the fingerprint printed above
  # would not be the one in the evidence.
  #
  # A run whose target is slow or erroring still seals its bundle *before*
  # exiting non-zero, and that non-zero code reports the test outcome, not a
  # demo failure. The evidence is the product here, so record the code, say so,
  # and carry on to verification.
  run_status=0
  "$BIN" run \
    --url "${URL}" \
    --rps "${RPS}" \
    --users "${USERS}" \
    --duration "${DURATION_SECS}" \
    --coordinated-omission \
    ${PRIVATE_OK} \
    --emit-bundle "${BUNDLE}" \
    --bundle-key "${KEY}" \
    --report-dir "${WORK}/report" || run_status=$?
  if [ "${run_status}" -ne 0 ]; then
    warn "run exited ${run_status} — SLA missed or requests failed"
    say  "       The bundle below still seals exactly what was measured. That is"
    say  "       the point of the exercise: a bad result is recorded, not hidden."
  fi
else
  VERIBENCH_KEY="${KEY}" python3 "${REF}" emit \
    --out "${BUNDLE}" --samples "${SAMPLES}" --count "${COUNT}" \
    --duration 10 --target "${URL}"
  note "(reference bundle: ${COUNT} samples, synthetic — no traffic was sent)"
fi
[ -f "${BUNDLE}" ]  || { bad "bundle was not created: ${BUNDLE}"; exit 3; }
[ -f "${SAMPLES}" ] || { bad "samples were not created: ${SAMPLES}"; exit 3; }

BUNDLE_ORIG_HASH="$(sha256 "${BUNDLE}")"
SAMPLES_HASH="$(sha256 "${SAMPLES}")"
say "bundle  : ${BUNDLE}  ($(wc -c <"${BUNDLE}" | tr -d ' ') bytes, sha256 ${BUNDLE_ORIG_HASH:0:16}…)"
say "samples : ${SAMPLES}  ($(wc -l <"${SAMPLES}" | tr -d ' ') lines, sha256 ${SAMPLES_HASH:0:16}…)"

VERIFY_RC=0
verify_now() {
  set +e
  if [ "${MODE}" = "live" ]; then
    "$BIN" verify --bundle "${BUNDLE}" --samples "${SAMPLES}"
  else
    python3 "${REF}" verify --bundle "${BUNDLE}" --samples "${SAMPLES}"
  fi
  VERIFY_RC=$?
  set -e
  return "${VERIFY_RC}"
}

step "4/5  verify — the honest bundle must PASS"
if verify_now; then
  ok "verifier accepted the bundle (exit ${VERIFY_RC})"
else
  bad "verifier rejected an intact bundle (exit ${VERIFY_RC}) — aborting"
  exit 1
fi

step "5/5  tamper with ONE byte, then verify again"
cp "${BUNDLE}" "${BUNDLE}.bak"
# Flip exactly one hexadecimal nibble inside the Merkle root. This changes the
# committed root while keeping the manifest valid JSON, so the failure the
# verifier reports is cryptographic rather than syntactic. The key is spelled
# `merkle_root` in the CLI's bundle and `root` in the reference emitter, so
# accept either.
perl -0777 -i -pe 's{("(?:merkle_root|root)"\s*:\s*")([0-9a-f])}{$1 . ($2 ne "0" ? "0" : "1")}e' "${BUNDLE}" \
  || { bad "could not perform the byte flip"; exit 3; }

# cmp exits 1 when the files differ, so swallow it inside the pipeline (the
# script runs with `set -o pipefail` and must not die on a successful detection).
DIFF_BYTES="$( { cmp -l "${BUNDLE}.bak" "${BUNDLE}" || true; } | wc -l | tr -d ' ')"
BUNDLE_BAD_HASH="$(sha256 "${BUNDLE}")"
say "altered : ${BUNDLE}  ($(wc -c <"${BUNDLE}" | tr -d ' ') bytes, sha256 ${BUNDLE_BAD_HASH:0:16}…)"
say "bytes differing from the original: ${DIFF_BYTES}"
if [ "${DIFF_BYTES}" != "1" ]; then
  bad "expected exactly 1 differing byte, saw ${DIFF_BYTES} — aborting"
  exit 1
fi
say "${DIM}one nibble of the Merkle root changed; the samples file is untouched${R}"

if verify_now; then
  bad "TAMPERING WAS NOT DETECTED (verifier exit ${VERIFY_RC}) — the guarantee is broken"
  cp "${BUNDLE}.bak" "${BUNDLE}"
  exit 1
fi
if [ "${VERIFY_RC}" != "1" ]; then
  bad "verifier failed with exit ${VERIFY_RC}, expected exactly 1"
  cp "${BUNDLE}.bak" "${BUNDLE}"
  exit 1
fi
ok "tampering detected — verifier refused the bundle (exit ${VERIFY_RC})"

say ""
say "${B}restore the byte and re-verify${R}"
cp "${BUNDLE}.bak" "${BUNDLE}"
rm -f "${BUNDLE}.bak"
RESTORED_HASH="$(sha256 "${BUNDLE}")"
if [ "${RESTORED_HASH}" != "${BUNDLE_ORIG_HASH}" ]; then
  bad "restored bundle hash differs from the original — cleanup failed"
  exit 1
fi
if verify_now; then
  ok "restored bundle verifies again (exit ${VERIFY_RC})"
else
  bad "restored bundle failed verification (exit ${VERIFY_RC})"
  exit 1
fi

say ""
say "${GRN}${B}RESULT${R}"
say "  intact bundle   → PASS (exit 0)   sha256 ${BUNDLE_ORIG_HASH:0:16}…"
say "  one byte changed→ FAIL (exit 1)   sha256 ${BUNDLE_BAD_HASH:0:16}…"
say "  byte restored   → PASS (exit 0)   sha256 ${RESTORED_HASH:0:16}…"
say "  mode            → ${MODE}"
say ""
say "${DIM}A load-test result you can check is a result you can use.${R}"
