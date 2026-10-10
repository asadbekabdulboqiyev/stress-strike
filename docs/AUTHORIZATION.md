# Authorization & Consent

stress-strike sends real traffic. A load generator and a denial-of-service tool
are the same program with different intent, and a scanner is an offensive tool
whatever you call it. This layer exists so that an enterprise can point at the
tool and say *what it refuses to do without written approval*.

Every run through `stress-strike run`, `stress-strike pentest`, or the
interactive wizard goes through it **before a single packet is sent**:

1. **Classify** the target — public / loopback / private / CGNAT / link-local /
   multicast / reserved / cloud-instance-metadata.
2. **Decide** with the policy — allow, or deny.
3. **Record** the decision in an append-only, hash-chained audit log.
4. **Notify** a webhook, if configured.

Traffic is only sent when the decision is *allow*.

---

## What is blocked by default

| Class | Default | Why |
| --- | --- | --- |
| `public` | allow | the normal case |
| `loopback` | allow | local smoke tests |
| `private` (RFC1918, ULA) | **deny** | `--allow-private`, or an allow-list entry |
| `cgnat` (100.64.0.0/10) | **deny** | shared carrier space |
| `link-local` | **deny** | device-level |
| `multicast` / `reserved` | **deny** | not a web target |
| `metadata` | **deny, always** | 169.254.169.254 and friends hand out IAM credentials |

The metadata class is the important one. Before this layer existed,

```sh
stress-strike run http://169.254.169.254/latest/meta-data/
```

was a one-line credential theft from inside any AWS/GCP/Azure workload. It is
now refused **even if a wildcard rule matches** — only an exact-host rule that
an approver recorded can unlock it.

```console
$ stress-strike run --url http://169.254.169.254/latest/meta-data/

BLOCKED by authorization policy
  target: http://169.254.169.254/latest/meta-data/
  reason: refusing to send traffic to cloud instance metadata (169.254.169.254) — this is the credential-theft path
$ echo $?
3
```

Exit code **3** means *policy denied this*, as distinct from `1` (the run
failed) and `2` (bad usage). CI can branch on that.

---

## The approval workflow

`pentest` — and, by policy, any target you want to name — requires an
**authorization entry** recorded by an approver, and the operator naming the
ticket. Two keys: someone else's approval, and your explicit intent.

**1. The approver records the authorization.**

```sh
stress-strike authorize add \
  --pattern shop.example.com \
  --approver ciso@corp.example \
  --ticket SEC-4421 \
  --until 2026-11-01T00:00:00Z \
  --reason "pre-release load test, window agreed with the platform team"
```

`--pattern` accepts an exact host, `*.example.com`, a CIDR (`10.0.0.0/8`), an
IP, or `*`. `--until` is an expiry; without it the entry never expires.

```
$ stress-strike authorize list
policy: /Users/you/.stress-strike/authz.json
mode: permissive (allow_private=false)
rules:
  shop.example.com                 until 2026-11-01T00:00:00Z  approver=ciso@corp   ticket=SEC-77
```

3 `authorize` also has `remove` and `verify`.

### 2. Run naming the ticket

```sh
stress-strike run --url https://shop.example.com --users 200 --duration 300 \
  --authorized SEC-77

stress-strike pentest --target https://shop.example.com --authorized SEC-77
```

For `pentest` both are required: the entry must exist **and** the operator must
name it. Naming a ticket with no matching entry fails. A wildcard never
satisfies a pentest.

---

## Policy file

`~/.stress-strike/authz.json` (override with `--policy` or `$STRESS_STRIKE_POLICY`):

```json
{
  "mode": "permissive",
  "allow_private": false,
  "rules": [
    {
      "pattern": "staging.internal",
      "until": "2026-12-01T00:00:00Z",
      "approver": "ciso@corp",
      "ticket": "SEC-310",
      "reason": "scheduled soak test"
    }
  ]
}
```

- `mode: "strict"` denies everything that is not on the allow-list — the usual
  enterprise posture for a regulated environment.
- `mode: "permissive"` (default) allows public and loopback, denies the rest.

| Flag | Env | Meaning |
| --- | --- | --- |
| `--policy` | `STRESS_STRIKE_POLICY` | policy file path |
| `--audit-log` | `STRESS_STRIKE_AUDIT_LOG` | audit log path |
| `--authorized` | — | ticket id recorded by an approver |
| `--allow-private` | — | allow RFC1918 targets without a rule |
| `--notify-webhook` | — | POST each decision to a URL |
| — | `STRESS_STRIKE_ALLOW` | comma-separated patterns, `pattern@RFC3339` |
| — | `STRESS_STRIKE_HOME` | config dir (default `~/.stress-strike`) |

---

## Audit trail

Every decision — allow *and* deny — is appended to
`~/.stress-strike/audit.jsonl` (`0600`, directory `0700`). Each record carries
the SHA-256 of itself chained to the previous record, so editing history is
detectable:

```
$ stress-strike audit show --limit 3
  #11  2026-10-10T04:15:23Z ALLOW run     metadata  targets=http://169.254.169.254/latest/meta-data/
  #12  2026-10-10T04:15:28Z DENY  run     metadata  targets=http://169.254.169.254/latest/meta-data/
  #13  2026-10-10T04:15:28Z ALLOW pentest metadata  targets=http://169.254.169.254

$ stress-strike audit verify
OK: 13 record(s), hash chain intact (/tmp/ssdemo/audit.jsonl)

# after editing a record on disk:
TAMPERED or corrupt: entry 2: hash mismatch — record has been modified (verified 1 record(s) before the break)
```

Each record holds the actor, action, targets, resolved IPs, class, verdict,
rule, reason, tool version, and argv:

```json
{
  "seq": 1,
  "actor": "asadbek",
  "action": "run",
  "targets": ["http://169.254.169.254/latest/meta-data/"],
  "ips": ["169.254.169.254"],
  "class": "metadata",
  "allowed": false,
  "reason": "refusing to send traffic to cloud instance metadata (169.254.169.254) — this is the credential-theft path",
  "version": "0.14.3",
  "prev_hash": "",
  "hash": "ec7c093327623715ba7e9d91bbca257c97fc3020db24a859525c6cc0d8a6b105"
}
```

Set `--notify-webhook` and each record is POSTed as JSON. Point it at a Slack
incoming-webhook URL to get a message per decision:

```
[stress-strike] BLOCKED: pentest ... (target=https://1.1.1.1, class=public, actor=ci, rule=)
```

If the receiver is a `hooks.slack.com` URL, the payload is sent as
`{"text": "..."}` automatically. A slow or failing webhook never blocks the
run — it is reported as a warning.

---

## Scope of this layer

Gated: `run` (including the interactive wizard, `beast`, and gate-strike
profiles), and `pentest`.

Not yet gated: `scan` and `replay`, which dispatch to separate binaries
(`stress-strike-scan`, `stress-strike-replay`). They are follow-ups, not
covered by this layer yet.
