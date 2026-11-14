// Package bounty implements a staged, verifiable bug-bounty triage workflow.
//
// The workflow has three independent parts:
//
//   - A package (manifest.go) binds the artifacts of one report together —
//     evidence bundle, sample sidecar, written report, program scope and typed
//     claim — and records a SHA-256 for each of them plus a digest over the
//     manifest itself.
//   - A verifier (verify.go) re-hashes every artifact, re-checks the manifest
//     digest, optionally replays the Sift attestation verification and checks
//     the claimed target against the program scope file.
//   - A triage log (triage.go) is an append-only JSONL state machine that
//     records who moved a report between stages and why.
//
// # Trust boundaries
//
// Package verification proves that the bytes a reporter packaged are the bytes
// a verifier examined, and (when a bundle is supplied) that the measurements
// were sealed by the holder of the coordinator key. It does NOT prove that the
// finding is real, novel, in scope in a legal sense, or worth a reward.
// Evidence integrity is not finding validity: a perfectly sealed bundle can
// describe a non-vulnerability, and a human triager must still read the report.
//
// Payment is deliberately out of scope. The rewarded state is a triage outcome
// — an audit record that a human decided a report earned a reward — not a
// transfer of funds. No wallet, contract or payout oracle lives here, and none
// should be inferred from the state machine.
//
// The triage log is tamper-evident only in the ordinary append-only sense: it
// carries a package digest so an event can be tied to a package, and LoadEvents
// rejects a broken chain, but a party with write access to the file can rewrite
// history. Anchoring the log (for example by signing its head) is a deployment
// concern, not something this package claims to solve.
package bounty
