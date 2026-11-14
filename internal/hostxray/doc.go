// Package hostxray implements Sift's opt-in host observability agent: it
// samples cheap, aggregate host counters and correlates them with Sift's
// external load signals so an operator can see whether a latency or error
// spike happened while the host itself was under pressure.
//
// # What this package is
//
// A defensive, diagnostic helper. When a Sift run shows elevated p99 latency,
// connection errors, or throughput collapse, external measurements alone
// cannot say whether the host was CPU-saturated, out of memory, dropping
// packets, or stalling in the Go runtime. This package gathers the minimum
// aggregate evidence needed to answer that question and labels every derived
// finding as correlated evidence, never as a causal claim.
//
// # What this package is not
//
// It is not an offensive tool, an EDR, or a surveillance agent:
//
//   - No eBPF programs are loaded in this release. There is no bpf() syscall,
//     no kernel module, no cgo, and no privilege escalation. The Linux path
//     reads world-readable /proc files as the invoking user; if they are not
//     readable the agent degrades to Go runtime metrics instead of failing.
//   - No process names, PIDs, command lines, environment variables, user
//     names, file contents, packet payloads, HTTP bodies, remote addresses, or
//     secrets are read or written. Only aggregate counters are sampled.
//   - BTF support is detected by stat-ing /sys/kernel/btf/vmlinux. That is a
//     capability fact, not a program load: a future backend would still need
//     CAP_BPF/CAP_PERFMON and explicit operator authorization.
//
// # Opt-in
//
// New refuses to construct an Agent unless Options.OptIn is true. The CLI
// exposes this as the --allow flag, so a bare "Sift xray collect" fails closed
// with an explanation. Capability detection (DetectCapabilities) performs only
// read-only stat calls and is safe without opt-in because it collects no
// measurements.
//
// # Platforms
//
// On Linux the collector reads /proc (loadavg, meminfo, net/dev, pressure,
// stat). On every other platform it falls back to Go runtime metrics
// (goroutines, heap, GC pauses) so the command remains useful for diagnosing
// the Sift process itself, and explicitly records that kernel evidence is
// unavailable.
package hostxray
