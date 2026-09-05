# Survey: XDP visibility tools, DPI engines, anti-DDoS techniques

2026-09-05. Commissioned to decide what, if anything, the surrounding
ecosystem offers nodeguard. Conclusions adopted into the roadmap in
docs/design.md section 11. Grounded against docs/design.md sections 4 to 8:
nodeguard is a ~200-line XDP program whose only drop path is an unexpired
LPM blocklist hit, fed exclusively by a gated Suricata-to-responder
pipeline. Every other path is XDP_PASS. Attach is libxdp-dispatcher-only
(ADR 0004).

## 1. XDPeek (github.com/tks98/XDPeek)

A small eBPF/XDP packet tracer: kernel component in C (BCC-compiled),
userspace in Go and Python. Prints per-packet lines (timestamp, protocol,
src/dst, size, optional payload). A visibility tool, not a firewall.

Maturity: 0 stars, 4 commits total, last commit 2024-07-19 (over a year
stale), no visible license (UNVERIFIED), single-author learning project.
Depends on BCC, LLVM/Clang, and matching kernel headers, which conflicts
with the no-compiler-on-production-hosts constraint.

Dispatcher coexistence: hard incompatibility. It attaches its own XDP
program exclusively, without libxdp, which is exactly the raw-attach
pattern ADR 0004 forbids on a nodeguard host; running it would risk
evicting or conflicting with the dispatcher member nodeguard depends on.

Verdict: do not adopt. Unmaintained, dispatcher-incompatible by
construction, and strictly inferior to tooling nodeguard already has
(xdpdump, the pinned stats map, nodeguard-status).

## 2. DPI topic survey (github.com/topics/dpi)

The topic listing is noisy (false-positive matches on the string "DPI").
Filtering to genuine deep-packet-inspection projects:

| Project | Language | Stars (approx) | What it is |
|---|---|---|---|
| GoodbyeDPI | C | ~28.6k | Client-side DPI circumvention (Windows); irrelevant to a gateway that enforces |
| ByeDPIAndroid, spoofdpi, GreenTunnel | Kotlin/Go/TS | 5k to 5.5k | Same category: circumvention clients |
| nDPI (ntop) | C | ~4.6k | The one genuine DPI toolkit: flow classification, app-protocol ID, TLS/JA3-JA4 fingerprinting, flow-risk flags |
| rustnet | Rust | ~5k | Per-process host-local monitor, not gateway-facing |

nDPI versus Suricata, skeptically: Suricata 8.0.6 already does app-layer
protocol detection, TLS SNI extraction, JA3/JA4-equivalent fingerprinting,
and QUIC parsing into eve.json, which is the responder's sole input. nDPI's
flow-risk framework is a packaging convenience Suricata signatures can
express. Where nDPI genuinely differs (per-application traffic accounting
and QoS classification) is explicitly out of nodeguard's scope.

Verdict: no adoption. No concrete gap for nodeguard's narrow
inbound-blocklist mission.

## 3. Anti-DDoS topic survey (github.com/topics/anti-ddos)

Notable XDP/eBPF-relevant projects: xdp-firewall (gamemann, C, ~927 stars,
actively maintained), gatekeeper (DPDK kernel-bypass, architecturally
unlike our driver-native model), qnsm (DPDK+Suricata), plus Cloudflare's
L4Drop/rakelimit lineage. xdp-firewall is the closest architectural peer
(single custom XDP program, pinned maps, CLI rule updates) and is
deliberately stateless, a useful confirmation that nodeguard's stateless
posture is not an outlier.

Techniques rather than projects, judged against the fail-open contract and
the 1 Gbps gated-services threat model:

- Per-source rate limiting in BPF maps: real gap (nothing bounds a
  distributed low-and-slow flood; the responder's caps bound new blocks,
  not throughput), but it adds a second, independent drop condition and so
  conflicts with the "only drop is a blocklist hit" invariant. Feasible
  only as a separately gated, off-by-default enforcement mode with its own
  ADR and watchdog safety net. Medium-large effort. Defer until evidence.
- SYN cookies / synproxy at XDP: technically feasible on this kernel, but
  the hosts run only gated public services and kernel tcp_syncookies
  already protect any real listener. Large effort, near-zero value here.
- Connection-limit tracking: defends stateful services the datapath does
  not run. No applicable target.
- Packet sampling at XDP: redundant; the af-packet copy to Suricata already
  sees full traffic.
- Adaptive volumetric thresholds: pure control-plane logic. The watchdog
  already polls per-path stats counters every minute; diffing successive
  snapshots against a rolling baseline and alerting on anomalous spikes is
  userspace-only, adds no drop path, and closes the observability half of
  the volumetric blind spot. Small effort, immediate value.
- Protocol sanity counters (impossible TCP flag combinations, TTL
  outliers): natural extension of the existing parse logic as COUNT-ONLY
  telemetry into new stats slots; every new branch still resolves to
  XDP_PASS. Using such heuristics to drop would bypass ADR 0002's
  anti-spoofing discipline and is explicitly not recommended.

## Recommended, ranked by value-for-effort

1. Watchdog volumetric anomaly alerting from existing stats deltas
   (small; userspace only; no fail-open risk).
2. Protocol-sanity counters in the XDP program, count-only, never drop
   (small-medium; additive telemetry).
3. Per-source rate limiting as a separately gated enforcement mode
   (large; deferred until 1 produces evidence of an actual flood problem;
   do not build speculatively).
