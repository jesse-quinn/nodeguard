# 0001 - Run Suricata passive and enforce with a separate XDP blocklist

## Status

accepted, 2026-09-04

## Context

nodeguard deploys to two hosts: an internet gateway (a multi-VLAN home router
whose operator depends on it for connectivity) and a remote node reachable only
over its management tunnel. Both run Fedora 44 with the stock suricata 8.0.6
RPM. The goal is automated blocking of confirmed attackers without ever putting
detection in the forwarding path.

Every inline option fails the environment:

- NFQUEUE inline is fail-closed: if the userspace listener dies and no nft
  bypass rule exists, matched traffic stops entirely. It also adds per-packet
  queueing latency on a gateway that carries the operator's own working
  traffic, and its queue rules would have to be defended against firewalld
  reload semantics.
- AF_PACKET copy-mode IPS requires a dedicated two-port L2 pair with Suricata
  acting as the forwarder between them. That is inherently fail-closed and
  physically impossible on a multi-VLAN router.
- Suricata's own eBPF/XDP machinery is compiled into the Fedora 44 suricata
  8.0.6 RPM, but the package ships zero .bpf objects (verified from the RPM
  filelist; upstream ebpf/Makefile.am has no install rule), and even built by
  hand it is capture bypass (acceleration), not policy blocking.
- xdp-filter from xdp-tools is packaged and libxdp-dispatcher-native, but it
  supports neither CIDR entries nor per-entry TTLs, both of which the design
  requires. It is retained only as a manual break-glass tool.

## Decision

Suricata runs as a passive af-packet IDS, never inline, and never loads any
BPF. Enforcement is a separate custom XDP program of a few hundred lines of
BPF C (src/nodeguard_kern.c), loaded in native mode through the libxdp
dispatcher (bin/nodeguard-attach:17); the program declares dispatcher metadata
with XDP_RUN_CONFIG, priority 10, chain-call action XDP_PASS
(src/nodeguard_kern.c:223-226), so other dispatcher members (xdpdump,
break-glass xdp-filter rules) can coexist.

The two halves are coupled only by a responder daemon
(bin/nodeguard-responder) that tails eve.json and writes offender source
addresses with an expiry into pinned LPM trie block maps
(src/nodeguard_kern.c:81-97). Detection and enforcement are fully decoupled:
the XDP layer reads no Suricata state except through the responder, and a dead
Suricata has zero traffic impact by construction.

## Consequences

- Suricata is blind to a source for as long as it is blocked: XDP_DROP happens
  before AF_PACKET delivery, so no packet from a blocked address ever reaches
  the IDS. The block TTL is therefore also the re-detection interval, and "no
  more alerts" is never evidence that an attacker stopped.
- A custom BPF object must be built and maintained off-host (build/build.sh);
  a future kernel that rejects the program at the verifier fails the attach
  unit visibly and the host runs open until a rebuild. The program parses only
  packet bytes, no kernel structs, precisely to keep that surface small.
- All XDP loading on these hosts must go through libxdp tooling; a raw ip-link
  attach anywhere would permanently block the dispatcher and is forbidden.
- The blocklist enforces only what the responder writes; there is no inline
  signature-based drop, ever. Anything Suricata detects but the responder does
  not act on is log-only.

## Alternatives considered

- NFQUEUE inline: rejected as fail-closed for a dead listener and a latency
  risk on the gateway path. Documented as a future option only.
- AF_PACKET copy-mode IPS: rejected; needs a dedicated two-port L2 pair and
  makes Suricata the forwarder; impossible on a multi-VLAN router.
- Suricata xdp_filter/eBPF bypass: rejected; the RPM ships no objects and the
  mechanism is capture acceleration, not policy blocking.
- xdp-filter (xdp-tools): rejected for blocking; no CIDR, no TTL. Kept as a
  manual break-glass tool in the same dispatcher.
- Third-party XDP firewalls and fail2ban as responder: rejected; unpackaged or
  pre-release, unverified dispatcher compatibility, userspace-only allowlists,
  and no in-kernel TTL.
