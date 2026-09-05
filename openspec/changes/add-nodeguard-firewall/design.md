# Design: add-nodeguard-firewall

The full architecture lives in `docs/design.md` (arc42): governing
principles, the per-packet decision order, the map contract, unit and CLI
behaviour, the watchdog's latch semantics, coexistence with the host's
existing firewall and mesh networking, the phased install plan, the
rollback table, and the failure-mode table. Decisions and their rejected
alternatives are recorded in `docs/adr/`. This file only orients the
reader; it does not duplicate either.

## Shape of the solution

Three decoupled layers, each of which fails open independently:

1. Detection: stock Suricata as a passive af-packet IDS. It loads no BPF
   and is never in the forwarding path; its only output the rest of the
   system reads is EVE alert records.
2. Response: a stdlib-only Python daemon tails the alert stream and, for
   alerts passing every gate (severity, anti-spoofing bidirectional TCP
   evidence, inbound direction, allowlist recheck, rate caps), writes the
   offender address with an absolute expiry into pinned BPF maps.
3. Enforcement: a small XDP program on one physical interface per host
   checks parse validity, kill switch, WireGuard port, allowlist, then
   blocklist with expiry compared in the kernel. Only an unexpired
   blocklist hit drops.

## Key decisions (see docs/adr/ for the full records)

- Fail open everywhere: an absent program, empty maps, a dead responder,
  or a dead IDS all leave a pristine datapath.
- TTL expiry in the kernel, not in a sweeper, so no dead userspace can
  extend a block.
- The C source's map declarations are the single source of truth; the
  build generates a spec from the object and the maps service verifies
  pins against it, making silent drift structurally impossible.
- Blocking requires bidirectionally confirmed TCP flows, so blind spoofing
  cannot poison the blocklist.
- Monitoring precedes enforcement: the watchdog's non-allowlisted canary
  exists precisely because over-blocking is invisible to lifeline probes.
