# 0003 - Fail open everywhere and enforce block TTL in the kernel

## Status

accepted, 2026-09-04

## Context

The deployment targets are an internet gateway whose operator depends on it
for connectivity, and a remote node reachable only over its management tunnel.
On these hosts an enforcement layer that can fail closed is worse than none:
a wedged blocklist on the gateway severs the operator's own uplink, and on the
remote node it severs the only administrative path, turning a software defect
into a physical-presence recovery.

TTL handling is the specific trap. If expiry is enforced from userspace only
(a responder or sweeper deleting entries past their deadline), then a dead
daemon leaves every existing block enforced forever; the failure of a
convenience component escalates into permanent denial of service against
whatever was blocked at the time, including any false positive.

## Decision

Every layer fails open, and expiry is checked in the datapath itself:

1. Any parse or bounds-check failure returns XDP_PASS
   (src/nodeguard_kern.c:136-139, 185-188, 240-243, 251-254). Never drop what
   cannot be parsed.
2. Empty or missing map entries pass: a blocklist miss is XDP_PASS
   (src/nodeguard_kern.c:166-169, 210-213), and no program attached is a
   pristine datapath (bin/nodeguard-attach exits nonzero on failure and loads
   nothing; there is no skb fallback).
3. Block values carry an absolute CLOCK_MONOTONIC expiry, and the XDP program
   itself compares it against bpf_ktime_get_ns() on every hit: an expired
   entry passes even while it still sits in the map
   (src/nodeguard_kern.c:170-173 in handle_v4, 214-217 in handle_v6). An
   expiry of 0 means permanent and is reserved for manual entries; the
   responder never writes it.
4. A kill switch in config slot 1 passes everything hitlessly, before any
   lookup (src/nodeguard_kern.c:264-269). Restarting the maps service
   preserves an existing kill-switch value; only a brand-new config map is
   initialized to enforcing (bin/ngmap.py:307-311), so a restart can never
   silently re-arm what a human or the watchdog switched off.
5. The sweeper is garbage collection only: it deletes entries already past
   expiry (bin/ngmap.py:217-230) to reclaim map slots. Enforcement expiry has
   already happened in the kernel by the time it runs.

## Consequences

- A dead responder, sweeper, or Suricata degrades the system to a pass-through
  no-op within one TTL: no new blocks are added and existing ones expire in
  the kernel. The cost is that protection quietly decays when components die,
  so component liveness must be alarmed externally; the datapath itself will
  never signal the loss.
- Attackers regain access when their block expires, by design. Persistent
  attackers are re-detected and re-blocked one detection cycle after expiry;
  permanent exclusion is a manual act.
- Pinned maps live on bpffs and CLOCK_MONOTONIC restarts at boot, so all
  blocks are lost at reboot (accepted; the allowlist and config are rebuilt at
  boot, the blocklist starts empty).
- The sweeper cannot be used as a safety mechanism and must never grow
  enforcement semantics; any future TTL behavior change must land in
  src/nodeguard_kern.c, not in userspace.
- Fail-open is a security trade: an attacker who can crash the XDP program or
  prevent attach gets an unfiltered path. That is deliberate; the design
  treats loss of connectivity as strictly worse than loss of filtering on
  these hosts.
