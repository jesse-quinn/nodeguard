# 0002 - Require bidirectional TCP flow evidence before any automated block

## Status

accepted, 2026-09-04

## Context

An IDS-fed blocklist keyed on alert source addresses is trivially poisonable.
A blind attacker can emit single UDP or ICMP packets with any spoofed source
address: a DNS resolver the host depends on, a coordination-server relay for
the management tunnel, an API endpoint the operator's tooling needs. If such a
packet can trigger a severity-1 signature, the responder would insert the
spoofed address into the block map and the system would DoS itself; the
attacker never needs to receive a reply. This is the single worst failure mode
of the whole design, because the enforcement point sits on the operator's own
uplink.

TCP is different in kind: sequence numbers make completing or continuing a
handshake blind infeasible. A flow in which our host answered (at least one
packet to the client) and the peer then continued (at least a second packet to
the server) proves the peer can see our traffic, so its source address is not
blind-spoofed.

## Decision

The responder (bin/nodeguard-responder) blocks only when every gate passes,
in order:

1. event_type is "alert"; never flow, anomaly, dns, or stats events
   (bin/nodeguard-responder:206).
2. alert severity is 1, or the SID is explicitly opted in via sids.conf
   (bin/nodeguard-responder:219); a per-SID ignore list is honored first
   (bin/nodeguard-responder:217).
3. Anti-spoofing gate: the protocol must be TCP
   (bin/nodeguard-responder:225), and the alert's flow counters must show
   bidirectional exchange, flow.pkts_toclient >= 1 and
   flow.pkts_toserver >= 2 (bin/nodeguard-responder:228-231). Alerts failing
   either check are logged as WOULD BLOCK and never acted on.
4. Inbound only: dest_ip must fall in HOME_NETS
   (bin/nodeguard-responder:239-240), and src_ip must be globally routable
   (bin/nodeguard-responder:241-242).
5. The source must not match the live allow maps or the never-block ranges
   (bin/nodeguard-responder:244, via ngmap.py allow-check).

UDP and ICMP signatures are log-only. A specific SID can be promoted to
UDP eligibility only by hand, via a "udp-ok" line in sids.conf
(bin/nodeguard-responder:84-85, 225) carrying a written justification of why
blind spoofing does not apply to that signature. A re-alert refreshes a block's
TTL only by passing this same full pipeline, so a spoofer cannot renew a block
either.

## Consequences

- Real attacks carried in single spoofable packets (UDP amplification probes,
  ICMP-based scans, one-shot exploit datagrams) are never blocked
  automatically. This is accepted: they are logged, visible in the WOULD BLOCK
  stream, and blockable by hand.
- A bounded residual risk remains: a severity-1 TCP rule that fires on a bare
  SYN after our SYN-ACK meets the flow-counter thresholds while the connection
  is still spoof-resistant but cheap. This is handled by severity curation,
  the responder's rate caps, and the allowlist backstop, not by the gate
  itself.
- The gate depends on Suricata's EVE alert records carrying
  flow.pkts_toserver and flow.pkts_toclient; the Suricata configuration must
  keep flow counters enabled in alert metadata, and removing them silently
  turns the responder into a no-op (every alert fails the gate and is logged,
  not blocked; it fails toward openness).
- Per-SID UDP promotion is a standing invitation to erode the gate; every
  udp-ok line is a documented exception that must defend itself.
