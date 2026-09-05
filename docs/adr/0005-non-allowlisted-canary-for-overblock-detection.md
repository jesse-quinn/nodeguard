# 0005 - Detect over-blocking with a non-allowlisted canary probe

## Status

accepted, 2026-09-04

## Context

The failure class this system must catch about itself is over-blocking: an
over-broad block entry, an inverted expiry comparison, or a key-encoding
defect that drops far more than intended. A watchdog that probes only
allowlisted lifelines is structurally blind to exactly that class, because
allowlisted sources bypass the blocklist lookup in the datapath
(src/nodeguard_kern.c:160-163, 204-207): with the whole internet being
dropped, every lifeline probe still succeeds and the watchdog reports green.
An earlier revision of the design had precisely this blind spot; adversarial
review found it before deployment.

The only probe that traverses the same path as real traffic is one whose
return packets are subject to the blocklist lookup, which means a target that
is deliberately not, and never will be, allowlisted.

## Decision

The watchdog (bin/nodeguard-watchdog, one cycle per minute) probes two
different things:

1. Lifeline probes over allowlisted paths detect total datapath death or an
   upstream outage (bin/nodeguard-watchdog:26-54, 63-70).
2. A canary probe makes a TCP connection to CANARY_IP:443, an
   operator-chosen, deliberately never-allowlisted public address
   (bin/nodeguard-watchdog:55-61). Its SYN-ACK traverses the blocklist
   lookup, so over-blocking breaks the canary while lifelines stay green.

Actions, all fail-open:

- 3 consecutive canary failures while at least one lifeline passes: suspected
  over-block; soft-disable enforcement via the kill switch (hitless), logging
  the stats-map drop counters as evidence (bin/nodeguard-watchdog:106-109).
- 5 consecutive cycles with all lifelines failing: soft-disable, since the
  cause may be an upstream outage the XDP layer did not create
  (bin/nodeguard-watchdog:110-114).
- 10 further cycles with the switch already latched and lifelines still dead:
  detach the XDP program by id (bin/nodeguard-watchdog:117-121).

Re-arm is bounded: only a watchdog-set latch (never a manual one), only after
15 consecutive fully clean cycles, and only once per boot, tracked in config
slot 2 (bin/nodeguard-watchdog:122-128). Any manual soft-off, and any second
latch in the same boot, is human-only recovery. To keep the canary honest, the
maps service refuses to load an allow file whose entries cover the configured
canary address (bin/ngmap.py:324-330).

## Consequences

- The canary target must remain outside operator control of the allowlist
  forever. Allowlisting it, even with good intentions during an incident,
  silently re-creates the blind spot; the reconcile-time refusal is the
  enforcement of that rule and must not be weakened.
- A routine outage of the canary target latches enforcement off even though
  nothing is wrong locally. This is accepted: the latch is hitless, loudly
  alarmed (a CRITICAL log repeats hourly while latched,
  bin/nodeguard-watchdog:129-135), and self-healing once per boot after 15
  clean cycles. The trade is deliberate; a false trip fails open, a missed
  over-block fails the operator's uplink.
- The once-per-boot re-arm bound means a flapping upstream converts into a
  latched-off system awaiting a human, rather than an enforcement layer that
  oscillates on and off unattended.
- The canary adds one outbound TCP connection per minute to a third-party
  address; the target should be chosen as something for which that is
  unremarkable.
