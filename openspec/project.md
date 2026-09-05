# Project Context

## Purpose

nodeguard is an eBPF/XDP firewall with Suricata IPS wiring for small Linux
gateways running Fedora with stock packages. Suricata detects passively; a
small custom XDP program blocks confirmed attackers at the driver with
in-kernel TTL expiry. The repository holds the generic artifacts (BPF C
source, CLIs, daemons, systemd units, container build, example host config),
including the `nodeguard-feeds` threat-intel loader; the `zbx/` Zabbix
template and dashboard generator suite and the count-only `stats2` kernel
map are proposed in change `add-nodeguard-telemetry`. Real deployments keep
per-host details (interfaces, allowlists, HOME_NET, real addresses) in a
private overlay outside this repository.

## Tech Stack

- BPF C (`src/nodeguard_kern.c`), compiled off-host with clang in a stock
  Fedora container; no compiler ever lands on a managed host.
- bash for CLIs, units glue, and the watchdog: `set -uo pipefail`,
  shellcheck-clean, quoted expansions.
- Python 3 standard library only (`bin/ngmap.py`, `bin/nodeguard-responder`,
  `build/mkyaml.py`); no pip dependencies on the hosts.
- systemd units and timers; libxdp dispatcher tooling (`xdp-loader`,
  `bpftool`); stock Fedora Suricata RPM.

## Project Conventions

- Every component fails open. No program attached, empty maps, a dead
  responder, or a dead Suricata all mean traffic flows; the only drop is an
  unexpired blocklist hit. A parse failure in the XDP program is a pass.
- Automated enforcement must be unspoofable: the responder blocks only flows
  with bidirectional TCP evidence. Blind spoofed packets never insert blocks.
- Monitoring exists before enforcement. No phase attaches or enforces
  anything that cannot already raise an alarm when it breaks.
- Rollback at every layer is one shipped command, never a hand-typed bpftool
  byte string.
- All XDP loading goes through the libxdp dispatcher; raw `ip link` attach is
  forbidden, and unload is by recorded program id, never `--all`, outside the
  documented last-resort rollback.
- Mutation scope: the tooling touches only the two managed gateway hosts it
  is deployed to, and only through the phased, human-driven bring-up in
  `docs/design.md`. `deploy.sh` pushes files only; it enables and starts
  nothing. Nothing in this repository mutates any other system.
- Builds run off-host in a privileged container, which also rehearses the
  exact production pin, attach, verify, and unload sequence in a network
  namespace before any artifact ships.
- No real addresses or network layout in this repository; examples use
  documentation ranges (192.0.2.0/24, 203.0.113.0/24).
- No emojis; no em or en dashes in prose (use commas, colons, parentheses).

## Domain Context

The managed hosts are consumer-grade gateways whose management path (a
WireGuard mesh) rides the same interface the firewall filters, so the specs
are dominated by two failure classes: severing the operator's own access,
and letting an attacker poison the blocklist. Decisions are recorded in
`docs/adr/`; the architecture, failure-mode table, and phased install plan
live in `docs/design.md` (arc42).
