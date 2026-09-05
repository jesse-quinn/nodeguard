## Why

The gateway hosts this project manages sit on consumer WAN links with no
upstream filtering. A passive IDS alone observes attacks without stopping
them, and every off-the-shelf blocking option evaluated fails closed
somewhere: NFQUEUE severs traffic when its listener dies, af-packet
copy-mode makes the IDS the forwarder, and the packaged xdp-filter has no
CIDR support and no TTL. The management path (a WireGuard mesh) rides the
same interface being filtered, so a firewall defect can sever the
operator's only access; and a naive alert-to-block pipeline lets a blind
attacker spoof packets that get a needed remote address blocked. The
project therefore needs a specified, fail-open, unspoofable
detect-and-block datapath rather than an assembled one.

## What Changes

- Add the XDP enforcement datapath: a custom BPF program loaded through the
  libxdp dispatcher with a fail-open parse contract, allowlist-before-
  blocklist ordering, in-kernel TTL expiry, a kill switch, a WireGuard port
  hard pass, and machine-verified map pinning (`src/nodeguard_kern.c`,
  `bin/ngmap.py`, `bin/nodeguard-attach`, `units/nodeguard-*.service`).
- Add passive Suricata detection: af-packet IDS, never inline, EVE alert
  output carrying flow counters, and a daily ruleset update timer whose
  reload fails open to the previous ruleset (`build/mkyaml.py`,
  `units/suricata-update.*`).
- Add the alert-to-block responder connecting the two: a gated pipeline
  (severity/SID filter, anti-spoofing bidirectional TCP evidence, inbound
  only, allowlist recheck, rate caps, TTL doubling, mandatory dry-run mode,
  journal pruning) that writes blocks with expiry into the pinned maps
  (`bin/nodeguard-responder`).
- Add the operational shell around them: watchdog with lifeline and canary
  probes, sweep timer, status CLI, container build with netns rehearsal and
  generated map spec, example host config, and a push-only deploy script.

## Capabilities

### New Capabilities

- `xdp-enforcement`: the in-kernel blocklist datapath and its loading,
  verification, kill-switch, and expiry contract.
- `suricata-detection`: passive af-packet IDS deployment with alert output
  the responder can trust and fail-open ruleset updates.
- `alert-to-block-response`: the gated pipeline that turns qualifying alerts
  into TTL-bounded blocks without being spoofable.

## Impact

- New repository artifacts only: BPF C source, Python and bash tooling,
  systemd units, build and deploy scripts, example config. No change to any
  system until a human runs the phased bring-up in `docs/design.md`.
- Dependencies on the managed hosts: stock Fedora `suricata`, `xdp-tools`,
  and `bpftool` RPMs; python3; a kernel with BTF. Build requires docker or
  podman on any Fedora x86_64 machine, never the hosts themselves.
- Blast radius: the two managed gateway hosts, one physical interface each.
  Every component fails open, so the worst-case defect is an unfiltered
  datapath, which is the status quo.
- Out of scope: inline IPS modes (NFQUEUE, af-packet copy mode); VLAN or
  LAN-side attach points; blocking on UDP or ICMP alerts by default;
  IPv6-specific rule curation; automated deployment or enablement (bring-up
  stays phased and human-driven); any mutation outside the two managed
  hosts.
