# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

There are no tagged releases yet; everything below is pre-release work on the
main branch.

## [Unreleased]

### Added

- XDP program (`src/nodeguard_kern.c`): a fail-open blocklist firewall loaded
  through the libxdp dispatcher. Per packet, in order: parse failure passes,
  kill switch passes, the host's live WireGuard UDP port hard-passes, an
  allowlist LPM lookup passes, and only an unexpired blocklist hit drops.
  Blocklist TTL expiry is enforced in the kernel against
  `bpf_ktime_get_ns()`, so a dead userspace can never leave a block enforced
  past its expiry. Map declarations in the C source are the single source of
  truth for map parameters.
- Map toolchain (`bin/ngmap.py`): the one place that encodes, decodes, and
  mutates the pinned BPF maps (LPM key layout, block values, config and stats
  slots), with a never-block range guard, plus the CLIs that shell into it:
  block, unblock, list, flush, off, on, status, and sweep
  (`bin/nodeguard-cli`, `bin/nodeguard-maps`, `bin/nodeguard-status`).
- Suricata alert-to-block responder (`bin/nodeguard-responder`): tails
  `eve.json` and inserts offender source addresses only when every gate
  passes: alert events only, severity 1 or an opted-in SID, an anti-spoofing
  gate requiring bidirectional TCP flow evidence (UDP and ICMP alerts are
  log-only unless a SID is promoted by hand), inbound only, an allowlist
  recheck, and rate caps. TTL doubles for repeat offenders up to a maximum;
  a journal records blocks and is pruned. `ENFORCE=no` dry-run is the
  mandatory first-run mode.
- Watchdog (`bin/nodeguard-watchdog`): per-minute lifeline probes over
  allowlisted paths detect datapath death, and a deliberately non-allowlisted
  canary probe detects over-blocking; either condition soft-disables
  enforcement through the kill switch, with latch, hourly re-alarm, and
  bounded once-per-boot auto re-arm semantics. Also refreshes the WireGuard
  port in the config map every cycle.
- Attach and reload discipline (`bin/nodeguard-attach`, `bin/nodeguard-detach`,
  `bin/nodeguard-reload`, `bin/nodeguard-canary`): dispatcher-only loading,
  post-attach verification that the attached program's maps are the pinned
  maps, unload by recorded program id (never `--all`), a hitless
  member-swap reload path, and a self-recovering canary wrapper for attaching
  on a host whose only access path rides the interface being modified.
- systemd units and timers (`units/`): map setup with pin verification and
  allowlist reconciliation, the XDP attach service, the responder service,
  a sweep timer for expired-entry garbage collection, the watchdog timer,
  and a daily Suricata ruleset update timer whose reload step fails open to
  the previous ruleset.
- Container build (`build/build.sh`): compiles the object in a stock Fedora
  container (no compiler on the target hosts), generates
  `nodeguard-maps.spec` from the object so the maps service and the object
  cannot drift, rehearses the exact production pin, attach, verify, and
  unload sequence in a network namespace, and renders per-host
  `suricata.yaml` files (`build/mkyaml.py`, with the stock yaml kept for
  drift comparison).
- Example host configuration (`hosts/example-gateway/`) using documentation
  addresses, and shared config (`etc/protected.conf`, `etc/sids.conf`,
  tmpfiles entry).
- Deploy script (`deploy/deploy.sh`): pushes and verifies files only; it
  enables and starts nothing (bring-up is phased and manual).
- arc42 design document (`docs/design.md`): architecture, failure-mode
  table, phased install plan, and rollback.
- Five ADRs (`docs/adr/`) recording the load-bearing decisions and their
  rejected alternatives.
- OpenSpec change `add-nodeguard-firewall` (`openspec/`) specifying the XDP
  enforcement, Suricata detection, and alert-to-block response capabilities.
