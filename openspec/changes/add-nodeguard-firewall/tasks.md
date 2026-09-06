# Tasks: add-nodeguard-firewall

## 1. Artifacts (authored; verified by the container build)

- [x] 1.1 Write `src/nodeguard_kern.c` with the fail-open parse contract,
      kill switch, WireGuard port pass, allowlist-before-blocklist order,
      and in-kernel TTL expiry
- [x] 1.2 Write `bin/ngmap.py` as the single encoder/decoder for every
      pinned map, with the never-block range guard
- [x] 1.3 Write the CLIs (`nodeguard-cli` block/unblock/list/flush/off/on,
      `nodeguard-status`, `nodeguard-maps`) and the attach/detach/reload
      wrappers with map-identity verification and unload-by-id
- [x] 1.4 Write `bin/nodeguard-responder` implementing every pipeline gate
      and the dry-run mode
- [x] 1.5 Write `bin/nodeguard-watchdog` (lifelines, canary, latch and
      re-arm semantics, port refresh) and `bin/nodeguard-canary`
- [x] 1.6 Write the systemd units and timers (maps, xdp, responder, sweep,
      watchdog, suricata-update)
- [x] 1.7 Write `build/build.sh` (container compile, spec generation from
      the object, netns rehearsal) and `build/mkyaml.py` per-host yaml
      rendering
- [x] 1.8 Write `hosts/example-gateway/` with documentation addresses,
      `etc/` shared config, and `deploy/deploy.sh` (push and verify only)
- [x] 1.9 `bash -n` and shellcheck the scripts; `python3 -m py_compile` the
      Python; run the container build end to end

## 2. Phase 0: package install and file deploy (per host, human-driven)

- [x] 2.1 Install `xdp-tools`, `bpftool`, `suricata`; verify
      `suricata --build-info` (AF_PACKET, Hyperscan) and SELinux module
      state
- [x] 2.2 Deploy artifacts with `deploy.sh`; `restorecon`; verify the
      deployed spec matches the deployed object

## 3. Phase 1: Suricata shadow (no XDP, no enforcement)

- [x] 3.1 Apply per-host sysconfig and yaml; on the remote node apply and
      assert the NIC offload changes, including after a deliberate
      tailscaled restart
- [x] 3.2 Enable suricata and the update timer; verify the unix-command
      socket answers
- [x] 3.3 Verify detection end to end from an external vantage and confirm
      alert records carry the flow counter fields the responder requires
- [ ] 3.4 Measure steady and reload-peak RSS; set final memory caps or trim
      the ruleset; watch kernel drops for one to two weeks

## 4. Phase 2: monitoring gate, maps, first attach

- [x] 4.1 Entry gate: create the monitoring items and triggers (attach
      state, kill switch, stats advancing, unit states, IDS restart and
      drift items) before any attach
- [x] 4.2 Enable the maps service; verify pins, reconciliation, and the
      WireGuard port value
- [x] 4.3 First attach on the internet gateway in a scheduled window with a
      dead-man abort; verify link, dispatcher membership, map identity,
      and the management path
- [x] 4.4 Verify the hitless reload path causes no carrier loss before
      calling it hitless anywhere
- [x] 4.5 Functional drop test with real routable traffic: block a test
      source, prove the drop with xdpdump and counters, prove in-kernel
      expiry and sweep collection
- [x] 4.6 Attach on the remote node via the self-recovering canary wrapper;
      run its return-traffic drop test against its own pin set
- [x] 4.7 Enable the sweep and watchdog timers
- [x] 4.8 Exit gate alarm drill: prove the kill-switch and attach-state
      alarms fire on deliberate trips before any enforcement

## 5. Phase 3: responder dry-run

- [ ] 5.1 Enable the responder with `ENFORCE=no` for at least 48 to 72
      hours; review every WOULD BLOCK line including the UDP/ICMP
      ineligible ones; tune `sids.conf`
- [x] 5.2 Enroll the operator's stable remote egress addresses in the allow
      files (mandatory before enforcement)

## 6. Phase 4: enforcement

- [x] 6.1 Flip `ENFORCE=yes` on the internet gateway; monitor
- [ ] 6.2 Enable on the remote node only after a week of clean operation
- [ ] 6.3 `openspec validate add-nodeguard-firewall --strict` and archive
      the change
