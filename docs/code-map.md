# nodeguard code map

A file-by-file, function-by-function tour in reading order, so you can find
what does what without spelunking. Every function also carries a
plain-language purpose comment at its definition; this map is the index.

The system is two halves that share pinned BPF maps and never call each
other directly: a **kernel datapath** (one XDP program) that decides each
packet, and **userspace tooling** (Python and bash) that fills the maps,
watches health, and reports. Killing any userspace piece degrades to
"maps stop changing"; the datapath keeps running. That is the fail-open
contract (ADR 0003).

```
             fetch/observe                 read per packet
  feeds/responder ---> [ block4/block6 ] <--- nodeguard_kern.c (XDP)
  nodeguard-maps  ---> [ allow4/allow6 ]         drops or passes
  watchdog        ---> [ config, stats  ]
       |                                              |
       +--> nodeguard-status --kv --> /run/zabbix --> Zabbix
```

## The datapath (kernel)

### src/nodeguard_kern.c
The whole firewall decision, ~330 lines of eBPF C, GPL-2.0 (kernel
requirement). Attached to one NIC via the libxdp dispatcher.

- The `.maps` declarations: `allow4/allow6` (never-block LPM tries),
  `block4/block6` (the blocklist LPM tries; value carries expiry_ns and a
  hit counter), `config` (kill switch, WireGuard port, re-arm count),
  `stats` (8 pass/drop path counters), `stats2` (7 protocol-sanity
  counters). These pins are the single source of truth for map shape;
  the build generates nodeguard-maps.spec from them.
- `count()` / `count2()`: increment a per-CPU counter in stats / stats2.
- `sanity_tcp_flags()`: count-only telemetry; tallies impossible TCP flag
  combinations (SYN+FIN, SYN+RST, NULL, XMAS) seen on a packet. Never a
  verdict input.
- `handle_v4()` / `handle_v6()`: the per-packet decision for one family.
  In order: sanity counters (before the kill switch, so scan visibility
  survives a latch), kill-switch pass, WireGuard-port pass, allowlist
  pass, then the blocklist lookup. A blocklist hit whose TTL has not
  expired is the ONLY XDP_DROP; everything else is XDP_PASS. This is
  where a Spamhaus DROP range actually blocks a packet.
- `nodeguard()` (SEC("xdp")): the entry point. Parses ethernet and one
  optional VLAN tag, reads the config map (kill switch, WG port), and
  dispatches to handle_v4/handle_v6. Any parse failure returns XDP_PASS.

## The map toolchain (userspace core)

### bin/ngmap.py
The single place that encodes, decodes, and mutates the pinned maps via
bpftool. Every CLI shells into it so the LPM key layout exists in one
tested implementation.

- Key/value codecs: `key_bytes()`, `decode_key()`, `encode_value()`,
  `decode_value()` translate between CIDRs/expiry and the raw map bytes.
- `bpftool()`: the one subprocess wrapper; raises on failure.
- `lookup_value()` / `update_map()` / `delete_key()` / `dump_map()`: the
  low-level map operations. lookup treats a miss on a pinned map as
  "absent", not an error (the LPM lookup-miss fix).
- `block_lock()`: the per-key inter-process lock so a sweep and a fresh
  block never race.
- `is_protected()` / `contains_protected()` / `NEVER_BLOCK`: the refusal
  logic that keeps RFC1918, CGNAT, and the allowlist unblockable.
- `cmd_block/unblock/list/flush/sweep`: the operator verbs. `cmd_sweep`
  also writes the map-stats cache (the only writer) every 10 minutes.
- `cmd_stats/stats2`: read the per-CPU counters.
- `cmd_create_maps`: create or verify the pins from the spec, refusing
  drift (ADR 0004). `cmd_reconcile_allow`: bring the allow maps to the
  files. `cmd_allow_check/allow_dump`: the allowlist query surface.

## Attaching and managing the program (bash)

### bin/nodeguard-lib.sh (sourced by the others)
- `ng_log`: journald plus stderr logging. `ng_env`: load the host env.
- `ng_cfg_get/set`: read/write a config map slot. `ng_prog_ids`: the
  three-valued attach state (attached / detached / xdp-loader-broken).
- `ng_live_wg_port`: tailscaled's actual bound WireGuard port.
- `ng_verify_map_identity`: prove an attached program uses the pinned
  maps (the generalized check). `ng_spec_pins_present`: refuse to load
  if the spec lists a map with no pin.

### bin/nodeguard-maps (ExecStart of nodeguard-maps.service)
Creates/verifies the pins from the spec, reconciles the allowlist from
the files plus generated protected remotes, and writes the live
WireGuard port into config. Truncates the sweep cache when it creates
maps (reboot honesty).

### bin/nodeguard-attach / -detach / -reload
attach loads the program via xdp-loader in native mode and verifies map
identity, recording the expected program id. detach unloads by id only
(never --all). reload swaps a new object in place hitlessly, verified in
both directions.

### bin/nodeguard-cli (block/unblock/list/flush/off/on)
Thin verb wrappers over ngmap.py, plus the kill switch (off/on) which
verifies its write by read-back so it can never falsely claim
enforcement is soft-off.

## Detection and response

### bin/nodeguard-responder
Tails Suricata's eve.json and, for a severity-1 TCP alert with
bidirectional flow evidence (the anti-spoofing gate), inserts the
offender into block4 with a TTL. Dry-run by default. Emits its own
security-event counters. `follow()` survives log rotation; `Journal`
tracks offenses so TTL escalation counts block windows not alert lines.

### Suricata (packaged, config generated by build/mkyaml.py)
Runs as a passive af-packet IDS; never inline. mkyaml.py renders a
host's suricata.yaml from a params file.

## Threat-intel feeds

### bin/nodeguard-feeds
Fetches Spamhaus DROP v4/v6 and DShield top-20 every 6h, validates each
against its real grammar, and reconciles the survivors into block4/block6
with a 25h TTL. Ownership is a journal plus compare-and-swap on the
written expiry value, so feed entries never disturb responder or operator
entries. `FEED_DEFS` names the sources; `obtain()` fetches and validates;
`gate()` runs the safety brakes (canary, coverage, churn, protected);
`reconcile()` does the insert/refresh/withdraw under invariant W1 (a
failed feed withdraws nothing). Enforcement needs the double gate:
config AND an interactive `apply --confirm`.

## Health and observability

### bin/nodeguard-watchdog (every minute)
Exports the monitoring kv snapshot, runs the EWMA volumetric-anomaly
detector (shadow by default), probes allowlisted lifelines plus a
non-allowlisted canary, and latches the kill switch on over-blocking or
datapath death, with bounded auto re-arm. Refreshes the WireGuard port.

### bin/nodeguard-status (the 2am command; --kv for monitoring)
Human summary by default. `--kv` emits the full key/value snapshot the
watchdog exports to /run/zabbix/nodeguard.kv; every value that cannot be
read is omitted (visible-unknown), never zeroed.

### bin/nodeguard-canary
The remote node's self-recovering first attach: runs detached, self-
checks connectivity, waits for operator confirmation, and rolls itself
back if unconfirmed, so a bad attach can never strand the box.

## Monitoring generators (public, host-group scaled)

### zbx/lib.py
The Zabbix JSON-RPC client (`Api`), host-group resolution, and the widget
builders (itemvalue, gauge, svggraph, pie, honeycomb, url) with stable
per-host colors so a growing fleet does not reshuffle. Field shapes
verified against the live 7.4 API.

### zbx/gen-template.py / check_template.py
gen-template renders the monitoring template v2 (master item plus
dependent items, feed discovery) carrying every existing uuid so history
survives. check_template is the build drift gate: it fails the build if a
templated field would not parse or an item identity changed.

### zbx/dashboards.py
Builds the three dashboards (Overview, Security, Capacity and Pipeline)
resolved live from a host group, so adding a host needs no code edit.
Plan by default; --confirm applies.

## Build and deploy

### build/build.sh
Runs in a Fedora container on a builder: compiles the object, generates
the map spec FROM the object (never a hardcoded list), and rehearses the
whole pin/attach/mutate sequence in a netns including crafted sanity
packets, a read-failure drill, and a rollback. No compiler ever touches a
gateway.

### deploy/deploy.sh
Pushes the artifact set to one host and verifies it, starting nothing.
`--with-kernel` is required to move the datapath object, so a routine
userspace deploy can never activate an untested kernel program.
