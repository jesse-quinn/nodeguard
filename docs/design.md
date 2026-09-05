# nodeguard: Design

Status: living document.
Last updated 2026-09-05, mid bring-up: phase 2 is complete on both hosts
(XDP attached, functional drop tests passed, the hitless reload verified,
sweep and watchdog timers enabled, alarm drills fired); the responder
dry-run soak and enforcement are pending, and the threat-intel feeds
loader is deployed in dry-run on both hosts.
Companion docs: [`docs/adr/`](adr/) (decisions), [`openspec/`](../openspec/)
(behaviour specs), [`CHANGELOG.md`](../CHANGELOG.md) (history),
[`README.md`](../README.md) (quick start and the 2am commands).

nodeguard is an eBPF/XDP blocklist firewall fed by a passive Suricata IDS,
built for small Fedora 44 Linux gateways running stock packages. Suricata
detects; a ~200-line custom XDP program enforces at the driver, with
in-kernel TTL expiry and fail-open behaviour on every path. This document
describes the architecture as it stands mid bring-up (phase 2 complete,
dry-run soak and enforcement pending): the per-packet decision path, the
alert-to-block pipeline, the watchdog, the feeds loader, the map contract,
the phased bring-up, and the failure modes.
The one fact a new reader must know: the only packet nodeguard ever drops
is one whose source address holds an unexpired blocklist entry; every
other path, including every error path, is `XDP_PASS`.

## 1. Introduction and Goals

nodeguard answers a narrow question: how does a self-managed internet
gateway block confirmed attackers at line rate without ever risking its
own reachability? The answer is strict separation: detection is a passive
Suricata af-packet IDS that touches no packet's fate; enforcement is a
small, independently verified XDP program whose entire policy lives in
pinned BPF maps; the only coupling is a userspace responder that turns
qualifying alerts into map entries with a TTL.

Quality goals, in priority order:

1. **Fail open, everywhere.** No program attached, empty maps, dead
   responder, dead Suricata, parse failure on a hostile frame: traffic
   flows. Availability of the gateway beats completeness of blocking.
2. **Unspoofable automated enforcement.** A blind spoofed packet must
   never be able to insert a block. Automated blocks require severity-1
   TCP alerts with bidirectional flow evidence
   (`bin/nodeguard-responder:225`).
3. **Monitoring before enforcement.** No phase of the bring-up attaches
   or enforces anything that cannot already raise an alarm when it
   breaks.
4. **One-command rollback at every layer**, shipped as scripts; the
   emergency path is never a hand-typed `bpftool` byte string.

### In scope

- Ingress blocklist enforcement on exactly one physical NIC per host,
  IPv4 and IPv6, via the libxdp dispatcher in native mode.
- Passive Suricata detection with the et/open ruleset, daily updated.
- Automated block insertion from alerts, gated, rate-capped, TTL-bounded.
- A watchdog that detects both total datapath death and over-blocking,
  and soft-disables enforcement hitlessly in either case.
- Off-host builds, file-push deployment, phased manual bring-up.

### Out of scope

- Egress filtering, NAT, routing policy, or any nftables interaction.
- Inline IPS (NFQUEUE, af-packet copy-mode); rejected, see ADR 0001.
- VLAN-tagged attach points and bonded interfaces (a tagged frame is
  parsed correctly but no per-VLAN policy exists;
  `src/nodeguard_kern.c:127`).
- Automatic enforcement on UDP or ICMP alerts (log-only by design, ADR
  0002).
- Any mutation of firewalld, docker, dnsmasq, or tailscale configuration.

## 2. Constraints

- **Fedora 44, stock packages only.** Suricata is the distribution's
  `suricata-8.0.6` RPM; XDP tooling is the packaged `xdp-tools`,
  `libbpf`, `bpftool`. No third-party repos, no source installs on the
  hosts.
- **No compiler on production hosts.** The BPF object is built in a
  privileged Fedora 44 container (`build/build.sh:6`) and shipped as a
  file with its sha256.
- **SELinux enforcing** on both targets; artifacts live under
  `/usr/local/lib/nodeguard` and are `restorecon`ed on deploy
  (`deploy/deploy.sh`), never under `/var/tmp`.
- **The libxdp dispatcher is the only sanctioned XDP loader.** A raw
  `ip link` attach anywhere on a nodeguard host would permanently block
  the dispatcher and is forbidden (README, ADR 0004).
- **GPL-2.0**: the XDP program must be GPL for the BPF helpers it uses
  (`src/nodeguard_kern.c:22`).
- **Public repository.** Real per-host configuration (interfaces,
  allowlists, `HOME_NET`) lives in a private overlay outside this tree;
  `hosts/example-gateway/` carries only documentation addresses
  (192.0.2.0/24 and friends). Nothing identifying a real deployment is
  committed.
- **Hardware floor**: Atom-class CPUs. Suricata sizing (threads, ring
  size, memory caps) is provisional until measured in phase 1
  (`hosts/example-gateway/suricata-50-limits.conf:1`).
- **Management access rides a tailnet** (WireGuard). The design must
  guarantee that no block entry can ever sever that tunnel.

## 3. Context and Scope

Two deployment targets, both Fedora 44:

- **The internet gateway**: 8-core Atom, 32 GiB, ixgbe WAN NIC with a
  public DHCP-assigned address. XDP attaches to the WAN NIC only; LAN
  traffic never traverses the program.
- **The remote node**: 4 cores, 16 GiB, NAT'd behind another LAN and
  reachable only over the tailnet. XDP attaches to its single upstream
  NIC.

```
                    internet
                        │
              ┌─────────▼──────────┐
              │  WAN NIC (ixgbe)   │
              │ ┌────────────────┐ │   libxdp dispatcher, native mode
              │ │ nodeguard XDP  │◄┼── pinned maps /sys/fs/bpf/nodeguard
              │ └───────┬────────┘ │   (allow4/6, block4/6, config, stats)
              └─────────┼──────────┘         ▲
             XDP_PASS   │                    │ ngmap.py (all encoding)
                        ▼                    │
      ┌──────────── netfilter ───────────┐   │
      │ firewalld / docker / tailscale   │   │
      └───────────────┬──────────────────┘   │
                      │ af-packet copy       │
              ┌───────▼────────┐    ┌────────┴────────┐
              │ Suricata 8.0.6 │    │ nodeguard-      │
              │ passive IDS    ├───►│ responder       │
              │ (never inline) │eve │ (gates, caps)   │
              └────────────────┘json└─────────────────┘
```

External interfaces:

| Neighbour | Direction | Purpose |
|---|---|---|
| Suricata (`eve.json`) | in | Alert stream the responder tails |
| tailscaled | read | Live WireGuard listen port for `config[0]`; DERP relay list for the allowlist (`bin/nodeguard-maps:81`) |
| Upstream DNS resolvers (Quad9) | out | Allowlisted; also a watchdog lifeline probe |
| `api.anthropic.com` | read | Resolved into the protected-remotes allowlist (`etc/protected.conf`) |
| Canary target (e.g. `1.1.1.1:443`) | out | Deliberately non-allowlisted watchdog probe (ADR 0005) |
| Spamhaus DROP v4 / v6 (`drop_v4.json`, `drop_v6.json`) | out | HTTPS fetch by `nodeguard-feeds` every 6 h (`bin/nodeguard-feeds:59`, `units/nodeguard-feeds.timer`) |
| DShield block list (`block.txt`) | out | HTTPS fetch by `nodeguard-feeds` every 6 h; dry-run only until promoted (`bin/nodeguard-feeds:65`) |
| The Zabbix server | in | Polls the agent's `nodeguard.kv[*]` items, backed by the watchdog's per-minute kv export to `/run/zabbix/nodeguard.kv` (section 8); journal CRITICALs are the out-of-band channel |
| A build host (container) | n/a | Compiles the object, generates the spec, rehearses attach |
| Operator over SSH | in | `deploy/deploy.sh` pushes files; bring-up is manual |

## 4. Solution Strategy

- **Detection and enforcement are fully decoupled.** Suricata loads no
  BPF and is never inline; the XDP layer reads no Suricata state except
  through the responder. Either side can die with zero effect on the
  other's core function (ADR 0001).
- **Policy lives in pinned maps, not in the program.** The XDP program is
  a pure function of packet bytes plus five pinned maps. All map
  mutation goes through one tested encoder, `bin/ngmap.py`, so the LPM
  key layout exists in exactly one implementation (`bin/ngmap.py:2`).
- **The compiled object is the single source of map truth.** The build
  extracts `nodeguard-maps.spec` from the loaded object's BTF
  (`build/build.sh:26`); the maps service creates or verifies pins only
  from that spec and refuses drift loudly (ADR 0004).
- **TTLs are enforced in the kernel** by comparing a stored absolute
  `CLOCK_MONOTONIC` expiry against `bpf_ktime_get_ns()` per packet
  (`src/nodeguard_kern.c:170`), so no dead userspace component can leave
  a block enforced past its expiry (ADR 0003).
- **Every failure path returns `XDP_PASS`**; the drop is the single
  final case (`src/nodeguard_kern.c:4`).
- **Bring-up is phased and gated** (phases 0 to 5, section 6.4), with
  monitoring as an entry gate before the first attach and alarm drills
  as an exit gate before enforcement.

## 5. Building Block View

```
src/nodeguard_kern.c    the XDP program; map declarations are normative
bin/                    userspace: encoder, CLIs, daemons
units/                  systemd units and timers
etc/                    shared config templates
hosts/example-gateway/  per-host config template (documentation IPs)
build/                  container build, spec generation, netns rehearsal
deploy/                 file push and verify; enables nothing
templates/              Zabbix template JSON for the kv items and triggers
zbx/                    (planned) dashboard and template generator suite,
                        proposed in OpenSpec change add-nodeguard-telemetry
```

### `src/nodeguard_kern.c`

Declares the six maps with `LIBBPF_PIN_BY_NAME` pinning: `allow4`/
`allow6` (LPM tries, u8 tag values), `block4`/`block6` (LPM tries,
16-byte `{expiry_ns, hits}` values, 65536 and 16384 entries), `config`
(array of four u64 slots: WireGuard port, kill switch, re-arm count,
reserved; `src/nodeguard_kern.c:42`), and `stats` (per-CPU array of
eight counters). Declares libxdp dispatcher metadata (`XDP_RUN_CONFIG`,
priority 10, chain action `XDP_PASS`; `src/nodeguard_kern.c:223`).

### `bin/`

- `ngmap.py`: the only code that encodes, decodes, or mutates the maps.
  Subcommands: `block`, `unblock`, `list`, `flush`, `sweep`, `stats`,
  `get-config`/`set-config`, `allow-check`, `create-maps`,
  `reconcile-allow`. Carries the `NEVER_BLOCK` ranges
  (`bin/ngmap.py:33`) and the guard rails: refuses to block anything
  protected or any CIDR containing a protected range
  (`bin/ngmap.py:161`), refuses short prefixes and permanent entries
  without `--i-mean-it` (`bin/ngmap.py:155`).
- `nodeguard-cli`: multiplexed thin wrapper installed as symlinks
  `nodeguard-block`, `-unblock`, `-list`, `-flush`, `-off`, `-on`.
- `nodeguard-maps`: `ExecStart` of the maps service; creates/verifies
  pins from the spec, builds the generated protected-remotes list,
  reconciles the allow maps, writes the live WireGuard port.
- `nodeguard-attach` / `nodeguard-detach`: `ExecStart`/`ExecStop` of the
  XDP unit; native-mode load plus map-identity verification, unload by
  program id only.
- `nodeguard-reload`: hitless object swap (new dispatcher member in,
  verify, old member out; `bin/nodeguard-reload:1`).
- `nodeguard-responder`: the Suricata-to-XDP daemon (section 6.2).
- `nodeguard-feeds`: the threat-intel feed loader (913 lines): fetches
  Spamhaus DROP v4/v6 and DShield top-20, validates each body against
  that feed's real grammar, and reconciles the survivors into
  `block4`/`block6` with a 25 h in-kernel TTL. Ownership is a journal
  plus compare-and-swap on the written expiry value, never a map dump
  (the block maps have other writers); a feed that failed this run
  performs zero withdrawals (invariant W1, `bin/nodeguard-feeds:9`).
  Enforcement needs a double gate: the feed listed in `FEEDS_APPLY` in
  the deployed config AND recorded in `approved.json` by an interactive
  `apply --confirm` (`bin/nodeguard-feeds:22`). Exports `ng.feeds_*` kv
  state to `/var/lib/nodeguard/feeds/feeds.kv`.
- `nodeguard-watchdog`: one probe cycle per minute (section 6.3).
- `nodeguard-canary`: the remote node's self-recovering first-attach
  script, run detached under a transient systemd unit.
- `nodeguard-status`: everything on one screen; `--kv` for the
  monitoring system's UserParameters.
- `nodeguard-lib.sh`: shared paths and helpers (`ng_prog_ids`,
  `ng_live_wg_port`).

### `units/`

`nodeguard-maps.service` (oneshot, `RemainAfterExit`), then
`nodeguard-xdp.service` (`Requires`/`After` maps;
`units/nodeguard-xdp.service:3`), `nodeguard-responder.service`
(`Restart=on-failure`), `nodeguard-sweep.timer` (10 min),
`nodeguard-watchdog.timer` (1 min), `nodeguard-feeds.service` (oneshot)
with `nodeguard-feeds.timer` (every 6 h, 15 min after boot, randomized
delay; `units/nodeguard-feeds.timer:8`), and the `suricata-update`
service/timer pair (daily, with the systemd ignore-failure `-` prefix on
the reload so a stopped Suricata never fails the update;
`units/suricata-update.service:8`).

### `etc/` and `hosts/example-gateway/`

Shared: `protected.conf` (directives `derp`, `resolve <name>`,
`cidr <net>`), `sids.conf` (directives `block`, `ignore`, `udp-ok`),
`zabbix-userparameter-nodeguard.conf` (the agent-side kv items, section
8), tmpfiles for `/run/nodeguard`. Per-host template: `nodeguard.env`
(`IFACE`, `CANARY_IP`, `CANARY_PORT`, `LIFELINES`,
`WAN_DYNAMIC_ALLOW`), `allow4.txt`/`allow6.txt`, `responder.conf`,
`feeds.conf` (the feeds loader's gates and caps, section 8), Suricata
sysconfig, resource-cap drop-in, device dependency drop-in, and
`suricata-params.json` for yaml generation.

### `build/` and `deploy/`

`build/build.sh` compiles with clang in a privileged container,
generates the spec from the loaded object, rehearses the exact
production pin/create/attach/verify/unload sequence in a netns
(`build/build.sh:66`), exercises the encoders against live maps, and
renders per-host `suricata.yaml` files via `build/mkyaml.py` from
`build/suricata-stock.yaml` (kept for drift comparison against RPM
updates). `deploy/deploy.sh` pushes the artifact set to one host,
installs, `bash -n`s every script, `py_compile`s the Python,
`systemd-analyze verify`s every unit, and deliberately enables nothing.

## 6. Runtime View

### 6.1 Per-packet XDP decision path

In order, for every frame on the attach NIC
(`src/nodeguard_kern.c:229`):

1. Ethernet bounds check; one optional 802.1Q/802.1AD header is parsed
   and skipped. Any parse failure anywhere: `XDP_PASS`, count
   `pass_parsefail`.
2. Non-IP ethertype (ARP, LLDP, anything else): `XDP_PASS`,
   `pass_nonip`.
3. `config[1]` nonzero (kill switch): `XDP_PASS`
   (`src/nodeguard_kern.c:264`).
4. UDP with destination port equal to `config[0]` (the live WireGuard
   port): hard `XDP_PASS`, `pass_wgport`. This runs before any blocklist
   lookup so no block entry can sever the management tunnel
   (`src/nodeguard_kern.c:141`).
5. LPM lookup of the source address in `allow4`/`allow6`: hit is
   `XDP_PASS`, `pass_allowlist`. Allowlist beats blocklist in the
   datapath itself, so no userspace ordering bug can block a protected
   range.
6. LPM lookup in `block4`/`block6`: miss is `XDP_PASS`. On a hit, if
   `expiry_ns != 0` and `bpf_ktime_get_ns() >= expiry_ns`: `XDP_PASS`,
   `pass_expired`. Otherwise increment `hits` and `XDP_DROP`
   (`src/nodeguard_kern.c:165`).

`expiry_ns == 0` means permanent and is reserved for manual entries; the
responder never writes it.

### 6.2 Alert-to-block pipeline

`af-packet capture -> eve.json alert -> responder -> nodeguard-block ->
pinned block map -> XDP drop on the offender's next packet.`

The responder (`bin/nodeguard-responder`) tails `eve.json` tail-F
style, reopening across rotation and starting at the end (never
replaying; `bin/nodeguard-responder:133`). All gates must pass before
any block:

1. `event_type == "alert"` only.
2. Severity 1, or the SID opted in via `sids.conf` (`block <sid>`);
   SIDs on the ignore list are dropped first.
3. Anti-spoofing gate: protocol must be TCP with
   `flow.pkts_toclient >= 1` and `flow.pkts_toserver >= 2`
   (`bin/nodeguard-responder:225`). UDP and ICMP alerts are logged as
   `WOULD BLOCK (udp/icmp, not eligible)` unless the SID is
   hand-promoted with `udp-ok` plus a written justification (ADR 0002).
4. Inbound only: destination in `HOME_NETS`, source globally routable.
5. Source not covered by the live allow maps or the `NEVER_BLOCK`
   ranges (userspace re-check via `ngmap.py allow-check`; the kernel
   allow map is the backstop).
6. Rate caps: 30 new blocks per rolling minute, 500 per hour
   (`bin/nodeguard-responder:249`); on breach it stops adding and logs
   loudly.
7. Action: block the source `/32` or `/128` for TTL 3600 s, doubling
   per repeat offense up to 86400 s (`bin/nodeguard-responder:262`),
   journaled in `/var/lib/nodeguard/blocks.json` (pruned at 30 days,
   never re-armed after reboot).

`ENFORCE=no` in `responder.conf` is the mandatory first-run mode: every
decision is logged as `WOULD BLOCK` and nothing is touched.

Deliberate blindness, stated plainly: `XDP_DROP` happens before
af-packet, so Suricata stops seeing a blocked address entirely. The TTL
is also the re-detection interval; "no more alerts" is never evidence
of cessation.

### 6.3 Watchdog cycle

Every minute (`units/nodeguard-watchdog.timer:6`),
`bin/nodeguard-watchdog` runs one cycle:

- **kv export, first**: writes the `nodeguard-status --kv` snapshot to
  `/run/zabbix/nodeguard.kv` (tmp then rename;
  `bin/nodeguard-watchdog:16`). This is the entry point of the entire
  monitoring chain (section 8) and runs before the maps-exist guard, so
  monitoring keeps reporting even on a host where nodeguard is not yet
  set up.
- **Anomaly detector (planned)**: OpenSpec change
  `add-nodeguard-telemetry` adds a per-cycle EWMA baseline over deltas
  of drop, pass, sanity-counter, and alert totals after the kv export,
  with regime-change reseeds (kill switch, attach state, feeds enforce)
  and updates excluded for at-threshold cycles so an attack cannot train
  the detector into silence. Shipped off/shadow first; it never touches
  the kill switch or any map.
- **Port refresh**: compares `config[0]` against the port tailscaled
  actually bound (`ss -ulpn`) and rewrites it on change
  (`bin/nodeguard-watchdog:21`). The tailscale RPM restarts tailscaled
  mid-update and can move the port; this closes the window within a
  minute.
- **Lifeline probes** (allowlisted paths, from `LIFELINES` in
  `nodeguard.env`): default gateway ping, a raw UDP DNS query to Quad9,
  tailscale self-online, or a LAN gateway ping. These detect total
  datapath death or an upstream outage.
- **Canary probe**: TCP connect to `CANARY_IP:443`, a target that must
  never appear in any allow source (`nodeguard-maps` refuses to load
  one that does; `bin/ngmap.py:324`). Because the canary's return
  traffic traverses the blocklist lookup, an over-broad block entry, an
  inverted expiry comparison, or an encoder defect breaks the canary
  while lifelines stay green (ADR 0005).
- **Triggers** (with a program attached and the kill switch clear):
  three consecutive canary failures while at least one lifeline passes
  means suspected over-blocking: `nodeguard-off --watchdog`, CRITICAL
  with the stats snapshot as evidence (`bin/nodeguard-watchdog:106`).
  Five consecutive cycles of all lifelines failing: soft-off, since the
  cause may be an upstream outage nodeguard did not create
  (`bin/nodeguard-watchdog:110`).
- **Latched**: ten further all-fail cycles detach the XDP program
  entirely (`bin/nodeguard-watchdog:117`). If the latch was
  watchdog-set (no manual marker), 15 fully clean cycles re-arm
  enforcement once per boot, tracked in `config[2]`
  (`bin/nodeguard-watchdog:124`). Any second latch, and any manual
  `nodeguard-off`, is human-only recovery. While latched, a CRITICAL
  reminder repeats hourly.

### 6.4 Phased bring-up (phases 0 to 5)

Each phase is independently abortable; the gateway leads the remote
node at every step.

- **Phase 0, prep**: install `xdp-tools`, `bpftool`, `suricata`; deploy
  files; `bash -n`, shellcheck, `systemd-analyze verify`, `restorecon`;
  verify the spec matches the deployed object.
- **Phase 1, Suricata shadow**: passive IDS only, no XDP. Verify
  detection end to end with a real external test alert; confirm alert
  records carry the flow counters the anti-spoofing gate requires;
  measure steady and reload-peak RSS and finalize the provisional
  memory caps; watch `capture.kernel_drops` for 1 to 2 weeks.
- **Phase 2, monitoring gate, maps, first attach**: entry gate creates
  the monitoring items first (attach state from `xdp-loader status`,
  never unit state; kill-switch trigger; counters advancing; unit
  checks). Then maps, then the first attach in a scheduled window (the
  first native attach on ixgbe blips the link), owned by systemd from
  the first moment with a dead-man abort timer; on the remote node via
  the detached self-recovering `nodeguard-canary` (result written
  early, 600 s operator-confirm window, at most one automatic retry;
  `bin/nodeguard-canary:1`). Functional drop tests use real routable
  traffic on both hosts (on the NAT'd node via the return-traffic
  technique: block a cooperating public host, curl it, and prove the
  returning SYN-ACK is dropped). Verify the hitless reload claim.
  Exit gate: deliberate `nodeguard-off` and unit-stop drills must
  alarm before phase 3.
- **Phase 3, responder dry-run**: `ENFORCE=no` for 48 to 72 hours
  minimum; review every `WOULD BLOCK`; tune `sids.conf`; enroll the
  operator's stable remote egress addresses in the allow files
  (mandatory before phase 4).
- **Phase 4, enforcement**: `ENFORCE=yes` on the gateway; the remote
  node follows after a week of clean operation.
- **Phase 5, steady state**: weekly journal review, monthly
  `nodeguard-reload` exercise, threshold tuning.

### 6.5 Failure modes

| Failure | Datapath effect | Recovery |
|---|---|---|
| Verifier reject or native attach fails | No program; all traffic passes | Unit fails visibly (`bin/nodeguard-attach:18`); attach-state alarm; skb mode only by human decision |
| XDP unit fails at boot | Pristine datapath, fail open | Attach-state alarm; host fully reachable |
| Program attached, maps empty | None; miss = PASS | n/a |
| Pin-spec drift (new object vs existing pins) | Attach refuses; fail open | Operator recreates pins per the maps-service instructions (`bin/ngmap.py:301`) |
| Parse bug on an odd frame | PASS by code contract | Patch off-host, deploy via `nodeguard-reload` |
| Kernel update rejects the program | Attach fails at boot; traffic flows | Rebuild in the container, redeploy; alarmed meanwhile |
| Over-broad block entry | Non-allowlisted internet unreachable | Canary fails 3 cycles while lifelines pass: auto soft-off, CRITICAL |
| Spoofed-packet poisoning attempt | None: UDP/ICMP never block-eligible; TCP needs bidirectional evidence | Review the WOULD BLOCK log |
| Responder crashes or hangs | No new blocks; existing expire in-kernel | `Restart=on-failure`; unit alarm |
| Responder berserk (alert flood) | Capped at 30/min, 500/h; protected ranges unblockable in-kernel | Stop responder, `nodeguard-flush` |
| Sweeper dead | Zero enforcement impact; map slowly fills with expired corpses | Restart the timer; 65536-entry headroom |
| Block map full | Updates fail, responder logs; packets unaffected | Sweep, or raise `max_entries` (rebuild spec and pins) |
| Suricata dead, hung, or upgrading | None (passive) | systemd restart; unit alarm; blind until restart |
| Ruleset update pulls a broken ruleset | None; reload fails, old rules persist (`units/suricata-update.service:8`) | Fix the source, rerun |
| False positive on a needed remote | Unreachable for at most one TTL | `nodeguard-unblock` over the always-open tailnet path; `ignore` the SID |
| tailscaled restarts and moves its port | WireGuard pass stale for at most one minute | Watchdog rewrites `config[0]` |
| Upstream/ISP outage | Watchdog soft-off at 5 strikes; hitless | One auto re-arm per boot after 15 clean cycles |
| Watchdog itself dead | No latch protection; datapath unchanged | Timer unit alarm |
| First attach / final detach on ixgbe | Multi-second link blip | Scheduled window; dead-man abort or self-recovering canary |
| `firewall-cmd --reload`, docker reconcile | None (XDP is not nftables) | n/a |
| Reboot | Maps empty; allowlist and config rebuilt at boot; blocks lost (accepted) | None needed |
| Responder and Suricata both dead, program attached | Blocklist decays to empty via in-kernel TTL; steady state is a pass-through no-op | Alarms on both units |

## 7. Deployment View

Two hosts (section 3), each carrying the identical artifact set; one
compiled object serves both because the program parses only packet
bytes, never kernel structs.

On-host layout (installed by `deploy/deploy.sh`):

| Path | Contents |
|---|---|
| `/usr/local/lib/nodeguard/` | `nodeguard_kern.o`, `nodeguard-maps.spec`, `ngmap.py`, `nodeguard-lib.sh` |
| `/usr/local/sbin/` | the `nodeguard-*` scripts; `block`/`unblock`/`list`/`flush`/`off`/`on` as symlinks to `nodeguard-cli` |
| `/etc/nodeguard/` | `nodeguard.env`, `allow4.txt`, `allow6.txt`, `responder.conf`, `protected.conf`, `sids.conf` |
| `/etc/systemd/system/` | units, timers, the per-host device drop-in, the Suricata limits drop-in |
| `/sys/fs/bpf/nodeguard/` | the six pinned maps (reset at boot) |
| `/run/nodeguard/` | prog id, watchdog counters, latch markers (tmpfs, tmpfiles.d) |
| `/var/lib/nodeguard/` | `blocks.json` responder journal |

Build: `docker run --rm --privileged -v "$PWD:/work" fedora:44 /bin/bash
/work/build/build.sh` on any Fedora 44 x86_64 machine with docker or
podman; outputs land in `build/out/` (gitignored). Deploy:
`bash deploy/deploy.sh <ssh-target> <host-config-dir>`, where the host
config dir is a private overlay outside this repository. The deploy
pushes and verifies files only; every enable and start is a manual,
phased step (section 6.4).

Rollback, each layer independent, no reboot, nothing outside nodeguard
ever modified:

| What | Command |
|---|---|
| Instant hitless soft-off | `nodeguard-off` (re-arm: `nodeguard-on`) |
| Stop new blocks | `systemctl stop nodeguard-responder` (existing expire in-kernel) |
| Unblock one address | `nodeguard-unblock <ip>` |
| Flush all blocks | `nodeguard-flush` |
| Detach the datapath | `systemctl disable --now nodeguard-xdp` (link blip; unloads nodeguard's id only) |
| Remove XDP state | disable maps/sweep/watchdog units; `rm -rf /sys/fs/bpf/nodeguard` |
| Evict the whole dispatcher | `xdp-loader unload $IFACE --all`; last resort only, never in a unit or the watchdog |
| Stop detection | `systemctl disable --now suricata suricata-update.timer` (zero traffic impact) |

## 8. Crosscutting Concepts

### Map contract and pinning lifecycle

The map declarations in `src/nodeguard_kern.c` are normative. The build
loads the object and extracts type, key size, value size,
`max_entries`, and flags for all six maps into `nodeguard-maps.spec`
(`build/build.sh:26`), so the object and the maps service share one
source of truth by construction. At every start, `ngmap.py create-maps`
creates missing pins from the spec and verifies existing ones; any
mismatch fails loudly with recovery instructions and blocks attach by
design (`bin/ngmap.py:301`). The attach wrapper then independently
verifies that every pinned map id appears in the attached program's
`map_ids`; on divergence it unloads its own program and exits nonzero
(`bin/nodeguard-attach:31`), so a firewall silently enforcing against
unmanaged maps is structurally impossible. bpffs resets at boot; maps
are recreated and the allowlist rebuilt by `nodeguard-maps.service`,
and lost blocks are an accepted consequence (ADR 0003). Unload is
always by recorded program id, never `--all`, so coexisting dispatcher
members (break-glass tools, an `xdpdump` investigation) survive
nodeguard restarts (`bin/nodeguard-detach:3`).

### Allowlist reconciliation

Three sources feed the allow maps on every maps start: the static
per-host files (tag 1), generated protected remotes (tag 2) from
`protected.conf` directives (current tailscale DERP relay addresses,
current A/AAAA records of listed names, literal CIDRs;
`bin/nodeguard-maps:19`), and, where `WAN_DYNAMIC_ALLOW=yes`, the live
default gateway, DHCP server, and own WAN address, each read fresh as a
`/32` so a renumbered WAN cannot rot the entries
(`bin/nodeguard-maps:67`). `ngmap.py reconcile-allow` then converges
the maps to exactly this desired set, adding and deleting
(`bin/ngmap.py:314`); removals therefore take effect on restart, not at
the next reboot. Reconciliation refuses to proceed if any allow source
covers the configured canary target (`bin/ngmap.py:324`), preserving
the over-block probe's blindness guarantee. The operator's stable
remote egress addresses are a mandatory static entry before
enforcement, so a false positive cannot cause a lockout.

### Kill-switch latch semantics

`config[1]` nonzero makes the program pass everything; flipping it is
hitless (no detach, no link blip). The only sanctioned paths are
`nodeguard-off` and `nodeguard-on` (`bin/nodeguard-cli:29`), which pair
the map write with a marker file (`manual_off` or `watchdog_off`)
recording who latched. `create-maps` initializes the switch to 0 only
when the config map is newly created; an existing value is preserved
(`bin/ngmap.py:307`), so restarting the maps service can never silently
re-arm enforcement that a human or the watchdog switched off. The
watchdog's bounded auto re-arm (once per boot, watchdog-set latches
only, 15 clean cycles, counted in `config[2]`) makes a routine
five-minute upstream outage self-healing while a real fault still
latches for a human.

### Anti-spoofing gate

Automated enforcement must be unspoofable. The responder blocks only on
TCP alerts whose flow counters prove bidirectional exchange
(`pkts_toclient >= 1`, `pkts_toserver >= 2`;
`bin/nodeguard-responder:225`): TCP sequence numbers make completing or
continuing a handshake blind infeasible, so a blind attacker cannot
fabricate a flow this host answered and then continued. Spoofed single
UDP or ICMP packets, the trivial poisoning vector against any address
the operator depends on, can therefore never insert a block; they are
log-only, promotable per SID only by hand with a written justification
(`etc/sids.conf:4`). Residual exposure (severity-1 rules firing on a
bare SYN after our SYN-ACK) is bounded by severity curation, the rate
caps, and the protected-remotes allowlist.

### Coexistence with firewalld, docker, and tailscale

XDP runs before netfilter, and nodeguard adds zero nftables chains,
rules, or marks. `firewall-cmd --reload`, zone edits, and docker's
boot-time firewall reconcile cannot see, detach, or perturb the XDP
program or the pinned maps; the one unidirectional effect is that
firewalld's counters never see XDP-dropped packets. Docker bridges
carry no XDP. The tailnet is protected four ways: the live WireGuard
port hard pass refreshed every minute, the CGNAT range
(`100.64.0.0/10`) and the tailnet ULA in the allow maps, protected
DERP relays, and the anti-spoofing gate making spoofed severance of
the tunnel impossible. Suricata attaches no XDP program of its own, so
the dispatcher's one-member-per-priority model stays open for
break-glass tools.

### Monitoring chain

One direction, one file handoff: `nodeguard-watchdog` writes the
`nodeguard-status --kv` snapshot to `/run/zabbix/nodeguard.kv` every
minute (`bin/nodeguard-watchdog:16`); the Zabbix agent's UserParameter
reads that file (`etc/zabbix-userparameter-nodeguard.conf:7`); the
template (`templates/zabbix-nodeguard-template.json`) turns the keys
into items and triggers, including the `ng.feeds_*` items with their
per-feed staleness and config-drift triggers; dashboards sit on top
(three fleet-scaling dashboards are proposed in OpenSpec change
`add-nodeguard-telemetry`, generated from the planned `zbx/` suite).

The file handoff is forced by SELinux, not taste: `zabbix_agent_t`
cannot make `bpf()` syscalls, and `sudo` does not change the SELinux
domain, so the agent can never run `bpftool` or `ngmap.py` itself; the
watchdog runs the tools and the agent only reads the exported file
(`bin/nodeguard-watchdog:12`). One agent-side trap is recorded in the
conf itself: the agent substitutes `$1..$9` with item arguments inside
the command, so awk field references must be written `$$1`/`$$2`
(`etc/zabbix-userparameter-nodeguard.conf:5`); a single-dollar awk
program silently matches nothing. `ng.ts` carries the export epoch so
staleness of the whole chain is one `fuzzytime` check.

### Configuration

| File | Variable | Default | Meaning |
|---|---|---|---|
| `nodeguard.env` | `IFACE` | (required) | Attach NIC; physical, never a bridge or bond member |
| `nodeguard.env` | `CANARY_IP` / `CANARY_PORT` | / `443` | Over-block probe target; must never be allowlisted |
| `nodeguard.env` | `LIFELINES` | (required) | Space-separated probe names: `gw dns tailscale officegw` |
| `nodeguard.env` | `WAN_DYNAMIC_ALLOW` | `no` | `yes` on a DHCP WAN gateway (live gw/DHCP/own /32 allow entries) |
| `responder.conf` | `ENFORCE` | `no` | `no` logs WOULD BLOCK only; mandatory first-run mode |
| `responder.conf` | `HOME_NETS` | (required) | Networks whose inbound traffic qualifies alerts |
| `responder.conf` | `TTL` / `TTL_MAX` | `3600` / `86400` | Base block TTL; doubling cap for repeat offenders |
| `responder.conf` | `RATE_MIN` / `RATE_HOUR` | `30` / `500` | Responder rate caps |
| `feeds.conf` | `FEEDS_ENFORCE` | `no` | Master feeds gate; `no` fetches and diffs only, zero map writes (mandatory first-run mode) |
| `feeds.conf` | `FEEDS_APPLY` / `FEEDS_DRYRUN` | empty / all three feeds | Feeds allowed to enforce (jointly with `approved.json`, the double gate) vs fetched and diffed only |
| `feeds.conf` | `FEEDS_TTL_S` | `90000` | In-kernel TTL (25 h) written per feed entry; every failure decays to no enforcement |
| `feeds.conf` | `FEEDS_MAX_V4` / `FEEDS_MAX_V6` | `8192` / `2048` | Per-family entry caps across all surviving feeds |
| `feeds.conf` | `FEEDS_MAX_BYTES` | `4194304` | Fetched body size cap |
| `feeds.conf` | `FEEDS_V6_FLOOR` | `19` | Shortest accepted IPv6 prefix; shorter fails the whole feed (`bin/nodeguard-feeds:405`) |
| `feeds.conf` | `FEEDS_MAX_COVERAGE_V4` | `67108864` | Aggregate v4 address-coverage cap; exceeding it aborts the run |
| `feeds.conf` | `FEEDS_MAX_COVERAGE_V6_48` | `46137344` | Aggregate v6 coverage cap in /48 equivalents; exceeding it aborts the run |
| `feeds.conf` | `FEEDS_MAX_CHURN_PCT` | `30` | Composition churn brake; a larger swing is held for operator review |
| `feeds.conf` | `FEEDS_MAX_STALE_S` | `1209600` | Upstream snapshot staleness cap (14 days); a staler feed fails and its entries decay |
| `nodeguard.env` | `WD_ANOM_MODE` / `WD_ANOM_K` / `WD_ANOM_FLOOR` / `WD_ANOM_TRIP` / `WD_ANOM_ADAPT` | (proposed) | Anomaly-detector tunables proposed in `add-nodeguard-telemetry`; not yet implemented |
| build-time | `NG_TTL_LOW_FLOOR` | (proposed) `5` | TTL-outlier counting floor for the stats2 counters proposed in `add-nodeguard-telemetry`; not yet implemented |

`sids.conf` is reloaded live on mtime change
(`bin/nodeguard-responder:193`); the allow files and `protected.conf`
take effect at the next maps-service start.

### Observability and error handling

The eight per-CPU stats counters name every code path
(`src/nodeguard_kern.c:51`). `nodeguard-status` aggregates attach
state, kill switch and latch owner, port match, block counts, counters,
unit states, and Suricata's `capture.kernel_drops`; `--kv` feeds the
monitoring system. Scripts log through `ng_log` to the journal with
severity; the watchdog's CRITICALs carry evidence (the stats snapshot
on an over-block trip). Errors fail loud and open: attach failures,
spec drift, and canary refusals all exit nonzero rather than degrade
silently, and the monitoring attach-state item reads
`xdp-loader status`, never unit state, because the oneshot unit stays
green after a watchdog detach.

## 9. Architectural Decisions

One bullet per ADR; the rationale and evidence live in the ADRs under
[`docs/adr/`](adr/).

- [`docs/adr/0001-passive-ids-with-separate-xdp-blocklist.md`](adr/0001-passive-ids-with-separate-xdp-blocklist.md):
  run Suricata as a passive af-packet IDS and enforce with a separate
  custom XDP blocklist program; NFQUEUE inline, af-packet copy-mode
  IPS, and Suricata's own eBPF bypass were rejected. Consequence:
  detection and enforcement fail independently, and Suricata is blind
  to blocked sources.
- [`docs/adr/0002-require-bidirectional-tcp-evidence-for-blocks.md`](adr/0002-require-bidirectional-tcp-evidence-for-blocks.md):
  automated blocks require severity-1 TCP alerts with bidirectional
  flow evidence; UDP and ICMP are log-only. Consequence: blind
  spoofing cannot poison the blocklist, at the cost of never
  auto-blocking single-packet attacks.
- [`docs/adr/0003-fail-open-with-in-kernel-ttl-expiry.md`](adr/0003-fail-open-with-in-kernel-ttl-expiry.md):
  every component fails open, and block TTLs are enforced in-kernel by
  expiry comparison. Consequence: no dead userspace component can
  leave a block enforced, and blocks do not survive a reboot.
- [`docs/adr/0004-map-spec-generated-from-object.md`](adr/0004-map-spec-generated-from-object.md):
  the maps spec is generated from the compiled object, pinned-map
  drift refuses attach, all loading goes through the libxdp
  dispatcher, and unload is by program id. Consequence: a silently
  inert or wrongly-wired firewall is structurally impossible.
- [`docs/adr/0005-non-allowlisted-canary-for-overblock-detection.md`](adr/0005-non-allowlisted-canary-for-overblock-detection.md):
  the watchdog probes a deliberately non-allowlisted canary to detect
  over-blocking, with a hitless kill switch and bounded auto re-arm.
  Consequence: the failure class where the firewall works too well is
  observable and self-limiting.

## 10. Quality Requirements

- **Build-time verification**: the container build fails on any
  compiler warning (`-Wall -Werror`), on a verifier reject, or on a
  pin-reuse mismatch, because the netns rehearsal runs the exact
  production sequence: spec-driven pin creation, dispatcher attach
  against the pins, map-identity check, encoder round-trips
  (block/list/config/sweep), unload by id (`build/build.sh:66`).
- **Deploy-time verification**: `bash -n` on every script,
  `py_compile` on the Python, `systemd-analyze verify` on every unit,
  and a sha256 of the installed object (`deploy/deploy.sh`).
- **Runtime self-verification**: attach refuses on map-identity
  divergence; maps service refuses on spec drift or a canary-covering
  allow entry; the responder refuses to start with empty `HOME_NETS`
  (`bin/nodeguard-responder:61`).
- **Operational gates**: monitoring items exist before the first attach
  (phase 2 entry gate); alarm drills must fire before enforcement
  (phase 2 exit gate); the responder runs a mandatory dry-run of 48 to
  72 hours; functional drop tests use real routable traffic and prove
  the drop with `xdpdump`, the hits counter, and in-kernel expiry, on
  both hosts. Suricata memory caps are set from measured reload-peak
  RSS, not guessed.
- **Performance stance**: per-packet work is two array lookups plus at
  most two LPM lookups on the hot path, at the earliest hook the
  driver offers; Suricata's cost is capped by cgroup quotas and CPU
  pinning so detection can never starve forwarding.

## 11. Risks and Technical Debt

Open items to verify live, recorded rather than assumed (the phase 2
verifications closed the native-attach, hitless-reload, and
EVE-flow-fields risks that stood here; see Amendments):

- Suricata sizing on Atom-class CPUs is inference; the memory caps in
  `suricata-50-limits.conf` are provisional until phase 1 measures
  steady and reload-peak RSS (reload builds the new detect engine
  beside the old and peaks near twice steady state).
- `bpftool` map operations and the attach wrapper under enforcing
  SELinux from systemd units are rehearsed on the gateway first.
- Sweep walk cost at scale: Cloudflare measured about 573 dump
  operations per second on a 10k-entry LPM trie, with multi-second CPU
  lockups freeing large tries, so any per-minute trie walk is a
  structural risk as the block maps grow toward their 65536-entry
  ceiling. `add-nodeguard-telemetry` keeps the 1-minute collection path
  O(1) in blocklist population (counts ride the existing 10-minute
  sweep) and makes the walk's own duration a metric (`sweep_walk_ms`)
  so degradation is visible before it hurts.
- Baseline-trigger maturity: seasonal (`baselinedev`) triggers are
  meaningless until enough trend history exists, and they explode on
  near-zero baselines. The telemetry change imports them at Information
  severity with absolute floors, and promotes them only after 14 days
  of trend rows reviewed as quiet; an unreviewed training window is
  never blessed.

Known accepted limitations:

- Blocks do not survive a reboot (bpffs and `CLOCK_MONOTONIC` both
  reset); the journal is deliberately not re-armed.
- A blocked attacker is invisible to Suricata until the TTL expires;
  the TTL is the re-detection clock.
- The watchdog's over-block trip can false-positive on a canary-target
  outage; a false trip fails open and is loud, which is the acceptable
  direction.
- The responder trusts the et/open ruleset's severity ratings; a noisy
  severity-1 rule is contained by the rate caps and tuned via
  `sids.conf`, not prevented.
- No IPv6 extension-header walk in the WireGuard port pass
  (`src/nodeguard_kern.c:190`): a tunneled-over-exotic-v6 corner would
  fall through to the ordinary lookups, which fail open.
- `mkyaml.py` re-serializes the stock Suricata config and loses its
  comments; `build/suricata-stock.yaml` is kept beside it for drift
  comparison against future RPM updates.

## 12. Glossary

| Term | Meaning |
|---|---|
| XDP | eXpress Data Path; a BPF hook in the NIC driver, before the kernel network stack and netfilter |
| libxdp dispatcher | A meta-program multiplexing several XDP programs on one interface by priority |
| Native mode | XDP executed by the driver itself (vs generic/skb mode in the stack) |
| Pinned map | A BPF map given a filesystem name under `/sys/fs/bpf` so it outlives its creator |
| LPM trie | Longest-prefix-match map type; keys are CIDR prefixes |
| Kill switch | `config[1]`; nonzero makes the program pass everything, hitlessly |
| Lifeline | A watchdog probe over an allowlisted path; detects total datapath death |
| Canary | A watchdog probe to a deliberately non-allowlisted target; detects over-blocking |
| Latch | The soft-off state plus its marker file recording who set it |
| Responder | The daemon translating qualifying Suricata alerts into block-map entries |
| SID | Suricata signature id; the unit of per-rule policy in `sids.conf` |
| eve.json | Suricata's structured event log, the responder's sole input |
| HOME_NETS | The networks whose inbound traffic qualifies alerts for blocking |
| DERP | Tailscale's relay servers; their addresses are protected remotes |
| Tailnet | The WireGuard-based overlay network used for management access |
| et/open | The freely available Emerging Threats ruleset pulled by `suricata-update` |

## Amendments

- 2026-09-05, phase 2 verified live: native XDP attach succeeded on both
  hosts (`add-nodeguard-firewall` tasks 4.3 and 4.6); the
  `nodeguard-reload` member swap was proven to cause no carrier loss
  before the word hitless was used anywhere (task 4.4); and real alerts
  confirmed this Suricata build's EVE records carry
  `flow.pkts_toserver`/`pkts_toclient` as the anti-spoofing gate
  requires (task 3.3). The three corresponding section 11 risks are
  closed.
- 2026-09-04, post adversarial implementation review (28 findings resolved): the IPv4 WireGuard-port pass applies only at fragment offset zero; non-first fragments of a blocked source's WireGuard datagrams are dropped, accepted because WireGuard sets DF and the operator's own paths are covered by the allowlist. The kill switch verifies by read-back and the watchdog escalates to detach if the soft-off write fails. Attach state is three-valued; an xdp-loader failure is treated as "unknown, assume enforcing", never as detached. Allowlist reconciliation is performed with "systemctl reload nodeguard-maps" (ExecReload); a restart of that unit propagates through Requires= and blips the link. The per-host device drop-in uses Wants= plus After= for the NIC device unit. The deploy script owns /etc/logrotate.d/suricata (rename-based rotation; the responder drains and reopens across it) and refuses to run before the suricata RPM is installed. Responder TTL escalation counts block windows, not alert lines, and rate caps count attempts identically in dry-run and enforce modes.

## Roadmap

Adopted 2026-09-05 from docs/research/2026-09-05-xdp-dpi-antiddos-survey.md,
in order; each ships through its own explore, adversarial review, and
OpenSpec proposal cycle:

1. Threat-intel feed loader (nodeguard-feeds): reputable CIDR feeds into the
   block maps on a TTL that fails open by expiry. Implemented and deployed
   in dry-run on both hosts (OpenSpec change `add-nodeguard-feeds`);
   activation (the interactive `apply --confirm` promotions) pending.
2. Volumetric anomaly alerting: the watchdog diffs successive stats-map
   snapshots against a rolling baseline and alerts on spikes. Userspace
   only; no new drop path. Closes the distributed low-rate flood blind spot
   at the observability layer. Proposed in OpenSpec change
   `add-nodeguard-telemetry` (section 6 there: local EWMA plus Zabbix
   seasonal triggers).
3. Protocol-sanity counters in the XDP program: count implausible frames
   (impossible TCP flag combinations, TTL outliers) into new stats slots;
   every new branch still resolves to XDP_PASS. Telemetry, never
   enforcement. Proposed in OpenSpec change `add-nodeguard-telemetry`
   (the `stats2` map).

Deliberately deferred, evidence-gated: per-source rate limiting in the
datapath. It would be a second, independent drop condition; it is not built
until the volumetric alerting above shows a real flood problem on either
host. Rejected with reasons in the survey: XDPeek (dispatcher-incompatible,
redundant), nDPI (no gap versus Suricata here), XDP synproxy and
connection-limit tracking (no stateful listener to defend), XDP-level
sampling (redundant with the af-packet capture path).
