# 0007 - Add counters in a second stats map and keep trie walks off the minute path

## Status

proposed (OpenSpec change add-nodeguard-telemetry), 2026-09-05

## Context

The telemetry change adds protocol-sanity counters (TCP flag combinations,
low TTL, fragments) to the XDP program and widens the kv export, without
touching enforcement. Several implementation choices look wrong from the
outside and will be re-proposed unless the reasoning is recorded.

The existing stats map is a PERCPU_ARRAY of ST_MAX slots, pinned by name
(src/nodeguard_kern.c:110-116). Growing it to hold the new counters is a
resize of a pinned map, and the map spec contract (ADR 0004) treats a
parameter mismatch as drift: the pin must be recreated, which on these hosts
means a detach/reattach and a WAN blip on the gateway uplink.

On collection cost, bin/nodeguard-status runs `ngmap.py list --json`
unconditionally (bin/nodeguard-status:31), a full trie dump on the 1-minute
monitoring path. Cloudflare's production experience with LPM tries is the
evidence that this does not scale: about 573 dump operations per second at
10k entries, and multi-second CPU lockups freeing large tries. block4 allows
65,536 entries; a per-minute walk is a structural risk that grows with
exactly the population the feeds change adds.

The current stats export also fails toward silent zero: a dump or parse
failure yields an empty dict and prints ng.pass=0 and friends
(bin/nodeguard-status:65-73), so a broken reader is indistinguishable from a
quiet network.

Finally, the map list is hardcoded in five places: build/build.sh:30 (stray
pin cleanup), build/build.sh:47 (spec generation), build/build.sh:84
(rehearsal identity loop), bin/nodeguard-reload:50 and
bin/nodeguard-lib.sh:67 (the "new program uses all six pinned maps" identity
checks). Left alone, the generated spec would silently omit the new map,
create-maps would never manage it, and the reload identity check would fail
in one direction or the other: the old check requires the incoming program to
use all pinned maps, so either a rollback to the old object (which does not
reference the new map) or a forward reload (new map not yet in the list)
breaks.

## Decision

1. New counters go in a second map, stats2, a PERCPU_ARRAY of 16 slots with
   reserved headroom, pinned alongside the existing maps. Additive only; a
   resize of any existing pinned map is rejected because it forces pin
   recreation and a detach/reattach WAN blip. build/build.sh derives the map
   list from what libbpf actually pins instead of the three hardcoded lists,
   so the spec follows the object.
2. No periodic trie walks on the 1-minute path. Live counts and per-entry
   hits are accumulated by the sweep (bin/ngmap.py:274), which already walks
   block4/block6 every 10 minutes for TTL hygiene, and are published through
   a cache file, /var/lib/nodeguard/mapstat.kv, with exactly one writer: the
   sweep. nodeguard-feeds never writes it (it knows only feeds-owned entries
   and would fake a mass-unblock four times a day); if post-apply freshness
   matters it triggers one extra sweep. The kv path must be verifiably
   unable to reach `list --json`; the interactive human-output path keeps a
   live count.
3. The reload/attach identity check is generalized from "the incoming program
   uses all six pinned maps" (bin/nodeguard-reload:50,
   bin/nodeguard-lib.sh:67) to: every map the program references whose name
   matches a pin must carry the pinned id, and the core six names must all be
   present in the program's set. This makes both directions hitless: forward
   (new object references stats2, pinned first by create-maps) and rollback
   (old object does not reference stats2; the pin is ignored). The old rule
   would have required an escape hatch for every rollback.
4. A load-time refusal of an unpinned map cannot exist and is not claimed.
   The object declares LIBBPF_PIN_BY_NAME on every map, so a load before
   create-maps silently creates and pins stats2 with the object's own
   parameters, bypassing the spec contract's CREATED/VERIFIED logging.
   Instead, nodeguard-reload and nodeguard-attach gain a pre-load guard:
   read the installed spec and refuse to invoke the loader if any spec-listed
   map has no pin, naming the recovery command. Because the spec ships with
   the object, "spec-listed but unpinned" precisely captures "create-maps has
   not run for this object version".
5. The kill-switch check moves from main() (src/nodeguard_kern.c:275-280)
   into handle_v4/handle_v6, after the sanity-counting block and before any
   verdict lookup, still resolving to XDP_PASS. Sanity counters therefore
   keep advancing while the kill switch is latched, which is exactly when an
   operator most needs scan visibility. The cost, accepted deliberately: a
   full header parse per packet during a latch instead of one array lookup,
   count-only and bounded.
6. During nodeguard-reload's dual-attach window both programs increment the
   same pinned per-cpu stats, so ST_PASS double-counts for the seconds the
   window lasts (drops do not double; the first XDP_DROP ends the chain).
   This artifact is documented rather than engineered away, and anomaly
   review must cross-check trip timestamps against reload journal lines.
7. Volumetric anomaly detection is split into two deliberately redundant
   layers. Layer 1 is gateway-local in the watchdog: EWMA mean and absolute
   deviation over per-cycle deltas, with two robustness rules: a cycle at or
   above threshold does not update the baseline (the detector cannot be
   trained into silence by the event it measures, with a bounded skip streak
   forcing eventual adaptation), and any between-cycle change of kill-switch,
   attach, or feeds-enforce state discards the cycle and reseeds the state
   (recovery from a latch cannot fire a false anomaly). Layer 2 is Zabbix:
   baselinedev() triggers, always conjoined with an absolute floor because
   baselinedev explodes on near-zero baselines, plus static absolute
   ceilings as the backstop for slow ramps that re-train the seasons. Layer
   1 survives a Zabbix outage; Zabbix runs off-host and the moment this
   matters most is when the gateway is under attack. Per-source rate
   limiting stays deferred: it is an enforcement change, and this change is
   count-only under the governing invariant that every new kernel branch
   resolves to XDP_PASS (ADR 0003).

## Consequences

- The stats surface is split across two maps forever; consumers read both.
  The reserved stats2 headroom makes the next counters a program-only
  change, which is the point.
- The sweep cache means block counts are up to 10 minutes stale on the
  monitoring path, and after a reboot they are unknown (keys omitted, items
  unsupported) until the first sweep rather than confidently wrong; the
  sweep's own walk duration is exported so its degradation is visible before
  it hurts. The single-writer rule must hold: a second writer to mapstat.kv
  reintroduces the stale-or-fake-counts problem the split exists to avoid.
- The generalized identity check is weaker by design: a future program that
  silently stops referencing a non-core map will pass it. The build-side
  assertion that spec rows equal the object's BTF-declared map set is the
  compensating control.
- The pre-load spec guard adds a failure mode (spec present, pin missing,
  reload refused) whose recovery is one named command; an out-of-band loader
  invocation can still auto-pin an unmanaged map, which is documented, not
  denied.
- While the kill switch is latched, every packet pays a header parse. If a
  latch ever coincides with a volumetric attack, the gateway does strictly
  more per-packet work than today's latched path; count-only, no verdict
  work, accepted.
- ST_PASS is not trustworthy across a reload window and dashboards must not
  alert on its rate without the reload cross-check.
- A sustained attack produces one local anomaly trip and then, after the
  bounded skip streak, absorbs into the baseline; the cumulative trip count
  and the static Zabbix ceilings carry the ongoing-event signal from there.
  Baseline triggers must not be promoted on an unreviewed training window.

## Alternatives considered

- Resize the existing stats map: rejected; pin recreation forces a
  detach/reattach and a WAN blip for a counter addition.
- Keep the per-minute live trie count and accept the cost: rejected on the
  Cloudflare evidence; the walk cost grows with exactly the blocklist growth
  the feeds change ships.
- Keep the kill-switch check in main() and document the counter blind spot:
  rejected; the latch window is the highest-value window for these counters.
- An --allow-unused-pins escape hatch on the old identity check: superseded
  by the generalized check, which needs no hatch in either direction.
- LRU_HASH top-N map or a ringbuf event stream: rejected; block_val.hits
  already gives exact counts and a ringbuf needs a consumer daemon for what
  a 10-minute sample already answers.
- Per-source rate limiting in this change: deferred; enforcement, not
  telemetry, and the anomaly layers must prove their baselines first.
