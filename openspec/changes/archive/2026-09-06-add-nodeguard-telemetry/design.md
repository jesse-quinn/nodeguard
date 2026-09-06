# NodeGuard observability, telemetry, and security-visibility layer

Revised design, 2026-09-05. Public repo /Users/Mac/Desktop/Workspace/sre/github/nodeguard; private overlay /Users/Mac/Desktop/Workspace/sre/infrastructure/nodeguard-local. All work ships as one OpenSpec change, openspec/changes/add-nodeguard-telemetry/.

Governing invariants:
- Every new kernel branch resolves to XDP_PASS (ADR 0003). Telemetry is count-only; no new drop path.
- Map changes are additive: a new map, never a resize of an existing pinned map (ADR 0004 preference). Growing the stats PERCPU_ARRAY is a resize and is rejected.
- The 1-minute collection path is O(1) in blocklist population. The only O(n) trie work rides the 10-minute sweep that already walks the maps.
- Every metric fails toward visible-unknown (item unsupported, explicit fail flag), never toward silent zero.
- Monitoring lands before anything influences behavior; dry-run then confirm then apply for every mutating step.
- Kernel artifacts and userspace artifacts deploy separately; the datapath object never ships as a stowaway of a userspace phase.

What was cut, and why (unchanged from the synthesis): stats-array resize (WAN blip); LRU_HASH top-N and ringbuf event stream (block_val.hits already gives exact counts; a ringbuf needs a consumer daemon for a sample); kernel.bpf_stats_enabled in any form (fleet-wide per-invocation tax; bpftool prog profile exists); the --allow-unused-pins escape hatch (superseded by the generalized identity check); the watchdog anomaly latch/hold machinery (cumulative counter instead); hand-maintained template JSON (generated, with uuid carry-over, see section 7); top-hosts widget and per-source LLD (two-gateway fleet gives host-ranking nothing); per-source rate limiting (stays deferred, per the roadmap); a dedicated ADR for the SELinux kv path (one forced constraint; becomes a design.md crosscutting paragraph).

## 1. Kernel: one new map, stats2, and protocol-sanity counters

New BPF_MAP_TYPE_PERCPU_ARRAY "stats2", max_entries 16, declared with LIBBPF_PIN_BY_NAME like the existing maps, pinned at /sys/fs/bpf/nodeguard/stats2. Seven live slots plus reserved headroom so the next counters are a program-only change: ST2_TCP_SYNFIN, ST2_TCP_SYNRST, ST2_TCP_NULL, ST2_TCP_XMAS, ST2_TTL_LOW, ST2_FRAG_V4, ST2_FRAG_V6; ST2_MAX=16. A count2() helper mirrors count().

Counting placement (revised). Sanity counting runs inside handle_v4/handle_v6 immediately after IP header validation and BEFORE the kill-switch gate, the WG-port short-circuit, and the allow/block lookups. To make that true, the kill-switch check moves from main() (currently src/nodeguard_kern.c:275-280) into handle_v4/v6, directly after the sanity block and before any verdict lookup; it still resolves to XDP_PASS. Consequences, stated honestly:
- Counters keep advancing while the kill switch is latched, which is exactly when an operator most needs scan visibility. The alternative (leave the check in main and document the blind spot) was rejected because the latch window is the highest-value window for these counters.
- Cost during a latch: a full header parse per packet instead of one array lookup. Count-only, bounded, acceptable; recorded in ADR 0007.
- WG-port UDP packets are now TTL/frag-counted too (they pass through the sanity block before their short-circuit). The design claim becomes: "sanity anomalies are counted on every packet that passes IP header validation, in every enforcement state."

Parse rules: TCP flags are examined only when protocol/nexthdr == IPPROTO_TCP and, for v4, fragment offset == 0; ihl honored exactly as the existing UDP parse does; v6 reads only a directly-following TCP header (same documented limitation as today). A bounds failure on the TCP header is not counted as parsefail (the IP header was fine) and falls through. At most one flag counter per packet, tested in order SYN+FIN, SYN+RST, NULL, XMAS. TTL: ttl/hop_limit < NG_TTL_LOW_FLOOR, a build-time #define defaulting to 5, with a comment stating that no shipped IDS publishes a numeric threshold (nearest precedent is p0f's 64/128/255 bucket model); explicitly a tunable design choice, revisited from soak data. Fragments: v4 frag_off nonzero; v6 nexthdr == 44; no overlap detection (needs reassembly state; Suricata's frag_overlap SIDs own that layer). Complementary to Suricata by construction: Suricata catches SYN+FIN only at the stream engine (SID 2210060), has no stateless flag-combo or TTL decode events, and its capture can drop packets the XDP program still sees.

Known observability artifact, documented in design.md and ADR 0007: during nodeguard-reload's dual-attach window both programs increment the same pinned per-cpu stats, so ST_PASS double-counts for the seconds the window lasts (drops do not double; the first XDP_DROP ends the chain). Anomaly shadow-trip review must cross-check trip timestamps against reload journal lines before tuning thresholds (section 6).

Verifier safety comes from reusing the exact bounds-check patterns already in the program; the fedora:44 container build and the extended netns rehearsal (section 2) gate it before any gateway sees it.

## 2. Build pipeline: the spec follows the object, never a hardcoded list

build/build.sh today hardcodes the six map names three times: stray-pin cleanup (build.sh:30), spec generation (build.sh:47), and the rehearsal identity loop (build.sh:84). Left alone, the generated spec would silently omit stats2, create-maps would never manage it, every gate would go green, and stats2 would live permanently outside the ADR 0004 contract. Changes:

1. After the throwaway load under $SPEC_PIN, derive the map list from what libbpf actually pinned: `MAPS=$(ls "$SPEC_PIN")`. Write one spec row per pin found.
2. Assertions that fail the build: the derived set contains the core six (allow4 allow6 block4 block6 config stats); the derived set equals the object's BTF-declared map set (`bpftool btf dump file "$OUT/nodeguard_kern.o"` parsed for map names). "Spec rows == object maps" becomes a checked invariant, not a comment.
3. The stray-pin cleanup and the rehearsal identity loop iterate the same derived list.

Rehearsal additions, all mandatory:
- Crafted-packet sanity assertions: python3 raw sockets in the netns send NULL, XMAS, SYN+FIN, SYN+RST, low-TTL, and fragmented probes; assert each stats2 counter increments and the verdict stays XDP_PASS (service continuity on a listening socket).
- Stats-read-failure drill: temporarily break the bpftool/ngmap path and assert the kv output emits no counter lines and ng.stats_read_fail=1 (section 5a), never zeros.
- Rollback rehearsal: reload new-to-old with the stats2 pin present, proving the reverse direction is hitless and the unreferenced pin is ignored.

## 3. Deploy phasing: --with-kernel, and honest pin-creation semantics

deploy.sh today unconditionally requires and installs build/out/nodeguard_kern.o and nodeguard-maps.spec (deploy.sh:24-25, 31, 58). That makes any userspace deploy a kernel stowaway: after phase 1, a reboot, an operator restart, or the watchdog's own soft-off/recovery path (systemctl stop in soft_off_or_detach, then the logged `systemctl start nodeguard-xdp`) would activate the untested stats2 object with none of the phase 3 gates. Fix:

- deploy.sh gains --with-kernel. Default runs neither require, stage, nor install nodeguard_kern.o or nodeguard-maps.spec; the running object and spec stay untouched on the host. With --with-kernel, both are required and installed as today.
- Phases 1 and 2 deploy without the flag. Any nodeguard-xdp restart during that multi-day window reloads the OLD object: safe by construction.
- Phase 3 deploys with --with-kernel, and the runbook treats deploy, create-maps, and nodeguard-reload as one sitting: between kernel install and reload, a nodeguard-xdp restart would activate the new object without the phase 3 gates. That window is minutes by procedure and stated as such in the runbook and tasks.md.

Pin-creation semantics, stated honestly: the object declares LIBBPF_PIN_BY_NAME on every map, and both attach and reload go through xdp-loader against $NG_PIN, so a load before create-maps does not fail; libbpf silently creates and pins stats2 with the object's own parameters. Functionally identical to what create-maps would create, but it bypasses the spec contract's CREATED/VERIFIED logging and drift refusal. The design therefore does NOT claim a refusal that cannot happen. Instead the enforcement point is added where it can exist:

- nodeguard-reload and nodeguard-attach gain a pre-load guard: read the installed $NG_SPEC, and refuse to invoke xdp-loader if any spec-listed map has no pin under $NG_PIN, with an error naming the exact recovery command (`systemctl reload nodeguard-maps`). Because the spec ships with the object in the same --with-kernel deploy, "spec-listed but unpinned" precisely captures "create-maps has not run for this object version." Rollback is unaffected: reloading the N-1 object under the new spec finds all pins present.

## 4. Reload/attach identity check generalized (ships in phase 1, before the kernel change)

bin/nodeguard-reload:50 and bin/nodeguard-lib.sh's ng_verify_map_identity iterate a hardcoded six-map list. Replace both with the same derivation: enumerate the incoming program's map_ids via `bpftool prog show -j`, resolve names via `bpftool map show -j`, require every referenced name that matches a pin under $NG_PIN to carry the pinned id, and additionally assert the core six names are all present in the program's set. Combined with the section 3 pre-load spec guard, both directions are safe: forward reload (new program references stats2, pinned first by create-maps) and rollback reload (old program does not reference stats2; the pin is ignored) are hitless, and both are rehearsed in netns in both directions. No escape hatch exists or is needed.

## 5. Userspace collection

All kv changes land in bin/nodeguard-status --kv, following the existing fragment pattern. The failure discipline is uniform: a value that cannot be read is OMITTED (its dependent item goes unsupported, one visible signal), plus an explicit fail flag where the failure is a local tool breaking rather than a subsystem being absent.

(a) Close the 5-of-8 gap and fix the silent-zero fallback. Export all eight stats slots (adding pass_expired, pass_nonip, pass_parsefail). The current fallback (nodeguard-status:65-73: parse failure yields d={} and prints ng.pass=0 etc.) is replaced: if the stats pin exists and the dump or parse fails, emit NO counter lines at all and emit ng.stats_read_fail=1; on success emit the counters and ng.stats_read_fail=0. A Warning trigger fires on stats_read_fail=1 and on the counters' unsupported state. The netns drill in section 2 proves this path.

(b) stats2 export: new `ngmap.py stats2 --json` subcommand; STATS2_NAMES in lockstep with the enum. Pin absent (rollout window): emit nothing; the stats2 items stay unsupported, which is the honest state. Pin present but read fails: same discipline as (a), via ng.stats2_read_fail.

(c) Config map: ng.rearm_count from slot 2; the once-per-boot re-arm becomes a metric instead of only a journal line.

(d) Kill the per-minute trie walk, with a single writer for the cache. The live `ngmap.py list --json` count currently runs unconditionally at nodeguard-status:31, above the kv branch; moving only the echo would leave the walk on the minute path. The spec therefore states: the live count computation itself moves inside the human-output branch (the operator-invoked 2am path keeps a live count), and the kv path sources counts exclusively from the cache file. Verified by grep: `list --json` must be unreachable from the kv code path.

The cache, /var/lib/nodeguard/mapstat.kv, has exactly ONE writer: the sweep. ngmap.py cmd_sweep, which already dumps block4/block6 every 10 minutes for TTL expiry, additionally accumulates in the same pass: live entry counts per family, per-entry hits, and its own walk duration, and writes atomically (tmp+rename): ng.blocks, blocks_v4, blocks_v6, util_v4_pct, util_v6_pct (denominators read from the installed spec, not hardcoded), top1_hits, top_blocked (bounded top-5 text), sweep_walk_ms, sweep_ts. It also persists the walk's per-entry hits snapshot to /var/lib/nodeguard/sweep_hits.json so top_blocked is ranked by hits DELTA since the previous walk (answering "who is hitting us now"), with the cumulative figure carried as a secondary field and the legend labeling both.

nodeguard-feeds does NOT write mapstat.kv (it knows only feeds-owned entries; block4/6 have three writers, which is the whole point of its journal-plus-CAS design, and publishing feeds-only totals would fake a mass-unblock four times a day). If post-apply freshness matters, feeds triggers an immediate one-off sweep (`systemctl start nodeguard-sweep.service`): the apply already paid the map-write cost, and one extra walk per 6h is within the Cloudflare-derived budget. Feeds-scoped counts stay in the existing ng.feeds_entries.

Reboot correctness: pins do not survive a reboot, but /var/lib/nodeguard does. nodeguard-maps truncates mapstat.kv (and sweep_hits.json) whenever it creates any map, so post-reboot the kv chain reports the count fields as unsupported (keys omitted) instead of confidently serving pre-reboot totals against freshly emptied maps; nodeguard-sweep.timer's OnBootSec drops from 10min to 2min to shorten the honest-unknown window. nodeguard-status emits ng.sweep_age = now - sweep_ts when the file is valid; file missing or empty means all mapstat keys are omitted.

Rationale: Cloudflare's production evidence (about 573 dump ops/s at 10k LPM entries; multi-second CPU lockups freeing large tries) makes any per-minute trie walk a structural risk; the minute path must be O(1) in map population. sweep_walk_ms makes the walk's own degradation observable before it hurts.

(e) Dispatcher health: reload and attach write the installed prog id to /run/nodeguard/expected_prog_id; nodeguard-detach removes the file. status emits ng.prog_match (live head id vs expected) and ng.attach_mode (native/skb/none from xdp-loader status). Defined edge: attached but expected_prog_id absent (tmpfs cleared, attach predating the tooling) emits NOTHING for prog_match; the item goes unsupported, which is visible, instead of a silent 1 or a false-paging 0. This case is covered in the netns rehearsal and the OpenSpec scenarios.

(f) Watchdog internals: ng.wd_canary_fail, wd_lifeline_fail, wd_toolfail, wd_clean read from the existing /run/nodeguard/wd_* files; distance-to-trip is visible before a soft-off. The one-cycle lag (kv written at cycle start reflects the previous cycle) is documented, and triggers use >= comparisons so the lag cannot mask a trip.

(g) Security-event fields: nodeguard-responder writes /run/nodeguard/responder.kv (same fragment pattern): ng.resp_alerts_seen, resp_blocks_issued, resp_dryrun_would_block, resp_last_alert_ts, resp_last_action_ts. ng.suricata_alerts comes from the detect.alert counter in the SAME suricatasc dump-counters call already made for kernel_drops (one parse, no second socket call), and the suricatasc invocation is wrapped in `timeout 5`. The existing `${kdrops:-0}` coercion (nodeguard-status:93) is removed: on any suricatasc timeout, socket error, or parse failure, the ng.kernel_drops and ng.suricata_alerts lines are OMITTED entirely, so their dependent items go unsupported (a wedged capture no longer reads as zero drops, and recovery cannot produce a false CHANGE_PER_SECOND spike off a stored 0). The template alerts on the unsupported state of kernel_drops, which catches the live-unit-dead-socket case that ng.suricata=active cannot. Section 12 describes this failure as "keys omitted, items unsupported", not "nodata": under the master/dependent model a dependent item cannot go nodata while the master keeps polling a stale-but-valid file; the unsupported state from a failed regex extraction is the correct and achievable signal.

Net cost at 1-minute cadence: the same process forks as today, minus the trie walk, plus file cats and two O(16) array-map reads: strictly cheaper than the status quo. Total kv surface grows from 38 to roughly 65 keys. The kv write stays tmp+rename.

## 6. Volumetric anomaly alerting: two deliberately redundant layers

Layer 1, gateway-local (satisfies the roadmap item literally and survives a Zabbix outage; Zabbix lives on a VPS, and the moment this matters most is when the gateway is under attack). In bin/nodeguard-watchdog after the kv export, per-cycle deltas of drop_total, sanity_total (sum of the four TCP combo counters), and suricata_alerts feed an EWMA mean and EWMA absolute deviation (alpha 0.05), state in /var/lib/nodeguard/wd_baseline.json. A cycle is anomalous when delta > max(WD_ANOM_FLOOR, m + WD_ANOM_K * d); WD_ANOM_TRIP consecutive anomalous cycles (default 3) increments ng.anomaly_count and sets ng.anomaly_last_ts, with a CRITICAL journal line recording metric, delta, threshold.

Robustness rules, all specified, none left to implementation accident:
- Regime awareness: on any between-cycle change of kill-switch state, attach state, or feeds-enforce state, the cycle is discarded and the EWMA state reseeded, exactly like the existing negative-delta rule. This kills the false-positive scenario where a multi-hour latch decays the baseline toward zero and the dawn auto re-arm fires a High "anomaly" caused by recovery. The watchdog already reads ks and attach state in the same script; feeds_enforce comes from feeds.kv.
- Update policy under attack: a cycle at or above threshold does NOT update mean or deviation, so the detector cannot be trained into silence by the event it is measuring. A bounded skip streak (WD_ANOM_ADAPT, default 30 consecutive skipped cycles) forces adaptation afterward so a legitimate level shift is not alarmed forever. Documented consequence: a sustained attack produces one trip and then, after roughly 30 minutes, absorbs into the baseline; the cumulative anomaly_count plus the Zabbix static ceilings (below) carry the ongoing-event signal from there.
- Reload artifact: a cycle spanning a nodeguard-reload (detected by prog_id change since the previous cycle) is discarded, so the dual-attach pass double-count cannot register as a shadow trip.
- Hard boundary: never touches the kill switch, latch files, or any map; per-source rate limiting stays deferred.

Tunables in nodeguard.env: WD_ANOM_MODE=off|shadow|on (ships shadow; shadow logs and exports ng.anomaly_shadow_count while anomaly_count stays 0), WD_ANOM_K default 8, WD_ANOM_FLOOR default 500 per cycle, WD_ANOM_TRIP default 3, WD_ANOM_ADAPT default 30.

Layer 2, Zabbix seasonal (catches slow drifts and diurnal anomalies, costs the gateway nothing):
- baselinedev() triggers on the rate items, always as a conjunction with an absolute floor because baselinedev explodes on near-zero baselines: baselinedev(drop_v4 rate, 1h:now/h, "d", 10) > 3 and last(rate) > 10; same shape for drop_v6, suricata_alerts (floor 1/s), block-hit pressure.
- Static absolute-ceiling triggers on drop_v4/v6 rate and suricata_alerts rate, values tuned from phase 5 shadow data. These exist because a slow ramp can stay under the baseline threshold each hour while permanently raising the seasons; a hard ceiling is the backstop the baseline family cannot provide. The sanity counters get generous static rate floors first; baseline variants only after a demonstrated quiet baseline.
- Capacity: timeleft(util_v4_pct, 7d, 90) < 24h with the <> -1 guard, plus a static > 85 warning; same pair for v6.
- Rate items get 90d trend storage. Baseline triggers import at Information severity and are promoted only after (i) trend rows cover at least 14 days, verified via trend.get, AND (ii) that 14-day window has been reviewed as quiet against ng.anomaly_shadow_count and the journal. Promotion never blesses an unreviewed training window.

## 7. Zabbix template: master plus dependent, generated with uuid and name carry-over

Agent side: a new UserParameter nodeguard.kv.raw (cat /run/zabbix/nodeguard.kv) joins the existing nodeguard.kv[*] passthrough (kept for zabbix_get spot checks and migration parity). Deployment owner, previously nonexistent: deploy.sh gains the agent conf as a staged/installed file (etc/zabbix-userparameter-nodeguard.conf into /etc/zabbix_agentd.d/, installed as nodeguard.conf; this fleet's agent config is /etc/zabbix_agentd.conf, whose Include=/etc/zabbix_agentd.d/*.conf line the deploy ensures, since Fedora's zabbix packaging ships no include dir and the packaged /etc/zabbix/zabbix_agentd.d/ path named previously does not exist here), matching its install-but-start-nothing philosophy; the zabbix-agent restart is a named pre-phase-2 runbook step, verified with `zabbix_get -k nodeguard.kv.raw` from the Zabbix server against BOTH hosts before the template import. Ordering is explicit in tasks.md: agent conf first, template second.

Master item: type Zabbix agent, key nodeguard.kv.raw, TEXT, delay 1m, history 1d (short retention aids torn-parse debugging), trends none. Every existing item KEEPS its key and flips to Dependent on the master. Preprocessing regex, specified exactly: `(?m)^ng\.<field>=(.+)$` -> \1. The inline multiline modifier is mandatory: Zabbix preprocessing is PCRE without a separate flags field, and without (?m) only the first kv line (ng.ts) would parse while roughly 60 dependents go unsupported. check_template.py runs every generated regex against a captured real nodeguard.kv file and asserts each templated field extracts a value.

Generator and migration safety:
- zbx/gen-template.py (stdlib) renders templates/zabbix-nodeguard-template.json deterministically. uuid policy: it seeds an object-key-to-uuid map from the COMMITTED v1 JSON and carries every existing object's uuid over verbatim; uuid.uuid5(NODEGUARD_NS, object_key) is minted only for genuinely new objects. This removes the delete-and-recreate risk (itemid churn, irreversible history loss) that regenerating all uuids would invite.
- Display names of existing items are reproduced byte-for-byte and asserted by check_template.py against the committed v1 JSON, because the live dashboard's svggraph datasets reference items by NAME pattern (zabbix-nodeguard-dashboard.py:92-102); a rename would silently empty every graph on the only existing dashboard for the whole phase 2 to 4 window.
- Pre-phase-2 rehearsal, a hard gate in tasks.md: import v1 then v2 into a scratch template on the Zabbix server; confirm itemids are preserved across the upgrade and at least one dependent item parses a pasted kv blob; only then touch the live template. Zabbix's exact same-key/different-uuid import behavior is treated as unverified until this rehearsal proves it.
- check_template.py also cross-checks template keys against the documented kv key list and runs in build/build.sh, so drift fails the build, not the 2am operator.

New items (all dependent): the three missing stats slots; stats_read_fail and stats2_read_fail; the seven stats2 counters; suricata_alerts; resp_* (5); each with a CHANGE_PER_SECOND rate twin where graphed; kernel_drops gains a rate twin (fixing the raw-cumulative plot); blocks_v4/v6, util_v4/v6_pct, sweep_age, sweep_walk_ms, top1_hits, top_blocked (text), rearm_count, prog_match, attach_mode, wd_* (4), anomaly_count, anomaly_shadow_count, anomaly_last_ts.

New triggers: change(anomaly_count)>0 [High]; prog_match=0 for 3m [High]; attach_mode<>native while attached [Warning]; change(rearm_count)>0 [Warning]; wd_canary_fail>=2 or wd_lifeline_fail>=2 [Warning, fires before the trip]; stats_read_fail=1 or counters unsupported [Warning]; kernel_drops unsupported [Warning: live unit, dead socket]; util static + timeleft pairs [Warning]; sweep_age>1800 [Warning] AND a belt-and-braces trigger on ng.sweep_timer (already exported, previously untemplated) not active; fuzzytime(ts,300)=0 [High, complements the existing nodata]; responder divergence (resp_dryrun_would_block rising while resp_blocks_issued flat in dry-run) [Info]; feeds never-ran: feeds_last_run_ts=0 sustained 24h [Warning], deliberately NOT gated by the existing `last(...)>0` guards so a wiped /var/lib/nodeguard or a disabled feeds timer cannot read healthy forever; the baseline and ceiling set per section 6.

Feeds visibility changes in the writers: per-feed snapshot_age is emitted only AFTER a feed's first success, so pre-first-run the per-feed items are undiscovered or unsupported (visible no-data) instead of green-zero; "feeds state wiped" joins the section 12 failure table with its expected alarm.

LLD, only for the genuinely variable dimension: one discovery rule (dependent on the master) extracts feed names from feeds_last_success_ts_* keys into {#FEED} macros, delay 1h, keep-lost-resources 30d. Prototype keys are DISTINCT from the static keys, e.g. nodeguard.feed.success_ts[{#FEED}] and nodeguard.feed.age[{#FEED}] (dependent items on the master with per-feed regex): reusing the static keys would collide on every discovery run and make parity permanently unmeetable. Accepted and stated consequences: per-feed history restarts under the new keys; during the parity window both item sets exist and the prototype stale/failed-open/upstream-frozen triggers import at Information severity to avoid duplicate paging; parity is defined as value-equality between paired items over 24h; then the static per-feed items and their triggers are removed as an explicit, recorded tasks.md step (history loss noted). Every prototype stale/frozen trigger is paired with a nodata() guard so a feed removed from feeds.conf stops alerting once discovery drops it, rather than firing on a frozen last() value for the whole 30d keep-lost window.

## 8. Dashboards: three, each answering one 2am question, both hosts on every panel

- NodeGuard Overview: is the firewall attached, enforcing, healthy right now. Tiles per host: attach_state, killswitch (latch secondary), prog_match, blocks, responder, anomaly_count. Graphs: drop rate v4 AND v6, pass rate, blocks over time, kernel_drops as RATE, allowlist and wgport pass rates. Pie per host: pass-path share (pass, allowlist, wgport, expired, nonip, parsefail). Legend URL widget kept.
- NodeGuard Security (new): are we being scanned or attacked, and is or would the pipeline be responding. Stacked graph of the four TCP sanity rates; graph of ttl_low + frag_v4 + frag_v6; the correlation graph: suricata_alerts rate vs resp_dryrun_would_block/resp_blocks_issued vs drop_total rate on one time axis (the whole alert-to-block story including dry-run divergence); tiles: top_blocked (labeled "since last sweep walk", with cumulative as secondary), top1_hits, resp_last_alert_ts and resp_last_action_ts age-formatted, wd_canary_fail.
- NodeGuard Capacity and Pipeline (new): will anything fill up or go stale before morning. Gauges: util_v4_pct, util_v6_pct per host (thresholds 70/85); Honeycomb of per-feed snapshot age via the LLD item pattern (green under 26h, amber, red); graphs: feeds_entries, candidates vs rejected vs failed, sweep_walk_ms; tiles: feeds_enforce, feeds_churn_held, feeds_journal_reset, feeds_map_errors, rearm_count, wd_lifeline_fail, sweep_age.

docs/legend.html is rewritten with three anchored sections, one line per panel stating what normal looks like; each dashboard's URL widget points at its anchor.

Naming and parity, pinned: the existing live dashboard is named "Nodeguard" and the old private script delete-and-creates it by that exact name. Phase 4 procedure: dashboards.py first exports the existing "Nodeguard" dashboard JSON to output/ (the same rollback pattern as the phase 2 template export), then creates "NodeGuard Overview" as a NEW dashboard (never updating "Nodeguard" in place, which would destroy the parity baseline), runs the side-by-side parity check against the still-live "Nodeguard", and only then deletes "Nodeguard" and the old private script in the same step.

## 9. Generator layout: public parameterized, private wrapper

New public directory zbx/: lib.py (urllib JSON-RPC client, itemid resolution, widget builders for graph/itemvalue/gauge/honeycomb/pie/url, Okabe-Ito palette and 72-column grid ported from the private script); dashboards.py building all three dashboards; gen-template.py and check_template.py per section 7. CLI: --url; --host name[:label], repeatable, no default, label defaulting to the full host name (the private script's hostname-prefix title derivation is NOT ported; committing that prefix would leak the fleet naming scheme the split exists to protect); --legend-url (defaults to the GitHub Pages constant, a public asset); --dashboard overview|security|capacity|all; token from env ZTOKEN only, never argv, never printed. House flow: the default run prints the full plan (dashboards, widgets, resolved and unresolved item keys) and exits; --confirm applies; idempotent via dashboard.get by name then update-or-create (except the phase 4 create-new-then-delete-old sequence above); unresolvable keys skip the widget loudly, never silently. tasks.md carries an explicit review item: no real host name, prefix, or URL appears anywhere in zbx/.

Widget field names for honeycomb/gauge were researched through a summarizing fetch: verify against the live 7.4 API with one plan-mode diff against a hand-exported dashboard before the first --confirm.

Private overlay: dashboards-apply.sh, a wrapper of at most 15 lines that sources the token into ZTOKEN and execs zbx/dashboards.py --url <real> --group "Nodeguard nodes" --host-pattern <real pattern> "$@" (per section 15; host enumeration resolved live from the group). The overlay's stale design.md/proposal.md drafts get a header marking them historical, superseded by the public docs (flagged to the operator, not silently rewritten).

## 10. Cross-change sequencing with add-nodeguard-feeds activation

The feeds change's own activation (operator `apply --confirm` on the real hosts, its tasks.md section 3) is pending and will otherwise interleave with this rollout. Rules, recorded in both changes' tasks.md:
- Feeds enforcement activation either completes before phase 5 begins, or is deferred until after phase 6's gate. Never inside the shadow-tuning window or the baselinedev season-building window: the first enforcing apply inserts on the order of a thousand block entries and shifts the drop-rate regime, which would either mistune WD_ANOM_K/FLOOR or fire the High anomaly trigger for a planned change.
- A feeds enforcement flip resets the EWMA state file (the section 6 regime rule does this automatically via feeds_enforce) and restarts the 14-day baseline maturity clock.
- Phase 1 modifies bin/nodeguard-feeds (post-apply sweep trigger), so the activation rehearsal that was validated runs against the phase 1 binary; noted in add-nodeguard-feeds tasks.md.
- The phase 1 gate "ng.blocks reconciles against one manual list --json count" is performed while feeds enforcement is off (its current state), so the reconciliation cannot race a feeds apply.

## 11. Documentation refresh (full task list; a section-by-section re-read of design.md against the tree, per AGENTS.md, not a diff patch)

docs/design.md:
1. Header: drop "before the first production deployment"; state the actual bring-up phase (phase 2 complete, dry-run soak and enforcement pending) with the metadata header updated.
2. Section 3 (Context and Scope): add external-interface rows for the three feed HTTPS sources (Spamhaus DROP v4/v6, DShield, 6h cadence) and the Zabbix server.
3. Section 5 (Building Block View): add nodeguard-feeds (914-line daemon), units/nodeguard-feeds.service/.timer, hosts/*/feeds.conf, and the new zbx/ directory; update the bin/ and etc/ file lists.
4. Section 6.3 (Watchdog cycle): document the kv export as the cycle's first step (the entire monitoring-chain entry point) and add the anomaly-detector step with its regime and update rules.
5. Section 8: new "Monitoring chain" crosscutting subsection (watchdog -> /run/zabbix/nodeguard.kv -> agent UserParameter kv.raw -> master/dependent template -> dashboards), recording in prose the SELinux constraint that zabbix_agent_t cannot call bpf(); configuration table gains the 11 feeds.conf variables, the WD_ANOM_* family, and NG_TTL_LOW_FLOOR; observability text describes stats2, the counting-before-killswitch placement, the sweep cache and its single-writer rule, the fail-to-unsupported discipline, the reload double-count artifact, and the full kv export.
6. Section 11 (Risks): remove the three risks tasks.md proves resolved (native attach 4.3, hitless reload 4.4, EVE flow fields 3.3, which the same document's Amendments section already contradicts); keep RSS measurement and SELinux-under-systemd; add sweep-walk-cost-at-scale with the Cloudflare citation and the sweep_walk_ms mitigation, and baseline-trigger maturity.
7. Roadmap: mark feeds implemented-activation-pending; point both telemetry items at add-nodeguard-telemetry; per-source rate limiting stays deferred.
8. Verification: every factual claim grep-verified against the tree in the same sitting.

docs/adr/:
9. 0006-load-threat-intel-through-the-journaled-cas-owner.md: NEW, accepted; rescues the feeds rationale before OpenSpec archive loses it (firehol_level1 rejected for live RFC1918/CGNAT ranges, feodo_c2 deferred for TTL mismatch, journal-plus-CAS ownership over dump-and-diff because block4/6 already have two other writers), evidence carried in. Must land before add-nodeguard-feeds archives.
10. 0007-add-counters-in-a-second-stats-map-and-keep-trie-walks-off-the-minute-path.md: NEW, proposed until the OpenSpec change is approved; records: new map never a stats resize (with the resize operational cost); no periodic trie walks on the minute path (Cloudflare numbers) and the sweep piggyback with its single-writer rule; the reload identity-check generalization and why it deliberately relaxes "uses all pinned maps" to "every referenced pin matches, core six present"; the LIBBPF_PIN_BY_NAME auto-pin reality and the spec-based pre-load guard that replaces the impossible refusal; the counting-before-killswitch placement and its latch-window rationale; the reload double-count artifact; the anomaly split (watchdog EWMA local with excluded-cycle updates, baselinedev seasonal with static ceilings) including why the roadmap wording evolved.

Other files:
11. CHANGELOG.md: back-fill the entire add-nodeguard-feeds entry (loader, units, feeds.conf, ngmap/status changes, template items); an entry for the monitoring chain and the hitless-reload verification; the entry for this change.
12. README.md: monitoring section names the three dashboards and zbx/.
13. docs/legend.html: full rewrite per section 8 (three anchored sections, one line per panel, top_blocked recency labeling).
14. etc/zabbix-userparameter-nodeguard.conf: add nodeguard.kv.raw; keep nodeguard.kv[*].
15. hosts/example-gateway/nodeguard.env: document WD_ANOM_MODE/K/FLOOR/TRIP/ADAPT with defaults and dates when retuned.
16. deploy/deploy.sh: --with-kernel flag; stage/install the zabbix agent conf and every other changed file following the feeds.conf wiring pattern; runbook note for the agent restart.
17. openspec/project.md: one-line component update naming nodeguard-feeds, zbx/, and stats2 so the project description is not stale.
18. Private overlay: historical-superseded headers on nodeguard-local's design.md/proposal.md (operator-flagged, not rewritten).
19. openspec/changes/add-nodeguard-telemetry/: proposal.md with Impact and out-of-scope (no enforcement changes, no per-source limiting, no ringbuf, no LRU map, no bpf_stats); design.md carrying this document's substance; specs with SHALL plus WHEN/THEN scenarios (including the prog_match-absent, stats-read-fail, feeds-never-ran, and reboot-cache cases); tasks.md in under-2h chunks that carries the audit's staleness list as an explicit checklist, names build/build.sh:30,47,84 alongside nodeguard-reload:50 and nodeguard-lib.sh:67 for the hardcoded-list fixes, and records the static-feed-item removal and cross-change sequencing steps. `openspec validate add-nodeguard-telemetry --strict` before ready. bash -n and shellcheck on every touched script.

## 12. Rollout (each phase independently shippable; the datapath is touched once, in phase 3; node-3 always first)

Phase 0, paperwork: OpenSpec change, ADR 0006 and 0007, the docs backfill that depends on no new code. Gate: strict validation passes; design.md claims spot-checked against the tree.

Phase 1, reload/attach generalization plus userspace kv expansion (everything in section 5; stats2 reads are pin-guarded and emit nothing). Deployed WITHOUT --with-kernel: the running object stays on disk and any restart reloads it. Build gate: bash -n, shellcheck, netns rehearsal green including the stats-read-failure drill. Deploy node-3. Gate: kv key list diffs clean against the spec'd list; the grep proof that `list --json` is unreachable from the kv path; sweep produces mapstat.kv and ng.blocks reconciles against one manual list --json count (feeds enforcement off, so no race); a deliberate bpftool break shows counters unsupported plus stats_read_fail=1, not zeros; 24h with wd_clean advancing and no new journal errors. Then node-2.

Pre-phase-2: deploy the updated agent conf (in the phase 1 deploy set), restart zabbix-agent on both hosts (named runbook step), verify `zabbix_get -k nodeguard.kv.raw` from the server on both; run the scratch-template import rehearsal (v1 then v2; itemids preserved; one dependent parse verified). Both are hard gates before any live import.

Phase 2, template v2: export the current live template to output/ as the rollback artifact, import the generated v2. Gate: every item fresh in Latest Data within 5 minutes on both hosts EXCEPT the enumerated stats2 items and their rate twins, which MUST be in state unsupported (listed by name in tasks.md) and are expected to flip to supported within one poll cycle after the phase 3 pin creation; ng.ts advancing across two consecutive samples and one XDP counter strictly monotonic on both hosts (freshness of dependents alone only proves the regexes work, not that the pipeline is live); a deliberate 3-minute watchdog-timer stop on node-3 confirming fuzzytime(ts,300) fires and recovers; the old "Nodeguard" dashboard's graphs render non-empty for both hosts (display-name contract held); agent log shows one kv.raw poll per minute; LLD discovers all three feeds under the new prototype keys; 24h value-parity between static and LLD per-feed items, then the static per-feed items removed as a recorded step; 48h without unexpected trigger flaps. Baseline triggers exist at Information severity only.

Phase 3, kernel stats2 (one sitting per host; minutes, not days): container build regenerates object and spec via the derived-map-list generator; netns rehearsal includes the crafted sanity packets AND the rollback rehearsal. Deploy with --with-kernel to node-3. Create the pin with the EXACT command `systemctl reload nodeguard-maps` (ExecReload runs create-maps against the installed spec) or `python3 $NG_MAP create-maps --spec $NG_SPEC`; NEVER `systemctl restart nodeguard-maps`, which propagates through Requires= to nodeguard-xdp and blips the WAN link. Gate before reload: `bpftool map show pinned $NG_PIN/stats2` succeeds AND the six existing pin ids are unchanged (bpftool map show -j diff). Then nodeguard-reload; its pre-load guard has already verified every spec-listed pin exists. Gates, all mandatory: zero carrier transitions (ip -s link counters plus ping continuity); the original stats counters monotonic across the swap (pins persisted; the brief ST_PASS inflation from dual-attach is expected and documented); a NULL-scan probe from a non-allowlisted, non-blocked host increments tcp_null while receiving service (fail-open observed live); ng.prog_match=1; the stats2 template items flip to supported. Soak 24h, then node-2.

Phase 4, dashboards: private wrapper runs the public generator, plan reviewed, then --confirm. Procedure per section 8: export "Nodeguard" JSON to output/, create "NodeGuard Overview" new, parity check side by side, then delete "Nodeguard" and the old private script in the same step. Gate: all widgets non-empty for both hosts; legend anchors resolve.

Phase 5, anomaly shadow: WD_ANOM_MODE=shadow fleet-wide at least 7 days, with feeds activation excluded from the window per section 10. Gate: shadow trip review cross-checked against reload journal lines; K and FLOOR retuned from real deltas and documented in nodeguard.env comments with the date; static ceiling values for the Zabbix layer chosen from the shadow data.

Phase 6, enable: WD_ANOM_MODE=on; baselinedev triggers promoted once 14 days of trend rows exist (trend.get) AND the window is reviewed as quiet against anomaly_shadow_count and the journal. Gate: one deliberate synthetic burst from an allowlisted admin host increments anomaly_count, fires the Zabbix trigger, and the EWMA recovers without operator action (the excluded-cycle rule means recovery is by the burst ending, not by absorption).

## 13. Failure modes

- Sweep stops: mapstat keys keep their last values but ng.sweep_age alarms at 1800s, and the sweep_timer trigger fires independently; no second writer can re-stamp the file (feeds only triggers a sweep, which either runs and is fresh or fails and leaves age growing). The "0 scanned looks like 0 found" trap is answered by age being first-class and single-sourced.
- Reboot: nodeguard-maps truncates the cache; counts are unsupported (visible unknown) until the first sweep at 2 minutes, never confident pre-reboot numbers against empty maps.
- Stats read fails with pin present: no counter lines, stats_read_fail=1, Warning; rehearsed in netns.
- Master item breaks: all dependents go unsupported at once, one clear signal, caught by fuzzytime(ts) and nodata, with the retained kv[*] passthrough for manual queries.
- suricatasc hangs or errors: timeout 5; kernel_drops and suricata_alerts keys omitted; items unsupported; trigger on the unsupported state catches live-unit-dead-socket.
- New object loaded before create-maps: the reload/attach pre-load guard refuses on a spec-listed-but-unpinned map and names the recovery command. An out-of-band xdp-loader invocation would auto-pin via LIBBPF_PIN_BY_NAME (harmless parameters, unmanaged provenance); documented, not denied.
- Verifier rejection: caught in the container build and netns; gateways have no compiler.
- Sweep walk degrades toward 65k entries: sweep_walk_ms trends on the Capacity dashboard; the minute path is already immune.
- Anomaly false positives: floor, consecutive-cycle trip, regime reseeds, reload-cycle discard, shadow tuning; the detector cannot cause harm regardless.
- Anomaly trained by attack: excluded-cycle EWMA updates bound absorption; static Zabbix ceilings backstop slow ramps; promotion requires a reviewed-quiet window.
- Renamed kv key: item unsupported plus check_template.py fails the next build; two independent nets.
- Feed set changes: LLD within 1h; a removed feed's prototype triggers go quiet via their nodata() guards while the items age out over the 30d keep-lost window.
- Feeds never ran or state wiped: feeds_last_run_ts=0 beyond 24h fires Warning; per-feed items show no data instead of green-zero.
- Insufficient trends: baseline triggers evaluate unknown at Information severity; no false paging.
- Zabbix down: the local detector still logs CRITICAL trips; nothing on the gateway depends on Zabbix.
- Counter reset on reboot: negative-delta reseed locally; CHANGE_PER_SECOND discards one sample server-side.
- Kill-switch latch: sanity and stats counters keep advancing (section 1 placement); the latch itself is visible via ng.killswitch/ng.latch.

## 14. Rollback (each layer independent)

Kernel: nodeguard-reload back to the N-1 object kept by deploy.sh; hitless in reverse via the generalized identity check, rehearsed in phase 3; the stats2 pin remains, unreferenced and harmless, preserving counters for re-roll-forward; removing it is an explicit operator action after detach only. Userspace: redeploy previous versions; vanished kv keys degrade to unsupported items, visible and harmless. Template: re-import the phase-2 export; keys AND uuids unchanged (carry-over policy), so items and history survive; new items disabled rather than deleted if return is expected. Dashboards: regenerable state; the exported "Nodeguard" JSON restores the old dashboard, or re-run the generator from a previous tag; the old private script exists until phase 4 completes. Anomaly detector: WD_ANOM_MODE=off; state file inert. Docs: git revert; ADRs never deleted; a reversed decision gets a superseding ADR.
## 15. Fleet scaling (operator requirement, added after synthesis)

Dashboards and monitoring MUST scale with the number of nodeguard hosts
with zero widget rework when a host is added. Binding rules, which
override any per-host enumeration above:

- A Zabbix host group (default name "Nodeguard nodes", configurable via
  --group) is the canonical fleet definition. Onboarding a host is:
  install nodeguard, link the template, add the host to the group.
- Every widget that supports group or pattern addressing uses it:
  honeycomb, top hosts, problems, and pie/svggraph datasets via host
  patterns. The host pattern is an argument (--host-pattern), supplied by
  the private wrapper, never committed; the public generator defaults to
  resolving the group's current members.
- Widgets that require per-host enumeration (item value tiles, gauges)
  are generated per group member resolved live at generator run time
  (host.get by group id), so adding a host costs one re-run of
  dashboards-apply.sh, not an edit. Where a honeycomb can replace a row
  of per-host tiles at fleet sizes above two, it does.
- The svggraph display-name contract in section 7 gains a corollary: item
  NAME patterns must be chosen so a new host's items match without
  change.
- The parity gate in section 8 includes a scale drill: run the generator
  plan with a synthetic third host in the group and verify the plan
  output covers it in every dashboard with no code edit. The synthetic
  host MUST carry a visible name different from its technical name, and
  the drill asserts the plan's dataset host patterns equal visible
  names: Zabbix resolves svggraph and pie dataset host patterns against
  the visible name, so a drill whose two names coincide cannot catch a
  generator that emits technical names.
