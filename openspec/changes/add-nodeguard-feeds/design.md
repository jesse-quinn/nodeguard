# nodeguard-feeds: revised design (v2)

Timer-driven oneshot loader that pulls Spamhaus DROP v4/v6 (JSONL, direct from source) and DShield top-20 into the existing block4/block6 maps with a 25h monotonic TTL, refreshed every 6h. One new script, one config file, one approval file, one service/timer pair; python3 stdlib only; no new daemons, no map or kernel changes (ADR 0004: the pinned map set is fixed and block4/block6 already exist). This revision resolves every blocker and major from review, plus all minors; each resolution is stated inline at the point it lands and summarized in the change log at the end.

## 1. Feed selection

Source the component feeds directly. Never consume firehol_level1.netset: its fullbogons component contains, confirmed live, 100.64.0.0/10 (the tailnet's CGNAT space), all RFC1918, 0.0.0.0/8, 169.254.0.0/16, 224.0.0.0/3; roughly 2,400 of its 3,939 subnets are allocation-status entries, not attacker reputation, and the repo has no LICENSE file. ngmap's NEVER_BLOCK guards would refuse those lines; the bogon class is nonetheless excluded at source selection, with the in-repo guards retained as defense in depth. firehol_level2 is out of scope (short-window attack observations, different false-positive class; separate review if ever proposed).

| feed id | URL | format | size (verified 2026-09-05) | notes |
|---|---|---|---|---|
| spamhaus_drop_v4 | https://www.spamhaus.org/drop/drop_v4.json | JSONL records {cidr, sblid, rir} + one metadata trailer object | 1,709 records | Hijacked or criminal-leased netblocks; network-layer dropping is Spamhaus's stated use; excludes legitimately-allocated space by policy; EDROP merged in 2026-04-10 |
| spamhaus_drop_v6 | https://www.spamhaus.org/drop/drop_v6.json | JSONL, same shape | 92 records | Only v6 source; populates block6 |
| dshield_top20 | https://feeds.dshield.org/block.txt | '#' comment header; tab-delimited data lines: start_ip, end_ip, netmask, targets, name, country, contact | 20 lines | Top attacking /24s over 3 days. License is CC BY-NC-SA 2.5 (in-file header), NOT public domain; see open item 5 |
| feodo_c2 | deferred | | ~1 entry | DEFERRED: abuse.ch recommends 5 to 15 minute refresh because C2 IPs recycle; against a 25h TTL a dead job leaves a recycled IP blocked up to a day. Future FEEDS_DRYRUN candidate only, through the approval gate |

Spamhaus terms compliance: 6h cadence is far under their once-per-hour cap; conditional GET (If-None-Match/If-Modified-Since) makes unchanged pulls a 304; the verbatim upstream bytes are retained as the last-good snapshot, and the metadata trailer's copyright and timestamp fields are preserved with it, satisfying the attribution requirement ("the date and (c) text should remain with the file and data"); sblid is kept per entry in the journal for provenance (the role sid plays in the responder's blocks.json). The legacy drop.txt endpoints are deprecating; the JSON endpoints are the target.

## 2. Program shape

`bin/nodeguard-feeds`, python3 stdlib (urllib.request, json, ipaddress, fcntl, struct, os). It imports ngmap as a module via `sys.path.insert(0, "/usr/local/lib/nodeguard")`; that is where deploy.sh installs it (deploy/deploy.sh:58) and where the responder (bin/nodeguard-responder:38) and sweep unit (units/nodeguard-sweep.service:6) already reference it.

Reused via import: key_bytes(), NEVER_BLOCK, is_protected(), block_lock(), update_map(), delete_key(), map_path(), mono_ns(), and a NEW helper this change extracts in ngmap.py itself: `contains_protected(net, extra_nets)`, factored out of the inline loop in cmd_block (bin/ngmap.py:205-210) and called by both cmd_block and the loader, preserving the single-implementation invariant. Two further small ngmap.py adjustments, required because the current helpers are CLI-shaped: (a) update_map()/delete_key() raise RuntimeError on bpftool failure instead of calling die(), with the CLI command functions converting the exception to die(); (b) the loader parses feed lines with ipaddress.ip_network(..., strict=True) directly and never calls parse_net(), which die()s on bad input and would kill a batch run on one bad line. The loader catches per-key RuntimeError, counts it, and continues; it catches nothing that would let a guard be skipped.

Never raw bulk bpftool; never ngmap flush (origin-blind, wipes responder and operator entries, bin/ngmap.py:254-261).

## 3. Pipeline, per run

1. **Fetch** each configured feed: urllib, 30s timeout, conditional GET from the saved etag, hard read cap FEEDS_MAX_BYTES (4 MiB; today's largest feed is ~110 KiB) to a temp file. A 304 is a successful exchange: re-parse last-good and proceed, subject to the staleness cap below. Any other outcome (non-200, DNS failure, timeout, cap overrun) marks the feed FAILED: no writes for it this run, existing entries decay by TTL. A TTL re-stamp only ever follows a successful HTTP exchange; re-stamping from a local cache on network failure is prohibited.

   **Frozen-upstream cap**: alongside etag, the loader records last_changed_ts, the wall time of the last 200 whose body differed from the previous last-good (seeded from the upstream Last-Modified header when present). A chain of 304s or byte-identical 200s does not advance it. When now - last_changed_ts exceeds 7 days, ng.feeds_snapshot_age_<feed> drives a WARNING; when it exceeds FEEDS_MAX_STALE_S (14 days), the feed is marked FAILED even though the exchange succeeded: no re-stamp, entries decay by TTL. A wedged CDN or paused publisher is upstream-dead one layer up, and gets the same fail-open answer.

2. **Validate, format-strict, per real grammar**:
   - Spamhaus JSONL: every non-empty line must json-parse to an object. An object with a `cidr` field that ipaddress.ip_network(strict=True) accepts is a record. An object with `type == "metadata"` is the trailer: it is REQUIRED, must be the final line, and its `records` field must equal the count of record lines (this is the truncation check the strict rule was reaching for; verified live, both drop_v4.json and drop_v6.json end with such a trailer carrying records, size, timestamp, copyright). Any other cidr-less object, a missing trailer, or a count mismatch rejects the whole file. The trailer's copyright and timestamp are stored with the snapshot (Spamhaus attribution).
   - DShield block.txt: skip lines starting with '#'; every remaining non-empty line must split on tabs into at least 3 fields; the CIDR is ip_network(f"{col0}/{col2}", strict=True); require the result to be a /24 and col1 to equal the network's broadcast address as a cheap integrity check (verified live format: `148.59.129.0\t148.59.129.255\t24\t351\tSERVER-MANIA\tCA\t...`). One bad data line rejects the file.
   - Per-feed count gates from feeds.conf (defaults: drop_v4 min 500 max 10000, 1,709 observed; drop_v6 min 10 max 5000, 92 observed; dshield min 5 max 64) reject error pages and runaway files. Validation failure: FAILED, temp file kept as last-bad, last-good untouched.

3. **Promote** a validated body atomically to <feed>/last-good (tmp + rename) with etag, fetch timestamp, and last_changed_ts.

4. **Normalize and gate**, once per run across all successful feeds:
   - exact-duplicate dedupe across feeds; each surviving CIDR is assigned to exactly one owning feed (first in FEEDS_DRYRUN+FEEDS_APPLY order wins provenance); no adjacent-range aggregation (LPM handles overlap; unmerged entries stay traceable);
   - prefix floors, named constants: drop v4 shorter than /8 rejects the file; drop v6 shorter than FEEDS_V6_FLOOR=/19 (RIR v6 allocations run /19 to /32; the CLI's interactive /32 floor at bin/ngmap.py:195 would drop real DROPv6 allocations; open item 1). The feed path never passes --i-mean-it;
   - snapshot allow4/allow6 ONCE via ngmap allow-dump (the responder AllowCache pattern, bin/nodeguard-responder:114-144), never the per-entry allow_entries_live() re-dump cmd_block does. If the dump fails, OR if it returns zero entries for any family this run would write to, abort the entire run with no writes and set feeds_failed: the deployed hosts always carry non-empty allow files, so an empty allow map means the allow layer itself is broken (a truncated allow4.txt reconciled by nodeguard-maps ExecReload legally empties the map mid-flight), and writing feed blocks while the allow-before-block masking is absent risks enforcing against the operator's own egress IPs, resolvers, and DERP ranges;
   - **canary run-abort, not per-entry drop**: if ANY candidate range covers CANARY_IP (from /etc/nodeguard/nodeguard.env), the ENTIRE feed that supplied it is marked FAILED for this run: no writes for that feed, feeds_failed set, nonzero exit. This matches the precedent exactly: cmd_reconcile_allow refuses to proceed when any allow source covers the canary (bin/ngmap.py:399-405). The previous draft silently dropped the covering entry and continued, which would have surgically removed the one entry able to trip the watchdog's over-block soft-off (bin/nodeguard-watchdog canary probe) while writing the rest of an anomalous feed for 25h. A curated DROP/DShield feed covering 1.1.1.1 is never normal; it is a run-level anomaly and is treated as one;
   - drop any candidate where is_protected(network_address, allow_snapshot) is true, or where contains_protected() finds a NEVER_BLOCK or allowed range as a sub-prefix. Every such drop increments feeds_rejected with a reason line in the diff; with fullbogons excluded upstream, nonzero rejected is anomalous and alarms;
   - entry-count capacity gates: desired totals within FEEDS_MAX_V4=8192 / FEEDS_MAX_V6=2048, AND live map count plus planned inserts under 80 percent of max_entries (52428 of 65536 v4; 13107 of 16384 v6), preserving responder headroom. Breach aborts loudly;
   - **aggregate coverage cap** (new): reject the run for a family whose desired set covers more address space than FEEDS_MAX_COVERAGE_V4=67108864 v4 addresses (64M, roughly 4x today's legitimate DROP coverage of ~14.9M) or FEEDS_MAX_COVERAGE_V6_48=4194304 /48-equivalents (sum of 2^(48-prefixlen), prefixes longer than /48 counting as 1). Coverage is computed as the plain sum over the deduped desired set; overlap double-counting only tightens the cap. Entry-count gates alone cannot catch a few thousand validity-passing /8-to-/12 aggregates that would black-hole most WAN inbound; this gate measures the thing that actually hurts;
   - **churn brake** (new): per feed, compare the desired set against the last successfully applied set for that feed (persisted in the journal). If the symmetric difference exceeds FEEDS_MAX_CHURN_PCT=30 percent of the last applied set's entry count, or the covered-space delta exceeds the same fraction, the feed enters CHURN-HELD for this run: refreshes of already-journaled, still-desired keys proceed (so protection does not decay while held), but zero inserts and zero withdrawals happen; the full diff is written, ng.feeds_churn_held is set, and a WARNING fires. The operator accepts the new set with `nodeguard-feeds apply --confirm` (which re-baselines). The first enforcing run of a feed has no baseline and is exempt; apply --confirm is itself the baseline-setter.

Survivors form the per-feed desired sets.

## 4. Ownership: journal plus compare-and-swap, no schema change

struct block_val is {u64 expiry_ns; u64 hits} (src/nodeguard_kern.c:39-42); no owner byte exists, so ownership lives in the loader's journal, exactly as responder ownership lives in blocks.json.

**Two state files, deliberately split**:
- /var/lib/nodeguard/feeds/state.json: the operational journal, rewritten every run (atomic tmp + os.replace). Fields: boot_id (/proc/sys/kernel/random/boot_id), run_in_progress marker, per-feed fetch metadata (etag, last_changed_ts, last_success_ts, last applied set hash and coverage for the churn brake), and entries: for each owned key {version, prefixlen, addr, feed, sblid, written_expiry_ns, first_seen, last_written}.
- /var/lib/nodeguard/feeds/approved.json: the human arming record. Written ONLY by `apply --confirm` (adds a feed) and `withdraw --feed <id> --confirm` (revokes it). Never touched by `run`. The previous draft kept approvals inside the churning journal, which made the documented journal-loss recovery impossible (a rebuilt journal had no approvals, so the promised insert-only run could write nothing) and meant journal corruption silently disarmed the fleet. With the split, journal loss degrades exactly as documented below, and approval lifetime matches operator intent: removing a feed via withdraw revokes it, so a later config edit or restored backup cannot silently re-arm it.

written_expiry_ns is the ownership disambiguator: nothing else will ever write that exact u64 to that key, which turns every mutation into a compare-and-swap under the existing per-key flock (bin/ngmap.py:86-96; held per key, never around the batch, so nodeguard-block and sweep are delayed one lookup+write at most).

**Mutation rules** (per key, under the lock):
- **Insert** (desired, not in journal): look up. Absent: write pack("<QQ", mono_ns()+TTL, 0), journal it. Present with expiry != 0 and mono_ns() >= expiry (a corpse awaiting sweep): treat as absent, overwrite and journal it; an expired entry enforces nothing for any owner and sweep would delete it anyway. Present and live (responder /32, operator entry, permanent expiry-0 entry alike): do not touch, do not journal, record the skip in the diff. Live-occupied is occupied.
- **Refresh** (in journal, in desired set): look up. Live expiry equals journaled written_expiry_ns: write new expiry with hits carried forward from the read, update journal. Differs: another writer owns it now; drop the journal row, leave the map entry alone. **Absent** (the common case after a >25h outage sweeps everything, or after an enforce off/on toggle): insert fresh in this same run, same lock hold, new expiry, journal updated, and log once: "previously-owned key absent, re-inserting; allowlist to suppress". Without this rule the first successful run after upstream recovery would write nothing and full protection would wait another cycle, up to 6h15m after upstream is already healthy.
- **Withdraw** (in journal, absent from that feed's desired set): look up. Expiry matches journal: delete. Mismatch or absent: drop the journal row only.

**Invariant W1 (withdrawal scope)**: withdrawal iterates journal entries PER FEED, against that feed's own desired set, and a feed whose fetch or validation FAILED this run (including canary-abort, staleness cap, churn hold for inserts/withdraws) performs ZERO withdrawals: its journal rows and map entries are untouched and age out by TTL only. The dry-run diff asserts this mechanically: a FAILED feed showing any planned withdrawal is a loader bug and fails the run. This closes the gap where a single Spamhaus 5xx, by shrinking a global desired set, would have mass-withdrawn ~1,700 live entries in one run instead of letting them decay gracefully.

**The trap this section exists to avoid**: cmd_reconcile_allow (bin/ngmap.py:389-420) diffs desired against a full live dump and prunes, which is safe only because nodeguard-maps.service is the allow maps' sole writer. block4/block6 already have two writers and gain a third here; a live-dump diff-and-prune would delete every responder and manual block each run. The reconcile baseline is state.json, never dump_map() of a block map.

**Crash mid-run**: `run` sets run_in_progress in state.json at start and clears it at the end. Keys written after the last journal flush are not upsert-recovered (the insert rule refuses live foreign-looking entries); instead, a run that starts with run_in_progress still set enters bounded adoption mode: a present, live entry whose key exactly equals a desired CIDR for an approved feed and has no journal row MAY be overwritten and journaled (the crash flag is the evidence it was probably ours). Expired entries are adoptable always (insert rule above). This replaces the previous draft's "recovered next run (upsert)" claim, which its own insert rule contradicted.

**Journal lost or corrupt**: log, set ng.feeds_journal_reset=1, run insert-only (approvals survive in approved.json, so writes are still permitted; this is what makes the recovery actually executable), rebuild the journal from this run's writes; formerly-owned keys that collide as live-present are skipped and decay by TTL within 25h. Never delete without proof of ownership.

**Reboot**: maps are wiped and CLOCK_MONOTONIC restarts (ADR 0003); if boot_id differs, skip the withdraw phase entirely (lookups would find nothing; also removes the post-reboot expiry_ns collision case) and write the full desired set fresh under the new boot_id. The sweeper needs no change: origin-agnostic, TTL is TTL for every writer.

## 5. TTL and cadence

FEEDS_TTL_S=90000 (25h), expiry_ns = mono_ns() + TTL, enforced by the kernel on every packet (ADR 0003); the sweeper is hygiene. Timer: OnBootSec=15min, OnUnitActiveSec=6h, RandomizedDelaySec=15min. No Persistent=true: it applies only to OnCalendar timers and was inert as previously specified; the prompt post-downtime run is provided by OnBootSec, and that is stated here so nobody reads catch-up semantics into the unit that are not there. Four refresh opportunities per TTL window: one to three failed runs change nothing, and only a full day of failure lets entries begin expiring, hours after alarms fire. Dead timer, dead upstream, garbage feed, wedged host all converge on no successful run, and no successful run means every feed entry leaves the data path within 25h with zero components alive.

## 6. Dry-run, confirm, apply

Config /etc/nodeguard/feeds.conf (KEY=VALUE like responder.conf), shipped defaults:

```
# SAFETY: FEEDS_ENFORCE=no is the mandatory first-run mode. The timer job
# fetches, validates, and writes the diff it WOULD apply; nothing reaches
# block4/block6 until this is yes AND the feed is approved (apply --confirm).
FEEDS_ENFORCE=no
FEEDS_APPLY=""
FEEDS_DRYRUN="spamhaus_drop_v4 spamhaus_drop_v6 dshield_top20"
FEEDS_TTL_S=90000
FEEDS_MAX_V4=8192
FEEDS_MAX_V6=2048
FEEDS_MAX_BYTES=4194304
FEEDS_V6_FLOOR=19
FEEDS_MAX_COVERAGE_V4=67108864
FEEDS_MAX_COVERAGE_V6_48=4194304
FEEDS_MAX_CHURN_PCT=30
FEEDS_MAX_STALE_S=1209600
```

Double gate, mechanically enforced: a timer run writes to the maps only for feeds present in BOTH the config's FEEDS_APPLY and approved.json, and approved.json is written only by an interactive `nodeguard-feeds apply --confirm`. Editing the config alone can never arm a feed; approving alone (without the config listing it) cannot either. Revocation is symmetric: `withdraw --feed <id> --confirm` removes the feed from approved.json as well as retiring its entries, so approval cannot outlive the operator's decision. This matches the kill-switch precedent that a restart or state loss must never silently change a human decision in either direction (bin/ngmap.py:381-386, ADR 0003 point 4).

CLI (all modes exit nonzero on any FAILED feed so the oneshot unit goes red):
- `nodeguard-feeds run`: timer entry point. Full pipeline always; approved+listed feeds get reconcile writes when FEEDS_ENFORCE=yes; everything else gets the full diff. Journald receives the per-feed SUMMARY (counts for insert/refresh/withdraw/skip/reject) plus every rejection line verbatim; the full entry-level diff goes ONLY to /var/lib/nodeguard/feeds/last-diff.txt. (The previous draft logged ~1,500 pending-insert lines to journald every 6h during the dry-run soak, burying the rejection lines that matter and inviting journald rate limiting exactly when something interesting happens.)
- `nodeguard-feeds diff`: recompute and print the pending diff from last-good snapshots without fetching. The review command.
- `nodeguard-feeds apply --confirm`: prints the diff, requires the literal flag, records the feed into approved.json, sets the churn baseline, performs the first enforcing reconcile. Also the acceptance path for a CHURN-HELD run.
- `nodeguard-feeds withdraw [--feed <id>] --confirm`: CAS-guarded delete of owned keys only; with --feed, also revokes that feed's approval. The rollback tool.
- `nodeguard-feeds status`: journal summary; source of the kv fragment.

**First activation runbook** (config edits go to hosts/<host>/feeds.conf IN THE REPO and reach the host via deploy, exactly as responder.conf does; deploy.sh reinstalls /etc/nodeguard/feeds.conf on every deploy, so an edit made on the live host file is silently reverted by the next unrelated deploy): deploy with defaults (all dry-run); let the timer produce at least two diffs on real data; review last-diff.txt on each gateway; promote one feed on one host (repo config edit + deploy + apply --confirm on the host); watch ng.feeds_* and the canary through one full cycle; then promote remaining feeds and the second host. New feeds always enter FEEDS_DRYRUN first and follow the same path. Alarms are proven live before the first enforcing run (openspec/project.md: monitoring exists before enforcement).

**Suppressing a false positive** (the 2am procedure, stated here and in section 10 because nodeguard-unblock alone is NOT sufficient): add the range to the host's allow file (repo copy) and reload nodeguard-maps. The allow-snapshot gate then drops the candidate on the next run and the withdraw phase removes the existing feed entry. A bare nodeguard-unblock is reverted by the next feed run within 6 to 12h; the loader logs "previously-owned key absent, re-inserting; allowlist to suppress" the first time it re-inserts such a key, pointing the operator at the durable mechanism.

## 7. Observability

The loader atomically rewrites /var/lib/nodeguard/feeds/feeds.kv at the end of every run. This file is deliberately on persistent storage, not /run: the previous draft's tmpfs fragment vanished at reboot, defaulting last_success to 0 and firing both staleness triggers on every boot with nothing wrong. Persisted, the pre-reboot timestamps remain true statements and the triggers behave. bin/nodeguard-status's hardcoded --kv block (bin/nodeguard-status:61-95) gains echo lines sourced from this file, defaulting to 0/unknown when absent (first boot ever). The rest of the chain needs nothing: the watchdog regenerates /run/zabbix/nodeguard.kv every minute (bin/nodeguard-watchdog:15-17) and the generic UserParameter nodeguard.kv[*] (etc/zabbix-userparameter-nodeguard.conf:8) answers any new ng.* key with zero agent change.

Fields, per feed where marked: ng.feeds_enforce (0/1), ng.feeds_approved (count), ng.feeds_config_approved_mismatch (0/1: approved.json non-empty AND (FEEDS_ENFORCE=no OR an approved feed missing from FEEDS_APPLY)), ng.feeds_journal_reset (0/1), ng.feeds_churn_held (0/1), ng.feeds_last_run_ts, ng.feeds_last_success_ts_<feed> (per feed; the aggregate ng.feeds_last_success_ts_min is defined as the min over configured feeds and labeled as such), ng.feeds_snapshot_age_<feed>, ng.feeds_entries, ng.feeds_candidates, ng.feeds_rejected, ng.feeds_failed. Per-feed keys cost one Zabbix item each; the wildcard userparameter already answers them.

templates/zabbix-nodeguard-template.json gains items for those keys plus triggers (per feed where the field is per feed; a single broken feed must not latch the aggregate alarms while the other ~1,700 entries refresh on schedule, and conversely must not train operators to ignore the alarm that matters):
- WARNING: now - feeds_last_success_ts_<feed> > 13h. That is two full 6h cycles plus jitter plus margin; the previous 8h threshold fired after ONE missed cycle and guaranteed a ~4h false alarm on any transient 5xx, and its "two missed cycles" rationale was arithmetically wrong.
- AVERAGE: now - feeds_last_success_ts_<feed> > 26h: that feed's entries have expired; it has failed open to no enforcement. Moderate severity on purpose: designed decay, not an outage (open item 4).
- WARNING: feeds_rejected > 0 for 2 cycles: a curated feed is shipping protected/allow ranges; review last-diff.txt.
- WARNING: feeds_config_approved_mismatch = 1 for 2 cycles: the drift tripwire that turns a deploy-reverted config (silent disarm) into a same-day alert instead of a decay discovered days later.
- WARNING: feeds_snapshot_age_<feed> > 7d: frozen upstream; re-stamp hard-stops at 14d.
- WARNING: feeds_churn_held = 1: a feed's composition jumped past the churn brake and is awaiting apply --confirm.
- INFO: feeds_failed > 0 for 3 consecutive cycles (18h): the transient-failure carrier, so the staleness WARNING does not have to be.

## 8. Files, units, deploy

New: bin/nodeguard-feeds (0755, /usr/local/sbin); units/nodeguard-feeds.service (Type=oneshot, ExecStart=/usr/local/sbin/nodeguard-feeds run, EnvironmentFile=/etc/nodeguard/feeds.conf, After=network-online.target, Wants=network-online.target, hardening copied from nodeguard-sweep.service); units/nodeguard-feeds.timer (section 5); hosts/example-gateway/feeds.conf. Modified: bin/ngmap.py (contains_protected() extraction; update_map/delete_key raise instead of die, CLI wrappers convert); bin/nodeguard-status (--kv lines); templates/zabbix-nodeguard-template.json. Runtime tree /var/lib/nodeguard/feeds/: state.json, approved.json, feeds.kv, last-diff.txt, <feed>/{last-good,last-bad,etag}. Persistent on purpose (journal and approval continuity, reboot-honest kv); no tmpfiles change needed.

deploy/deploy.sh (explicit file list, verified): add nodeguard-feeds to the scp list (~:32-36) and the remote install loop (~:51-53); add feeds.conf with its own scp entry and install -m 0644 line (~:60-61) and to the preflight existence check (:20-24); units are picked up by the existing *.service/*.timer globs (:37, :65-66) but nodeguard-feeds.service and .timer must be added to the explicit systemd-analyze verify loop (:86-90) or they are silently unverified; add install -d /var/lib/nodeguard/feeds next to the existing /var/lib/nodeguard line (:47); add nodeguard-feeds to the py_compile check alongside ngmap.py and the responder (:105). deploy.sh never touches state.json or approved.json (host-local state, like blocks.json).

Gates before done: bash -n and shellcheck on any shell, python3 -m py_compile on nodeguard-feeds and the modified ngmap.py, systemd-analyze verify on both units, one live fetch of each feed URL confirming the parser grammars against reality (the DShield grammar in particular), and a full dry-run cycle on a real gateway producing a real last-diff.txt.

## 9. Failure modes

| failure | behavior | decays to | surfaced by |
|---|---|---|---|
| timer/service dead | no runs, no writes | all feed entries expire within 25h (kernel TTL) | 13h WARN, 26h AVERAGE per feed |
| upstream unreachable / 5xx / DNS | feed FAILED, no writes AND no withdrawals for it (invariant W1); others proceed | that feed expires within 25h | per-feed WARN/AVERAGE, feeds_failed, nonzero exit |
| truncated body | trailer records-count mismatch (Spamhaus) or bad tab line (DShield) rejects file; last-good kept | as above | feeds_failed, last-bad retained |
| frozen upstream (endless 304 / identical 200) | re-stamp allowed to 14d, then FAILED; no indefinite stale enforcement | entries decay after the cap | snapshot_age WARN at 7d |
| near-empty or runaway file | count gates / byte cap reject | never loaded | feeds_failed |
| feed ships RFC1918/CGNAT/allow-covered range | dropped per entry by imported guards; never written | never enters map | feeds_rejected trigger |
| feed range covers CANARY_IP | ENTIRE feed FAILED this run; zero writes; watchdog tripwire intact | that feed decays by TTL | feeds_failed, rejection reason in diff |
| desired set covers huge address space | aggregate coverage cap aborts pre-write | no load | unit failure |
| feed composition jumps >30 percent | CHURN-HELD: refreshes only, no inserts/withdraws, awaiting apply --confirm | held set decays only if never confirmed | churn_held WARN |
| allow dump fails or is empty | entire run aborts, no writes | feeds decay by TTL | feeds_failed |
| feed key collides with live responder /32 | insert refuses live-occupied; CAS leaves foreign values alone | responder entry lives out its own TTL | skip recorded in diff |
| feed key collides with expired corpse | adopted: overwritten and journaled (safe; enforces nothing for anyone) | normal feed lifecycle | diff |
| operator unblocks a feed CIDR | CAS mismatch drops the claim, but the next run re-inserts (absent + desired); durable suppression is the allow file | operator uses allowlist procedure (sections 6, 10) | re-insert logged with guidance |
| state.json lost/corrupt | approvals survive in approved.json; insert-only run rebuilds journal; no unproven deletes | orphans expire within 25h | feeds_journal_reset kv, journald |
| approved.json lost | disarm: double gate blocks all writes until a human re-runs apply --confirm; entries decay | 25h decay | config_approved_mismatch WARN, per-feed staleness |
| deploy reverts live config edit | enforcement disarms in the fail-open direction | 25h decay | config_approved_mismatch WARN within 2 cycles |
| crash mid-run | run_in_progress flag enables bounded adoption next run; journal rebuilt | TTL for anything unadopted | stale per-feed success ts |
| reboot | maps wiped; boot_id mismatch skips withdraws; fresh full write next run; kv persists so no false staleness alarms | clean reload | normal run |
| map near capacity | 80 percent headroom gate aborts pre-write | no partial load | unit failure |
| kill switch active | irrelevant; XDP ignores blocklist; entries still TTL out | unchanged | existing ng.killswitch |

## 10. Rollback and suppression

```
systemctl disable --now nodeguard-feeds.timer     # stop future loads; full decay within 25h
nodeguard-feeds withdraw --confirm                # remove all feed-owned entries now, CAS-guarded
nodeguard-feeds withdraw --feed spamhaus_drop_v4 --confirm
                                                  # drop one feed AND revoke its approval;
                                                  # then remove it from FEEDS_APPLY in hosts/<host>/feeds.conf and deploy
# demote to dry-run: edit FEEDS_ENFORCE=no in hosts/<host>/feeds.conf and deploy
```

To suppress a single false positive durably: add the range to the host's allow file (repo copy), deploy, reload nodeguard-maps. nodeguard-unblock alone WILL be reverted by the next feed run. Doing nothing is itself a valid rollback (25h decay). Never nodeguard-flush: it wipes responder and operator blocks too.

## Open items (flagged, not silently decided)

1. FEEDS_V6_FLOOR=/19: verify the live prefix distribution of drop_v6.json during implementation; tighten the constant if all entries are /32 or narrower.
2. Hits carried forward on refresh can undercount by the lookup-to-write window; informational grade, accepted.
3. feodo_c2 stays deferred until the 25h-TTL versus 5-minute-churn tradeoff is accepted in writing.
4. Whether the per-feed 26h failed-open trigger should page or notify; designed as AVERAGE because failing open is the intended behavior.
5. Licensing: Spamhaus terms are honored (attribution kept with snapshots, fetch far under the hourly cap). DShield block.txt declares CC BY-NC-SA 2.5 in its header; one gateway is an office node, so the NC clause needs an explicit one-line internal-defensive-use judgment recorded before dshield_top20 is promoted out of dry-run. Not "public".
6. Tuning of FEEDS_MAX_COVERAGE_V6_48 and FEEDS_MAX_CHURN_PCT against the first weeks of real diffs; both are deliberately generous first guesses with the mechanism being the point.

Repo anchors: bin/ngmap.py:38-43, 73-75, 86-96, 140-142, 172-177, 195, 204-210, 254-261, 264-291, 338-339, 381-386, 389-420; bin/nodeguard-responder:38, 114-144, 146-216, 403; bin/nodeguard-status:61-95; bin/nodeguard-watchdog:15-17, 113-114, 175-177; etc/zabbix-userparameter-nodeguard.conf:8; deploy/deploy.sh:20-24, 32-37, 47, 51-58, 60-66, 86-90, 105; units/nodeguard-sweep.service:6; src/nodeguard_kern.c:29-42, 151-167; docs/adr/0003, 0004; hosts/example-gateway/nodeguard.env, responder.conf.