## 0. Phase 0: paperwork (no new code)

- [x] 0.1 Write proposal.md, specs/telemetry-observability/spec.md, and
      this tasks.md; `openspec validate add-nodeguard-telemetry
      --strict` passes
- [x] 0.2 Write docs/adr/0006-load-threat-intel-through-the-journaled-
      cas-owner.md (accepted; feeds rationale with evidence: firehol
      level1 rejected for live RFC1918/CGNAT ranges, feodo_c2 deferred
      for TTL mismatch, journal-plus-CAS over dump-and-diff because
      block4/6 already have two other writers); MUST land before
      add-nodeguard-feeds archives
- [x] 0.3 Write docs/adr/0007-add-counters-in-a-second-stats-map-and-
      keep-trie-walks-off-the-minute-path.md (proposed until this
      change is approved; new-map-never-resize, no minute-path trie
      walks with the Cloudflare numbers, identity-check relaxation
      rationale, LIBBPF_PIN_BY_NAME auto-pin reality and the spec-based
      pre-load guard, counting-before-killswitch placement, reload
      double-count artifact, the two-layer anomaly split)
- [x] 0.4 Gate (phase 0): strict validation passes and design.md claims
      spot-checked against the tree

## 1. Phase 1: reload/attach generalization and userspace kv expansion

Deployed WITHOUT --with-kernel; the running kernel object stays on disk
and any restart reloads it.

- [x] 1.1 Replace the hardcoded six-map lists in bin/nodeguard-reload:50
      and bin/nodeguard-lib.sh ng_verify_map_identity
      (nodeguard-lib.sh:67) with the derived set: enumerate the
      incoming program's map_ids via `bpftool prog show -j`, resolve
      names via `bpftool map show -j`, require every referenced name
      matching a pin to carry the pinned id, and assert the core six
      are present; remove any --allow-unused-pins escape hatch
- [x] 1.2 Add the pre-load spec guard to nodeguard-reload and
      nodeguard-attach: refuse to invoke the loader if any spec-listed
      map has no pin, naming `systemctl reload nodeguard-maps` as the
      recovery command
- [x] 1.3 nodeguard-status kv: export all eight stats slots
      (pass_expired, pass_nonip, pass_parsefail added); replace the
      silent-zero fallback (nodeguard-status:65-73) with
      omit-plus-ng.stats_read_fail=1; add ng.rearm_count from config
      slot 2
- [x] 1.4 ngmap.py: `stats2 --json` subcommand with STATS2_NAMES in
      lockstep with the enum; status emits nothing when the pin is
      absent, and omit-plus-ng.stats2_read_fail=1 when present but
      unreadable
- [x] 1.5 Move the live `list --json` count computation inside the
      human-output branch of nodeguard-status (it currently runs
      unconditionally at nodeguard-status:31); kv sources counts
      exclusively from the cache file
- [x] 1.6 ngmap.py cmd_sweep: accumulate counts, per-entry hits, and
      walk duration in the existing 10-minute walk; write
      /var/lib/nodeguard/mapstat.kv atomically (tmp+rename) with
      ng.blocks, blocks_v4/v6, util_v4/v6_pct (denominators from the
      installed spec, not hardcoded), top1_hits, top_blocked (top-5 by
      hits delta via /var/lib/nodeguard/sweep_hits.json, cumulative as
      secondary), sweep_walk_ms, sweep_ts
- [x] 1.7 Reboot correctness: nodeguard-maps truncates mapstat.kv and
      sweep_hits.json whenever it creates any map;
      nodeguard-sweep.timer OnBootSec 10min to 2min; nodeguard-status
      emits ng.sweep_age from sweep_ts and omits all mapstat keys when
      the file is missing or empty
- [ ] 1.8 bin/nodeguard-feeds: trigger a one-off sweep
      (`systemctl start nodeguard-sweep.service`) after apply instead
      of writing mapstat.kv; note in add-nodeguard-feeds tasks.md that
      its pending activation rehearsal now runs against this phase 1
      binary (cross-change rule, design section 10)
- [ ] 1.9 Dispatcher health: reload and attach write
      /run/nodeguard/expected_prog_id, detach removes it; status emits
      ng.prog_match and ng.attach_mode, emitting nothing for
      prog_match when the expectation file is absent
- [ ] 1.10 Watchdog internals kv: ng.wd_canary_fail, wd_lifeline_fail,
      wd_toolfail, wd_clean from the existing /run/nodeguard/wd_*
      files; document the one-cycle lag and use >= trigger comparisons
- [ ] 1.11 Security-event kv: nodeguard-responder writes
      /run/nodeguard/responder.kv (resp_alerts_seen,
      resp_blocks_issued, resp_dryrun_would_block, resp_last_alert_ts,
      resp_last_action_ts); ng.suricata_alerts parsed from the same
      suricatasc dump-counters call as kernel_drops; wrap suricatasc in
      `timeout 5`; remove the `${kdrops:-0}` coercion
      (nodeguard-status:93) so failure omits both keys
- [ ] 1.12 Watchdog EWMA anomaly layer (ships in this deploy set,
      WD_ANOM_MODE=shadow default): per-cycle deltas of drop_total,
      pass, sanity_total, suricata_alerts; EWMA mean and absolute
      deviation (alpha 0.05) in /var/lib/nodeguard/wd_baseline.json;
      trip on WD_ANOM_TRIP consecutive cycles over
      max(WD_ANOM_FLOOR, m + WD_ANOM_K * d); excluded-cycle updates
      with WD_ANOM_ADAPT bound; regime reseed on kill-switch, attach,
      or feeds-enforce change; discard cycles spanning a reload
      (prog_id change); never touches kill switch, latch files, or
      maps; tunables WD_ANOM_MODE/K/FLOOR/TRIP/ADAPT in nodeguard.env
- [x] 1.13 Open question (LPM used_entries): check on a live host
      whether bpftool reports a usable live entry count for LPM_TRIE
      maps; record the answer; the sweep-count derivation stands unless
      a cheaper accurate source exists
- [ ] 1.14 Build gate (phase 1): bash -n and shellcheck clean on every
      touched script; netns rehearsal green including the
      stats-read-failure drill (broken bpftool/ngmap path yields no
      counter lines plus ng.stats_read_fail=1, never zeros) and the
      prog_match-absent case
- [ ] 1.15 Deploy node-3 without --with-kernel
- [ ] 1.16 Gate: kv key list on node-3 diffs clean against the spec'd
      list
- [ ] 1.17 Gate: grep proof that `list --json` is unreachable from the
      kv code path
- [ ] 1.18 Gate: sweep produces mapstat.kv and ng.blocks reconciles
      against one manual `list --json` count, performed while feeds
      enforcement is off (its current state) so the reconciliation
      cannot race a feeds apply (cross-change rule, design section 10)
- [ ] 1.19 Gate: a deliberate bpftool break on node-3 shows counters
      unsupported plus stats_read_fail=1, not zeros
- [ ] 1.20 Gate: 24h soak on node-3 with wd_clean advancing and no new
      journal errors; then deploy node-2 and repeat 1.16 to 1.19

## 2. Pre-phase-2 gates and phase 2: template v2

- [ ] 2.1 Add nodeguard.kv.raw UserParameter to
      etc/zabbix-userparameter-nodeguard.conf (keep nodeguard.kv[*]);
      deploy.sh stages and installs it (in the phase 1 deploy set);
      runbook names the zabbix-agent restart as an explicit step
- [ ] 2.2 Hard gate (pre-phase-2): restart zabbix-agent on both hosts
      and verify `zabbix_get -k nodeguard.kv.raw` from the Zabbix
      server against BOTH hosts before any template import
- [ ] 2.3 Write zbx/gen-template.py: deterministic render of
      templates/zabbix-nodeguard-template.json; uuid map seeded from
      the committed v1 with verbatim carry-over, uuid5 minting only for
      new objects; display names of existing items reproduced
      byte-for-byte
- [ ] 2.4 Write zbx/check_template.py: assert every generated
      preprocessing regex `(?m)^ng\.<field>=(.+)$` extracts a value
      from a captured real nodeguard.kv; assert display-name parity
      against committed v1; cross-check template keys against the
      documented kv key list; wire into build/build.sh so drift fails
      the build
- [ ] 2.5 Generate v2: master item nodeguard.kv.raw (TEXT, 1m, history
      1d, trends none); every existing item keeps its key and flips to
      dependent; new dependent items (three missing stats slots,
      stats_read_fail, stats2_read_fail, seven stats2 counters,
      suricata_alerts, five resp_*, rate twins where graphed,
      kernel_drops rate twin, blocks_v4/v6, util_v4/v6_pct, sweep_age,
      sweep_walk_ms, top1_hits, top_blocked, rearm_count, prog_match,
      attach_mode, four wd_*, anomaly_count, anomaly_shadow_count,
      anomaly_last_ts); rate items get 90d trend storage
- [ ] 2.6 Generate the trigger set: change(anomaly_count)>0 High;
      prog_match=0 for 3m High; attach_mode<>native while attached
      Warning; change(rearm_count)>0 Warning; wd_canary_fail>=2 or
      wd_lifeline_fail>=2 Warning; stats_read_fail=1 or counters
      unsupported Warning; kernel_drops unsupported Warning; util
      static plus timeleft pairs Warning; sweep_age>1800 Warning plus
      the independent ng.sweep_timer trigger; fuzzytime(ts,300)=0 High;
      responder dry-run divergence Info; feeds_last_run_ts=0 sustained
      24h Warning with no last()>0 gate; baselinedev conjunctions with
      absolute floors, and static ceilings, imported at Information
      severity only
- [ ] 2.7 LLD: one discovery rule dependent on the master extracting
      {#FEED} from feeds_last_success_ts_* keys (delay 1h,
      keep-lost-resources 30d); prototype keys DISTINCT from static
      keys (nodeguard.feed.success_ts[{#FEED}],
      nodeguard.feed.age[{#FEED}]); prototype stale/failed-open/
      upstream-frozen triggers at Information severity during parity,
      each paired with a nodata() guard
- [ ] 2.8 Feeds writer visibility: emit per-feed snapshot_age only
      after a feed's first success, so pre-first-run items are visibly
      undiscovered or unsupported instead of green-zero
- [x] 2.9 Hard gate (pre-phase-2, open question): scratch-template
      import rehearsal on the Zabbix server, v1 then v2; confirm
      itemids are preserved across the upgrade and one dependent item
      parses a pasted kv blob; Zabbix same-key/different-uuid import
      behavior is treated as unverified until this passes
- [ ] 2.10 Export the current live template to output/ as the rollback
      artifact, then import the generated v2
- [ ] 2.11 Gate: every item fresh in Latest Data within 5 minutes on
      both hosts, EXCEPT the stats2 items and their rate twins
      (ng.tcp_synfin, ng.tcp_synrst, ng.tcp_null, ng.tcp_xmas,
      ng.ttl_low, ng.frag_v4, ng.frag_v6 and each rate twin, plus
      ng.stats2_read_fail), which MUST be unsupported until phase 3
      creates the pin
- [ ] 2.12 Gate: ng.ts advancing across two consecutive samples and one
      XDP counter strictly monotonic on both hosts (dependent
      freshness alone only proves the regexes, not a live pipeline)
- [ ] 2.13 Gate: a deliberate 3-minute watchdog-timer stop on node-3
      confirms fuzzytime(ts,300) fires and recovers
- [ ] 2.14 Gate: the old "Nodeguard" dashboard's graphs render
      non-empty for both hosts (display-name contract held); agent log
      shows one kv.raw poll per minute
- [ ] 2.15 Gate: LLD discovers all three feeds under the new prototype
      keys; after 24h of value-parity between static and LLD per-feed
      items, remove the static per-feed items and their triggers as
      this recorded step (per-feed history under the old keys is lost;
      accepted)
- [ ] 2.16 Gate: 48h on the v2 template without unexpected trigger
      flaps; baseline triggers still at Information severity only

## 3. Phase 3: kernel stats2 (one sitting per host; minutes, not days)

- [ ] 3.1 src/nodeguard_kern.c: add PERCPU_ARRAY stats2 (max_entries
      16, LIBBPF_PIN_BY_NAME), count2() helper, seven counters
      (ST2_TCP_SYNFIN, ST2_TCP_SYNRST, ST2_TCP_NULL, ST2_TCP_XMAS,
      ST2_TTL_LOW, ST2_FRAG_V4, ST2_FRAG_V6, ST2_MAX=16); parse rules
      per design section 1 (TCP only at frag offset 0 for v4, ihl
      honored, v6 directly-following TCP header only, at most one flag
      counter per packet in order SYN+FIN, SYN+RST, NULL, XMAS; TCP
      bounds failure not counted as parsefail); NG_TTL_LOW_FLOOR
      build-time define defaulting to 5 with the no-published-threshold
      comment
- [ ] 3.2 Move the kill-switch check from main()
      (src/nodeguard_kern.c:275-280) into handle_v4/handle_v6, after
      the sanity block and before any verdict lookup; still resolves
      to XDP_PASS; record the latch-window rationale and the reload
      double-count artifact in ADR 0007
- [ ] 3.3 build/build.sh: derive the map list from the throwaway load's
      pins (`ls "$SPEC_PIN"`) and use it in all three hardcoded sites:
      stray-pin cleanup (build.sh:30), spec generation (build.sh:47),
      and the rehearsal identity loop (build.sh:84); add the build-
      failing assertions (derived set contains the core six; derived
      set equals the BTF-declared map set from `bpftool btf dump`)
- [ ] 3.4 deploy/deploy.sh: add --with-kernel; default runs neither
      require, stage, nor install nodeguard_kern.o or
      nodeguard-maps.spec; with the flag, both required and installed
      as today
- [ ] 3.5 Netns rehearsal additions: crafted-packet sanity assertions
      (python3 raw sockets sending NULL, XMAS, SYN+FIN, SYN+RST,
      low-TTL, fragmented probes; each counter increments, verdict
      stays XDP_PASS with service continuity); rollback rehearsal
      (new-to-old reload with the stats2 pin present is hitless and
      the pin ignored)
- [ ] 3.6 Open question (latch cost): in the netns rehearsal, compare
      packet rate and CPU with the kill switch latched versus
      unlatched under the same load, confirming the full-header-parse-
      during-latch cost claim before any gateway sees the object;
      record the numbers
- [ ] 3.7 Build gate (phase 3): fedora:44 container build regenerates
      object and spec via the derived-map-list generator; full netns
      rehearsal green in both reload directions
- [ ] 3.8 Deploy node-3 with --with-kernel; create the stats2 pin with
      EXACTLY `systemctl reload nodeguard-maps` (or `python3 $NG_MAP
      create-maps --spec $NG_SPEC`); NEVER `systemctl restart
      nodeguard-maps`, which propagates through Requires= to
      nodeguard-xdp and blips the WAN link; runbook treats deploy,
      create-maps, and reload as one sitting (the untested-object
      window between install and reload is minutes by procedure)
- [ ] 3.9 Gate before reload: `bpftool map show pinned $NG_PIN/stats2`
      succeeds AND the six existing pin ids are unchanged (`bpftool
      map show -j` diff)
- [ ] 3.10 Run nodeguard-reload; gate: zero carrier transitions
      (ip -s link counters plus ping continuity)
- [ ] 3.11 Gate: original stats counters monotonic across the swap
      (brief ST_PASS inflation from dual-attach is expected and
      documented)
- [ ] 3.12 Gate: a NULL-scan probe from a non-allowlisted, non-blocked
      host increments tcp_null while receiving service (fail-open
      observed live)
- [ ] 3.13 Gate: ng.prog_match=1 and the stats2 template items flip to
      supported within one poll cycle
- [ ] 3.14 Gate: 24h soak on node-3, then repeat 3.8 to 3.13 on node-2

## 4. Phase 4: dashboards

- [ ] 4.1 Write zbx/lib.py: urllib JSON-RPC client, itemid resolution,
      widget builders (graph, itemvalue, gauge, honeycomb, pie, url),
      Okabe-Ito palette, 72-column grid; token from env ZTOKEN only,
      never argv, never printed
- [ ] 4.2 Write zbx/dashboards.py: Overview, Security, Capacity and
      Pipeline per design section 8; CLI --url, --host name[:label]
      (no default), --group (default "Nodeguard nodes"),
      --host-pattern, --legend-url (GitHub Pages default),
      --dashboard, --confirm; default run prints the full plan and
      exits; idempotent update-or-create; unresolvable keys skip the
      widget loudly
- [ ] 4.3 Fleet scaling (design section 15): the host group is the
      canonical fleet definition; group- or pattern-addressed widgets
      wherever supported; per-host tiles and gauges generated from
      live group membership (host.get by group id); item NAME patterns
      chosen so a new host's items match without change; honeycomb
      replaces per-host tile rows at fleet sizes above two
- [ ] 4.4 Review gate: no real host name, host-name prefix, or server
      URL appears anywhere in zbx/; the private wrapper
      (dashboards-apply.sh, at most 15 lines) supplies url, group,
      host pattern, and token
- [x] 4.5 Open question (widget fields): verify the researched
      honeycomb and gauge widget field names against the live 7.4 API
      with one plan-mode diff against a hand-exported dashboard before
      the first --confirm
- [ ] 4.6 Rewrite docs/legend.html: three anchored sections, one line
      per panel stating what normal looks like; top_blocked labeled
      "since last sweep walk" with cumulative secondary; each
      dashboard's URL widget points at its anchor
- [ ] 4.7 Apply, per the section 8 procedure: export the live
      "Nodeguard" dashboard JSON to output/; create "NodeGuard
      Overview" as a NEW dashboard (never update "Nodeguard" in
      place); run the side-by-side parity check against the still-live
      "Nodeguard"; only then delete "Nodeguard" and the old private
      script in the same step
- [ ] 4.8 Gate: all widgets non-empty for both hosts; legend anchors
      resolve
- [ ] 4.9 Gate (fleet-scale drill): run the generator plan with a
      synthetic third host in the group and verify the plan output
      covers it in every dashboard with no code edit; the synthetic
      host must carry a visible name different from its technical
      name, and the drill asserts the plan's dataset host patterns
      equal visible names (Zabbix matches dataset host patterns
      against the visible name)

## 5. Phase 5: anomaly shadow window

- [ ] 5.1 Confirm WD_ANOM_MODE=shadow fleet-wide for at least 7 days;
      feeds enforcement activation is excluded from this window
      (cross-change rule, design section 10: activation either
      completed before this phase began or waits until after the
      phase 6 gate)
- [ ] 5.2 Gate: shadow trip review with every trip timestamp
      cross-checked against nodeguard-reload journal lines (the
      dual-attach double-count artifact)
- [ ] 5.3 Gate: WD_ANOM_K and WD_ANOM_FLOOR retuned from real deltas
      and documented in nodeguard.env comments with the date
- [ ] 5.4 Gate: static ceiling values for the Zabbix layer chosen from
      the shadow data and applied to the template

## 6. Phase 6: enable

- [ ] 6.1 Set WD_ANOM_MODE=on fleet-wide
- [ ] 6.2 Promote baselinedev triggers from Information severity only
      after trend rows cover at least 14 days (verified via trend.get)
      AND that window is reviewed as quiet against
      ng.anomaly_shadow_count and the journal; a feeds enforcement
      flip resets the EWMA state (regime rule) and restarts this
      14-day maturity clock (cross-change rule, design section 10)
- [ ] 6.3 Gate: one deliberate synthetic burst from an allowlisted
      admin host increments anomaly_count, fires the Zabbix trigger,
      and the EWMA recovers without operator action (recovery by the
      burst ending, not by absorption)

## 7. Documentation refresh (design section 11, items 1 to 19)

- [ ] 7.1 (1) docs/design.md header: drop "before the first production
      deployment"; state the actual bring-up phase (phase 2 complete,
      dry-run soak and enforcement pending); update the metadata
      header
- [ ] 7.2 (2) design.md section 3 (Context and Scope): add
      external-interface rows for the three feed HTTPS sources
      (Spamhaus DROP v4/v6, DShield, 6h cadence) and the Zabbix server
- [ ] 7.3 (3) design.md section 5 (Building Block View): add
      nodeguard-feeds (914-line daemon),
      units/nodeguard-feeds.service/.timer, hosts/*/feeds.conf, and
      the new zbx/ directory; update the bin/ and etc/ file lists
- [ ] 7.4 (4) design.md section 6.3 (Watchdog cycle): document the kv
      export as the cycle's first step (the monitoring-chain entry
      point) and add the anomaly-detector step with its regime and
      update rules
- [ ] 7.5 (5) design.md section 8: new "Monitoring chain" crosscutting
      subsection (watchdog to kv file to agent UserParameter to
      master/dependent template to dashboards), recording in prose the
      SELinux constraint that zabbix_agent_t cannot call bpf();
      configuration table gains the 11 feeds.conf variables, the
      WD_ANOM_* family, and NG_TTL_LOW_FLOOR; observability text
      describes stats2, the counting-before-killswitch placement, the
      sweep cache and its single-writer rule, the
      fail-to-unsupported discipline, the reload double-count
      artifact, and the full kv export
- [ ] 7.6 (6) design.md section 11 (Risks): remove the three risks the
      tree proves resolved (native attach 4.3, hitless reload 4.4, EVE
      flow fields 3.3); keep RSS measurement and
      SELinux-under-systemd; add sweep-walk-cost-at-scale with the
      Cloudflare citation and the sweep_walk_ms mitigation, and
      baseline-trigger maturity
- [ ] 7.7 (7) design.md roadmap: mark feeds
      implemented-activation-pending; point both telemetry items at
      add-nodeguard-telemetry; per-source rate limiting stays deferred
- [ ] 7.8 (8) Verification: every factual design.md claim
      grep-verified against the tree in the same sitting
- [ ] 7.9 (9) docs/adr/0006 (see task 0.2)
- [ ] 7.10 (10) docs/adr/0007 (see task 0.3)
- [ ] 7.11 (11) CHANGELOG.md: back-fill the entire add-nodeguard-feeds
      entry (loader, units, feeds.conf, ngmap/status changes, template
      items); an entry for the monitoring chain and the hitless-reload
      verification; the entry for this change
- [ ] 7.12 (12) README.md: monitoring section names the three
      dashboards and zbx/
- [ ] 7.13 (13) docs/legend.html full rewrite (see task 4.6)
- [ ] 7.14 (14) etc/zabbix-userparameter-nodeguard.conf: add
      nodeguard.kv.raw; keep nodeguard.kv[*]
- [ ] 7.15 (15) hosts/example-gateway/nodeguard.env: document
      WD_ANOM_MODE/K/FLOOR/TRIP/ADAPT with defaults and dates when
      retuned
- [ ] 7.16 (16) deploy/deploy.sh: --with-kernel flag; stage/install the
      zabbix agent conf and every other changed file following the
      feeds.conf wiring pattern; runbook note for the agent restart
- [ ] 7.17 (17) openspec/project.md: one-line component update naming
      nodeguard-feeds, zbx/, and stats2
- [ ] 7.18 (18) Private overlay: historical-superseded headers on the
      overlay's stale design.md/proposal.md drafts, flagged to the
      operator, not silently rewritten
- [ ] 7.19 (19) This change's own artifacts complete;
      `openspec validate add-nodeguard-telemetry --strict` passes;
      bash -n and shellcheck on every touched script
