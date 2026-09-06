## Why

nodeguard currently blocks only what the responder observes locally, and the
responder stays gated behind its dry-run soak. Reputable network-layer
blocklists (Spamhaus DROP: hijacked and criminal-leased netblocks whose
stated purpose is outright dropping) offer proactive coverage of known-bad
address space at near-zero false-positive cost. The first dry-run night
already recorded 1,225 hits from DShield-listed sources against the
internet gateway. The existing machinery (pinned LPM maps with in-kernel
TTL, the ngmap toolchain, timers, kv observability) needs only a loader.

## What Changes

- New `nodeguard-feeds` oneshot script plus a 6h timer: fetch Spamhaus
  DROP v4/v6 (JSONL, direct from source) and DShield top-20, validate
  against each feed's real grammar, and reconcile into block4/block6 with
  a 25h monotonic TTL, so every failure decays to no enforcement.
- Ownership by journal plus compare-and-swap on the written expiry value:
  feed entries coexist with responder and operator entries in the same
  maps and are never confused with them; a FAILED feed performs zero
  withdrawals (invariant W1).
- Safety gates: firehol level1 rejected at source selection (its
  fullbogons component contains RFC1918 and 100.64.0.0/10, confirmed
  live); allowlist snapshot gate; canary-coverage aborts the whole feed;
  aggregate address-space coverage cap; composition churn brake;
  entry-count and map-headroom caps.
- Double activation gate: a feed enforces only when listed in the config
  AND recorded in approved.json by an interactive `apply --confirm`.
  FEEDS_ENFORCE=no dry-run with reviewable diffs is the mandatory first
  mode.
- Observability: ng.feeds_* kv fields (persistent across reboot), zabbix
  items and per-feed triggers, including the config-drift tripwire.

## Impact

- Affected specs: new capability `feed-loading`.
- Affected code: new bin/nodeguard-feeds, units/nodeguard-feeds.service
  and .timer, hosts/example-gateway/feeds.conf; modified bin/ngmap.py
  (contains_protected extraction; update_map/delete_key raise instead of
  exiting), bin/nodeguard-status, deploy/deploy.sh,
  templates/zabbix-nodeguard-template.json.
- Out of scope: feodo_c2 (deferred: 5-minute churn versus 25h TTL),
  firehol level2 (different false-positive class), any XDP program or map
  change, any change to responder or sweeper behavior.
- Licensing: Spamhaus attribution retained with snapshots, fetch cadence
  far under their cap. DShield block.txt is CC BY-NC-SA 2.5; an explicit
  internal-defensive-use judgment is required before dshield_top20 is
  promoted out of dry-run.
