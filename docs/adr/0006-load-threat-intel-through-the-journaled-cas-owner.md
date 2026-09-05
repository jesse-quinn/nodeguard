# 0006 - Load threat intel through a journaled compare-and-swap owner

## Status

accepted, 2026-09-05

## Context

The feeds loader (bin/nodeguard-feeds) pulls Spamhaus DROP v4/v6 and DShield
top-20 into the existing block4/block6 maps on a 6h timer with a 25h TTL. Two
questions forced a decision: which feeds are safe to consume, and who owns a
map entry when three writers share the same maps.

Feed selection evidence, confirmed live 2026-09-05:

- firehol_level1 is rejected. Its fullbogons component live-contains
  100.64.0.0/10 (the tailnet's CGNAT space) and all of RFC1918; the file's
  first line is 0.0.0.0/8 and its last is 224.0.0.0/3, and roughly 2,400 of
  its 3,939 subnets are allocation-status entries, not attacker reputation.
  Loading it would enforce against the operator's own address space; the
  in-repo NEVER_BLOCK guards would refuse those lines one by one, but the
  bogon class is excluded at source selection, with the guards kept as
  defense in depth.
- feodo_c2 is deferred. abuse.ch recommends a 5 to 15 minute refresh because
  C2 IPs recycle; against a 25h TTL, a dead job leaves a recycled IP blocked
  up to a day. It remains a dry-run candidate only, through the approval gate.

Ownership evidence: block4/block6 already have two other writers, the
responder daemon and the operator CLI (nodeguard-block/unblock). The obvious
reconcile pattern in the repo, cmd_reconcile_allow's dump-and-diff-and-prune
(bin/ngmap.py:399), is safe only because the allow maps have a single writer;
applied to the block maps it would delete every responder and operator entry
on every run. cmd_flush (bin/ngmap.py:264) is origin-blind for the same
reason. struct block_val is {u64 expiry_ns; u64 hits}
(src/nodeguard_kern.c:39-42); there is no owner field to disambiguate with.

## Decision

Ownership lives entirely in userspace state, and every mutation is a
compare-and-swap:

1. The loader keeps a journal (/var/lib/nodeguard/feeds/state.json) recording,
   per owned key, the exact expiry value it wrote (written_expiry_ns). Nothing
   else ever writes that exact u64 to that key, so a live entry whose expiry
   equals the journaled value is provably the loader's; any mismatch means
   another writer owns it now and the loader drops its claim without touching
   the map. Refresh and withdraw both compare before acting
   (bin/nodeguard-feeds:558, 628), under the existing per-key lock
   (bin/ngmap.py:89), held per key and never around the batch.
2. The reconcile baseline is the journal, never a dump of the live map. The
   loader inserts desired keys that are absent or expired, refreshes keys it
   can prove it owns, and withdraws only journaled keys whose expiry still
   matches. Live-occupied is occupied: a responder /32 or operator entry on a
   desired key is skipped and recorded in the diff.
3. Invariant W1: withdrawal is computed per feed against that feed's own
   desired set, and a feed whose fetch or validation FAILED this run performs
   zero withdrawals; its entries age out by TTL only. The assertion is
   mechanical: a FAILED feed showing any planned withdrawal fails the run
   (bin/nodeguard-feeds:535-538). A single upstream 5xx therefore cannot
   mass-withdraw ~1,700 live entries; they decay instead.
4. Activation is double-gated: a timer run writes only for feeds present in
   both the deployed config's FEEDS_APPLY and the human arming record
   /var/lib/nodeguard/feeds/approved.json (bin/nodeguard-feeds:308-311),
   which is written only by an interactive apply --confirm. This follows the
   kill-switch precedent that a restart or state loss must never silently
   change a human decision (bin/ngmap.py:391-396).

## Consequences

- Feed, responder, and operator entries are indistinguishable in-kernel:
  block_val carries no owner byte. This is deliberate; adding one is a map
  schema change, and the pinned map set is fixed (ADR 0004). The cost is that
  provenance is only as durable as the journal.
- Journal loss degrades, it does not disarm or destroy: approvals survive in
  approved.json, so the next run proceeds insert-only and rebuilds the
  journal; formerly-owned keys that collide as live-present are skipped and
  decay within 25h. The loader never deletes without proof of ownership.
- An operator's nodeguard-unblock of a feed-owned entry is reverted by the
  next run within 6 to 12h: the key is absent and still desired, so it is
  re-inserted. The durable suppression is the allowlist; the loader logs
  guidance to that effect the first time it re-inserts such a key.
- Everything fails open by construction: no successful run for a full day
  means every feed entry leaves the data path within 25h with zero components
  alive, enforced by the kernel TTL (ADR 0003).
- feodo_c2 stays out until the 25h-TTL versus 5-minute-churn tradeoff is
  accepted in writing; firehol_level1 stays out permanently unless its
  composition changes.

## Alternatives considered

- firehol_level1 as a convenient aggregate: rejected on the live evidence
  above; its bogon component blocks the operator's own networks.
- Dump-and-diff reconcile against the live map (the cmd_reconcile_allow
  pattern): rejected; correct only under a single writer, and block4/block6
  have three.
- An owner byte in block_val: rejected; a schema change to a pinned map for
  a problem userspace state solves, against ADR 0004's fixed map set.
- Trusting the config file alone to arm a feed: rejected; deploy reinstalls
  the config, so a config-only gate could re-arm or disarm a feed as a side
  effect of an unrelated deploy. The approved.json half of the gate keeps
  arming a human act.
