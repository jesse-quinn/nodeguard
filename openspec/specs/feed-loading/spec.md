# feed-loading Specification

## Purpose
TBD - created by archiving change add-nodeguard-feeds. Update Purpose after archive.

## Requirements

### Requirement: Feed source selection SHALL exclude allocation-status lists
The loader SHALL consume only curated attacker-reputation feeds fetched
directly from their publishers, and SHALL NOT consume aggregate lists
whose composition includes allocation-status entries (bogons, RFC1918,
CGNAT), independently of downstream guards.

#### Scenario: firehol level1 is never fetched
- WHEN the loader configuration is inspected
- THEN no configured source resolves to an aggregate containing bogon or
  private address space, and the never-block guards remain as defense in
  depth rather than the primary control

### Requirement: Every failure SHALL decay to no enforcement
Feed entries SHALL carry an absolute in-kernel TTL such that a dead
timer, unreachable upstream, invalid download, or wedged host results in
all feed-driven enforcement expiring without any component running.

#### Scenario: upstream outage
- WHEN every fetch of a feed fails for longer than the TTL window
- THEN that feed's entries expire in-kernel and monitoring has raised
  per-feed staleness alerts before expiry completes

#### Scenario: TTL re-stamp requires a successful exchange
- WHEN a run cannot complete a successful HTTP exchange for a feed
- THEN the run does not extend any TTL for that feed from cached data

### Requirement: A FAILED feed SHALL perform zero withdrawals
Withdrawal SHALL be computed per feed against that feed's own desired
set, and a feed that failed fetch, validation, staleness, canary, or
churn checks SHALL leave its journaled entries and map entries untouched.

#### Scenario: transient upstream error
- WHEN one feed returns a server error while others succeed
- THEN the failed feed's existing entries remain and age out by TTL only,
  and the diff records no planned withdrawal for it

### Requirement: Feed entries SHALL never displace foreign entries
Every map mutation SHALL be guarded by comparing the live expiry value
against the journaled written value under the per-key lock; a live entry
not written by the loader SHALL never be modified or deleted.

#### Scenario: collision with a responder block
- WHEN a desired feed CIDR equals a key holding a live responder entry
- THEN the loader skips it, records the skip, and the responder entry is
  unaffected

#### Scenario: operator unblocks a feed entry
- WHEN the operator deletes a feed-owned key and the CIDR remains in the
  feed
- THEN the next run re-inserts it and logs that the allowlist is the
  durable suppression mechanism

### Requirement: Anomalous feed content SHALL abort rather than shrink
The loader SHALL abort the affected feed or run, with zero writes, when
candidates cover the watchdog canary address, when the aggregate address
space of a desired set exceeds the coverage cap, when the allowlist
snapshot is unavailable or empty, or when composition churn exceeds the
brake threshold pending interactive confirmation.

#### Scenario: canary coverage
- WHEN any candidate range covers the configured canary address
- THEN the entire supplying feed is FAILED for the run with zero writes,
  preserving the watchdog's over-block tripwire

#### Scenario: churn brake
- WHEN a feed's composition changes beyond the configured fraction of its
  last applied set
- THEN inserts and withdrawals are held, refreshes of still-desired keys
  proceed, and enforcement of the new composition waits for an
  interactive confirmation

### Requirement: Enforcement SHALL require a double interactive gate
A feed SHALL write to the maps only when both the deployed configuration
lists it for enforcement and a host-local approval record written by an
interactive confirm command contains it; dry-run with reviewable diffs
SHALL be the default for every new feed.

#### Scenario: config edit alone
- WHEN a feed is added to the enforcement list but never confirmed
- THEN runs produce diffs only, and the config-approval mismatch signal
  raises an alert

#### Scenario: deploy reverts a live config edit
- WHEN a deploy overwrites the host configuration and disarms enforcement
- THEN the mismatch signal alerts within two cycles while entries decay
  open

### Requirement: Feed activity SHALL be observable per feed
The loader SHALL export per-run and per-feed state (success timestamps,
snapshot age, entry and rejection counts, churn hold, journal reset) to
persistent storage consumed by the existing kv chain, with per-feed
staleness and failed-open alerts.

#### Scenario: reboot does not false-alarm
- WHEN a host reboots
- THEN previously recorded success timestamps remain visible and no
  staleness alert fires without a genuinely missed cycle
