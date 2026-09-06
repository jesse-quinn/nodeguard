# telemetry-observability Specification

## Purpose
Give nodeguard operators a truthful, fail-open view of what the XDP
firewall and Suricata pipeline are doing, without ever letting observation
change enforcement. This capability defines the count-only kernel telemetry
(the `stats2` protocol-sanity counters, every branch resolving to
XDP_PASS), the once-a-minute userspace kv export whose every metric fails
toward visible-unknown rather than a silent zero, the O(1) single-writer
sweep cache that keeps blocklist-sized work off the minute path, the
untrainable gateway-local anomaly detector that never mutates the kill
switch, and the Zabbix master/dependent template and fleet-scaling
dashboards built on top. It exists so a 2am reader can tell "attached and
quiet" from "blind", and so adding a host is a group membership change, not
a dashboard rewrite.

## Requirements

### Requirement: Kernel telemetry SHALL be count-only in every enforcement state
Every branch added for telemetry SHALL resolve to XDP_PASS; sanity
anomalies SHALL be counted on every packet that passes IP header
validation, in every enforcement state, including while the kill switch
is latched.

#### Scenario: crafted probes are counted and pass
- WHEN NULL, XMAS, SYN+FIN, SYN+RST, low-TTL, and fragmented probes are
  sent through the program in the netns rehearsal
- THEN each corresponding stats2 counter increments, at most one flag
  counter per packet, and every probe still reaches a listening socket

#### Scenario: kill-switch latch does not blind the counters
- WHEN the kill switch is latched and scan traffic continues to arrive
- THEN the stats2 counters keep advancing, because the sanity block
  executes before the kill-switch gate, and no packet is dropped by any
  telemetry branch

#### Scenario: malformed TCP header falls through uncounted
- WHEN a packet passes IP header validation but its TCP header fails
  the bounds check
- THEN no parsefail counter increments for it (the IP header was valid)
  and the packet continues through the normal verdict path

### Requirement: Map changes SHALL be additive and reloads hitless in both directions
Telemetry SHALL add a new pinned map, never resize an existing pinned
map; the map list used by build, spec generation, cleanup, and identity
verification SHALL be derived from the object rather than hardcoded;
and reload SHALL be hitless in both the forward and rollback
directions.

#### Scenario: forward reload with the new pin present
- WHEN the new object is reloaded after create-maps has pinned stats2
- THEN the identity check verifies every referenced pin matches the
  pinned id, the core six maps are all present, existing counters stay
  monotonic across the swap, and no carrier transition occurs

#### Scenario: rollback reload ignores the unreferenced pin
- WHEN the previous object, which does not reference stats2, is
  reloaded while the stats2 pin exists
- THEN the reload succeeds hitlessly, the pin remains in place
  unreferenced, and its counters are preserved for a later roll-forward

#### Scenario: pre-load guard refuses spec-listed-but-unpinned
- WHEN reload or attach is invoked while any map listed in the
  installed spec has no pin under the pin directory
- THEN the loader is not invoked, and the error names the exact
  recovery command that runs create-maps against the installed spec

#### Scenario: spec generation cannot silently omit a map
- WHEN the build generates the map spec from a throwaway load
- THEN the build fails unless the derived pin set contains the core six
  maps and equals the object's BTF-declared map set

### Requirement: Every metric SHALL fail toward visible unknown, never silent zero
A value that cannot be read SHALL be omitted from the kv output so its
dependent item goes unsupported, accompanied by an explicit fail flag
where the failure is a local tool breaking; no read or parse failure
SHALL ever be rendered as a zero.

#### Scenario: stats read failure with the pin present
- WHEN the stats pin exists but the dump or parse fails
- THEN no counter lines are emitted, ng.stats_read_fail=1 is emitted,
  and the counters' unsupported state plus the fail flag both raise
  Warning triggers

#### Scenario: suricatasc failure omits the keys
- WHEN the suricatasc call times out, errors, or fails to parse
- THEN the kernel_drops and suricata_alerts lines are omitted entirely,
  their items go unsupported, and a trigger on the unsupported state
  fires, so a wedged capture never reads as zero drops

#### Scenario: reboot truncates the sweep cache
- WHEN the host reboots and map creation runs
- THEN the map-statistics cache and hits snapshot are truncated, the
  count keys are omitted until the first post-boot sweep completes, and
  pre-reboot totals are never served against freshly emptied maps

#### Scenario: prog_match is absent when the expectation file is missing
- WHEN the interface is attached but the expected-program-id file does
  not exist
- THEN no prog_match line is emitted and the item goes unsupported,
  rather than reporting a silent 1 or a false-paging 0

### Requirement: The minute path SHALL be O(1) with a single-writer sweep cache
The 1-minute kv collection SHALL perform no work proportional to
blocklist population; map counts, utilization, and top-blocked SHALL be
sourced exclusively from a cache file written atomically by exactly one
writer, the 10-minute sweep, which also exports its own walk duration.

#### Scenario: the live walk is unreachable from the kv path
- WHEN the kv code path of the status tool is inspected
- THEN no invocation of the live list dump is reachable from it; the
  live count runs only in the operator-invoked human-output branch

#### Scenario: feeds does not write the cache
- WHEN a feeds apply completes and fresh counts are wanted
- THEN feeds triggers a one-off sweep run instead of writing the cache
  itself, so the file never reflects a single writer's partial view of
  maps that have three writers

#### Scenario: a stalled sweep is visible
- WHEN the sweep stops running
- THEN the cache keys keep their last values while a first-class age
  key grows past its alarm threshold and an independent trigger on the
  sweep timer's state fires

### Requirement: Anomaly detection SHALL be untrainable by its own subject and SHALL never mutate enforcement
The gateway-local detector SHALL exclude at-or-above-threshold cycles
from baseline updates with a bounded adaptation streak, SHALL discard
and reseed on any regime change (kill-switch, attach, feeds-enforce
state, or a reload within the cycle), and SHALL never modify the kill
switch, latch files, or any map.

#### Scenario: an attack cannot train the detector into silence
- WHEN deltas at or above the trip threshold arrive on consecutive
  cycles
- THEN the mean and deviation are not updated by those cycles, the trip
  fires after the configured consecutive count, and only after the
  bounded skip streak is exhausted does the baseline absorb the new
  level

#### Scenario: recovery from a latch does not false-trip
- WHEN the kill-switch state changes between cycles, such as the
  once-per-boot re-arm ending a multi-hour latch
- THEN that cycle is discarded and the baseline state reseeded, so the
  recovery surge cannot fire an anomaly against a decayed baseline

#### Scenario: the detector observes only
- WHEN an anomaly trips
- THEN the cumulative count and timestamp are exported and a CRITICAL
  journal line records metric, delta, and threshold, and no enforcement
  state of any kind is changed

#### Scenario: shadow mode precedes enforcement of attention
- WHEN the detector first ships
- THEN it runs in shadow mode, exporting a shadow count while the real
  count stays zero, and thresholds are promoted only after a reviewed
  shadow window cross-checked against reload journal lines

### Requirement: Template migration SHALL preserve item identity
The generated v2 template SHALL carry over every existing object's uuid
and display name verbatim from the committed v1, minting new uuids only
for genuinely new objects, and the live import SHALL be gated by a
scratch-template rehearsal proving itemids survive the upgrade.

#### Scenario: regeneration does not churn identity
- WHEN the generator renders the v2 template
- THEN every object present in v1 keeps its uuid and byte-identical
  display name, verified by the checker against the committed v1, so
  no item is deleted and recreated and no history is lost

#### Scenario: scratch rehearsal gates the live import
- WHEN the v2 template is ready for the live server
- THEN v1 then v2 are first imported into a scratch template, itemid
  preservation across the upgrade is confirmed, and at least one
  dependent item is shown parsing a real kv blob, before the live
  template is touched

#### Scenario: dependent parsing is proven against real output
- WHEN the template checker runs in the build
- THEN every generated preprocessing regex is executed against a
  captured real kv file and every templated field extracts a value,
  and template keys are cross-checked against the documented kv key
  list

### Requirement: Dashboards SHALL scale with the fleet without widget rework
The Zabbix host group SHALL be the canonical fleet definition; every
widget that supports group or pattern addressing SHALL use it, and
per-host-enumerated widgets SHALL be generated from live group
membership, so onboarding a host requires no code or widget edit.

#### Scenario: synthetic third host drill
- WHEN the generator plan is run with a synthetic third host added to
  the group
- THEN the plan output covers the new host in every dashboard with no
  code edit, and item name patterns match the new host's items without
  change

#### Scenario: no fleet identity in the public generator
- WHEN the public generator directory is reviewed
- THEN no real host name, host-name prefix, or server URL appears in
  it; the group name, host pattern, and URL arrive from the private
  wrapper, and the token arrives only via the environment

### Requirement: Documentation SHALL be refreshed and verified against the tree
The design document, ADRs, changelog, README, legend, and configuration
examples SHALL be updated to describe the shipped system, with every
factual claim re-verified against the tree in the same sitting rather
than patched by diff.

#### Scenario: stale claims are removed with evidence
- WHEN the design document's risk and roadmap sections are revised
- THEN risks the tree proves resolved are removed, new measured risks
  are added with their citations and mitigations, and each retained
  claim is grep-verified against the current tree
