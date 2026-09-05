# suricata-detection Specification

## ADDED Requirements

### Requirement: Run Suricata as a passive af-packet IDS, never inline
Suricata SHALL run in passive af-packet mode on one interface per host and
MUST NOT be placed in the forwarding path in any mode (no NFQUEUE, no
af-packet copy mode, no XDP or eBPF loaded by Suricata). A stopped, hung,
or upgrading Suricata SHALL have zero traffic impact by construction.

#### Scenario: Suricata dies
- **WHEN** the Suricata process crashes or is stopped
- **THEN** traffic forwarding is unaffected; only detection coverage is lost until restart, and the unit-state monitoring item alarms

#### Scenario: Suricata never loads BPF
- **WHEN** Suricata starts with the deployed configuration
- **THEN** it attaches no XDP or eBPF program, leaving the libxdp dispatcher entirely to nodeguard

### Requirement: Emit EVE alert records carrying flow counters
The Suricata configuration SHALL write EVE JSON output restricted to alert
events with metadata enabled and flow counters included in each alert
record, because the responder's anti-spoofing gate depends on
`flow.pkts_toserver` and `flow.pkts_toclient` being present.

#### Scenario: Alert record shape
- **WHEN** a rule fires on a live flow
- **THEN** the resulting EVE record has `event_type` alert and carries the flow packet counters in both directions

#### Scenario: Verified during bring-up
- **WHEN** the shadow phase runs its end-to-end detection test
- **THEN** the operator confirms the alert record carries the flow counter fields before the responder is ever enabled

### Requirement: Update rulesets on a timer with a nonblocking reload that fails open to stale rules
A daily timer SHALL run the ruleset updater and then request a nonblocking
ruleset reload, with the reload step marked ignore-failure so that a
stopped Suricata does not fail the update unit and a broken ruleset leaves
the previous ruleset live. Detection SHALL degrade to stale rules, never to
no rules and never to blocked traffic.

#### Scenario: Broken ruleset downloaded
- **WHEN** the updater pulls a ruleset that fails to load
- **THEN** the reload fails, the previously loaded rules remain live, and traffic is unaffected

#### Scenario: Update fires while Suricata is stopped
- **WHEN** the timer runs and Suricata is not running
- **THEN** the update unit still succeeds (the reload step's failure is ignored) and the fresh rules are picked up at the next Suricata start

### Requirement: Bound Suricata's resources and keep the bound honest
Each host's Suricata SHALL run under explicit CPU and memory limits sized
from measured steady-state and reload-peak usage during the shadow phase,
because a nonblocking ruleset reload builds the new detect engine beside
the old and peaks near twice steady state. Capture drops and restart
counts SHALL be observable through the status tooling and monitoring.

#### Scenario: Reload peak exceeds a guessed cap
- **WHEN** the shadow phase measures a reload-peak RSS above the provisional memory cap
- **THEN** the cap is raised with headroom above the measured peak, or the ruleset is trimmed until it fits; the provisional value never ships as final

#### Scenario: Crash loop under memory pressure
- **WHEN** Suricata is OOM-killed and restarts repeatedly
- **THEN** the restart-count monitoring trigger alarms rather than the loop continuing silently
