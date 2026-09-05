# alert-to-block-response Specification

## ADDED Requirements

### Requirement: Act only on qualifying alert events
The responder SHALL process only EVE records with `event_type` alert and
SHALL consider a candidate for blocking only when the alert has severity 1
or its signature id is explicitly opted in via the SID configuration, and
the signature id is not on the deny list. All other events and severities
SHALL be log-only.

#### Scenario: Severity 2 alert without opt-in
- **WHEN** an alert with severity 2 fires and its SID is not opted in
- **THEN** no block is inserted; the alert is available for review and later SID promotion

#### Scenario: Non-alert event types
- **WHEN** the EVE stream carries flow, dns, anomaly, or stats records
- **THEN** the responder ignores them entirely

### Requirement: Require bidirectional TCP flow evidence before any automated block
The responder SHALL block only when the alert's protocol is TCP and its
flow counters show bidirectional exchange with at least one packet to the
client and at least two packets to the server, so that a blind spoofed
packet can never insert a block. UDP and ICMP alerts SHALL be log-only
unless the specific SID is promoted by hand with a written justification of
why blind spoofing does not apply to that signature.

#### Scenario: Spoofed single-packet alert
- **WHEN** a severity 1 alert fires on a single spoofed UDP or ICMP packet whose source is a forged address of a needed remote service
- **THEN** no block is inserted; the responder logs the alert as ineligible

#### Scenario: TCP alert lacking return traffic
- **WHEN** a TCP alert's flow counters show zero packets to the client
- **THEN** no block is inserted, because the flow was never answered by the host

#### Scenario: Confirmed bidirectional TCP flow
- **WHEN** a severity 1 TCP alert carries flow counters with at least one packet to the client and at least two to the server, and every other gate passes
- **THEN** the source address is blocked with the configured TTL

### Requirement: Block inbound sources only, after an allowlist recheck
The responder SHALL take only the alert's source address as a candidate,
only when the destination address is within the configured home networks
and the source is globally routable, and SHALL recheck the candidate
against the live allow maps and the never-block ranges in userspace before
inserting, with the in-kernel allowlist as the backstop. It MUST NOT block
destination addresses or remotes of outbound-triggered alerts.

#### Scenario: Alert on outbound traffic
- **WHEN** an alert fires whose destination is outside the home networks
- **THEN** no block is inserted

#### Scenario: Candidate covered by the allowlist
- **WHEN** a candidate source address matches an allow source, a protected remote, or a never-block range
- **THEN** no block is inserted and the skip is logged

### Requirement: Cap the rate of automated blocks
The responder SHALL insert at most a configured number of new blocks per
rolling minute and a configured number of distinct additions per hour
(defaults 30 and 500); on breach it SHALL stop adding, log loudly, and keep
counting rather than exiting.

#### Scenario: Alert flood
- **WHEN** qualifying alerts arrive faster than the per-minute cap
- **THEN** blocks beyond the cap are not inserted, the breach is logged, and existing blocks continue to expire normally

### Requirement: Bound every automated block with a TTL that only real evidence can extend
Every responder-inserted block SHALL carry a finite TTL (default one hour);
the responder MUST NOT write permanent entries. A re-alert SHALL refresh
the TTL only if it itself passes the full pipeline including the
anti-spoofing gate, and repeat offenders SHALL have their TTL doubled up to
a configured maximum (default one day).

#### Scenario: Spoofer attempts renewal
- **WHEN** a spoofed packet triggers an alert against an already-blocked address
- **THEN** the block's TTL is not refreshed, because the renewal alert fails the anti-spoofing gate

#### Scenario: Repeat offender
- **WHEN** an address that was blocked before qualifies again after expiry
- **THEN** the new block's TTL is doubled from the previous one, capped at the configured maximum

### Requirement: Ship a mandatory dry-run mode
The responder SHALL support a mode in which it evaluates the full pipeline
and logs WOULD BLOCK lines (including UDP/ICMP-ineligible lines) but writes
nothing, and this mode SHALL be the default and the mandatory first-run
mode. Enforcement is enabled per host only by explicit operator
configuration after reviewing the dry-run output.

#### Scenario: Dry run touches nothing
- **WHEN** the responder runs with enforcement disabled and a fully qualifying alert arrives
- **THEN** a WOULD BLOCK line is logged with address, SID, signature, and TTL, and no map is modified

### Requirement: Keep a pruned journal and never replay old alerts
The responder SHALL record its blocks in a durable journal (address, SID,
first and last seen, expiry, count), prune entries older than a retention
window on start and daily, and on start SHALL seek to the end of the alert
stream rather than replaying history. Journal entries MUST NOT be re-armed
into the maps after a reboot.

#### Scenario: Restart does not replay
- **WHEN** the responder restarts against an alert file containing hours of history
- **THEN** it seeks to the end and processes only new records

#### Scenario: Reboot leaves blocks expired
- **WHEN** the host reboots
- **THEN** the maps start empty and the journal is retained for review only; no block is reinserted from it
