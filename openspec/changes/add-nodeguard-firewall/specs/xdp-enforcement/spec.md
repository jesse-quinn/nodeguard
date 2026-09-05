# xdp-enforcement Specification

## ADDED Requirements

### Requirement: Fail open on anything the program cannot parse
The XDP program SHALL return XDP_PASS for every non-IP ethertype and for
every bounds-check or parse failure, counting each in the stats map, and
MUST NOT drop any packet it could not fully parse. The only permitted drop
is an unexpired blocklist hit on a parsed source address.

#### Scenario: Truncated or malformed frame
- **WHEN** a frame fails any bounds check during parsing
- **THEN** the program returns XDP_PASS and increments the parse-failure counter

#### Scenario: Non-IP traffic
- **WHEN** an ARP, LLDP, or other non-IP frame arrives, with or without one 802.1Q tag
- **THEN** the program returns XDP_PASS and increments the non-IP counter

### Requirement: Check the allowlist before the blocklist in the datapath
The XDP program SHALL look up the packet's source address in the allow maps
before any blocklist lookup, and an allowlist hit SHALL return XDP_PASS
unconditionally, so that no userspace ordering bug can cause a protected
range to be dropped.

#### Scenario: Address present in both maps
- **WHEN** a source address matches an allowlist prefix and also matches an unexpired blocklist entry
- **THEN** the packet passes and the allowlist counter increments; the blocklist entry is never consulted

### Requirement: Enforce block expiry in the kernel
The XDP program SHALL compare each blocklist hit's expiry against
`bpf_ktime_get_ns()` in the kernel and SHALL pass packets whose entry has
expired, counting them as expired passes. A dead responder or sweeper MUST
NOT be able to keep a block enforced past its expiry. An expiry of zero
means permanent and SHALL be reserved for manual entries; the responder
never writes zero.

#### Scenario: Entry past its expiry with all userspace dead
- **WHEN** a packet matches a blocklist entry whose expiry is nonzero and in the past, and no userspace process is running
- **THEN** the packet passes and the expired-pass counter increments

#### Scenario: Unexpired entry
- **WHEN** a packet matches a blocklist entry whose expiry is in the future
- **THEN** the packet is dropped and the entry's hit counter increments

### Requirement: Provide a kill switch that passes everything
The XDP program SHALL treat a nonzero value in the kill-switch config slot
as an instruction to pass all traffic before any allowlist or blocklist
lookup. The only sanctioned paths for changing the kill switch SHALL be the
shipped off and on commands, and a restart of the maps service MUST
preserve an existing kill-switch value rather than re-arming enforcement.

#### Scenario: Kill switch engaged
- **WHEN** the kill-switch slot is nonzero
- **THEN** every packet passes with no map lookups and no drops, while the program remains attached

#### Scenario: Maps service restart while switched off
- **WHEN** the maps service restarts and the config map already exists with the kill switch set
- **THEN** the kill-switch value is preserved, not reset to enforcing

### Requirement: Hard-pass the host's live WireGuard port
The XDP program SHALL pass UDP packets whose destination port equals the
configured WireGuard port before any blocklist lookup, so no block entry
can sever the management tunnel. Tooling SHALL keep the configured port in
step with the live bound port, rewriting it when the daemon moves.

#### Scenario: Blocked source sends WireGuard traffic
- **WHEN** a UDP packet to the configured WireGuard port arrives from an address with an unexpired blocklist entry
- **THEN** the packet passes and the WireGuard-port counter increments

#### Scenario: The tunnel daemon moves its port
- **WHEN** the daemon restarts and binds a different UDP port
- **THEN** the watchdog rewrites the config slot to the live port within one cycle and logs the change

### Requirement: Load only through the libxdp dispatcher and unload only by program id
All XDP loading SHALL go through libxdp dispatcher tooling; a raw ip-link
attach is forbidden. Detach SHALL unload the recorded program id only and
MUST NOT use an unload-all operation outside the documented last-resort
manual rollback, so coexisting dispatcher members survive restarts. Native
mode is required; a failed native attach SHALL fail the unit visibly with
no silent generic-mode fallback.

#### Scenario: Restart with another dispatcher member present
- **WHEN** the XDP service restarts while a break-glass filter or capture program shares the dispatcher
- **THEN** only the recorded nodeguard program id is unloaded and reloaded; the other members remain attached

#### Scenario: Native attach fails
- **WHEN** the driver rejects a native-mode attach
- **THEN** the unit fails visibly, the host runs with an unfiltered datapath, and monitoring alarms; no generic-mode attach is attempted automatically

### Requirement: Verify pinned maps against a spec generated from the object
The build SHALL generate a map spec (type, key size, value size, max
entries, flags per map) from the compiled object, and the maps service
SHALL create or verify pins only from that spec, failing loudly on any
mismatch rather than recreating maps. After attach, the wrapper SHALL
verify that the attached program's map ids are the pinned maps' ids and
SHALL unload its own program and fail if they diverge, so a silently inert
firewall is structurally impossible.

#### Scenario: Spec drift against existing pins
- **WHEN** the maps service finds an existing pinned map whose parameters differ from the deployed spec
- **THEN** it fails with explicit operator instructions and does not recreate or shadow the map

#### Scenario: Attached program not using the pinned maps
- **WHEN** the post-attach verification finds the program's map ids differ from the pinned map ids
- **THEN** the wrapper unloads its own program by id and exits nonzero
