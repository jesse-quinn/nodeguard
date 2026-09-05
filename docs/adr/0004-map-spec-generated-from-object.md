# 0004 - Generate the map spec from the compiled object and refuse pin drift

## Status

accepted, 2026-09-04

## Context

The pinned maps must exist before the program attaches: a maps service creates
the pins, loads the allowlist, and writes config, and only then does the
attach unit run, so enforcement never starts with an empty allowlist or an
uninitialized kill switch. That ordering means two independent artifacts
describe the same maps: the BTF declarations compiled into nodeguard_kern.o
and whatever the maps service uses to create the pins.

libbpf reuses a pinned map only on an exact parameter match (type, key size,
value size, max_entries, flags). If a hand-written creation script drifts from
the object's declarations, one of two things happens: every attach fails at
boot, or, worse, the loader silently creates parallel unpinned maps and the
program enforces against maps nobody manages, an inert firewall that looks
attached and healthy. Both hosts share one object, so a drift defect ships to
both.

## Decision

The compiled object is the single source of truth, and every consumer is
machine-verified against it:

1. build/build.sh loads the freshly compiled object into the kernel and
   extracts every map's type, key size, value size, max_entries, and flags
   into nodeguard-maps.spec (build/build.sh:23-59); the spec is generated,
   never edited.
2. ngmap.py create-maps creates missing pins from that spec and verifies
   existing pins against it; on any mismatch it fails loudly with explicit
   recovery instructions (stop the units, remove the pin, restart the maps
   service) and never silently recreates (bin/ngmap.py:268-311, mismatch
   handling at bin/ngmap.py:300-305).
3. nodeguard-attach verifies after attach that every pinned map id appears in
   the attached program's map_ids; on divergence it unloads its own program by
   id and exits nonzero, so a program enforcing against unmanaged maps is
   structurally impossible (bin/nodeguard-attach:28-55).
4. The build rehearses the exact production sequence in a netns before any
   artifact ships: create pins from the spec, attach against them, run the
   same map-identity check, exercise the encoders, unload by id
   (build/build.sh:61-95).
5. All loading goes through the libxdp dispatcher, and unload is always by
   program id, never --all (bin/nodeguard-attach:52, build/build.sh:93-94);
   --all appears only in the documented manual full-rollback procedure.

## Consequences

- Changing any map parameter (growing max_entries, widening a value struct)
  is a deliberate operation: rebuild off-host, deploy the new object and
  spec, then an operator stops the units and recreates the affected pin per
  the printed instructions, losing that map's contents. There is no silent
  migration path, on purpose.
- The spec file must travel with the object; deploying one without the other
  fails the maps service or the attach check. The sha256 emitted by the build
  is the pairing evidence.
- Unloading by id keeps the dispatcher usable for xdpdump investigations and
  break-glass xdp-filter rules across nodeguard restarts; the price is that
  the attach and detach paths must track the program id in runtime state
  rather than assuming they own the interface.
- The rehearsal makes the build environment heavier (a privileged container
  with a BTF kernel and bpffs), which is accepted: it catches verifier
  rejects and pin-reuse mismatches before production, and no compiler ever
  lands on the target hosts.
