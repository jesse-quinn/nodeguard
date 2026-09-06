#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""ngmap.py: the single place that encodes, decodes, and mutates nodeguard's
pinned BPF maps. Every CLI (nodeguard-block, -list, -sweep, ...) shells into
this file so the LPM key layout exists in exactly one tested implementation.

INVARIANT: key layout matches src/nodeguard_kern.c, x86_64. Dependents:
src/nodeguard_kern.c structs, nodeguard-maps.spec.
  lpm_v4_key: u32 prefixlen (little-endian) + 4 addr bytes (network order)
  lpm_v6_key: u32 prefixlen (little-endian) + 16 addr bytes (network order)
  block value: u64 expiry_ns (CLOCK_MONOTONIC, 0 = permanent) + u64 hits, LE
  allow value: u8 tag (1 = static file entry, 2 = generated protected remote)
  config: ARRAY u32 -> u64, slots: 0 wg_port (host order), 1 kill switch,
          2 watchdog re-arm count, 3 reserved
  stats: PERCPU_ARRAY u32 -> u64, 8 slots
"""

import argparse
import fcntl
import ipaddress
import json
import os
import struct
import subprocess
import sys
import time

PIN = "/sys/fs/bpf/nodeguard"
BPFTOOL = "/usr/sbin/bpftool"

STAT_NAMES = [
    "pass", "drop_v4", "drop_v6", "pass_expired",
    "pass_allowlist", "pass_wgport", "pass_nonip", "pass_parsefail",
]

# INVARIANT: lockstep with the stats2 enum in src/nodeguard_kern.c;
# append-only, reserved slots unnamed.
STATS2_NAMES = [
    "tcp_synfin", "tcp_synrst", "tcp_null", "tcp_xmas",
    "ttl_low", "frag_v4", "frag_v6",
]

MAPSTAT = "/var/lib/nodeguard/mapstat.kv"
SWEEP_HITS = "/var/lib/nodeguard/sweep_hits.json"
SPEC = "/usr/local/lib/nodeguard/nodeguard-maps.spec"

# INVARIANT: addresses that must never be blockable regardless of
# allow-map contents; enforced by is_protected() for every block and
# allow-check call in this file.
NEVER_BLOCK = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
    "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "224.0.0.0/4",
    "255.255.255.255/32",
    "::1/128", "fe80::/10", "fd00::/8", "ff00::/8",
)]


def die(msg, code=1):
    """Print an error prefixed with the tool name to stderr and exit; the single failure path shared by every command in this file."""
    print(f"ngmap: {msg}", file=sys.stderr)
    sys.exit(code)


def bpftool(*args, parse_json=False):
    """Run the bpftool binary and return its output; the one place this file shells out to the kernel's BPF map tooling."""
    cmd = [BPFTOOL] + (["-j"] if parse_json else []) + list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
    except OSError as e:
        raise RuntimeError(f"cannot execute {BPFTOOL}: {e}") from e
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {r.stderr.strip()}")
    return json.loads(r.stdout) if parse_json else r.stdout


def mono_ns():
    """Return the current CLOCK_MONOTONIC time in nanoseconds, the clock base for every block-map expiry value."""
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)


def parse_net(text):
    """Parse operator-supplied text into an IP network (a bare address becomes a host route), dying with a clear message if it is not valid."""
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError as e:
        die(f"not an IP or CIDR: {text} ({e})")


def key_bytes(net):
    """Encode an IP network into the packed LPM map key bytes the kernel expects (prefix length followed by the address)."""
    addr = net.network_address.packed
    return struct.pack("<I", net.prefixlen) + addr


def bytes_to_args(b):
    """Turn a byte string into the list of 0xNN hex tokens bpftool takes on its command line."""
    return [f"0x{x:02x}" for x in b]


def args_to_bytes(hexlist):
    """Turn bpftool's list of hex string tokens back into a Python byte string; the inverse of bytes_to_args."""
    return bytes(int(x, 16) for x in hexlist)


BLOCK_LOCK = "/run/nodeguard/block.lock"


def block_lock():
    """Inter-process lock serializing block-map write/delete pairs. Held
    per key, never around a whole sweep, so a sweep delays a fresh block
    by at most one lookup+delete."""
    os.makedirs(os.path.dirname(BLOCK_LOCK), exist_ok=True)
    f = open(BLOCK_LOCK, "w")
    fcntl.flock(f, fcntl.LOCK_EX)
    return f


def lookup_value(path, key):
    """Value bytes for one key, or None if absent."""
    try:
        e = bpftool("map", "lookup", "pinned", path, "key",
                    *bytes_to_args(key), parse_json=True)
    except RuntimeError as e:
        # A lookup MISS returns nonzero; bpftool's message for it varies
        # by version ("Not found", or empty stderr, rc 254). When the map
        # pin exists, a failed lookup means the key is absent, not an
        # error; only a genuinely unpinned map is raised.
        if os.path.exists(path):
            return None
        raise
    # a miss with -j prints JSON null -> None
    if not e or not isinstance(e, dict) or "value" not in e:
        return None
    return args_to_bytes(e["value"])


def map_path(net, kind):
    """Return the pinned-map filesystem path for a given map kind and a network's address family (e.g. block4 versus block6)."""
    return f"{PIN}/{kind}{4 if net.version == 4 else 6}"


def decode_key(raw):
    """Decode packed LPM map key bytes back into an IP network; the inverse of key_bytes, used when reading maps."""
    prefixlen = struct.unpack("<I", raw[:4])[0]
    addr = ipaddress.ip_address(raw[4:])
    return ipaddress.ip_network(f"{addr}/{prefixlen}", strict=False)


def dump_map(path):
    """Yield (key_bytes, value_bytes) for each entry; empty map yields nothing."""
    try:
        entries = bpftool("map", "dump", "pinned", path, parse_json=True)
    except RuntimeError as e:
        if "No such file" in str(e):
            raise RuntimeError(
                f"map {path} is not pinned; is nodeguard-maps.service "
                "running?") from e
        raise
    for e in entries:
        if "key" in e and "value" in e:
            yield args_to_bytes(e["key"]), args_to_bytes(e["value"])
        elif "key" in e and "values" in e:  # percpu
            yield args_to_bytes(e["key"]), [args_to_bytes(v["value"]) for v in e["values"]]


def update_map(path, key, value):
    """Insert or overwrite one entry in a pinned map via bpftool."""
    bpftool("map", "update", "pinned", path, "key", *bytes_to_args(key),
            "value", *bytes_to_args(value))


def delete_key(path, key):
    """Delete one entry from a pinned map, tolerating an already-absent key while still distinguishing that from an unpinned map."""
    try:
        bpftool("map", "delete", "pinned", path, "key", *bytes_to_args(key))
    except RuntimeError as e:
        if "No such file or directory" in str(e) or "ENOENT" in str(e):
            if not os.path.exists(path):
                raise RuntimeError(
                    f"map {path} is not pinned; is nodeguard-maps.service "
                    "running?") from e
            return False  # key already gone; tolerated by contract
        raise
    return True


def load_allow_files(files):
    """Read one or more allow-list text files (comments stripped) into a list of parsed networks."""
    nets = []
    for path in files:
        try:
            with open(path) as f:
                for line in f:
                    line = line.split("#", 1)[0].strip()
                    if line:
                        nets.append(parse_net(line))
        except FileNotFoundError:
            die(f"allow file missing: {path}")
    return nets


def allow_entries_live():
    """Return every network currently present in the live allow4/allow6 maps, the runtime snapshot of the allowlist."""
    nets = []
    for path in (f"{PIN}/allow4", f"{PIN}/allow6"):
        for k, _ in dump_map(path):
            nets.append(decode_key(k))
    return nets


def contains_protected(net, extra_nets=()):
    """A protected range fully contained inside net, or None.
    INVARIANT: the single containment check for both cmd_block and the
    feeds loader; a broad CIDR that would swallow a never-block or
    allowlisted range is refused here."""
    for p in list(NEVER_BLOCK) + list(extra_nets):
        if p.version == net.version and p.subnet_of(net):
            return p
    return None


def is_protected(addr, extra_nets=()):
    """Return a reason string if an address sits in a never-block range or a live allow entry, else None; the per-address guard against blocking something we must not."""
    ip = ipaddress.ip_address(addr)
    for net in NEVER_BLOCK:
        if net.version == ip.version and ip in net:
            return f"never-block range {net}"
    for net in extra_nets:
        if net.version == ip.version and ip in net:
            return f"allow entry {net}"
    return None


# ---------------------------------------------------------------- commands

def cmd_block(a):
    """Add a block-map entry for a target after every safety refusal (over-broad prefix, protected range, allowlisted), the CLI block command."""
    net = parse_net(a.target)
    min_len = 8 if net.version == 4 else 32
    if net.prefixlen < min_len and not a.i_mean_it:
        die(f"prefix /{net.prefixlen} is shorter than /{min_len}; "
            "pass --i-mean-it if this is deliberate")
    if a.permanent and not a.i_mean_it:
        die("--permanent requires --i-mean-it")
    if not a.permanent and a.ttl <= 0:
        die(f"--ttl {a.ttl} would create an already-expired entry that "
            "enforces nothing; permanent blocks require --permanent --i-mean-it")
    reason = is_protected(net.network_address, allow_entries_live())
    if reason is None and net.prefixlen < net.max_prefixlen:
        p = contains_protected(net, allow_entries_live())
        if p is not None:
            reason = f"contains protected range {p}"
    if reason:
        die(f"refusing to block {net}: {reason}")
    expiry = 0 if a.permanent else mono_ns() + a.ttl * 10**9
    value = struct.pack("<QQ", expiry, 0)
    lock = block_lock()
    try:
        update_map(map_path(net, "block"), key_bytes(net), value)
    finally:
        lock.close()
    print(f"blocked {net} "
          + ("permanently" if a.permanent else f"for {a.ttl}s"))


def cmd_unblock(a):
    """Remove one block-map entry for a target, reporting whether it had been blocked."""
    net = parse_net(a.target)
    if delete_key(map_path(net, "block"), key_bytes(net)):
        print(f"unblocked {net}")
    else:
        print(f"{net} was not blocked")


def cmd_list(a):
    """List every current block entry with its remaining TTL and hit count, as text or JSON."""
    now = mono_ns()
    rows = []
    for ver in (4, 6):
        for k, v in dump_map(f"{PIN}/block{ver}"):
            net = decode_key(k)
            expiry, hits = struct.unpack("<QQ", v)
            if expiry == 0:
                left = "permanent"
            else:
                left = f"{max(0, (expiry - now)) // 10**9}s"
                if now >= expiry:
                    left = "expired"
            rows.append({"net": str(net), "ttl_left": left, "hits": hits})
    if a.json:
        print(json.dumps(rows))
    else:
        for r in rows:
            print(f"{r['net']:<45} ttl={r['ttl_left']:<12} hits={r['hits']}")
        print(f"total: {len(rows)} entries")


def cmd_flush(_a):
    """Delete every entry from both block maps, the operator panic clear."""
    n = 0
    for ver in (4, 6):
        path = f"{PIN}/block{ver}"
        for k, _ in list(dump_map(path)):
            if delete_key(path, k):
                n += 1
    print(f"flushed {n} entries")


def cmd_sweep(_a):
    """TTL garbage collection PLUS the map-stats cache. SAFETY: this is
    the ONLY writer of mapstat.kv (single-writer rule, ADR 0007); the
    1-minute kv path reads the cache and never walks a trie."""
    walk_start = time.monotonic()
    now = mono_ns()
    n = 0
    counts = {4: 0, 6: 0}
    hits_now = {}
    for ver in (4, 6):
        path = f"{PIN}/block{ver}"
        # SAFETY: two race directions guarded here - a snapshot entry may
        # vanish (ENOENT is tolerated) and a snapshot key may be re-blocked
        # after the snapshot. Each candidate is therefore re-looked-up
        # under the same lock cmd_block writes with, and deleted only if
        # it is still expired against the sweep-start clock. On any other
        # lookup error the delete is skipped: leaving a corpse is
        # harmless, deleting a fresh block is not.
        for k, v in list(dump_map(path)):
            expiry, hits = struct.unpack("<QQ", v)
            counts[ver] += 1
            hits_now[str(decode_key(k))] = hits
            if not (expiry and now >= expiry):
                continue
            lock = block_lock()
            try:
                cur = lookup_value(path, k)
                if cur is None:
                    continue
                cur_expiry, _ = struct.unpack("<QQ", cur)
                if cur_expiry and now >= cur_expiry:
                    if delete_key(path, k):
                        n += 1
                        counts[ver] -= 1  # deleted this pass: not live
            finally:
                lock.close()
    print(f"swept {n} expired entries")

    # Cache write: entry counts, utilization vs the installed spec, and
    # hits ranked by DELTA since the previous walk (answers "who is
    # hitting us NOW"; the cumulative figure rides as a secondary field).
    try:
        prev = json.load(open(SWEEP_HITS))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        prev = {}
    deltas = {c: h - prev.get(c, 0) for c, h in hits_now.items()
              if h - prev.get(c, 0) > 0}
    top = sorted(deltas.items(), key=lambda kv: -kv[1])[:5]
    # cidr:delta:cumulative, delta-ranked (who is hitting us NOW), with
    # the lifetime figure carried as the secondary number per entry
    top_txt = ",".join(f"{c}:{d}:{hits_now.get(c, d)}"
                       for c, d in top) or "none"
    top1 = top[0][1] if top else 0
    # ready-to-display leaderboard rows for the dashboard (one item each)
    rank_lines = []
    for i in range(5):
        if i < len(top):
            c, d = top[i]
            rank_lines.append(f"ng.top_blocked_{i + 1}={c}  {d} new "
                              f"({hits_now.get(c, d)} total)")
        else:
            rank_lines.append(f"ng.top_blocked_{i + 1}=-")
    caps = _spec_max_entries()
    walk_ms = int((time.monotonic() - walk_start) * 1000)
    lines = [
        f"ng.blocks={counts[4] + counts[6]}",
        f"ng.blocks_v4={counts[4]}",
        f"ng.blocks_v6={counts[6]}",
        f"ng.top1_hits={top1}",
        f"ng.top_blocked={top_txt}",
        f"ng.sweep_walk_ms={walk_ms}",
        f"ng.sweep_ts={int(time.time())}",
    ] + rank_lines
    if caps.get("block4"):
        lines.append(f"ng.util_v4_pct={100 * counts[4] // caps['block4']}")
    if caps.get("block6"):
        lines.append(f"ng.util_v6_pct={100 * counts[6] // caps['block6']}")
    try:
        os.makedirs(os.path.dirname(MAPSTAT), exist_ok=True)
        with open(SWEEP_HITS + ".tmp", "w") as f:
            json.dump(hits_now, f)
        os.replace(SWEEP_HITS + ".tmp", SWEEP_HITS)
        with open(MAPSTAT + ".tmp", "w") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(MAPSTAT + ".tmp", MAPSTAT)
    except OSError as e:
        print(f"mapstat cache write failed: {e}", file=sys.stderr)


def _percpu_totals(path, names):
    """Sum a per-CPU counter map across all CPUs and label each slot by name; shared by the stats commands."""
    out = {}
    for k, vals in dump_map(path):
        idx = struct.unpack("<I", k)[0]
        total = sum(struct.unpack("<Q", v)[0] for v in vals)
        if idx < len(names):
            out[names[idx]] = total
    return out


def cmd_stats(a):
    """Print the primary packet-decision counters (pass, drops, allowlist and WG-port hits) as text or JSON."""
    out = _percpu_totals(f"{PIN}/stats", STAT_NAMES)
    if a.json:
        print(json.dumps(out))
    else:
        for name, v in out.items():
            print(f"{name:<16} {v}")


def cmd_stats2(a):
    """Print the secondary malformed-packet counters (TCP flag anomalies, low TTL, fragments) as text or JSON."""
    out = _percpu_totals(f"{PIN}/stats2", STATS2_NAMES)
    if a.json:
        print(json.dumps(out))
    else:
        for name, v in out.items():
            print(f"{name:<16} {v}")


def _spec_max_entries():
    """Read the installed map spec file to learn each map's configured capacity, used for the utilization percentages."""
    caps = {}
    try:
        with open(SPEC) as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    parts = line.split()
                    caps[parts[0]] = int(parts[4])
    except (FileNotFoundError, IndexError, ValueError):
        pass
    return caps


def cmd_get_config(a):
    """Print the value of one config-map slot (wg_port, kill switch, watchdog re-arm count)."""
    for k, v in dump_map(f"{PIN}/config"):
        if struct.unpack("<I", k)[0] == a.slot:
            print(struct.unpack("<Q", v)[0])
            return
    die(f"config slot {a.slot} not found")


def cmd_set_config(a):
    """Write one config-map slot, range-checking the WireGuard port in slot 0."""
    if a.slot == 0 and not (1 <= a.value <= 65535):
        die(f"wg_port {a.value} out of range 1-65535")
    update_map(f"{PIN}/config", struct.pack("<I", a.slot),
               struct.pack("<Q", a.value))


def cmd_allow_check(a):
    """Report via exit code whether one address is protected, blockable, or undeterminable, for operator scripting."""
    # INVARIANT: exit 0 = protected, 1 = blockable, 3 = could not
    # determine (callers must fail toward NOT blocking on 3). No in-repo
    # caller today (the responder consumes allow-dump instead); the
    # contract stands for operator scripting and future callers.
    try:
        reason = is_protected(a.target, allow_entries_live())
    except (RuntimeError, OSError, ValueError) as e:
        die(f"allow-check failed for {a.target}: {e}", code=3)
    if reason:
        print(reason)
        sys.exit(0)
    sys.exit(1)


def cmd_allow_dump(_a):
    """Print the live allowlist as a JSON array of CIDRs, the interface the responder consumes."""
    print(json.dumps([str(n) for n in allow_entries_live()]))


def cmd_create_maps(a):
    """Create each pinned map from the spec file, or verify an existing pin matches the spec and refuse attach on any mismatch."""
    spec = []
    with open(a.spec) as f:
        for line in f:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            name, mtype, ksize, vsize, entries, flags = line.split()
            spec.append((name, mtype, int(ksize), int(vsize),
                         int(entries), int(flags)))
    if not spec:
        die(f"spec file {a.spec} is empty")
    subprocess.run(["mkdir", "-p", PIN], check=True)
    created = []
    for name, mtype, ksize, vsize, entries, flags in spec:
        path = f"{PIN}/{name}"
        try:
            info = bpftool("map", "show", "pinned", path, parse_json=True)
        except RuntimeError:
            info = None
        if info is None:
            bpftool("map", "create", path, "type", mtype,
                    "key", str(ksize), "value", str(vsize),
                    "entries", str(entries), "name", name,
                    "flags", str(flags))
            created.append(name)
            print(f"CREATED {name}")
            continue
        got = (info.get("type"), info.get("bytes_key"),
               info.get("bytes_value"), info.get("max_entries"),
               int(info.get("flags", 0)))
        want = (mtype, ksize, vsize, entries, flags)
        if got != want:
            die(f"pinned map {name} does not match the spec: "
                f"have {got}, want {want}. This blocks attach BY DESIGN. "
                f"To recreate: stop nodeguard-xdp and nodeguard-responder, "
                f"rm {path}, restart nodeguard-maps (blocks in that map are "
                f"lost; allowlist is rebuilt).", code=2)
        print(f"VERIFIED {name}")
    if "config" in created:
        # SAFETY: only a brand-new config map gets kill switch 0; an
        # existing value is preserved so a maps restart can never
        # silently re-arm.
        update_map(f"{PIN}/config", struct.pack("<I", 1), struct.pack("<Q", 0))
        print("INITIALIZED config kill_switch=0")


def cmd_reconcile_allow(a):
    """Reconcile the allow4/allow6 maps to match the static and generated allow files, adding, retagging, and removing entries as needed."""
    desired = {}  # (version, key_bytes) -> tag
    static_nets = load_allow_files(a.static)
    for net in static_nets:
        desired[(net.version, key_bytes(net))] = 1
    gen_nets = load_allow_files(a.generated) if a.generated else []
    for net in gen_nets:
        k = (net.version, key_bytes(net))
        if k not in desired:
            desired[k] = 2
    if a.canary:
        canary = ipaddress.ip_address(a.canary)
        for net in static_nets + gen_nets:
            if net.version == canary.version and canary in net:
                die(f"allow sources contain the canary target {canary} "
                    f"(entry {net}); the watchdog's over-block probe would "
                    "be blind. Remove the entry.", code=2)
    added = removed = 0
    for ver in (4, 6):
        path = f"{PIN}/allow{ver}"
        current = {k: v[0] for k, v in dump_map(path)}
        want = {kb: tag for (v, kb), tag in desired.items() if v == ver}
        for kb, tag in want.items():
            if current.get(kb) != tag:
                update_map(path, kb, bytes([tag]))
                added += 1
        for kb in current:
            if kb not in want:
                delete_key(path, kb)
                removed += 1
    print(f"allow maps reconciled: {added} added/updated, {removed} removed, "
          f"{len(desired)} total")


def main():
    """Parse the subcommand and dispatch to its handler, the CLI entry point every nodeguard-* wrapper shells into."""
    p = argparse.ArgumentParser(prog="ngmap.py")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("block")
    b.add_argument("target")
    b.add_argument("--ttl", type=int, default=3600)
    b.add_argument("--permanent", action="store_true")
    b.add_argument("--i-mean-it", action="store_true")
    b.set_defaults(fn=cmd_block)

    u = sub.add_parser("unblock")
    u.add_argument("target")
    u.set_defaults(fn=cmd_unblock)

    ls = sub.add_parser("list")
    ls.add_argument("--json", action="store_true")
    ls.set_defaults(fn=cmd_list)

    sub.add_parser("flush").set_defaults(fn=cmd_flush)
    sub.add_parser("sweep").set_defaults(fn=cmd_sweep)

    st = sub.add_parser("stats")
    st.add_argument("--json", action="store_true")
    st.set_defaults(fn=cmd_stats)

    s2 = sub.add_parser("stats2")
    s2.add_argument("--json", action="store_true")
    s2.set_defaults(fn=cmd_stats2)

    gc = sub.add_parser("get-config")
    gc.add_argument("slot", type=int)
    gc.set_defaults(fn=cmd_get_config)

    sc = sub.add_parser("set-config")
    sc.add_argument("slot", type=int)
    sc.add_argument("value", type=int)
    sc.set_defaults(fn=cmd_set_config)

    ac = sub.add_parser("allow-check")
    ac.add_argument("target")
    ac.set_defaults(fn=cmd_allow_check)

    ad = sub.add_parser("allow-dump")
    ad.set_defaults(fn=cmd_allow_dump)

    cm = sub.add_parser("create-maps")
    cm.add_argument("--spec", required=True)
    cm.set_defaults(fn=cmd_create_maps)

    ra = sub.add_parser("reconcile-allow")
    ra.add_argument("--static", nargs="+", required=True)
    ra.add_argument("--generated", nargs="*", default=[])
    ra.add_argument("--canary")
    ra.set_defaults(fn=cmd_reconcile_allow)

    a = p.parse_args()
    try:
        a.fn(a)
    except RuntimeError as e:
        die(str(e))


if __name__ == "__main__":
    main()
