#!/usr/bin/env python3
"""ngmap.py: the single place that encodes, decodes, and mutates nodeguard's
pinned BPF maps. Every CLI (nodeguard-block, -list, -sweep, ...) shells into
this file so the LPM key layout exists in exactly one tested implementation.

Key layout (matches src/nodeguard_kern.c, x86_64):
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

# Addresses that must never be blockable regardless of allow-map contents.
NEVER_BLOCK = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12",
    "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16", "224.0.0.0/4",
    "255.255.255.255/32",
    "::1/128", "fe80::/10", "fd00::/8", "ff00::/8",
)]


def die(msg, code=1):
    print(f"ngmap: {msg}", file=sys.stderr)
    sys.exit(code)


def bpftool(*args, parse_json=False):
    cmd = [BPFTOOL] + (["-j"] if parse_json else []) + list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True)
    except OSError as e:
        raise RuntimeError(f"cannot execute {BPFTOOL}: {e}") from e
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: {r.stderr.strip()}")
    return json.loads(r.stdout) if parse_json else r.stdout


def mono_ns():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)


def parse_net(text):
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError as e:
        die(f"not an IP or CIDR: {text} ({e})")


def key_bytes(net):
    addr = net.network_address.packed
    return struct.pack("<I", net.prefixlen) + addr


def bytes_to_args(b):
    return [f"0x{x:02x}" for x in b]


def args_to_bytes(hexlist):
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
        if "ENOENT" in str(e) or "No such file or directory" in str(e):
            return None
        raise
    if not e or "value" not in e:
        return None
    return args_to_bytes(e["value"])


def map_path(net, kind):
    return f"{PIN}/{kind}{4 if net.version == 4 else 6}"


def decode_key(raw):
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
    bpftool("map", "update", "pinned", path, "key", *bytes_to_args(key),
            "value", *bytes_to_args(value))


def delete_key(path, key):
    try:
        bpftool("map", "delete", "pinned", path, "key", *bytes_to_args(key))
    except RuntimeError as e:
        if "No such file or directory" in str(e) or "ENOENT" in str(e):
            if not os.path.exists(path):
                die(f"map {path} is not pinned; is nodeguard-maps.service "
                    "running?")
            return False  # key already gone; tolerated by contract
        raise
    return True


def load_allow_files(files):
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
    nets = []
    for path in (f"{PIN}/allow4", f"{PIN}/allow6"):
        for k, _ in dump_map(path):
            nets.append(decode_key(k))
    return nets


def is_protected(addr, extra_nets=()):
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
        # For a CIDR, also refuse if it CONTAINS a protected range.
        for p in NEVER_BLOCK + allow_entries_live():
            if p.version == net.version and p.subnet_of(net):
                reason = f"contains protected range {p}"
                break
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
    net = parse_net(a.target)
    if delete_key(map_path(net, "block"), key_bytes(net)):
        print(f"unblocked {net}")
    else:
        print(f"{net} was not blocked")


def cmd_list(a):
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
    n = 0
    for ver in (4, 6):
        path = f"{PIN}/block{ver}"
        for k, _ in list(dump_map(path)):
            if delete_key(path, k):
                n += 1
    print(f"flushed {n} entries")


def cmd_sweep(_a):
    now = mono_ns()
    n = 0
    for ver in (4, 6):
        path = f"{PIN}/block{ver}"
        # Two race directions: a snapshot entry may vanish (ENOENT is
        # tolerated) and a snapshot key may be re-blocked after the
        # snapshot. Each candidate is therefore re-looked-up under the
        # same lock cmd_block writes with, and deleted only if it is
        # still expired against the sweep-start clock. On any other
        # lookup error the delete is skipped: leaving a corpse is
        # harmless, deleting a fresh block is not.
        for k, v in list(dump_map(path)):
            expiry, _hits = struct.unpack("<QQ", v)
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
            finally:
                lock.close()
    print(f"swept {n} expired entries")


def cmd_stats(a):
    out = {}
    for k, vals in dump_map(f"{PIN}/stats"):
        idx = struct.unpack("<I", k)[0]
        total = sum(struct.unpack("<Q", v)[0] for v in vals)
        if idx < len(STAT_NAMES):
            out[STAT_NAMES[idx]] = total
    if a.json:
        print(json.dumps(out))
    else:
        for name, v in out.items():
            print(f"{name:<16} {v}")


def cmd_get_config(a):
    for k, v in dump_map(f"{PIN}/config"):
        if struct.unpack("<I", k)[0] == a.slot:
            print(struct.unpack("<Q", v)[0])
            return
    die(f"config slot {a.slot} not found")


def cmd_set_config(a):
    if a.slot == 0 and not (1 <= a.value <= 65535):
        die(f"wg_port {a.value} out of range 1-65535")
    update_map(f"{PIN}/config", struct.pack("<I", a.slot),
               struct.pack("<Q", a.value))


def cmd_allow_check(a):
    # Exit 0 = protected, 1 = blockable, 3 = could not determine (callers
    # must fail toward NOT blocking on 3).
    try:
        reason = is_protected(a.target, allow_entries_live())
    except (RuntimeError, OSError, ValueError) as e:
        die(f"allow-check failed for {a.target}: {e}", code=3)
    if reason:
        print(reason)
        sys.exit(0)
    sys.exit(1)


def cmd_allow_dump(_a):
    print(json.dumps([str(n) for n in allow_entries_live()]))


def cmd_create_maps(a):
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
        # Only a brand-new config map gets kill switch 0. An existing value
        # is preserved so a maps restart can never silently re-arm.
        update_map(f"{PIN}/config", struct.pack("<I", 1), struct.pack("<Q", 0))
        print("INITIALIZED config kill_switch=0")


def cmd_reconcile_allow(a):
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
