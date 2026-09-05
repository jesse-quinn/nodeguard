# shellcheck shell=bash disable=SC2034
# Shared paths and helpers for the nodeguard CLIs. Sourced, not executed.

NG_ENV=/etc/nodeguard/nodeguard.env
NG_PIN=/sys/fs/bpf/nodeguard
NG_RUN=/run/nodeguard
NG_LIB=/usr/local/lib/nodeguard
NG_OBJ="$NG_LIB/nodeguard_kern.o"
NG_SPEC="$NG_LIB/nodeguard-maps.spec"
NG_MAP="$NG_LIB/ngmap.py"

ng_log() {
    logger -t nodeguard -p "daemon.${2:-info}" -- "$1"
    echo "$1" >&2
}

ng_env() {
    # shellcheck disable=SC1090
    [ -f "$NG_ENV" ] && . "$NG_ENV"
    : "${IFACE:?IFACE not set in $NG_ENV}"
}

ng_cfg_get() { python3 "$NG_MAP" get-config "$1"; }
ng_cfg_set() { python3 "$NG_MAP" set-config "$1" "$2"; }

# Program ids of nodeguard members currently in this interface's dispatcher.
# INVARIANT: three-valued contract - prints ids and returns 0 when the
# dispatcher was read; prints NOTHING and returns nonzero when xdp-loader
# itself failed, which callers must treat as UNKNOWN, never as detached.
# Dependents: nodeguard-watchdog, nodeguard-status, nodeguard-attach,
# nodeguard-detach, nodeguard-reload.
ng_prog_ids() {
    local out rc
    out=$(xdp-loader status "$IFACE" 2>&1)
    rc=$?
    if [ "$rc" -ne 0 ]; then
        ng_log "xdp-loader status $IFACE failed (rc=$rc): $(printf '%s' "$out" | head -1)" err
        return "$rc"
    fi
    printf '%s\n' "$out" | awk '$1 == "=>" && $3 == "nodeguard" { print $4 }'
}

# tailscaled's live WireGuard listen port, empty if not found. Prefers the
# IPv4 socket when tailscaled holds multiple distinct UDP ports.
ng_live_wg_port() {
    local ports v4
    ports=$(ss -ulpnH 2>/dev/null | awk '/"tailscaled"/ { print $4 }' \
        | sed 's/.*:\([0-9][0-9]*\)$/\1/' | sort -un)
    if [ "$(printf '%s\n' "$ports" | grep -c .)" -gt 1 ]; then
        v4=$(ss -4 -ulpnH 2>/dev/null | awk '/"tailscaled"/ { print $4 }' \
            | sed 's/.*:\([0-9][0-9]*\)$/\1/' | sort -un | head -1)
        ng_log "tailscaled holds multiple UDP ports ($(printf '%s' "$ports" | tr '\n' ' ')); preferring IPv4 socket" warning
        if [ -n "$v4" ]; then
            printf '%s\n' "$v4"
            return 0
        fi
    fi
    printf '%s\n' "$ports" | head -1
}

# INVARIANT (ADR 0007): identity is generalized so additive maps roll
# out hitlessly in BOTH directions: every map the program references
# that has a pin of the same name under $NG_PIN must carry that pin's
# id, and the core six must all be present in the program's set. An
# unreferenced extra pin (rollback to an older object) is ignored.
ng_verify_map_identity() {
    local prog_id="$1"
    python3 - "$NG_PIN" "$prog_id" <<'IDPY'
import json, subprocess, sys
pin_root, prog_id = sys.argv[1], sys.argv[2]
r = subprocess.run(["bpftool", "prog", "show", "id", prog_id, "-j"],
                   capture_output=True, text=True)
if r.returncode != 0:
    sys.exit(1)
prog = json.loads(r.stdout)
ids = prog.get("map_ids", [])
core = {"allow4", "allow6", "block4", "block6", "config", "stats"}
names = {}
for i in ids:
    r = subprocess.run(["bpftool", "map", "show", "id", str(i), "-j"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(1)
    m = json.loads(r.stdout)
    names[m.get("name")] = i
missing = core - set(names)
if missing:
    print(f"map identity: core maps missing from program: {sorted(missing)}",
          file=sys.stderr)
    sys.exit(1)
import os
ok = True
for name, prog_map_id in names.items():
    pin = os.path.join(pin_root, name or "")
    if not name or not os.path.exists(pin):
        continue
    r = subprocess.run(["bpftool", "map", "show", "pinned", pin, "-j"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        ok = False
        continue
    if json.loads(r.stdout).get("id") != prog_map_id:
        print(f"map identity: prog map {name} id {prog_map_id} != pinned",
              file=sys.stderr)
        ok = False
sys.exit(0 if ok else 1)
IDPY
}

# SAFETY (ADR 0007): refuse to load when the installed spec lists a map
# with no pin: precisely "create-maps has not run for this object
# version". Prevents libbpf silently auto-pinning outside the spec
# contract. Recovery is named because 2am.
ng_spec_pins_present() {
    local name rest ok=1
    [ -f "$NG_SPEC" ] || { ng_log "spec $NG_SPEC missing" crit; return 1; }
    while read -r name rest; do
        case "$name" in ''|'#'*) continue ;; esac
        if [ ! -e "$NG_PIN/$name" ]; then
            ng_log "spec lists map '$name' but no pin exists; run: systemctl reload nodeguard-maps" crit
            ok=0
        fi
    done < "$NG_SPEC"
    [ "$ok" -eq 1 ]
}
