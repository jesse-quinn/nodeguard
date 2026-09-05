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

# Verify that the program with id $1 uses exactly the pinned nodeguard
# maps. Returns 0 only when every pinned map id appears in its map_ids.
ng_verify_map_identity() {
    local prog_id="$1" prog_maps pinned_id ok=1 m
    prog_maps=$(bpftool prog show id "$prog_id" -j 2>/dev/null | python3 -c \
        'import json,sys; print(" ".join(str(i) for i in json.load(sys.stdin).get("map_ids", [])))' 2>/dev/null)
    for m in allow4 allow6 block4 block6 config stats; do
        pinned_id=$(bpftool map show pinned "$NG_PIN/$m" -j 2>/dev/null | python3 -c \
            'import json,sys; print(json.load(sys.stdin)["id"])' 2>/dev/null)
        if [ -z "$pinned_id" ]; then
            ng_log "map identity: $m has no pin under $NG_PIN" crit
            ok=0
            continue
        fi
        case " $prog_maps " in
        *" $pinned_id "*) ;;
        *)
            ng_log "map identity: prog $prog_id does not use pinned $m (id $pinned_id)" crit
            ok=0
            ;;
        esac
    done
    [ "$ok" -eq 1 ]
}
