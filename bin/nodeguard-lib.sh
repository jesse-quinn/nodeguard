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
ng_prog_ids() {
    xdp-loader status "$IFACE" 2>/dev/null \
        | awk '$1 == "=>" && $3 == "nodeguard" { print $4 }'
}

# tailscaled's live WireGuard listen port, empty if not found.
ng_live_wg_port() {
    ss -ulpnH 2>/dev/null | awk '/"tailscaled"/ { print $4 }' \
        | sed 's/.*:\([0-9][0-9]*\)$/\1/' | sort -u | head -1
}
