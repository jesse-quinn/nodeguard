#!/bin/bash
# deploy.sh: push the nodeguard artifact set to one host and verify it,
# WITHOUT enabling or starting anything. Run from the repo root:
#   bash deploy/deploy.sh <ssh-target> <host-config-dir>
# e.g.
#   bash deploy/deploy.sh admin@gateway.example.net /path/to/private/hosts/gateway
# The host config dir holds the per-host files (see hosts/example-gateway).
# Real deployments keep those dirs OUTSIDE this repo; never commit real
# addresses, interface names, or network layout to a public tree.
# Bring-up is deliberately manual and phased; see docs/design.md.
set -euo pipefail

SSH="${1:?usage: deploy.sh <ssh-target> <host-config-dir> [--with-kernel]}"
HOSTDIR="${2:?usage: deploy.sh <ssh-target> <host-config-dir> [--with-kernel]}"
WITH_KERNEL=0
for arg in "${@:3}"; do
    case "$arg" in
    --with-kernel) WITH_KERNEL=1 ;;
    *)
        echo "unknown argument: $arg" >&2
        echo "usage: deploy.sh <ssh-target> <host-config-dir> [--with-kernel]" >&2
        exit 2
        ;;
    esac
done
REPO="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$REPO/build/out"

[ -d "$HOSTDIR" ] || { echo "no such host config dir: $HOSTDIR"; exit 2; }
for f in nodeguard.env allow4.txt allow6.txt responder.conf feeds.conf \
         sysconfig-suricata suricata-50-limits.conf \
         nodeguard-xdp-10-device.conf suricata.yaml; do
    [ -f "$HOSTDIR/$f" ] || { echo "missing $HOSTDIR/$f (suricata.yaml comes from build.sh)"; exit 2; }
done
# SAFETY (ADR 0007): the datapath object never ships as a stowaway of a
# userspace deploy; a restart during a multi-day phase must reload the
# OLD object. Kernel artifacts move only with --with-kernel.
if [ "$WITH_KERNEL" -eq 1 ]; then
    [ -f "$OUT/nodeguard_kern.o" ] || { echo "run build/build.sh first"; exit 2; }
    [ -f "$OUT/nodeguard-maps.spec" ] || { echo "spec missing; run build/build.sh"; exit 2; }
fi

STAGE=/tmp/nodeguard-deploy
echo "== staging to $SSH:$STAGE =="
# shellcheck disable=SC2029
ssh "$SSH" "rm -rf $STAGE && mkdir -p $STAGE"
KERNEL_FILES=""
if [ "$WITH_KERNEL" -eq 1 ]; then
    KERNEL_FILES="$OUT/nodeguard_kern.o $OUT/nodeguard-maps.spec"
fi
# shellcheck disable=SC2086
scp -q $KERNEL_FILES \
    "$REPO"/bin/ngmap.py "$REPO"/bin/nodeguard-lib.sh \
    "$REPO"/bin/nodeguard-maps "$REPO"/bin/nodeguard-attach \
    "$REPO"/bin/nodeguard-detach "$REPO"/bin/nodeguard-cli \
    "$REPO"/bin/nodeguard-status "$REPO"/bin/nodeguard-reload \
    "$REPO"/bin/nodeguard-watchdog "$REPO"/bin/nodeguard-canary \
    "$REPO"/bin/nodeguard-responder "$REPO"/bin/nodeguard-feeds \
    "$REPO"/units/*.service "$REPO"/units/*.timer \
    "$REPO"/etc/protected.conf "$REPO"/etc/sids.conf \
    "$REPO"/etc/tmpfiles-nodeguard.conf "$REPO"/etc/logrotate-suricata.conf \
    "$REPO"/etc/zabbix-userparameter-nodeguard.conf \
    "$HOSTDIR"/nodeguard.env "$HOSTDIR"/allow4.txt "$HOSTDIR"/allow6.txt \
    "$HOSTDIR"/responder.conf "$HOSTDIR"/feeds.conf \
    "$HOSTDIR"/sysconfig-suricata \
    "$HOSTDIR"/suricata-50-limits.conf "$HOSTDIR"/nodeguard-xdp-10-device.conf \
    "$HOSTDIR"/suricata.yaml \
    "$SSH:$STAGE/"

echo "== installing (no unit is enabled or started) =="
ssh "$SSH" sudo /bin/bash -s <<'REMOTE'
set -euo pipefail
S=/tmp/nodeguard-deploy

# Preflight: deploy is phase 0 AFTER package install; failing early keeps
# a run from half-installing.
[ -d /etc/suricata ] || { echo "ERROR: /etc/suricata missing; install the suricata RPM first (phase 0: dnf install suricata), then re-run deploy.sh" >&2; exit 3; }

install -d -m 0755 /usr/local/lib/nodeguard /etc/nodeguard /var/lib/nodeguard /var/lib/nodeguard/feeds
if [ -f "$S/nodeguard_kern.o" ]; then
    # keep the N-1 object for hitless rollback, but only rotate when the
    # staged object actually differs: an idempotent re-run must never
    # overwrite the rollback target with the object it rolls back FROM
    cur=/usr/local/lib/nodeguard/nodeguard_kern.o
    if [ -f "$cur" ] && ! cmp -s "$S/nodeguard_kern.o" "$cur"; then
        cp -p "$cur" "$cur.prev"
    fi
    install -m 0644 "$S/nodeguard_kern.o" "$S/nodeguard-maps.spec" /usr/local/lib/nodeguard/
fi
install -m 0755 "$S/ngmap.py" /usr/local/lib/nodeguard/
install -m 0644 "$S/nodeguard-lib.sh" /usr/local/lib/nodeguard/

for f in nodeguard-maps nodeguard-attach nodeguard-detach nodeguard-cli \
         nodeguard-status nodeguard-reload nodeguard-watchdog \
         nodeguard-canary nodeguard-responder nodeguard-feeds; do
    install -m 0755 "$S/$f" /usr/local/sbin/
done
for name in block unblock list flush off on; do
    ln -sf nodeguard-cli "/usr/local/sbin/nodeguard-$name"
done

install -m 0644 "$S/nodeguard.env" "$S/allow4.txt" "$S/allow6.txt" \
    "$S/responder.conf" "$S/feeds.conf" "$S/protected.conf" "$S/sids.conf" /etc/nodeguard/

install -m 0644 "$S"/nodeguard-*.service "$S"/nodeguard-*.timer \
    "$S"/suricata-update.service "$S"/suricata-update.timer \
    /etc/systemd/system/
install -d /etc/systemd/system/nodeguard-xdp.service.d
install -m 0644 "$S/nodeguard-xdp-10-device.conf" \
    /etc/systemd/system/nodeguard-xdp.service.d/10-device.conf
install -d /etc/systemd/system/suricata.service.d
install -m 0644 "$S/suricata-50-limits.conf" \
    /etc/systemd/system/suricata.service.d/50-limits.conf
install -m 0644 "$S/tmpfiles-nodeguard.conf" /etc/tmpfiles.d/nodeguard.conf
install -d /etc/zabbix_agentd.d
install -m 0644 "$S/zabbix-userparameter-nodeguard.conf" /etc/zabbix_agentd.d/nodeguard.conf
# NOTE: this fleet's agent reads /etc/zabbix_agentd.conf (Fedora ships no
# include dir); deploy owns the Include line so the conf actually loads.
if [ -f /etc/zabbix_agentd.conf ] && \
        ! grep -q '^Include=/etc/zabbix_agentd.d/' /etc/zabbix_agentd.conf; then
    echo 'Include=/etc/zabbix_agentd.d/*.conf' >> /etc/zabbix_agentd.conf
fi
# NOTE: agent restart is a deliberate runbook step, not automated here.
systemd-tmpfiles --create /etc/tmpfiles.d/nodeguard.conf

install -m 0644 "$S/sysconfig-suricata" /etc/sysconfig/suricata
install -m 0640 -o suricata -g suricata "$S/suricata.yaml" /etc/suricata/suricata.yaml

# [18] Own eve.json rotation: replace whatever /etc/logrotate.d/suricata
# holds (stale pre-RPM configs silently win otherwise; verified on a
# live target) and clear any .rpmnew the RPM left.
install -m 0644 "$S/logrotate-suricata.conf" /etc/logrotate.d/suricata
rm -f /etc/logrotate.d/suricata.rpmnew

restorecon -Rv /usr/local/lib/nodeguard /usr/local/sbin /etc/nodeguard \
    /etc/systemd/system /etc/sysconfig/suricata 2>/dev/null | grep -v '^$' || true
systemctl daemon-reload

echo "-- verification --"
for f in /usr/local/sbin/nodeguard-maps /usr/local/sbin/nodeguard-attach \
         /usr/local/sbin/nodeguard-detach /usr/local/sbin/nodeguard-cli \
         /usr/local/sbin/nodeguard-status /usr/local/sbin/nodeguard-reload \
         /usr/local/sbin/nodeguard-watchdog /usr/local/sbin/nodeguard-canary \
         /usr/local/lib/nodeguard/nodeguard-lib.sh; do
    bash -n "$f"
done
python3 -m py_compile /usr/local/lib/nodeguard/ngmap.py /usr/local/sbin/nodeguard-responder /usr/local/sbin/nodeguard-feeds
verify_fail=0
for u in nodeguard-maps.service nodeguard-xdp.service nodeguard-responder.service \
         nodeguard-sweep.service nodeguard-watchdog.service suricata-update.service \
         nodeguard-feeds.service nodeguard-sweep.timer nodeguard-watchdog.timer \
         suricata-update.timer nodeguard-feeds.timer; do
    out=$(systemd-analyze verify "/etc/systemd/system/$u" 2>&1 | grep -v 'Unit is bound' || true)
    if [ -n "$out" ]; then
        echo "UNIT VERIFY FAILED: $u"
        printf '%s\n' "$out"
        verify_fail=1
    fi
done
grep -q '^UserParameter=nodeguard.kv.raw,' /etc/zabbix_agentd.d/nodeguard.conf \
    || { echo "zabbix agent conf missing nodeguard.kv.raw"; verify_fail=1; }
grep -q '/var/log/suricata/\*.json' /etc/logrotate.d/suricata || { echo "logrotate config missing eve.json coverage"; verify_fail=1; }
grep -vE '^[[:space:]]*#' /etc/logrotate.d/suricata | grep -q copytruncate && { echo "logrotate config uses copytruncate (loses lines)"; verify_fail=1; }
[ "$verify_fail" -eq 0 ] || { echo "deploy verification FAILED"; exit 4; }
[ -f "$S/nodeguard_kern.o" ] && sha256sum /usr/local/lib/nodeguard/nodeguard_kern.o
rm -rf "$S"
echo "deploy OK: files installed, nothing enabled or started"
REMOTE
