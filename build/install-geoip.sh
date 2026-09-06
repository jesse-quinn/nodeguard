#!/bin/bash
# install-geoip.sh: fetch the DB-IP lite IP-to-city CSV (free, no key) to
# /usr/local/share/nodeguard/dbip.csv.gz for nodeguard-geo. Run on each
# host from a monthly timer or by hand. Fail-open: if the fetch fails the
# old DB (or none) stays and geo output degrades to empty, never an error.
set -uo pipefail
DEST=/usr/local/share/nodeguard/dbip.csv.gz
MONTH=$(date +%Y-%m)
URL="https://download.db-ip.com/free/dbip-city-lite-${MONTH}.csv.gz"
install -d /usr/local/share/nodeguard
tmp=$(mktemp)
if curl -fsSL --max-time 120 "$URL" -o "$tmp"; then
    # sanity: must be a gzip with plausible size (the lite DB is tens of MB)
    if [ "$(stat -c%s "$tmp")" -gt 5000000 ] && gzip -t "$tmp" 2>/dev/null; then
        install -m 0644 "$tmp" "$DEST"
        echo "geoip DB updated: $DEST ($(stat -c%s "$DEST") bytes, $MONTH)"
    else
        echo "geoip DB fetch looked wrong (size/gzip); keeping existing" >&2
    fi
else
    echo "geoip DB fetch failed for $MONTH; keeping existing" >&2
fi
rm -f "$tmp"
