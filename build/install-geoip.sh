#!/bin/bash
# install-geoip.sh: fetch the DB-IP lite IP-to-city CSV (free, no key) and
# preprocess it ONCE into a compact binary index for nodeguard-geo, so the
# 5-minute enrichment does a fast bisect instead of re-parsing 85 MB of CSV
# (which pegs an Atom core for minutes). Run monthly or by hand. Fail-open:
# a failed fetch or preprocess keeps the existing index, never errors out.
set -uo pipefail
SHARE=/usr/local/share/nodeguard
MONTH=$(date +%Y-%m)
URL="https://download.db-ip.com/free/dbip-city-lite-${MONTH}.csv.gz"
install -d "$SHARE"
tmp=$(mktemp)
if ! curl -fsSL --max-time 180 "$URL" -o "$tmp"; then
    echo "geoip fetch failed for $MONTH; keeping existing index" >&2
    rm -f "$tmp"; exit 0
fi
if [ "$(stat -c%s "$tmp")" -lt 5000000 ] || ! gzip -t "$tmp" 2>/dev/null; then
    echo "geoip download looked wrong (size/gzip); keeping existing" >&2
    rm -f "$tmp"; exit 0
fi
# Preprocess into two files: starts (array of u32 range starts, for
# bisect) and recs (14-byte packed records in the same order). IPv4 only.
python3 - "$tmp" "$SHARE" <<'PYEOF'
import csv, gzip, ipaddress, struct, sys, array, os
src, share = sys.argv[1], sys.argv[2]
starts = array.array("I")
recs = open(os.path.join(share, "dbip.recs.tmp"), "wb")
n = 0
with gzip.open(src, "rt") as f:
    for r in csv.reader(f):
        if len(r) < 8:
            continue
        try:
            a = ipaddress.ip_address(r[0]); b = ipaddress.ip_address(r[1])
            if a.version != 4:
                continue
            s, e = int(a), int(b)
            lat = max(-32767, min(32767, round(float(r[6]) * 100)))
            lon = max(-32767, min(32767, round(float(r[7]) * 100)))
            cc = (r[3] or "??")[:2].ljust(2).encode("ascii", "replace")
        except (ValueError, IndexError):
            continue
        starts.append(s)
        recs.write(struct.pack("<IIhh2s", s, e, lat, lon, cc))
        n += 1
recs.close()
with open(os.path.join(share, "dbip.starts.tmp"), "wb") as sf:
    starts.tofile(sf)
os.replace(os.path.join(share, "dbip.recs.tmp"),
           os.path.join(share, "dbip.recs"))
os.replace(os.path.join(share, "dbip.starts.tmp"),
           os.path.join(share, "dbip.starts"))
print(f"geoip index built: {n} ranges ({MONTH})".replace("{MONTH}", os.environ.get("MONTH","")))
PYEOF
rm -f "$tmp" "$SHARE/dbip.csv.gz"
echo "geoip index ready in $SHARE (dbip.starts + dbip.recs)"
