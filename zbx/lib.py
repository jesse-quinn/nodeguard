"""Shared library for the nodeguard Zabbix generators.

Contract:
- JSON-RPC client for the Zabbix API (7.4). The auth token comes from the
  environment variable ZTOKEN only; it is never accepted on argv and never
  printed, logged, or echoed in error messages. The API URL is always an
  explicit argument; there is no default URL in this public repository.
- Connection and API failures raise ZabbixError with a clear message so
  callers can fail gracefully without a traceback.
- Fleet resolution per the fleet-scaling rules: a host group name is the
  canonical fleet definition; resolve_group() returns the group id and its
  member hosts live, so widgets that need per-host enumeration are generated
  from the group's current membership at run time.
- Widget builders (itemvalue, gauge, svggraph, pie, honeycomb, url)
  return dashboard widget dicts for dashboard.create/update. svggraph
  and pie datasets address hosts by PATTERN and items by NAME pattern, so a
  new host's items match without a code edit; Zabbix resolves those host
  patterns against the host's VISIBLE name, not the technical name. Field
  names for gauge and honeycomb follow the 7.4 export format and must be
  verified with one plan-mode diff against a hand-exported dashboard before
  the first confirmed apply.
- 72-column grid helpers and the Okabe-Ito palette. host_color() hashes the
  host name into the palette so a host keeps its color when the fleet grows
  or the member list reorders.

Stdlib only. No mutation happens in this module beyond api() POSTs the
caller explicitly issues.
"""

import hashlib
import itertools
import json
import os
import urllib.error
import urllib.request

# Zabbix dashboard widget field types.
FIELD_INT = 0
FIELD_STR = 1
FIELD_GROUP = 2
FIELD_HOST = 3
FIELD_ITEM = 4

# Zabbix 7.x dashboards are a 72-column grid.
GRID_COLUMNS = 72

# Okabe-Ito colorblind-safe palette (hex, no leading #), grey substituted
# for black so lines stay visible on the dark theme.
OKABE_ITO = [
    "0072B2",  # blue
    "D55E00",  # vermillion
    "009E73",  # bluish green
    "CC79A7",  # reddish purple
    "E69F00",  # orange
    "56B4E9",  # sky blue
    "F0E442",  # yellow
    "999999",  # grey
]


class ZabbixError(Exception):
    """A Zabbix API call failed or could not be issued."""


def host_color(host, shift=0):
    """Stable per-host color: hash of the host name into the palette.

    The assignment depends only on the name, so colors do not shuffle when
    hosts are added to or removed from the group. shift offsets the index
    for a second metric of the same host on one graph.
    """
    idx = int(hashlib.sha256(host.encode()).hexdigest(), 16)
    return OKABE_ITO[(idx + shift) % len(OKABE_ITO)]


def split_columns(n, total=GRID_COLUMNS, x0=0):
    """Divide the grid into n equal columns; returns [(x, width), ...]."""
    if n < 1:
        return []
    w = total // n
    return [(x0 + i * w, w) for i in range(n)]


class RefSeq:
    """Unique widget reference strings (svggraph and pie require one)."""

    def __init__(self, prefix="NG"):
        self._it = (prefix + a + b + c
                    for a in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    for b in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ")

    def next(self):
        return next(self._it)


class Api:
    """Minimal Zabbix JSON-RPC client. Token from env ZTOKEN only."""

    def __init__(self, url, timeout=20):
        if not url.endswith(".php"):
            url = url.rstrip("/") + "/api_jsonrpc.php"
        self.url = url
        self.timeout = timeout
        token = os.environ.get("ZTOKEN")
        if not token:
            raise ZabbixError(
                "ZTOKEN is not set in the environment; export the API token "
                "as ZTOKEN (never pass it on the command line)")
        self._token = token
        self._id = itertools.count(1)

    def call(self, method, params):
        body = json.dumps({
            "jsonrpc": "2.0", "method": method,
            "params": params, "id": next(self._id),
        }).encode()
        req = urllib.request.Request(
            self.url, data=body,
            headers={"Content-Type": "application/json-rpc",
                     "Authorization": "Bearer %s" % self._token})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            raise ZabbixError("cannot reach Zabbix API at %s: HTTP %s %s"
                              % (self.url, e.code, e.reason))
        except (urllib.error.URLError, OSError) as e:
            reason = getattr(e, "reason", e)
            raise ZabbixError("cannot reach Zabbix API at %s: %s"
                              % (self.url, reason))
        try:
            r = json.loads(raw)
        except ValueError:
            raise ZabbixError("non-JSON response from %s to %s"
                              % (self.url, method))
        if "error" in r:
            err = r["error"]
            raise ZabbixError("%s failed: %s %s" % (
                method, err.get("message", ""), err.get("data", "")))
        return r["result"]


def resolve_group(api, group_name):
    """Host group name to (groupid, [{hostid, host, name}, ...]).

    The group is the canonical fleet definition: onboarding a host is
    linking the template and adding it to this group, then re-running the
    generator.
    """
    groups = api.call("hostgroup.get", {
        "filter": {"name": [group_name]},
        "output": ["groupid", "name"]})
    if not groups:
        raise ZabbixError("host group not found: %s" % group_name)
    gid = groups[0]["groupid"]
    hosts = api.call("host.get", {
        "groupids": [gid],
        "output": ["hostid", "host", "name"],
        "sortfield": "host"})
    if not hosts:
        raise ZabbixError("host group %s has no members" % group_name)
    return gid, hosts


def resolve_itemids(api, hostid):
    """All nodeguard item keys on one host, as {key: itemid}."""
    out = {}
    for it in api.call("item.get", {
            "hostids": [hostid],
            "search": {"key_": "nodeguard."},
            "output": ["itemid", "key_", "name"]}):
        out[it["key_"]] = it["itemid"]
    return out


def _f(ftype, name, value):
    return {"type": ftype, "name": name, "value": str(value)}


def widget(wtype, x, y, w, h, name="", fields=None):
    return {"type": wtype, "name": name, "x": x, "y": y,
            "width": w, "height": h, "fields": fields or []}


def itemvalue(x, y, w, h, name, itemid):
    """Single item value tile (widget type "item")."""
    return widget("item", x, y, w, h, name,
                  [_f(FIELD_ITEM, "itemid", itemid),
                   _f(FIELD_INT, "show.0", 2)])


def gauge(x, y, w, h, name, itemid, vmin=0, vmax=100, thresholds=()):
    """Gauge widget; thresholds is [(value, color_hex), ...]."""
    fl = [_f(FIELD_ITEM, "itemid", itemid),
          _f(FIELD_STR, "min", vmin),
          _f(FIELD_STR, "max", vmax)]
    for i, (val, color) in enumerate(thresholds):
        fl += [_f(FIELD_STR, "thresholds.%d.color" % i, color),
               _f(FIELD_STR, "thresholds.%d.threshold_value" % i, val)]
    return widget("gauge", x, y, w, h, name, fl)


def svggraph(x, y, w, h, name, datasets, refseq, stacked=False,
             legend_lines=2):
    """SVG graph. datasets is [(host_patterns, item_patterns, color), ...].

    host_patterns and item_patterns may each be a string or a list; host
    patterns match the Zabbix VISIBLE host name (API search on "name"),
    and items are addressed by display-NAME pattern per the template's
    display-name contract, so a rename would empty the graph (guarded by
    check_template.py).
    """
    fl = [_f(FIELD_STR, "reference", refseq.next())]
    for i, (hosts, items, color) in enumerate(datasets):
        hosts = [hosts] if isinstance(hosts, str) else list(hosts)
        items = [items] if isinstance(items, str) else list(items)
        for j, hp in enumerate(hosts):
            fl.append(_f(FIELD_STR, "ds.%d.hosts.%d" % (i, j), hp))
        for j, ip in enumerate(items):
            fl.append(_f(FIELD_STR, "ds.%d.items.%d" % (i, j), ip))
        fl.append(_f(FIELD_STR, "ds.%d.color" % i, color))
        if stacked:
            fl.append(_f(FIELD_INT, "ds.%d.stacked" % i, 1))
    fl.append(_f(FIELD_INT, "legend_lines", legend_lines))
    return widget("svggraph", x, y, w, h, name, fl)


def pie(x, y, w, h, name, host_pattern, item_patterns, colors, refseq):
    """Pie chart: one dataset of item name patterns on one host pattern.
    The host pattern matches the Zabbix VISIBLE host name."""
    fl = [_f(FIELD_STR, "reference", refseq.next()),
          _f(FIELD_STR, "ds.0.hosts.0", host_pattern)]
    for j, ip in enumerate(item_patterns):
        fl.append(_f(FIELD_STR, "ds.0.items.%d" % j, ip))
    for j, color in enumerate(colors):
        fl.append(_f(FIELD_STR, "ds.0.color.%d" % j, color))
    return widget("piechart", x, y, w, h, name, fl)


def honeycomb(x, y, w, h, name, groupid, item_pattern, thresholds=()):
    """Honeycomb addressed by host GROUP and item name pattern.

    Group addressing means a new group member appears with no widget
    rework. thresholds is [(value, color_hex), ...].
    """
    fl = [_f(FIELD_GROUP, "groupids.0", groupid),
          _f(FIELD_STR, "items.0", item_pattern),
          _f(FIELD_STR, "primary_label", "{HOST.NAME}")]
    for i, (val, color) in enumerate(thresholds):
        fl += [_f(FIELD_STR, "thresholds.%d.color" % i, color),
               _f(FIELD_STR, "thresholds.%d.threshold" % i, val)]
    return widget("honeycomb", x, y, w, h, name, fl)


def url_widget(x, y, w, h, name, url):
    """Legend URL widget. The Zabbix URL widget refuses data: URIs, so the
    legend is served from the public repository's GitHub Pages, which
    sends no frame-blocking headers."""
    return widget("url", x, y, w, h, name, [_f(FIELD_STR, "url", url)])
