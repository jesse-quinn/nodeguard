#!/usr/bin/env python3
"""Build the three nodeguard dashboards via the Zabbix API.

Contract:
- Builds "NodeGuard Overview", "NodeGuard Security", and "NodeGuard
  Capacity and Pipeline". Each answers one 2am question and carries a
  legend URL widget pointing at the public legend page's matching anchor.
- Fleet scaling: the host group (--group, default "Nodeguard nodes") is
  the canonical fleet definition, resolved live at run time. Item value
  tiles and gauges are generated per resolved group member; svggraph and
  pie datasets address hosts by pattern (--host-pattern, repeatable; the
  default is the resolved members' VISIBLE names, because Zabbix matches
  dataset host patterns against the visible name) and items by NAME
  pattern; the
  honeycomb is group-addressed over the LLD per-feed item names. Adding a
  host costs one re-run, never a code edit.
- The default run prints the full plan (widgets, resolved hosts, resolved
  and unresolved item keys) and exits 0 WITHOUT writing anything to the
  API. --confirm applies, update-or-create by dashboard name. An
  unresolvable item skips its widget with a loud warning line, never
  silently.
- --rename-legacy runs the phase 4 first step: export the dashboard named
  "Nodeguard" to a local JSON file. It REFUSES to delete it; deletion
  stays a manual runbook step after the side-by-side parity check.
- Token from env ZTOKEN only; --url required; connection failures exit
  with a clear message and no traceback.

Stdlib only.
"""

import argparse
import json
import os
import sys

import lib

DASH_OVERVIEW = "NodeGuard Overview"
DASH_SECURITY = "NodeGuard Security"
DASH_CAPACITY = "NodeGuard Capacity and Pipeline"
LEGACY_DASH = "Nodeguard"
DEFAULT_GROUP = "Nodeguard nodes"
DEFAULT_LEGEND = "https://jesse-quinn.github.io/nodeguard/legend.html"

PASS_PATH_ITEMS = [
    "nodeguard XDP pass rate",
    "nodeguard allowlist pass rate",
    "nodeguard WireGuard pass rate",
    "nodeguard expired pass rate",
    "nodeguard non-IP pass rate",
    "nodeguard parse-fail pass rate",
]

TCP_SANITY_ITEMS = [
    "nodeguard TCP SYN+FIN rate",
    "nodeguard TCP SYN+RST rate",
    "nodeguard TCP NULL rate",
    "nodeguard TCP XMAS rate",
]

TTL_FRAG_ITEMS = [
    "nodeguard low TTL rate",
    "nodeguard IPv4 fragment rate",
    "nodeguard IPv6 fragment rate",
]


class Ctx:
    """Everything a dashboard builder needs, resolved once."""

    def __init__(self, api, groupid, hosts, patterns, explicit_patterns,
                 legend_url):
        self.api = api
        self.groupid = groupid
        self.hosts = hosts                    # [{hostid, host, name}]
        self.patterns = patterns              # host patterns for datasets
        self.explicit_patterns = explicit_patterns
        self.legend_url = legend_url
        self.items_by_host = {}               # hostid -> {key: itemid}
        self.warnings = []
        self.resolved = []                    # (visible name, key, itemid)
        self.unresolved = []                  # (visible name, key)
        for h in hosts:
            self.items_by_host[h["hostid"]] = lib.resolve_itemids(
                api, h["hostid"])

    def itemid(self, host, key):
        """host is a resolved host dict ({hostid, host, name}); lookup is
        by hostid, reporting labels use the visible name."""
        iid = self.items_by_host.get(host["hostid"], {}).get(key)
        if iid is None:
            self.unresolved.append((host["name"], key))
            self.warnings.append(
                "WARNING: item %s unresolved on host %s; widget skipped"
                % (key, host["name"]))
            return None
        self.resolved.append((host["name"], key, iid))
        return iid

    def datasets(self, item_names, shift_base=0):
        """svggraph datasets per the scaling rules: explicit patterns get
        one dataset each with palette colors; the derived default gets
        one dataset per member host with the stable host color. Zabbix
        resolves dataset host patterns against the VISIBLE name, so the
        derived default uses h["name"], never the technical h["host"]."""
        out = []
        if self.explicit_patterns:
            for i, pat in enumerate(self.patterns):
                for j, iname in enumerate(item_names):
                    color = lib.OKABE_ITO[(i + j + shift_base)
                                          % len(lib.OKABE_ITO)]
                    out.append((pat, iname, color))
        else:
            for h in self.hosts:
                for j, iname in enumerate(item_names):
                    out.append((h["name"], iname,
                                lib.host_color(h["name"],
                                               shift_base + j)))
        return out


def kv(field):
    return "nodeguard.kv[%s]" % field


def tile_row(ctx, widgets, y, host, specs, height=3):
    """One row of item value tiles for one host (a resolved host dict;
    itemid lookup by hostid, label by visible name). specs is
    [(width, label, kv_field), ...]; unresolvable tiles are skipped
    loudly and their slot left empty."""
    x = 0
    for width, label, field in specs:
        iid = ctx.itemid(host, kv(field))
        if iid is not None:
            widgets.append(lib.itemvalue(
                x, y, width, height, "%s: %s" % (host["name"], label),
                iid))
        x += width
    return y + height


def build_overview(ctx):
    """Is the firewall attached, enforcing, and healthy right now."""
    refs = lib.RefSeq("OV")
    widgets = [lib.url_widget(0, 0, 72, 3,
                              "Legend: how to read this dashboard",
                              ctx.legend_url + "#overview")]
    y = 3
    tiles = [(12, "firewall attached?", "attach_state"),
             (12, "kill switch (0=enforcing)", "killswitch"),
             (12, "program identity ok?", "prog_match"),
             (12, "active blocks", "blocks"),
             (12, "responder unit", "responder"),
             (12, "anomaly trips", "anomaly_count")]
    for h in ctx.hosts:
        y = tile_row(ctx, widgets, y, h, tiles)
    graphs = [
        ("XDP drop rate v4 and v6: pkts/s dropped in-driver from "
         "blocklisted sources (attacks stopped)",
         ["nodeguard XDP drop rate v4", "nodeguard XDP drop rate v6"],
         False),
        ("XDP pass rate: internet traffic reaching the blocklist check",
         ["nodeguard XDP pass rate"], False),
        ("Active blocks: block-map population (entries expire in-kernel "
         "by TTL)",
         ["nodeguard active blocks"], False),
        ("Suricata kernel drop rate: sustained nonzero = capture ring "
         "overflow, detection gaps",
         ["suricata kernel drop rate"], False),
        ("Allowlist pass rate: never-blockable sources",
         ["nodeguard allowlist pass rate"], False),
        ("WireGuard pass rate: tunnel traffic hard-passed before any "
         "lookup",
         ["nodeguard WireGuard pass rate"], False),
    ]
    for i, (name, items, stacked) in enumerate(graphs):
        x = (i % 2) * 36
        gy = y + (i // 2) * 7
        widgets.append(lib.svggraph(x, gy, 36, 7, name,
                                    ctx.datasets(items), refs,
                                    stacked=stacked))
    y += ((len(graphs) + 1) // 2) * 7
    for h, (x, w) in zip(ctx.hosts,
                         lib.split_columns(len(ctx.hosts))):
        widgets.append(lib.pie(x, y, w, 7,
                               "%s: pass-path share" % h["name"],
                               h["name"], PASS_PATH_ITEMS))
    return widgets


def build_security(ctx):
    """Are we being scanned or attacked, and is or would the pipeline be
    responding."""
    refs = lib.RefSeq("SE")
    widgets = [lib.url_widget(0, 0, 72, 3,
                              "Legend: how to read this dashboard",
                              ctx.legend_url + "#security")]
    y = 3
    widgets.append(lib.svggraph(
        0, y, 36, 7,
        "TCP sanity scan rates (stacked): SYN+FIN, SYN+RST, NULL, XMAS",
        ctx.datasets(TCP_SANITY_ITEMS), refs, stacked=True))
    widgets.append(lib.svggraph(
        36, y, 36, 7,
        "Low TTL and fragments: evasion probing and fragment noise",
        ctx.datasets(TTL_FRAG_ITEMS), refs))
    y += 7
    widgets.append(lib.svggraph(
        0, y, 72, 8,
        "Alert-to-block story: suricata alert rate vs responder "
        "decisions vs XDP drop rate (dry-run divergence reads directly)",
        ctx.datasets(["suricata alerts rate",
                      "responder dry-run would-block",
                      "responder blocks issued",
                      "nodeguard XDP drop rate v4",
                      "nodeguard XDP drop rate v6"]), refs))
    y += 8
    tiles = [(24, "top blocked (since last sweep walk)", "top_blocked"),
             (12, "top blocked hits", "top1_hits"),
             (12, "last alert seen", "resp_last_alert_ts"),
             (12, "last responder action", "resp_last_action_ts"),
             (12, "watchdog canary failures", "wd_canary_fail")]
    for h in ctx.hosts:
        y = tile_row(ctx, widgets, y, h, tiles)
    return widgets


def build_capacity(ctx):
    """Will anything fill up or go stale before morning."""
    refs = lib.RefSeq("CA")
    widgets = [lib.url_widget(0, 0, 72, 3,
                              "Legend: how to read this dashboard",
                              ctx.legend_url + "#capacity")]
    y = 3
    gauges = []
    for h in ctx.hosts:
        for field, label in (("util_v4_pct", "v4 map fill"),
                             ("util_v6_pct", "v6 map fill")):
            gauges.append((h, field, label))
    for (host, field, label), (x, w) in zip(
            gauges, lib.split_columns(len(gauges))):
        iid = ctx.itemid(host, kv(field))
        if iid is not None:
            widgets.append(lib.gauge(
                x, y, w, 5, "%s: %s" % (host["name"], label), iid,
                thresholds=[("70", "E69F00"), ("85", "D55E00")]))
    y += 5
    widgets.append(lib.honeycomb(
        0, y, 72, 5,
        "Per-feed snapshot age (discovered): green under 26h",
        ctx.groupid, "feed * snapshot age",
        thresholds=[("0", "009E73"), ("93600", "E69F00"),
                    ("172800", "D55E00")]))
    y += 5
    graphs = [
        ("Feeds-owned entries", ["feeds owned entries"]),
        ("Feeds pipeline: candidates vs rejected vs failed",
         ["feeds candidates", "feeds rejected", "feeds failed count"]),
        ("Sweep walk duration: the walk's own degradation, visible "
         "before it hurts",
         ["nodeguard sweep walk duration"]),
    ]
    for i, (name, items) in enumerate(graphs):
        x = (i % 2) * 36
        gy = y + (i // 2) * 7
        widgets.append(lib.svggraph(x, gy, 36, 7, name,
                                    ctx.datasets(items), refs))
    y += ((len(graphs) + 1) // 2) * 7
    tiles = [(10, "feeds enforce", "feeds_enforce"),
             (10, "churn held", "feeds_churn_held"),
             (10, "journal reset", "feeds_journal_reset"),
             (10, "map errors", "feeds_map_errors"),
             (10, "re-arm count", "rearm_count"),
             (10, "lifeline failures", "wd_lifeline_fail"),
             (12, "sweep age (s)", "sweep_age")]
    for h in ctx.hosts:
        y = tile_row(ctx, widgets, y, h, tiles)
    return widgets


BUILDERS = [
    ("overview", DASH_OVERVIEW, build_overview),
    ("security", DASH_SECURITY, build_security),
    ("capacity", DASH_CAPACITY, build_capacity),
]


def print_plan(ctx, plans):
    print("== plan (no API writes; use --confirm to apply) ==")
    print("resolved hosts (%d):" % len(ctx.hosts))
    for h in ctx.hosts:
        # Both names printed so a technical-vs-visible divergence is
        # visible in plan mode; dataset patterns match the visible name.
        print("  %s (visible name %r, hostid %s)"
              % (h["host"], h["name"], h["hostid"]))
    print("host patterns for graph datasets (matched against visible "
          "names): %s" % ", ".join(ctx.patterns))
    for name, widgets in plans:
        print("dashboard: %s (%d widgets)" % (name, len(widgets)))
        for w in widgets:
            print("  %-10s x=%-2d y=%-2d %dx%-2d %s"
                  % (w["type"], w["x"], w["y"], w["width"], w["height"],
                     w["name"]))
    if ctx.resolved:
        print("resolved item keys (%d):" % len(ctx.resolved))
        for host, key, iid in ctx.resolved:
            print("  %s %s -> itemid %s" % (host, key, iid))
    if ctx.unresolved:
        print("unresolved item keys (%d):" % len(ctx.unresolved))
        for host, key in ctx.unresolved:
            print("  %s %s" % (host, key))
    for w in ctx.warnings:
        print(w)


def apply_dashboards(api, plans):
    for name, widgets in plans:
        pages = [{"widgets": widgets}]
        existing = api.call("dashboard.get", {"filter": {"name": [name]}})
        if existing:
            api.call("dashboard.update", {
                "dashboardid": existing[0]["dashboardid"],
                "pages": pages})
            print("updated dashboard: %s" % name)
        else:
            api.call("dashboard.create", {
                "name": name, "display_period": 60, "auto_start": 1,
                "pages": pages})
            print("created dashboard: %s" % name)


def export_legacy(api, out_path):
    """Phase 4 first step: export the legacy dashboard to a local file.
    Deletion stays manual per the runbook; this tool refuses to do it."""
    got = api.call("dashboard.get", {
        "filter": {"name": [LEGACY_DASH]},
        "output": "extend", "selectPages": "extend"})
    if not got:
        print("legacy dashboard %r not found; nothing exported"
              % LEGACY_DASH)
        return
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w") as fh:
        json.dump(got[0], fh, indent=1)
    print("exported legacy dashboard %r to %s" % (LEGACY_DASH, out_path))
    print("refusing to delete %r: run the side-by-side parity check "
          "first; deletion stays a manual runbook step" % LEGACY_DASH)


def main():
    ap = argparse.ArgumentParser(
        description="Generate the three NodeGuard dashboards. Default is "
                    "a read-only plan; --confirm applies.")
    ap.add_argument("--url", required=True,
                    help="Zabbix API URL (no default in the public repo)")
    ap.add_argument("--group", default=DEFAULT_GROUP,
                    help="host group naming the fleet (default: %r)"
                         % DEFAULT_GROUP)
    ap.add_argument("--host-pattern", action="append", default=[],
                    help="host pattern for svggraph and pie datasets "
                         "(matched by Zabbix against the VISIBLE host "
                         "name); repeatable; default: the group's "
                         "resolved member visible names")
    ap.add_argument("--legend-url", default=DEFAULT_LEGEND,
                    help="base URL of the legend page (default: the "
                         "public GitHub Pages asset)")
    ap.add_argument("--dashboard", default="all",
                    choices=["overview", "security", "capacity", "all"],
                    help="which dashboard(s) to build (default: all)")
    ap.add_argument("--confirm", action="store_true",
                    help="apply via the API (update-or-create by "
                         "dashboard name); without it, plan only")
    ap.add_argument("--rename-legacy", action="store_true",
                    help="export the legacy 'Nodeguard' dashboard to a "
                         "local JSON file; never deletes it")
    ap.add_argument("--legacy-export",
                    default=os.path.join("output",
                                         "nodeguard-legacy-dashboard.json"),
                    help="where --rename-legacy writes the export")
    args = ap.parse_args()

    try:
        api = lib.Api(args.url)
        if args.rename_legacy:
            export_legacy(api, args.legacy_export)
        groupid, hosts = lib.resolve_group(api, args.group)
        ctx = Ctx(api, groupid, hosts,
                  args.host_pattern or [h["name"] for h in hosts],
                  bool(args.host_pattern), args.legend_url)
        plans = [(name, builder(ctx))
                 for short, name, builder in BUILDERS
                 if args.dashboard in ("all", short)]
        if args.confirm:
            for w in ctx.warnings:
                print(w)
            apply_dashboards(api, plans)
        else:
            print_plan(ctx, plans)
    except lib.ZabbixError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
