#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Assertions over the generated nodeguard Zabbix template.

Contract (nonzero exit on any failure):
(a) Every dependent item's preprocessing regex, including rate twins and
    LLD item prototypes with {#FEED} substituted per feed discovered from
    the sample, extracts a non-empty value from a sample kv file
    (--sample; zbx/sample-nodeguard.kv covers every documented key). The
    LLD extraction logic itself is re-run in Python and must find every
    per-feed key while excluding the _min aggregate.
(b) Display names of items that existed in the committed v1 template are
    byte-for-byte unchanged: dashboards address svggraph datasets by item
    NAME pattern, so a rename would silently empty every graph. LLD item
    prototype display names are covered too, scoped per discovery rule:
    the Capacity honeycomb's "feed * snapshot age" pattern matches only
    the prototype name.
(c) uuids of every pre-existing object (template group, template, items
    by key, triggers by name, discovery rules by key, and item and
    trigger prototypes scoped per discovery rule) are unchanged versus
    the baseline template. The baseline is the git HEAD version of
    templates/zabbix-nodeguard-template.json read via git show, or the
    file named by --baseline (for the gitless build container). A
    changed uuid means delete-and-recreate on import: itemid churn and
    irreversible history loss.
(d) Every template item key is either the master item, an LLD artifact
    (discovery rule or prototype key), or maps onto the documented kv key
    list (a trailing .rate twin maps onto its source field).

Designed removals: an object present in the baseline but deliberately
retired (for example the static per-feed items after the LLD parity
window) is sanctioned by an entry in zbx/removed-objects.txt (kind,
identifier, reason, date). A sanctioned object may be absent from the
generated template without failing (b) or (c); anything missing and NOT
sanctioned still fails, and a sanctioned object still present in the
generated template fails as stale-sanction drift.

Intended to run in build gating so template drift fails the build, not
the 2am operator. Stdlib only; read-only.
"""

import argparse
import json
import os
import re
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TEMPLATE = os.path.join(REPO_ROOT, "zbx", "preview-template-v2.json")
DEFAULT_SAMPLE = os.path.join(REPO_ROOT, "zbx", "sample-nodeguard.kv")
BASELINE_GIT_PATH = "templates/zabbix-nodeguard-template.json"
REMOVED_OBJECTS = os.path.join(REPO_ROOT, "zbx", "removed-objects.txt")
REMOVED_KINDS = {"item", "trigger", "discovery_rule", "item_prototype",
                 "trigger_prototype"}

MASTER_KEY = "nodeguard.kv.raw"
LLD_KEY = "nodeguard.feeds.discovery"
PROTOTYPE_KEYS = {
    "nodeguard.feed.success_ts[{#FEED}]",
    "nodeguard.feed.age[{#FEED}]",
}

# The documented kv key surface (design section 5 plus the pre-existing
# export). Template item keys must be a subset of this list (after
# stripping a .rate twin suffix) plus the master and the LLD artifacts.
DOCUMENTED_KV_FIELDS = {
    # exporter heartbeat and dispatcher state
    "ts", "attached", "attach_state", "attach_mode", "prog_id",
    "prog_match",
    # enforcement state
    "killswitch", "latch", "rearm_count",
    # stats (eight slots plus the read-fail flag)
    "pass", "drop_v4", "drop_v6", "pass_allowlist", "pass_wgport",
    "pass_expired", "pass_nonip", "pass_parsefail", "stats_read_fail",
    # stats2 sanity counters plus the read-fail flag
    "tcp_synfin", "tcp_synrst", "tcp_null", "tcp_xmas", "ttl_low",
    "frag_v4", "frag_v6", "stats2_read_fail",
    # sweep cache
    "blocks", "blocks_v4", "blocks_v6", "util_v4_pct", "util_v6_pct",
    "top1_hits", "top_blocked", "sweep_walk_ms", "sweep_ts", "sweep_age",
    # wireguard port
    "port_cfg", "port_live", "port_match",
    # units and timers
    "suricata", "responder", "xdp_unit", "maps_unit", "watchdog_timer",
    "sweep_timer",
    # suricata and responder
    "kernel_drops", "suricata_alerts", "resp_alerts_seen",
    "resp_blocks_issued", "resp_dryrun_would_block", "resp_last_alert_ts",
    "resp_last_action_ts",
    # watchdog internals and anomaly detector
    "wd_canary_fail", "wd_lifeline_fail", "wd_toolfail", "wd_clean",
    "anomaly_count", "anomaly_shadow_count", "anomaly_last_ts",
    # feeds
    "feeds_enforce", "feeds_approved", "feeds_config_approved_mismatch",
    "feeds_journal_reset", "feeds_churn_held", "feeds_last_run_ts",
    "feeds_entries", "feeds_candidates", "feeds_rejected", "feeds_failed",
    "feeds_map_errors", "feeds_last_success_ts_min",
    "geo_summary", "geo_sources_hitting", "geo_located",
    "geo_countries",
    "top_blocked_1", "top_blocked_2", "top_blocked_3", "top_blocked_4", "top_blocked_5",
    "geo_country_1", "geo_country_2", "geo_country_3", "geo_country_4", "geo_country_5",
    "feeds_last_success_ts_spamhaus_drop_v4",
    "feeds_snapshot_age_spamhaus_drop_v4",
    "feeds_last_success_ts_spamhaus_drop_v6",
    "feeds_snapshot_age_spamhaus_drop_v6",
    "feeds_last_success_ts_dshield_top20",
    "feeds_snapshot_age_dshield_top20",
}

# Same extraction the LLD rule's JavaScript performs, re-run in Python.
LLD_FEED_RE = re.compile(
    r"(?m)^ng\.feeds_last_success_ts_(?!min=)([A-Za-z0-9_]+)=")


class Checker:
    """Tallies check results and prints a PASS or FAIL line for each."""

    def __init__(self):
        """Start with zero recorded failures."""
        self.failures = 0

    def ok(self, label):
        """Record a passing check by printing a PASS line."""
        print("PASS %s" % label)

    def fail(self, label, detail):
        """Record a failing check: bump the failure count and print FAIL."""
        self.failures += 1
        print("FAIL %s: %s" % (label, detail))


def load_template(path):
    """Read a generated template JSON file and return its zabbix_export."""
    with open(path) as fh:
        doc = json.load(fh)
    return doc["zabbix_export"]


def load_baseline(git_ref_path, baseline_path=None):
    """Baseline template: the committed HEAD version via git show by
    default, or an explicit file when --baseline is given (the build
    container has no .git, so it passes the committed file directly)."""
    if baseline_path is not None:
        try:
            with open(baseline_path) as fh:
                return json.load(fh)["zabbix_export"]
        except (OSError, ValueError, KeyError) as e:
            print("error: cannot read baseline file %s: %s"
                  % (baseline_path, e), file=sys.stderr)
            sys.exit(2)
    try:
        out = subprocess.run(
            ["git", "-C", REPO_ROOT, "show", "HEAD:%s" % git_ref_path],
            capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError) as e:
        print("error: cannot read baseline via git show HEAD:%s: %s"
              % (git_ref_path, e), file=sys.stderr)
        sys.exit(2)
    return json.loads(out.stdout)["zabbix_export"]


def load_removed(path):
    """Sanctioned removals from zbx/removed-objects.txt, as
    {kind: {identifier}}. Malformed lines are hard errors: the sanction
    record is load-bearing, so a half-written entry must not silently
    sanction nothing (or everything)."""
    removed = {k: set() for k in REMOVED_KINDS}
    if not os.path.exists(path):
        return removed
    with open(path) as fh:
        for n, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) != 4 or not all(p.strip() for p in parts):
                print("error: %s:%d: expected kind|identifier|reason|"
                      "date, got %r" % (path, n, line), file=sys.stderr)
                sys.exit(2)
            kind, ident = parts[0].strip(), parts[1].strip()
            if kind not in REMOVED_KINDS:
                print("error: %s:%d: unknown kind %r (expected one of "
                      "%s)" % (path, n, kind,
                               ", ".join(sorted(REMOVED_KINDS))),
                      file=sys.stderr)
                sys.exit(2)
            removed[kind].add(ident)
    return removed


def walk_items(exp):
    """Yield every item across all templates in the export."""
    for t in exp.get("templates", []):
        for it in t.get("items", []):
            yield it


def walk_triggers(exp):
    """Yield every trigger in the export: those attached to items first,
    then the top-level multi-item triggers."""
    for it in walk_items(exp):
        for tr in it.get("triggers", []):
            yield tr
    for tr in exp.get("triggers", []):
        yield tr


def discovery_rules(exp):
    """Yield every discovery rule across all templates in the export."""
    for t in exp.get("templates", []):
        for dr in t.get("discovery_rules", []):
            yield dr


def check_regexes(c, exp, sample):
    """(a) every dependent regex extracts a value from the sample."""
    feeds = LLD_FEED_RE.findall(sample)
    if sorted(feeds) != sorted(set(feeds)) or not feeds:
        c.fail("lld-extraction", "feed extraction returned %r" % feeds)
    elif "min" in feeds:
        c.fail("lld-extraction", "the _min aggregate leaked into "
                                 "discovery: %r" % feeds)
    else:
        c.ok("lld-extraction found feeds: %s" % ", ".join(sorted(feeds)))

    def check_one(label, pattern):
        try:
            m = re.search(pattern, sample)
        except re.error as e:
            c.fail(label, "invalid regex %r: %s" % (pattern, e))
            return
        if not m or not m.group(1):
            c.fail(label, "regex %r extracted nothing from the sample"
                   % pattern)

    n = 0
    for it in walk_items(exp):
        for step in it.get("preprocessing", []):
            if step["type"] == "REGEX":
                check_one("regex %s" % it["key"], step["parameters"][0])
                n += 1
    for dr in discovery_rules(exp):
        for ip in dr.get("item_prototypes", []):
            for step in ip.get("preprocessing", []):
                if step["type"] != "REGEX":
                    continue
                for feed in feeds:
                    pat = step["parameters"][0].replace("{#FEED}",
                                                        re.escape(feed))
                    check_one("prototype regex %s feed %s"
                              % (ip["key"], feed), pat)
                    n += 1
    c.ok("checked %d extraction regexes against the sample" % n)


def proto_pairs(exp, field, ident, value="uuid"):
    """Prototype (identifier, value) pairs scoped per owning discovery
    rule, so identifiers stay unique if a second rule ever appears."""
    for dr in discovery_rules(exp):
        for p in dr.get(field, []):
            yield ("%s/%s" % (dr["key"], p[ident]), p[value])


def check_names(c, exp, base, removed):
    """(b) baseline display names byte-for-byte unchanged, items and LLD
    item prototypes alike; sanctioned removals may be absent."""
    new_names = {it["key"]: it["name"] for it in walk_items(exp)}
    missing, renamed = [], []
    for it in walk_items(base):
        if it["key"] not in new_names:
            if it["key"] not in removed["item"]:
                missing.append(it["key"])
        elif new_names[it["key"]] != it["name"]:
            renamed.append("%s: %r != %r"
                           % (it["key"], new_names[it["key"]], it["name"]))
    if missing:
        c.fail("v1-names", "baseline items missing from v2 and not "
                           "sanctioned in removed-objects.txt: %s"
               % ", ".join(missing))
    if renamed:
        c.fail("v1-names", "display names changed: %s" % "; ".join(renamed))
    if not missing and not renamed:
        c.ok("all baseline item display names carried byte-for-byte")

    new_proto = dict(proto_pairs(exp, "item_prototypes", "key", "name"))
    p_missing, p_renamed = [], []
    for ident, name in proto_pairs(base, "item_prototypes", "key", "name"):
        if ident not in new_proto:
            if ident not in removed["item_prototype"]:
                p_missing.append(ident)
        elif new_proto[ident] != name:
            p_renamed.append("%s: %r != %r"
                             % (ident, new_proto[ident], name))
    if p_missing:
        c.fail("prototype-names",
               "baseline item prototypes missing from v2 and not "
               "sanctioned: %s" % ", ".join(p_missing))
    if p_renamed:
        c.fail("prototype-names",
               "item prototype display names changed (the Capacity "
               "honeycomb's 'feed * snapshot age' pattern matches the "
               "prototype name): %s" % "; ".join(p_renamed))
    if not p_missing and not p_renamed:
        c.ok("all baseline item prototype display names carried "
             "byte-for-byte")


def check_uuids(c, exp, base, removed):
    """(c) uuids of pre-existing objects unchanged vs the baseline;
    sanctioned removals may be absent, but a sanctioned object still
    present in v2 is stale-sanction drift and fails."""
    problems = []

    def cmp_map(label, base_pairs, new_pairs, sanctioned=frozenset()):
        new_map = dict(new_pairs)
        for key, buuid in base_pairs:
            nuuid = new_map.get(key)
            if nuuid is None:
                if key not in sanctioned:
                    problems.append("%s %r missing from v2 (not "
                                    "sanctioned in removed-objects.txt)"
                                    % (label, key))
            elif key in sanctioned:
                problems.append("%s %r is sanctioned as removed but "
                                "still present in v2 (stale entry in "
                                "removed-objects.txt)" % (label, key))
            elif nuuid != buuid:
                problems.append("%s %r uuid changed %s -> %s"
                                % (label, key, buuid, nuuid))

    cmp_map("template group",
            [(g["name"], g["uuid"]) for g in base.get("template_groups", [])],
            [(g["name"], g["uuid"]) for g in exp.get("template_groups", [])])
    cmp_map("template",
            [(t["template"], t["uuid"]) for t in base.get("templates", [])],
            [(t["template"], t["uuid"]) for t in exp.get("templates", [])])
    cmp_map("item",
            [(i["key"], i["uuid"]) for i in walk_items(base)],
            [(i["key"], i["uuid"]) for i in walk_items(exp)],
            removed["item"])
    cmp_map("trigger",
            [(t["name"], t["uuid"]) for t in walk_triggers(base)],
            [(t["name"], t["uuid"]) for t in walk_triggers(exp)],
            removed["trigger"])
    cmp_map("discovery rule",
            [(d["key"], d["uuid"]) for d in discovery_rules(base)],
            [(d["key"], d["uuid"]) for d in discovery_rules(exp)],
            removed["discovery_rule"])
    cmp_map("item prototype",
            list(proto_pairs(base, "item_prototypes", "key")),
            list(proto_pairs(exp, "item_prototypes", "key")),
            removed["item_prototype"])
    cmp_map("trigger prototype",
            list(proto_pairs(base, "trigger_prototypes", "name")),
            list(proto_pairs(exp, "trigger_prototypes", "name")),
            removed["trigger_prototype"])
    if problems:
        c.fail("uuid-carry", "; ".join(problems))
    else:
        c.ok("every pre-existing object keeps its committed uuid")


def check_keys(c, exp):
    """(d) item keys are a subset of the documented kv surface."""
    bad = []
    for it in walk_items(exp):
        key = it["key"]
        if key == MASTER_KEY:
            continue
        m = re.fullmatch(r"nodeguard\.kv\[(.+)\]", key)
        if not m:
            bad.append(key)
            continue
        field = m.group(1)
        if field.endswith(".rate"):
            field = field[:-len(".rate")]
        if field not in DOCUMENTED_KV_FIELDS:
            bad.append(key)
    for dr in discovery_rules(exp):
        if dr["key"] != LLD_KEY:
            bad.append(dr["key"])
        for ip in dr.get("item_prototypes", []):
            if ip["key"] not in PROTOTYPE_KEYS:
                bad.append(ip["key"])
    if bad:
        c.fail("kv-surface", "keys outside the documented kv surface: %s"
               % ", ".join(bad))
    else:
        c.ok("all template keys map onto the documented kv surface")


def main():
    """Command-line entry point: load the generated template, baseline,
    and sample, run all four checks (regex extraction, v1 names, uuid
    carry-over, kv surface), and return nonzero if any check failed."""
    ap = argparse.ArgumentParser(
        description="Assert the generated nodeguard template preserves "
                    "v1 names and uuids, extracts every field from a "
                    "sample kv file, and stays inside the documented kv "
                    "surface.")
    ap.add_argument("--template", default=DEFAULT_TEMPLATE,
                    help="generated template JSON to check (default: "
                         "zbx/preview-template-v2.json)")
    ap.add_argument("--sample", default=DEFAULT_SAMPLE,
                    help="sample kv file (default: "
                         "zbx/sample-nodeguard.kv)")
    ap.add_argument("--baseline", default=None,
                    help="baseline template JSON file; default is the "
                         "committed HEAD version via git show, which "
                         "needs a .git directory (the build container "
                         "passes the committed file explicitly instead)")
    args = ap.parse_args()

    if not os.path.exists(args.template):
        print("error: template not found: %s (run zbx/gen-template.py "
              "first)" % args.template, file=sys.stderr)
        return 2
    with open(args.sample) as fh:
        sample = fh.read()
    exp = load_template(args.template)
    base = load_baseline(BASELINE_GIT_PATH, args.baseline)
    removed = load_removed(REMOVED_OBJECTS)

    c = Checker()
    check_regexes(c, exp, sample)
    check_names(c, exp, base, removed)
    check_uuids(c, exp, base, removed)
    check_keys(c, exp)

    if c.failures:
        print("%d check(s) FAILED" % c.failures)
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
