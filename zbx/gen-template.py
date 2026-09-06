#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Render the nodeguard Zabbix template (v2) from a declarative table.

Contract:
- Deterministic: the same table and the same committed baseline always
  produce byte-identical output (json.dumps indent=1, no trailing newline,
  matching the committed v1 formatting).
- UUID carry-over: the COMMITTED templates/zabbix-nodeguard-template.json
  is loaded first and object-key-to-uuid maps are built (template group by
  name, template by name, items by key, triggers by name, discovery rules
  by key). Every pre-existing object keeps its uuid verbatim; only
  genuinely new objects get uuid5(NODEGUARD_NS, kind + ":" + object key).
  This removes the delete-and-recreate risk (itemid churn, irreversible
  history loss) a full regeneration would invite.
- Display names of items that exist in the committed v1 are reproduced
  byte-for-byte (asserted by check_template.py): the dashboards address
  svggraph datasets by item NAME pattern, so a rename would silently empty
  every graph.
- v2 content: one master item (Zabbix agent, nodeguard.kv.raw, TEXT, 1m,
  history 1d, trends 0); every other item is DEPENDENT on it with a
  preprocessing regex '(?m)^ng\\.<field>=(.+)$' capture \\1; the new item,
  trigger, and LLD set from the add-nodeguard-telemetry design.
- Output goes to zbx/preview-template-v2.json by default. The committed
  template is NOT overwritten by this tool during review; pointing --out at
  templates/ is a deliberate rollout step (phase 2).

Stdlib only. Reads the repo tree; writes only the --out file.
"""

import argparse
import json
import os
import sys
import uuid

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMMITTED = os.path.join(REPO_ROOT, "templates",
                         "zabbix-nodeguard-template.json")
DEFAULT_OUT = os.path.join(REPO_ROOT, "zbx", "preview-template-v2.json")

TEMPLATE = "Nodeguard by Zabbix agent"
TEMPLATE_GROUP = "Templates/Nodeguard"
MASTER_KEY = "nodeguard.kv.raw"
LLD_KEY = "nodeguard.feeds.discovery"
FEEDS = ["spamhaus_drop_v4", "spamhaus_drop_v6", "dshield_top20"]

# Fixed uuid5 namespace for newly minted objects. Deterministic by
# construction; never used for objects that exist in the committed v1.
NODEGUARD_NS = uuid.uuid5(uuid.NAMESPACE_DNS, "nodeguard.zbx.template")


def kv_key(field):
    """Build the Zabbix item key for one kv field: nodeguard.kv[<field>]."""
    return "nodeguard.kv[%s]" % field


def iref(key):
    """Trigger expression item reference."""
    return "/%s/%s" % (TEMPLATE, key)


def rx(field):
    """The mandatory multiline extraction regex for one kv field. The
    inline (?m) is required: Zabbix preprocessing is PCRE with no separate
    flags field, and without it only the first kv line would ever parse."""
    return "(?m)^ng\\.%s=(.+)$" % field


def trig(name, expression, priority, description):
    """Build one trigger definition dict (name, expression, priority,
    description) for later rendering with a carried or minted uuid."""
    return {"name": name, "expression": expression,
            "priority": priority, "description": description}


def feed_triggers(feed):
    """Return the two staleness triggers for one threat feed: a warning
    after two missed refresh cycles and an average-severity failed-open
    once its entries have decayed out of the kernel."""
    succ = iref(kv_key("feeds_last_success_ts_%s" % feed))
    return [
        trig("nodeguard feed %s stale on {HOST.NAME}" % feed,
             "last(%s)>0 and fuzzytime(%s,46800)=0" % (succ, succ),
             "WARNING",
             "Two full cycles plus margin without a successful exchange."),
        trig("nodeguard feed %s failed open on {HOST.NAME}" % feed,
             "last(%s)>0 and fuzzytime(%s,93600)=0" % (succ, succ),
             "AVERAGE",
             "Entries for this feed have expired in-kernel; designed "
             "decay, not an outage."),
    ]


def feed_frozen_trigger(feed):
    """Return the trigger that warns when a feed's upstream content has not
    changed in 7 days (a stalled source, ahead of the 14-day hard stop)."""
    age = iref(kv_key("feeds_snapshot_age_%s" % feed))
    return trig("nodeguard feed %s upstream frozen on {HOST.NAME}" % feed,
                "last(%s)>604800" % age, "WARNING",
                "Upstream unchanged for 7 days; re-stamp hard-stops at "
                "14 days.")


def row(field, name, vt, desc, units=None, history="31d", trends="180d",
        rate=False, triggers=(), rate_of=None):
    """One dependent-item table row. rate=True appends CHANGE_PER_SECOND
    after the regex; rate_of names the kv field a .rate twin extracts."""
    return {"field": field, "name": name, "value_type": vt,
            "description": desc, "units": units, "history": history,
            "trends": trends, "rate": rate, "triggers": list(triggers),
            "rate_of": rate_of}


def rate_twin(field, name, desc, trends="90d", triggers=()):
    """CHANGE_PER_SECOND twin of a raw counter; distinct key <field>.rate,
    same source kv field. Rate items get 90d trend storage."""
    return row(field + ".rate", name, "FLOAT", desc, units="pps",
               trends=trends, rate=True, triggers=triggers, rate_of=field)


# ---------------------------------------------------------------------------
# Declarative item table, v2. Order is the render order: items carried from
# v1 first (names byte-for-byte), then the new telemetry items.
# ---------------------------------------------------------------------------

def build_rows():
    """Build the full ordered list of dependent-item table rows, v1 items
    first (names byte-for-byte) then the new v2 telemetry, each row carrying
    its name, value type, retention, rate flag, and any triggers."""
    rows = []

    # --- carried from v1, in v1 order -------------------------------------
    rows += [
        row("attach_state", "nodeguard attach state", "TEXT",
            "attached, detached, or unknown (xdp-loader itself failed; "
            "the program may still be enforcing)", trends="0",
            triggers=[
                trig("nodeguard XDP is not attached on {HOST.NAME}",
                     "last(%s)<>\"attached\"" % iref(kv_key("attach_state")),
                     "WARNING",
                     "detached = fail open (no enforcement); unknown = "
                     "xdp-loader broken, state unverifiable"),
                trig("nodeguard telemetry stale on {HOST.NAME}",
                     "nodata(%s,10m)=1" % iref(kv_key("attach_state")),
                     "WARNING",
                     "The watchdog export or the agent path is dead; "
                     "nodeguard state unknown to monitoring."),
            ]),
        row("killswitch", "nodeguard kill switch", "UNSIGNED",
            "nonzero = enforcement soft-off (latched)",
            triggers=[
                trig("nodeguard enforcement latched OFF on {HOST.NAME}",
                     "last(%s)=1" % iref(kv_key("killswitch")), "HIGH",
                     "nodeguard-on to re-arm after diagnosing; check "
                     "ng.latch for manual vs watchdog"),
            ]),
        row("latch", "nodeguard latch owner", "TEXT",
            "manual, watchdog, or none", trends="0"),
        row("blocks", "nodeguard active blocks", "UNSIGNED",
            "entries in the block maps"),
        row("port_match", "nodeguard wg port match", "UNSIGNED",
            "1 = config[0] equals tailscaled's live port",
            triggers=[
                trig("nodeguard WireGuard port drift on {HOST.NAME}",
                     "last(%s)=0" % iref(kv_key("port_match")), "WARNING",
                     "watchdog rewrites within a minute; persistent drift "
                     "means the watchdog timer is dead"),
            ]),
        row("suricata", "suricata unit state", "TEXT",
            "systemd is-active for suricata", trends="0",
            triggers=[
                trig("suricata is not active on {HOST.NAME}",
                     "last(%s)<>\"active\"" % iref(kv_key("suricata")),
                     "WARNING",
                     "detection blind while down; zero traffic impact by "
                     "design"),
            ]),
        row("responder", "nodeguard responder unit state", "TEXT",
            "systemd is-active for nodeguard-responder", trends="0",
            triggers=[
                trig("nodeguard responder is not active on {HOST.NAME}",
                     "last(%s)<>\"active\"" % iref(kv_key("responder")),
                     "WARNING",
                     "no NEW blocks while down; existing blocks expire "
                     "in-kernel"),
            ]),
        row("kernel_drops", "suricata kernel drops", "UNSIGNED",
            "cumulative af-packet kernel_drops across capture threads",
            triggers=[
                trig("suricata capture is dropping packets on {HOST.NAME}",
                     "last(%s)-last(%s,#5)>50000" % (
                         iref(kv_key("kernel_drops")),
                         iref(kv_key("kernel_drops"))),
                     "WARNING",
                     "ring saturated; reduced detection coverage. Raise "
                     "ring-size or trim the ruleset"),
            ]),
        row("drop_v4", "nodeguard XDP drop rate v4", "FLOAT",
            "blocked packets per second (in-kernel drops of blocklisted "
            "sources)", units="pps", rate=True,
            triggers=[
                trig("nodeguard v4 drop rate above weekly baseline on "
                     "{HOST.NAME}",
                     "baselinedev(%s,1h:now/h,\"d\",10)>3 and last(%s)>10"
                     % (iref(kv_key("drop_v4")), iref(kv_key("drop_v4"))),
                     "INFO",
                     "Seasonal baseline deviation with an absolute floor "
                     "(baselinedev explodes on near-zero baselines). "
                     "Imported at Information severity; promoted only "
                     "after 14 days of reviewed-quiet trend rows."),
                trig("nodeguard v4 drop rate above static ceiling on "
                     "{HOST.NAME}",
                     "min(%s,5m)>5000" % iref(kv_key("drop_v4")),
                     "INFO",
                     "Placeholder ceiling; value retuned from phase 5 "
                     "shadow data (tasks.md 5.4). Backstop for slow "
                     "ramps the baseline family cannot catch."),
            ]),
        row("drop_v6", "nodeguard XDP drop rate v6", "FLOAT",
            "IPv6 drops per second", units="pps", rate=True,
            triggers=[
                trig("nodeguard v6 drop rate above weekly baseline on "
                     "{HOST.NAME}",
                     "baselinedev(%s,1h:now/h,\"d\",10)>3 and last(%s)>10"
                     % (iref(kv_key("drop_v6")), iref(kv_key("drop_v6"))),
                     "INFO",
                     "Seasonal baseline deviation with an absolute floor "
                     "(baselinedev explodes on near-zero baselines). "
                     "Imported at Information severity; promoted only "
                     "after 14 days of reviewed-quiet trend rows."),
                trig("nodeguard v6 drop rate above static ceiling on "
                     "{HOST.NAME}",
                     "min(%s,5m)>5000" % iref(kv_key("drop_v6")),
                     "INFO",
                     "Placeholder ceiling; value retuned from phase 5 "
                     "shadow data (tasks.md 5.4). Backstop for slow "
                     "ramps the baseline family cannot catch."),
            ]),
        row("pass", "nodeguard XDP pass rate", "FLOAT",
            "default-pass packets per second", units="pps", rate=True),
        row("pass_allowlist", "nodeguard allowlist pass rate", "FLOAT",
            "allowlist hits per second", units="pps", rate=True),
        row("pass_wgport", "nodeguard WireGuard pass rate", "FLOAT",
            "WireGuard port passes per second", units="pps", rate=True),
        row("feeds_enforce", "feeds enforce", "UNSIGNED",
            "1 = FEEDS_ENFORCE=yes in the deployed config"),
        row("feeds_approved", "feeds approved count", "UNSIGNED",
            "feeds recorded in approved.json"),
        row("feeds_config_approved_mismatch",
            "feeds config/approval mismatch", "UNSIGNED",
            "1 = approvals exist but the deployed config does not enforce "
            "them (deploy-reverted config tripwire)",
            triggers=[
                trig("nodeguard feeds config/approval mismatch on "
                     "{HOST.NAME}",
                     "min(%s,13h)>0"
                     % iref(kv_key("feeds_config_approved_mismatch")),
                     "WARNING",
                     "A deploy likely reverted a live config edit; "
                     "enforcement is decaying open. Re-align "
                     "hosts/<host>/feeds.conf and redeploy."),
            ]),
        row("feeds_journal_reset", "feeds journal reset", "UNSIGNED",
            "1 = state.json was lost and rebuilt insert-only this run"),
        row("feeds_churn_held", "feeds churn held", "UNSIGNED",
            "1 = a feed's composition jumped past the churn brake",
            triggers=[
                trig("nodeguard feed composition churn held on {HOST.NAME}",
                     "last(%s)=1" % iref(kv_key("feeds_churn_held")),
                     "WARNING",
                     "Review last-diff.txt; accept with nodeguard-feeds "
                     "apply --feed <id> --confirm."),
            ]),
        row("feeds_last_run_ts", "feeds last run", "UNSIGNED",
            "epoch of the last run",
            triggers=[
                trig("nodeguard feeds have never run on {HOST.NAME}",
                     "max(%s,24h)=0" % iref(kv_key("feeds_last_run_ts")),
                     "WARNING",
                     "feeds_last_run_ts has been 0 for 24h: a wiped "
                     "/var/lib/nodeguard or a disabled feeds timer. "
                     "Deliberately not gated on last()>0 so the never-ran "
                     "state cannot read healthy forever."),
            ]),
        row("feeds_entries", "feeds owned entries", "UNSIGNED",
            "journal-owned block entries"),
        row("feeds_candidates", "feeds candidates", "UNSIGNED",
            "candidates seen this run"),
        row("feeds_rejected", "feeds rejected", "UNSIGNED",
            "candidates dropped by protected/allow guards; nonzero is "
            "anomalous with bogon feeds excluded upstream",
            triggers=[
                trig("nodeguard feed shipped protected ranges on "
                     "{HOST.NAME}",
                     "min(%s,13h)>0" % iref(kv_key("feeds_rejected")),
                     "WARNING",
                     "A curated feed is shipping protected or allowlisted "
                     "ranges; review last-diff.txt."),
            ]),
        row("feeds_failed", "feeds failed count", "UNSIGNED",
            "feeds FAILED this run (fetch, validation, staleness, canary)",
            triggers=[
                trig("nodeguard feeds failing for 18h on {HOST.NAME}",
                     "min(%s,19h)>0" % iref(kv_key("feeds_failed")),
                     "INFO",
                     "Transient-failure carrier; per-feed staleness "
                     "escalates separately."),
            ]),
        row("feeds_last_success_ts_min", "feeds oldest success",
            "UNSIGNED",
            "min over configured feeds of the last successful exchange"),
    ]
    for feed in FEEDS:
        rows.append(
            row("feeds_last_success_ts_%s" % feed,
                "feeds %s last success" % feed, "UNSIGNED",
                "epoch of %s's last successful HTTP exchange" % feed,
                triggers=feed_triggers(feed)))
        rows.append(
            row("feeds_snapshot_age_%s" % feed,
                "feeds %s snapshot age" % feed, "UNSIGNED",
                "seconds since %s's content last changed" % feed,
                triggers=[feed_frozen_trigger(feed)]))
    rows.append(
        row("feeds_map_errors", "feeds map errors", "UNSIGNED",
            "per-key bpftool failures this run (one lost key each, never "
            "a lost batch)"))

    # --- new in v2 --------------------------------------------------------
    rows += [
        row("ts", "nodeguard kv timestamp", "UNSIGNED",
            "epoch stamped by the exporter at the top of the kv file",
            units="unixtime",
            triggers=[
                trig("nodeguard telemetry clock skew or frozen kv on "
                     "{HOST.NAME}",
                     "fuzzytime(%s,300)=0" % iref(kv_key("ts")), "HIGH",
                     "The kv timestamp is more than 5 minutes from server "
                     "time: a frozen but still-served kv file or host "
                     "clock skew. Complements the nodata trigger, which "
                     "only catches the file not arriving at all."),
            ]),
        row("stats_read_fail", "nodeguard stats read failure", "UNSIGNED",
            "1 = the stats pin exists but the dump or parse failed; the "
            "counter keys are omitted rather than served as zeros"),
        row("stats2_read_fail", "nodeguard stats2 read failure",
            "UNSIGNED",
            "1 = the stats2 pin exists but the dump or parse failed; the "
            "sanity counter keys are omitted rather than served as zeros",
            triggers=[
                trig("nodeguard stats2 unreadable on {HOST.NAME}",
                     "last(%s)=1" % iref(kv_key("stats2_read_fail")),
                     "WARNING",
                     "The stats2 pin exists but could not be read; sanity "
                     "counters are unknown, not zero."),
            ]),
        row("pass_expired", "nodeguard expired pass rate", "FLOAT",
            "packets per second passed because their block entry had "
            "expired in-kernel", units="pps", rate=True),
        row("pass_nonip", "nodeguard non-IP pass rate", "FLOAT",
            "non-IP ethertype passes per second", units="pps", rate=True),
        row("pass_parsefail", "nodeguard parse-fail pass rate", "FLOAT",
            "packets per second passed because the IP header failed "
            "bounds validation (fail-open by design)", units="pps",
            rate=True),
    ]

    stats2 = [
        ("tcp_synfin", "TCP SYN+FIN", "SYN and FIN set together; classic "
         "scanner fingerprint, counted statelessly before any verdict"),
        ("tcp_synrst", "TCP SYN+RST", "SYN and RST set together; "
         "impossible combination, counted statelessly"),
        ("tcp_null", "TCP NULL", "no TCP flags set; NULL scan "
         "fingerprint, counted statelessly"),
        ("tcp_xmas", "TCP XMAS", "FIN, PSH, and URG set together; XMAS "
         "scan fingerprint, counted statelessly"),
        ("ttl_low", "low TTL", "TTL or hop limit below the build-time "
         "floor (default 5); traceroute noise or evasion probing"),
        ("frag_v4", "IPv4 fragment", "IPv4 packets with a nonzero "
         "fragment offset"),
        ("frag_v6", "IPv6 fragment", "IPv6 packets carrying a fragment "
         "header"),
    ]
    # Generous static rate floors for the sanity counters: the "static
    # rate floors first" layer of design section 6; baselinedev variants
    # only after a demonstrated quiet baseline. Values are deliberately
    # generous placeholders, retuned from phase 5 shadow data.
    stats2_floor = {
        "tcp_synfin": 100, "tcp_synrst": 100, "tcp_null": 100,
        "tcp_xmas": 100, "ttl_low": 1000, "frag_v4": 1000,
        "frag_v6": 1000,
    }
    for field, label, desc in stats2:
        rows.append(row(field, "nodeguard %s packets" % label, "UNSIGNED",
                        desc + " (cumulative)"))
        rows.append(rate_twin(
            field, "nodeguard %s rate" % label, desc + " (per second)",
            triggers=[
                trig("nodeguard %s rate above static floor on "
                     "{HOST.NAME}" % label,
                     "min(%s,5m)>%d" % (iref(kv_key(field + ".rate")),
                                        stats2_floor[field]),
                     "INFO",
                     "Generous static rate floor, the sanity counters' "
                     "first alerting layer per design section 6; "
                     "placeholder value retuned from phase 5 shadow "
                     "data (tasks.md 5.4). A baselinedev variant is "
                     "added only after a demonstrated quiet baseline."),
            ]))

    rows += [
        row("suricata_alerts", "suricata alerts", "UNSIGNED",
            "cumulative detect.alert count from the same suricatasc "
            "dump-counters call as kernel_drops"),
        rate_twin("suricata_alerts", "suricata alerts rate",
                  "detection alerts per second",
                  triggers=[
                      trig("suricata alert rate above weekly baseline on "
                           "{HOST.NAME}",
                           "baselinedev(%s,1h:now/h,\"d\",10)>3 and "
                           "last(%s)>1"
                           % (iref(kv_key("suricata_alerts.rate")),
                              iref(kv_key("suricata_alerts.rate"))),
                           "INFO",
                           "Seasonal baseline deviation with a 1/s "
                           "absolute floor. Imported at Information "
                           "severity; promoted only after 14 days of "
                           "reviewed-quiet trend rows."),
                      trig("suricata alert rate above static ceiling on "
                           "{HOST.NAME}",
                           "min(%s,5m)>50"
                           % iref(kv_key("suricata_alerts.rate")),
                           "INFO",
                           "Placeholder ceiling; value retuned from "
                           "phase 5 shadow data (tasks.md 5.4). "
                           "Backstop for slow ramps the baseline "
                           "family cannot catch."),
                  ]),
        rate_twin("kernel_drops", "suricata kernel drop rate",
                  "capture-ring drops per second (rate twin of the "
                  "cumulative counter, fixing the raw-cumulative plot)"),
        row("resp_alerts_seen", "responder alerts seen", "UNSIGNED",
            "cumulative EVE alerts the responder has consumed"),
        row("resp_blocks_issued", "responder blocks issued", "UNSIGNED",
            "cumulative blocks the responder has written to the maps"),
        row("resp_dryrun_would_block", "responder dry-run would-block",
            "UNSIGNED",
            "cumulative blocks the responder would have issued while in "
            "dry-run"),
        row("resp_last_alert_ts", "responder last alert time", "UNSIGNED",
            "epoch of the last alert the responder consumed",
            units="unixtime"),
        row("resp_last_action_ts", "responder last action time",
            "UNSIGNED",
            "epoch of the responder's last block or dry-run decision",
            units="unixtime"),
        row("blocks_v4", "nodeguard blocks v4", "UNSIGNED",
            "live v4 block-map entries, from the sweep cache"),
        row("blocks_v6", "nodeguard blocks v6", "UNSIGNED",
            "live v6 block-map entries, from the sweep cache"),
        row("util_v4_pct", "nodeguard v4 block map utilization", "FLOAT",
            "v4 block-map fill percentage; denominator read from the "
            "installed map spec", units="%",
            triggers=[
                trig("nodeguard v4 block map over 85 percent full on "
                     "{HOST.NAME}",
                     "last(%s)>85" % iref(kv_key("util_v4_pct")),
                     "WARNING",
                     "Static ceiling; the backstop the trend projection "
                     "cannot provide."),
                trig("nodeguard v4 block map projected full within 24h "
                     "on {HOST.NAME}",
                     "timeleft(%s,7d,90)<86400 and timeleft(%s,7d,90)<>-1"
                     % (iref(kv_key("util_v4_pct")),
                        iref(kv_key("util_v4_pct"))),
                     "WARNING",
                     "7-day trend projects 90 percent within 24h; the "
                     "<>-1 guard suppresses the no-projection case."),
            ]),
        row("util_v6_pct", "nodeguard v6 block map utilization", "FLOAT",
            "v6 block-map fill percentage; denominator read from the "
            "installed map spec", units="%",
            triggers=[
                trig("nodeguard v6 block map over 85 percent full on "
                     "{HOST.NAME}",
                     "last(%s)>85" % iref(kv_key("util_v6_pct")),
                     "WARNING",
                     "Static ceiling; the backstop the trend projection "
                     "cannot provide."),
                trig("nodeguard v6 block map projected full within 24h "
                     "on {HOST.NAME}",
                     "timeleft(%s,7d,90)<86400 and timeleft(%s,7d,90)<>-1"
                     % (iref(kv_key("util_v6_pct")),
                        iref(kv_key("util_v6_pct"))),
                     "WARNING",
                     "7-day trend projects 90 percent within 24h; the "
                     "<>-1 guard suppresses the no-projection case."),
            ]),
        row("sweep_age", "nodeguard sweep age", "UNSIGNED",
            "seconds since the sweep last wrote the map statistics "
            "cache", units="s",
            triggers=[
                trig("nodeguard sweep cache stale on {HOST.NAME}",
                     "last(%s)>1800" % iref(kv_key("sweep_age")),
                     "WARNING",
                     "Three sweep periods without a cache write; map "
                     "counts are aging. Age is first-class so 0 scanned "
                     "can never read as 0 found."),
            ]),
        row("sweep_walk_ms", "nodeguard sweep walk duration", "FLOAT",
            "wall time of the sweep's full trie walk; trends make walk "
            "degradation visible before it hurts", units="ms"),
        row("top1_hits", "nodeguard top blocked hits", "UNSIGNED",
            "hit count of the busiest blocked entry at the last sweep",
            triggers=[
                trig("nodeguard block-hit pressure above weekly baseline "
                     "on {HOST.NAME}",
                     "baselinedev(%s,1h:now/h,\"d\",10)>3 and "
                     "last(%s)>1000"
                     % (iref(kv_key("top1_hits")),
                        iref(kv_key("top1_hits"))),
                     "INFO",
                     "Seasonal baseline deviation with an absolute "
                     "floor. Imported at Information severity; promoted "
                     "only after 14 days of reviewed-quiet trend rows."),
            ]),
        row("top_blocked", "nodeguard top blocked sources", "TEXT",
            "top-5 blocked sources ranked by hit DELTA since the "
            "previous sweep walk, cumulative carried as the secondary "
            "figure", trends="0"),
        row("rearm_count", "nodeguard re-arm count", "UNSIGNED",
            "cumulative once-per-boot kill-switch auto re-arms, from "
            "config map slot 2",
            triggers=[
                trig("nodeguard kill switch auto re-arm occurred on "
                     "{HOST.NAME}",
                     "change(%s)>0" % iref(kv_key("rearm_count")),
                     "WARNING",
                     "The watchdog re-armed enforcement after a latch; "
                     "review why the latch happened."),
            ]),
        row("prog_match", "nodeguard program identity match", "UNSIGNED",
            "1 = the live head program id equals "
            "/run/nodeguard/expected_prog_id; key omitted when the "
            "expected id is unknown, so the item goes unsupported "
            "instead of false-paging",
            triggers=[
                trig("nodeguard running program is not the installed one "
                     "on {HOST.NAME}",
                     "max(%s,3m)=0" % iref(kv_key("prog_match")), "HIGH",
                     "The attached XDP program is not the one reload or "
                     "attach installed; enforcement provenance unknown."),
            ]),
        row("attach_mode", "nodeguard attach mode", "TEXT",
            "native, skb, or none, from xdp-loader status", trends="0"),
        row("wd_canary_fail", "nodeguard watchdog canary failures",
            "UNSIGNED",
            "consecutive canary failures at the last completed watchdog "
            "cycle (one-cycle lag; triggers use >= so the lag cannot "
            "mask a trip)"),
        row("wd_lifeline_fail", "nodeguard watchdog lifeline failures",
            "UNSIGNED",
            "consecutive lifeline failures at the last completed "
            "watchdog cycle (one-cycle lag)"),
        row("wd_toolfail", "nodeguard watchdog tool failures", "UNSIGNED",
            "consecutive tooling failures at the last completed watchdog "
            "cycle (one-cycle lag)"),
        row("wd_clean", "nodeguard watchdog clean cycles", "UNSIGNED",
            "cumulative clean watchdog cycles; a stalled value with the "
            "timer active means the cycle is failing"),
        row("anomaly_count", "nodeguard anomaly count", "UNSIGNED",
            "cumulative volumetric anomaly trips from the gateway-local "
            "EWMA detector",
            triggers=[
                trig("nodeguard volumetric anomaly detected on "
                     "{HOST.NAME}",
                     "change(%s)>0" % iref(kv_key("anomaly_count")),
                     "HIGH",
                     "The gateway-local EWMA detector tripped: a "
                     "per-cycle delta exceeded max(floor, mean + K * "
                     "deviation) for the configured consecutive cycles."),
            ]),
        row("anomaly_shadow_count", "nodeguard anomaly shadow count",
            "UNSIGNED",
            "cumulative shadow-mode trips (logged and exported, no "
            "alerting side effects); used to review the training window "
            "before promotion"),
        row("anomaly_last_ts", "nodeguard last anomaly time", "UNSIGNED",
            "epoch of the most recent anomaly trip", units="unixtime"),
        row("sweep_timer", "nodeguard sweep timer state", "TEXT",
            "systemd is-active for nodeguard-sweep.timer (previously "
            "exported but untemplated)", trends="0",
            triggers=[
                trig("nodeguard sweep timer is not active on {HOST.NAME}",
                     "last(%s)<>\"active\"" % iref(kv_key("sweep_timer")),
                     "WARNING",
                     "Belt-and-braces companion to the sweep_age "
                     "trigger; the cache will age out while this is "
                     "inactive."),
            ]),
    ]
    return rows


# Triggers that reference more than one item live at export top level.
def build_multi_item_triggers():
    """Return the triggers whose expressions span more than one item, so
    they are attached at the export's top level rather than to any single
    item (for example stats unreadable, degraded attach mode)."""
    return [
        trig("nodeguard stats unreadable on {HOST.NAME}",
             "last(%s)=1 or nodata(%s,10m)=1"
             % (iref(kv_key("stats_read_fail")), iref(kv_key("pass"))),
             "WARNING",
             "stats_read_fail=1 or the counters are unsupported; XDP "
             "counters are unknown, not zero."),
        trig("suricata alive but counters unreadable on {HOST.NAME}",
             "nodata(%s,10m)=1 and last(%s)=\"active\""
             % (iref(kv_key("kernel_drops")), iref(kv_key("suricata"))),
             "WARNING",
             "Live unit, dead socket: suricata reports active but "
             "kernel_drops is unsupported, which ng.suricata alone "
             "cannot catch."),
        trig("nodeguard attached in degraded mode on {HOST.NAME}",
             "last(%s)<>\"native\" and last(%s)=\"attached\""
             % (iref(kv_key("attach_mode")), iref(kv_key("attach_state"))),
             "WARNING",
             "Attached but not in native driver mode; enforcement works "
             "with reduced performance headroom."),
        trig("nodeguard watchdog approaching trip on {HOST.NAME}",
             "last(%s)>=2 or last(%s)>=2"
             % (iref(kv_key("wd_canary_fail")),
                iref(kv_key("wd_lifeline_fail"))),
             "WARNING",
             "Two consecutive canary or lifeline failures; fires before "
             "the watchdog's soft-off trip. >= comparisons so the "
             "one-cycle export lag cannot mask a trip."),
        trig("nodeguard responder dry-run divergence on {HOST.NAME}",
             "(last(%s)-last(%s,#10))>0 and (last(%s)-last(%s,#10))=0"
             % (iref(kv_key("resp_dryrun_would_block")),
                iref(kv_key("resp_dryrun_would_block")),
                iref(kv_key("resp_blocks_issued")),
                iref(kv_key("resp_blocks_issued"))),
             "INFO",
             "Dry-run would-block is rising while issued blocks are "
             "flat: the responder wants to act and is configured not "
             "to."),
    ]


LLD_JS = (
    "var out = [];\n"
    "var re = /^ng\\.feeds_last_success_ts_(?!min=)([A-Za-z0-9_]+)=/gm;\n"
    "var m;\n"
    "while ((m = re.exec(value)) !== null) {\n"
    "  out.push({\"{#FEED}\": m[1]});\n"
    "}\n"
    "return JSON.stringify(out);"
)


def build_discovery_rule():
    """Return the low-level discovery rule that finds each configured feed
    from the kv export and, per feed, creates a last-success item, a
    snapshot-age item, and their staleness triggers."""
    succ_key = "nodeguard.feed.success_ts[{#FEED}]"
    age_key = "nodeguard.feed.age[{#FEED}]"
    succ = iref(succ_key)
    age = iref(age_key)
    return {
        "key": LLD_KEY,
        "name": "nodeguard feeds discovery",
        "description":
            "Discovers configured feed names from the "
            "feeds_last_success_ts_* keys in the kv export (excluding "
            "the _min aggregate). Prototype keys are distinct from the "
            "static per-feed keys so discovery never collides with them "
            "during the parity window.",
        "lifetime": "30d",
        "preprocessing": [
            {"type": "JAVASCRIPT", "parameters": [LLD_JS]},
            {"type": "DISCARD_UNCHANGED_HEARTBEAT", "parameters": ["1h"]},
        ],
        "item_prototypes": [
            {
                "key": succ_key,
                "name": "feed {#FEED} last success",
                "value_type": "UNSIGNED",
                "units": "unixtime",
                "description": "epoch of {#FEED}'s last successful HTTP "
                               "exchange (discovered)",
                "history": "31d",
                "trends": "180d",
                "regex": "(?m)^ng\\.feeds_last_success_ts_{#FEED}=(.+)$",
            },
            {
                "key": age_key,
                "name": "feed {#FEED} snapshot age",
                "value_type": "UNSIGNED",
                "units": "s",
                "description": "seconds since {#FEED}'s content last "
                               "changed (discovered)",
                "history": "31d",
                "trends": "180d",
                "regex": "(?m)^ng\\.feeds_snapshot_age_{#FEED}=(.+)$",
            },
        ],
        "trigger_prototypes": [
            trig("nodeguard feed {#FEED} stale (discovered) on "
                 "{HOST.NAME}",
                 "last(%s)>0 and fuzzytime(%s,46800)=0 and "
                 "nodata(%s,2h)=0" % (succ, succ, succ),
                 "INFO",
                 "Two full cycles plus margin without a successful "
                 "exchange. Information severity during the parity "
                 "window; the nodata guard silences a feed removed from "
                 "feeds.conf once discovery drops it."),
            trig("nodeguard feed {#FEED} failed open (discovered) on "
                 "{HOST.NAME}",
                 "last(%s)>0 and fuzzytime(%s,93600)=0 and "
                 "nodata(%s,2h)=0" % (succ, succ, succ),
                 "INFO",
                 "Entries for this feed have expired in-kernel; designed "
                 "decay, not an outage. Information severity during the "
                 "parity window; nodata-guarded."),
            trig("nodeguard feed {#FEED} upstream frozen (discovered) on "
                 "{HOST.NAME}",
                 "last(%s)>604800 and nodata(%s,2h)=0" % (age, age),
                 "INFO",
                 "Upstream unchanged for 7 days. Information severity "
                 "during the parity window; nodata-guarded."),
        ],
    }


# ---------------------------------------------------------------------------
# Rendering with uuid carry-over
# ---------------------------------------------------------------------------

def load_uuid_maps(committed_path):
    """Read the committed v1 template and index every existing object's uuid
    by its natural key (groups and templates by name, items by key, triggers
    by name, discovery rules and prototypes), so the render can carry each
    uuid over verbatim."""
    with open(committed_path) as fh:
        v1 = json.load(fh)
    exp = v1["zabbix_export"]
    maps = {
        "template_groups": {g["name"]: g["uuid"]
                            for g in exp.get("template_groups", [])},
        "templates": {},
        "items": {},
        "triggers": {},
        "discovery": {},
        "item_prototypes": {},
        "trigger_prototypes": {},
    }
    for t in exp.get("templates", []):
        maps["templates"][t["template"]] = t["uuid"]
        for it in t.get("items", []):
            maps["items"][it["key"]] = it["uuid"]
            for tr in it.get("triggers", []):
                maps["triggers"][tr["name"]] = tr["uuid"]
        for dr in t.get("discovery_rules", []):
            maps["discovery"][dr["key"]] = dr["uuid"]
            for ip in dr.get("item_prototypes", []):
                maps["item_prototypes"][ip["key"]] = ip["uuid"]
            for tp in dr.get("trigger_prototypes", []):
                maps["trigger_prototypes"][tp["name"]] = tp["uuid"]
    for tr in exp.get("triggers", []):
        maps["triggers"][tr["name"]] = tr["uuid"]
    return maps


def make_uuid(maps, kind, mapname, obj_key):
    """Carry the committed uuid verbatim; mint uuid5 only for new
    objects."""
    existing = maps[mapname].get(obj_key)
    if existing:
        return existing
    return uuid.uuid5(NODEGUARD_NS, "%s:%s" % (kind, obj_key)).hex


def render_trigger(maps, t, mapname="triggers", kind="trigger"):
    """Render one trigger definition into its export dict, attaching the
    carried-over or newly minted uuid."""
    return {
        "uuid": make_uuid(maps, kind, mapname, t["name"]),
        "name": t["name"],
        "expression": t["expression"],
        "priority": t["priority"],
        "description": t["description"],
    }


def render_item(maps, r):
    """Render one table row into a dependent-item export dict: uuid, key,
    the master-item link, the field-extraction regex (plus a
    CHANGE_PER_SECOND step for rate items), and any triggers."""
    key = kv_key(r["field"])
    field = r["rate_of"] or r["field"]
    d = {
        "uuid": make_uuid(maps, "item", "items", key),
        "name": r["name"],
        "type": "DEPENDENT",
        "key": key,
        "delay": "0",
        "value_type": r["value_type"],
    }
    if r["units"]:
        d["units"] = r["units"]
    d["description"] = r["description"]
    d["history"] = r["history"]
    d["trends"] = r["trends"]
    d["master_item"] = {"key": MASTER_KEY}
    pre = [{"type": "REGEX", "parameters": [rx(field), "\\1"]}]
    if r["rate"]:
        pre.append({"type": "CHANGE_PER_SECOND", "parameters": [""]})
    d["preprocessing"] = pre
    if r["triggers"]:
        d["triggers"] = [render_trigger(maps, t) for t in r["triggers"]]
    return d


def render_master(maps):
    """Render the single master item (the whole kv export polled once) that
    every other item depends on."""
    return {
        "uuid": make_uuid(maps, "item", "items", MASTER_KEY),
        "name": "nodeguard kv raw",
        "key": MASTER_KEY,
        "delay": "1m",
        "value_type": "TEXT",
        "description":
            "Master item: the whole nodeguard kv export in one agent "
            "poll. Every other item is dependent on it. Short history "
            "retention aids torn-parse debugging.",
        "history": "1d",
        "trends": "0",
    }


def render_discovery(maps):
    """Render the feed discovery rule and its item and trigger prototypes
    into their export dicts, carrying uuids over where they already exist."""
    src = build_discovery_rule()
    rule = {
        "uuid": make_uuid(maps, "discovery", "discovery", src["key"]),
        "name": src["name"],
        "type": "DEPENDENT",
        "key": src["key"],
        "delay": "0",
        "lifetime": src["lifetime"],
        "description": src["description"],
        "item_prototypes": [],
        "trigger_prototypes": [],
        "master_item": {"key": MASTER_KEY},
        "preprocessing": src["preprocessing"],
    }
    for ip in src["item_prototypes"]:
        rule["item_prototypes"].append({
            "uuid": make_uuid(maps, "item_prototype", "item_prototypes",
                              ip["key"]),
            "name": ip["name"],
            "type": "DEPENDENT",
            "key": ip["key"],
            "delay": "0",
            "value_type": ip["value_type"],
            "units": ip["units"],
            "description": ip["description"],
            "history": ip["history"],
            "trends": ip["trends"],
            "master_item": {"key": MASTER_KEY},
            "preprocessing": [
                {"type": "REGEX", "parameters": [ip["regex"], "\\1"]},
            ],
        })
    for tp in src["trigger_prototypes"]:
        rule["trigger_prototypes"].append(
            render_trigger(maps, tp, "trigger_prototypes",
                           "trigger_prototype"))
    return rule


def render(committed_path):
    """Assemble the complete v2 zabbix_export dict: template group,
    template with its master item, all dependent items, the discovery rule,
    and the top-level multi-item triggers, every uuid carried from the
    committed v1 where the object already existed."""
    maps = load_uuid_maps(committed_path)
    items = [render_master(maps)]
    items += [render_item(maps, r) for r in build_rows()]
    export = {
        "zabbix_export": {
            "version": "7.4",
            "template_groups": [
                {
                    "uuid": make_uuid(maps, "template_group",
                                      "template_groups", TEMPLATE_GROUP),
                    "name": TEMPLATE_GROUP,
                },
            ],
            "templates": [
                {
                    "uuid": make_uuid(maps, "template", "templates",
                                      TEMPLATE),
                    "template": TEMPLATE,
                    "name": TEMPLATE,
                    "description":
                        "nodeguard XDP firewall + Suricata IPS "
                        "monitoring. Requires the nodeguard.kv "
                        "UserParameter and sudoers rule from the "
                        "nodeguard repo (etc/).",
                    "groups": [{"name": TEMPLATE_GROUP}],
                    "items": items,
                    "discovery_rules": [render_discovery(maps)],
                },
            ],
            "triggers": [render_trigger(maps, t)
                         for t in build_multi_item_triggers()],
        },
    }
    return export


def main():
    """Command-line entry point: render the v2 template from the committed
    baseline, write it to --out as deterministic JSON, and print an item,
    trigger, and discovery-prototype count summary."""
    ap = argparse.ArgumentParser(
        description="Render the nodeguard Zabbix template v2 "
                    "deterministically, carrying every committed uuid "
                    "over verbatim.")
    ap.add_argument("--committed", default=COMMITTED,
                    help="committed v1 template JSON to carry uuids from "
                         "(default: templates/zabbix-nodeguard-"
                         "template.json)")
    ap.add_argument("--out", default=DEFAULT_OUT,
                    help="output path (default: zbx/preview-template-"
                         "v2.json; pointing this at templates/ is a "
                         "deliberate rollout step, not a review step)")
    args = ap.parse_args()

    if not os.path.exists(args.committed):
        print("error: committed template not found: %s" % args.committed,
              file=sys.stderr)
        return 1
    export = render(args.committed)
    text = json.dumps(export, indent=1)
    with open(args.out, "w") as fh:
        fh.write(text)
    tpl = export["zabbix_export"]["templates"][0]
    n_items = len(tpl["items"])
    n_trig = sum(len(i.get("triggers", [])) for i in tpl["items"])
    n_trig += len(export["zabbix_export"]["triggers"])
    dr = tpl["discovery_rules"][0]
    print("wrote %s" % args.out)
    print("items: %d (1 master), triggers: %d, discovery rules: 1 "
          "(%d item prototypes, %d trigger prototypes)"
          % (n_items, n_trig, len(dr["item_prototypes"]),
             len(dr["trigger_prototypes"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
