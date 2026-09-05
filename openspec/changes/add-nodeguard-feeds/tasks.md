## 1. Implementation

- [x] 1.1 Extract contains_protected() in ngmap.py; update_map/delete_key
      raise RuntimeError, CLI wrappers convert to die()
- [x] 1.2 Write bin/nodeguard-feeds (fetch, validate, gate, reconcile,
      journal, CLI modes run/diff/apply/withdraw/status)
- [x] 1.3 Units, example feeds.conf, deploy.sh integration
- [x] 1.4 nodeguard-status kv fields from feeds.kv
- [x] 1.5 Zabbix template items and triggers
- [x] 1.6 Adversarial code review of the implementation; resolve findings

## 2. Verification

- [x] 2.1 shellcheck, py_compile, systemd-analyze verify
- [x] 2.2 Live fetch of each feed URL confirms the parser grammars
      (DShield grammar and drop_v6 prefix floor especially)
- [ ] 2.3 Deploy to both hosts; full dry-run cycle produces last-diff.txt

## 3. Activation

- [ ] 3.1 At least two dry-run diffs reviewed on real data per host
- [ ] 3.2 DShield NC-license judgment recorded before its promotion
- [ ] 3.3 Promote spamhaus feeds on the internet gateway via
      apply --confirm; watch feeds kv and canary a full cycle
- [ ] 3.4 Promote on the remote node; alarms proven live
