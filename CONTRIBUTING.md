# Contributing

## Code annotation standard

Comments explain why, not what. Load-bearing comments carry one of these
tags so a reader can find every safety argument, contract, and accepted
risk mechanically (`grep -rn 'SAFETY:\|INVARIANT:\|RESIDUAL:'`):

- `SAFETY:` why a failure path is safe, always in terms of the fail-open
  contract (what traffic does when this code is wrong, dead, or absent).
- `INVARIANT:` a contract other code depends on; breaking it requires
  updating every referenced dependent. Name the dependents.
- `RESIDUAL:` an accepted residual risk, with the reason it is accepted
  and what bounds it.
- `NOTE:` non-obvious context that is neither a safety argument nor a
  contract (tool quirks, kernel behavior, ordering subtleties).
- `TODO(#n):` deferred work, always linked to a GitHub issue number.
  Bare TODOs are not accepted.

Rules:

- Tags start a comment line; the text after the tag stands alone (no
  reliance on surrounding prose).
- Do not tag routine comments; a tag that does not carry weight dilutes
  the ones that do.
- The XDP program's per-packet decision path and every enforcement write
  path (block, kill switch, sweep, responder gates) must carry SAFETY or
  INVARIANT tags; a change that removes one must replace the argument.

## Style

- Bash: `set -uo pipefail`, shellcheck-clean, quote expansions.
- Python: stdlib only, py_compile-clean.
- No emojis; no em or en dashes in prose (semicolons, colons, commas,
  parentheses; ranges as "X to Y").
- No AI attribution in commits. Imperative commit subjects, <= 72 chars.

## Verification before claiming done

`bash -n` and `shellcheck` on every script, `python3 -m py_compile` on
every Python file, `build/build.sh` in a privileged Fedora 44 container
(compiles, generates the map spec, and rehearses the pin/attach sequence
in a netns), and `openspec validate --strict` for spec changes.
