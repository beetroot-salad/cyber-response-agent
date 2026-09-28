"""`tacit_cli` — the tacit-knowledge registry's author-side CLI: does this file say what its
author thinks it says?

    defender/.venv/bin/python -m defender.scripts.tacit_cli check [--defender-dir <tree>]
    defender/.venv/bin/python -m defender.scripts.tacit_cli show  [--defender-dir <tree>] [--as-of YYYY-MM-DD]

The registry is a hand-edited, committed YAML file. A malformed entry is dropped rather than
refused, and the reason goes to stderr during an investigation run where nobody reads it, so a
typo looks exactly like an unwritten entry: the lookup misses and the run escalates a case
someone had sanctioned. This gives the loader's refusal text a reader.

It is a second consumer of the loader, never a second implementation: `check` prints what
`tacit_knowledge_adapter.read_registry` returns, the same walk a live `lookup` uses. A separate
validator could certify a file the runtime reads differently. For the same reason `check` fails
only on the loader's drops; everything under `notes` (expiring soon, legal but broad) is advice
the loader does not judge.

A maintainer tool with no `bin/` shim: agents reach the registry through the typed `query`
tool, and a `defender-*` command would be one more thing for the gate to classify. Humans and
CI run it as a module.
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from pathlib import Path

from defender._paths import PATHS
from defender.scripts.adapters.tacit_knowledge_adapter import (
    _literal_chars,
    _parse_date,
    read_registry,
    registry_path,
)

#: How close to `review_by` an entry must be before `check` mentions it — advice, never a
#: failure. A working month, leaving time to re-attest before the sanction silently stops.
_EXPIRING_SOON_DAYS = 30

#: Literal characters below which a wildcarded scope is called broad. Advice only, never a
#: second threshold: the loader's minimum is a shape rule, and only the human reading this can
#: tell whether the breadth was meant.
_BROAD_SCOPE_CHARS = 8


def _notes(entry: dict[str, str], today: dt.date) -> list[str]:
    """Advisory observations about one loaded entry — never a reason to fail — surfaced while
    the author is editing the file.
    """
    out: list[str] = []
    review_by = _parse_date(entry["review_by"])
    added_at = _parse_date(entry["added_at"])
    if review_by is not None:
        remaining = (review_by - today).days
        if remaining < 0:
            out.append(
                f"EXPIRED {-remaining} day(s) ago — it loads, and every lookup against it is a "
                f"plain miss. Re-attest it in a fresh commit (move `added_at` and `review_by`) "
                f"or delete it; leaving it here reads as coverage that is not there"
            )
        elif remaining <= _EXPIRING_SOON_DAYS:
            out.append(
                f"expires in {remaining} day(s) — past `review_by` it stops answering silently, "
                f"so re-attest it before then if the sanction still holds"
            )
    if added_at is not None and added_at > today:
        out.append(
            f"`added_at` is {(added_at - today).days} day(s) in the future — it will not answer "
            f"any lookup until then"
        )
    for field in ("actor_scope", "host_scope"):
        scope = entry[field]
        # Without a wildcard a scope names one thing however short (`uid-0`), so only a
        # wildcarded scope can be broad.
        if not any(ch in scope for ch in "*?[") or _literal_chars(scope) >= _BROAD_SCOPE_CHARS:
            continue
        out.append(
            f"`{field}` is {scope!r} — legal, and broad: {_literal_chars(scope)} literal "
            f"character(s) around a wildcard. The loader's minimum is a shape rule, not a "
            f"breadth proof; confirm you MEANT everything this covers"
        )
    return out


def _report_drops(path: Path, today: dt.date) -> int:
    """Report what the runtime will and will not read out of `path`. Exit 1 on any drop."""
    read = read_registry(path)
    print(f"tacit-knowledge registry: {path}")

    if read.fatal is not None:
        print(f"\n  [✗] {read.fatal}")
        print(
            "\n1 fatal: NOTHING in this file answers a lookup, and a run cannot tell that from "
            "an empty registry — every authorization contract it should cover falls through to "
            "`indeterminate`."
        )
        return 1

    for refusal in read.refusals:
        print(f"\n  [✗] DROPPED — {refusal}")
    for entry in read.entries:
        print(f"\n  [✓] {entry['id']}  ({entry['added_by']}, review_by {entry['review_by']})")
        print(f"        {entry['actor_scope']} on {entry['host_scope']}: {entry['pattern']}")
        for note in _notes(entry, today):
            print(f"      [!] {note}")

    live = sum(1 for e in read.entries if not _expired(e, today))
    print(
        f"\n{len(read.entries) + len(read.refusals)} entr(ies): {len(read.entries)} load "
        f"({live} answering as of {today.isoformat()}), {len(read.refusals)} dropped."
    )
    if read.refusals:
        print(
            "A dropped entry is INDISTINGUISHABLE from one nobody wrote — the lookup misses and "
            "the run escalates. Fix each reason above and re-run."
        )
        return 1
    return 0


def _expired(entry: dict[str, str], today: dt.date) -> bool:
    review_by = _parse_date(entry["review_by"])
    added_at = _parse_date(entry["added_at"])
    if review_by is None or added_at is None:
        return True
    return not added_at <= today <= review_by


def _report_in_force(path: Path, today: dt.date) -> int:
    """What is in force as of `today`. Separate from `check`: a well-formed file can cover
    nothing once every entry has aged past its review date.
    """
    read = read_registry(path)
    if read.fatal is not None:
        print(f"[✗] {read.fatal}", file=sys.stderr)
        return 1
    live = [e for e in read.entries if not _expired(e, today)]
    if not live:
        print(
            f"No sanction is in force as of {today.isoformat()} "
            f"({len(read.entries)} entr(ies) load, {len(read.refusals)} dropped)."
        )
        return 0
    for entry in live:
        print(f"{entry['id']}")
        print(f"  action    {entry['pattern']}")
        print(f"  actor     {entry['actor_scope']}")
        print(f"  host      {entry['host_scope']}")
        print(f"  authored  {entry['added_by']} on {entry['added_at']}")
        print(f"  review_by {entry['review_by']}")
        print(f"  because   {entry['justification']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tacit_cli",
        description=(
            "Validate and read the tacit-knowledge registry — the human-authored file that "
            "records which actor may do what on which hosts."
        ),
    )
    parser.add_argument(
        "command", choices=("check", "show"),
        help=(
            "check: report every entry the runtime will DROP, and why (exit 1 if any). "
            "show: the sanctions in force right now."
        ),
    )
    # lint-default: ok — a CLI boundary resolving `--defender-dir` once, as `policy_cli` does.
    parser.add_argument(
        "--defender-dir", type=Path, default=None,
        help="the defender tree to read (default: this checkout's)",
    )
    parser.add_argument(
        "--as-of", default=None, metavar="YYYY-MM-DD",
        help="judge expiry as of this date instead of today",
    )
    args = parser.parse_args(argv)

    defender_dir = args.defender_dir if args.defender_dir is not None else PATHS.defender_dir
    today = dt.date.today() if args.as_of is None else _parse_date(args.as_of)
    if today is None:
        print(f"--as-of {args.as_of!r} is not an ISO date (YYYY-MM-DD)", file=sys.stderr)
        return 2
    path = registry_path(defender_dir)
    return (_report_drops if args.command == "check" else _report_in_force)(path, today)


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    raise SystemExit(main())
