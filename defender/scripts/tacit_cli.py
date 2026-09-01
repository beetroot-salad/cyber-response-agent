"""`tacit_cli` — the tacit-knowledge registry's author-side CLI: does this file say what its
author thinks it says?

    defender/.venv/bin/python -m defender.scripts.tacit_cli check [--defender-dir <tree>]
    defender/.venv/bin/python -m defender.scripts.tacit_cli show  [--defender-dir <tree>] [--as-of YYYY-MM-DD]

WHY IT EXISTS. The registry is the one system in this tree with no service behind it: a human
edits a YAML file and commits it, and the commit IS the sign-off. Everything about that is
deliberate — but until this, the edit had no feedback of any kind. A malformed entry is DROPPED
rather than refused (one bad row must not sink every sanction in the estate), the reason is
printed on stderr DURING AN INVESTIGATION RUN, and nobody is watching that stream. So a typo
produced exactly the outcome an unwritten entry produces: the lookup misses, the authorization
contract falls through to `indeterminate`, and the run escalates a case somebody had already
sanctioned. The failure is silent, and it is silent in the direction that looks like ordinary
operation.

The refusal text was already written for a human — `_read_entry`'s docstring says "the refusal
text is what a human editing the file reads on stderr, so it names the field and the rule". It
had no reader. This is the reader.

THE ONE RULE THIS MODULE LIVES BY, borrowed verbatim from `policy_cli`: **it is a second
CONSUMER of the loader, never a second implementation.** `check` calls
`tacit_knowledge_adapter.read_registry` — the same walk `load_entries` serves a live `lookup`
from — and prints what it returns. A validator that modelled the rules separately would be
worse than none, because it would certify a file the runtime reads differently: it would tell
someone their sanction is live while every lookup in production misses it.

That rule is also why the ADVICE below is labelled as advice. `check`'s FAILURES are exactly
the loader's drops and nothing else. Everything under `notes` — an entry expiring soon, a scope
that is legal and broad — is something the loader deliberately does NOT judge (see
`TACIT_KNOWLEDGE_MIN_LITERAL_SCOPE_CHARS`: "this is a shape rule, not a breadth proof"), and
printing it as a failure would quietly mint a second policy.

A MAINTAINER tool, not an agent one, and there is no `bin/` shim on purpose. No agent reads the
registry this way — the runtime reaches it through the typed `query` tool — so a `defender-*`
token here would be one more command for the gate to classify and one more thing a lane could
be talked into. Humans and CI invoke it as a module, the way the lint gates are invoked.
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

#: How close to its `review_by` an entry has to be before `check` mentions it. Advice, never a
#: failure: an entry inside its window is doing exactly what it is supposed to, and refusing one
#: for being near its end would make the review date mean something it does not.
#:
#: Sized as a working month, so the note lands with time to re-attest before the sanction stops
#: answering — the point is that the drop-off is currently invisible until a run escalates.
_EXPIRING_SOON_DAYS = 30

#: How many literal characters a scope carries before `check` stops calling it broad. Well above
#: the loader's own minimum, and it is NOT a second threshold: nothing here refuses a scope the
#: loader admits. It exists because the loader's rule is stated as a shape rule with a named
#: limit — "no character count can tell a fleet-wide sanction a human MEANT from one they wrote
#: carelessly" — and the thing that CAN tell them apart is the human reading this output.
_BROAD_SCOPE_CHARS = 8


def _notes(entry: dict[str, str], today: dt.date) -> list[str]:
    """Advisory observations about one loaded entry — never a reason to fail.

    Each is something the loader deliberately does not judge, surfaced at the one moment a
    person is in a position to act on it: while they are editing the file.
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
        # A scope with no metacharacter names ONE thing, however short: `uid-0` is the design's
        # own motivating actor and is exactly as precise as a forty-character hostname. Breadth
        # comes from the wildcard, so only a scope that HAS one can be called broad — otherwise
        # the note fires on the canonical entry and teaches the reader to skip these.
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
    """What is IN FORCE as of `today` — the question a reviewer actually asks of this file.

    Separate from `check` because they answer different questions and a run answers only this
    one: a file can be perfectly well formed and cover nothing, every entry having quietly aged
    past its own review date.
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
    # lint-default: ok — a CLI boundary owning its default: `--defender-dir` is resolved ONCE
    # here, into a concrete path threaded inward, exactly as `policy_cli` resolves its own.
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
    raise SystemExit(main())
