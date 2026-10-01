#!/usr/bin/env python3
"""spec-graph check #3 — a probed claim's instrument matches its kind.

The ledger records, per claim, the `probe_kind` used (`executed | read | search`). A
`behavior` or `primitive` claim (what code does over an input) cannot be settled by reading
the code: a read never sees the input the bug needs.

INSTRUMENT: every claim whose verdict means it was probed (`holds | refuted | unrefuted`)
needs a `probe_kind` drawn from the set its `kind` admits (`_REQUIRED`). `unprobed` and
`deferred` are skipped. Unknown `kind` or `probe_kind` values are flagged.

TYPING: `kind` is author-declared, so mis-typing would bypass the table. A claim whose
sentence makes a runtime prediction (`raises`, `returns`, `coerces`, `defaults to`,
`silently`, ...) may not be typed `referential` or `census`. Grammar only; the escape
hatch is a reviewed baseline entry.

PROBE CORPUS: a probe that enumerates names out of a tree (`ls-tree`, a glob, a directory
walk) must record the `alphabet:` it sampled: ordinary names, non-ASCII, a name with a
space, and the cwd it ran from. An ASCII-only sample at the repo root hides C-quoting,
whitespace splitting and cwd-relative output. The check reads only that each class is
addressed, never the answer.

SPEND POINTS: `cites: [<claim id>, ...]` anywhere in the gate block or on a demand must
resolve to a probed claim. `cites` is required on a judgment rule's (R0, R5, R6)
`fired: false`, every `pre_discharged` credit, and every `form: waiver` demand. The
`*_waivers` maps cannot carry `cites` without a shape change, so those stay a phase-F hand
check.

Usage:
    spec-graph claims [graph.yaml ...] [--config <path>]
(the `spec-graph` wrapper in the plugin's bin/ is on the Bash PATH and finds this script itself.)
Exit 1 if any claim's instrument is wrong or missing, any name-enumerating probe leaves its
corpus alphabet unstated, or any spend-point citation is missing, dangling, or unprobed.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

import _cli
import _config
import _schema

# kind -> the probe_kinds it may close on (rules.md describes it; this table enforces it).
# Only `executed` runs the logic, so claims about what code does demand it.
_REQUIRED: dict[str, set[str]] = {
    "referential": {"read", "search"},   # the symbol/path exists — read/import/stat, or a defs search
    "census": {"search"},                # the full hit list — the search that established it
    "behavior": {"executed"},            # what existing code does on an input — run it
    "primitive": {"executed"},           # an I/O primitive's contract — execute it
    "reachability": {"executed"},        # a break-attempt is an execution
    "discharge": {"executed", "read", "search"},  # inherits its cited claim's instrument
}
_PROBE_KINDS = {"executed", "read", "search"}
_PROBED = {"holds", "refuted", "unrefuted"}   # an instrument was used — require probe_kind
_UNPROBED = {"unprobed", "deferred"}          # nothing run yet — skip (step-9 handles unprobed)
#: fired:false here rests on an agent's reading, not a slot predicate — it must cite.
_JUDGMENT_RULES = set(_schema.JUDGMENT)

#: The kinds a claim may close on without running anything (guarded by `check_typing`).
_INSPECTABLE = {"referential", "census"}

#: Runtime-action grammar: verbs that predicate over an input rather than the tree's shape
#: ("exists", "is defined" stay allowed). Whole words, so `returns` does not match
#: `returning-path`.
_RUNTIME_GRAMMAR = re.compile(
    r"\b(raise[sd]?|throws?|returns?|coerces?|normali[sz]es?|parses?|seriali[sz]es?"
    r"|rejects?|accepts?|swallows?|truncates?|overwrites?|crashe[sd]?"
    r"|fails?|succeeds?|skips?|drops?|handles?|silently|defaults? to|falls? back)\b",
    re.IGNORECASE,
)


#: Instruments that enumerate names out of a tree (directory listing, VCS tree read, glob):
#: their answer depends on what the sampled names looked like.
_ENUMERATION_GRAMMAR = re.compile(
    r"\b(ls-tree|ls-files|--name-only|--porcelain|rglob|iterdir|scandir|listdir"
    r"|os\.walk|\.glob\(|glob\(|find -)",
    re.IGNORECASE,
)

#: The value classes a name-enumerating probe must say it sampled, and why each matters.
_ALPHABET_CLASSES: dict[str, str] = {
    "ascii": "the ordinary names — the sample every probe already takes",
    "non-ascii": "git C-QUOTES a non-ASCII path under `--name-only`, and a shell tool may "
                 "transliterate or reorder it; the entry stops having the shape the reader matches",
    "space": "a whitespace split TEARS a name containing a space into two tokens, and a "
             "non-`-z` listing gives the reader no way to tell that happened",
    "cwd": "a VCS listing is resolved from the CWD unless told otherwise, while a "
           "path-addressed read beside it is resolved from the project root — a probe run "
           "only at the root cannot see the two disagree",
}


def check_alphabet(path: Path, graph: dict) -> list[str]:
    """rules.md's "probe values must sample the types the boundary admits", for names read out
    of a tree.

    A probe that enumerates names owes a sentence per class in `_ALPHABET_CLASSES`: what it
    sampled, or why the class cannot arise here. Writing it forces the author to look. The
    check reads only that a non-empty answer exists.
    """
    findings: list[str] = []
    for c in graph.get("claims", []) or []:
        # Not gated on `probe_kind == "executed"`: census claims must close on `search`, and an
        # enumeration is as often a `search` or `read` probe. Unprobed claims owe nothing yet.
        #
        # The text scope is wide (claim + probe + observed): matching `probe:` alone misses
        # claims that name the instrument in the claim text. The few prose false positives
        # this admits are baselined.
        if c.get("verdict") in _UNPROBED:
            continue
        text = " ".join(str(c.get(k, "")) for k in ("claim", "probe", "observed"))
        m = _ENUMERATION_GRAMMAR.search(text)
        if not m:
            continue
        cid = c.get("id", "<no-id>")
        alphabet = c.get("alphabet")
        if alphabet is None:
            findings.append(
                f"{path.name}:{cid}: enumerates names (`{m.group(0)}`) and records no "
                f"`alphabet` — a probe whose OUTPUT becomes the reader cannot be read back "
                f"for the inputs it never sampled. Name {sorted(_ALPHABET_CLASSES)}."
            )
            continue
        if not isinstance(alphabet, dict):
            findings.append(
                f"{path.name}:{cid}: `alphabet` is a {type(alphabet).__name__}, not a "
                f"mapping of {sorted(_ALPHABET_CLASSES)} -> what was sampled."
            )
            continue
        for cls, why in _ALPHABET_CLASSES.items():
            value = alphabet.get(cls)
            if value is None:
                findings.append(
                    f"{path.name}:{cid}: `alphabet` names no `{cls}` — {why}. Say what the "
                    f"probe sampled, or why the class cannot arise at this boundary."
                )
            elif not str(value).strip():
                findings.append(
                    f"{path.name}:{cid}: `alphabet.{cls}` is empty — a blank value is "
                    f"nobody looking, which is the state this check exists to end."
                )
    return findings


def check_typing(path: Path, graph: dict) -> list[str]:
    """A claim whose sentence makes a runtime prediction may not be typed into an inspectable
    kind: `kind` is author-declared, and a read cannot falsify a prediction over an input.

    Flags grammar only. The remedy is to retype and run the probe; the escape hatch is a
    reviewed baseline entry, not a field the author can set.
    """
    findings: list[str] = []
    for c in graph.get("claims", []) or []:
        if c.get("kind") not in _INSPECTABLE or c.get("verdict") in _UNPROBED:
            continue
        if c.get("probe_kind") == "executed":
            continue  # a stronger instrument than required
        m = _RUNTIME_GRAMMAR.search(str(c.get("claim", "")))
        if m:
            findings.append(
                f"{path.name}:{c.get('id', '<no-id>')}: typed `{c.get('kind')}` and closed on "
                f"`{c.get('probe_kind')}`, but the claim predicts runtime behavior "
                f"(`{m.group(0)}`) — a prediction over an input is a `behavior`/`primitive`/"
                f"`reachability` claim and owes an executed probe. Retype it and run it."
            )
    return findings


def _cited(entry: dict) -> list[str]:
    c = entry.get("cites")
    if c is None:
        return []
    return [str(x) for x in c] if isinstance(c, list) else [str(c)]


def check_spend_points(path: Path, graph: dict) -> list[str]:
    # str() to match `_cited`, so an int id (`cites: [12]`) resolves.
    verdicts = {
        str(c.get("id")): c.get("verdict")
        for c in graph.get("claims", []) or []
        if c.get("id") is not None
    }
    findings: list[str] = []

    def resolve(where: str, entry: dict, required: str | None = None) -> None:
        ids = _cited(entry)
        if not ids and required:
            findings.append(
                f"{path.name}:{where}: {required} closes with no `cites` — an uncited "
                f"rationale is asserted, a finding, not a pass (rules.md, 'Probed claims')."
            )
        for cid in ids:
            if cid not in verdicts:
                findings.append(f"{path.name}:{where}: cites `{cid}`, which is no claim in "
                                f"this graph's ledger.")
            elif verdicts[cid] not in _PROBED:
                findings.append(
                    f"{path.name}:{where}: cites `{cid}` (verdict `{verdicts[cid]}`) — a "
                    f"spend-point resting on a claim nothing has probed."
                )

    gate = graph.get("gate", {}) or {}
    for e in gate.get("evaluated", []) or []:
        rule = str(e.get("rule"))
        need = (f"judgment rule {rule} `fired: false`"
                if e.get("fired") is False and rule in _JUDGMENT_RULES else None)
        resolve(f"gate.evaluated[{rule}]", e, need)
    for e in gate.get("pre_discharged", []) or []:
        resolve(f"gate.pre_discharged[{e.get('element')}]", e, "a pre-discharge credit")
    for e in gate.get("obligations", []) or []:
        resolve(f"gate.obligations[{e.get('element')}]", e)
    for e in gate.get("holes", []) or []:
        # A hole closed by judgment alone (no spawned `resolved_to` demand) must cite.
        need = ("a hole resolved with no spawned demand"
                if e.get("resolution") and not e.get("resolved_to") else None)
        resolve(f"gate.holes[{e.get('element')}]", e, need)
    for d in graph.get("demands", []) or []:
        if d.get("form") == "waiver":
            resolve(f"demand {d.get('id')}", d, "a waiver's rationale")
        else:
            resolve(f"demand {d.get('id')}", d)
    return findings


def check(path: Path, graph: dict) -> list[str]:
    findings: list[str] = []
    for c in graph.get("claims", []) or []:
        cid = c.get("id", "<no-id>")
        kind, verdict, pk = c.get("kind"), c.get("verdict"), c.get("probe_kind")
        if kind not in _REQUIRED:
            findings.append(f"{path.name}:{cid}: unknown kind `{kind}` (not one of {sorted(_REQUIRED)}).")
            continue
        if verdict in _UNPROBED:
            continue
        if verdict not in _PROBED:
            findings.append(f"{path.name}:{cid}: unknown verdict `{verdict}`.")
            continue
        if pk is None:
            findings.append(
                f"{path.name}:{cid}: `{kind}` is {verdict} but records no `probe_kind` "
                f"— name the instrument used ({sorted(_REQUIRED[kind])})."
            )
        elif pk not in _PROBE_KINDS:
            findings.append(f"{path.name}:{cid}: unknown probe_kind `{pk}` (not one of {sorted(_PROBE_KINDS)}).")
        elif pk not in _REQUIRED[kind]:
            findings.append(
                f"{path.name}:{cid}: `{kind}` requires probe_kind {sorted(_REQUIRED[kind])} but closed "
                f"on `{pk}` — a claim about what code does over an input is not settled by reading it."
            )
    return findings


def main(argv: list[str]) -> int:
    _cli.utf8_stdio()
    opts, args = _cli.parse_argv(argv, valued={"--config"})
    cfg = _config.load(opts["config"])
    paths = [Path(a) for a in args] or _config.artifacts(cfg)
    if not paths:
        # Nothing to check is could-not-look (2), not clean.
        print("check_claims: no spec_graph_*.yaml found", file=sys.stderr)
        return 2
    findings: list[str] = []
    spend: list[str] = []
    typing: list[str] = []
    alphabet: list[str] = []
    unreadable: list[Path] = []
    for p in paths:
        # Parsed once for all passes. The passes run inside the try: nested wrong shapes
        # surface as AttributeError mid-walk, the same could-not-read class.
        try:
            graph = _cli.load_graph(p)
            findings.extend(check(p, graph))
            spend.extend(check_spend_points(p, graph))
            typing.extend(check_typing(p, graph))
            alphabet.extend(check_alphabet(p, graph))
        # `ValueError` covers UnicodeDecodeError, which is not an OSError.
        except (OSError, ValueError, yaml.YAMLError, TypeError, AttributeError) as e:
            # Collected, not returned on, so other graphs' findings still print.
            print(f"check_claims: cannot read {p}: {e.__class__.__name__}: {e}", file=sys.stderr)
            unreadable.append(p)
            continue
    for f in findings:
        print(f"  INSTRUMENT {f}")
    for f in typing:
        print(f"  MISTYPED {f}")
    for f in alphabet:
        print(f"  CORPUS {f}")
    for f in spend:
        print(f"  CITATION {f}")
    # Counted by kind: four different slips.
    print(f"\n[check_claims] {len(findings)} claim-instrument finding(s), {len(typing)} "
          f"claim-typing finding(s), {len(alphabet)} probe-corpus finding(s), {len(spend)} "
          f"spend-point citation finding(s) over {len(paths)} graph(s).")
    if unreadable:
        return 2
    return 1 if findings or typing or alphabet or spend else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
