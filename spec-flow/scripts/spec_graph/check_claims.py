#!/usr/bin/env python3
"""spec-graph check #3 — a probed claim's instrument matches its kind (#633).

The ledger records, per claim, the `probe_kind` actually used (`executed | read | search`).
The escape this closes: a `behavior` or `primitive` claim — a claim about what code does over
an input — "probed" by READING the code. A read holds at parse level over exactly the input
the bug needs to see, so the suite pins the bug green. The prose rule "run it and watch" never
bit because nothing separated an execution from an inspection at gate time; this check is that
separation.

THE CHECK (deterministic, no LLM): for every claim whose verdict means it was probed
(`holds | refuted | unrefuted`), require a `probe_kind` present and drawn from the set its
`kind` admits — the `_REQUIRED` table below is the single source of truth for the mapping.
`unprobed`/`deferred` carry no instrument and are skipped (an `unprobed` load-bearing claim is
step-9's own finding, not this check's). An unknown `kind` or `probe_kind` is flagged too — the
closed vocabulary is enforced here.

THE TYPING PASS (same run): the table above is keyed on a kind the AUTHOR declares, so
mis-typing is a free way past it — and that is not hypothetical, it is how the claim behind
the most recent shipped defect closed on a read while predicting what every persisted record
holds. A claim whose sentence makes a runtime prediction (`raises`, `returns`, `coerces`,
`defaults to`, `silently`) may not be typed `referential` or `census`, whatever its author
believed. Grammar only, never judgment; the escape hatch is a reviewed baseline entry.

THE PROBE-CORPUS PASS (same run): the instrument can be right and the probe still blind, if it
ran over the one input class that cannot fail. A probe that ENUMERATES NAMES out of a tree
(`ls-tree`, a glob, a directory walk) must record the `alphabet:` it sampled — ordinary names,
non-ASCII, a name with a space, and the cwd it ran from. #869 shipped three defects through a
probe that was executed, correctly typed and correctly instrumented, whose output was
transcribed into the reader and into the test that asserted on it: the tree it enumerated was
ASCII, at the repo root, so C-quoting, `.split()`-on-spaces and cwd-relative output were all
invisible. A class that cannot arise closes by saying so; the check reads the presence of the
sentence, never its content.

THE SPEND-POINT PASS (same run): rules.md's "a spend-point closes only by citation", as a
field — `cites: [<claim id>, ...]`. Any `cites` anywhere in the gate block or on a demand
must resolve to a claim that exists and was probed (`holds | refuted | unrefuted`) — a
citation of an `unprobed`/`deferred` claim rests on nothing executed. `cites` is REQUIRED
on: a `fired: false` for a judgment rule (R0, R5, R6 — where no slot predicate computed the
no; `spec-graph gate` verifies the computed rules' `fired` flags against the slots), every
`pre_discharged` credit, and every `form: waiver` demand. The `binds_waivers` /
`exercise_waivers` / `actor_waivers` maps cannot carry a `cites` without a shape change
check_binds/check_actors would trip over — those citations stay a phase-F hand check.

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

# kind -> the probe_kinds it may legitimately close on. The one place the mapping lives: the
# rules.md prose describes it for the human, this table enforces it, and the check flags any
# drift. `read`/`search` are inspections; only `executed` runs the logic under test — which is
# why the behavior/primitive/reachability claims (about what code DOES) demand it.
_REQUIRED: dict[str, set[str]] = {
    "referential": {"read", "search"},   # the symbol/path exists — read/import/stat, or a defs search
    "census": {"search"},                # the full hit list — the search that established it
    "behavior": {"executed"},            # what existing code does on an input — run it
    "primitive": {"executed"},           # an I/O primitive's contract — execute it
    "reachability": {"executed"},        # a break-attempt is an execution
    "discharge": {"executed", "read", "search"},  # inherits its cited claim's instrument (#634 pins the cross-claim link)
}
_PROBE_KINDS = {"executed", "read", "search"}
_PROBED = {"holds", "refuted", "unrefuted"}   # an instrument was used — require probe_kind
_UNPROBED = {"unprobed", "deferred"}          # nothing run yet — skip (step-9 handles unprobed)
#: fired:false here rests on an agent's reading, not a slot predicate — it must cite.
_JUDGMENT_RULES = set(_schema.JUDGMENT)

#: The kinds a claim may close on WITHOUT running anything. The typing pass below exists
#: because membership here is what the instrument table trusts, and the author declares it.
_INSPECTABLE = {"referential", "census"}

#: Runtime-action grammar: verbs that predicate over an INPUT rather than over the tree's
#: shape. Deliberately narrow — a claim can say "exists", "is defined", "is imported by" and
#: mean it, but nothing that only exists can also raise, coerce, or default. Each is a whole
#: word so `returns` does not fire on `returning-path`, and each is a verb a reader cannot
#: settle: seeing the `raise` statement is not seeing that this input reaches it.
_RUNTIME_GRAMMAR = re.compile(
    r"\b(raise[sd]?|throws?|returns?|coerces?|normali[sz]es?|parses?|seriali[sz]es?"
    r"|rejects?|accepts?|swallows?|truncates?|overwrites?|crashe[sd]?"
    r"|fails?|succeeds?|skips?|drops?|handles?|silently|defaults? to|falls? back)\b",
    re.IGNORECASE,
)


#: Instruments that ENUMERATE names out of a tree — a directory listing, a VCS tree read, a
#: glob. Closed and concrete on purpose: these are the probes whose recorded OUTPUT becomes an
#: implementation, and whose answer depends on what the names in the sampled tree looked like.
#: A probe that runs a function over a value it constructed is not in this class — its input
#: is written down in the probe itself.
_ENUMERATION_GRAMMAR = re.compile(
    r"\b(ls-tree|ls-files|--name-only|--porcelain|rglob|iterdir|scandir|listdir"
    r"|os\.walk|\.glob\(|glob\(|find -)",
    re.IGNORECASE,
)

#: The value classes a name-enumerating probe must say it sampled, and why each is here. Every
#: one is a class the #869 probe did not sample and the shipped reader then got wrong.
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
    """rules.md's "probe values must sample the types the boundary admits", made mechanical
    for the one value space no reader can enumerate by looking: a NAME read out of a tree.

    The escape this closes is the shipped #869/#908 defect. A `primitive` claim recorded an
    executed probe — `git ls-tree -r --name-only HEAD -- defender/skills/` over a planted
    ASCII tree at the repo root — and the observed output, INCLUDING its depth constant, was
    transcribed verbatim into both the implementation and the test that asserted on it. The
    probe was honest, executed, correctly typed, and correctly instrumented; every gate in
    this toolchain passed it. What it never recorded was its ALPHABET, and three preconditions
    rode along unnoticed: C-quoting of non-ASCII paths, `.split()` tearing a spaced path, and
    cwd-relative output. Each silently un-declared a real system.

    So a probe that enumerates names owes a sentence per class in `_ALPHABET_CLASSES` — what
    it sampled, or why the class cannot arise here. The sentence is the whole mechanism: an
    author who has to write down what `non-ascii` did looks, and looking is what the ASCII
    fixture prevented. Grammar only, never judgment — an out-of-scope class closes by saying
    so, exactly as a waiver does, and the check never reads the answer.
    """
    findings: list[str] = []
    for c in graph.get("claims", []) or []:
        if c.get("probe_kind") != "executed" or c.get("verdict") in _UNPROBED:
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
    """The hole under the instrument table: a claim's `kind` is DECLARED, and the table
    trusts it, so mis-typing is a free way past the whole ledger.

    The escape this closes is not hypothetical — the claim behind the most recent shipped
    defect asserted a universal about what every persisted record holds, and it closed on a
    read, because the read instrument is legitimate for the kind its author wrote down. A
    read cannot falsify a prediction over an input; only running it can. So a claim whose
    sentence makes a runtime prediction may not be typed into an inspectable kind, however
    honestly the typing was meant.

    Deterministic and deliberately narrow: it flags the grammar, never the judgment. The
    remedy is to retype the claim and run its probe, and the escape hatch is the same one
    the rest of this repo's gates use — a reviewed baseline entry, not a field an author can
    write to silence the check on their own claim.
    """
    findings: list[str] = []
    for c in graph.get("claims", []) or []:
        if c.get("kind") not in _INSPECTABLE or c.get("verdict") in _UNPROBED:
            continue
        if c.get("probe_kind") == "executed":
            continue  # typed inspectable, ran it anyway — the instrument is stronger, not weaker
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
    # Ids coerced with str() to match `_cited`, which stringifies every citation — an
    # int-keyed ledger made `cites: [12]` dangle against the claim it names.
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
        # A hole that spawned a demand (`resolved_to`) closes through that demand; one
        # closed by judgment alone ("unreachable", "out of scope") is a spend-point —
        # rules.md: it closes only by citation.
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
    opts, args = _cli.parse_argv(argv, valued={"--config"})
    cfg = _config.load(opts["config"])
    paths = [Path(a) for a in args] or _config.artifacts(cfg)
    if not paths:
        # 2, not 0: the whole toolchain's contract (verify.md) is 2 = could not look —
        # a run with nothing to check must not read as clean.
        print("check_claims: no spec_graph_*.yaml found", file=sys.stderr)
        return 2
    findings: list[str] = []
    spend: list[str] = []
    typing: list[str] = []
    alphabet: list[str] = []
    unreadable: list[Path] = []
    for p in paths:
        # Parsed ONCE and handed to both passes: the two used to load the same graph
        # independently, doubling every read and parse. Both passes run INSIDE the try —
        # nested wrong shapes (a string where a mapping belongs) surface as AttributeError
        # mid-walk, the same could-not-read class as a bad top level.
        try:
            graph = _cli.load_graph(p)
            findings.extend(check(p, graph))
            spend.extend(check_spend_points(p, graph))
            typing.extend(check_typing(p, graph))
            alphabet.extend(check_alphabet(p, graph))
        except (OSError, yaml.YAMLError, TypeError, AttributeError) as e:
            # Collected, not returned on: bailing here threw away every finding the
            # already-checked graphs produced.
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
    # Counted by kind: an instrument mismatch, a mis-typed claim, an unstated probe corpus and
    # an uncited spend-point are four different slips. The middle two are how the first is
    # evaded — by declaring a weaker kind, or by running the right instrument over the one
    # input class that cannot fail.
    print(f"\n[check_claims] {len(findings)} claim-instrument finding(s), {len(typing)} "
          f"claim-typing finding(s), {len(alphabet)} probe-corpus finding(s), {len(spend)} "
          f"spend-point citation finding(s) over {len(paths)} graph(s).")
    if unreadable:
        return 2
    return 1 if findings or typing or alphabet or spend else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
