"""#1222 slice S01 — the alert's three facts, derived once at run start through the tenant's
alert mapping (A1, A5, A6, C16, C43).

Every test drives the PRODUCTION front door (`run.main`, through `S.run_alert`) over a tenant whose
`settings/alert-mapping.yaml` the test wrote, and reads the outcome off what the run's readers
actually received: MAIN's opening message (harness prose only, frames removed), the argv every
orientation lookup was handed (`S.RecordingShim`), the case ticket's open payload (`S.TicketStore`
at the real ticket writer's seam), the invlang corpus loader, the judge's enqueued rule key — and,
last, the run's record (`S.read_record` / `d.recorded`, the coined accessor).

HOW THE INPUTS ARE CHOSEN (so a test is red at base for the design's reason, not only because the
record accessor does not exist yet). At base every reader takes `rule.id` and ignores the mapping:

* a value the design makes a REAL signature is put at a mapped path that is NOT `rule.id`
  (`vendor.code`, `detection.key`, `event.kind`), with a decoy `rule.id` beside it — a reader that
  still reads `rule.id` hands the decoy on, never the mapped value;
* a value the design makes NO signature is put AT `rule.id` under the shipped mapping
  (`signature: rule.id`) — a reader that treats it as a signature hands it on.

"Named exactly like an unmapped one" (A6) is asserted as PARITY with a reference run in the same
tenant: the mapping names no signature and the alert has no `rule.id` at all, so the reference is
"no signature" under every reading. The two runs must tell MAIN the same thing, hand every lookup the
same argv and open the same ticket. No sentence is asserted (the design fixes none); where a demand
says orientation NAMES the missing signature, the suite's one reading applies
(`S.missing_signature_lines`, shared with S09's O10): some line of the no-signature run's
`## Lessons` section that an otherwise identical run with a signature lacks says "signature".
"""
from __future__ import annotations

import difflib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from defender.tests import _judge_921 as J
from defender.tests import _state1135 as ST
from defender.tests.alert_front_door_1222 import _spec1222 as S

# =================================================================================================
# Inputs
# =================================================================================================

#: The alert carries no `rule.id` at all.
ABSENT = object()

#: The shipped mapping over `S.generic_alert()` (F-MAPPING-FILE: signature is `rule.id`).
SHIPPED: Mapping[str, str] = S.DEFAULT_MAPPING_GENERIC
#: A tenant that keys its signature on a vendor field that is not `rule.id` (O8's remap).
VENDOR: Mapping[str, str] = {"signature": "vendor.code", "event_time": "detected_at",
                             "summary": "rule.description"}
#: A mapping that names no signature (A5: accepted; O10 reworded) — the "unmapped" reference.
UNMAPPED: Mapping[str, str] = {"event_time": "detected_at", "summary": "rule.description"}

#: A `rule.id` no reader may hand on where the mapping keys the signature elsewhere.
DECOY = "R-DECOY-4410"
DESCRIPTION = "Host contacted a rare external destination on a fixed cadence."
DETECTED_AT = "2026-09-30T08:15:00Z"
#: A valid signature: ASCII, alphanumeric first character, no space, quote or control character.
VALID = "Zq7731-ok"
#: 128 characters (C43's bound), and one more.
AT_BOUND = "K" + "7" * 127
OVER_BOUND = "K" + "7" * 128


def _alert(rule_id: Any = DECOY, *, vendor: Any = ABSENT, **over: Any) -> dict[str, Any]:
    """`S.generic_alert()` with `rule.id` set to `rule_id` (or left out: `ABSENT`) and, when
    given, `vendor.code`. `over` replaces top-level members."""
    rule: dict[str, Any] = {"name": "Generic outbound beacon", "description": DESCRIPTION}
    if rule_id is not ABSENT:
        rule["id"] = rule_id
    doc = S.generic_alert(rule=rule, **over)
    if vendor is not ABSENT:
        doc["vendor"] = {"code": vendor}
    return doc


#: The placeholder a raw JSON literal replaces (see `_literal`).
_HOLE = "@@literal@@"


def _literal(doc: Mapping[str, Any], literal: str) -> bytes:
    """`doc` as the suite serialises it, with the one string `_HOLE` replaced by `literal` verbatim
    — a JSON number spelled as the alert spells it (`-0`, `1E3`, `5710.0`, a 129-digit integer),
    which `json.dumps` would respell. Real bytes, written to the operator's input file as is."""
    raw = S.alert_bytes(doc)
    hole = json.dumps(_HOLE).encode("utf-8")
    assert raw.count(hole) == 1, "the literal's placeholder must appear exactly once"
    return raw.replace(hole, literal.encode("utf-8"))


# =================================================================================================
# Driving
# =================================================================================================

def _drive(tmp_path: Path, planted: S.Planted, alert: Mapping[str, Any] | bytes, run_id: str, *,
           mapping: Mapping[str, Any] | None = None, main: Sequence[S.Turn] | None = None,
           ) -> S.Drive:
    """One alert through `run.main` with every reader recorded: the orientation lookups'
    argv, the case ticket's open and record legs. `mapping` (when given) is written first."""
    if mapping is not None:
        S.remap(planted, mapping)
    d = S.run_alert(tmp_path, alert=alert, tenant=planted, run_id=run_id, main=main,
                    orient_shim=S.RecordingShim(), tickets=S.ticket_writer(S.TicketStore()),
                    update_ticket=True)
    ran = d.raised is None and d.refusal is None and d.rc == 0 and d.main.requests >= 1
    assert ran, (f"run {run_id} did not run to MAIN: rc={d.rc!r} refusal={d.refusal!r} "
                 f"raised={d.raised!r}")
    return d


def _reference(tmp_path: Path, planted: S.Planted, run_id: str = "s01-unmapped") -> S.Drive:
    """The "no signature" reference: a mapping that names none, an alert with no `rule.id`."""
    return _drive(tmp_path, planted, _alert(ABSENT), run_id, mapping=UNMAPPED)


# =================================================================================================
# Observing
# =================================================================================================

def _run_id(d: S.Drive) -> str:
    assert d.run_dir is not None
    return d.run_dir.name


def _told(d: S.Drive) -> str:
    """MAIN's opening message as the HOST wrote it: every untrusted frame removed (the raw alert,
    corpus text, the correlation summary), the run folder and run id as placeholders."""
    return S.normalize(S.harness_text(d.opening_message), run_dir=d.run_dir, run_id=_run_id(d))


def _instructed(d: S.Drive) -> str:
    """MAIN's instructions (its system prompt), normalised like `_told`."""
    return S.normalize(d.main_instructions, run_dir=d.run_dir, run_id=_run_id(d))


def _argvs(d: S.Drive) -> list[list[str]]:
    """Every orientation lookup's argv, in order, the run folder and run id as placeholders."""
    assert d.shim is not None
    return [[a.replace(str(d.run_dir), "<RUN_DIR>").replace(_run_id(d), "<RUN_ID>") for a in argv]
            for argv in d.shim.argvs()]


def _handed(d: S.Drive) -> set[str]:
    """Every single argument any orientation lookup received."""
    assert d.shim is not None
    return {a for argv in d.shim.argvs() for a in argv}


def _hands(d: S.Drive, value: str) -> bool:
    """Whether some lookup received `value` as one whole argument (or as `--opt=<value>`)."""
    return any(a == value or a.endswith("=" + value) for a in _handed(d))


def _opened(d: S.Drive) -> dict[str, Any]:
    """The case ticket's open payload as the store received it, the run id as a placeholder."""
    payload = d.tickets.store.only_open()
    text = json.dumps(payload, sort_keys=True, ensure_ascii=False).replace(_run_id(d), "<RUN_ID>")
    doc = json.loads(text)
    assert isinstance(doc, dict)
    return doc


def _labels(d: S.Drive, prefix: str) -> list[str]:
    """The open payload's labels that start with `prefix` (`sig:` / `evt:`)."""
    labels = d.tickets.store.only_open().get("labels") or []
    return [lbl for lbl in labels if isinstance(lbl, str) and lbl.startswith(prefix)]


def _diff(a: str, b: str, a_name: str, b_name: str) -> str:
    lines = difflib.unified_diff(a.splitlines(), b.splitlines(), a_name, b_name, lineterm="", n=1)
    return "\n".join(lines)[:2500]


def _unlike_unmapped(case: S.Drive, ref: S.Drive, label: str) -> list[str]:
    """Every channel on which `case` was NOT treated exactly like the unmapped reference: what
    MAIN was told and instructed, what each orientation lookup was handed, what the case ticket
    opened with."""
    problems: list[str] = []
    told, ref_told = _told(case), _told(ref)
    if told != ref_told:
        problems.append(f"[{label}] MAIN's opening message differs from the unmapped run's:\n"
                        + _diff(ref_told, told, "unmapped", label))
    if _instructed(case) != _instructed(ref):
        problems.append(f"[{label}] MAIN's instructions differ from the unmapped run's")
    if _argvs(case) != _argvs(ref):
        problems.append(f"[{label}] the orientation lookups were handed {_argvs(case)!r}; the "
                        f"unmapped run's were {_argvs(ref)!r}")
    if _opened(case) != _opened(ref):
        problems.append(f"[{label}] the case ticket opened with {_opened(case)!r}; the unmapped "
                        f"run's opened with {_opened(ref)!r}")
    return problems


def _carries(d: S.Drive, signature: str, label: str, *, decoy: str | None = DECOY) -> list[str]:
    """Every reader that did NOT yield `signature` — the orientation lookups (one whole argument),
    the ticket's one `sig:` label — or that yielded the decoy `rule.id` instead."""
    problems: list[str] = []
    if not _hands(d, signature):
        problems.append(f"[{label}] no orientation lookup was handed {signature!r}: {_argvs(d)!r}")
    if decoy is not None and _hands(d, decoy):
        problems.append(f"[{label}] an orientation lookup was handed the alert's rule.id "
                        f"{decoy!r} instead: {_argvs(d)!r}")
    if _labels(d, "sig:") != [f"sig:{signature}"]:
        problems.append(f"[{label}] the case ticket's sig: labels are {_labels(d, 'sig:')!r}, "
                        f"not ['sig:{signature}']")
    return problems


def _not_handed(d: S.Drive, values: Sequence[str], label: str) -> list[str]:
    """Every value in `values` some orientation lookup was handed as an argument."""
    return [f"[{label}] an orientation lookup was handed {v!r} as an argument: {_argvs(d)!r}"
            for v in values if v and _hands(d, v)]


def _judge_keys(tmp: Path, d: S.Drive) -> set[str]:
    """The rule keys the real judge enqueues for an episode carrying `d`'s alert and record (what
    branch launch copies into the episode, A1) — `learning.judge.grade_episode`, scripted judge.
    Each call grades into a learning state of its own under `tmp`, so the findings queue it reads
    back holds this episode's rows only."""
    ep = J.accepted_episode(tmp)
    S.plant_episode_copy(ep, alert=d.stored_alert, record=d.record)
    assert d.tenant is not None
    J.grade(ep, runs_base=d.tenant.runs, state=ST.state_over(tmp / "learning-state"))
    rows = J.enqueued_rows(J.judge_record(ep))
    assert rows, f"the judge enqueued no finding for {ep}"
    return {str(row.get("alert_rule_key")) for row in rows}


def _record_problems(d: S.Drive, label: str, **expected: str | None) -> list[str]:
    """Each recorded fact that is not `expected` (None: absent or null)."""
    return [f"[{label}] the record's {fact} is {d.recorded(fact)!r}, not {want!r}"
            for fact, want in expected.items() if d.recorded(fact) != want]


def _fail(problems: Sequence[str]) -> str:
    return "\n\n".join(problems)


# =================================================================================================
# The tests (one per demand; the name is the demand's `discharged_by`)
# =================================================================================================

def test_alert_facts_resolve_each_mapped_path_or_absent(tmp_path: Path) -> None:
    """Given the admitted alert and the tenant's alert mapping, the one derivation, run once at
    run start, yields exactly three facts — signature, event_time, summary — each the value at its
    mapped dotted path (a walk over JSON objects only), or absent when the key is unmapped or the
    path is absent from the alert; it never substitutes another field.

    Driven through run start (`run.main`); the facts are read where the readers meet them — the
    orientation lookups and the case ticket — and then off the run's record."""
    mapping = {"signature": "detection.key", "event_time": "detection.seen",
               "summary": "detection.title"}
    planted = S.plant_tenant("acme", alert_mapping=mapping)
    detection = {"key": "DK-7731", "seen": "2026-09-30T08:20:00Z", "title": "Odd beacon cadence"}
    mapped = _drive(tmp_path, planted, _alert(detection=detection), "s01-mapped")
    absent = _drive(tmp_path, planted, _alert(), "s01-absent")
    partial = _drive(tmp_path, planted, _alert(detection=detection), "s01-partial",
                     mapping={"summary": "detection.title"})

    problems = _carries(mapped, "DK-7731", "mapped")
    if _labels(mapped, "evt:") != ["evt:2026-09-30T08:20:00Z"]:
        problems.append(f"[mapped] evt: labels {_labels(mapped, 'evt:')!r}")
    if mapped.tickets.store.only_open().get("summary") != "Odd beacon cadence":
        problems.append(f"[mapped] ticket summary {mapped.tickets.store.only_open().get('summary')!r}")
    # Never another field: neither the alert's rule.id, its detected_at nor its rule.description.
    for d, label in ((absent, "paths absent"), (partial, "signature and event_time unmapped")):
        problems += _not_handed(d, [DECOY, DETECTED_AT], label)
        if _labels(d, "sig:") == [f"sig:{DECOY}"]:
            problems.append(f"[{label}] the case ticket's sig: label is the alert's rule.id")
        if _labels(d, "evt:"):
            problems.append(f"[{label}] the case ticket carries {_labels(d, 'evt:')!r}")
    if absent.tickets.store.only_open().get("summary") == DESCRIPTION:
        problems.append("[paths absent] the ticket's summary is the alert's rule.description")
    assert not problems, _fail(problems)

    assert {f: mapped.recorded(f) for f in S.FACTS} == {
        "signature": "DK-7731", "event_time": "2026-09-30T08:20:00Z",
        "summary": "Odd beacon cadence"}
    assert {f: absent.recorded(f) for f in S.FACTS} == {
        "signature": None, "event_time": None, "summary": None}
    assert {f: partial.recorded(f) for f in S.FACTS} == {
        "signature": None, "event_time": None, "summary": "Odd beacon cadence"}


def test_alert_facts_value_domain(tmp_path: Path) -> None:
    """A mapped value is a signature only when it is a JSON string, or an integer as its decimal
    text (5710 → '5710', 0 → '0', -0 → '0'), matching [A-Za-z0-9][A-Za-z0-9._:/@+=-]{0,127} —
    ASCII only, no leading dash, at most 128 characters. Anything else — a negative integer, a
    float, a boolean, an empty string, a list, an object, a value with a leading dash, whitespace,
    a quote, a control or shell character, a non-ASCII character, or a value of 129 characters —
    is no signature, recorded and named exactly like an unmapped one. Mapping the signature to
    rule.name over the committed fixture alerts gives no signature (every committed rule.name holds
    a space, RD-05)."""
    planted = S.plant_tenant("acme", alert_mapping=SHIPPED)
    ref = _reference(tmp_path, planted)

    # Real signatures, mapped through vendor.code beside a decoy rule.id.
    real = [("int", "5710", "5710"), ("zero", "0", "0"), ("negative zero", "-0", "0"),
            ("string", json.dumps(VALID), VALID), ("at bound", json.dumps(AT_BOUND), AT_BOUND)]
    # No signature, put at rule.id under the shipped mapping: (case, raw JSON literal, a value no
    # lookup may be handed — the alert's own text, and the text a str() of it would print).
    bad: list[tuple[str, str, tuple[str, ...]]] = [
        ("negative int", "-7731", ("-7731",)),
        ("float", "7731.5", ("7731.5",)),
        ("false", "false", ("false", "False")),
        ("empty", '""', ()),
        ("list", '["Zq7731"]', ("Zq7731", "['Zq7731']")),
        ("object", '{"k": "Zq7731"}', ("Zq7731", "{'k': 'Zq7731'}")),
        ("leading dash", '"-Zq7731"', ("-Zq7731",)),
        ("whitespace", '"Zq7731 tail"', ("Zq7731 tail",)),
        ("quote", json.dumps('Zq7731"tail'), ('Zq7731"tail',)),
        ("control", json.dumps("Zq7731\u0007tail"), ("Zq7731\u0007tail",)),
        ("shell", json.dumps("Zq7731;id|cat&"), ("Zq7731;id|cat&",)),
        ("non-ascii", json.dumps("Zq7731\u00e9", ensure_ascii=False), ("Zq7731\u00e9",)),
        ("over bound", json.dumps(OVER_BOUND), (OVER_BOUND,)),
    ]
    reals = [(name, _drive(tmp_path, planted, _literal(_alert(vendor=_HOLE), lit),
                           f"s01-real-{i}", mapping=VENDOR), want)
             for i, (name, lit, want) in enumerate(real)]
    bads = [(name, _drive(tmp_path, planted, _literal(_alert(_HOLE), lit), f"s01-bad-{i}",
                          mapping=SHIPPED), leaked)
            for i, (name, lit, leaked) in enumerate(bad)]
    # RD-05: rule.name over the committed fixture alerts; each against its own fixture's reference.
    by_name = {**SHIPPED, "signature": "rule.name"}
    names = []
    for i, slug in enumerate(S.FIXTURE_SLUGS):
        fixture = S.fixture_alert(slug)
        bare = {**fixture, "rule": {k: v for k, v in fixture["rule"].items() if k != "id"}}
        named = _drive(tmp_path, planted, fixture, f"s01-name-{i}", mapping=by_name)
        name_ref = _drive(tmp_path, planted, bare, f"s01-name-ref-{i}", mapping=UNMAPPED)
        names.append((slug, named, name_ref, fixture["rule"]["name"], fixture["rule"]["id"]))

    problems: list[str] = []
    for name, d, want in reals:
        problems += _carries(d, want, name)
    for name, d, leaked in bads:
        problems += _unlike_unmapped(d, ref, name)
        problems += _not_handed(d, leaked, name)
    for slug, d, name_ref, rule_name, rule_id in names:
        problems += _unlike_unmapped(d, name_ref, f"rule.name of {slug}")
        problems += _not_handed(d, [rule_name, rule_id], f"rule.name of {slug}")
    assert not problems, _fail(problems)

    for name, d, want in reals:
        problems += _record_problems(d, name, signature=want)
    for name, d, _leaked in bads:
        problems += _record_problems(d, name, signature=None)
    for slug, d, _r, _n, _i in names:
        problems += _record_problems(d, f"rule.name of {slug}", signature=None)
    problems += _record_problems(ref, "unmapped", signature=None)
    assert not problems, _fail(problems)


def test_o10_absent_path_is_treated_as_unmapped(tmp_path: Path) -> None:
    """A mapping whose signature path is absent from the alert gives every reader the same result
    as a mapping that names no signature.

    Readers observed: what MAIN is told and instructed, every orientation lookup's argv, the case
    ticket's open payload, and the run's record. The path-absent alert carries a rule.id; the
    unmapped run's alert carries none."""
    planted = S.plant_tenant("acme", alert_mapping=VENDOR)
    ref = _reference(tmp_path, planted)
    absent = _drive(tmp_path, planted, _alert(), "s01-path-absent", mapping=VENDOR)
    present = _drive(tmp_path, planted, _alert(vendor=VALID), "s01-path-present", mapping=VENDOR)

    # Positive control: the same mapping DOES reach every reader when the path is present.
    problems = _carries(present, VALID, "path present")
    problems += _unlike_unmapped(absent, ref, "path absent")
    assert not problems, _fail(problems)

    assert absent.recorded("signature") is None
    assert ref.recorded("signature") is None
    assert absent.record.get("signature") == ref.record.get("signature")


def test_p042_mapping_path_names_a_flat_dotted_key(tmp_path: Path) -> None:
    """A flat key named "rule.id" is not addressed: signature None, named like unmapped. Every
    reader yields the recorded value."""
    planted = S.plant_tenant("acme", alert_mapping=SHIPPED)
    ref = _reference(tmp_path, planted)
    flat = _drive(tmp_path, planted, _alert(ABSENT, **{"rule.id": "FLAT-7731"}), "s01-flat",
                  mapping=SHIPPED)

    problems = _unlike_unmapped(flat, ref, "flat 'rule.id' key")
    problems += _not_handed(flat, ["FLAT-7731"], "flat 'rule.id' key")
    assert not problems, _fail(problems)

    assert flat.recorded("signature") is None


def test_p043_flat_and_nested_spellings_disagree(tmp_path: Path) -> None:
    """When both spellings are present, the nested value is the signature."""
    planted = S.plant_tenant("acme", alert_mapping=VENDOR)
    both = _drive(tmp_path, planted,
                  _alert(vendor="NEST-7731", **{"vendor.code": "FLAT-7731"}), "s01-both")

    problems = _carries(both, "NEST-7731", "nested and flat")
    problems += _not_handed(both, ["FLAT-7731"], "nested and flat")
    assert not problems, _fail(problems)

    assert both.recorded("signature") == "NEST-7731"


def test_p044_mapping_path_crosses_a_list(tmp_path: Path) -> None:
    """A list, string, null, number, boolean or list-index look-alike on the path gives no fact.
    There is no rule.id fallback.

    The mapping keys the signature on `vendor.rule.key`; the alert puts something that is not a
    JSON object at `vendor` (or a list at the end of the path, or an object), with a rule.id
    beside it that no reader may fall back to."""
    mapping = {"signature": "vendor.rule.key", "event_time": "detected_at",
               "summary": "rule.description"}
    planted = S.plant_tenant("acme", alert_mapping=SHIPPED)
    ref = _reference(tmp_path, planted)
    shapes: list[tuple[str, Mapping[str, Any], Any]] = [
        ("list on the path", mapping, [{"rule": {"key": "LK-7731"}}]),
        ("string on the path", mapping, "LK-7731"),
        ("null on the path", mapping, None),
        ("number on the path", mapping, 7731),
        ("boolean on the path", mapping, True),
        ("list-index look-alike", {**mapping, "signature": "vendor.0.key"},
         [{"key": "LK-7731"}]),
        ("list at the end", {**mapping, "signature": "vendor"}, ["LK-7731"]),
        ("object at the end", {**mapping, "signature": "vendor"}, {"rule": {"key": "LK-7731"}}),
    ]
    runs = [(name, _drive(tmp_path, planted, {**_alert(), "vendor": value}, f"s01-list-{i}",
                          mapping=m))
            for i, (name, m, value) in enumerate(shapes)]

    problems: list[str] = []
    for name, d in runs:
        problems += _unlike_unmapped(d, ref, name)
        problems += _not_handed(d, [DECOY, "LK-7731", "7731", "True"], name)
    assert not problems, _fail(problems)

    for name, d in runs:
        problems += _record_problems(d, name, signature=None)
    assert not problems, _fail(problems)


def test_p046_signature_mapped_to_a_long_multiline_field(tmp_path: Path) -> None:
    """A multi-line, whitespace-bearing or over-long value is no signature, named like unmapped,
    and reaches no sink.

    Sinks observed: MAIN's opening message and instructions, every orientation lookup's argv, the
    case ticket's open payload."""
    planted = S.plant_tenant("acme", alert_mapping=SHIPPED)
    ref = _reference(tmp_path, planted)
    values = [("multi-line", "Zq7731 first line\nsecond line\n## Forged heading"),
              ("whitespace", "Zq7731 sshd success after failures"),
              ("over-long", "Zq7731" + "x" * 300)]
    runs = [(name, value, _drive(tmp_path, planted, _alert(value), f"s01-long-{i}",
                                 mapping=SHIPPED))
            for i, (name, value) in enumerate(values)]

    problems: list[str] = []
    for name, value, d in runs:
        problems += _unlike_unmapped(d, ref, name)
        problems += _not_handed(d, [value], name)
        if "Zq7731" in json.dumps(_opened(d), ensure_ascii=False):
            problems.append(f"[{name}] the value reached the case ticket: {_opened(d)!r}")
    assert not problems, _fail(problems)

    for name, _value, d in runs:
        problems += _record_problems(d, name, signature=None)
    assert not problems, _fail(problems)


def test_p047_signature_value_begins_with_a_dash(tmp_path: Path) -> None:
    """A value with a leading dash, a negative rule number included, is no signature under the
    allow-list [A-Za-z0-9][A-Za-z0-9._:/@+=-]{0,127}: orientation names it like an unmapped one
    and no lookup receives it as an argument.

    PR-06: given as an argument, `--x`-shaped values were parsed as options by the vocabulary
    lookup; `-5` was taken as a value."""
    planted = S.plant_tenant("acme", alert_mapping=SHIPPED)
    ref = _reference(tmp_path, planted)
    valid = _drive(tmp_path, planted, _alert(VALID), "s01-dash-control", mapping=SHIPPED)
    cases = [("double dash", json.dumps("--Zq7731-high"), "--Zq7731-high"),
             ("option-shaped", json.dumps("--runs-base=/elsewhere"), "--runs-base=/elsewhere"),
             ("single dash", json.dumps("-Zq7731h"), "-Zq7731h"),
             ("negative rule number", "-7731", "-7731"),
             ("negative number as text", json.dumps("-7731"), "-7731")]
    runs = [(name, value, _drive(tmp_path, planted, _literal(_alert(_HOLE), lit),
                                 f"s01-dash-{i}", mapping=SHIPPED))
            for i, (name, lit, value) in enumerate(cases)]

    # Positive control: a valid rule.id IS handed to the lookups as one argument.
    problems = [] if _hands(valid, VALID) else [
        f"[control] no lookup was handed the valid signature {VALID!r}: {_argvs(valid)!r}"]
    for name, value, d in runs:
        problems += _unlike_unmapped(d, ref, name)
        if any(value in a for a in _handed(d)):
            problems.append(f"[{name}] a lookup received {value!r} in an argument: {_argvs(d)!r}")
    assert not problems, _fail(problems)

    for name, _value, d in runs:
        problems += _record_problems(d, name, signature=None)
    assert not problems, _fail(problems)


def test_p048_signature_with_shell_metacharacters_when_the_age(tmp_path: Path) -> None:
    """Quotes, $( ), backticks, semicolons, newlines and a leading dash put a value outside the
    allow-list, so it is no signature: MAIN is told there is nothing to pass, and nothing executes
    from a signature.

    "Told": MAIN's instructions and opening message equal the unmapped run's. "Nothing executes":
    no lookup is handed the value at all."""
    planted = S.plant_tenant("acme", alert_mapping=SHIPPED)
    ref = _reference(tmp_path, planted)
    valid = _drive(tmp_path, planted, _alert(VALID), "s01-shell-control", mapping=SHIPPED)
    values = [("double quote", 'Zq7731"dq'), ("single quote", "Zq7731'sq"),
              ("dollar-paren", "Zq7731$(touch pwned)"), ("backtick", "Zq7731`id`"),
              ("semicolon", "Zq7731;id"), ("newline", "Zq7731\nid"), ("leading dash", "-Zq7731")]
    runs = [(name, value, _drive(tmp_path, planted, _alert(value), f"s01-shell-{i}",
                                 mapping=SHIPPED))
            for i, (name, value) in enumerate(values)]

    problems = [] if _hands(valid, VALID) else [
        f"[control] no lookup was handed the valid signature {VALID!r}: {_argvs(valid)!r}"]
    for name, value, d in runs:
        problems += _unlike_unmapped(d, ref, name)
        problems += _not_handed(d, [value], name)
    assert not problems, _fail(problems)

    for name, _value, d in runs:
        problems += _record_problems(d, name, signature=None)
    assert not problems, _fail(problems)


def test_p049_signature_value_carries_a_nul_or_control(tmp_path: Path) -> None:
    """A NUL or other control character in the mapped signature value gives no signature, named
    in orientation, and the run continues; a NUL in summary or event_time is ordinary data; an
    unpaired surrogate escape is refused at admission.

    PR-05 / PR-09: at base a NUL or lone surrogate handed to a lookup failed inside it and the
    section silently dropped."""
    planted = S.plant_tenant("acme", alert_mapping=SHIPPED)
    ref = _reference(tmp_path, planted)
    controls = [("NUL", "Zq7731\u0000nul"), ("escape", "Zq7731\u001b[31mred"),
                ("DEL", "Zq7731\u007fdel"), ("tab", "Zq7731\ttab"), ("bell", "Zq7731\u0007")]
    runs = [(name, value, _drive(tmp_path, planted, _alert(value), f"s01-ctl-{i}",
                                 mapping=SHIPPED))
            for i, (name, value) in enumerate(controls)]
    nul_data = _drive(tmp_path, planted, S.generic_alert(
        rule={"id": VALID, "description": "first part\u0000second part"},
        detected_at="2026-09-30T08:15:00Z\u0000"), "s01-nul-data", mapping=SHIPPED)
    before = sorted(p.name for p in planted.runs.iterdir())
    surrogate = S.run_alert(
        tmp_path, tenant=planted, run_id="s01-surrogate",
        alert=_literal(_alert(_HOLE), '"Zq7731\\ud800tail"'), orient_shim=S.RecordingShim())

    problems: list[str] = []
    for name, value, d in runs:
        problems += _unlike_unmapped(d, ref, name)
        problems += _not_handed(d, [value], name)
    # The unpaired surrogate is refused at run start: no folder, MAIN never asked.
    if surrogate.raised is not None or surrogate.rc in (0, None):
        problems.append(f"[surrogate] not refused: rc={surrogate.rc!r} raised={surrogate.raised!r}")
    if surrogate.main.requests:
        problems.append("[surrogate] MAIN was asked for a turn over an unadmitted alert")
    after = sorted(p.name for p in planted.runs.iterdir())
    if after != before:
        problems.append(f"[surrogate] the refused alert left {sorted(set(after) - set(before))}")
    assert not problems, _fail(problems)

    for name, _value, d in runs:
        problems += _record_problems(d, name, signature=None)
    problems += _record_problems(nul_data, "NUL in summary and event_time", signature=VALID,
                                 summary="first part\u0000second part",
                                 event_time="2026-09-30T08:15:00Z\u0000")
    assert not problems, _fail(problems)


def test_p050_signature_is_a_float_exponent_or_huge_integer(tmp_path: Path) -> None:
    """An integer gives its decimal text (-0 gives '0'); a float, an exponent form and an integer
    whose text exceeds 128 characters are no signature; '05710' and 5710 are distinct; every sink
    uses that one text.

    PR-04: at base the signature text was Python's own spelling (5710.0 -> '5710.0', 1E3 ->
    '1000.0')."""
    planted = S.plant_tenant("acme", alert_mapping=SHIPPED)
    ref = _reference(tmp_path, planted)
    digits_128 = "9" * 128
    real = [("integer", "5710", "5710"), ("negative zero", "-0", "0"),
            ("zero-padded text", '"05710"', "05710"), ("128-digit integer", digits_128, digits_128)]
    bad = [("float", "5710.0", ("5710.0", "5710")), ("exponent", "1E3", ("1E3", "1000.0")),
           ("lower exponent", "1e3", ("1e3", "1000.0")),
           ("129-digit integer", "9" * 129, ("9" * 129,)),
           ("long fraction", "12345678901234567890.5",
            ("12345678901234567890.5", "1.2345678901234567e+19"))]
    reals = [(name, _drive(tmp_path, planted, _literal(_alert(vendor=_HOLE), lit),
                           f"s01-num-{i}", mapping=VENDOR), want)
             for i, (name, lit, want) in enumerate(real)]
    bads = [(name, _drive(tmp_path, planted, _literal(_alert(_HOLE), lit), f"s01-nan-{i}",
                          mapping=SHIPPED), leaked)
            for i, (name, lit, leaked) in enumerate(bad)]

    problems: list[str] = []
    for name, d, want in reals:
        problems += _carries(d, want, name)
    for name, d, leaked in bads:
        problems += _unlike_unmapped(d, ref, name)
        problems += _not_handed(d, leaked, name)
    padded = next(d for name, d, _w in reals if name == "zero-padded text")
    problems += _not_handed(padded, ["5710"], "zero-padded text")
    assert not problems, _fail(problems)

    for name, d, want in reals:
        problems += _record_problems(d, name, signature=want)
    for name, d, _leaked in bads:
        problems += _record_problems(d, name, signature=None)
    assert not problems, _fail(problems)


def test_p054_mapping_names_only_some_of_the_three_facts(tmp_path: Path) -> None:
    """A mapping that names no signature is accepted. The signature is None and orientation names
    it. Unmapped event_time and summary are empty, never a vendor default.

    The alert offers every vendor default a reader could guess — `timestamp`, `detected_at`,
    `rule.description`, `rule.id`. The positive control maps event_time and summary and gets
    them on the case ticket."""
    planted = S.plant_tenant("acme", alert_mapping=SHIPPED)
    vendor_time = "2026-09-30T08:16:00Z"
    alert = _alert("R-1001", timestamp=vendor_time)
    mapped = _drive(tmp_path, planted, alert, "s01-some-all", mapping=SHIPPED)
    sig_only = _drive(tmp_path, planted, alert, "s01-some-sig", mapping={"signature": "rule.id"})
    no_sig = _drive(tmp_path, planted, alert, "s01-some-nosig", mapping=UNMAPPED)

    problems: list[str] = []
    # Positive control: mapped event_time and summary reach the ticket.
    if _labels(mapped, "evt:") != [f"evt:{DETECTED_AT}"]:
        problems.append(f"[mapped] evt: labels {_labels(mapped, 'evt:')!r}")
    if mapped.tickets.store.only_open().get("summary") != DESCRIPTION:
        problems.append(f"[mapped] ticket summary {mapped.tickets.store.only_open().get('summary')!r}")
    # Unmapped: no vendor default reaches the ticket.
    if _labels(sig_only, "evt:"):
        problems.append(f"[signature only] the ticket carries {_labels(sig_only, 'evt:')!r}")
    opened = json.dumps(_opened(sig_only), ensure_ascii=False)
    for vendor_value in (DESCRIPTION, vendor_time, DETECTED_AT):
        if vendor_value in opened:
            problems.append(f"[signature only] the ticket carries the vendor value "
                            f"{vendor_value!r}: {_opened(sig_only)!r}")
    # No signature: accepted, and orientation names what is missing.
    named = S.missing_signature_lines(no_sig.opening_message, mapped.opening_message)
    if not named:
        problems.append("[no signature] orientation's lessons section told MAIN nothing about "
                        "the missing signature that the signed run's did not: "
                        f"{S.lessons_section(no_sig.opening_message)!r}")
    assert not problems, _fail(problems)

    assert no_sig.run_dir is not None
    assert no_sig.refusal is None
    problems += _record_problems(no_sig, "no signature", signature=None,
                                 event_time=DETECTED_AT, summary=DESCRIPTION)
    problems += _record_problems(sig_only, "signature only", signature="R-1001",
                                 event_time=None, summary=None)
    assert not problems, _fail(problems)


def test_p057_duplicate_keys_at_the_mapped_path(tmp_path: Path) -> None:
    """When the mapped member is repeated, the last one wins, and every reader agrees.

    Readers observed: the orientation lookups, the case ticket's sig: label, the invlang corpus
    loader over the tenant's runs, and the run's record. Real duplicate bytes, written as is."""
    planted = S.plant_tenant("acme", alert_mapping=VENDOR)
    inner = S.alert_bytes(_alert(vendor="@@")).replace(
        b'"code": "@@"', b'"code": "FIRST-7731",\n  "code": "LAST-7731"')
    outer_doc = _alert(vendor="OUTER-1")
    outer = S.alert_bytes(outer_doc).rstrip()
    assert outer.endswith(b"}")
    outer = outer[:-1].rstrip() + b',\n "vendor": {"code": "OUTER-2"}\n}'
    assert inner.count(b'"code"') == 2
    assert outer.count(b'"vendor"') == 2
    dup_inner = _drive(tmp_path, planted, inner, "s01-dup-inner", main=S.closing_main_turns())
    dup_outer = _drive(tmp_path, planted, outer, "s01-dup-outer")

    problems = _carries(dup_inner, "LAST-7731", "repeated member")
    problems += _not_handed(dup_inner, ["FIRST-7731"], "repeated member")
    problems += _carries(dup_outer, "OUTER-2", "repeated parent")
    problems += _not_handed(dup_outer, ["OUTER-1"], "repeated parent")
    load_corpus = S.sym("skills.invlang.corpus", "load_corpus")
    companions, _report = load_corpus(planted.runs)
    seen = {c.case_id: c.signature_id for c in companions}
    if seen.get("s01-dup-inner") != "LAST-7731":
        problems.append(f"[repeated member] the invlang corpus reads the run's signature as "
                        f"{seen.get('s01-dup-inner')!r}; corpus: {seen!r}")
    assert not problems, _fail(problems)

    assert dup_inner.recorded("signature") == "LAST-7731"
    assert dup_outer.recorded("signature") == "OUTER-2"


def test_p083_event_time_mapped_to_a_number_zero_or_object(tmp_path: Path) -> None:
    """The evt: label is non-empty for the committed fixture alerts.
    - An object, list or float event_time is no fact.
    - An integer gives its decimal text; "now" stays "now".
    - No other field changes, and no reader raises.

    The evt: label is the case ticket's open payload; "no other field" is the signature and the
    summary, on the ticket and in the record."""
    planted = S.plant_tenant("acme", alert_mapping=S.DEFAULT_MAPPING)
    fixtures = [(slug, S.fixture_alert(slug)["alert_timestamp"],
                 _drive(tmp_path, planted, S.fixture_alert_bytes(slug), f"s01-evt-fx-{i}"))
                for i, slug in enumerate(S.FIXTURE_SLUGS)]
    shapes = [("integer", "1727683200", "1727683200"), ("zero", "0", "0"),
              ("text", '"now"', "now"), ("object", '{"t": 1727683200}', None),
              ("list", '["2026-09-30T08:15:00Z"]', None), ("float", "1727683200.5", None)]
    generic = [(name, want, _drive(tmp_path, planted,
                                   _literal(_alert("R-EVT-1", detected_at=_HOLE), lit),
                                   f"s01-evt-{i}", mapping=SHIPPED))
               for i, (name, lit, want) in enumerate(shapes)]

    problems: list[str] = []
    for slug, stamp, d in fixtures:
        if not isinstance(stamp, str) or _labels(d, "evt:") != [f"evt:{stamp}"]:
            problems.append(f"[fixture {slug}] evt: labels {_labels(d, 'evt:')!r}, not "
                            f"['evt:{stamp}']")
    for name, want, d in generic:
        expected = [f"evt:{want}"] if want is not None else []
        if _labels(d, "evt:") != expected:
            problems.append(f"[{name}] evt: labels {_labels(d, 'evt:')!r}, not {expected!r}")
        if _labels(d, "sig:") != ["sig:R-EVT-1"]:
            problems.append(f"[{name}] sig: labels {_labels(d, 'sig:')!r}")
        if d.tickets.store.only_open().get("summary") != DESCRIPTION:
            problems.append(f"[{name}] summary {d.tickets.store.only_open().get('summary')!r}")
        if len(d.tickets.store.comments()) != 1:
            problems.append(f"[{name}] the ticket's record leg posted {d.tickets.store.comments()!r}")
    assert not problems, _fail(problems)

    for slug, stamp, d in fixtures:
        problems += _record_problems(d, f"fixture {slug}", event_time=stamp)
    for name, want, d in generic:
        problems += _record_problems(d, name, event_time=want, signature="R-EVT-1",
                                     summary=DESCRIPTION)
    assert not problems, _fail(problems)


def test_p090_mapped_value_equals_a_fallback_sentinel(tmp_path: Path) -> None:
    """An unmapped path gives None, never a string. A real signature spelled "unknown" is a fact.

    Readers observed: the orientation lookups, the case ticket's sig: label, the judge's enqueued
    rule key (an episode carrying the run's alert and record), and the run's record."""
    planted = S.plant_tenant("acme", alert_mapping=SHIPPED)
    literal = _drive(tmp_path, planted, _alert("unknown"), "s01-sentinel", mapping=SHIPPED)
    absent = _drive(tmp_path, planted, _alert(), "s01-sentinel-absent", mapping=VENDOR)

    problems: list[str] = []
    if not _hands(literal, "unknown"):
        problems.append(f"[spelled unknown] no lookup was handed 'unknown': {_argvs(literal)!r}")
    if _labels(literal, "sig:") != ["sig:unknown"]:
        problems.append(f"[spelled unknown] sig: labels {_labels(literal, 'sig:')!r}")
    problems += _not_handed(absent, [DECOY, "unknown", "unkeyed", "None"], "path absent")
    if _labels(absent, "sig:") == [f"sig:{DECOY}"]:
        problems.append("[path absent] the case ticket's sig: label is the alert's rule.id")
    assert not problems, _fail(problems)

    assert literal.recorded("signature") == "unknown"
    assert absent.record.get("signature") is None, (
        f"an unmapped path is recorded as {absent.record.get('signature')!r}, not as no signature")
    assert _judge_keys(tmp_path / "judge-literal", literal) == {"unknown"}
    assert _judge_keys(tmp_path / "judge-absent", absent) == {S.UNKEYED}


def test_p101_scaffolded_tenant_whose_alerts_lack_the_template(tmp_path: Path) -> None:
    """Only the model is told: orientation names the missing signature. The run record shows the
    facts absent. No operator channel.

    The tenant keeps the shipped template mapping (rule.id, alert_timestamp, rule.description);
    its alerts carry none of those paths. The run is not refused — the operator is not stopped —
    and the facts are absent; an otherwise identical alert that does carry rule.id is the signed
    run orientation's lines are compared with."""
    planted = S.plant_tenant("acme", alert_mapping=S.DEFAULT_MAPPING)
    vendor_shaped = {"detection": {"key": "DK-7731", "title": "Odd login"},
                     "observed_at": "2026-09-30T08:15:00Z", "host": {"hostname": "app-7"}}
    lacking = _drive(tmp_path, planted, vendor_shaped, "s01-lacking")
    signed = _drive(tmp_path, planted, {**vendor_shaped, "rule": {"id": "R-1001"}}, "s01-signed")

    named = S.missing_signature_lines(lacking.opening_message, signed.opening_message)
    assert named, (
        "orientation's lessons section told MAIN nothing about the missing signature that the "
        f"signed run's did not: {S.lessons_section(lacking.opening_message)!r}")
    assert lacking.rc == 0
    assert lacking.refusal is None
    assert {f: lacking.recorded(f) for f in S.FACTS} == {
        "signature": None, "event_time": None, "summary": None}


def test_p106_mapping_moved_to_a_coarse_field(tmp_path: Path) -> None:
    """A coarse or per-alert field changes nothing in the readers: each yields the recorded value.
    No cardinality guard.

    Coarse: every alert shares `event.kind`; per-alert: `event.id` differs on each. Every run is
    accepted, and each reader yields the value the mapping names, never the alert's rule.id."""
    coarse = {"signature": "event.kind", "event_time": "detected_at", "summary": "rule.description"}
    per_alert = {**coarse, "signature": "event.id"}
    planted = S.plant_tenant("acme", alert_mapping=coarse)
    runs = [
        ("coarse 1", "alert", _drive(tmp_path, planted, _alert(
            "R-COARSE-1", event={"kind": "alert", "id": "ev-0001-aa"}), "s01-coarse-1")),
        ("coarse 2", "alert", _drive(tmp_path, planted, _alert(
            "R-COARSE-2", event={"kind": "alert", "id": "ev-0002-bb"}), "s01-coarse-2")),
        ("per-alert 1", "ev-0001-aa", _drive(tmp_path, planted, _alert(
            "R-COARSE-1", event={"kind": "alert", "id": "ev-0001-aa"}), "s01-per-1",
            mapping=per_alert)),
        ("per-alert 2", "ev-0002-bb", _drive(tmp_path, planted, _alert(
            "R-COARSE-2", event={"kind": "alert", "id": "ev-0002-bb"}), "s01-per-2")),
    ]

    problems: list[str] = []
    for name, want, d in runs:
        problems += _carries(d, want, name, decoy=None)
        problems += _not_handed(d, ["R-COARSE-1", "R-COARSE-2"], name)
    assert not problems, _fail(problems)

    for name, want, d in runs:
        problems += _record_problems(d, name, signature=want)
    assert not problems, _fail(problems)


def test_p179_signature_at_and_one_past_the_length_bound(tmp_path: Path) -> None:
    """A signature at the length bound is recorded. One character past it is no signature, named
    like unmapped."""
    assert len(AT_BOUND) == S.SIGNATURE_MAX
    assert len(OVER_BOUND) == S.SIGNATURE_MAX + 1
    planted = S.plant_tenant("acme", alert_mapping=SHIPPED)
    ref = _reference(tmp_path, planted)
    at = _drive(tmp_path, planted, _alert(vendor=AT_BOUND), "s01-at-bound", mapping=VENDOR)
    over = _drive(tmp_path, planted, _alert(OVER_BOUND), "s01-over-bound", mapping=SHIPPED)

    problems = _carries(at, AT_BOUND, "at the bound")
    problems += _unlike_unmapped(over, ref, "one past the bound")
    problems += _not_handed(over, [OVER_BOUND, AT_BOUND], "one past the bound")
    assert not problems, _fail(problems)

    assert at.recorded("signature") == AT_BOUND
    assert over.recorded("signature") is None


def test_p180_unicode_whitespace_format_and_quote_characters(tmp_path: Path) -> None:
    """Every non-ASCII character — Unicode whitespace, format controls, curly or guillemet quotes,
    line separators — is outside the allow-list, so such a value is no signature, named like an
    unmapped one.

    PA-22: no Unicode category isolates "quote", and one_line() drops format controls, so two such
    values could print alike."""
    planted = S.plant_tenant("acme", alert_mapping=SHIPPED)
    ref = _reference(tmp_path, planted)
    values = [("no-break space", "Zq7731\u00a0nb"), ("ideographic space", "Zq7731\u3000id"),
              ("em space", "Zq7731\u2003em"), ("zero-width space", "Zq7731\u200bzw"),
              ("bidi override", "Zq7731\u202ebidi"), ("word joiner", "Zq7731\u2060wj"),
              ("byte-order mark", "Zq7731\ufeffbom"), ("line separator", "Zq7731\u2028ls"),
              ("paragraph separator", "Zq7731\u2029ps"), ("next line", "Zq7731\u0085nl"),
              ("curly quotes", "\u201cZq7731\u201d"), ("guillemets", "\u00abZq7731\u00bb"),
              ("fullwidth quote", "Zq7731\uff02fw"), ("accented letter", "Zq7731\u00e9")]
    runs = [(name, value, _drive(tmp_path, planted, _alert(value), f"s01-uni-{i}",
                                 mapping=SHIPPED))
            for i, (name, value) in enumerate(values)]

    problems: list[str] = []
    for name, value, d in runs:
        problems += _unlike_unmapped(d, ref, name)
        problems += _not_handed(d, [value], name)
    assert not problems, _fail(problems)

    for name, _value, d in runs:
        problems += _record_problems(d, name, signature=None)
    assert not problems, _fail(problems)


def test_p181_negative_zero_padded_and_string_versus_integer_i(tmp_path: Path) -> None:
    """A negative integer is no signature; the string '05710' is the signature '05710'; the string
    '5710' and the integer 5710 both give '5710', one key."""
    planted = S.plant_tenant("acme", alert_mapping=SHIPPED)
    ref = _reference(tmp_path, planted)
    negative = _drive(tmp_path, planted, _literal(_alert(_HOLE), "-5710"), "s01-neg",
                      mapping=SHIPPED)
    padded = _drive(tmp_path, planted, _alert(vendor="05710"), "s01-padded", mapping=VENDOR)
    as_text = _drive(tmp_path, planted, _alert(vendor="5710"), "s01-text")
    as_int = _drive(tmp_path, planted, _literal(_alert(vendor=_HOLE), "5710"), "s01-int")

    problems = _unlike_unmapped(negative, ref, "negative integer")
    problems += _not_handed(negative, ["-5710", "5710"], "negative integer")
    problems += _carries(padded, "05710", "zero-padded text")
    problems += _not_handed(padded, ["5710"], "zero-padded text")
    problems += _carries(as_text, "5710", "'5710' as text")
    problems += _carries(as_int, "5710", "5710 as an integer")
    if _labels(as_text, "sig:") != _labels(as_int, "sig:"):
        problems.append(f"the text and the integer 5710 label the ticket differently: "
                        f"{_labels(as_text, 'sig:')!r} vs {_labels(as_int, 'sig:')!r}")
    assert not problems, _fail(problems)

    assert negative.recorded("signature") is None
    assert padded.recorded("signature") == "05710"
    assert as_text.recorded("signature") == as_int.recorded("signature") == "5710"
