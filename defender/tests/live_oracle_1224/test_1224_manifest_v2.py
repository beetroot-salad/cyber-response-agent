"""Manifest v2 loading: world facts and served_systems, plus refusal of malformed facts and hostile world labels / system names."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

import pytest

from defender import _yaml
from defender.tests import _episode_1025 as E
from defender.tests import _judge_921 as J
from defender.tests.live_oracle_1224 import _spec1224 as S

# --------------------------------------------------------------------------------------
# Readers — the runtime loader, the sibling's loader, the judge's raw reader, the page.
# --------------------------------------------------------------------------------------


def _family_error() -> type[BaseException]:
    return S.sym(S.FAMILY, "FamilyError")


def _episode_cls() -> Any:
    return S.sym("_episode_handle", "Episode")


def _parse(doc: Any) -> Any:
    """The runtime loader's schema gate over an in-memory document."""
    return S.sym(S.FAMILY, "parse_family")(doc)


def _episode(where: Path, doc: dict | None = None, *, text: str | None = None) -> Path:
    """An episode dir holding `doc` (or the raw manifest `text`) as its `family.yaml`."""
    ep = S.episode_v2(Path(where), doc=doc if doc is not None else _doc())
    if text is not None:
        (ep / "family.yaml").write_text(text, encoding="utf-8")
    return ep


def _load(ep: Path) -> Any:
    """The runtime loader over the episode's manifest on disk (`load_family` through a view)."""
    with _episode_cls().open(Path(ep)) as handle:
        return S.sym(S.FAMILY, "load_family")(handle.view())


def _no_tenant() -> Any:
    raise AssertionError(
        "the sibling's loader resolved a tenant for the manifest — the launcher records "
        "served_systems so no reader after it resolves one (d01e)")


def _resume(ep: Path, label: str) -> Any:
    """The sibling's own loader (`run.resume_world`), with a tenant callable that raises."""
    return S.sym(S.RUN, "resume_world")(_episode_cls().open(Path(ep)), label,
                                        tenant=_no_tenant)


def _judge_read(ep: Path) -> dict:
    """The judge's raw manifest reader (`read_manifest` through its own bind)."""
    return S.sym("learning.judge.family", "raw_manifest")(Path(ep))


def _page(ep: Path, capsys: Any) -> tuple[int, str]:
    """The episode page as the operator runs it: its exit code and what it printed on stderr
    (#1105 PR 2, declared change 4: `--tenant T <episode_id>` under the episodes base holding
    `ep`, `_episode_1025.cli_on`)."""
    capsys.readouterr()
    rc, _out, err = E.cli_on(Path(ep), capsys, module=S.mod(S.VISUALIZE))
    return rc, err


def _page_file(ep: Path) -> Path:
    return Path(ep) / str(S.sym("_episode_paths", "LAYOUT").learning_html)


def _grade(ep: Path, judge: Any, where: Path) -> Any:
    """`grade_episode` over the episode at `ep`, by id (#1105 PR 2, `_judge_921.grade_at`): the
    judge reads only the episode it is handed (J3), so `where` threads nothing in."""
    from defender.tests._state1135 import env_state

    del where
    return J.grade_at(ep, judge=judge, state=env_state())


def _refused(call: Any, cls: type[BaseException]) -> str:
    """The message of `call`'s refusal, which must be exactly `cls` (never a crash)."""
    with pytest.raises(cls) as caught:
        call()
    return str(caught.value)


# --------------------------------------------------------------------------------------
# Documents.
# --------------------------------------------------------------------------------------

_F1 = S.fact("f1")
_F2 = S.fact("f2", "bob reset carol's password from 10.0.0.9", ("bob", "carol", "10.0.0.9"))
_ROLES = "BCDEFGH"
_PREDICATE = "did the analyst look at idp after the branch"


def _doc(*seats: tuple[str, list], **over: Any) -> dict:
    """A v2 manifest: the control world `a` (an explicit `facts: []`, M07=A), then one seat per
    `(label, facts)`, each with its OWN role — two arms sharing a role are refused by the
    launcher's identity gate, which would mask the rule a scenario is about."""
    seats = seats or (("b", [_F1]), ("c", [_F2]))
    worlds = [S.control_world("a")] + [
        S.world_v2(label, facts=list(facts), role=_ROLES[i])
        for i, (label, facts) in enumerate(seats)]
    return S.family_v2(worlds=worlds, **over)


def _old_doc(key: str, value: Any) -> dict:
    """`S.old_manifest(key)` with the old field set to exactly `value` — `None` included, which
    `S.old_manifest`'s own `value=None` cannot express (it means "the default")."""
    doc = S.old_manifest(key)
    if key == "overlay":
        doc["worlds"][1]["overlay"] = value
    elif key.startswith("discriminator."):
        doc["discriminator"][key.split(".", 1)[1]] = value
    else:
        doc[key] = value
    return doc


def _text(doc: dict, raw: dict[str, str] | None = None) -> str:
    """`doc` dumped as the launcher dumps it, then each placeholder replaced by a RAW literal —
    how a YAML literal (`on`, `007`, an alias) reaches the manifest unquoted."""
    text = _yaml.safe_dump(doc, sort_keys=False)
    for placeholder, literal in (raw or {}).items():
        assert placeholder in text, f"placeholder {placeholder} not in the dumped manifest"
        text = text.replace(placeholder, literal)
    return text


# --------------------------------------------------------------------------------------
# Observing what a loaded family exposes (fact objects or mappings alike).
# --------------------------------------------------------------------------------------


def _fact_view(fact: Any) -> dict:
    def field(name: str) -> Any:
        return fact[name] if isinstance(fact, dict) else getattr(fact, name)

    return {"fact_id": field("fact_id"), "statement": field("statement"),
            "entities": list(field("entities"))}


def _facts(family: Any, label: str) -> list[dict]:
    return [_fact_view(f) for f in family.world(label).facts]


def _served(family: Any) -> list[str]:
    return list(family.served_systems)


def _discriminator_text(disc: Any) -> Any:
    return disc.get("predicate") if isinstance(disc, dict) else disc


def _loads(doc: dict) -> Any:
    """The positive control: `doc` loads and exposes its facts and served_systems as written."""
    family = _parse(doc)
    assert _served(family) == list(doc["served_systems"]), _served(family)
    for world in doc["worlds"]:
        assert _facts(family, world["world_id"]) == [_fact_view(f) for f in world["facts"]]
    return family


_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _names(message: str, value: str) -> bool:
    """Does a refusal name `value`? As the project shows a refused value (`_shown.quoted`), as
    its repr or JSON spelling, or — for a long or control-bearing value the rendering truncates
    or escapes — by a printable head of at least two characters (a one-character head would
    be found in nearly any message)."""
    from defender._shown import quoted

    if any(shown in message for shown in (quoted(value), repr(value), json.dumps(value))):
        return True
    head = _CONTROL.split(value)[0][:24]
    return len(head) >= 2 and head in message


def _serving(where: Path, doc: dict, label: str, *, oracle: Any = None, verifier: Any = None,
             **knobs: Any) -> tuple[Any, Any, Path, Any]:
    """One world's registry over the fixture estate, `idp.query user:alice` answered by the
    real system. Returns `(registry, estate, episode dir, investigator ctx)`."""
    where = Path(where)
    est = S.estate(where)
    est.answer("idp", "query", S.query_params("user:alice"), _BASE_PAYLOAD)
    ep = S.episode_v2(where, doc=doc)
    box, _log = S.sandboxed_box()
    reg = S.world_registry(ep, label, est, oracle=oracle, verifier=verifier, box=box, **knobs)
    return reg, est, ep, est.ctx(where / "run")


def _samples(*, siem_x: list[str] | None = None) -> dict:
    """A samples record with a section for EVERY served system (O16: a served system with no
    section is itself a failure), `siem-x` carrying `siem_x` as its lookup examples."""
    out: dict[str, Any] = {s: {"unavailable": "no capture"} for s in S.SYSTEMS}
    if siem_x is not None:
        out["siem-x"] = {"verbs": {"lookup": list(siem_x)}}
    return out


_BASE_PAYLOAD = {"rows": [{"user": "alice", "event_id": "e-100", "action": "logon",
                           "host": "web-1", "ts": "2026-07-28T15:00:00Z"}]}


def _in_text(value: str, text: str) -> bool:
    """`value` reached `text` unchanged — written plainly or as a JSON string body."""
    return value in text or json.dumps(value)[1:-1] in text


# ======================================================================================
# The v2 shape (d01*).
# ======================================================================================


def test_1224_v2_manifest_with_facts_and_served_systems_loads(tmp_path):
    """d01a_v2_manifest_loads — parse_family and load_family load a v2 manifest and expose each world's facts, the family's served_systems and a discriminator holding only its text.

    (M1, M07=A: the control world's explicit empty facts list.)"""
    doc = _doc()
    for family in (_parse(doc), _load(_episode(tmp_path, doc))):
        assert _served(family) == list(S.SYSTEMS)
        assert _facts(family, "a") == []
        assert _facts(family, "b") == [_fact_view(_F1)]
        assert _facts(family, "c") == [_fact_view(_F2)]
        disc = family.discriminator
        assert _discriminator_text(disc) == _PREDICATE, disc
        if isinstance(disc, dict):
            assert not {"holding_system", "envelope"} & set(disc), disc


def test_1224_malformed_fact_is_refused_naming_the_field():
    """d01b_malformed_fact_refused — a fact missing a field or naming an entity outside the widened domain is refused naming the world, the field and the entity, while UPN, DOMAIN\\user and IPv6 entities load.

    RE-PINNED (M24=A; GD-25 refutes `_ENTITY_RE` as the entity domain). Outside the domain:
    empty, over the length bound, or carrying a control character (F-16, M24=A)."""
    FamilyError = _family_error()
    _loads(_doc())
    for entity in ("alice@corp.example", "CORP\\alice", "fe80::1%eth0", "2001:db8::7"):
        fact = S.fact("f1", "alice logged on to db-1 at 15:22Z", ("alice", entity))
        family = _parse(_doc(("oddfact", [fact]), ("c", [_F2])))
        assert _facts(family, "oddfact") == [_fact_view(fact)], entity
    for missing in ("fact_id", "statement", "entities"):
        bad = S.fact("f1")
        del bad[missing]
        msg = _refused(lambda bad=bad: _parse(_doc(("oddfact", [bad]), ("c", [_F2]))),
                       FamilyError)
        assert "oddfact" in msg, (missing, msg)
        assert missing in msg, (missing, msg)
    for entity in ("", "x" * 100_000, "ali\x07ce", "bob\ncarol", "\x00"):
        bad = S.fact("f1", "alice logged on to db-1 at 15:22Z", ("alice", entity))
        msg = _refused(lambda bad=bad: _parse(_doc(("oddfact", [bad]), ("c", [_F2]))),
                       FamilyError)
        assert "oddfact" in msg, (entity[:24], msg[:400])
        assert "entities" in msg, (entity[:24], msg[:400])
        assert _names(msg, entity), (entity[:24], msg[:400])






def _also_unknown(key: str) -> dict:
    doc = S.old_manifest(key)
    doc["zzz_unknown_1224"] = "x"
    doc["worlds"][2]["touches"] = ["idp"]
    return doc


def _five_worlds() -> dict:
    return _doc(("b", [_F1]), ("c", [_F2]), ("d", [S.fact("f3")]), ("e", [S.fact("f4")]))


def _old_in_third_of_five() -> dict:
    doc = _five_worlds()
    doc["worlds"][2]["overlay"] = {"patches": {"idp": {"alice": {"mfa": "off"}}}}
    return doc


def _discriminator(value: Any, *, overlay_world: int | None = None) -> dict:
    doc = _doc(("b", [_F1]), ("c", [_F2]), ("d", [S.fact("f3")])) if overlay_world else _doc()
    doc["discriminator"] = value
    if overlay_world:
        doc["worlds"][overlay_world]["overlay"] = {}
    return doc


def _aliased_text() -> str:
    base = _text(_doc())
    aliased = base.replace("served_systems:\n", "served_systems: &systems_1224\n", 1)
    assert aliased != base
    return aliased + "configured_patterns: *systems_1224\n"


#: Every old-manifest shape, as `(id, builder)`; a builder returns a document or raw YAML text.
_OLD_MANIFESTS: list[tuple[str, Any]] = [
    *[(f"field-{k}", lambda k=k: S.old_manifest(k)) for k in S.OLD_MANIFEST_KEYS],
    *[(f"also-unknown-{k}", lambda k=k: _also_unknown(k)) for k in S.OLD_MANIFEST_KEYS],
    ("alias", _aliased_text),
    ("merge-key", lambda: _text(_doc()) + '<<: {captured_patterns: ["logs-*"]}\n'),
    ("duplicate-key", lambda: _text(_old_doc("discriminator.holding_system", "elastic"))
     + f"discriminator:\n  predicate: {_PREDICATE}\n"),
    ("third-of-five", _old_in_third_of_five),
    ("discriminator-string", lambda: _discriminator("holding_system: elastic")),
    ("discriminator-list", lambda: _discriminator(
        [{"predicate": _PREDICATE}, {"holding_system": "elastic"}])),
    ("discriminator-null", lambda: _discriminator(None, overlay_world=3)),
]




# ======================================================================================
# Facts (N01, M24=A).
# ======================================================================================


def test_input_fact_entity_is_an_idp_principal(tmp_path):
    """b_p001 — identity-shaped entities load and reach the oracle's world block unchanged, and a refused entity is named, never dropped.

    Reading (M24=A, human R6): the entity domain is any non-empty printable string within a
    length bound, no control characters, never a path component; entity strings are data
    everywhere. Driven with a UPN, DOMAIN\\user, a link-local IPv6 address and a non-ASCII name."""
    entities = ["alice@corp.example", "CORP\\alice", "fe80::1%eth0", "élodie"]
    fact = S.fact("f1", "alice@corp.example (CORP\\alice, élodie) logged on from fe80::1%eth0 "
                  "at 15:22Z", entities)
    doc = _doc(("b", [fact]), ("c", [_F2]))
    assert _facts(_loads(doc), "b") == [_fact_view(fact)], "an entity was dropped or re-spelled"

    bad = S.fact("f1", "alice logged on", ("alice@corp.example", "ali\x07ce"))
    msg = _refused(lambda: _parse(_doc(("b", [bad]), ("c", [_F2]))), _family_error())
    assert _names(msg, "ali\x07ce"), msg

    oracle = S.oracle(S.submit(_BASE_PAYLOAD, S.EMPTY_CLAIM))
    reg, _est, _ep, ctx = _serving(tmp_path, doc, "b", oracle=oracle,
                                   verifier=S.passing_verifier(), retry_cap=1)
    S.call(reg, "idp", "query", ctx, q="user:alice")
    seen = oracle.all_seen()
    for entity in entities:
        assert _in_text(entity, seen), f"entity {entity!r} did not reach the oracle unchanged"
    assert not oracle.overrun


def test_input_fact_has_empty_entities():
    """b_p002 — a fact with no entities, a blank statement, or an oversized statement or entity list is refused promptly at load with a named reason.

    Reading (N01, auto). Settled regardless: such a fact never causes a served answer to differ
    from the base answer (it never loads), and nothing fails with a generic error."""
    FamilyError = _family_error()
    _loads(_doc())
    cases = [
        ("entities", S.fact("f1", "alice logged on to db-1 at 15:22Z", ())),
        ("statement", S.fact("f1", "", ("alice",))),
        ("statement", S.fact("f1", "  \t  ", ("alice",))),
        ("statement", S.fact("f1", "x" * 1_000_000, ("alice",))),
        ("entities", S.fact("f1", "a fleet logged on", [f"host{i}" for i in range(10_000)])),
    ]
    for field_name, bad in cases:
        start = time.monotonic()
        msg = _refused(lambda bad=bad: _parse(_doc(("oddfact", [bad]), ("c", [_F2]))),
                       FamilyError)
        assert time.monotonic() - start < 10, "an oversized fact hung the load"
        assert "oddfact" in msg, (field_name, msg[:400])
        assert field_name in msg, (field_name, msg[:400])


def test_input_fact_with_wrong_types(tmp_path):
    """s_p003 — a facts mapping, a single-string entities and a numeric fact_id each fail the load naming the field, and no world is served from the half-parsed manifest.

    No sibling or oracle turn starts for it."""
    FamilyError = _family_error()
    cases = [
        ("facts", {"f1": dict(_F1)}),
        ("entities", [{"fact_id": "f1", "statement": "alice logged on", "entities": "alice"}]),
        ("fact_id", [{"fact_id": 7, "statement": "alice logged on", "entities": ["alice"]}]),
    ]
    for field_name, facts in cases:
        doc = _doc(("oddfact", [_F1]), ("c", [_F2]))
        doc["worlds"][1]["facts"] = facts
        msg = _refused(lambda doc=doc: _parse(doc), FamilyError)
        assert "oddfact" in msg, (field_name, msg)
        assert field_name in msg, (field_name, msg)

    # The positive control: a well-formed world IS served through the oracle.
    oracle = S.oracle(S.submit(_BASE_PAYLOAD, S.EMPTY_CLAIM))
    reg, _est, _ep, ctx = _serving(tmp_path / "well-formed", _doc(("oddfact", [_F1]),
                                                                  ("c", [_F2])),
                                   "oddfact", oracle=oracle, verifier=S.passing_verifier(),
                                   retry_cap=1)
    S.call(reg, "idp", "query", ctx, q="user:alice")
    assert oracle.requests >= 1

    half = _doc(("oddfact", [_F1]), ("c", [_F2]))
    half["worlds"][1]["facts"] = cases[2][1]
    never = S.oracle(S.submit(_BASE_PAYLOAD, S.EMPTY_CLAIM))
    with pytest.raises(FamilyError):
        _serving(tmp_path / "half-parsed", half, "oddfact", oracle=never,
                 verifier=S.passing_verifier(), retry_cap=1)
    assert never.requests == 0
    assert S.Estate(tmp_path / "half-parsed" / "estate").calls() == []


def test_input_facts_share_a_fact_id_within_one_world():
    """b_p004 — two facts sharing one fact_id in one world are refused at load naming the duplicate id.

    Reading (N01, auto): fact_id is per world. Settled regardless: a forged row is never
    attributed to a fact other than the one the claim names (an ambiguous id never loads)."""
    first = S.fact("f1", "alice logged on to db-1 at 15:22Z", ("alice", "db-1"))
    second = S.fact("f1", "alice logged on to db-2 at 15:40Z", ("alice", "db-2"))
    msg = _refused(lambda: _parse(_doc(("dupworld", [first, second]), ("c", [_F2]))),
                   _family_error())
    assert "dupworld" in msg, msg
    assert "f1" in msg, msg
    family = _loads(_doc(("dupworld", [first, dict(second, fact_id="f2")]), ("c", [_F2])))
    assert [f["statement"] for f in _facts(family, "dupworld")] == [
        first["statement"], second["statement"]]


def test_input_facts_share_a_fact_id_across_worlds(tmp_path):
    """b_p005 — two worlds may each carry fact f1, and one world's frozen telemetry and statement never reach the other world's oracle or verifier.

    Reading (N01, auto): fact_id is per world. World b's frozen forged row sits in b's store as
    pre-flight leaves it, while c's own `f1` statement does reach c's oracle."""
    fact_b = S.fact("f1", "alice logged on to db-1 at 15:22Z", ("alice", "db-1"))
    fact_c = S.fact("f1", "bob reset carol's password from 10.0.0.9", ("bob", "carol",
                                                                        "10.0.0.9"))
    doc = _doc(("b", [fact_b]), ("c", [fact_c]))
    family = _loads(doc)
    assert _facts(family, "b") == [_fact_view(fact_b)]
    assert _facts(family, "c") == [_fact_view(fact_c)]

    # World b's frozen store, as pre-flight leaves it, in place before world c's registry.
    forged_b = {"forged_id": "fb-901x", "fact_id": "f1", "system": "idp",
                "row": {"user": "alice", "event_id": "e-77901", "action": "logon",
                        "host": "db-1", "ts": "2026-07-28T15:22:00Z"}}
    store_b = S.oracle_dir(tmp_path / "episodes" / S.EPISODE_ID, "b")
    store_b.mkdir(parents=True, exist_ok=True)
    (store_b / "forged.jsonl").write_text(json.dumps(forged_b) + "\n", encoding="utf-8")

    oracle = S.oracle(S.submit(_BASE_PAYLOAD, S.EMPTY_CLAIM))
    verifier = S.passing_verifier()
    reg, _est, ep, ctx = _serving(tmp_path, doc, "c", oracle=oracle, verifier=verifier,
                                  retry_cap=1)
    assert S.oracle_dir(ep, "b") == store_b
    S.call(reg, "idp", "query", ctx, q="user:alice")
    assert fact_c["statement"] in oracle.all_seen(), "world c's own fact never reached its oracle"
    for model in (oracle, verifier):
        seen = model.all_seen()
        assert "fb-901x" not in seen, "world b's forged row leaked"
        assert "e-77901" not in seen, "world b's forged row leaked"
        assert fact_b["statement"] not in seen, "world b's f1 statement reached world c"
    assert all(r.get("forged_id") != "fb-901x" for r in S.oracle_rows(ep, "c", "forged"))


def test_input_fact_statement_names_an_entity_not_in_entities():
    """b_p007 — a statement naming an entity its list omits, and a list naming an entity its statement never mentions, both load as written: no statement-entity cross-check at load.

    Deliberately not pinned here: the seed's "O3 holds either way" (a served answer differs
    from base only by what the facts imply). Whether a served answer honours a fact whose
    statement and entity list disagree is the oracle's and verifier's judgement — a
    non-obligation for this suite; O3's host half, checks 1-5, is pinned by the host-checks
    tests, and none of it depends on a statement agreeing with its entities."""
    omits = S.fact("f1", "alice logged on to db-1 and then db-7 at 15:22Z", ("alice", "db-1"))
    unmentioned = S.fact("f2", "a password reset happened at 10:00Z", ("bob", "carol"))
    family = _loads(_doc(("b", [omits, unmentioned]), ("c", [_F2])))
    assert _facts(family, "b") == [_fact_view(omits), _fact_view(unmentioned)]




# ======================================================================================
# Names (N02, N03).
# ======================================================================================


def test_input_served_system_name_is_path_hostile():
    """b_p015 — a served system name or world label holding a slash, a dot-dot, a space, an over-long run or a reserved token is refused at load naming it, and duplicate systems collapse to one.

    Reading (N02, auto); N03: served_systems is de-duplicated and roster-validated. Settled
    regardless: no file outside the episode's own directories is read or written from such a
    name (it never loads, so nothing is keyed by it). The samples record and the run-record
    labels are keyed only by names that loaded (d19c pins the run-record rule)."""
    FamilyError = _family_error()
    _loads(_doc())
    served = _served(_parse(_doc(served_systems=["idp", "edr", "idp"])))
    assert sorted(served) == ["edr", "idp"], served
    assert len(served) == 2, served
    for name in ("idp/../x", "../idp", "id p", "x" * 200, "__none__", "*", "IDP",
                 "idp\n## forged"):
        msg = _refused(lambda name=name: _parse(_doc(served_systems=["edr", name])),
                       FamilyError)
        assert "served_systems" in msg, (name[:24], msg[:400])
        assert _names(msg, name), (name[:24], msg[:400])
    for label in ("b/x", "..", "b c", "*"):
        msg = _refused(lambda label=label: _parse(_doc((label, [_F1]), ("c", [_F2]))),
                       FamilyError)
        assert _names(msg, label), (label, msg)


def test_input_world_labels_collide_or_are_reserved(tmp_path):
    """b_p016 — colliding, case-folded, hyphenated, traversing, drive-lettered, NUL-bearing, trailing-dot and reserved world labels are refused by the loader the sibling shares, and admitted labels keep distinct locations inside the episode.

    Reading (N02, auto): the world-token rule is unique case-insensitively, `base` reserved, no
    `-`; it lives in `parse_family`, so the sibling's `resume_world` applies it too."""
    FamilyError = _family_error()
    _loads(_doc())
    cases = [
        ((("b", [_F1]), ("b", [_F2])), "b"),
        ((("b", [_F1]), ("B", [_F2])), "B"),
        ((("b-x", [_F1]), ("c", [_F2])), "b-x"),
        ((("../b", [_F1]), ("c", [_F2])), "../b"),
        ((("c:", [_F1]), ("d", [_F2])), "c:"),
        ((("b\x00", [_F1]), ("c", [_F2])), "b\x00"),
        ((("b.", [_F1]), ("c", [_F2])), "b."),
        ((("base", [_F1]), ("c", [_F2])), "base"),
        ((("BASE", [_F1]), ("c", [_F2])), "BASE"),
    ]
    for seats, label in cases:
        msg = _refused(lambda seats=seats: _parse(_doc(*seats)), FamilyError)
        assert _names(msg, label), (label, msg)

    hostile = _episode(tmp_path / "hyphen", _doc(("b-x", [_F1]), ("c", [_F2])))
    for label in ("b-x", "c"):
        msg = _refused(lambda label=label: _resume(hostile, label), FamilyError)
        assert _names(msg, "b-x"), (label, msg)

    ep = _episode(tmp_path / "well-formed", _doc())
    worlds = [S.load_world(ep, label) for label in S.WORLDS]
    assert len({w.world_id for w in worlds}) == len(S.WORLDS)
    root = ep.resolve()
    for paths in ([S.ledger_path(ep, w.label) for w in worlds],
                  [S.oracle_dir(ep, w.label) for w in worlds]):
        assert len({p.resolve() for p in paths}) == len(S.WORLDS)
        assert all(root in p.resolve().parents for p in paths)


def test_p055_system_name_spelled_as_a_yaml_boolean_null_or_number(tmp_path):
    """b_p017 — a served system name that YAML reads as a boolean or null is refused at load, and the launcher's writer quotes such names so they read back as text.

    Reading (N02, auto). `1e3`, which YAML reads as text, loads as its text. Settled
    regardless: served_systems holds only text names, so lesson selection, the judge and the
    oracle's run_query door compare the intended name, never True or None."""
    FamilyError = _family_error()
    _loads(_doc())
    for i, literal in enumerate(("on", "no", "null", "1e3")):
        text = _text(_doc(served_systems=["edr", "PH_SYSTEM_1224"]),
                     {"PH_SYSTEM_1224": literal})
        ep = _episode(tmp_path / f"literal-{i}", text=text)
        read = _yaml.safe_load(literal)
        if isinstance(read, str):
            assert _served(_load(ep)) == ["edr", read]
        else:
            msg = _refused(lambda ep=ep: _load(ep), FamilyError)
            assert "served_systems" in msg, (literal, msg)

    ep = _episode(tmp_path / "quoted", _doc())
    with _episode_cls().open(ep) as handle:
        S.sym(S.FAMILY, "write_family")(handle, _doc(served_systems=["on", "no", "null",
                                                                     "1e3"]))
    served = _served(_load(ep))
    assert served == ["on", "no", "null", "1e3"]
    assert all(type(s) is str for s in served)


def test_p056_entity_or_fact_id_spelled_as_a_yaml_literal(tmp_path):
    """b_p018 — an entity or fact_id that YAML reads as a boolean, number or date is refused at load, and quoted 007 and 7 stay two distinct values.

    Reading (N02, auto). `1e3` reads as text and loads as it."""
    FamilyError = _family_error()
    _loads(_doc())
    for i, literal in enumerate(("no", "007", "1e3", "2026-05-25")):
        read = _yaml.safe_load(literal)
        as_entity = _text(_doc(("b", [S.fact("f1", "alice logged on", ("alice",
                                                                         "PH_ENTITY_1224"))]),
                               ("c", [_F2])), {"PH_ENTITY_1224": literal})
        as_fact_id = _text(_doc(("b", [S.fact("PH_FACT_ID_1224")]), ("c", [_F2])),
                           {"PH_FACT_ID_1224": literal})
        for field_name, text in (("entities", as_entity), ("fact_id", as_fact_id)):
            ep = _episode(tmp_path / f"{field_name}-{i}", text=text)
            if isinstance(read, str):
                fact = _facts(_load(ep), "b")[0]
                got = fact["entities"][1] if field_name == "entities" else fact["fact_id"]
                assert got == read, (literal, got)
            else:
                msg = _refused(lambda ep=ep: _load(ep), FamilyError)
                assert field_name in msg, (literal, field_name, msg)

    ep = _episode(tmp_path / "quoted", _doc())
    distinct = _doc(("b", [S.fact("007", "alice logged on", ("007", "7")),
                           S.fact("7", "bob logged on", ("bob",))]), ("c", [_F2]))
    with _episode_cls().open(ep) as handle:
        S.sym(S.FAMILY, "write_family")(handle, distinct)
    facts = _facts(_load(ep), "b")
    assert [f["fact_id"] for f in facts] == ["007", "7"]
    assert facts[0]["entities"] == ["007", "7"]






def test_1224_hostile_world_label_or_system_name_never_forges_a_section_or_leaves_its_directory(
        tmp_path, capsys):
    """o33_hostile_names_inert — a label or system name carrying a newline, '#', '<' or '/' is refused at every manifest reader and never reaches a judge prompt or a page, while a well-formed system's samples render as its own section.

    So it never forges a samples, judge or page section nor names a path outside its
    directory (N02, GR-08, GR-09). The label shapes at the launcher and the sibling's loader are
    driven by o26's test; here the system names at the loader, and a hostile label and system
    through the real judge and the page.
    """
    FamilyError, JudgeRefused = _family_error(), S.judge_refused_cls()
    for name in ("idp\n## forged", "idp#x", "idp<x", "idp/../x"):
        msg = _refused(lambda name=name: _parse(_doc(served_systems=["edr", name])),
                       FamilyError)
        assert "served_systems" in msg, (name, msg)
        assert _names(msg, name), (name, msg)

    # The positive control: well-formed names reach the judge and the page, and a system's
    # samples render as that system's own section.
    good = S.judged_episode(tmp_path / "well-formed", doc=_doc())
    S.samples_record(good, _samples(siem_x=["WELL-FORMED-SAMPLE-1224"]))
    judge = S.FakeJudge(default=S.as_reply_text(J.reply_doc()))
    _grade(good, judge, tmp_path / "well-formed")
    assert any("WELL-FORMED-SAMPLE-1224" in p for p in judge.prompts), "no samples section"
    rc, err = _page(good, capsys)
    assert rc == 0, err

    hostile_label = S.judged_episode(tmp_path / "hostile-label",
                                     doc=_doc(("b#x", [_F1]), ("c", [_F2])),
                                     labels=("a", "b#x", "c"))
    hostile_system = S.judged_episode(tmp_path / "hostile-system",
                                      doc=_doc(served_systems=["edr", "idp#x"]))
    S.samples_record(hostile_system, {"edr": {"unavailable": "no capture"},
                                      "idp#x": {"verbs": {"query": ["HOSTILE-SAMPLE-1224"]}}})
    for ep, named in ((hostile_label, "b#x"), (hostile_system, "idp#x")):
        judge = S.FakeJudge(default=S.as_reply_text(J.reply_doc()))
        msg = _refused(lambda ep=ep, judge=judge: _grade(ep, judge, ep.parent), JudgeRefused)
        assert _names(msg, named), msg
        assert judge.prompts == [], "a hostile name reached a judge prompt"
        rc, err = _page(ep, capsys)
        assert rc != 0, err
        assert _names(err, named), err
        assert not _page_file(ep).exists()


# ======================================================================================
# The branch-point clock.
# ======================================================================================


def test_input_manifest_has_no_branch_point_clock(tmp_path):
    """s_p019 — a manifest with no branch-point clock, or one that is not a time, is refused naming as_of before any world registry, oracle turn or read exists.

    No read is ever issued unbounded because the clock is missing (O6). Observed at the shared
    loader, the sibling's loader and the world registry a sibling builds; the positive control
    is a well-formed clock bounding the one read a control-world call makes. (The launcher
    writes the clock itself; a manifest without one reaches a reader only by being edited.)

    #1255 D3: that control-world call is one the source never asked (the episode records
    nothing), so it now goes through the control's oracle, which is told the same clock (was
    M07=A: no oracle turn)."""
    FamilyError = _family_error()
    control_oracle = S.oracle(S.submit(_BASE_PAYLOAD, S.EMPTY_CLAIM))
    reg, est, _ep, ctx = _serving(tmp_path / "clocked", _doc(), "a", oracle=control_oracle,
                                  verifier=S.passing_verifier())
    S.call(reg, "idp", "query", ctx, q="user:alice")
    assert [c["as_of"] for c in est.calls()] == [S.AS_OF_DT.isoformat()]
    assert control_oracle.requests >= 1, (
        "the control world served a question the source never asked as a raw live read")
    assert S.AS_OF in control_oracle.all_seen(), "the control's oracle was not told the clock"

    for i, as_of in enumerate((None, "yesterday afternoon", "2026-13-45T99:99:99Z")):
        doc = _doc()
        if as_of is None:
            del doc["as_of"]
        else:
            doc["as_of"] = as_of
        assert "as_of" in _refused(lambda doc=doc: _parse(doc), FamilyError)
        ep = _episode(tmp_path / f"clock-{i}", doc)
        assert "as_of" in _refused(lambda ep=ep: _resume(ep, "b"), FamilyError)
        oracle = S.oracle(S.submit(_BASE_PAYLOAD, S.EMPTY_CLAIM))
        before = len(est.calls())
        with pytest.raises(FamilyError):
            S.world_registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier(),
                             box=S.sandboxed_box()[0])
        assert oracle.requests == 0
        assert len(est.calls()) == before


# ======================================================================================
# Old manifests (O15, N04).
# ======================================================================================


def _beside_new(key: str) -> dict:
    doc = _doc()
    if key == "overlay":
        doc["worlds"][1]["overlay"] = {"patches": {"idp": {"alice": {"mfa": "off"}}}}
    else:
        doc["configured_patterns"] = ["logs-*"]
    return doc


#: Old fields present as empty or null (b_p023), and beside the new fields (s_p025).
_OLD_AT_EVERY_READER: list[tuple[str, Any]] = [
    ("overlay-empty", lambda: _old_doc("overlay", {})),
    ("overlay-null", lambda: _old_doc("overlay", None)),
    ("captured-empty", lambda: _old_doc("captured_patterns", [])),
    ("configured-empty", lambda: _old_doc("configured_patterns", [])),
    ("envelope-null", lambda: _old_doc("discriminator.envelope", None)),
    ("holding-null", lambda: _old_doc("discriminator.holding_system", None)),
    ("overlay-beside-facts", lambda: _beside_new("overlay")),
    ("configured-beside-served", lambda: _beside_new("configured_patterns")),
]




def test_p067_manifest_alias_bomb_or_pathological_nesting(tmp_path, capsys):
    """s_p030 — an alias bomb or a thousand-deep nesting is refused promptly with a named reason at the loader, the judge's reader and the page.

    It neither hangs nor exhausts memory. The readers it protects are O15's two manifest read
    paths — the runtime loader (`load_family` over `parse_family`) and the judge's raw
    `read_manifest` (`learning.judge.family.raw_manifest`), which the episode page reads
    through — so the old-field refusal O15 demands of them is reached only if a hostile manifest
    cannot hang or exhaust them first. Asserted per reader: a refusal of the reader's own class
    with a non-empty reason within 10 s (the page: a non-zero exit with a stderr reason within
    30 s); the plain v2 manifest loading is the positive control."""
    FamilyError, JudgeRefused = _family_error(), S.judge_refused_cls()
    base = _text(_doc())
    assert _served(_load(_episode(tmp_path / "plain", text=base))) == list(S.SYSTEMS)
    bomb = ["lol0: &lol0 [lol, lol, lol, lol, lol, lol, lol, lol, lol]"] + [
        f"lol{i}: &lol{i} [{', '.join([f'*lol{i - 1}'] * 9)}]" for i in range(1, 10)]
    deep = base.replace("base_story: the captured story",
                        "base_story: " + "[" * 1000 + "]" * 1000)
    assert deep != base
    for name, text in (("alias-bomb", base + "\n".join(bomb) + "\n"), ("deep", deep)):
        ep = _episode(tmp_path / name, text=text)
        for reader, cls in ((_load, FamilyError), (_judge_read, JudgeRefused)):
            start = time.monotonic()
            msg = _refused(lambda ep=ep, reader=reader: reader(ep), cls)
            assert time.monotonic() - start < 10, (name, "hung")
            assert msg.strip(), (name, "refused with no reason")
        start = time.monotonic()
        rc, err = _page(ep, capsys)
        assert time.monotonic() - start < 30, (name, "the page hung")
        assert rc != 0, (name, err)
        assert err.strip(), (name, err)


