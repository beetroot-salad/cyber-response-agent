"""#1224 — manifest v2: facts and served_systems in, every pre-oracle field refused (M1, O1, O15).

The manifest (`runtime/branch/_family.py`) carries a world's natural-language `facts` and the
family's `served_systems`; `discriminator` keeps only its text. Five old fields refuse the whole
manifest with a message saying it predates the oracle, at both read paths (the runtime loader
and the judge's raw `read_manifest`, which the episode page shares). The world-label rule that
the deleted view-name arm used to enforce moves into the loader every reader shares (N02), and
the entity domain is widened to any printable string within a bound (M24=A).

RED at base 96e4cdb0 by construction: today's loader refuses every v2 document on its first
unknown top-level field, so every refusal below is paired, in the same test, with the
well-formed v2 document loading (the positive control), and every refusal names what it
refused — a bare `FamilyError` would be green at HEAD for the wrong reason.

Every reader is reached through `S.sym` / `S.mod` at call time; nothing new is imported at
collection time.
"""
from __future__ import annotations

import contextlib
import json
import re
import time
from pathlib import Path
from typing import Any

import pytest

from defender import _yaml
from defender.tests import _judge_921 as J
from defender.tests.live_oracle_1224 import _spec1224 as S

# --------------------------------------------------------------------------------------
# Readers — the runtime loader, the sibling's loader, the judge's raw reader, the page.
# --------------------------------------------------------------------------------------


def _family_error() -> type[BaseException]:
    return S.sym(S.FAMILY, "FamilyError")


def _judge_refused() -> type[BaseException]:
    return S.sym(S.JUDGE, "JudgeRefused")


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
    """The episode page as the operator runs it: its exit code and what it printed on stderr."""
    capsys.readouterr()
    rc = S.sym(S.VISUALIZE, "main")([str(ep)])
    return rc, capsys.readouterr().err


def _page_file(ep: Path) -> Path:
    return Path(ep) / str(S.sym("_episode_paths", "LAYOUT").learning_html)


def _grade(ep: Path, judge: Any, where: Path) -> Any:
    from defender.tests._state1135 import env_state

    return S.sym(S.JUDGE, "grade_episode")(ep, judge=judge, runs_base=Path(where) / "runs-base",
                                           state=env_state())


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

    parse_family and load_family load a manifest whose worlds carry facts
    [{fact_id, statement, entities}] and which records served_systems, exposing each world's
    facts and the family's served_systems, and whose discriminator keeps its text without
    holding_system or envelope (M1, M07=A: the control world's explicit empty facts list).
    """
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

    RE-PINNED (M24=A; GD-25 refutes `_ENTITY_RE` as the entity domain). A fact missing
    fact_id, statement or entities, or naming an entity outside the widened entity domain
    (empty, over the length bound, or carrying a control character), fails to load with
    FamilyError naming the world, the field and the entity; a UPN, a DOMAIN\\user name and an
    IPv6 address load (F-16, M24=A).
    """
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


def test_1224_manifest_load_assumes_no_system_name():
    """d01c_manifest_assumes_no_system_names — a manifest serving edr, idp and siem-x loads, and the loader keeps no lab-system rule.

    A manifest whose served_systems are [edr, idp, siem-x] loads, and nothing at load refuses
    a system for not being one of the lab's (the C1 refusal 'not one of the six state systems'
    is gone, with PATCHABLE_SYSTEMS and STAGED_SYSTEM) (O1, M1).
    """
    family = _loads(_doc(served_systems=["edr", "idp", "siem-x"]))
    assert _served(family) == ["edr", "idp", "siem-x"]
    # A lab system is no more special than a tenant's own: nothing keys on the name.
    assert _served(_parse(_doc(served_systems=["tacit-knowledge", "edr"]))) == [
        "tacit-knowledge", "edr"]
    fam = S.mod(S.FAMILY)
    for gone in ("PATCHABLE_SYSTEMS", "STAGED_SYSTEM"):
        assert not hasattr(fam, gone), f"{gone} survives in the manifest loader"
    src = S.source_text("runtime/branch/_family.py")
    assert "def parse_family" in src, "the census did not read the loader's source"
    assert "six state systems" not in src


def test_1224_sibling_resume_resolves_no_tenant_for_the_manifest(tmp_path):
    """d01e_resume_reads_served_systems_not_a_tenant — the sibling's resume_world loads a v2 manifest without ever calling its tenant callable, and run.py keeps no configured_patterns fallback.

    resume_world loads a v2 manifest and builds the world with a tenant callable that raises
    if called, so no reader after the launcher resolves a tenant for the manifest (run.py's
    configured_patterns fallback is gone) (M1, C5).
    """
    ep = _episode(tmp_path, _doc())
    world = _resume(ep, "b")
    assert world.label == "b"
    assert _served(world.family) == list(S.SYSTEMS)
    assert _facts(world.family, "b") == [_fact_view(_F1)]
    src = S.source_text("run.py")
    assert "def resume_world" in src, "the census did not read the sibling's loader"
    assert "configured_patterns" not in src


def test_1224_old_manifest_field_is_refused_at_the_loader_as_predating_the_oracle(tmp_path):
    """d01g_old_manifest_refused_at_loader — each of the five pre-oracle fields refuses the manifest at the runtime loader with a message saying it predates the oracle.

    For each of overlay, discriminator.holding_system, discriminator.envelope,
    captured_patterns and configured_patterns, a manifest carrying that field fails to load at
    the runtime loader with a FamilyError whose message says the manifest predates the oracle,
    not a generic unknown-field or schema error and not a crash (O15). Old manifests are not
    translated (non-obligation).
    """
    FamilyError = _family_error()
    assert _served(_load(_episode(tmp_path / "v2", _doc()))) == list(S.SYSTEMS)
    for key in S.OLD_MANIFEST_KEYS:
        ep = _episode(tmp_path / key.replace(".", "_"), S.old_manifest(key))
        msg = _refused(lambda ep=ep: _load(ep), FamilyError)
        assert S.PREDATES in msg, (key, msg)


# ======================================================================================
# Facts (N01, M24=A).
# ======================================================================================


def test_input_fact_entity_is_an_idp_principal(tmp_path):
    """b_p001 — identity-shaped entities load and reach the oracle's world block unchanged, and a refused entity is named, never dropped.

    Reading (M24=A, human R6): the entity domain is any non-empty printable string within a
    length bound, no control characters, never a path component; entity strings are data
    everywhere; an entity the loader refuses is named in the message, never dropped. Applied: a
    UPN, DOMAIN\\user, a link-local IPv6 address and a non-ASCII name load as written and
    reach the oracle unchanged. Settled regardless: the load never fails with a generic error
    or crash on such an entity, and a fact naming an entity the loader does not accept is
    refused with a message naming the entity.
    """
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

    Reading (N01, auto): refuse at load, with a named reason, a fact with no entities, a blank
    statement, or a statement or entity list over a size bound. Settled regardless: such a fact
    never causes a served answer to differ from the base answer (it never loads), an oversized
    fact is refused with a named reason rather than hanging the load, and nothing fails with a
    generic error.
    """
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

    Settled: a world whose facts is a mapping, whose entities is a single string, or whose
    fact_id is a number fails manifest load with a message naming the malformed field; no world
    is served from a half-parsed manifest and no sibling or oracle turn starts for it.
    """
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

    Reading (N01, auto): refuse a duplicate fact_id within a world; fact_id is per world.
    Applied: two facts `f1` with different statements in one world fail the load naming the
    world and the id; distinct ids load, each its own fact. Settled regardless: a forged row is
    never attributed to a fact other than the one the claim names (an ambiguous id never
    loads).
    """
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

    Reading (N01, auto): fact_id is per world. Applied: worlds b and c each carrying `f1` with
    different statements load, each world keeping its own; world b's frozen forged row (as
    pre-flight leaves it in b's store) never reaches world c's oracle or verifier, while c's
    own `f1` statement does. Settled regardless: served answers are per world, so one world's
    forged rows never appear in another world's answers.
    """
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

    Reading (N01, auto): no statement-entity cross-check at load. Asserted: both facts load
    with statement and entities exactly as written — nothing at load parses the statement
    against its entity list (the seed's settled "nothing at load parses the statement").
    Deliberately not pinned here: the seed's "O3 holds either way" (a served answer differs
    from base only by what the facts imply). Whether a served answer honours a fact whose
    statement and entity list disagree is the oracle's and verifier's judgement — a
    non-obligation for this suite; O3's host half, checks 1-5, is pinned by the host-checks
    tests, and none of it depends on a statement agreeing with its entities.
    """
    omits = S.fact("f1", "alice logged on to db-1 and then db-7 at 15:22Z", ("alice", "db-1"))
    unmentioned = S.fact("f2", "a password reset happened at 10:00Z", ("bob", "carol"))
    family = _loads(_doc(("b", [omits, unmentioned]), ("c", [_F2])))
    assert _facts(family, "b") == [_fact_view(omits), _fact_view(unmentioned)]


def test_p053_two_facts_in_one_world_contradict_each_other(tmp_path):
    """b_p020 — contradictory facts load and both reach the verifier, and the host honours the verifier's verdict on them: a failing verdict ends the call unservable with no oracle answer, while the same submission under a passing verdict is served.

    Reading (N01, auto): contradictory facts are left to the oracle and verifier, ending
    unservable. Settled regardless: no served answer contradicts itself or an earlier one (O2);
    a world that cannot be served consistently is unservable rather than served with an
    inconsistency.

    Asserted (the F-01 pattern): the world loads with both facts. One scripted submission —
    the base plus a forged 15:22Z logon for f1, which f2 contradicts — is put to the verifier,
    and the host hands the verifier the call, the base answer, the served answer carrying the
    frozen forged row, and BOTH fact statements, never the oracle's own text (a sentinel in its
    python source). Under a verifier whose verdict fails it, the call raises `OracleUnservable`
    and no `oracle` row is written; under a passing verifier the SAME submission is served and
    rowed `oracle`. So the verdict, and no host rule about contradictory statements, is what
    ends the world. Whether a verifier DETECTS the contradiction is model quality — a
    non-obligation, deliberately not pinned (the verdicts here are scripted).
    """
    on = S.fact("f1", "alice logged on to db-1 at 15:22Z", ("alice", "db-1"))
    never = S.fact("f2", "alice never logged on to any host on 2026-07-28", ("alice",))
    doc = _doc(("b", [on, never]), ("c", [_F2]))
    assert [f["fact_id"] for f in _facts(_loads(doc), "b")] == ["f1", "f2"]

    sentinel = "ORACLEREASON-P053"
    forged = {"user": "alice", "event_id": "e-90053", "action": "logon", "host": "db-1",
              "ts": "2026-07-28T15:22:00Z"}
    served = {"rows": [*_BASE_PAYLOAD["rows"], forged]}

    def oracle() -> Any:
        """The one submission both arms make: a forged f1 logon on top of the base answer."""
        return S.oracle(S.python(f"# {sentinel}: f2 says never, f1 says 15:22Z; serve f1"),
                        S.forge("fg-53", "f1", "idp", forged),
                        S.submit(served, S.claim(added=[S.added("fg-53", "f1")])))

    failing_oracle = oracle()
    failing = S.failing_verifier("f1 and f2 cannot both hold")
    reg, _est, ep, ctx = _serving(tmp_path / "failing", doc, "b", oracle=failing_oracle,
                                  verifier=failing, retry_cap=1)
    with pytest.raises(S.unservable_cls()):
        S.call(reg, "idp", "query", ctx, q="user:alice")
    seen = failing_oracle.all_seen()
    assert on["statement"] in seen, "both facts reach the oracle"
    assert never["statement"] in seen, "both facts reach the oracle"
    assert not [r for r in S.ledger_rows(ep, "b") if r.get("source") == S.ORACLE_DECISION]
    assert failing.requests >= 1, "the verifier was never consulted"
    shown = failing.all_seen()
    for what, needle in (("f1's statement", on["statement"]),
                         ("f2's statement", never["statement"]),
                         ("the call's params", "user:alice"),
                         ("the base answer", "e-100"),
                         ("the served answer and its frozen forged row", "e-90053")):
        assert needle in shown, f"the verifier was not handed {what}"
    assert sentinel not in shown, "the oracle's own text reached the verifier"

    # The control: the SAME submission under a passing verdict is served — the verdict decides.
    passing_oracle, passing = oracle(), S.passing_verifier()
    reg, _est, ep, ctx = _serving(tmp_path / "passing", doc, "b", oracle=passing_oracle,
                                  verifier=passing, retry_cap=1)
    assert S.call(reg, "idp", "query", ctx, q="user:alice") == served
    assert [r.get("source") for r in S.ledger_rows(ep, "b")] == [S.ORACLE_DECISION]
    assert never["statement"] in passing.all_seen()
    assert not passing_oracle.overrun


# ======================================================================================
# Names (N02, N03).
# ======================================================================================


def test_input_served_system_name_is_path_hostile():
    """b_p015 — a served system name or world label holding a slash, a dot-dot, a space, an over-long run or a reserved token is refused at load naming it, and duplicate systems collapse to one.

    Reading (N02, auto): refuse at load, with a named reason, any system name the roster does
    not accept and any world label outside the world-token rule; N03: served_systems is
    de-duplicated and roster-validated. Settled regardless: no file outside the episode's own
    directories is read or written from such a name (it never loads, so nothing is keyed by
    it), and two distinct names never share one file or key. The samples record and the
    run-record labels are keyed only by names that loaded (d19c pins the run-record rule).
    """
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

    Reading (N02, auto): refuse at load any world label outside the world-token rule (unique
    case-insensitively, `base` reserved, no `-`); the rule lives in the loader every reader
    shares (`parse_family`, so the sibling's `resume_world` applies it too). Settled
    regardless: every world has a distinct ledger, store and archive location, none outside
    the episode directory, and one world's records are never read as another's.
    """
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

    Reading (N02, auto): names are read and written as quoted strings; a non-string scalar is
    refused. Applied: unquoted `on`, `no` and `null` in served_systems refuse the load naming
    the field; `1e3`, which YAML reads as text, loads as its text; the same four names written
    by the manifest writer read back as text. Settled regardless: served_systems holds only text
    names, so lesson selection, the judge and the oracle's run_query door compare the intended
    name, never True or None.
    """
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

    Reading (N02, auto): names, entities and fact_ids are read and written as quoted strings;
    a non-string scalar is refused. Applied: unquoted `no`, `007` and `2026-05-25` as an entity
    refuse the load naming `entities`, and as a fact_id naming `fact_id`; `1e3` reads as text
    and loads as it. Settled regardless: an entity or fact_id is never silently turned into a
    different value, so `007` and `7` stay distinct.
    """
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


def test_1224_forbidden_world_label_is_refused_by_the_launcher_and_the_sibling_loader(tmp_path):
    """o26_label_rule_at_every_loader — a world label with a newline, '#', '<', '/', upper case or '-' is refused with a named reason by the shared loader, the sibling's loader and the launcher.

    After the world-view hooks are gone, a world label of a forbidden shape (a newline, '#',
    '<', '/', upper case, '-') is still refused at load with a named reason, by the launcher's
    check and by the sibling's loader (resume_world through parse_family) (N02, GR-09, GR-11).
    """
    FamilyError = _family_error()
    _loads(_doc())
    assert _resume(_episode(tmp_path / "well-formed", _doc()), "b").label == "b"
    for i, label in enumerate(("b\nx", "b#x", "b<x", "b/x", "Bx", "b-x")):
        doc = _doc((label, [_F1]), ("c", [_F2]))
        assert _names(_refused(lambda doc=doc: _parse(doc), FamilyError), label), label
        ep = _episode(tmp_path / f"label-{i}", doc)
        assert _names(_refused(lambda ep=ep, label=label: _resume(ep, label), FamilyError),
                      label), label

    est = S.estate(tmp_path)
    launch = S.launch(tmp_path, est, questioner=S.questioner_for(_doc(("b#x", [_F1]),
                                                                      ("c", [_F2]))))
    assert launch.rc != 0
    assert launch.spawn.launches == []
    assert _names(launch.message, "b#x"), launch.message


def test_1224_world_label_with_a_hyphen_is_refused_so_the_label_round_trips():
    """o29_label_hyphen_rule — with the view-name arm gone, a label carrying '-' is refused at load naming it, and an admitted label round-trips through the launcher's run-dir label reader.

    After the view-name arm is removed, a world label containing '-' (siem-x, -edr) is refused
    at launch with a named reason, so every admitted label round-trips through the launcher's
    run-dir label reader (siem_x reads back as siem_x) (N02 re-homes the hyphen rule; GR-12,
    GR-13).
    """
    FamilyError = _family_error()
    confinement = S.mod("scripts.adapters.confinement")
    assert hasattr(confinement, "confine_index"), "the census did not reach confinement"
    assert not hasattr(confinement, "refuse_unnameable_world"), "the view-name arm survives"
    src = S.source_text("runtime/branch/_family.py")
    assert "def parse_family" in src, "the census did not read the loader"
    assert "refuse_unnameable_world" not in src
    for label in ("siem-x", "-edr"):
        msg = _refused(lambda label=label: _parse(_doc((label, [_F1]), ("c", [_F2]))),
                       FamilyError)
        assert _names(msg, label), (label, msg)
    family = _loads(_doc(("siem_x", [_F1]), ("c", [_F2])))
    assert [w.world_id for w in family.worlds] == ["a", "siem_x", "c"]
    label_of = S.sym(S.CLI, "_world_label_of")
    assert label_of(Path("/runs") / f"{S.EPISODE_ID}-siem_x") == "siem_x"


def test_1224_launcher_identity_gate_refuses_hyphenated_labels(tmp_path, monkeypatch):
    """pco10_hyphen_label_rule — the launcher refuses an authored family whose labels are siem-x or -edr, naming the label, before any sibling starts; siem_x is admitted and round-trips.

    The launcher's identity gate (or its successor) refuses the labels `siem-x` and `-edr`
    with a named reason; positive control: `siem_x` is admitted and round-trips through the
    run-dir label reader (N02, PCO-10).
    """
    from defender.tests._data_root_1078 import DATA_ROOT_ENV

    for label in ("siem-x", "-edr"):
        where = tmp_path / f"launch{label}"
        (where / "data-root").mkdir(parents=True)
        monkeypatch.setenv(DATA_ROOT_ENV, str(where / "data-root"))
        est = S.estate(where)
        launch = S.launch(where, est, questioner=S.questioner_for(_doc((label, [_F1]),
                                                                       ("c", [_F2]))))
        assert launch.rc != 0, label
        assert launch.spawn.launches == [], label
        assert _names(launch.message, label), (label, launch.message)
    _loads(_doc(("siem_x", [_F1]), ("c", [_F2])))
    label_of = S.sym(S.CLI, "_world_label_of")
    assert label_of(Path("/runs") / f"{S.EPISODE_ID}-siem_x") == "siem_x"


def test_1224_hostile_world_label_or_system_name_never_forges_a_section_or_leaves_its_directory(
        tmp_path, capsys):
    """o33_hostile_names_inert — a label or system name carrying a newline, '#', '<' or '/' is refused at every manifest reader and never reaches a judge prompt or a page, while a well-formed system's samples render as its own section.

    A world label or system name carrying a newline, '#', '<' or '/' is refused at every
    manifest reader (the launcher, the sibling's loader, the judge's and the page's
    read_manifest) and so never forges a samples, judge or page section nor names a path
    outside its directory; a well-formed name renders as its own section (positive control)
    (N02, GR-08, GR-09).
    """
    FamilyError, JudgeRefused = _family_error(), _judge_refused()
    for i, label in enumerate(("b\n## forged", "b#x", "b<x", "b/x")):
        doc = _doc((label, [_F1]), ("c", [_F2]))
        assert _names(_refused(lambda doc=doc: _parse(doc), FamilyError), label)
        ep = _episode(tmp_path / f"label-{i}", doc)
        assert _names(_refused(lambda ep=ep, label=label: _resume(ep, label), FamilyError),
                      label)
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
    with contextlib.suppress(Exception):
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


def test_1224_sibling_loader_and_raw_manifest_reader_refuse_a_label_outside_the_alphabet(
        tmp_path):
    """pco11_every_loader_refuses_hostile_label — the sibling's resume_world, the judge's raw read_manifest and the page's loader each refuse a label outside the launcher alphabet; a well-formed label reads through all three.

    A manifest whose world label lies outside the launcher alphabet is refused by
    resume_world (the sibling's loader) and by the judge's and the page's read_manifest, so the
    label reaches no judge prompt and no page; positive control: a well-formed label loads
    through all three (N02, PCO-11).
    """
    FamilyError, JudgeRefused = _family_error(), _judge_refused()
    load_page = S.sym(S.VISUALIZE, "load_episode")
    good = _episode(tmp_path / "well-formed", _doc())
    assert _resume(good, "b").label == "b"
    assert [w["world_id"] for w in _judge_read(good)["worlds"]] == list(S.WORLDS)
    load_page(good)
    for i, label in enumerate(("b\nx", "b#x", "Bx")):
        ep = _episode(tmp_path / f"label-{i}", _doc((label, [_F1]), ("c", [_F2])))
        assert _names(_refused(lambda ep=ep, label=label: _resume(ep, label), FamilyError),
                      label), label
        assert _names(_refused(lambda ep=ep: _judge_read(ep), JudgeRefused), label), label
        assert _names(_refused(lambda ep=ep: load_page(ep), JudgeRefused), label), label


# ======================================================================================
# The branch-point clock.
# ======================================================================================


def test_input_manifest_has_no_branch_point_clock(tmp_path):
    """s_p019 — a manifest with no branch-point clock, or one that is not a time, is refused naming as_of before any world registry, oracle turn or read exists.

    Settled: a manifest with no branch-point clock, or one that does not parse as a time, is
    refused with a named reason before any sibling, oracle exploration or pre-flight replay; no
    read is ever issued unbounded because the clock is missing (O6). Observed at the shared
    loader, the sibling's loader and the world registry a sibling builds; the positive control
    is a well-formed clock bounding the one read a control-world call makes. (The launcher
    writes the clock itself; a manifest without one reaches a reader only by being edited.)
    """
    FamilyError = _family_error()
    control_oracle = S.oracle()
    reg, est, _ep, ctx = _serving(tmp_path / "clocked", _doc(), "a", oracle=control_oracle,
                                  verifier=S.passing_verifier())
    S.call(reg, "idp", "query", ctx, q="user:alice")
    assert [c["as_of"] for c in est.calls()] == [S.AS_OF_DT.isoformat()]
    assert control_oracle.requests == 0, "the control world (no facts) took an oracle turn"

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


def test_input_old_manifest_field_is_empty_or_null(tmp_path, capsys):
    """b_p023 — an old field present as an empty mapping, an empty list or null still refuses the manifest as predating the oracle at the loader, the judge's reader and the page.

    Reading (N04, auto): the presence of an old key refuses the manifest (empty or null
    included) and the predates-the-oracle reason is reported first. Settled regardless: a
    manifest that triggers it fails with a message saying it predates the oracle, never a
    generic schema error.
    """
    FamilyError, JudgeRefused = _family_error(), _judge_refused()
    good = S.judged_episode(tmp_path / "v2", doc=_doc())
    assert _served(_load(good)) == list(S.SYSTEMS)
    assert _judge_read(good)["served_systems"] == list(S.SYSTEMS)
    rc, err = _page(good, capsys)
    assert rc == 0, err

    cases = [("overlay", {}), ("overlay", None), ("captured_patterns", []),
             ("configured_patterns", []), ("discriminator.envelope", None),
             ("discriminator.holding_system", None)]
    for i, (key, value) in enumerate(cases):
        ep = _episode(tmp_path / f"old-{i}", _old_doc(key, value))
        assert S.PREDATES in _refused(lambda ep=ep: _load(ep), FamilyError), (key, value)
        assert S.PREDATES in _refused(lambda ep=ep: _judge_read(ep), JudgeRefused), (key, value)
        rc, err = _page(ep, capsys)
        assert rc != 0, (key, value, err)
        assert S.PREDATES in err, (key, value, err)


def test_input_manifest_is_both_old_and_malformed(tmp_path):
    """b_p024 — a manifest carrying an old field and also an unknown field is refused with the predates-the-oracle reason, not the other malformation.

    Settled: a manifest that carries an old field and is also malformed another way is refused
    with the reason that it predates the oracle (O15: a generic schema error is the failure),
    and that reason is not displaced by the other malformation. Control: the same unknown
    field with no old field is refused naming it, without the predates reason.
    """
    FamilyError, JudgeRefused = _family_error(), _judge_refused()
    _loads(_doc())
    only_unknown = _doc()
    only_unknown["zzz_unknown_1224"] = "x"
    msg = _refused(lambda: _parse(only_unknown), FamilyError)
    assert "zzz_unknown_1224" in msg, msg
    assert S.PREDATES not in msg, msg
    for key in S.OLD_MANIFEST_KEYS:
        doc = S.old_manifest(key)
        doc["zzz_unknown_1224"] = "x"
        doc["worlds"][2]["touches"] = ["idp"]
        ep = _episode(tmp_path / key.replace(".", "_"), doc)
        assert S.PREDATES in _refused(lambda ep=ep: _load(ep), FamilyError), key
        assert S.PREDATES in _refused(lambda ep=ep: _judge_read(ep), JudgeRefused), key


def test_input_manifest_mixes_old_and_new_shapes(tmp_path, capsys):
    """s_p025 — a manifest carrying the new fields and an old one is refused as predating the oracle at the runtime loader, the judge and the episode page.

    Settled: any manifest carrying an old field is refused with the predates-the-oracle reason
    at the runtime loader, the judge's reader and the episode page, whether or not it also
    carries the new fields; the new fields do not rescue it (O15).
    """
    FamilyError, JudgeRefused = _family_error(), _judge_refused()
    good = S.judged_episode(tmp_path / "v2", doc=_doc())
    S.samples_record(good, _samples())
    judge = S.FakeJudge(default=S.as_reply_text(J.reply_doc()))
    with contextlib.suppress(Exception):
        _grade(good, judge, tmp_path / "v2")
    assert judge.prompts, "the v2 episode never reached the judge"
    rc, err = _page(good, capsys)
    assert rc == 0, err

    beside_facts = _doc()
    beside_facts["worlds"][1]["overlay"] = {"patches": {"idp": {"alice": {"mfa": "off"}}}}
    beside_served = _doc()
    beside_served["configured_patterns"] = ["logs-*"]
    for name, doc in (("overlay", beside_facts), ("configured", beside_served)):
        ep = S.judged_episode(tmp_path / name, doc=_doc())
        S.write_manifest(ep, doc)
        assert S.PREDATES in _refused(lambda ep=ep: _load(ep), FamilyError), name
        judge = S.FakeJudge(default=S.as_reply_text(J.reply_doc()))
        msg = _refused(lambda ep=ep, judge=judge: _grade(ep, judge, ep.parent), JudgeRefused)
        assert S.PREDATES in msg, (name, msg)
        assert judge.prompts == [], (name, "an old manifest reached the judge")
        rc, err = _page(ep, capsys)
        assert rc != 0, (name, err)
        assert S.PREDATES in err, (name, err)
        assert not _page_file(ep).exists()


def test_p065_old_field_introduced_via_alias_merge_key_or_duplicate_key(tmp_path):
    """s_p028 — an old field arriving through an alias, a merge key or a hidden duplicate key is refused as predating the oracle by both read paths alike.

    Settled: an old field that enters the manifest through a YAML anchor, merge key or
    duplicate key is refused with the predates-the-oracle reason exactly as a written-out field
    would be, and the runtime loader and the judge's raw reader agree on every such manifest.
    """
    FamilyError, JudgeRefused = _family_error(), _judge_refused()
    base = _text(_doc())
    plain = _episode(tmp_path / "plain", text=base)
    assert _served(_load(plain)) == list(S.SYSTEMS)
    assert _judge_read(plain)["served_systems"] == list(S.SYSTEMS)

    aliased = base.replace("served_systems:\n", "served_systems: &systems_1224\n", 1)
    assert aliased != base
    hidden = _old_doc("discriminator.holding_system", "elastic")
    variants = {
        "alias": aliased + "configured_patterns: *systems_1224\n",
        "merge": base + '<<: {captured_patterns: ["logs-*"]}\n',
        "duplicate": _text(hidden) + f"discriminator:\n  predicate: {_PREDICATE}\n",
    }
    for name, text in variants.items():
        ep = _episode(tmp_path / name, text=text)
        loader = _refused(lambda ep=ep: _load(ep), FamilyError)
        judge = _refused(lambda ep=ep: _judge_read(ep), JudgeRefused)
        assert S.PREDATES in loader, (name, loader)
        assert S.PREDATES in judge, (name, judge)


def test_p066_old_marker_in_one_world_only_or_inside_a_discriminator_that_is_not_a_mapping(
        tmp_path):
    """s_p029 — an old field in one world of five, or old markers inside a string, list or null discriminator, refuse the whole manifest as predating the oracle at both read paths, never crashing.

    Settled: an old field in only one world of several, or markers sitting inside a
    discriminator that is a string, list or null, still refuses the whole manifest with the
    predates-the-oracle reason at both read paths; a non-mapping discriminator never causes a
    crash instead of the named refusal.
    """
    FamilyError, JudgeRefused = _family_error(), _judge_refused()
    five = _doc(("b", [_F1]), ("c", [_F2]), ("d", [S.fact("f3")]), ("e", [S.fact("f4")]))
    _loads(five)
    third = _doc(("b", [_F1]), ("c", [_F2]), ("d", [S.fact("f3")]), ("e", [S.fact("f4")]))
    third["worlds"][2]["overlay"] = {"patches": {"idp": {"alice": {"mfa": "off"}}}}
    as_string = _doc()
    as_string["discriminator"] = "holding_system: elastic"
    as_list = _doc()
    as_list["discriminator"] = [{"predicate": _PREDICATE}, {"holding_system": "elastic"}]
    as_null = _doc(("b", [_F1]), ("c", [_F2]), ("d", [S.fact("f3")]))
    as_null["discriminator"] = None
    as_null["worlds"][3]["overlay"] = {}
    for name, doc in (("third-of-five", third), ("string", as_string), ("list", as_list),
                      ("null", as_null)):
        ep = _episode(tmp_path / name, doc)
        assert S.PREDATES in _refused(lambda ep=ep: _load(ep), FamilyError), name
        assert S.PREDATES in _refused(lambda ep=ep: _judge_read(ep), JudgeRefused), name


def test_p067_manifest_alias_bomb_or_pathological_nesting(tmp_path, capsys):
    """s_p030 — an alias bomb or a thousand-deep nesting is refused promptly with a named reason at the loader, the judge's reader and the page.

    Discharges settled premise s_p030 (P030, 45-dispositions, settled; the graph binds
    `parse_family`, `grade_episode` and `render_episode`): a manifest that expands
    exponentially through YAML aliases or nests a thousand levels deep is refused promptly with
    a named reason at the loader, the judge's reader and the page; it neither hangs nor
    exhausts memory. The readers it protects are O15's two manifest read paths — the runtime
    loader (`load_family` over `parse_family`) and the judge's raw `read_manifest`
    (`learning.judge.family.raw_manifest`), which the episode page reads through — so the
    old-field refusal O15 demands of them is reached only if a hostile manifest cannot hang or
    exhaust them first. Asserted per reader: a refusal of the reader's own class with a
    non-empty reason within 10 s (the page: a non-zero exit with a stderr reason within 30 s);
    the plain v2 manifest loading is the positive control.
    """
    FamilyError, JudgeRefused = _family_error(), _judge_refused()
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


def test_p068_old_field_spelled_with_case_or_whitespace_variants():
    """b_p031 — Overlay, "overlay " and holding-system are unknown fields: the manifest is refused naming the variant, not as predating the oracle.

    Reading (N04, auto): spelling variants of an old field are unknown fields (O15 names the
    exact field names). Settled regardless: such a manifest is not loaded.
    """
    FamilyError = _family_error()
    _loads(_doc())
    in_world = []
    for variant in ("Overlay", "overlay "):
        doc = _doc()
        doc["worlds"][1][variant] = {"patches": {}}
        in_world.append((variant, doc))
    in_discriminator = _doc()
    in_discriminator["discriminator"]["holding-system"] = "elastic"
    for variant, doc in [*in_world, ("holding-system", in_discriminator)]:
        msg = _refused(lambda doc=doc: _parse(doc), FamilyError)
        assert variant.strip() in msg, (variant, msg)
        assert S.PREDATES not in msg, (variant, msg)


def test_1224_judges_raw_manifest_reader_reads_v2_and_refuses_every_old_field(tmp_path):
    """o38_read_manifest_refuses_old — the judge's raw read_manifest reads a v2 manifest's facts and served_systems and refuses each old field as predating the oracle.

    The judge's raw read_manifest reads a v2 manifest's facts and served_systems, and fails
    every manifest carrying overlay, discriminator.holding_system, discriminator.envelope,
    captured_patterns or configured_patterns with the predates-the-oracle reason (F-11, N04).
    """
    JudgeRefused = _judge_refused()
    doc = _judge_read(_episode(tmp_path / "v2", _doc()))
    assert doc["served_systems"] == list(S.SYSTEMS)
    assert doc["worlds"][1]["facts"] == [_F1]
    for key in S.OLD_MANIFEST_KEYS:
        ep = _episode(tmp_path / key.replace(".", "_"), S.old_manifest(key))
        assert S.PREDATES in _refused(lambda ep=ep: _judge_read(ep), JudgeRefused), key
