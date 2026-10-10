"""#1224 O1 — any tenant can branch: every layer, end to end, over a tenant that is not the lab.

One scenario shape drives every layer the obligation names over the fixture tenant's own
systems (`edr`, `idp`, `siem-x`, served by stub adapters), or over a variant of it: the launcher
accepts the tenant and records its served systems, the question-writer authors world facts
against them, pre-flight calibrates through each fact world's oracle, a sibling's call on a
tenant system is served a verified world change, the judge grades the world, and a lesson keyed
by the systems the judge named is selected for a later episode of the same tenant.

Observed failing (O1): a branch over such a tenant is refused by some layer, or serves no world
change. Each test asserts every stage it reaches, so the first layer that still assumes a lab
system, a vendor or a response shape is the one that goes red.

The model seams are doubles entering through the coined injection points (the question-writer,
the oracle and verifier, the judge); the tenant's systems are real adapter modules planted on
disk. Nothing here uses `monkeypatch.setattr`.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests import _judge_921 as J  # noqa: E402
from defender.tests import _tenants1106 as T6  # noqa: E402
from defender.tests._state1135 import state_over  # noqa: E402
from defender.tests.live_oracle_1224 import _spec1224 as S  # noqa: E402

#: The answer every captured call of these launches returns. One shape for every call, so a
#: single pre-flight oracle script (submit the base unchanged) is right for any world and any
#: replay order; the launch stages are the subject here, not the answers.
SHARED = {"rows": [{"entity": "alice", "event_id": "e-1", "kind": "seen"}]}


@dataclass
class _Branch:
    """Everything one end-to-end branch over a tenant left behind, stage by stage."""

    launch: Any
    questioner: Any
    pre_oracle: Any
    pre_verifier: Any
    sibling_oracle: Any
    base: Any
    served: Any
    judge: Any
    judge_world: dict
    section: str
    #: A value only the forged row carries, so a reader that shows it was shown the served row.
    forged_marker: str
    lesson_marker: str
    foreign_marker: str


def _judge_world(record: dict, label: str) -> dict:
    """World `label`'s entry in the family record (`judge.yaml`), whether the record lists its
    worlds as rows naming `world` or maps them by label."""
    worlds = record.get("worlds")
    if isinstance(worlds, dict):
        entry = worlds.get(label)
        return entry if isinstance(entry, dict) else {}
    return J.world_rows(record).get(label, {}) if isinstance(worlds, list) else {}


def _lesson(directory: Path, name: str, systems: list[str], marker: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.md"
    path.write_text(f"---\nsystems: {json.dumps(systems)}\n---\n{marker}\n", encoding="utf-8")
    return path


def _branch_end_to_end(tmp_path: Path, est: S.Estate, *, doc: dict, calls: list,  # noqa: PLR0913 — one scenario's whole input
                       system: str, sibling_params: dict, sibling_base: dict,
                       forged_row: dict, bucket: str = "lead-set") -> _Branch:
    """Launch over `est`, serve one sibling call on `system` in world b, grade world b, then
    select lessons for a later episode by the systems the judge recorded."""
    questioner = S.questioner_for(doc)
    pre_oracle = S.oracle(then=S.submit(SHARED, S.EMPTY_CLAIM))
    pre_verifier = S.passing_verifier()
    launch = S.launch(tmp_path, est, calls=calls, questioner=questioner, oracle=pre_oracle,
                      verifier=pre_verifier,
                      judge=S.FakeJudge(default=S.judge_reply(systems=(system,), bucket=bucket)))

    est.answer(system, "query", sibling_params, sibling_base)
    key = next(iter(sibling_base))
    served = {key: [*sibling_base[key], forged_row]}
    sibling_oracle = S.oracle(S.forge("fg-1", "f1", system, forged_row),
                              S.submit(served, S.claim(added=[S.added("fg-1", "f1")])))
    box, _log = S.sandboxed_box()
    registry = S.world_registry(launch.ep, "b", est, oracle=sibling_oracle,
                                verifier=S.passing_verifier(), box=box, retry_cap=3)
    got = S.call(registry, system, "query", est.ctx(tmp_path / "sibling-run"), **sibling_params)

    judged = S.judged_episode(tmp_path / "judged", doc=doc,
                              ledgers={"b": S.ledger_rows(launch.ep, "b")})
    judge = S.FakeJudge(default=S.judge_reply(systems=(system,), bucket=bucket))
    J.grade_at(judged, judge=judge, state=state_over(tmp_path / "judge-state"), draws=1)
    judge_world = _judge_world(J.judge_record(judged), "b")

    lesson_marker, foreign_marker = f"LESSON-ON-{system}", "LESSON-ON-elastic"
    lessons = [
        _lesson(tmp_path / "lessons", "learned", list(judge_world.get("systems") or []),
                lesson_marker),
        _lesson(tmp_path / "lessons", "foreign", ["elastic"], foreign_marker),
    ]
    section = S.sym(S.QUESTIONER, "_questioner_lessons_section")(
        lessons, served_systems=est.served_systems())
    return _Branch(launch=launch, questioner=questioner, pre_oracle=pre_oracle,
                   pre_verifier=pre_verifier, sibling_oracle=sibling_oracle, base=sibling_base,
                   served=got, judge=judge, judge_world=judge_world, section=section,
                   forged_marker=next(v for v in forged_row.values()
                                      if isinstance(v, str) and "9001" in v),
                   lesson_marker=lesson_marker, foreign_marker=foreign_marker)


def _assert_every_layer(run: _Branch, *, systems: tuple[str, ...], system: str,
                        bucket: str = "lead-set") -> None:
    """The stages O1 names, each observed where it leaves its trace."""
    # The launcher accepted the tenant and the question-writer ran against its systems.
    assert "elastic" not in run.launch.message
    assert run.questioner.calls >= 1
    for name in systems:
        assert name in run.questioner.prompts[0], f"the question-writer is shown {name}"
    # Pre-flight calibrated through each fact world's oracle and accepted the family.
    assert run.pre_oracle.requests >= 2
    assert run.pre_verifier.requests >= 2
    outcome = S.read_outcome(run.launch.ep)
    assert outcome is not None
    assert outcome["outcome"] == "accepted"
    assert set(run.launch.spawn.worlds) >= {"a", "b", "c"}
    # The manifest the launcher wrote loads for the sibling, and serving changes the world.
    assert S.load_world(run.launch.ep, "b") is not None
    assert run.served != run.base, "the sibling is served a world change"
    assert [r.get("source") for r in S.ledger_rows(run.launch.ep, "b")] == [S.ORACLE_DECISION]
    assert system in run.sibling_oracle.all_seen()
    # The judge graded the world from the model's reading.
    assert any(run.forged_marker in p for p in run.judge.prompts), (
        "the judge is shown the sibling's served (forged) row")
    assert run.judge_world.get("bucket") == bucket
    assert system in (run.judge_world.get("systems") or [])
    # A lesson keyed by the systems the judge recorded is selected for this tenant.
    assert run.lesson_marker in run.section
    assert run.foreign_marker not in run.section


def _family(systems: tuple[str, ...], fact_b: dict, fact_c: dict) -> dict:
    return S.family_v2(served_systems=systems, worlds=[
        S.control_world("a"),
        S.world_v2("b", facts=[fact_b]),
        S.world_v2("c", facts=[fact_c]),
    ])


EDR_ROW = {"event_id": "x-7", "host": "db-1", "process": "sshd", "ts": "2026-07-28T15:10:00Z"}
EDR_FORGED = {"event_id": "x-9001", "host": "db-1", "process": "kinit",
              "ts": "2026-07-28T15:22:00Z"}


def _windowed(q: str) -> dict:
    """A call the source run never made (its window differs from every captured call's), so the
    sibling reads its base live."""
    return S.query_params(q, start="2026-07-28T15:00:00Z", end="2026-07-28T16:00:00Z")


def _default_calls() -> list:
    return [S.Call(c.system, c.verb, c.params, SHARED) for c in S.default_calls()]


def test_1224_a_tenant_with_no_lab_systems_branches_and_serves_a_world_change(tmp_path):
    """d02a_any_tenant_branches_end_to_end — a branch over a tenant serving only edr, idp and
    siem-x is refused by no layer and serves a verified world change on edr.

    The manifest loads, the question-writer runs, pre-flight accepts, a sibling call on edr
    receives an `oracle` answer that differs from the base answer, the judge grades, and a
    lesson with systems [edr] is selected for a later episode of that tenant. O1.
    """
    est = S.estate(tmp_path)
    doc = _family(S.SYSTEMS, S.fact("f1"), S.fact("f2", "bob reset carol's password from "
                                                        "10.0.0.9", ("bob", "carol", "10.0.0.9")))
    run = _branch_end_to_end(tmp_path, est, doc=doc, calls=_default_calls(), system="edr",
                             sibling_params=_windowed("host:db-1"),
                             sibling_base={"events": [EDR_ROW]}, forged_row=EDR_FORGED)
    _assert_every_layer(run, systems=S.SYSTEMS, system="edr")
    assert run.served == {"events": [EDR_ROW, EDR_FORGED]}
    assert est.served_systems() == sorted(S.SYSTEMS)


@pytest.mark.parametrize("elastic", ["none-configured", "fails-to-resolve"])
def test_1224_launch_over_a_tenant_with_no_elastic_system(tmp_path, elastic):
    """s_p036 — a branch over a tenant that configures no elastic system, or whose elastic part
    fails to resolve while elastic is not in its gather grant, is not refused for lack of
    elastic: every stage from tenant acceptance to lesson selection proceeds.

    O1: a branch over such a tenant refused or serving no world change is the observed failure.
    """
    est = S.estate(tmp_path)
    if elastic == "fails-to-resolve":
        T6.place_tenant(Path(os.environ["DEFENDER_DATA_ROOT"]), S.FIXTURE_TENANT,
                        table=est.table(),
                        configs={"elastic": "ELASTIC_TRANSPORT=carrier-pigeon\n"})
        assert type(est.run_tenant().elastic).__name__ == "ConfigFault"
    else:
        assert est.run_tenant().elastic is None
    assert "elastic" not in est.run_tenant().grants.gather.systems

    doc = _family(S.SYSTEMS, S.fact("f1"), S.fact("f2", "bob reset carol's password from "
                                                        "10.0.0.9", ("bob", "carol", "10.0.0.9")))
    # Check 2's reference is the column set of some real idp row at this path (M14 re-ruled
    # 2026-10-10), so the forged row carries exactly the sibling base row's columns.
    idp_row = {"action": "logon", "event_id": "e-100", "user": "alice", "entity": "alice",
               "kind": "seen"}
    run = _branch_end_to_end(tmp_path, est, doc=doc, calls=_default_calls(), system="idp",
                             sibling_params=_windowed("user:alice"),
                             sibling_base={"rows": [idp_row]},
                             forged_row={"action": "tgt-issued", "event_id": "e-9001",
                                         "user": "alice", "entity": "alice", "kind": "seen"})
    _assert_every_layer(run, systems=S.SYSTEMS, system="idp")
    assert "elastic" not in run.launch.message.lower()


def test_input_tenant_system_replaces_a_lab_system_with_another_shape(tmp_path):
    """s_p037 — a tenant system named like a lab system (identity, ticket) whose verbs, params
    and answer shapes are nothing like the lab's is branched end to end with no lab assumption.

    The question-writer authors facts against the tenant's own systems, the oracle serves world
    changes from the tenant's own verbs and shapes, and the judge buckets from the model's
    reading (O1).
    """
    systems = ("identity", "ticket")
    est = S.estate(tmp_path, systems=systems)
    doc = _family(systems,
                  S.fact("f1", "alice enrolled a new MFA device at 15:22Z", ("alice",)),
                  S.fact("f2", "bob reopened record T-9 at 15:40Z", ("bob", "T-9")))
    calls = [S.Call("identity", "query", S.query_params("user:alice"), SHARED),
             S.Call("ticket", "lookup", {"entity": "T-9"}, SHARED)]
    device = {"device": "yubi-1", "owner": "alice", "seen": "2026-07-28T15:00:00Z"}
    forged = {"device": "phone-9001", "owner": "alice", "seen": "2026-07-28T15:22:00Z"}
    run = _branch_end_to_end(tmp_path, est, doc=doc, calls=calls, system="identity",
                             sibling_params=_windowed("user:alice"),
                             sibling_base={"devices": [device]}, forged_row=forged,
                             bucket="lead-quality")
    _assert_every_layer(run, systems=systems, system="identity", bucket="lead-quality")
    assert run.served == {"devices": [device, forged]}, (
        "the world change is served in the tenant's own answer shape")


def test_input_all_worlds_fact_the_same_single_system(tmp_path):
    """s_p038 — a tenant serving exactly one system, with every world's facts on it, launches,
    pre-flights, serves and is graded like any other, and the samples record, the oracle's
    family block and lesson selection work from that one system.
    """
    systems = ("edr",)
    est = S.estate(tmp_path, systems=systems)
    doc = _family(systems,
                  S.fact("f1", "db-1 ran kinit for alice at 15:22Z", ("db-1", "alice")),
                  S.fact("f2", "web-1 spawned a reverse shell at 15:40Z", ("web-1",)))
    calls = [S.Call("edr", "query", S.query_params("host:db-1"), SHARED),
             S.Call("edr", "lookup", {"entity": "db-1"}, SHARED)]
    run = _branch_end_to_end(tmp_path, est, doc=doc, calls=calls, system="edr",
                             sibling_params=S.query_params("host:web-1"),
                             sibling_base={"events": [dict(EDR_ROW, host="web-1")]},
                             forged_row=dict(EDR_FORGED, host="web-1"))
    _assert_every_layer(run, systems=systems, system="edr")

    samples = S.read_samples(run.launch.ep)
    assert samples is not None
    assert set(samples) == {"edr"}, "the samples record is keyed by the one served system"
    family_block = run.pre_oracle.seen[0]
    assert "edr" in family_block
    assert "siem-x" not in family_block
    assert est.served_systems() == ["edr"]
