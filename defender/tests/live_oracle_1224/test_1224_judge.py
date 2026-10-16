"""The judge model decides each world's bucket from the served-world prompt; host-side gate, reply validation and finding enqueue around it."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from defender import _yaml
from defender.learning.core.state import FINDINGS, QUESTIONER_FINDINGS
from defender.tests import _episode_1025 as E
from defender.tests import _judge_921 as J
from defender.tests import _state1135
from defender.tests._state1135 import env_state
from defender.tests.live_oracle_1224 import _spec1224 as S




# --------------------------------------------------------------------------------------
# Private helpers (listed as helper requests in the hand-back).
# --------------------------------------------------------------------------------------


@dataclass
class _JudgeByScope(S.FakeJudge):
    """#921's recording `FakeJudge`, whose reply is chosen by the world (or the family scope)
    the call names in its agent id. Inject-only: it routes a SCRIPT, it decides nothing.

    `worlds[label]` is a reply text, or a list of texts answered in call order (the last one
    repeats); `family` is the family-scope reply. A label with no script falls back to
    `FakeJudge`'s own `replies`/`default`. `fault` keeps #921's P9 shape (executed): a failed
    call is `RunUnprocessable`, whatever its cause."""

    worlds: dict[str, Any] = field(default_factory=dict)
    family: Any = None

    def __call__(self, prompt: str, *, role: Any = None, agent_id: str = "judge",
                 **kw: Any) -> str:
        label = S.judge_label(agent_id)
        scripted = self.family if label == "family" else self.worlds.get(label)
        if scripted is None:
            return super().__call__(prompt, role=role, agent_id=agent_id, **kw)
        self.prompts.append(prompt)
        self.agent_ids.append(agent_id)
        self.kwargs.append({"role": role, "agent_id": agent_id, **kw})
        if self.fault.hits(agent_id):
            raise self._unprocessable(f"judge ({agent_id}) failed", "TransportFault")
        if isinstance(scripted, list):
            return scripted.pop(0) if len(scripted) > 1 else scripted[0]
        return scripted


def _finding(topic: str = "the lead was never revisited", *, bucket: str = "lead-quality",
             subject: str = "defender", evidence: list[str] | None = None,
             **over: Any) -> dict:
    """One finding as the model writes it — #921's `finding_doc` in the #1234 shape, with no
    pattern or holding_system (the v2 reply drops both). A `defender` finding is an
    investigator finding resting on the default two-run contrast; a `world` finding names
    `idp` (one of `S.SYSTEMS`) and, by default, the manifest's family-level discriminator."""
    doc = J.finding_doc(bucket=bucket, subject=subject, topic=topic, evidence=evidence,
                        systems=None if subject == "defender" else ["idp"])
    doc.update(over)
    return doc


def _world_reply(bucket: str | Any = "lead-quality", systems: Any = ("idp",),
                 findings: list[dict] | None = None, **over: Any) -> dict:
    """A world-scope reply in the #1234 shape (the three pass tables, noise_floor_note, the
    three filed lists) with the top-level `bucket` and `systems` exactly as given."""
    doc = J.reply_doc(findings=[_finding()] if findings is None else findings)
    doc["bucket"] = bucket
    doc["systems"] = list(systems) if isinstance(systems, (list, tuple)) else systems
    doc.update(over)
    return doc


def _family_reply(**over: Any) -> dict:
    """A family-scope reply in the #1234 shape: family-scope world findings only (none by
    default) — no family verdict word (A17)."""
    return J.family_reply(**over)


def _text(doc: Any) -> str:
    return S.as_reply_text(doc)


def _judge(worlds: dict[str, Any] | None = None, *,
           family_text: str | None = None, default: str | None = None,
           fault: Any = S.CLEAN) -> _JudgeByScope:
    """A by-scope judge double. Unscripted worlds answer an explicit `none` with no finding."""
    def as_text(value: Any) -> Any:
        if isinstance(value, list):
            return [as_text(v) for v in value]
        return value if isinstance(value, str) else _text(value)

    return _JudgeByScope(
        worlds={label: as_text(v) for label, v in (worlds or {}).items()},
        family=family_text if family_text is not None else _text(_family_reply()),
        default=default if default is not None else _text(
            _world_reply("none", (), findings=[])),
        fault=fault)


def _grade(tmp_path: Path, ep: Path, judge: Any, **kw: Any) -> Any:
    """`grade_episode` through its own seams: one draw, a recording `git show`, this test's
    state handle — by id (#1105 PR 2, `_judge_921.grade_at`): the judge reads only the episode
    it is handed (J3), so `tmp_path` threads nothing in."""
    del tmp_path
    kw.setdefault("draws", 1)
    kw.setdefault("git_show", J.FakeGitShow())
    kw.setdefault("state", env_state())
    return J.grade_at(ep, judge=judge, **kw)


def _record(ep: Path) -> dict:
    """`judge.yaml`, read raw off disk (an absent file is `{}`)."""
    path = Path(ep) / "judge.yaml"
    if not path.is_file():
        return {}
    return _yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _rows(ep: Path) -> dict[str, dict]:
    rec = _record(ep)
    return {r["world"]: r for r in rec.get("worlds") or [] if isinstance(r, dict)
            and "world" in r}


def _row(ep: Path, label: str) -> dict:
    return _rows(ep).get(label) or {}


def _queue(state: Any = None, channel: Any = FINDINGS) -> list[dict]:
    """A queue's rows, read through the state handle's own reader."""
    return (state if state is not None else env_state()).rows(channel)


def _all_queued(state: Any = None) -> list[dict]:
    return _queue(state, FINDINGS) + _queue(state, QUESTIONER_FINDINGS)


def _from_world(rows: list[dict], label: str) -> list[dict]:
    """Queue rows whose finding id names world `label` (`<run>/<label>/<draw>/<i>`)."""
    return [r for r in rows if f"/{label}/" in str(r.get("finding_id"))]


def _prompt_for(judge: Any, label: str) -> str:
    """The first prompt the double was handed for world `label`."""
    for prompt, agent_id in zip(judge.prompts, judge.agent_ids, strict=True):
        if str(agent_id).startswith(f"judge:{label}:"):
            return prompt
    raise AssertionError(
        f"the judge model was never called for world {label!r} (calls: {judge.agent_ids})")








def _topics(findings: Any) -> set[str]:
    return {f.get("topic") for f in findings or [] if isinstance(f, dict)}


def _worlds_named(doc: Any) -> set[str]:
    """Every value held under a `world` key anywhere in a loaded record (or list of rows) —
    the family record's rows, its findings, a queue row."""
    if isinstance(doc, dict):
        own = {doc["world"]} if isinstance(doc.get("world"), str) else set()
        return own.union(*(_worlds_named(v) for v in doc.values()))
    if isinstance(doc, (list, tuple)):
        return set().union(*(_worlds_named(v) for v in doc))
    return set()


def _filed(ep: Path, label: str) -> list[dict]:
    """Every finding world `label`'s draws filed (#1234: a world row carries no findings; the
    draw documents hold the three filed lists), draw by draw in filing order."""
    out: list[dict] = []
    for n in range(len(J.draw_files(ep, label))):
        doc = J.draw_doc(ep, label, n)
        for key in ("investigator_findings", "world_findings", "gaps"):
            out.extend(f for f in doc.get(key) or [] if isinstance(f, dict))
    return out


def _lanes(ep: Path, label: str, draw: int = 0) -> dict[Any, Any]:
    """Each filed finding of world `label`'s draw `draw`, by topic, mapped to the lane the
    record's ledger (`dispositions`) gave it — joined on `finding_id`'s index (A13: one index
    space over the three filed lists in filing order)."""
    ledger = {e.get("finding_id"): e.get("lane") for e in _record(ep).get("dispositions") or []}
    doc = J.draw_doc(ep, label, draw)
    filed = [f for key in ("investigator_findings", "world_findings", "gaps")
             for f in doc.get(key) or []]
    return {f.get("topic"): ledger.get(f"{S.EPISODE_ID}/{label}/{draw}/{i}")
            for i, f in enumerate(filed)}


def _draws_of(ep: Path) -> list[Path]:
    worlds = Path(ep) / "worlds"
    return sorted(worlds.glob("*/judge/*.yaml")) if worlds.is_dir() else []


def _call(q: str, system: str = "idp") -> dict:
    return {"system": system, "verb": "query", "params": S.query_params(q)}


def _sibling_says(ep: Path, label: str, disposition: str) -> None:
    """The sibling's archived verdict (the close gate's report shape)."""
    (Path(ep) / "worlds" / label / "report.md").write_text(
        J.report_text(disposition), encoding="utf-8")


def _oracle_row(q: str, *, label: str = "b", claim: dict | None = None,
                verdict: dict | None = None, **extra: Any) -> dict:
    """A served `oracle` ledger row (coined fields: base_digest, claim, verifier_verdict,
    attempts)."""
    row = S.ledger_row(S.ORACLE_DECISION, params=S.query_params(q), label=label,
                       payload={"rows": [{"user": "alice", "event_id": "f-1"}]},
                       base_digest=S.digest("base"), attempts=1, **extra)
    if claim is not None:
        row["claim"] = claim
    if verdict is not None:
        row["verifier_verdict"] = verdict
    return row


def _page(ep: Path) -> tuple[str | None, str | None]:
    """The episode page: `(html, None)` when it renders, `(None, refusal text)` when it refuses
    by name (`JudgeRefused`). Any other exception propagates — that is a crash. (#1105 PR 2,
    declared change 4: rendered by id, `_episode_1025.render_episode`.)"""
    refused = S.judge_refused_cls()
    try:
        path = E.render_episode(Path(ep), module=S.mod(S.VISUALIZE))
    except refused as refusal:
        return None, str(refusal)
    return Path(path).read_text(encoding="utf-8"), None




def _validate(text: str, *, scope: str = "world") -> Any:
    return S.sym(S.JUDGE_RUN, "validate_reply")(text, scope=scope)


# --------------------------------------------------------------------------------------
# M21 / O15 — what the judge reads the family from
# --------------------------------------------------------------------------------------






# --------------------------------------------------------------------------------------
# O5 / S9 — family validity, counted from pre-flight plus each world's own record
# --------------------------------------------------------------------------------------


def test_1224_family_with_one_unservable_sibling_is_graded_on_the_rest(tmp_path):
    """d06a_one_unservable_still_graded — a family with exactly one unservable sibling is
    graded: the healthy worlds get the judge model's buckets and findings, and the unservable
    world gets none.

    O5, M07=A. World c's sibling went unservable mid-run (its own record says "oracle
    unservable", S8). The judge double would answer c with a bucket and a finding if asked;
    neither may be recorded or enqueued, while world b's model bucket and finding are, and the
    family is recorded usable.
    """
    ep = S.judged_episode(tmp_path)
    S.world_record(ep, "c", S.REASON_UNSERVABLE, call=_call("user:carol"),
                   detail="the call failed check 2 on every attempt")
    judge = _judge({
        "b": _world_reply("lead-quality", ("idp",), findings=[_finding("b-healthy")]),
        "c": _world_reply("lead-set", ("idp",), findings=[_finding("c-unservable")]),
    })
    _grade(tmp_path, ep, judge)

    rec, rows = _record(ep), _rows(ep)
    assert rows.get("b", {}).get("bucket") == "lead-quality", (
        f"the healthy world did not get the judge model's bucket: {rows.get('b')!r}")
    assert "b-healthy" in _topics(_filed(ep, "b")), (
        "the healthy world's model finding was not recorded")
    assert rec.get("validity") == "usable", (
        f"one unservable sibling made the family {rec.get('validity')!r}, not usable (O5)")
    unservable = rows.get("c", {})
    assert not unservable.get("bucket"), f"the unservable world was bucketed: {unservable!r}"
    assert not unservable.get("findings"), f"the unservable world carries findings: {unservable!r}"
    assert not _filed(ep, "c"), "the unservable world has draw documents filing findings"
    queued = _all_queued()
    assert _from_world(queued, "b"), "the healthy world's finding never reached a queue"
    assert not _from_world(queued, "c"), "a finding of the unservable world was enqueued"


def test_1224_family_with_two_unservable_siblings_is_unusable_and_yields_no_findings(
        tmp_path, monkeypatch):
    """d06b_two_unservable_unusable — two or more failed worlds make the family unusable at
    both sites, with no findings and no model call at the judge.

    RE-PINNED (48: S9; two sites). M04=A, M19=A (validity is its own field).

    The judge site counts BOTH sources: the outcome record (written `accepted` by pre-flight
    with one failed world, b) plus world c's own "did not finish" record written after launch.
    Positive control: the same family with only pre-flight's one failure is graded.
    """
    # Positive control: one unservable world (pre-flight's) — graded, the model is called.
    one = tmp_path / "one"
    ep1 = S.judged_episode(one, outcome=None)
    S.outcome_record(ep1, "accepted", unservable=[
        {"world": "b", "reason": S.REASON_UNSERVABLE, "call": _call("user:alice")}])
    judge1 = _judge({"c": _world_reply("decision-discipline", ("edr",))})
    _grade(one, ep1, judge1, state=_state1135.state_over(one / "state"))
    assert S.judge_called_for(judge1, "c"), "the positive control: a one-unservable family was not graded"
    assert _record(ep1).get("validity") == "usable"

    # The judge site: pre-flight's failed world plus a world whose own record says it did not
    # finish — two, counted with no model call.
    two = tmp_path / "two"
    ep = S.judged_episode(two, outcome=None)
    S.outcome_record(ep, "accepted", unservable=[
        {"world": "b", "reason": S.REASON_UNSERVABLE, "call": _call("user:alice")}])
    S.world_record(ep, "c", S.REASON_DID_NOT_FINISH, detail="the sibling exited 1")
    state = _state1135.state_over(two / "state")
    judge = _judge({"b": _world_reply("lead-set", ("idp",)),
                    "c": _world_reply("lead-quality", ("idp",))})
    _grade(two, ep, judge, state=state)

    rec = _record(ep)
    assert judge.calls == 0, f"an unusable family bought model calls: {judge.agent_ids}"
    assert rec.get("validity") == "unusable", (
        f"two unservable worlds (pre-flight's plus a sibling's own record) left the family "
        f"{rec.get('validity')!r} (S9)")
    assert all(not r.get("bucket") and not r.get("findings") for r in _rows(ep).values()), (
        "an unusable family carries a bucket or findings")
    assert not _draws_of(ep), "an unusable family left draw files"
    assert _all_queued(state) == [], "an unusable family enqueued findings"

    # The pre-flight site: two failed calibrations write `unusable` and start no sibling.
    monkeypatch.setenv(S.KNOB_RETRY_CAP, "1")
    site = tmp_path / "launch"
    est = S.estate(site)
    spawn = S.FakeSpawn()
    launch = S.launch(site, est, oracle=S.oracle(then=S.text_only()),
                      verifier=S.passing_verifier(), spawn=spawn, judge=_judge())
    outcome = S.read_outcome(launch.ep) or {}
    assert outcome.get("outcome") == "unusable", f"pre-flight wrote {outcome!r}"
    assert {u.get("world") for u in outcome.get("unservable_worlds") or []} == {"b", "c"}
    assert spawn.launches == [], "a sibling started for a family pre-flight found unusable"


# --------------------------------------------------------------------------------------
# O11 / M19 / M20 — the model decides the bucket; the host only refuses
# --------------------------------------------------------------------------------------


def test_1224_world_bucket_is_the_judge_models_output(tmp_path):
    """d12a_bucket_is_the_models — each bucket the judge model returns for a world is the one
    recorded for it, whatever the world's ledger decisions and the sibling's verdict were.

    O11, M19=A (`none` is an explicit bucket on the defender arm, recorded, never enqueued).

    Every episode is held fixed — world b's ledger is `passthrough` but for one `oracle` row
    (#1234 A5: the discipline buckets are unavailable to a world never shown its facts, so the
    world is shown them once) and its sibling concluded `benign` against a declared
    `malicious` — so only the model's reply varies, and the recorded bucket follows it.
    `validate_reply` admits each member on its own.
    """
    for bucket in ("lead-set", "lead-quality", "analyze-discipline", "decision-discipline",
                   "none"):
        root = tmp_path / bucket
        ledger = [S.ledger_row(S.PASSTHROUGH, params=S.query_params(f"user:u{i}"))
                  for i in range(3)] + [_oracle_row("user:shown")]
        ep = S.judged_episode(root, ledgers={"b": ledger})
        _sibling_says(ep, "b", "benign")
        findings = [] if bucket == "none" else [_finding(f"{bucket}-finding", bucket=bucket)]
        reply = _world_reply(bucket, ("idp",), findings=findings)
        assert getattr(_validate(_text(reply)), "bucket", None) == bucket, (
            f"validate_reply did not admit the bucket {bucket!r} as the reply's own")

        state = _state1135.state_over(root / "state")
        judge = _judge({"b": reply})
        _grade(root, ep, judge, state=state)
        assert _row(ep, "b").get("bucket") == bucket, (
            f"the model answered {bucket!r} and the record holds "
            f"{_row(ep, 'b').get('bucket')!r} — a bucket that did not come from the reply")
        if bucket == "none":
            assert all(r.get("type") != "none" for r in _queue(state)), (
                "`none` was enqueued as a finding type (M19=A: recorded, never enqueued)")
        else:
            assert [r["type"] for r in _from_world(_queue(state), "b")] == [bucket], (
                f"the {bucket!r} finding did not reach the defender queue as written")


def test_1224_world_whose_facts_sit_only_on_unserved_systems_is_never_lead_set(tmp_path):
    """d12c_couldnt_look_is_never_lead_set — a world whose facts touch only systems outside the
    manifest's served_systems is never recorded lead-set, even when the model says lead-set.

    M20=A: the host refusal lives in `validate_reply` — it refuses `lead-set` when the reply's
    systems share nothing with served_systems, and it never computes a bucket, so the refused
    world carries NO bucket rather than a substituted one. The world is still admitted to the
    judge (the model is called for it).

    Positive control: world b, whose reply names a served system, is recorded lead-set.
    """
    doc = S.family_v2(served_systems=("edr", "idp"), worlds=[
        S.control_world("a"),
        S.world_v2("b", facts=[S.fact("f1")]),
        S.world_v2("c", facts=[S.fact("f2", "the badge reader logged carol at door 7",
                                      ("carol", "door-7"))]),
    ])
    ep = S.judged_episode(tmp_path, doc=doc)
    judge = _judge({
        "b": _world_reply("lead-set", ("idp",), findings=[_finding("b-lead", bucket="lead-set")]),
        "c": _world_reply("lead-set", ("badge",), findings=[_finding("c-lead", bucket="lead-set")]),
    })
    _grade(tmp_path, ep, judge)

    assert _row(ep, "b").get("bucket") == "lead-set", "the positive control: b was not lead-set"
    assert S.judge_called_for(judge, "c"), "a couldn't-look world was not admitted to the judge (M20=A)"
    assert _row(ep, "c").get("bucket") != "lead-set", (
        "a world whose facts sit only on unserved systems was recorded lead-set (O11)")
    assert _row(ep, "c").get("bucket") is None, (
        f"the refusal substituted a bucket ({_row(ep, 'c').get('bucket')!r}); the host refuses, "
        "it never computes one (M20=A)")
    assert not [r for r in _from_world(_queue(), "c") if r.get("type") == "lead-set"], (
        "a couldn't-look world's lead-set finding was enqueued")


def test_1224_judge_model_gets_facts_verdict_calls_claims_movement_and_served_systems(
        tmp_path):
    """d12d_judge_input — the judge model's world prompt carries the world's facts and declared
    verdict, the sibling's calls, the verified claims, the sibling's verdict and conclusion
    movement, and served_systems.

    M26: every non-host-authored text among them (the fact statement, the call's params, the
    claim) arrives inside an untrusted frame and nowhere outside one.
    """
    doc = S.family_v2(served_systems=("edr", "idp", "siem-x", "recorded-sys-d12d"), worlds=[
        S.control_world("a"),
        S.world_v2("b", disposition_declared="malicious", facts=[S.fact(
            "f1", "MARKERFACT alice obtained a TGT and logged on to db-1", ("alice", "db-1"))]),
        S.world_v2("c", disposition_declared="benign",
                   facts=[S.fact("f2", "bob reset carol's password", ("bob", "carol"))]),
    ])
    claim = S.claim(changed=[S.changed("alice", "MARKERCLAIMFIELD", "absent", "present")])
    ledger = [_oracle_row("user:MARKERCALL", claim=claim,
                          verdict={"passed": True, "reason": "fact f1's logon is present"})]
    ep = S.judged_episode(tmp_path, doc=doc, ledgers={"b": ledger})
    _sibling_says(ep, "b", "inconclusive")
    judge = _judge({"b": _world_reply()})
    _grade(tmp_path, ep, judge)

    prompt = _prompt_for(judge, "b")
    S.assert_wrapped_untrusted(prompt, "MARKERFACT", "the world's fact statement")
    S.assert_wrapped_untrusted(prompt, "user:MARKERCALL", "the sibling's call")
    S.assert_wrapped_untrusted(prompt, "MARKERCLAIMFIELD", "the verified claim")
    assert "recorded-sys-d12d" in prompt, "the manifest's served_systems never reached the judge"
    assert "malicious" in prompt, "the world's declared verdict never reached the judge"
    assert "inconclusive" in prompt, "the sibling's own verdict never reached the judge"
    assert "revisited after the branch" in prompt, (
        "the sibling's conclusion movement (its resolutions) never reached the judge")




def test_1224_world_whose_change_never_reached_the_investigator_is_judged_not_withheld(
        tmp_path):
    """d12f_unreached_change_is_judged — a world whose every sibling call was passthrough is
    sent to the judge model, can yield findings, and carries no withheld reason.

    Design non-obligation "No mechanical bucket": such a world is a finding, not withheld.
    """
    ledger = [S.ledger_row(S.PASSTHROUGH, params=S.query_params(f"user:p{i}")) for i in range(4)]
    ep = S.judged_episode(tmp_path, ledgers={"b": ledger})
    judge = _judge({"b": _world_reply("lead-set", ("idp",),
                                      findings=[_finding("never-queried", bucket="lead-set")])})
    _grade(tmp_path, ep, judge)

    assert S.judge_called_for(judge, "b"), "a world whose change never reached the investigator was not judged"
    row = _row(ep, "b")
    assert row.get("bucket") == "lead-set"
    assert "never-queried" in _topics(_filed(ep, "b"))
    assert row.get("withheld_reason") is None, f"the world was withheld: {row!r}"
    assert not _record(ep).get("withheld_findings"), "a finding of the world was withheld"
    assert [r["subject_topic"] for r in _from_world(_queue(), "b")] == ["never-queried"], (
        "the unreached world's finding did not reach the defender queue")


def test_1224_preflight_drift_reaches_the_judge_model(tmp_path):
    """d12g_drift_reaches_the_judge — the drift calls pre-flight recorded appear in the judge
    model's prompt.

    Whether drift spoils the family is the model's call (design "No mechanical control-drift
    discard"). The call's params are the source run's own, so they arrive framed (M26).
    """
    ep = S.judged_episode(tmp_path, outcome=None)
    S.outcome_record(ep, "accepted", drift=[
        {**_call("user:MARKERDRIFT"), "status": "drifted"}])
    judge = _judge({"b": _world_reply()})
    _grade(tmp_path, ep, judge)

    carrying = [p for p in judge.prompts if "MARKERDRIFT" in p]
    assert judge.prompts, "the positive control: the judge model was never called"
    assert carrying, "pre-flight's drift calls never reached the judge model"
    for prompt in carrying:
        S.assert_wrapped_untrusted(prompt, "MARKERDRIFT", "a drift call")


def test_1224_drift_on_the_discriminating_call_discards_nothing_mechanically(tmp_path):
    """d12h_no_mechanical_drift_discard — a family whose recorded drift includes the call the
    discriminator describes is not discarded by any code path; its outcome is the model's.

    The mechanical discard keyed on `discriminator.envelope` is gone (design, confirmed by the
    human); drift is the model's to weigh.

    Two episodes, the same drift on the discriminating call: the model filing nothing against
    the world keeps the findings; the model filing an `incoherent` world finding for each
    world (the positive control — #1234's channel for validity: the world is then not measured,
    A7) keeps their defender findings off the queue.
    """
    def episode(root: Path) -> Path:
        doc = S.family_v2(predicate="did the analyst query idp for user:MARKERDISC after the "
                                    "branch")
        ep = S.judged_episode(root, doc=doc, outcome=None)
        S.outcome_record(ep, "accepted", drift=[
            {**_call("user:MARKERDISC"), "status": "drifted"}])
        return ep

    kept_root = tmp_path / "gradable"
    ep = episode(kept_root)
    state = _state1135.state_over(kept_root / "state")
    _grade(kept_root, ep, _judge({"b": _world_reply(findings=[_finding("kept")])}), state=state)
    rec = _record(ep)
    for key in ("episode_outcome", "verdict_word"):
        assert key not in rec, f"the record carries the retired {key!r}: {rec!r}"
    assert _row(ep, "b").get("measured") is True, (
        f"drift on the discriminating call took the world out of measurement mechanically: "
        f"{_row(ep, 'b')!r}")
    assert "kept" in {r["subject_topic"] for r in _queue(state)}, (
        "the findings of a family the model called gradable were not enqueued")

    dropped_root = tmp_path / "discard"
    ep = episode(dropped_root)
    state = _state1135.state_over(dropped_root / "state")
    incoherent = _finding("drift spoils the world", subject="world", bucket="incoherent")
    _grade(dropped_root, ep, _judge(
        {"b": _world_reply(findings=[_finding("dropped"), incoherent]),
         "c": _world_reply(findings=[incoherent])}), state=state)
    assert _row(ep, "b").get("measured") is False, (
        f"the positive control: the model's incoherent finding was not honoured: "
        f"{_row(ep, 'b')!r}")
    assert _queue(state) == [], "a world the model found incoherent enqueued defender findings"








# --------------------------------------------------------------------------------------
# O13 / M05 — the gate
# --------------------------------------------------------------------------------------


def _gate_case(root: Path, word: str | None, *, raw: str | None = None) -> tuple[Path, Any]:
    """An archived v2 episode whose outcome record says `word` (None: no record; `raw`: these
    exact bytes), graded once."""
    ep = S.judged_episode(root, outcome=None)
    if raw is not None:
        (ep / S.OUTCOME_NAME).write_text(raw, encoding="utf-8")
    elif word is not None:
        S.outcome_record(ep, word, reason=f"MARKER-REASON-{word}")
    judge = _judge({"b": _world_reply(findings=[_finding("gate-finding")])})
    _grade(root, ep, judge, state=_state1135.state_over(root / "state"))
    return ep, judge


def _torn_outcome_text(scratch: Path) -> str:
    """A REAL outcome record torn mid-write (fault rung 1): the record written whole in the
    coined shape by the suite's writer (`S.outcome_record`), then cut inside its quoted reason —
    the bytes a crash mid-write leaves. Keys are written sorted, so the cut lands after
    `outcome: accepted`: the torn bytes still carry the word, and they do not parse."""
    import yaml

    scratch.mkdir(parents=True, exist_ok=True)
    reason = "MARKER-TORN: pre-flight calibrated every world"   # the `: ` forces a quoted scalar
    whole = S.outcome_record(scratch, "accepted", reason=reason).read_text(encoding="utf-8")
    torn = whole[:whole.index("MARKER-TORN") + len("MARKER-TORN: pre")]
    assert "outcome: accepted" in torn, f"fixture: the cut fell before the word: {torn!r}"
    try:
        _yaml.safe_load(torn)
    except yaml.YAMLError:
        return torn
    raise AssertionError(f"fixture: the torn record still parses: {torn!r}")


def test_1224_judge_grades_only_an_accepted_outcome(tmp_path):
    """d14h_judge_gated_on_accepted — the judge grades only an exactly-`accepted` outcome;
    unusable, refused and an absent or torn record are stamped not-graded with no model call.
    pco02_judge_gate_new_words — the gate stamps `unusable` and `refused` not-graded with
    their word and reason, and an absent, empty or torn outcome record not-graded with one
    distinct 'no record' word, all with no model call.

    RE-PINNED (48: S9; M05=A). M05=A (R-05): an absent or torn record is a distinct "no record"
    state, so the word stamped for an absent, an empty and a torn record is in NONE of
    {`accepted`, `unusable`, `refused`, `incomplete`} — never read as accepted, never conflated
    with a judged-bad family, never the retired word — and the three share that one word: 70's
    M05 reading makes them ONE state that "every reader reports as missing", and the gate is one
    of those readers (PCO-02's absent-record default). The torn record is a REAL torn write
    (rung 1): pre-flight's record shape written whole by the suite's writer, then cut inside its
    quoted reason, after `outcome: accepted` — the bytes still carry the word and are no record.
    Positive control: an exactly `accepted` record is graded and carries no stamp.
    """
    for word in ("unusable", "refused"):
        root = tmp_path / word
        ep, judge = _gate_case(root, word)
        stamp = _record(ep).get("not_graded") or {}
        assert (stamp.get("outcome"), stamp.get("reason")) == (word, f"MARKER-REASON-{word}"), (
            f"{word}: the stamp reads {stamp!r}")
        assert judge.calls == 0, f"{word}: the gate let a model call through"
        assert _all_queued(_state1135.state_over(root / "state")) == []

    no_record: dict[str, str] = {}
    for case, raw in (("absent", None), ("empty", ""),
                      ("torn", _torn_outcome_text(tmp_path / "torn-source"))):
        ep, judge = _gate_case(tmp_path / case, None, raw=raw)
        stamp = _record(ep).get("not_graded") or {}
        word = stamp.get("outcome")
        assert isinstance(word, str), f"{case}: the stamp names no word: {stamp!r}"
        assert word, f"{case}: the stamp names an empty word: {stamp!r}"
        assert word not in (*S.OUTCOMES, S.RETIRED_OUTCOME), (
            f"{case}: a missing outcome record was stamped {word!r} — a word of the record's own "
            f"vocabulary or the retired one, not the distinct 'no record' state (M05=A)")
        assert S.OUTCOME_NAME in str(stamp.get("reason")), (
            f"{case}: the reason does not say the outcome record is missing: {stamp!r}")
        assert judge.calls == 0, f"{case}: the gate let a model call through"
        no_record[case] = word
    assert len(set(no_record.values())) == 1, (
        f"absent, empty and torn records are one 'no record' state (M05=A) but were stamped "
        f"{no_record}")

    ep, judge = _gate_case(tmp_path / "accepted", "accepted")
    assert S.judge_called_for(judge, "b"), "the positive control: an accepted episode was not graded"
    assert "not_graded" not in _record(ep), "the positive control: an accepted episode was stamped"


def test_1224_judge_citation_check_matches_samples_by_system(tmp_path):
    """d16c_citation_check_by_system — pointer assessment accepts a finding citing the samples
    section of a served system with a section, and refuses one citing a system's section the
    record marks unavailable.
    s_p242 — only a served system's own samples section passes the citation check; an
    unavailable section, a case or lookalike spelling, an old pattern key and a dot-dot path all
    fail it.

    O16: the samples record is keyed by system (`samples.yaml#<system>`). Driven through the
    whole pass, which is where the check gates the queue. The reply names siem-x among its
    systems, so its section fails for being unavailable, not for being unnamed.

    #1234 A13: what the check decides is each finding's ledger lane. A finding whose only
    pointer is a samples citation cites no manifest entry, so a passing one is a serving
    finding (`user_record`); a failing one is `unqueueable` (or `dropped_unresolved` where the
    pointer resolves nowhere) — never queued, never kept.
    """
    ep = S.judged_episode(tmp_path)
    S.samples_record(ep, {
        "edr": {"verbs": {"query": ['{"events": [{"host": "db-1"}]}']}},
        "idp": {"verbs": {"query": ['{"rows": [{"user": "alice"}]}']}},
        "siem-x": {"unavailable": "the capture made no siem-x call"}})
    pointers = {
        "own-section": "samples.yaml#edr",
        "own-dot": "./samples.yaml#edr",
        "own-redundant": "unused/../samples.yaml#edr",
        "unavailable": "samples.yaml#siem-x",
        "unavailable-dot": "./samples.yaml#siem-x",
        "unavailable-redundant": "unused/../samples.yaml#siem-x",
        "missing-dot": "./samples.yaml#missing",
        "case": "samples.yaml#EDR",
        "lookalike": "samples.yaml#edr_",
        "old-pattern": "samples.yaml#logs-*",
        "dot-dot": "samples.yaml#../edr",
        "dot-dot-path": "../samples.yaml#edr",
    }
    reply = _world_reply("lead-quality", ("edr", "siem-x"), findings=[
        _finding(topic, subject="world", bucket="mislabelled", evidence=[pointer])
        for topic, pointer in pointers.items()])
    _grade(tmp_path, ep, _judge({"b": reply}))

    lanes = _lanes(ep, "b")
    assert set(lanes) == set(pointers), f"the ledger does not file every finding: {lanes!r}"
    passed = {topic for topic, lane in lanes.items()
              if lane not in ("unqueueable", "dropped_unresolved")}
    assert passed == {"own-section", "own-dot", "own-redundant"}, (
        f"the citation check passed {sorted(passed)}; only a served system's own section may "
        f"(lanes {lanes!r})")
    assert lanes["own-section"] == "user_record", lanes
    assert not _queue(channel=QUESTIONER_FINDINGS), "a samples-only finding reached the questioner"

    # A resolving plan must not rescue a prohibited sample citation, even when the
    # sample section itself cannot resolve. Equivalent paths have the same fate.
    reply = _world_reply("lead-quality", ("edr", "siem-x"), findings=[
        _finding(topic, subject="world", bucket="mislabelled",
                 evidence=["family.yaml#worlds/b", pointer])
        for topic, pointer in pointers.items()
        if topic.startswith(("own-", "unavailable", "missing-", "old-pattern"))])
    ep = S.judged_episode(tmp_path / "with-plan")
    S.samples_record(ep, {
        "edr": {"verbs": {"query": ['{"events": []}']}},
        "siem-x": {"unavailable": "no captured call"}})
    _grade(tmp_path / "with-plan", ep, _judge({"b": reply}))
    lanes = _lanes(ep, "b")
    assert len(lanes) == 8, lanes
    assert all(lane == ("world" if topic.startswith("own-") else "unqueueable")
               for topic, lane in lanes.items()), lanes




# --------------------------------------------------------------------------------------
# Premises — couldn't-look (M20=A)
# --------------------------------------------------------------------------------------






def test_p078_judge_reply_lead_set_for_a_world_whose_facts_are_only_partly_servable(tmp_path):
    """b_p012 — lead-set stands for a world whose reply touches at least one served system, and
    is refused for one whose reply touches none.

    M20=A: `validate_reply` refuses `lead-set` only when the reply's systems share NOTHING with
    served_systems; it never computes a bucket.
    """
    doc = S.family_v2(served_systems=("edr", "idp"), worlds=[
        S.control_world("a"),
        S.world_v2("b", facts=[S.fact("f1")]),
        S.world_v2("c", facts=[S.fact("f2", "carol badged in at door 7", ("carol",))]),
        S.world_v2("d", facts=[S.fact("f3", "dave's token was replayed", ("dave",))]),
    ])
    ep = S.judged_episode(tmp_path, doc=doc, labels=("a", "b", "c", "d"))
    lead = [_finding("lead", bucket="lead-set")]
    judge = _judge({"b": _world_reply("lead-set", ("idp", "badge"), findings=lead),
                    "c": _world_reply("lead-set", (), findings=lead),
                    "d": _world_reply("lead-set", ("badge",), findings=lead)})
    _grade(tmp_path, ep, judge)

    assert _row(ep, "b").get("bucket") == "lead-set", (
        "a world whose reply touches one served system was refused lead-set")
    for label in ("c", "d"):
        assert S.judge_called_for(judge, label), f"world {label} was not admitted to the judge"
        assert _row(ep, label).get("bucket") != "lead-set", (
            f"world {label}, whose reply touches no served system, was recorded lead-set")
        assert _row(ep, label).get("bucket") is None, (
            f"world {label}: a bucket was substituted for the refused lead-set")


def test_served_system_grants_only_health_checks(tmp_path, monkeypatch):
    """b_p042 — a granted system readable only through a health check is not served: the
    launcher leaves it out of served_systems, the judge never records lead-set for a world
    whose facts sit only there, and no query uses a verb the grant lacks.

    M20=A: a served system is one with at least one non-health-check read verb in the grant.
    Settled regardless: the oracle never forges telemetry the investigator can read nowhere and
    no query uses a verb the grant lacks.
    """
    monkeypatch.setenv(S.KNOB_RETRY_CAP, "1")
    est = S.estate(tmp_path / "estate-root", withheld=(("siem-x", "query"), ("siem-x", "lookup")))
    authored = S.family_v2()
    authored.pop("served_systems")
    launch = S.launch(tmp_path / "launch", est, questioner=S.questioner_for(authored),
                      oracle=S.oracle(then=S.text_only()), verifier=S.passing_verifier(),
                      spawn=S.FakeSpawn(), judge=_judge())
    recorded = _yaml.safe_load((launch.ep / "family.yaml").read_text(encoding="utf-8"))
    assert sorted(recorded.get("served_systems") or []) == est.served_systems() == ["edr", "idp"], (
        f"the launcher recorded {recorded.get('served_systems')!r}; a health-check-only system "
        "is not served (M20=A)")

    graded = S.judged_episode(tmp_path / "judged", doc=S.family_v2(served_systems=("edr", "idp")))
    judge = _judge({"b": _world_reply("lead-set", ("idp",),
                                      findings=[_finding("b", bucket="lead-set")]),
                    "c": _world_reply("lead-set", ("siem-x",),
                                      findings=[_finding("c", bucket="lead-set")])})
    _grade(tmp_path / "judged", graded, judge)
    assert _row(graded, "b").get("bucket") == "lead-set", "the positive control: b was refused"
    assert _row(graded, "c").get("bucket") != "lead-set", (
        "a world whose facts sit only on a health-check-only system was recorded lead-set")

    payload = {"rows": [{"user": "alice", "event_id": "e-100", "action": "logon"}]}
    ep = S.episode_v2(tmp_path / "serving", base_rows=[
        S.captured("idp", "query", S.query_params("user:alice"), payload)])
    est.answer("idp", "query", S.query_params("user:alice"), payload)
    oracle = S.oracle(S.run_query("siem-x", "query", S.query_params("user:alice")),
                      S.submit(payload, S.EMPTY_CLAIM), then=S.text_only())
    reg = S.world_registry(ep, "b", est, oracle=oracle, verifier=S.passing_verifier(),
                           retry_cap=1)
    try:
        S.call(reg, "idp", "query", est.ctx(tmp_path / "run"), q="user:alice")
    except S.unservable_cls():
        pass  # whether this attempt is served is not this premise's question
    assert est.calls("idp", "query"), "the positive control: the served system was never read"
    assert est.calls("siem-x", "query") == [], (
        "the oracle's run_query used a verb the gather grant lacks on a health-check-only system")


def test_1224_couldnt_look_because_the_only_served_system_was_down(tmp_path):
    """b_p248 — a world whose facts sit only on a served system that was down for the whole
    sibling run is NOT couldn't-look: the outage reaches the judge as telemetry and lead-set
    may stand.

    M20=A: an outage of a served system is telemetry, not couldn't-look, so the host does not
    refuse the model's lead-set for it; the outage itself reaches the judge model.
    """
    ledger = [S.ledger_row(S.REAL_ERROR, params=S.query_params(f"user:alice-{i}"),
                           payload={"error": f"MARKER-OUTAGE 503 from idp ({i})"})
              for i in range(3)]
    ep = S.judged_episode(tmp_path, ledgers={"b": ledger})
    judge = _judge({"b": _world_reply("lead-set", ("idp",),
                                      findings=[_finding("down", bucket="lead-set")])})
    _grade(tmp_path, ep, judge)

    prompt = _prompt_for(judge, "b")
    assert "MARKER-OUTAGE" in prompt, "the served system's outage never reached the judge"
    assert S.REAL_ERROR in prompt, "the outage did not reach the judge as `real-error` rows"
    assert _row(ep, "b").get("bucket") == "lead-set", (
        "an outage of a served system was treated as couldn't-look and lead-set refused")


# --------------------------------------------------------------------------------------
# Premises — old and unreadable manifests (O15, F-11)
# --------------------------------------------------------------------------------------






# --------------------------------------------------------------------------------------
# Premises — unservable worlds at the judge (O5, S9, S10, N22 / FU22)
# --------------------------------------------------------------------------------------


def test_judge_reads_a_family_whose_unservable_sibling_left_a_partial_ledger(tmp_path):
    """s_p199 — an unservable sibling's partial records stay readable, contribute no findings,
    and the judge and page show the world as unservable while the rest is graded.

    O5. N22: the unservable world appears to the judge as an explicit entry built from its own
    record — its label, reason and the call it failed on. #1234: never the record's `detail`
    (the oracle's last refusal can quote the rows it forged for that world's facts, and this
    entry reaches every judged world's prompt; `render.render_family_text`).
    """
    partial = [S.ledger_row(S.PASSTHROUGH, params=S.query_params("user:MARKER-PARTIAL"), label="c")]
    ep = S.judged_episode(tmp_path, ledgers={"c": partial})
    S.world_record(ep, "c", S.REASON_UNSERVABLE, call=_call("user:carol"),
                   detail="MARKER-C-DETAIL attempts exhausted on check 4")
    archived = S.ledger_path(ep, "c").read_bytes()
    judge = _judge({"b": _world_reply(findings=[_finding("b-rest")]),
                    "c": _world_reply("lead-set", ("idp",), findings=[_finding("c-partial")])})
    _grade(tmp_path, ep, judge)

    assert _row(ep, "b").get("bucket") == "lead-quality", "the rest of the family was not graded"
    for key in ("findings", "bucket"):
        assert not _row(ep, "c").get(key), (
            f"the unservable world contributed {key} from its partial records")
    assert not _filed(ep, "c"), "the unservable world has draw documents filing findings"
    assert not _from_world(_all_queued(), "c"), "a finding of the unservable world was enqueued"
    assert any("user:carol" in p and S.REASON_UNSERVABLE in p for p in judge.prompts), (
        "the judge was not shown the unservable world as an explicit entry from its own record")
    assert not any("MARKER-C-DETAIL" in p for p in judge.prompts), (
        "the failed world's detail (which can quote its forged rows) reached a judge prompt")

    assert S.ledger_path(ep, "c").read_bytes() == archived, (
        "grading disturbed the partial world's archived ledger")
    assert [{k: v for k, v in r.items() if k != J.CALL_ID} for r in S.ledger_rows(ep, "c")] == (
        partial), "the partial world's archived ledger is not the rows it was built from"
    html, refusal = _page(ep)
    assert refusal is None, f"the page refused a family with one unservable world: {refusal}"
    assert S.REASON_UNSERVABLE in str(html), "the page does not show world c as unservable"


def test_input_judge_gives_an_unservable_world_a_bucket(tmp_path):
    """s_p243 — a bucket and findings the judge model gives a world recorded unservable are not
    recorded as findings, and an unusable family carries none at all.

    O5. The model is never asked about such a world, so its "answer" is planted where an answer
    lives: a draw document under the world's own judge directory, beside a scripted reply.
    """
    def plant(ep: Path, label: str) -> None:
        draws = ep / "worlds" / label / "judge"
        draws.mkdir(parents=True, exist_ok=True)
        (draws / "0.yaml").write_text(_text(_world_reply(
            "lead-set", ("idp",), findings=[_finding(f"{label}-planted", bucket="lead-set")])),
            encoding="utf-8")

    one = tmp_path / "one"
    ep = S.judged_episode(one, outcome=None)
    S.outcome_record(ep, "accepted", unservable=[
        {"world": "c", "reason": S.REASON_UNSERVABLE, "call": _call("user:carol")}])
    plant(ep, "c")
    state = _state1135.state_over(one / "state")
    judge = _judge({"b": _world_reply(findings=[_finding("b-graded")]),
                    "c": _world_reply("lead-set", ("idp",), findings=[_finding("c-said")])})
    _grade(one, ep, judge, state=state)
    assert _row(ep, "b").get("bucket") == "lead-quality", "the positive control: b was not graded"
    for key in ("bucket", "findings"):
        assert not _row(ep, "c").get(key), (
            f"the unservable world was recorded with {key}: {_row(ep, 'c')!r}")
    assert not _from_world(_all_queued(state), "c"), "a finding of the unservable world was enqueued"

    two = tmp_path / "two"
    ep = S.judged_episode(two, outcome=None)
    S.outcome_record(ep, "accepted", unservable=[
        {"world": "c", "reason": S.REASON_UNSERVABLE, "call": _call("user:carol")}])
    S.world_record(ep, "b", S.REASON_UNSERVABLE, call=_call("user:alice"))
    plant(ep, "b")
    plant(ep, "c")
    state = _state1135.state_over(two / "state")
    _grade(two, ep, _judge({"b": _world_reply(), "c": _world_reply()}), state=state)
    assert _record(ep).get("validity") == "unusable"
    assert all(not r.get("findings") and not r.get("bucket") for r in _rows(ep).values()), (
        "an unusable family carries findings")
    assert _all_queued(state) == [], "an unusable family enqueued findings"


def test_1224_original_call_unservable_in_preflight_and_the_worlds_ledger(tmp_path, monkeypatch):
    """b_fu22 — pre-flight exhausts the oracle on an original call for world b: b's ledger stays
    empty, the base recording is the original run's alone, b is never graded, and with one
    unservable world the family is accepted and graded on the rest.

    Pre-flight queries never land in a sibling's ledger (O9); the family's base recording is
    unchanged by pre-flight's replay or by the failure (O9; FA-11). World b is not graded and
    not bucketed, as a miss or otherwise (O5, O11). N22: b appears in the judge's input as an
    explicit entry with no calls, built from pre-flight's result.

    The launcher half runs a two-world family (the control and b), so the oracle double that
    never submits fails exactly world b; the judge half grades the archived three-world shape
    of the same outcome.
    """
    monkeypatch.setenv(S.KNOB_RETRY_CAP, "1")
    site = tmp_path / "launch"
    est = S.estate(site)
    calls = S.default_calls()
    two_worlds = S.family_v2(worlds=[S.control_world("a"), S.world_v2("b", facts=[S.fact("f1")])])
    spawn = S.FakeSpawn()
    launch = S.launch(site, est, calls=calls, questioner=S.questioner_for(two_worlds),
                      oracle=S.oracle(then=S.text_only()), verifier=S.passing_verifier(),
                      spawn=spawn, judge=_judge())
    outcome = S.read_outcome(launch.ep) or {}
    assert outcome.get("outcome") == "accepted", f"one unservable world: the outcome is {outcome!r}"
    assert [u.get("world") for u in outcome.get("unservable_worlds") or []] == ["b"]
    assert "b" not in spawn.worlds, f"world b's sibling started: {spawn.worlds}"
    assert "a" in spawn.worlds, f"the other world's sibling never started: {spawn.worlds}"
    assert S.ledger_rows(launch.ep, "b") == [], "pre-flight's queries landed in world b's ledger"
    base = S.base_rows(launch.ep)
    assert len(base) == len(calls), f"the base recording is not the original run's alone: {base!r}"
    assert all(r.get("world_id") is None for r in base), f"a world row reached the base: {base!r}"
    assert {(r["system"], r["verb"], S.canonical(r["params"])) for r in base} == {
        (c.system, c.verb, S.canonical(c.params)) for c in calls}

    root = tmp_path / "judged"
    ep = S.judged_episode(root, labels=("a", "c"), outcome=None)
    S.outcome_record(ep, "accepted", unservable=[
        {"world": "b", "reason": S.REASON_UNSERVABLE, "call": _call("user:MARKER-FU22")}])
    # #1234 A5: the discipline buckets are unavailable to a world never shown its facts.
    judge = _judge({"c": _world_reply("lead-quality", ("edr",))})
    _grade(root, ep, judge)
    assert not S.judge_called_for(judge, "b"), "the unservable world was graded"
    assert not _row(ep, "b").get("bucket"), "the unservable world was bucketed"
    assert _row(ep, "c").get("bucket") == "lead-quality", "the rest of the family was not graded"
    assert _record(ep).get("validity") == "usable", "one unservable world made the family unusable"
    assert any("MARKER-FU22" in p for p in judge.prompts), (
        "world b is not an explicit entry in the judge's input, built from pre-flight's result")


# --------------------------------------------------------------------------------------
# Premises — reply handling (N22, M19)
# --------------------------------------------------------------------------------------


def test_judge_input_has_a_served_call_with_no_verified_claim(tmp_path):
    """b_p200 — an `oracle` row whose claim or verifier verdict was never stored reaches the
    judge as that call with "claim unavailable", never as a verified claim.

    Scenario: a sibling's ledger has an `oracle` row whose claim or verifier verdict was never
    stored (the sibling died, or the write failed). N22 reading: "claim unavailable" for a call
    with no stored claim.

    The ledger holds a verified row first (its claim reaches the judge — the positive control)
    and the claimless row LAST, so the text around the claimless call's own marker is that
    call's entry: it must say the claim is unavailable.
    """
    verified = _oracle_row("user:MARKER-VERIFIED", claim=S.claim(changed=[
        S.changed("alice", "MARKER-CLAIMED", "absent", "present")]),
        verdict={"passed": True, "reason": "fact f1's logon is present"})
    claimless = _oracle_row("user:MARKER-NOCLAIM")
    ep = S.judged_episode(tmp_path, ledgers={"b": [verified, claimless]})
    judge = _judge({"b": _world_reply()})
    _grade(tmp_path, ep, judge)

    prompt = _prompt_for(judge, "b")
    assert "MARKER-CLAIMED" in prompt, "the positive control: a verified claim never reached the judge"
    at = prompt.find("MARKER-NOCLAIM")
    assert at != -1, "the claimless call was omitted from the judge's input"
    entry = prompt[max(at - 400, 0):at + 600].lower()
    assert "claim unavailable" in entry, (
        "the judge was not told the claimless call has no stored claim: " + entry[:200])


def test_judge_model_call_fails_for_one_world_but_not_the_rest(tmp_path):
    """b_p237 — a judge call that fails for one world's draw leaves that world ungraded, the
    others graded and enqueued, and a bare re-run grades only the missing world.

    The failure is #921's P9 shape (executed): a transport failure and a timeout both arrive as
    `RunUnprocessable`.
    """
    # #1234 A5: the discipline buckets are unavailable to a world never shown its facts.
    reply_b = _world_reply("lead-set", ("idp",), findings=[_finding("b-later", bucket="lead-set")])
    reply_c = _world_reply("lead-quality", ("edr",), findings=[_finding("c-now")])
    ep = S.judged_episode(tmp_path)
    first = _judge({"b": reply_b, "c": reply_c}, fault=S.Fault(fail_on=("judge:b:",)))
    _grade(tmp_path, ep, first)

    assert not _row(ep, "b").get("bucket"), (
        f"a bucket was recorded for the world whose judge call failed: {_row(ep, 'b')!r}")
    assert not _row(ep, "b").get("findings")
    assert _row(ep, "c").get("bucket") == "lead-quality", "the healthy world was not graded"
    assert _from_world(_queue(), "c"), "the graded world's findings were not enqueued"
    assert not _from_world(_queue(), "b"), "the failed world has queued findings"

    second = _judge({"b": reply_b, "c": reply_c})
    _grade(tmp_path, ep, second)
    world_calls = {S.judge_label(a) for a in second.agent_ids if S.judge_label(a) != "family"}
    assert world_calls == {"b"}, f"a bare re-run regraded {sorted(world_calls)}, not only b"
    assert _row(ep, "b").get("bucket") == "lead-set", "the re-run did not grade b"
    assert _row(ep, "c").get("bucket") == "lead-quality", "the re-run disturbed c's grade"


def test_judge_reply_gives_a_bucket_outside_the_five(tmp_path):
    """b_p238 — a bucket outside the set (a lookalike, a padded or capitalised spelling, null,
    two buckets, a new word) is refused, never recorded or enqueued as written and never
    coerced. #1234 (P-a, A4): `observability` left the bucket set — a gap is a deployment
    gap, never a teachable defender bucket — so it is refused like any other word outside the
    set.

    M19=A: the bucket set is O11's five; `none` is an explicit member.
    """
    refused = S.judge_refused_cls()
    for bad in ("lead_set", "Lead-Set", " lead-set ", "lead-set\n", None,
                ["lead-set", "lead-quality"], "missed-lead", "", "observability"):
        with pytest.raises(refused) as refusal:
            _validate(_text(_world_reply(bad, ("idp",))))
        assert "bucket" in str(refusal.value), f"the refusal of {bad!r} does not name the field"
    admitted = _validate(_text(_world_reply("none", ())))
    assert admitted.bucket == "none", "`none` is not admitted as an explicit bucket (M19=A)"

    ep = S.judged_episode(tmp_path)
    judge = _judge({
        "b": _world_reply("lead-quality", ("idp",),
                          findings=[_finding("in-the-set", bucket="lead-quality")]),
        "c": _world_reply("Lead-Set", ("idp",), findings=[_finding("lookalike")])})
    _grade(tmp_path, ep, judge)
    assert _row(ep, "b").get("bucket") == "lead-quality", (
        "the positive control: an in-set reply was not recorded as the world's bucket")
    assert _row(ep, "c").get("bucket") not in ("Lead-Set", "lead-set"), (
        "an off-vocabulary bucket was recorded as written or coerced to its nearest member")
    assert all(r.get("type") not in ("Lead-Set",) for r in _all_queued()), (
        "an off-vocabulary bucket was enqueued")


def test_judge_reply_leaves_a_world_out(tmp_path):
    """b_p240 — no code supplies a bucket for a world the replies leave unanswered, an invalid
    reply is retried as a whole, and a world the family does not have is never recorded.

    N22 reading: a reply with missing, extra or duplicated worlds is invalid as a whole and
    retried.

    The coined reply is per world (one call per world), so the three shapes are driven as that
    shape spells them: world c's every reply is invalid (it never answers its own bucket); world
    d's first reply is invalid and its retry valid; a reply giving its world's bucket twice is
    refused whole.

    The foreign world: the only place a per-world reply can name another world is a finding's
    `world` field, which the pre-#1234 pass copied VERBATIM into the draw document and the
    family record's world findings; the #1234 draw document (`run.draw_document`) files only a
    world finding's own fields, and `judge.yaml` carries no findings list. World b's first reply carries, beside its own
    two findings, a world-lane finding whose `world` is "z" (a world the family lacks); its
    retry is the same reply without that finding. Under either reading — the reply is refused
    whole and retried (N22), or the stray field is ignored — "z" must never be recorded: no
    `world: z` anywhere in the family record (judge.yaml) or on any queue row, no row keyed
    "z", no finding id under "/z/". Positive controls: world b is graded from its reply, its own
    two findings are recorded and queued under b, and the record names its worlds through the
    same `world` keys the negative reads. Draw files are not pinned (b_p241's scope).
    """
    doc = S.family_v2(worlds=[S.control_world("a"), *[
        S.world_v2(label, facts=[S.fact(f"f-{label}")]) for label in ("b", "c", "d")]])
    ep = S.judged_episode(tmp_path, doc=doc, labels=("a", "b", "c", "d"))
    no_bucket = _world_reply()
    no_bucket.pop("bucket")
    b_own = [_finding("b-defender"),
             _finding("b-world-lane", subject="world", bucket="mislabelled")]
    names_z = _finding("names-z", subject="world", bucket="mislabelled", world="z")
    judge = _judge({
        "b": [_text(_world_reply(findings=[*b_own, names_z])),
              _text(_world_reply(findings=b_own))],
        "c": [_text(no_bucket)],
        "d": [_text(no_bucket), _text(_world_reply("lead-set", ("edr",)))]})
    _grade(tmp_path, ep, judge)

    rec, rows = _record(ep), _rows(ep)
    assert rows.get("b", {}).get("bucket") == "lead-quality", "the positive control: b ungraded"
    assert rows.get("c", {}).get("bucket") is None, (
        f"code supplied a bucket for a world no valid reply answered: {rows.get('c')!r}")
    assert rows.get("d", {}).get("bucket") == "lead-set", (
        "an invalid reply was not retried: world d's valid retry was never recorded")

    # The foreign world "z": positive controls first (the channels the negatives read are live).
    assert {"b-defender", "b-world-lane"} <= _topics(_filed(ep, "b")), (
        f"the positive control: world b's own findings were not recorded: {_filed(ep, 'b')!r}")
    queued = _all_queued()
    assert {"b-defender", "b-world-lane"} <= {
        r.get("subject_topic") for r in _from_world(queued, "b")}, (
        "the positive control: world b's own findings did not reach the queues under b")
    assert "b" in _worlds_named(rec), (
        "the positive control: the family record names no world through a `world` key")
    assert "z" not in rows, "a world the family does not have was recorded as one of its worlds"
    assert "z" not in _worlds_named(rec), (
        "the family record carries `world: z` — a world the family does not have, recorded off "
        "a finding's model-written field")
    assert "z" not in _worlds_named(queued), "a queue row names the foreign world z"
    assert not [r for r in queued if "/z/" in str(r.get("finding_id"))], (
        "a queue row's finding id files a finding under the foreign world z")

    twice = _text(_world_reply("lead-set", ("idp",))) + "bucket: lead-quality\n"
    with pytest.raises(S.judge_refused_cls()):
        _validate(twice)






def test_1224_judge_draws_disagree_on_a_worlds_bucket_or_systems(tmp_path):
    """b_p246 — when two draws give one world different buckets or systems, every draw's answer
    is recorded and no code reduces them to a bucket of its own.

    N22 reading: disagreeing draws are all recorded with the disagreement flagged. The
    disagreement flag has no coined name (hand-back red flag); what is pinned is that both
    draws' buckets and systems are recorded and the world's row names no bucket neither draw
    gave.
    """
    ep = S.judged_episode(tmp_path)
    judge = _judge({"b": [_world_reply("lead-set", ("idp",)),
                          _world_reply("lead-quality", ("edr",))]})
    _grade(tmp_path, ep, judge, draws=2)

    assert len(J.draw_files(ep, "b")) == 2, "the two draws of world b were not both recorded"
    drawn = [J.draw_doc(ep, "b", n) for n in (0, 1)]
    assert [d.get("bucket") for d in drawn] == ["lead-set", "lead-quality"], (
        f"the draws' own buckets were not recorded per draw: {[d.get('bucket') for d in drawn]}")
    assert [d.get("systems") for d in drawn] == [["idp"], ["edr"]]
    row = _row(ep, "b")
    dumped = _yaml.safe_dump(row)
    for value in ("lead-set", "lead-quality", "idp", "edr"):
        assert value in dumped, f"the family record dropped one draw's {value!r}"
    named = row.get("bucket")
    named = named if isinstance(named, list) else [named]
    assert set(named) <= {"lead-set", "lead-quality", None}, (
        f"the record names a bucket neither draw gave: {named!r}")




def test_1224_judge_prompt_over_a_world_with_hundreds_of_verified_claims(tmp_path, monkeypatch):
    """b_p249 — under the payload cap every one of a world's calls still reaches the judge model
    with its decision kind, the served-answer bytes reaching it stay within the cap knob, and
    the world's bucket is the model's.

    N22 reading; O11. An unchanged world is a finding, not a withheld case (world c's every
    call is `passthrough`).

    Rows are counted by UNIQUE per-row markers — `MARKER-ORC-nnn` in the params of each of the
    120 `oracle` calls, `MARKER-PAS-nnn` in each of the 80 `passthrough` calls — never by
    occurrences of a common word: every one of the 200 markers must be in world b's prompt (a
    call cut by the cap is a missing marker). The decision-word counts stay as a secondary floor.

    The bound is relative to the knob and to what it caps: each served answer carries a 2000-byte
    `QZ` run (400000 bytes over 200 calls), and the `QZ` bytes reaching the prompt are at most
    the knob's value. The knob is 60000 so that the 200 calls with their decision kinds (about
    250 rendered bytes each, ~50000) can fit under it however the implementation charges the
    cap, while the answers (400000) cannot. Positive control: the same episode under a cap too
    large to bind (10**7) hands the model more `QZ` bytes than 60000 — the answers do reach the
    judge (b_p245), so the bound is the cap's work and not an absent channel.
    """
    cap = 60000
    blob = "QZ" * 1000                                  # 2000 bytes per served answer

    def blob_bytes(text: str) -> int:
        return text.count("QZ") * 2

    def ledgers() -> dict[str, list[dict]]:
        bulky = {"rows": [{"user": "alice", "blob": blob}]}
        claim = S.claim(changed=[S.changed("alice", "logon", "absent", "present")])
        rows = [_oracle_row(f"user:MARKER-ORC-{i:03d}", claim=claim,
                            verdict={"passed": True, "reason": "ok"}) for i in range(120)]
        for row in rows:
            row["payload_text"] = json.dumps(bulky)
        rows += [S.ledger_row(S.PASSTHROUGH, params=S.query_params(f"user:MARKER-PAS-{i:03d}"),
                              payload=bulky) for i in range(80)]
        unchanged = [S.ledger_row(S.PASSTHROUGH, params=S.query_params(f"user:c{i}"), label="c")
                     for i in range(5)]
        return {"b": rows, "c": unchanged}

    def graded(root: Path) -> tuple[Path, Any]:
        ep = S.judged_episode(root, ledgers=ledgers())
        judge = _judge({"b": _world_reply("lead-quality", ("idp",)),
                        "c": _world_reply("lead-set", ("idp",),
                                          findings=[_finding("unchanged", bucket="lead-set")])})
        _grade(root, ep, judge, state=_state1135.state_over(root / "state"))
        return ep, judge

    monkeypatch.setenv(J.CAP_KNOB, str(cap))
    ep, judge = graded(tmp_path / "capped")
    prompt = _prompt_for(judge, "b")

    expected = ({f"MARKER-ORC-{i:03d}" for i in range(120)}
                | {f"MARKER-PAS-{i:03d}" for i in range(80)})
    seen = set(re.findall(r"MARKER-(?:ORC|PAS)-\d{3}", prompt))
    assert seen == expected, (
        f"{len(expected - seen)} of the world's 200 calls were cut from the judge's prompt by the "
        f"cap (first missing: {sorted(expected - seen)[:5]})")
    assert prompt.count(S.ORACLE_DECISION) >= 120, "a call's `oracle` decision kind was cut by the cap"
    assert prompt.count(S.PASSTHROUGH) >= 80, "a call's `passthrough` decision kind was cut by the cap"
    assert blob_bytes(prompt) <= cap, (
        f"{blob_bytes(prompt)} bytes of served answers reached the judge under a {cap}-byte "
        f"payload cap ({J.CAP_KNOB})")
    assert _row(ep, "b").get("bucket") == "lead-quality"
    assert _row(ep, "c").get("bucket") == "lead-set", "an unchanged world was not graded"
    assert _row(ep, "c").get("withheld_reason") is None, "an unchanged world was withheld"

    # Positive control: a cap that cannot bind lets more than `cap` answer bytes through.
    monkeypatch.setenv(J.CAP_KNOB, str(10**7))
    _ep, open_judge = graded(tmp_path / "uncapped")
    assert blob_bytes(_prompt_for(open_judge, "b")) > cap, (
        "the positive control: with no binding cap the served answers still never reached the "
        "judge, so the capped bound above measured an absent channel")


def test_judge_is_run_again_on_an_episode_it_already_graded(tmp_path):
    """b_p250 — a graded episode is final: a bare re-run after its outcome record or a ledger
    changed makes no model call and changes neither the record nor the queue; an old-manifest
    episode is never graded, even over a pre-oracle grade record.

    N22 reading: a graded episode is final unless re-run explicitly. Settled regardless: an
    old-manifest episode is not graded (O15).

    #1234 A6: a re-run runs the gates again before it grades anything — so a changed outcome
    record may now stamp the record not graded — but it never re-judges a world whose rows are
    `queued`: every recorded world row and ledger entry is carried verbatim, no model is
    called and no queue changes (the unchanged-archive case is
    `test_1234_bare_rerun_after_a_fully_graded_pass`).
    """
    ep = S.judged_episode(tmp_path / "graded")
    first = _judge({"b": _world_reply(findings=[_finding("once")])})
    _grade(tmp_path, ep, first)
    assert S.judge_called_for(first, "b"), "the positive control: the first pass did not grade"
    before, queued = _record(ep), _all_queued()

    S.outcome_record(ep, "unusable", reason="rewritten after grading")
    S.write_ledger(ep, "b", [S.ledger_row(S.PASSTHROUGH, params=S.query_params("user:late"))])
    second = _judge({"b": _world_reply("lead-set", ("idp",), findings=[_finding("twice")])})
    _grade(tmp_path, ep, second)
    assert second.calls == 0, "a bare re-run regraded a graded episode"
    after = _record(ep)
    assert after.get("worlds") == before.get("worlds"), "a re-run changed a recorded world row"
    assert after.get("dispositions") == before.get("dispositions"), (
        "a re-run changed the recorded ledger")
    assert _all_queued() == queued, "a bare re-run changed the queues"

    old = S.judged_episode(tmp_path / "old", doc=S.old_manifest("overlay"), outcome=None)
    (old / "judge.yaml").write_text(_yaml.safe_dump({
        "verdict_word": "survived", "episode_outcome": "gradable",
        "worlds": [{"world": "b", "bucket": "lead-set", "withheld_reason": None,
                    "doctored_answer_served": True}]}), encoding="utf-8")
    state = _state1135.state_over(tmp_path / "old" / "state")
    third = _judge({"b": _world_reply()})
    try:
        _grade(tmp_path / "old", old, third, state=state)
    except S.judge_refused_cls():
        pass  # a named refusal is "not graded"; any other exception is a crash and propagates
    assert third.calls == 0, "an old-manifest episode bought model calls"
    assert _all_queued(state) == [], "an old-manifest episode enqueued findings"


# --------------------------------------------------------------------------------------
# Obligations — readers that survive the change (O-21, O-22, O-24, O-39, O-41, O-42, O-51)
# --------------------------------------------------------------------------------------








def test_1224_enqueue_admits_a_finding_citing_a_systems_samples_section(tmp_path):
    """o39_enqueue_samples_by_system — a design finding citing a served system's samples
    section is enqueued and one citing a section marked unavailable is not, by the per-system
    samples record.

    O-39. #1234 (A8) removed the bare re-enqueue this test once drove (`enqueue_report` reading
    the draw files and the samples record back itself): rows are built only from the replies
    the pass just drew, so the check is driven through the pass, and a re-enqueue with no
    `drawn=` rows is refused by name and appends nothing.
    """
    ep = S.judged_episode(tmp_path)
    S.samples_record(ep, {
        "edr": {"verbs": {"query": ['{"events": [{"host": "db-1"}]}']}},
        "siem-x": {"unavailable": "the capture made no siem-x call"}})
    plan = "family.yaml#worlds/b"
    reply = _world_reply("lead-quality", ("edr", "siem-x"), findings=[
        _finding("cites-edr", subject="world", bucket="mislabelled",
                 evidence=["samples.yaml#edr", plan]),
        _finding("cites-siemx", subject="world", bucket="mislabelled",
                 evidence=["samples.yaml#siem-x", plan])])
    _grade(tmp_path, ep, _judge({"b": reply}))
    topics = {r.get("subject_topic") for r in _queue(channel=QUESTIONER_FINDINGS)}
    assert "cites-edr" in topics, "a finding citing a served system's own section was not enqueued"
    assert "cites-siemx" not in topics, "a finding citing an unavailable section was enqueued"
    assert _lanes(ep, "b").get("cites-siemx") == "unqueueable", _lanes(ep, "b")

    fresh = _state1135.state_over(tmp_path / "re-enqueue")
    with pytest.raises(S.judge_refused_cls()) as refused:
        S.sym(S.JUDGE_ENQUEUE, "enqueue_report")(ep, _row(ep, "b"), state=fresh, drawn=None)
    assert "drawn" in str(refused.value), f"the refusal does not name drawn=: {refused.value}"
    assert _queue(fresh, QUESTIONER_FINDINGS) == [], "a bare re-enqueue appended rows"


def test_1224_curator_gate_authors_a_row_built_from_the_judge_models_output(tmp_path):
    """o41_gate_family_keeps_authoring (rewritten for #1234) — a defender row the pass built
    from the judge model's output passes enqueue's row validation and is admitted for authoring
    by `_gate_family`; the same row in its pre-#1234 shape (a family word on `judge_outcome`)
    is held naming the retired name, never authored or consumed.

    Was `test_1224_curator_gate_authors_a_lesson_for_the_judge_models_family_word`, which
    pinned `survived` authored and `caught`/`undecidable` consumed (M19=A, RF-6). #1234 retired
    the family word (A17): the row's own fields are its ground truth (I10).
    """
    gate = S.sym(S.LESSONS_RUN, "_gate_family")
    validate_row = S.sym(S.JUDGE_ENQUEUE, "_validate_row")
    ep = S.judged_episode(tmp_path)
    state = _state1135.state_over(tmp_path / "state")
    _grade(tmp_path, ep, _judge({"b": _world_reply(findings=[_finding("authored-row")])}),
           state=state)
    rows = _queue(state)
    assert rows, "the pass put no row on the defender queue"
    for row in rows:
        validate_row(row)
        assert gate(dict(row)) is None, f"a row the pass built was not admitted: {row!r}"
        for word in ("survived", "caught", "undecidable"):
            routed = gate({**row, "judge_outcome": word})
            assert routed is not None, (
                f"a pre-#1234 row carrying judge_outcome={word!r} was admitted for authoring")
            assert routed[0] == "held", (
                f"a pre-#1234 row carrying judge_outcome={word!r} was not held: {routed!r}")
            assert "judge_outcome" in routed[1].get("held_reason", ""), routed






# --------------------------------------------------------------------------------------
# Re-ground coherence (PCO-02, PCO-06, PCO-07, PCO-08)
# --------------------------------------------------------------------------------------




def test_1224_judge_reads_a_real_error_row_and_an_adapter_cannot_load_fault_row_as_decided(
        tmp_path):
    """pco07_fault_and_real_error_rows_read — an erroring original query is a `real-error` row
    and an adapter that cannot load is a `fault` row; the judge reads each as such and no code
    computes a bucket from either.

    PCO-07, F-02=A. Today a `fault` row on the holding system makes the world ungradable by rule
    (family.py:1051); here the world whose only row is that `fault` row is graded by the model.
    """
    real_error = S.ledger_row(S.REAL_ERROR, params=S.query_params("user:MARKER-PCO7-REALERR"),
                              payload={"error": "502 from idp"})
    fault = S.ledger_row(S.FAULT, system="edr", params=S.query_params("host:MARKER-PCO7-FAULT"),
                         payload={"error": "the edr adapter could not load"}, label="c")
    ep = S.judged_episode(tmp_path, ledgers={"b": [real_error], "c": [fault]})
    # #1234 A5: the discipline buckets are unavailable to a world never shown its facts.
    judge = _judge({"b": _world_reply("lead-quality", ("idp",)),
                    "c": _world_reply("lead-set", ("edr",))})
    _grade(tmp_path, ep, judge)

    prompt_b, prompt_c = _prompt_for(judge, "b"), _prompt_for(judge, "c")
    assert "MARKER-PCO7-REALERR" in prompt_b, "the `real-error` row did not reach the judge"
    assert S.REAL_ERROR in prompt_b, "the erroring query did not reach the judge as `real-error`"
    assert "MARKER-PCO7-FAULT" in prompt_c, "the adapter-cannot-load row did not reach the judge"
    assert S.FAULT in prompt_c, "the adapter-cannot-load row did not reach the judge as `fault`"
    assert _row(ep, "b").get("bucket") == "lead-quality"
    assert _row(ep, "c").get("bucket") == "lead-set", (
        "a code rule decided the world with a `fault` row instead of the model")


