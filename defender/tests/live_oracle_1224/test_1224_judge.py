"""#1224 — the judge under a live oracle (M9, O11, O5, O13 gate, O15, O16): the model decides.

The change removes the judge's code half (`family.grade_family`, `_grade_world`, the bucket
table, the withholding ladder, `_holding_system`, `own_h_rows`, `doctored_answer_served`) and
the mechanical control-drift discard. The judge MODEL decides each world's bucket (O11) from a
prompt carrying the world's facts, declared verdict, the sibling's calls, the verified claims,
the sibling's verdict and conclusion movement, and the manifest's recorded `served_systems`
(M21=A: the recorded list, never a tenant lookup). The host keeps exactly one refusal of its
own on the bucket (M20=A): `validate_reply` refuses `lead-set` when the reply's `systems` share
nothing with `served_systems` — it refuses, it never computes. The bucket set is O11's five plus
`observability` (M19=A); `none` is an explicit bucket, recorded and never enqueued; the family
word stays in `JUDGE_OUTCOME_ENUM` so `_gate_family` keeps authoring; O5's validity is its own
`validity: usable | unusable` field on `judge.yaml`.

The gate reads pre-flight's `outcome.yaml` (not `review.yaml`): only the exact word `accepted`
with an O5 count under two is graded (S9 counts pre-flight's failed worlds plus every world's own
record, no model call); `unusable`, `refused` and an absent or torn record ("no record", never
`incomplete`, M05=A) are stamped not-graded. An old manifest is refused with the
predates-the-oracle reason AHEAD of that gate (O15, F-11).

Drive points: `S.judged_episode(...)` builds the archived v2 episode; `grade_episode` is called
through its own seams (the judge, git-show, state and draws keywords); the model double is #921's
`FakeJudge`, routed per world by the `judge:<label>:<n>` agent id it is called with (scripting,
never policy). Every assertion reads what the double RECEIVED or what landed on disk
(`judge.yaml`, the draw files, the two queues).

RED against 96e4cdb0: the gate reads `review.yaml` (so every v2 episode is stamped not-graded
`incomplete` with no model call), `grade_family` refuses a manifest with no
`discriminator.holding_system` (GC-33), the reply carries no `bucket`/`systems`, and the
record carries no `validity`.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from defender import _yaml
from defender.learning.core.state import FINDINGS, QUESTIONER_FINDINGS
from defender.tests import _judge_921 as J
from defender.tests import _state1135
from defender.tests._state1135 import env_state
from defender.tests.live_oracle_1224 import _spec1224 as S


@pytest.fixture(autouse=True)
def _roots(tmp_path, monkeypatch):
    """The episodes root a launch resolves (`DEFENDER_EPISODES_BASE`, outside the data root),
    and the learning STATE root, so the judge's appender writes this test's own queues and never
    the checkout's `learning/_pending/`."""
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


# --------------------------------------------------------------------------------------
# Private helpers (listed as helper requests in the hand-back).
# --------------------------------------------------------------------------------------


def _label_of(agent_id: str) -> str | None:
    """`judge:<label>:<n>` -> `<label>` (the family call is `judge:family:<n>`)."""
    parts = str(agent_id).split(":")
    return parts[1] if len(parts) >= 3 and parts[0] == "judge" else None


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
        label = _label_of(agent_id)
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
    """One finding as the model writes it — #921's `finding_doc`, with no pattern or
    holding_system (the v2 reply drops both)."""
    doc = J.finding_doc(bucket=bucket, subject=subject, topic=topic,
                        evidence=evidence if evidence is not None else ["investigation.md#l-001"])
    doc.update(over)
    return doc


def _world_reply(bucket: str | Any = "lead-quality", systems: Any = ("idp",),
                 findings: list[dict] | None = None, **over: Any) -> dict:
    """A world-scope v2 reply: today's required fields (episode_outcome, the three pass
    tables, noise_floor_note, findings) PLUS the coined top-level `bucket` and `systems`."""
    doc = J.reply_doc(findings=[_finding()] if findings is None else findings)
    doc["bucket"] = bucket
    doc["systems"] = list(systems) if isinstance(systems, (list, tuple)) else systems
    doc.update(over)
    return doc


def _family_reply(verdict_word: Any = "survived", **over: Any) -> dict:
    """A family-scope v2 reply: today's required fields PLUS the coined `verdict_word`
    (a `JUDGE_OUTCOME_ENUM` member, M19=A)."""
    doc = J.reply_doc(findings=[])
    doc["verdict_word"] = verdict_word
    doc.update(over)
    return doc


def _text(doc: Any) -> str:
    return S.as_reply_text(doc)


def _judge(worlds: dict[str, Any] | None = None, *, verdict: Any = "survived",
           family_text: str | None = None, default: str | None = None,
           fault: Any = S.CLEAN) -> _JudgeByScope:
    """A by-scope judge double. Unscripted worlds answer an explicit `none` with no finding."""
    def as_text(value: Any) -> Any:
        if isinstance(value, list):
            return [as_text(v) for v in value]
        return value if isinstance(value, str) else _text(value)

    return _JudgeByScope(
        worlds={label: as_text(v) for label, v in (worlds or {}).items()},
        family=family_text if family_text is not None else _text(_family_reply(verdict)),
        default=default if default is not None else _text(
            _world_reply("none", (), findings=[])),
        fault=fault)


def _grade(tmp_path: Path, ep: Path, judge: Any, **kw: Any) -> Any:
    """`grade_episode` through its own seams: one draw, a recording `git show`, this test's
    state handle."""
    kw.setdefault("draws", 1)
    kw.setdefault("git_show", J.FakeGitShow())
    kw.setdefault("state", env_state())
    return S.sym(S.JUDGE, "grade_episode")(
        ep, judge=judge, runs_base=tmp_path / "defender-runs", **kw)


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


def _called_for(judge: Any, label: str) -> bool:
    return any(str(a).startswith(f"judge:{label}:") for a in judge.agent_ids)


def _prompt_for(judge: Any, label: str) -> str:
    """The first prompt the double was handed for world `label`."""
    for prompt, agent_id in zip(judge.prompts, judge.agent_ids, strict=True):
        if str(agent_id).startswith(f"judge:{label}:"):
            return prompt
    raise AssertionError(
        f"the judge model was never called for world {label!r} (calls: {judge.agent_ids})")


def _topics(findings: Any) -> set[str]:
    return {f.get("topic") for f in findings or [] if isinstance(f, dict)}


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


def _refused() -> type[BaseException]:
    return S.sym(S.JUDGE, "JudgeRefused")


def _page(ep: Path) -> tuple[str | None, str | None]:
    """The episode page: `(html, None)` when it renders, `(None, refusal text)` when it refuses
    by name (`JudgeRefused`). Any other exception propagates — that is a crash."""
    render = S.sym(S.VISUALIZE, "render_episode")
    refused = _refused()
    try:
        path = render(ep)
    except refused as refusal:
        return None, str(refusal)
    return Path(path).read_text(encoding="utf-8"), None


def _validate(text: str, *, scope: str = "world") -> Any:
    return S.sym(S.JUDGE_RUN, "validate_reply")(text, scope=scope)


# --------------------------------------------------------------------------------------
# M21 / O15 — what the judge reads the family from
# --------------------------------------------------------------------------------------


def test_1224_judge_takes_served_systems_from_the_manifest(tmp_path):
    """d01f_judge_reads_served_systems_not_a_tenant — the judge's prompt shows the
    served_systems recorded in family.yaml, unchanged by a later change to the tenant's grant.

    M21=A: the recorded served_systems governs the judge; no later reader resolves a tenant.
    The tenant placed under the data root now grants a system the manifest never recorded
    (`zzz-live-only`), and the manifest records one the tenant no longer has (`legacy-ids`):
    the recorded name reaches the prompt and the live-only name never does.
    """
    est = S.estate(tmp_path, systems=(*S.SYSTEMS, "zzz-live-only"))
    est.place()
    ep = S.judged_episode(tmp_path, doc=S.family_v2(served_systems=("edr", "idp", "legacy-ids")))
    judge = _judge({"b": _world_reply("lead-quality", ("idp",))})
    _grade(tmp_path, ep, judge)

    prompt = _prompt_for(judge, "b")
    assert "legacy-ids" in prompt, "the manifest's recorded served_systems never reached the judge"
    assert "zzz-live-only" not in prompt, (
        "a system only the tenant's CURRENT grant names reached the judge; the judge read a "
        "tenant instead of the recorded served_systems (M21=A)")
    assert "siem-x" not in prompt, (
        "the tenant's live system list (siem-x is granted, never recorded) reached the judge")


def test_1224_judge_refuses_an_old_manifest_naming_the_reason(tmp_path):
    """d01h_old_manifest_refused_at_judge — an old manifest (overlay, or a discriminator
    envelope) is not graded: no findings, and a not-graded record whose reason says the
    manifest predates the oracle.

    Grading an archived episode whose manifest carries an overlay records no findings and
    leaves a not-graded record whose reason says the manifest predates the oracle, rather than
    crashing or reporting a missing outcome record. O15 + F-11: the old-manifest check runs
    AHEAD of the outcome gate — the episode is a real pre-oracle one, holding the old
    `review.yaml` saying accepted and no `outcome.yaml`, so only a check made before the gate
    can name the right reason. RF-9: the judge's own raw manifest read refuses, not only the
    runtime loader.

    Positive control: a v2 manifest in the same state (old review record, no outcome record)
    is stamped with a reason that is NOT the predates-the-oracle one, so the reason is
    specific to the old field and not a blanket string.
    """
    for key in ("overlay", "discriminator.envelope"):
        root = tmp_path / key.replace(".", "-")
        ep = S.judged_episode(root, doc=S.old_manifest(key), outcome=None)
        J.review_record(ep, outcome="accepted")
        judge = _judge({"b": _world_reply()})
        _grade(root, ep, judge, state=_state1135.state_over(root / "state"))

        stamp = _record(ep).get("not_graded") or {}
        assert S.PREDATES in str(stamp.get("reason", "")), (
            f"{key}: the old manifest was not refused with the predates-the-oracle reason "
            f"(stamp {stamp!r})")
        assert S.OUTCOME_NAME not in str(stamp.get("reason", "")), (
            f"{key}: the judge reported a missing outcome record instead of the old manifest — "
            "the old-manifest check did not run ahead of the gate (F-11)")
        assert judge.calls == 0, f"{key}: an old-manifest episode bought model calls"
        assert not _draws_of(ep), f"{key}: an old-manifest episode left draw files"
        assert _all_queued(_state1135.state_over(root / "state")) == [], (
            f"{key}: an old-manifest episode enqueued findings")

    control = tmp_path / "v2"
    ep = S.judged_episode(control, outcome=None)
    J.review_record(ep, outcome="accepted")
    judge = _judge()
    _grade(control, ep, judge, state=_state1135.state_over(control / "state"))
    stamp = _record(ep).get("not_graded") or {}
    assert stamp, "the positive control: a v2 episode with no outcome record was graded"
    assert S.PREDATES not in str(stamp.get("reason", "")), (
        "a v2 manifest was refused as predating the oracle — the reason is not specific to "
        "the old field")


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
    assert "b-healthy" in _topics(rows["b"].get("findings")), (
        "the healthy world's model finding was not recorded")
    assert rec.get("validity") == "usable", (
        f"one unservable sibling made the family {rec.get('validity')!r}, not usable (O5)")
    unservable = rows.get("c", {})
    assert not unservable.get("bucket"), f"the unservable world was bucketed: {unservable!r}"
    assert not unservable.get("findings"), f"the unservable world carries findings: {unservable!r}"
    queued = _all_queued()
    assert _from_world(queued, "b"), "the healthy world's finding never reached a queue"
    assert not _from_world(queued, "c"), "a finding of the unservable world was enqueued"


def test_1224_family_with_two_unservable_siblings_is_unusable_and_yields_no_findings(
        tmp_path, monkeypatch):
    """d06b_two_unservable_unusable — two or more failed worlds make the family unusable at
    both sites, with no findings and no model call at the judge.

    RE-PINNED (48: S9; two sites). Two or more failed worlds make the family unusable at both
    sites: at pre-flight (two failed calibrations, no sibling starts) and at the judge stage,
    which counts pre-flight's failed worlds plus every world whose own record says unservable
    or did not finish, records the family unusable on the family record (validity field) and
    yields no findings, with no model call. M04=A, M19=A (validity is its own field).

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
    assert _called_for(judge1, "c"), "the positive control: a one-unservable family was not graded"
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

    For each of lead-set, lead-quality, analyze-discipline, decision-discipline and none, a judge
    model double returning that bucket for a world gets it recorded for that world, whatever
    the world's ledger decisions and the sibling's verdict were. O11, M19=A (`none` is an
    explicit bucket on the defender arm, recorded, never enqueued).

    Every episode is held fixed — world b's ledger is all `passthrough` (its change never
    reached the investigator) and its sibling concluded `benign` against a declared
    `malicious` — so only the model's reply varies, and the recorded bucket follows it.
    `validate_reply` admits each member on its own.
    """
    for bucket in ("lead-set", "lead-quality", "analyze-discipline", "decision-discipline",
                   "none"):
        root = tmp_path / bucket
        ledger = [S.ledger_row(S.PASSTHROUGH, params=S.query_params(f"user:u{i}"))
                  for i in range(3)]
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


def test_1224_no_code_path_computes_a_bucket(tmp_path):
    """d12b_no_code_bucket — the judge's code half is gone, and nothing assigns a bucket that
    did not come from the model's reply.

    grade_family, _grade_world, the bucket table, withheld_reason, _holding_system, own_h_rows
    and doctored_answer_served are gone, and no production module assigns a bucket that did not
    come from the judge model's reply. Read off the shipped tree (the judge package and its
    two readers, the episode page and the frontend serializer), which is where the code half and
    its consumers live today (GC-01, GC-02). The behavioural half is the pair, d12a.

    Positive control: the same scan finds `grade_episode`, so an empty result is not a scan
    that reads nothing.
    """
    scope = ("learning/judge/", "scripts/visualize/", "learning/frontend/")

    def hits(needle: str) -> list[str]:
        return [h for h in S.grep_shipped(needle) if h.startswith(scope)]

    assert hits("def grade_episode"), "the positive control: the scan saw no judge module"
    for needle in ("def grade_family", "def _grade_family", "def _grade_world",
                   "MECHANICAL_WORLD_BUCKET", "withheld_reason", "def _holding_system",
                   "own_h_rows", "doctored_answer_served", "_control_drift_discard"):
        found = hits(needle)
        assert not found, f"the judge's code half survives: {needle!r} at {found}"


def test_1224_world_whose_facts_sit_only_on_unserved_systems_is_never_lead_set(tmp_path):
    """d12c_couldnt_look_is_never_lead_set — a world whose facts touch only systems outside the
    manifest's served_systems is never recorded lead-set, even when the model says lead-set.

    A world whose facts touch only systems outside the manifest's served_systems is never
    recorded with bucket lead-set, even when the judge model double returns lead-set for it.
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
    assert _called_for(judge, "c"), "a couldn't-look world was not admitted to the judge (M20=A)"
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

    The judge model's world prompt carries the world's facts and declared verdict, the sibling's
    calls, the verified claims of the answers it was served, the sibling's verdict and
    conclusion movement, and the manifest's served_systems. M26: every non-host-authored text
    among them (the fact statement, the call's params, the claim) arrives inside an untrusted
    frame and nowhere outside one.
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


def test_1224_judge_reply_bucket_systems_and_findings_are_recorded_per_world(tmp_path):
    """d12e_judge_output_recorded — validate_reply accepts a world reply carrying a bucket, the
    systems the facts touched and findings, and the family record stores all three per world.

    validate_reply accepts a world reply carrying a bucket, the systems the facts touched and
    findings, and the family record stores all three per world; pattern and holding_system are
    no longer reply fields — neither the record's findings nor the draw document carry them.
    """
    reply = _world_reply("analyze-discipline", ("edr", "idp"), findings=[
        _finding("d12e-defender", bucket="analyze-discipline"),
        _finding("d12e-world", bucket="shape-invention", subject="world",
                 evidence=["report.md"])])
    parsed = _validate(_text(reply))
    assert parsed.bucket == "analyze-discipline"
    assert list(parsed.systems) == ["edr", "idp"]
    assert {f.topic for f in parsed.findings} == {"d12e-defender", "d12e-world"}

    ep = S.judged_episode(tmp_path)
    _grade(tmp_path, ep, _judge({"b": reply}))
    row = _row(ep, "b")
    assert row.get("bucket") == "analyze-discipline", f"the record's bucket: {row!r}"
    assert sorted(row.get("systems") or []) == ["edr", "idp"], f"the record's systems: {row!r}"
    assert _topics(row.get("findings")) == {"d12e-defender", "d12e-world"}, (
        f"the record's findings: {row.get('findings')!r}")
    recorded = list(row.get("findings") or []) + list(J.draw_doc(ep, "b", 0).get("findings") or [])
    for finding in recorded:
        for key in ("pattern", "holding_system"):
            assert key not in finding, f"a recorded finding still carries {key!r}: {finding!r}"


def test_1224_world_whose_change_never_reached_the_investigator_is_judged_not_withheld(
        tmp_path):
    """d12f_unreached_change_is_judged — a world whose every sibling call was passthrough is
    sent to the judge model, can yield findings, and carries no withheld reason.

    A world whose every sibling call was `passthrough` (its change never reached the
    investigator) is sent to the judge model and can yield findings; it carries no withheld
    reason. Design non-obligation "No mechanical bucket": such a world is a finding, not
    withheld.
    """
    ledger = [S.ledger_row(S.PASSTHROUGH, params=S.query_params(f"user:p{i}")) for i in range(4)]
    ep = S.judged_episode(tmp_path, ledgers={"b": ledger})
    judge = _judge({"b": _world_reply("lead-set", ("idp",),
                                      findings=[_finding("never-queried", bucket="lead-set")])})
    _grade(tmp_path, ep, judge)

    assert _called_for(judge, "b"), "a world whose change never reached the investigator was not judged"
    row = _row(ep, "b")
    assert row.get("bucket") == "lead-set"
    assert "never-queried" in _topics(row.get("findings"))
    assert row.get("withheld_reason") is None, f"the world was withheld: {row!r}"
    assert not _record(ep).get("withheld_findings"), "a finding of the world was withheld"
    assert [r["subject_topic"] for r in _from_world(_queue(), "b")] == ["never-queried"], (
        "the unreached world's finding did not reach the defender queue")


def test_1224_preflight_drift_reaches_the_judge_model(tmp_path):
    """d12g_drift_reaches_the_judge — the drift calls pre-flight recorded appear in the judge
    model's prompt.

    The drift calls pre-flight recorded on the outcome record appear in the judge model's
    prompt (whether drift spoils the family is the model's call, design "No mechanical
    control-drift discard"). The call's params are the source run's own, so they arrive framed
    (M26).
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

    A family whose recorded drift includes the call the discriminator's text describes is not
    discarded by any code path; its outcome is whatever the judge model's reply says. The
    mechanical discard keyed on `discriminator.envelope` is gone (design, confirmed by the
    human); drift is the model's to weigh.

    Two episodes, the same drift on the discriminating call: the model saying gradable keeps
    the findings; the model saying discard (the positive control — the channel still works)
    discards them.
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
        assert rec.get(key) != "discard", (
            f"drift on the discriminating call discarded the family mechanically: {rec!r}")
    assert "kept" in {r["subject_topic"] for r in _queue(state)}, (
        "the findings of a family the model called gradable were not enqueued")

    dropped_root = tmp_path / "discard"
    ep = episode(dropped_root)
    state = _state1135.state_over(dropped_root / "state")
    _grade(dropped_root, ep, _judge(
        {"b": _world_reply(findings=[_finding("dropped")], episode_outcome="discard"),
         "c": _world_reply(findings=[], episode_outcome="discard")},
        verdict="discard"), state=state)
    rec = _record(ep)
    assert "discard" in (rec.get("episode_outcome"), rec.get("verdict_word")), (
        f"the positive control: the model's discard was not honoured: {rec!r}")
    assert _queue(state) == [], "a family the model discarded enqueued defender findings"


def test_1224_judge_prompt_names_no_overlay_holding_system_or_envelope(tmp_path):
    """d12i_judge_prompt_free_of_staging_language — the judge's prompts say nothing of an
    overlay, a holding system, an envelope, staging or mechanical rows.

    The judge's prompts (role.md and the rendered world and family prompts) say nothing of an
    overlay, a holding system, an envelope, staging or mechanical rows. The host-authored text
    is what is read (outside every untrusted frame): the role file whole, and every prompt the
    double received.

    Positive control: the prompts exist and carry the manifest's served_systems (the pair,
    d12d, pins the rest of what they carry).
    """
    banned = ("overlay", "holding system", "holding_system", "envelope", "staging", "staged",
              "mechanical row")
    role = S.source_text("learning/judge/role.md").lower()
    assert role, "the positive control: the judge's role file was not found"
    for word in banned:
        assert word not in role, f"role.md still speaks of {word!r}"

    ep = S.judged_episode(tmp_path, doc=S.family_v2(served_systems=("edr", "idp", "x-d12i")))
    judge = _judge({"b": _world_reply()})
    _grade(tmp_path, ep, judge)
    assert "x-d12i" in _prompt_for(judge, "b"), (
        "the positive control: no world prompt carrying served_systems was rendered")
    for agent_id, prompt in zip(judge.agent_ids, judge.prompts, strict=True):
        host = S.outside_untrusted_frames(prompt).lower()
        for word in banned:
            assert word not in host, f"the {agent_id} prompt still speaks of {word!r}"


def test_1224_finding_rows_carry_the_judge_models_bucket_and_systems(tmp_path):
    """d12j_enqueue_reads_the_models_output — enqueue builds each world finding row from the
    judge model's output, carrying its bucket and systems, with no pattern, holding_system or
    withheld reason.

    enqueue builds each world finding row from the judge model's output, carrying its bucket
    and systems, with no pattern, holding_system or withheld reason. The world's reply and its
    world-subject finding share the bucket, so "its bucket" names one value whichever field the
    row takes it from; the systems are the reply's.
    """
    ep = S.judged_episode(tmp_path)
    reply = _world_reply("lead-quality", ("idp", "edr"), findings=[
        _finding("d12j-world", bucket="lead-quality", subject="world", evidence=["report.md"]),
        _finding("d12j-defender", bucket="lead-quality")])
    _grade(tmp_path, ep, _judge({"b": reply}))

    world_rows = _from_world(_queue(channel=QUESTIONER_FINDINGS), "b")
    assert [r.get("subject_topic") for r in world_rows] == ["d12j-world"], (
        f"the world finding row was not built from the model's output: {world_rows!r}")
    row = world_rows[0]
    assert row.get("type") == "lead-quality", f"the row's bucket: {row.get('type')!r}"
    assert sorted(row.get("systems") or []) == ["edr", "idp"], f"the row's systems: {row!r}"
    for queued in [row, *_from_world(_queue(), "b")]:
        for key in ("pattern", "holding_system", "withheld_reason"):
            assert key not in queued, f"a queue row still carries {key!r}: {queued!r}"


def test_1224_family_verdict_word_comes_from_the_judge_models_output(tmp_path):
    """d12m_verdict_word_from_the_model — the family record's verdict_word, read by enqueue's
    lane routing, is the one the judge model gave.

    The family record's verdict_word, read by enqueue's lane routing, is the one taken from the
    judge model's output, not one computed from mechanical rows. M19=A, F-20: the model emits a
    `JUDGE_OUTCOME_ENUM` word at family scope. Two episodes identical in every archived byte
    differ only in the model's family word, and the record and every defender row follow it.
    """
    for word in ("survived", "caught"):
        root = tmp_path / word
        ep = S.judged_episode(root)
        state = _state1135.state_over(root / "state")
        _grade(root, ep, _judge({"b": _world_reply(findings=[_finding(f"{word}-finding")])},
                                verdict=word), state=state)
        assert _record(ep).get("verdict_word") == word, (
            f"the model said {word!r}; the record holds {_record(ep).get('verdict_word')!r}")
        rows = _queue(state)
        assert rows, f"{word}: no defender row was enqueued"
        assert {r.get("judge_outcome") for r in rows} == {word}, (
            f"the defender rows' judge_outcome is not the model's family word {word!r}: "
            f"{[r.get('judge_outcome') for r in rows]}")


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


def test_1224_judge_grades_only_an_accepted_outcome(tmp_path):
    """d14h_judge_gated_on_accepted — the judge grades only an exactly-`accepted` outcome;
    unusable, refused and an absent or torn record are stamped not-graded with no model call.

    RE-PINNED (48: S9; M05=A). The judge grades only when the outcome word is exactly
    `accepted` and its O5 count is under two; for `unusable`, `refused`, or an absent/torn
    record (the distinct 'no record' state, never `incomplete`) it writes a not-graded record
    carrying the word and reason, with no model call and no findings.
    """
    for word in ("unusable", "refused"):
        root = tmp_path / word
        ep, judge = _gate_case(root, word)
        stamp = _record(ep).get("not_graded") or {}
        assert stamp.get("outcome") == word, f"{word}: the stamp reads {stamp!r}"
        assert stamp.get("reason") == f"MARKER-REASON-{word}", (
            f"{word}: the stamp does not carry the outcome record's reason: {stamp!r}")
        assert judge.calls == 0, f"{word}: the gate let a model call through"
        assert _all_queued(_state1135.state_over(root / "state")) == []

    for case, raw in (("absent", None), ("torn", 'outcome: accepted\nreason: "unterminated\n')):
        root = tmp_path / case
        ep, judge = _gate_case(root, None, raw=raw)
        stamp = _record(ep).get("not_graded") or {}
        assert stamp, f"{case}: no not-graded record was written"
        assert stamp.get("outcome") not in ("accepted", S.RETIRED_OUTCOME), (
            f"{case}: a missing or torn outcome record read as {stamp.get('outcome')!r}")
        assert S.OUTCOME_NAME in str(stamp.get("reason")), (
            f"{case}: the reason does not say the outcome record is missing: {stamp!r}")
        assert judge.calls == 0, f"{case}: the gate let a model call through"

    root = tmp_path / "accepted"
    ep, judge = _gate_case(root, "accepted")
    assert _called_for(judge, "b"), "the positive control: an accepted episode was not graded"
    assert "not_graded" not in _record(ep)


def test_1224_judge_citation_check_matches_samples_by_system(tmp_path):
    """d16c_citation_check_by_system — cites_sample accepts a finding citing the samples
    section of a served system with a section, and refuses one citing a system's section the
    record marks unavailable.

    cites_sample accepts a finding citing the samples section of a system the world's row
    names, and refuses one citing a system's section that the row says was unavailable. O16:
    the samples record is keyed by system (`samples.yaml#<system>`). Driven through the whole
    pass, which is where the check gates the queue.
    """
    ep = S.judged_episode(tmp_path)
    S.samples_record(ep, {
        "edr": {"verbs": {"query": ['{"events": [{"host": "db-1"}]}']}},
        "siem-x": {"unavailable": "the capture made no siem-x call"}})
    reply = _world_reply("lead-quality", ("edr", "siem-x"), findings=[
        _finding("cites-edr", subject="world", bucket="shape-invention",
                 evidence=["samples.yaml#edr"]),
        _finding("cites-siemx", subject="world", bucket="shape-invention",
                 evidence=["samples.yaml#siem-x"])])
    _grade(tmp_path, ep, _judge({"b": reply}))

    topics = {r.get("subject_topic") for r in _queue(channel=QUESTIONER_FINDINGS)}
    assert "cites-edr" in topics, "a finding citing a served system's own samples section was refused"
    assert "cites-siemx" not in topics, (
        "a finding citing a section the samples record marks unavailable passed the check")


def test_1224_judge_render_shows_samples_per_system(tmp_path):
    """d16d_judge_render_by_system — the judge's render shows the samples record per system.

    The judge's render shows the samples record per system (O16): each system's real example
    answer under its own name, and a system whose section is unavailable shown with its
    reason — never one document per Elastic pattern.
    """
    ep = S.judged_episode(tmp_path)
    S.samples_record(ep, {
        "edr": {"verbs": {"query": ["MARKER-EDR-SAMPLE"]}},
        "idp": {"verbs": {"lookup": ["MARKER-IDP-SAMPLE"]}},
        "siem-x": {"unavailable": "MARKER-SIEMX-UNAVAILABLE"}})
    judge_input = S.sym(S.JUDGE_RENDER, "render")(ep, "b", git_show=J.FakeGitShow())
    text = "\n".join(judge_input.as_prompt_sections().values())

    for marker in ("MARKER-EDR-SAMPLE", "MARKER-IDP-SAMPLE", "MARKER-SIEMX-UNAVAILABLE"):
        assert marker in text, f"the render does not show {marker} from the samples record"
    for system in ("edr", "idp", "siem-x"):
        assert system in text, f"the render shows no section named for {system!r}"


# --------------------------------------------------------------------------------------
# Premises — couldn't-look (M20=A)
# --------------------------------------------------------------------------------------


def _badge_family(served: tuple[str, ...] = ("edr", "idp", "siem-x")) -> dict:
    """World c's facts sit only on a system the tenant does not serve (a badge reader)."""
    return S.family_v2(served_systems=served, worlds=[
        S.control_world("a"),
        S.world_v2("b", facts=[S.fact("f1")]),
        S.world_v2("c", facts=[S.fact("f2", "the badge reader logged carol at door 7 at 15:40Z",
                                      ("carol", "door-7"))]),
    ])


def test_input_facts_sit_only_on_unserved_systems_at_launch(tmp_path):
    """b_p011 — a world whose facts touch only unserved systems is admitted (it loads and
    reaches the judge), is never served a changed answer for an unserved system, and is never
    bucketed lead-set.

    Scenario: the question-writer authors a world whose facts (statement and entities) touch
    only systems the tenant does not serve. M20=A: such a world is admitted to the judge, which
    contemplates it ("couldn't look" is never graded as a miss); the host refuses `lead-set`
    for it in `validate_reply` and never computes a bucket. Settled regardless: no sibling in
    that world is served a changed answer for an unserved system, and the judge never buckets
    the world lead-set.

    Three observables: the manifest loader admits the family (no refusal at load); an
    investigator call naming the unserved system in that world gets no oracle turn and no
    `oracle` ledger row, while a served system is wired; the judge is called for the world and
    no lead-set is recorded for it.
    """
    doc = _badge_family()
    S.sym(S.FAMILY, "parse_family")(doc)  # admitted at load: no refusal

    est = S.estate(tmp_path / "estate-root")
    ep = S.episode_v2(tmp_path / "serving", doc=doc, base_rows=[])
    oracle = S.oracle(then=S.text_only())
    reg = S.world_registry(ep, "c", est, oracle=oracle, verifier=S.passing_verifier(),
                           retry_cap=1)
    assert "query" in reg.verbs("idp"), "the positive control: a served system is not wired"
    with pytest.raises((KeyError, *J.refusals())):
        S.call(reg, "badge", "query", est.ctx(tmp_path / "run"), q="user:carol")
    assert oracle.requests == 0, "the oracle was handed a call on a system the tenant does not serve"
    assert not [r for r in S.ledger_rows(ep, "c") if r.get("source") == S.ORACLE_DECISION], (
        "a world was served a changed answer for an unserved system")

    graded = S.judged_episode(tmp_path / "judged", doc=doc)
    judge = _judge({"b": _world_reply("lead-quality", ("idp",)),
                    "c": _world_reply("lead-set", ("badge",),
                                      findings=[_finding("c-badge", bucket="lead-set")])})
    _grade(tmp_path / "judged", graded, judge)
    assert _called_for(judge, "c"), "the couldn't-look world was not admitted to the judge"
    assert _row(graded, "c").get("bucket") != "lead-set", (
        "a world whose facts sit only on unserved systems was recorded lead-set")
    assert _row(graded, "b").get("bucket") == "lead-quality", "the positive control: b ungraded"


def test_p078_judge_reply_lead_set_for_a_world_whose_facts_are_only_partly_servable(tmp_path):
    """b_p012 — lead-set stands for a world whose reply touches at least one served system, and
    is refused for one whose reply touches none.

    Scenario: a world's facts touch one served system and one the tenant does not serve, or
    touch none, and the reply says lead-set. M20=A: `validate_reply` refuses `lead-set` only
    when the reply's systems share NOTHING with served_systems; it never computes a bucket.
    Settled regardless: a world whose facts surface only on systems the tenant does not serve
    is never recorded as lead-set (O11); a world with at least one served system touched may
    legitimately be lead-set.
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
        assert _called_for(judge, label), f"world {label} was not admitted to the judge"
        assert _row(ep, label).get("bucket") != "lead-set", (
            f"world {label}, whose reply touches no served system, was recorded lead-set")
        assert _row(ep, label).get("bucket") is None, (
            f"world {label}: a bucket was substituted for the refused lead-set")


def test_served_system_grants_only_health_checks(tmp_path, monkeypatch):
    """b_p042 — a granted system readable only through a health check is not served: the
    launcher leaves it out of served_systems, the judge never records lead-set for a world
    whose facts sit only there, and no query uses a verb the grant lacks.

    Scenario: served_systems (the tenant's gather grant systems) includes a system on which
    gather holds only a health-check verb, and a world's facts surface only there. M20=A:
    a served system is one with at least one non-health-check read verb in the grant. Settled
    regardless: the oracle never forges telemetry the investigator can read nowhere and no
    query uses a verb the grant lacks.
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

    Scenario: a world's facts sit only on a served system that was down for the whole sibling
    run (its real-system errors passed through as `real-error` rows). M20=A: an outage of a
    served system is telemetry, not couldn't-look, so the host does not refuse the model's
    lead-set for it; the outage itself reaches the judge model.
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


def test_input_judge_and_page_read_an_old_manifest_with_only_holding_system(tmp_path):
    """s_p026 — a manifest carrying only discriminator.holding_system, or only
    configured_patterns, is refused by the judge and by the page with the predates-the-oracle
    reason; neither renders the episode nor crashes.

    Scenario: an archived episode whose manifest carries only discriminator.holding_system, or
    only configured_patterns, and none of the other old fields reaches the judge and the
    episode page. Settled: the judge refuses to grade it with a named reason saying the
    manifest predates the oracle, and the episode page shows that same reason; neither renders
    the episode, and neither raises a generic error or crashes (O15 covers the judge and the
    page, and the judge's reader is separate from the runtime loader).
    """
    for key in ("discriminator.holding_system", "configured_patterns"):
        root = tmp_path / key.replace(".", "-")
        doc = S.old_manifest(key)
        doc["worlds"][1]["story"] = "MARKER-OLD-STORY"
        ep = S.judged_episode(root, doc=doc, outcome=None)
        J.review_record(ep, outcome="accepted")
        judge = _judge({"b": _world_reply()})
        _grade(root, ep, judge, state=_state1135.state_over(root / "state"))
        stamp = _record(ep).get("not_graded") or {}
        assert S.PREDATES in str(stamp.get("reason", "")), (
            f"{key}: the judge did not refuse with the predates-the-oracle reason: {stamp!r}")
        assert judge.calls == 0, f"{key}: an old-manifest episode bought model calls"

        html, refusal = _page(ep)
        shown = refusal if refusal is not None else html
        assert S.PREDATES in str(shown), f"{key}: the page does not show the refusal reason"
        assert html is None or "MARKER-OLD-STORY" not in html, (
            f"{key}: the page rendered the old episode")


def test_input_manifest_cannot_be_parsed_at_judge_or_page(tmp_path):
    """s_p027 — a truncated, duplicate-key or non-mapping family.yaml is reported unreadable by
    the judge and the page with its own named reason, distinct from predates-the-oracle, and
    crashes neither.

    Scenario: an archived family.yaml is truncated, has a duplicated key, or is not a mapping,
    and the judge and the page read it. Settled: a truncated, duplicate-key or non-mapping
    family manifest read by the judge or the page is reported as unreadable with its own named
    reason, distinct from the predates-the-oracle refusal, and does not crash either consumer.
    A named refusal (`JudgeRefused`) or a not-graded record naming the manifest both count as
    reported; any other exception is a crash.
    """
    whole = _yaml.safe_dump(S.family_v2())
    # The shared loader refuses the truncated text and reads the duplicate-key one silently
    # (last key wins), so the duplicate arm is the judge's and the page's own to detect.
    shapes = {
        "truncated": "episode_id: x\nworlds:\n  - {world_id: a",
        "duplicate-key": whole + "served_systems: [edr]\n",
        "not-a-mapping": "- this is\n- a list, not a manifest\n",
    }
    for shape, text in shapes.items():
        root = tmp_path / shape
        ep = S.judged_episode(root)
        (ep / "family.yaml").write_text(text, encoding="utf-8")
        judge = _judge()
        refused = _refused()
        try:
            _grade(root, ep, judge, state=_state1135.state_over(root / "state"))
            said = str((_record(ep).get("not_graded") or {}).get("reason", ""))
        except refused as refusal:
            said = str(refusal)
        assert "family.yaml" in said, f"{shape}: the judge did not name the unreadable manifest: {said!r}"
        assert S.PREDATES not in said, f"{shape}: the judge called an unreadable manifest old"
        assert judge.calls == 0, f"{shape}: an unreadable manifest bought model calls"

        html, refusal = _page(ep)
        shown = str(refusal if refusal is not None else html)
        assert "family.yaml" in shown, f"{shape}: the page did not report the unreadable manifest"
        assert S.PREDATES not in shown, f"{shape}: the page called an unreadable manifest old"


def test_p093_old_review_record_says_accepted_with_no_new_outcome_record(tmp_path):
    """s_p034 — an episode holding only an old review record that says accepted is not graded,
    and both the judge and the episode reader report the missing outcome record.

    Scenario: an episode folder from before this change holds a review record saying accepted,
    and no outcome record of the new kind. Settled: it is not graded; the old review.yaml is not
    read as the O13 outcome record, and the judge and episode reader report the missing outcome
    or the predates-the-oracle manifest reason. Driven with a v2 manifest, so the only thing
    missing is the outcome record. Positive control: the same episode with an `accepted`
    outcome record is graded and read.
    """
    EpisodeError = S.sym(S.EPISODE, "EpisodeError")
    verdicts = S.sym(S.EPISODE, "verdicts")

    ep = S.judged_episode(tmp_path / "old", outcome=None)
    J.review_record(ep, outcome="accepted")
    judge = _judge({"b": _world_reply()})
    _grade(tmp_path / "old", ep, judge, state=_state1135.state_over(tmp_path / "old" / "state"))
    stamp = _record(ep).get("not_graded") or {}
    assert judge.calls == 0, "an old review record was read as the outcome record"
    assert S.OUTCOME_NAME in str(stamp.get("reason", "")), (
        f"the judge did not report the missing outcome record: {stamp!r}")
    with pytest.raises(EpisodeError) as refused:
        verdicts(ep)
    assert S.OUTCOME_NAME in str(refused.value), "the episode reader did not name the missing record"

    ok = S.judged_episode(tmp_path / "new")
    judge = _judge({"b": _world_reply()})
    _grade(tmp_path / "new", ok, judge, state=_state1135.state_over(tmp_path / "new" / "state"))
    assert _called_for(judge, "b"), "the positive control: an accepted outcome record was not graded"
    assert verdicts(ok), "the positive control: the episode reader refused an accepted episode"


# --------------------------------------------------------------------------------------
# Premises — unservable worlds at the judge (O5, S9, S10, N22 / FU22)
# --------------------------------------------------------------------------------------


def test_judge_reads_a_family_whose_unservable_sibling_left_a_partial_ledger(tmp_path):
    """s_p199 — an unservable sibling's partial records stay readable, contribute no findings,
    and the judge and page show the world as unservable while the rest is graded.

    Scenario: one unservable sibling aborted partway and left a ledger and evidence of its own
    calls up to the failure. Settled: an unservable sibling's partial evidence and ledger are
    archived and readable, but the family is still graded on the other worlds without that
    world contributing findings from its partial records (O5); the episode page and judge show
    the world as unservable. N22: the unservable world appears to the judge as an explicit
    entry built from its own record.
    """
    partial = [S.ledger_row(S.PASSTHROUGH, params=S.query_params("user:MARKER-PARTIAL"), label="c")]
    ep = S.judged_episode(tmp_path, ledgers={"c": partial})
    S.world_record(ep, "c", S.REASON_UNSERVABLE, call=_call("user:carol"),
                   detail="MARKER-C-DETAIL attempts exhausted on check 4")
    judge = _judge({"b": _world_reply(findings=[_finding("b-rest")]),
                    "c": _world_reply("lead-set", ("idp",), findings=[_finding("c-partial")])})
    _grade(tmp_path, ep, judge)

    assert _row(ep, "b").get("bucket") == "lead-quality", "the rest of the family was not graded"
    for key in ("findings", "bucket"):
        assert not _row(ep, "c").get(key), (
            f"the unservable world contributed {key} from its partial records")
    assert not _from_world(_all_queued(), "c"), "a finding of the unservable world was enqueued"
    assert any("MARKER-C-DETAIL" in p for p in judge.prompts), (
        "the judge was not shown the unservable world as an explicit entry from its own record")

    assert S.ledger_rows(ep, "c") == partial, "grading disturbed the partial world's archived ledger"
    html, refusal = _page(ep)
    assert refusal is None, f"the page refused a family with one unservable world: {refusal}"
    assert S.REASON_UNSERVABLE in str(html), "the page does not show world c as unservable"


def test_input_judge_gives_an_unservable_world_a_bucket(tmp_path):
    """s_p243 — a bucket and findings the judge model gives a world recorded unservable are not
    recorded as findings, and an unusable family carries none at all.

    Scenario: the judge model's reply gives a bucket and findings to a world that pre-flight or a
    sibling recorded as unservable. Settled: those are not recorded as findings — the
    unservable world is not graded, and an unusable family carries no findings (O5). The model
    is never asked about such a world, so its "answer" is planted where an answer lives: a draw
    document under the world's own judge directory, beside a scripted reply.
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

    Scenario: pre-flight exhausts the oracle's attempts on an original call for world b, so
    world b is unservable and its sibling never starts, while the other worlds' siblings run.
    Bound: world b's world ledger holds no rows, because its sibling never started and
    pre-flight queries never land in a sibling's ledger (O9); the family's base recording holds
    only the original run's recording, unchanged by pre-flight's replay or by the failure (O9;
    FA-11). World b is not graded and not bucketed, as a miss or otherwise (O5, O11); the
    outcome record names world b among the unservable worlds; with exactly one unservable world
    the outcome is `accepted`, the other worlds are graded, and the family is not marked
    unusable. N22: b appears in the judge's input as an explicit entry with no calls, built from
    pre-flight's result.

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
    judge = _judge({"c": _world_reply("decision-discipline", ("edr",))})
    _grade(root, ep, judge)
    assert not _called_for(judge, "b"), "the unservable world was graded"
    assert not _row(ep, "b").get("bucket"), "the unservable world was bucketed"
    assert _row(ep, "c").get("bucket") == "decision-discipline", "the rest of the family was not graded"
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
    with no stored claim. Settled regardless: the judge is never told a claim was verified when
    no verdict exists.

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

    Scenario: the judge model's call fails for one world's draw (a transient provider error) and
    succeeds for the others. N22 reading: a failed draw leaves that world ungraded and a bare
    re-run grades only missing worlds. Settled regardless: no bucket for the failed world is
    computed by code. The failure is #921's P9 shape (executed): a transport failure and a
    timeout both arrive as `RunUnprocessable`.
    """
    reply_b = _world_reply("analyze-discipline", ("idp",), findings=[_finding("b-later")])
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
    world_calls = {_label_of(a) for a in second.agent_ids if _label_of(a) != "family"}
    assert world_calls == {"b"}, f"a bare re-run regraded {sorted(world_calls)}, not only b"
    assert _row(ep, "b").get("bucket") == "analyze-discipline", "the re-run did not grade b"
    assert _row(ep, "c").get("bucket") == "lead-quality", "the re-run disturbed c's grade"


def test_judge_reply_gives_a_bucket_outside_the_five(tmp_path):
    """b_p238 — a bucket outside the set (a lookalike, a padded or capitalised spelling, null,
    two buckets, a new word) is refused, never recorded or enqueued as written and never
    coerced; `observability` is admitted and recorded as the world's bucket.

    Scenario: the judge model's reply names a bucket that is not one of the allowed ones. M19=A:
    the bucket set is O11's five plus `observability` (hole H-04 resolves to it); `none` is an
    explicit member. Settled regardless: a bucket outside the accepted set is never recorded or
    enqueued as written.
    """
    refused = _refused()
    for bad in ("lead_set", "Lead-Set", " lead-set ", "lead-set\n", None,
                ["lead-set", "lead-quality"], "missed-lead", ""):
        with pytest.raises(refused) as refusal:
            _validate(_text(_world_reply(bad, ("idp",))))
        assert "bucket" in str(refusal.value), f"the refusal of {bad!r} does not name the field"
    admitted = _validate(_text(_world_reply("observability", ("idp",))))
    assert admitted.bucket == "observability", "`observability` is not admitted (M19=A)"

    ep = S.judged_episode(tmp_path)
    judge = _judge({
        "b": _world_reply("observability", ("idp",),
                          findings=[_finding("refused-externally", bucket="observability")]),
        "c": _world_reply("Lead-Set", ("idp",), findings=[_finding("lookalike")])})
    _grade(tmp_path, ep, judge)
    assert _row(ep, "b").get("bucket") == "observability", (
        "an `observability` reply was not recorded as the world's bucket")
    assert _row(ep, "c").get("bucket") not in ("Lead-Set", "lead-set"), (
        "an off-vocabulary bucket was recorded as written or coerced to its nearest member")
    assert all(r.get("type") not in ("Lead-Set",) for r in _all_queued()), (
        "an off-vocabulary bucket was enqueued")


def test_judge_reply_leaves_a_world_out(tmp_path):
    """b_p240 — no code supplies a bucket for a world the replies leave unanswered, an invalid
    reply is retried as a whole, and a world the family does not have is never recorded.

    Scenario: the judge model's reply covers two of three worlds, names a world the family lacks,
    or names one world twice. N22 reading: a reply with missing, extra or duplicated worlds is
    invalid as a whole and retried. Settled regardless: no code supplies a bucket for an omitted
    world, and no finding is recorded for a world the family does not have.

    The coined reply is per world (one call per world), so the three shapes are driven as that
    shape spells them: world c's every reply is invalid (it never answers its own bucket); world
    d's first reply is invalid and its retry valid; world b's reply carries a finding naming a
    world "z" the family lacks; a reply giving its world's bucket twice is refused whole.
    """
    doc = S.family_v2(worlds=[S.control_world("a"), *[
        S.world_v2(label, facts=[S.fact(f"f-{label}")]) for label in ("b", "c", "d")]])
    ep = S.judged_episode(tmp_path, doc=doc, labels=("a", "b", "c", "d"))
    no_bucket = _world_reply()
    no_bucket.pop("bucket")
    judge = _judge({
        "b": _world_reply(findings=[_finding("names-z", subject="world", bucket="shape-invention",
                                             evidence=["report.md"], world="z")]),
        "c": [_text(no_bucket)],
        "d": [_text(no_bucket), _text(_world_reply("decision-discipline", ("edr",)))]})
    _grade(tmp_path, ep, judge)

    rows = _rows(ep)
    assert rows.get("b", {}).get("bucket") == "lead-quality", "the positive control: b ungraded"
    assert rows.get("c", {}).get("bucket") is None, (
        f"code supplied a bucket for a world no valid reply answered: {rows.get('c')!r}")
    assert rows.get("d", {}).get("bucket") == "decision-discipline", (
        "an invalid reply was not retried: world d's valid retry was never recorded")
    assert "z" not in rows, "a world the family does not have was recorded as one of its worlds"
    assert not [r for r in _all_queued() if r.get("world") == "z" or "/z/" in str(r.get("finding_id"))]

    twice = _text(_world_reply("lead-set", ("idp",))) + "bucket: lead-quality\n"
    with pytest.raises(_refused()):
        _validate(twice)


def test_input_judge_reply_still_carries_pattern_and_holding_system(tmp_path):
    """b_p241 — a reply still carrying pattern and holding_system validates with both keys
    ignored: neither reaches the family record or any queue row.

    Scenario: the judge model's reply for a world still includes pattern and holding_system
    fields as the old prompt asked. N22 reading: leftover pattern/holding_system keys are
    ignored. Settled regardless: those fields feed nothing downstream (no holding system
    anywhere).
    """
    stale = {"pattern": "logs-*", "holding_system": "elastic"}
    reply = _world_reply("lead-quality", ("idp",), findings=[
        _finding("stale-defender", **stale),
        _finding("stale-world", subject="world", bucket="shape-invention",
                 evidence=["report.md"], **stale)], **stale)
    parsed = _validate(_text(reply))
    assert {f.topic for f in parsed.findings} == {"stale-defender", "stale-world"}, (
        "a reply carrying leftover keys was not accepted with its findings")

    ep = S.judged_episode(tmp_path)
    _grade(tmp_path, ep, _judge({"b": reply}))
    row = _row(ep, "b")
    assert _topics(row.get("findings")) == {"stale-defender", "stale-world"}
    queued = _from_world(_all_queued(), "b")
    assert {r.get("subject_topic") for r in queued} == {"stale-defender", "stale-world"}, (
        "the positive control: the reply's findings did not reach the queues")
    for thing in [row, *(row.get("findings") or []), *queued]:
        for key in ("pattern", "holding_system"):
            assert key not in thing, f"a leftover {key!r} fed something downstream: {thing!r}"
    for value in ("elastic", "logs-*"):
        assert value not in json.dumps(queued), f"the leftover value {value!r} reached a queue row"


def test_input_judge_finding_cites_an_unserved_or_misspelled_samples_section(tmp_path):
    """s_p242 — only a served system's own samples section passes the citation check; an
    unavailable section, a case or lookalike spelling, an old pattern key and a dot-dot path all
    fail it.

    Scenario: a finding cites the samples section of a system the world's row says was
    unavailable, of a system spelled with different case, and of a pattern as the old format
    keyed it. Settled: each of those, and a lookalike system or a path with dot-dot segments,
    fails the citation check; citations resolve only to a served system's own section (O16).
    """
    ep = S.judged_episode(tmp_path)
    S.samples_record(ep, {
        "edr": {"verbs": {"query": ['{"events": [{"host": "db-1"}]}']}},
        "idp": {"verbs": {"query": ['{"rows": [{"user": "alice"}]}']}},
        "siem-x": {"unavailable": "the capture made no siem-x call"}})
    pointers = {
        "own-section": "samples.yaml#edr",
        "unavailable": "samples.yaml#siem-x",
        "case": "samples.yaml#EDR",
        "lookalike": "samples.yaml#edr_",
        "old-pattern": "samples.yaml#logs-*",
        "dot-dot": "samples.yaml#../edr",
        "dot-dot-path": "../samples.yaml#edr",
    }
    reply = _world_reply("lead-quality", ("edr",), findings=[
        _finding(topic, subject="world", bucket="shape-invention", evidence=[pointer])
        for topic, pointer in pointers.items()])
    _grade(tmp_path, ep, _judge({"b": reply}))

    passed = {r.get("subject_topic") for r in _queue(channel=QUESTIONER_FINDINGS)}
    assert passed == {"own-section"}, (
        f"the citation check passed {sorted(passed)}; only a served system's own section may")


def test_input_outcome_record_is_inconsistent_or_in_legacy_words(tmp_path):
    """b_p244 — the gate grades only an outcome that is exactly `accepted`, with a reason and
    fewer than two unservable worlds; the episode reader treats every other record as not
    usable; nothing crashes.

    Scenario: an outcome record says accepted while listing two unservable worlds, names an
    unservable world the manifest lacks, uses a legacy word (rejected, incomplete) or the right
    word in capitals, or has no reason. N22 reading: the judge grades only when the outcome word
    is exactly `accepted` and its O5 count (S9) is under two. Settled regardless: a legacy word,
    a capitalised or newline-suffixed word, a list or a missing reason is not `accepted`
    (O13).
    """
    EpisodeError = S.sym(S.EPISODE, "EpisodeError")
    verdicts = S.sym(S.EPISODE, "verdicts")
    two = [{"world": w, "reason": S.REASON_UNSERVABLE, "call": _call(f"user:{w}")}
           for w in ("b", "c")]
    raws = {
        "rejected": "outcome: rejected\nreason: r\nunservable_worlds: []\n",
        "incomplete": "outcome: incomplete\nreason: r\nunservable_worlds: []\n",
        "capitals": "outcome: Accepted\nreason: r\nunservable_worlds: []\n",
        "newline": 'outcome: "accepted\\n"\nreason: r\nunservable_worlds: []\n',
        "a-list": "outcome: [accepted]\nreason: r\nunservable_worlds: []\n",
        "no-reason": "outcome: accepted\nunservable_worlds: []\n",
        "two-unservable": _yaml.safe_dump({"outcome": "accepted", "reason": "r",
                                           "unservable_worlds": two}),
    }
    for case, raw in raws.items():
        root = tmp_path / case
        ep, judge = _gate_case(root, None, raw=raw)
        assert judge.calls == 0, f"{case}: the gate graded an outcome that is not exactly accepted"
        assert _all_queued(_state1135.state_over(root / "state")) == []
        if case != "two-unservable":  # the reader's own recount is unsettled (hedge)
            with pytest.raises(EpisodeError):
                verdicts(ep)

    # Unsettled (which way it reads), bound only to not crash.
    root = tmp_path / "foreign-world"
    ep = S.judged_episode(root, outcome=None)
    S.outcome_record(ep, "accepted", unservable=[
        {"world": "z", "reason": S.REASON_UNSERVABLE, "call": _call("user:zed")}])
    _grade(root, ep, _judge(), state=_state1135.state_over(root / "state"))
    assert (ep / "judge.yaml").is_file(), "an outcome naming a foreign world left no record"

    root = tmp_path / "accepted"
    ep, judge = _gate_case(root, "accepted")
    assert _called_for(judge, "b"), "the positive control: an exactly-accepted episode was not graded"
    assert verdicts(ep), "the positive control: the episode reader refused an accepted episode"


def test_1224_judge_draws_disagree_on_a_worlds_bucket_or_systems(tmp_path):
    """b_p246 — when two draws give one world different buckets or systems, every draw's answer
    is recorded and no code reduces them to a bucket of its own.

    Scenario: with more than one judge draw, two draws give one world different buckets or
    different systems. N22 reading: disagreeing draws are all recorded with the disagreement
    flagged. Settled regardless: no code computes the bucket. The disagreement flag has no
    coined name (hand-back red flag); what is pinned is that both draws' buckets and systems
    are recorded and the world's row names no bucket neither draw gave.
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


def test_1224_judge_family_word_outside_what_the_queue_accepts(tmp_path):
    """b_p247 — a family word outside `JUDGE_OUTCOME_ENUM` is refused, never reaches a queue
    row, and the pass records why; every member of the vocabulary is admitted.

    Scenario: the judge model's family-level word is not one the queue's validator or the
    curator gates accept (a misspelling, `unusable`, a new word). M19=A: the family word is kept
    and comes from `JUDGE_OUTCOME_ENUM`, so `_gate_family` keeps authoring. Settled regardless:
    removing the code half must not silently stop lesson authoring or drop a pass without a
    recorded reason.
    """
    enum = S.sym(S.VOCAB, "JUDGE_OUTCOME_ENUM")
    for word in sorted(enum):
        assert _validate(_text(_family_reply(word)), scope="family").verdict_word == word
    for bad in ("survivd", "unusable", "promoted"):
        with pytest.raises(_refused()):
            _validate(_text(_family_reply(bad)), scope="family")

    ep = S.judged_episode(tmp_path)
    _grade(tmp_path, ep, _judge({"b": _world_reply(findings=[_finding("b")])}, verdict="survivd"))
    rec = _record(ep)
    assert rec.get("verdict_word") != "survivd", "an off-vocabulary family word was recorded"
    assert all(r.get("judge_outcome") != "survivd" for r in _all_queued()), (
        "an off-vocabulary family word reached a queue row")
    assert "survivd" in _yaml.safe_dump(rec) or (rec.get("family_malformed_replies") or 0) >= 1, (
        "the pass dropped the family word without a recorded reason")


def test_1224_judge_prompt_over_a_world_with_hundreds_of_verified_claims(tmp_path, monkeypatch):
    """b_p249 — under the payload cap the judge model still gets every call's decision kind, and
    the world's bucket is the model's.

    Scenario: a sibling made hundreds of calls whose verified claims and served answers exceed
    the judge's payload cap. N22 reading: under a payload cap the judge still gets each call's
    decision kind. Settled regardless: the world's bucket is the judge model's decision from
    what it is given (O11), and an unchanged world is a finding, not a withheld case (world c's
    every call is `passthrough`).
    """
    monkeypatch.setenv(J.CAP_KNOB, "20000")
    bulky = {"rows": [{"user": "alice", "blob": "x" * 2000}]}
    claim = S.claim(changed=[S.changed("alice", "logon", "absent", "present")])
    rows = [_oracle_row(f"user:o{i:03d}", claim=claim, verdict={"passed": True, "reason": "ok"})
            for i in range(120)]
    for row in rows:
        row["payload_text"] = json.dumps(bulky)
    rows += [S.ledger_row(S.PASSTHROUGH, params=S.query_params(f"user:p{i:03d}"), payload=bulky)
             for i in range(80)]
    unchanged = [S.ledger_row(S.PASSTHROUGH, params=S.query_params(f"user:c{i}"), label="c")
                 for i in range(5)]
    ep = S.judged_episode(tmp_path, ledgers={"b": rows, "c": unchanged})
    judge = _judge({"b": _world_reply("lead-quality", ("idp",)),
                    "c": _world_reply("lead-set", ("idp",),
                                      findings=[_finding("unchanged", bucket="lead-set")])})
    _grade(tmp_path, ep, judge)

    prompt = _prompt_for(judge, "b")
    assert len(prompt) < 120 * 2000, "the payload cap was not applied at all"
    assert prompt.count(S.ORACLE_DECISION) >= 120, "a call's `oracle` decision kind was cut by the cap"
    assert prompt.count(S.PASSTHROUGH) >= 80, "a call's `passthrough` decision kind was cut by the cap"
    assert _row(ep, "b").get("bucket") == "lead-quality"
    assert _row(ep, "c").get("bucket") == "lead-set", "an unchanged world was not graded"
    assert _row(ep, "c").get("withheld_reason") is None, "an unchanged world was withheld"


def test_judge_is_run_again_on_an_episode_it_already_graded(tmp_path):
    """b_p250 — a graded episode is final: a bare re-run after its outcome record or a ledger
    changed makes no model call and changes neither the record nor the queue; an old-manifest
    episode is never graded, even over a pre-oracle grade record.

    Scenario: the judge is run a second time over an episode that has a graded record, and
    between the two runs the outcome record or a world ledger has been changed. N22 reading: a
    graded episode is final unless re-run explicitly. Settled regardless: an old-manifest episode
    is not graded (O15).
    """
    ep = S.judged_episode(tmp_path / "graded")
    first = _judge({"b": _world_reply(findings=[_finding("once")])})
    _grade(tmp_path, ep, first)
    assert _called_for(first, "b"), "the positive control: the first pass did not grade"
    before, queued = (ep / "judge.yaml").read_text(encoding="utf-8"), _all_queued()

    S.outcome_record(ep, "unusable", reason="rewritten after grading")
    S.write_ledger(ep, "b", [S.ledger_row(S.PASSTHROUGH, params=S.query_params("user:late"))])
    second = _judge({"b": _world_reply("lead-set", ("idp",), findings=[_finding("twice")])})
    _grade(tmp_path, ep, second)
    assert second.calls == 0, "a bare re-run regraded a graded episode"
    assert (ep / "judge.yaml").read_text(encoding="utf-8") == before, "the graded record changed"
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
    except _refused():
        pass  # a named refusal is "not graded"; any other exception is a crash and propagates
    assert third.calls == 0, "an old-manifest episode bought model calls"
    assert _all_queued(state) == [], "an old-manifest episode enqueued findings"


# --------------------------------------------------------------------------------------
# Obligations — readers that survive the change (O-21, O-22, O-24, O-39, O-41, O-42, O-51)
# --------------------------------------------------------------------------------------


def test_1224_judge_reply_citing_review_yaml_is_not_accepted_after_review_is_gone(tmp_path):
    """o21_validate_reply_without_review_record — with review.yaml gone, the judge's reply
    validation neither crashes nor accepts a finding citing review.yaml; a finding citing a
    file the episode does hold still validates.

    With review.yaml gone from the episode, the judge's reply validation neither crashes nor
    accepts a finding citing review.yaml; a finding citing a file the oracle-era episode does
    hold still validates (O-21). Today the world lane's episode-level allowlist still names
    `review.yaml`, so a pointer to it "resolves" with nothing there.
    """
    reply = _world_reply("lead-quality", ("idp",), findings=[
        _finding("cites-review", subject="world", bucket="shape-invention",
                 evidence=["review.yaml#worlds.b.reachability"]),
        _finding("cites-report", subject="world", bucket="shape-invention",
                 evidence=["report.md"])])
    assert _validate(_text(reply)).findings, "the reply did not validate at all"
    ep = S.judged_episode(tmp_path)
    assert not (ep / "review.yaml").exists()
    _grade(tmp_path, ep, _judge({"b": reply}))

    row = _row(ep, "b")
    assert "cites-report" in _topics(row.get("findings")), (
        "the positive control: a finding citing the world's own report was not kept")
    assert "cites-review" not in _topics(row.get("findings")), (
        "a finding citing the review record an oracle-era episode no longer has was accepted")
    assert "cites-review" not in {r.get("subject_topic") for r in _all_queued()}


def test_1224_judge_render_builds_its_prompt_without_a_review_record(tmp_path):
    """o22_judge_render_without_reachability — the judge's render produces a world prompt for an
    oracle-era episode with no review.yaml, carrying no reachability block, without crashing.

    The judge's render produces a world prompt for an oracle-era episode that has no review.yaml,
    with no reachability block and no crash (O-22): the review step and its reachability
    measurements are gone (design, "Today's review step is not kept"), so the prompt must not
    still carry a section about them.
    """
    ep = S.judged_episode(tmp_path)
    assert not (ep / "review.yaml").exists()
    judge_input = S.sym(S.JUDGE_RENDER, "render")(ep, "b", git_show=J.FakeGitShow())
    prompt = S.sym(S.JUDGE_RUN, "_build_prompt")(judge_input)
    assert "world b" in prompt.lower(), "the positive control: no world prompt was built"
    lowered = prompt.lower()
    for word in ("reachability", "capture_addressed", "review record", "review.yaml"):
        assert word not in lowered, f"the world prompt still carries the review step's {word!r}"


def test_1224_judge_grades_a_non_lab_tenant_without_the_stagers_package(tmp_path):
    """o24_judge_without_stagers — with the stagers package gone, the judge imports and grades an
    episode over a non-lab tenant, taking its system list from the manifest's served_systems.

    With learning/branch/estate/stagers/ gone, the judge imports and grades an episode over a
    non-lab tenant (edr, idp, siem-x), taking its system list from the manifest's served_systems
    (O-24, O1). Observed three ways: no judge module names the stagers package; importing the
    judge in a fresh interpreter loads no stagers module; and a non-lab family is graded with
    its recorded systems in the prompt.
    """
    names = [h for h in S.grep_shipped("stagers") if h.startswith("learning/judge/")]
    assert not names, f"the judge still names the stagers package: {names}"
    probe = ("import sys, defender.learning.judge\n"
             "print(sorted(m for m in sys.modules if '.stagers' in m))\n")
    env = {**os.environ, "PYTHONPATH": str(S.REPO_ROOT)}
    done = subprocess.run([sys.executable, "-c", probe], cwd=S.REPO_ROOT, env=env,
                          capture_output=True, text=True, timeout=120, check=False)
    assert done.returncode == 0, f"the judge does not import: {done.stderr[-800:]}"
    assert done.stdout.strip() == "[]", f"importing the judge loads {done.stdout.strip()}"

    ep = S.judged_episode(tmp_path, doc=S.family_v2(served_systems=S.SYSTEMS))
    judge = _judge({"b": _world_reply("lead-quality", ("siem-x",))})
    _grade(tmp_path, ep, judge)
    assert _row(ep, "b").get("bucket") == "lead-quality", "a non-lab family was not graded"
    prompt = _prompt_for(judge, "b")
    for system in S.SYSTEMS:
        assert system in prompt, f"the recorded served system {system!r} never reached the judge"


def test_1224_enqueue_admits_a_finding_citing_a_systems_samples_section(tmp_path):
    """o39_enqueue_samples_by_system — through enqueue's own read of the per-system samples
    record, a finding citing a served system's section is enqueued and one citing a section
    marked unavailable is not.

    Through enqueue's own read of the per-system samples record, a finding citing a served
    system's section is enqueued and one citing a section the world's row marks unavailable is
    not (O-39). Driven as a BARE re-enqueue (no draws handed over, so enqueue reads the draw
    files and the samples record itself) into a fresh queue of its own.
    """
    ep = S.judged_episode(tmp_path)
    S.samples_record(ep, {
        "edr": {"verbs": {"query": ['{"events": [{"host": "db-1"}]}']}},
        "siem-x": {"unavailable": "the capture made no siem-x call"}})
    reply = _world_reply("lead-quality", ("edr", "siem-x"), findings=[
        _finding("cites-edr", subject="world", bucket="shape-invention",
                 evidence=["samples.yaml#edr"]),
        _finding("cites-siemx", subject="world", bucket="shape-invention",
                 evidence=["samples.yaml#siem-x"])])
    _grade(tmp_path, ep, _judge({"b": reply}))
    assert J.draw_files(ep, "b"), "the grading pass left no draw for enqueue to read back"

    fresh = _state1135.state_over(tmp_path / "re-enqueue")
    S.sym(S.JUDGE_ENQUEUE, "enqueue_report")(ep, _record(ep), state=fresh)
    topics = {r.get("subject_topic") for r in _queue(fresh, QUESTIONER_FINDINGS)}
    assert "cites-edr" in topics, "a finding citing a served system's own section was not enqueued"
    assert "cites-siemx" not in topics, "a finding citing an unavailable section was enqueued"


def test_1224_curator_gate_authors_a_lesson_for_the_judge_models_family_word(tmp_path):
    """o41_gate_family_keeps_authoring — a model-decided family word, carried through enqueue
    onto a queue row, is recognised by `_gate_family` and by enqueue's row validation.

    A model-decided family word from JUDGE_OUTCOME_ENUM, carried through enqueue onto a queue
    row, is recognised by lessons/run.py::_gate_family (a `survived` row is authored,
    `caught`/`undecidable` consumed) and by enqueue's row validation, so removing the code half
    does not silently stop lesson authoring (M19=A, RF-6).
    """
    gate = S.sym(S.LESSONS_RUN, "_gate_family")
    validate_row = S.sym(S.JUDGE_ENQUEUE, "_validate_row")
    for word, expected in (("survived", None), ("caught", "consumed"),
                           ("undecidable", "consumed")):
        root = tmp_path / word
        ep = S.judged_episode(root)
        state = _state1135.state_over(root / "state")
        _grade(root, ep, _judge({"b": _world_reply(findings=[_finding(f"{word}-row")])},
                                verdict=word), state=state)
        rows = _queue(state)
        assert rows, f"{word}: the model's family word put no row on the defender queue"
        for row in rows:
            assert row.get("judge_outcome") == word
            validate_row(row)
            routed = gate(dict(row))
            if expected is None:
                assert routed is None, f"a `survived` row was not authored: {routed!r}"
            else:
                assert routed is not None, f"a {word!r} row was admitted for authoring"
                assert routed[0] == expected, (
                    f"a {word!r} row was routed {routed!r}, not {expected!r}")


def test_1224_corpus_drain_reads_a_row_built_from_the_judge_models_output(tmp_path):
    """o42_drain_reads_new_rows — a queue row built from the judge model's output drains
    through the corpus drain's batch read, neither held as malformed nor crashing; `none` is
    never enqueued.

    A queue row built from the judge model's output (systems, no pattern or holding_system;
    bucket from the five plus observability) drains through the corpus drain's batch read
    without being held as malformed or crashing; `none` is never enqueued (O-42, M19=A). The
    rows are the ones a real grading pass appended to the drain's own state root; the drain is
    the real one, with a recording authoring agent.
    """
    import importlib

    D = importlib.import_module("defender.tests._drain719")
    paths = D.make_paths(tmp_path / "drain")
    state = _state1135.state_for_paths(paths)
    ep = S.judged_episode(tmp_path / "ep")
    _grade(tmp_path, ep, _judge({
        "b": _world_reply("observability", ("idp",),
                          findings=[_finding("drains", bucket="observability")]),
        "c": _world_reply("none", (), findings=[])}), state=state)
    rows = state.rows(FINDINGS)
    assert {r.get("subject_topic") for r in rows} == {"drains"}, (
        f"the graded pass did not enqueue exactly the model's finding: {rows!r}")
    assert all(r.get("type") != "none" for r in rows), "`none` was enqueued"

    channel = D.channel_of("findings")
    agent = D.recording(D.committing("judge-row"))
    cfg = D.cfg_for(paths, "findings", invoke_agent=agent)
    assert S.sym("learning.author.drain", "run_batch")(cfg=cfg) == 0
    authored = {r["finding_id"] for call in agent.calls for r in call["rows"]}
    assert {r["finding_id"] for r in rows} <= authored, (
        "a row built from the judge model's output was not handed to the author")
    assert D.stuck_records(paths, channel) == [], "the drain stuck-recorded the judge's row"
    assert D.pending(paths, channel) == [], "the judge's row is still held on the queue"


def test_1224_judge_reads_the_per_system_samples_record(tmp_path):
    """o51_judge_samples_read — the judge reads the per-system samples record into its world
    prompt, and a world whose row marks a system's section unavailable is judged, not crashed.

    The judge reads the per-system samples record into its world prompt, and a world whose row
    marks a system's section unavailable is judged, not crashed (O-51, O16). The sample is a
    real answer from the capture — not host-authored — so it arrives framed (M26).
    """
    ep = S.judged_episode(tmp_path)
    S.samples_record(ep, {
        "edr": {"verbs": {"query": ["MARKER-O51-EDR-ANSWER"]}},
        "siem-x": {"unavailable": "MARKER-O51-UNAVAILABLE"}})
    judge = _judge({"b": _world_reply("lead-quality", ("edr", "siem-x"))})
    _grade(tmp_path, ep, judge)

    prompt = _prompt_for(judge, "b")
    S.assert_wrapped_untrusted(prompt, "MARKER-O51-EDR-ANSWER", "a system's sample answer")
    assert "MARKER-O51-UNAVAILABLE" in prompt, "the unavailable section's reason never reached the judge"
    assert _row(ep, "b").get("bucket") == "lead-quality", (
        "a world with an unavailable samples section was not judged")


# --------------------------------------------------------------------------------------
# Re-ground coherence (PCO-02, PCO-06, PCO-07, PCO-08)
# --------------------------------------------------------------------------------------


def test_1224_judge_stamps_unusable_refused_and_absent_records_not_graded_with_no_model_call(
        tmp_path):
    """pco02_judge_gate_new_words — the gate stamps `unusable`, `refused` and an absent or empty
    outcome record not-graded with the word and reason and no model call; the word written for
    an absent record is never `incomplete`.

    The judge's gate stamps `unusable`, `refused` and an absent or empty outcome record
    not-graded with the word and the reason and makes no model call; the word it writes for an
    absent record is a member of the new vocabulary, never `incomplete` (PCO-02, M05=A: an
    absent record is "no record", never read as `accepted`). Positive control: an exactly
    `accepted` record is graded and carries no stamp.
    """
    for word in ("unusable", "refused"):
        ep, judge = _gate_case(tmp_path / word, word)
        stamp = _record(ep).get("not_graded") or {}
        assert (stamp.get("outcome"), stamp.get("reason")) == (word, f"MARKER-REASON-{word}"), (
            f"{word}: the stamp reads {stamp!r}")
        assert judge.calls == 0, f"{word}: the gate let a model call through"
    for case, raw in (("absent", None), ("empty", "")):
        ep, judge = _gate_case(tmp_path / case, None, raw=raw)
        stamp = _record(ep).get("not_graded") or {}
        word = stamp.get("outcome")
        assert isinstance(word, str), f"{case}: the stamp names no word: {stamp!r}"
        assert word, f"{case}: the stamp names an empty word: {stamp!r}"
        assert word != S.RETIRED_OUTCOME, f"{case}: the gate wrote the retired word {word!r}"
        assert word != "accepted", f"{case}: a missing record read as accepted"
        assert stamp.get("reason"), f"{case}: the stamp carries no reason"
        assert judge.calls == 0, f"{case}: the gate let a model call through"

    ep, judge = _gate_case(tmp_path / "accepted", "accepted")
    assert _called_for(judge, "b"), "the positive control: an accepted episode was not graded"
    assert "not_graded" not in _record(ep), "the positive control: an accepted episode was stamped"


def test_1224_judge_ledger_read_keeps_oracle_and_real_error_rows(tmp_path):
    """pco06_judge_keeps_new_rows — the judge's ledger read keeps a served `oracle` and a
    `real-error` row and puts both in front of the judge model.

    The judge's ledger read keeps a served `oracle` and a `real-error` row and puts them in front
    of the judge model, not counting them malformed and dropping them (GR-06: today both are
    outside the ledger's words and are dropped as malformed).
    """
    ledger = [
        _oracle_row("user:MARKER-PCO6-ORACLE", claim=S.claim(changed=[
            S.changed("alice", "logon", "absent", "present")]),
            verdict={"passed": True, "reason": "ok"}),
        S.ledger_row(S.REAL_ERROR, params=S.query_params("user:MARKER-PCO6-REALERR"),
                     payload={"error": "upstream said no"}),
    ]
    ep = S.judged_episode(tmp_path, ledgers={"b": ledger})
    judge = _judge({"b": _world_reply()})
    _grade(tmp_path, ep, judge)

    prompt = _prompt_for(judge, "b")
    assert "MARKER-PCO6-ORACLE" in prompt, "the served `oracle` row was dropped from the judge's input"
    assert "MARKER-PCO6-REALERR" in prompt, "the `real-error` row was dropped from the judge's input"


def test_1224_judge_reads_a_real_error_row_and_an_adapter_cannot_load_fault_row_as_decided(
        tmp_path):
    """pco07_fault_and_real_error_rows_read — an erroring original query is a `real-error` row
    and an adapter that cannot load is a `fault` row; the judge reads each as such and no code
    computes a bucket from either.

    An erroring original query is a `real-error` row and an adapter that cannot load is a `fault`
    row; the judge reads each as such and no code computes a bucket from either (PCO-07,
    F-02=A). Today a `fault` row on the holding system makes the world ungradable by rule
    (family.py:1051); here the world whose only row is that `fault` row is graded by the model.
    """
    real_error = S.ledger_row(S.REAL_ERROR, params=S.query_params("user:MARKER-PCO7-REALERR"),
                              payload={"error": "502 from idp"})
    fault = S.ledger_row(S.FAULT, system="edr", params=S.query_params("host:MARKER-PCO7-FAULT"),
                         payload={"error": "the edr adapter could not load"}, label="c")
    ep = S.judged_episode(tmp_path, ledgers={"b": [real_error], "c": [fault]})
    judge = _judge({"b": _world_reply("analyze-discipline", ("idp",)),
                    "c": _world_reply("decision-discipline", ("edr",))})
    _grade(tmp_path, ep, judge)

    prompt_b, prompt_c = _prompt_for(judge, "b"), _prompt_for(judge, "c")
    assert "MARKER-PCO7-REALERR" in prompt_b, "the `real-error` row did not reach the judge"
    assert S.REAL_ERROR in prompt_b, "the erroring query did not reach the judge as `real-error`"
    assert "MARKER-PCO7-FAULT" in prompt_c, "the adapter-cannot-load row did not reach the judge"
    assert S.FAULT in prompt_c, "the adapter-cannot-load row did not reach the judge as `fault`"
    assert _row(ep, "b").get("bucket") == "analyze-discipline"
    assert _row(ep, "c").get("bucket") == "decision-discipline", (
        "a code rule decided the world with a `fault` row instead of the model")


def test_1224_judge_prompt_names_and_explains_passthrough_oracle_and_real_error(tmp_path):
    """pco08_judge_prompt_explains_words — the judge's rendered rows name each decision word and
    the judge prompt explains the three.

    The judge's rendered rows name each decision word (`passthrough`, `oracle`, `real-error`) and
    the judge prompt explains the three (PCO-08: none is defined to the model today). The
    rows' words are read from the world prompt; the explanation is host text, outside every
    untrusted frame.
    """
    ledger = [
        S.ledger_row(S.PASSTHROUGH, params=S.query_params("user:pco8-pass")),
        _oracle_row("user:pco8-oracle", claim=S.claim(changed=[
            S.changed("alice", "logon", "absent", "present")]),
            verdict={"passed": True, "reason": "ok"}),
        S.ledger_row(S.REAL_ERROR, params=S.query_params("user:pco8-error"),
                     payload={"error": "upstream said no"}),
    ]
    ep = S.judged_episode(tmp_path, ledgers={"b": ledger})
    judge = _judge({"b": _world_reply()})
    _grade(tmp_path, ep, judge)

    prompt = _prompt_for(judge, "b")
    host = S.outside_untrusted_frames(prompt)
    for word in (S.PASSTHROUGH, S.ORACLE_DECISION, S.REAL_ERROR):
        assert word in prompt, f"the rendered rows never name {word!r}"
        assert f"`{word}`" in host or f"{word}:" in host or f"{word} " in host, (
            f"the judge prompt never explains the decision word {word!r}")
