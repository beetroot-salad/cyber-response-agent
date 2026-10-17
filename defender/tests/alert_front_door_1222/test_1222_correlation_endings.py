"""The correlation lead's endings: each way `l-00c` fails or yields nothing is named in MAIN's
opening message outside any frame, and the run still closes."""
from __future__ import annotations

from defender.tests._spec1077 import fixture_run as _fixture_run_1165

import collections
import re
import shutil
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest

from defender.run_repository import RunPaths
from defender.tests import _invlang_warn_836 as W836
from defender.tests import _triplet_947 as T
from defender.tests.alert_front_door_1222 import _spec1222 as S

# The scene: one tenant, one alert, as many front-door drives as a test needs

#: A unique member value planted in the alert: the raw alert's own frame carries it, and "no alert
#: byte in the sentence" is asserted on it.
ALERT_MARK = "FD1222-S05-ALERT-MARK"
#: What every elastic search answers by default: one document (the real `search_envelope`).
ONE_DOC = {"@timestamp": "2026-05-25T15:20:00Z", "message": "sshd: Failed password for dev.dana"}
DONE = "Investigation complete."


def _alert() -> dict[str, Any]:
    return S.kibana_alert(fd1222_note=ALERT_MARK)


def _one_doc(system: str, verb: str, params: dict) -> Any:
    if system == "elastic" and verb in ("query", "alerts"):
        return S.envelope([ONE_DOC], index=params.get("index") or "logs-*")
    return {"system": system, "verb": verb, "result": []}


def _backend(*, fault: Any = T.CLEAN, exc: Callable[[], BaseException] = S.transport_fault,
             answer: Callable[[str, str, dict], Any] = _one_doc) -> S.Backend:
    return S.Backend(answer=answer, fault=fault, exc=exc)


def _q(i: int | str) -> S.Turn:
    """One of the correlation lead's own calls on its granted verb (`elastic.alerts`, TABLE_A),
    each with distinct params so the repeat guard never stands in for the fault under test."""
    return S.query("elastic", "alerts", {"native_query": f"host.name:office-ws-{i}"})


class _Scene:
    """A planted tenant under the current data root, driven through `run.main` as often as a
    test needs; every drive gets its own input dir and run id."""

    def __init__(self, tmp_path: Path, *, tenant_id: str = "acme", table: str = S.TABLE_ELASTIC,
                 root: Path | None = None, omit_systems: Sequence[str] = ()) -> None:
        self.tmp = Path(tmp_path)
        self.tenant = S.plant_tenant(tenant_id, root=root, alert_mapping=S.DEFAULT_MAPPING,
                                     table=table, omit_systems=omit_systems)
        self._n = 0

    def run(self, label: str, *, backend: S.Backend | None = None, **kw: Any) -> S.Drive:
        self._n += 1
        sub = self.tmp / f"{self.tenant.tenant_id}-{self._n:02d}-{label}"
        sub.mkdir(parents=True)
        kw.setdefault("tenant", self.tenant)
        kw.setdefault("run_id", f"fd1222-{self.tenant.tenant_id}-{label}-{self._n:02d}")
        return S.run_alert(sub, alert=_alert(), backend=backend if backend is not None
                           else _backend(), **kw)

    def control(self, **kw: Any) -> S.Drive:
        """The summary control: `l-00c` answered by its own default fake (C01, C38: usable)."""
        return self.run("summary", **kw)


# Reading MAIN's opening message

#: One entry of the workspace map's run-dir listing (`- name` / `- name dir/`): it differs between
#: two runs with whatever the lead left in the folder, so it is never part of a sentence.
_LISTING = re.compile(r"^- \S+(?: dir/)?$")


def _norm(d: S.Drive, text: str) -> str:
    assert d.run_dir is not None
    return S.normalize(text, run_dir=d.run_dir, run_id=d.run_dir.name)


def _prose(d: S.Drive) -> list[str]:
    """The opening message's harness prose — every closed frame removed, the run folder and id
    normalised — as stripped, non-blank lines."""
    return [ln.strip() for ln in _norm(d, S.harness_text(d.opening_message)).splitlines()
            if ln.strip()]


def _ending(d: S.Drive, control: S.Drive) -> str:
    """The sentence `d`'s opening message carries that the summary control's does not."""
    seen = set(_prose(control))
    return "\n".join(ln for ln in _prose(d) if ln not in seen and not _LISTING.match(ln))


def _frames(d: S.Drive) -> collections.Counter[str]:
    """The opening message's OUTERMOST frames' bodies, normalised (a summary persisted already
    framed and framed again is one correlation section, not two)."""
    return collections.Counter(_norm(d, body) for body in S.outer_frames(d.opening_message))


def _summary_frame(control: S.Drive, text: str = S.DEFAULT_CORRELATION_SUMMARY) -> str:
    """The control's correlation summary, framed in its opening message (A4) — the positive
    control every 'nothing framed beside the sentence' check is measured against."""
    found = [b for b in _frames(control) if text in b]
    assert len(found) == 1, (
        "the summary control's opening message does not carry l-00c's summary in exactly one "
        f"frame (A4: the lead runs to its end before the opening message is built); "
        f"frames carrying it: {len(found)}")
    return found[0]


def _frames_beside(d: S.Drive, control: S.Drive) -> list[str]:
    """Frames `d`'s opening message carries beyond the control's frames less its summary frame:
    framed lead output standing beside (or in place of) a sentence."""
    expected = _frames(control) - collections.Counter([_summary_frame(control)])
    extra = _frames(d) - expected
    missing = expected - _frames(d)
    assert not missing, f"frames the control carries are missing from this opening: {missing}"
    return list(extra.elements())


def _summary_frames(d: S.Drive, control: S.Drive) -> list[str]:
    """The frames `d`'s opening message carries beyond the control's frames less its summary
    frame: for a lead that wrote a usable summary, exactly that summary."""
    return _frames_beside(d, control)


def _roots(d: S.Drive) -> tuple[Path, ...]:
    assert d.tenant is not None
    return (d.tmp, d.tenant.root, S.DEFENDER, S.REPO_ROOT)


def _named(d: S.Drive, control: S.Drive, what: str) -> str:
    """The ending's sentence, asserted present and clean (no run folder, host path or alert
    text)."""
    sentence = _ending(d, control)
    assert sentence, (
        f"{what}: MAIN's opening message names no ending — its harness prose is the summary "
        "run's, line for line (A2: one fixed sentence outside the lead's frame; RC1: silent "
        "or late at base)")
    assert "<RUN_DIR>" not in sentence, f"{what}: the sentence names the run folder: {sentence!r}"
    assert not S.host_paths_in(sentence, *_roots(d)), (
        f"{what}: the sentence carries a host path: {sentence!r}")
    assert ALERT_MARK not in sentence, f"{what}: the sentence carries alert text: {sentence!r}"
    return sentence


def _alone(control: S.Drive, *named: tuple[str, S.Drive]) -> None:
    """Each named ending is the ONE correlation section: nothing the lead wrote is framed in its
    opening message beside (or in place of) the sentence."""
    for what, d in named:
        beside = _frames_beside(d, control)
        assert beside == [], (
            f"{what}: the opening message carries framed lead output beside the sentence "
            f"(exactly one correlation section, never both): {beside}")


def _assert_never_handed(d: S.Drive, *needles: str) -> None:
    """None of `needles` (fault text, a key, a host path, an earlier attempt's text) is anywhere
    MAIN was handed: its opening message or any later request's history."""
    handed = d.main.history_text + "\n" + d.opening_message
    leaked = [n for n in needles if n and n in handed]
    assert not leaked, f"MAIN was handed {leaked}"


def _assert_continued(d: S.Drive, what: str, *, requests: int | None = None) -> None:
    assert d.raised is None, f"{what}: the run raised {d.raised!r}"
    assert d.refusal is None, f"{what}: the run was refused: {d.refusal!r}"
    assert d.rc == 0, f"{what}: rc={d.rc!r}"
    if requests is not None:
        assert d.main.requests == requests, (
            f"{what}: MAIN made {d.main.requests} requests, its script asks {requests} — the run "
            "did not continue to MAIN's own end")
    assert not (d.summary or {}).get("truncated_by"), (
        f"{what}: the run was cut: {d.summary!r}")


def _assert_closed(d: S.Drive, what: str, disposition: str = "inconclusive") -> None:
    report = d.report
    assert report is not None, f"{what}: the run never wrote report.md ({d.summary!r})"
    meta, _body = S.sym("_frontmatter", "parse_frontmatter")(report)
    assert meta.get("disposition") == disposition, (
        f"{what}: report.md closes {meta.get('disposition')!r}, MAIN closed {disposition!r}")


def _stopped_loudly(d: S.Drive) -> bool:
    summary = d.summary or {}
    return (d.raised is not None or d.rc not in (0, None)
            or bool(summary.get("truncated_by")) or bool(summary.get("exit_reason")))


# Fault builders — each a REAL state or the shared fakes' data, each citing what observed it

def _secret_path(d_or_tmp: Path) -> str:
    return str(Path(d_or_tmp) / "host-secrets" / "creds.json")


def _runtime_error(detail: str) -> Callable[[], BaseException]:
    """PR-19 (executed): a `RuntimeError` in the correlation dispatch, silent at base."""
    return lambda: RuntimeError(detail)


def _preclaim(goal: str = "an earlier attempt's correlation goal",
              summary: str | None = None) -> Callable[[Path], None]:
    """`before=`: `l-00c`'s leads row already claimed in the run folder — through the REAL
    `claim_lead` (PR-28: a second claim over it collides) — and, optionally, that attempt's
    summary left where a gather summary is persisted."""
    def plant(run_dir: Path) -> None:
        claimed = S.sym("hooks.record_lead", "claim_lead")({
            "run_dir": str(run_dir), "lead_id": S.L3, "goal": goal,
            "what_to_summarize": ["what the earlier attempt measured"], "provenance": "harness"}, run=_fixture_run_1165(run_dir))
        assert claimed == S.sym("hooks.record_lead", "CLAIMED"), "the planted claim did not land"
        if summary is not None:
            path = Path(RunPaths(run_dir).gather_summary(S.L3))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(summary, encoding="utf-8")
    return plant


def _squat_leads_area(run_dir: Path) -> None:
    """`before=`: a regular file squats the leads area (`gather_raw`), so no leads-table row can
    be written there — `claim_lead` answers NOT_CLAIMED for any id (a real file state)."""
    leads = Path(RunPaths(run_dir).gather_raw)
    shutil.rmtree(leads)
    leads.write_text("not the leads table\n", encoding="utf-8")


#: An investigation.md the real validator refuses (`test_ungated_artifact_write_961_964`'s
#: executed `_ERROR_DOC`): `class` refined twice in one write. PR-33: over such a document the
_REFUSED_DOC = W836.PROLOGUE + W836.attr_block("l-001|v-001|class|bastion",
                                                "l-001|v-001|class|workstation")


def _undeclarable_investigation(run_dir: Path) -> None:
    """`before=`: the run's investigation.md is a document the validator refuses, so the
    harness cannot write `l-00c`'s declaring row into it (PR-33)."""
    Path(RunPaths(run_dir).investigation).write_text(_REFUSED_DOC, encoding="utf-8")


def _lead_session_refused_once(tmp_path: Path) -> Callable[..., Any]:
    """The store whose REAL `locked` fault — a second connection holds `BEGIN EXCLUSIVE`, so the
    real sqlite refuses `l-00c`'s session insert — is released the moment that one open has been
    refused (`S.store_factory(lead_session="once")`). The lead cannot start; MAIN's own writes to
    the store are healthy again afterwards (PR-14: the session open failing is silent at base)."""
    return S.store_factory(Path(tmp_path), lead_session="once")


def _pre_trip(system: str = "elastic") -> Callable[[Path], None]:
    """`before=`: the run's breaker already marks `system` down — written by the REAL
    `circuit_breaker.record_outcome` (two connectivity failures, exit 2), PR-19's pre-tripped
    breaker."""
    def plant(run_dir: Path) -> None:
        state = S.sym("runtime.run_state", "RunState")(run_dir, run_dir.name)
        plant.run_state = state
        record = S.sym("runtime.circuit_breaker", "record_outcome")
        for _ in range(S.sym("runtime.circuit_breaker", "PER_SYSTEM_FAIL_LIMIT")):
            record(state, system, 2)
        assert S.sym("runtime.circuit_breaker", "is_tripped")(state, system)
    return plant


def _fail_alerts(exc: Callable[[], BaseException]) -> S.Backend:
    """Every `elastic.alerts` call raises `exc()` — an adapter's own fault class."""
    return _backend(fault=T.Fault(fail_on=("elastic.alerts",)), exc=exc)


# O5 — each ending named to MAIN

def test_o5_withheld_correlation_is_named_in_the_opening_message(tmp_path: Path) -> None:
    """When the tenant's table withholds the correlation lead, the opening message's correlation section is the one fixed 'withheld' sentence: no correlation ran and none is coming, naming the table."""
    granting = _Scene(tmp_path)
    withholding = _Scene(tmp_path, tenant_id="acme-withheld", table=S.TABLE_WITHHELD)
    control = granting.control()
    d = withholding.run("withheld")

    sentence = _named(d, control, "withheld")
    assert "verb-grants.yaml" in sentence, (
        f"the withheld sentence does not name the table that withholds the lead: {sentence!r}")
    assert not d.router.dispatched(S.L3), "a withholding table still dispatched l-00c"
    assert not d.has_sidecar(S.L3), "a withholding table still claimed l-00c's leads row"
    _assert_continued(d, "withheld", requests=2)
    again = withholding.run("withheld-again")
    assert _ending(again, control) == sentence, "the withheld sentence is not fixed"


def test_o5_dispatch_that_raised_is_named_to_main(tmp_path: Path) -> None:
    """When l-00c's dispatch raises (a provider refusal included), MAIN's opening message carries the one fixed 'dispatch raised' sentence, outside the lead's frame, with no error text and no host path; the run continues."""
    scene = _Scene(tmp_path)
    control = scene.control()
    secret = _secret_path(tmp_path)
    refused = scene.run("refused", lead_faults={S.L3: S.LeadFault(raise_on=1,
                                                                  exc=S.provider_refusal)})
    crashed = scene.run("crashed", lead_faults={S.L3: S.LeadFault(raise_on=1, exc=_runtime_error(
        f"dispatch exploded reading {secret} with token sk-FD1222-LEAK-0001"))})

    sentence = _named(refused, control, "dispatch raised (provider refusal, PR-12)")
    assert _named(crashed, control, "dispatch raised (RuntimeError, PR-19)") == sentence, (
        "two dispatches that raised with different errors give different sentences — the "
        "sentence carries the error, not the ending")
    for d in (refused, crashed):
        assert d.router.requests(S.L3) >= 1, "the lead's model was never asked: no dispatch ran"
        _assert_never_handed(d, "request refused by provider", "dispatch exploded", secret,
                             "sk-FD1222-LEAK-0001")
        _assert_continued(d, "dispatch raised", requests=2)
    _alone(control, ("provider refusal", refused), ("RuntimeError", crashed))


def test_o5_l00c_claim_collision_is_named_to_main(tmp_path: Path) -> None:
    """When l-00c is already claimed on the run dir, MAIN's opening message says, in one fixed sentence, that correlation did not run because its claim collided; an earlier attempt's summary is never delivered as this one's."""
    scene = _Scene(tmp_path)
    control = scene.control()
    earlier = "FD1222-EARLIER-ATTEMPT-SUMMARY: 41 alerts on office-ws-1"
    collided = scene.run("collided", before=_preclaim(summary=earlier))
    collided_bare = scene.run("collided-bare", before=_preclaim(goal="another earlier goal"))
    claim_failed = scene.run("claim-failed", before=_squat_leads_area)

    sentence = _named(collided, control, "claim collided")
    assert _named(collided_bare, control, "claim collided (no earlier summary)") == sentence, (
        "the collision sentence varies with what the earlier attempt left")
    assert sentence != _named(claim_failed, control, "claim failed"), (
        "the collision is named with the claim-failure sentence: MAIN is not told the claim "
        "collided")
    _assert_never_handed(collided, earlier, "FD1222-EARLIER-ATTEMPT")
    assert not collided.router.dispatched(S.L3), "a collided claim still dispatched the lead"
    _assert_continued(collided, "claim collided", requests=2)
    _alone(control, ("claim collided", collided), ("claim collided, bare", collided_bare))


def test_o5_l00c_claim_that_failed_to_write_is_named_to_main(tmp_path: Path) -> None:
    """When a store fault keeps the lead from starting — its leads row or its declaring row cannot be written, or its session cannot be opened — MAIN's opening message names it in one fixed sentence (no citation instruction) and the run continues."""
    scene = _Scene(tmp_path)
    control = scene.control()
    leads_row = scene.run("leads-row", before=_squat_leads_area)
    declaring_row = scene.run("declaring-row", before=_undeclarable_investigation)
    session = scene.run("session", store_factory=_lead_session_refused_once(tmp_path))

    sentence = _named(session, control, "the lead's session cannot be opened")
    assert _named(leads_row, control, "the leads row cannot be written") == sentence, (
        "a leads row that cannot be written is not named with the claim-failed sentence")
    assert _named(declaring_row, control, "the declaring row cannot be written") == sentence, (
        "a declaring row that cannot be written is not named with the claim-failed sentence")
    assert ":L" not in sentence, (
        f"the claim-failed sentence instructs MAIN how to cite or declare l-00c: {sentence!r}")
    for label, d in (("leads row", leads_row), ("declaring row", declaring_row),
                     ("session", session)):
        assert not d.rows_for(S.L3), f"{label}: the lead ran calls though it never started"
        _assert_continued(d, label, requests=2)
    _alone(control, ("leads row", leads_row), ("declaring row", declaring_row),
           ("session", session))


def test_o5_correlation_cut_at_its_request_limit_is_named_outside_its_frame(
        tmp_path: Path) -> None:
    """A correlation lead stopped at its own request limit with no summary gets the one fixed 'request limit' sentence, outside the lead's untrusted frame (red at base: today the notice sits inside the frame, RC1)."""
    scene = _Scene(tmp_path)
    control = scene.control()
    over = S.CORRELATION_REQUEST_LIMIT + 4
    querying = scene.run("limit-querying", leads={S.L3: [_q(i) for i in range(over)]})
    listing = scene.run("limit-listing", leads={S.L3: [S.list_verbs("elastic")] * over})
    empty = scene.run("empty-output", leads={S.L3: [S.EMPTY_OUTPUT]})

    sentence = _named(querying, control, "request limit (querying)")
    assert _named(listing, control, "request limit (no backend call)") == sentence, (
        "the request-limit sentence varies with what the lead did before the limit")
    assert sentence != _named(empty, control, "empty output"), (
        "the request limit is named with another ending's sentence")
    for label, d in (("querying", querying), ("listing", listing)):
        assert d.router.requests(S.L3) == S.CORRELATION_REQUEST_LIMIT, (
            f"{label}: the lead was not stopped at its own request limit")
        _assert_continued(d, f"request limit ({label})", requests=2)
    _alone(control, ("request limit, querying", querying), ("request limit, listing", listing))


def test_o5_lead_that_yields_nothing_is_named_to_main(tmp_path: Path) -> None:
    """When l-00c ends with empty output, or issued at least one call and every call it issued failed (decided from the call results), MAIN's opening message carries the matching fixed sentence outside the lead's frame. A lead that issued no call and wrote a summary has produced a result (C38)."""
    scene = _Scene(tmp_path)
    control = scene.control()
    empty = scene.run("empty-output", leads={S.L3: [S.EMPTY_OUTPUT]})
    failed = scene.run("every-call-failed", backend=_fail_alerts(S.upstream_fault),
                       leads={S.L3: [_q(1), _q(2), S.text("FD1222-ECF-NARRATION")]})
    no_call = scene.run("no-call-summary",
                        leads={S.L3: [S.text("FD1222-NO-CALL-SUMMARY: nothing scoped")]})

    empty_sentence = _named(empty, control, "empty output")
    failed_sentence = _named(failed, control, "every call failed")
    assert empty_sentence != failed_sentence, (
        "empty output and every-call-failed are named with one sentence: MAIN is not told which")
    rows = failed.rows_for(S.L3)
    assert rows, "the every-call-failed scenario issued no call"
    assert all(r.get("exit_code") != 0 for r in rows), (
        f"the every-call-failed scenario did not fail every issued call: {rows}")
    _assert_never_handed(failed, "FD1222-ECF-NARRATION", "index_not_found_exception")
    # C38: a lead that issued no call and wrote a summary has produced a result.
    assert _ending(no_call, control) == "", (
        f"a no-call summary was named as an ending: {_ending(no_call, control)!r}")
    S.assert_wrapped_untrusted(no_call.opening_message, "FD1222-NO-CALL-SUMMARY",
                               "the no-call lead's summary")
    for d in (empty, failed, no_call):
        _assert_continued(d, "no summary", requests=2)
    _alone(control, ("empty output", empty), ("every call failed", failed))


def test_o5_tripped_breaker_is_named_to_main(tmp_path: Path) -> None:
    """When the breaker refused any of l-00c's calls, MAIN's sentence is 'tripped breaker' — telling MAIN that system is marked down for the run — and takes precedence over 'every call failed'; the sentence is unframed harness text, not the breaker's own message inside the lead's notice."""
    scene = _Scene(tmp_path)
    control = scene.control()
    # PR-14 / RJ-07: two connectivity failures trip `elastic`; the third call is refused.
    tripped = scene.run("tripped", backend=_fail_alerts(S.transport_fault),
                        leads={S.L3: [_q(1), _q(2), _q(3), S.text("FD1222-TB-NARRATION")]})
    pre_tripped = scene.run("pre-tripped", before=_pre_trip(),
                            leads={S.L3: [_q(1), S.text("FD1222-PT-NARRATION")]})
    two_failed = scene.run("two-failed", backend=_fail_alerts(S.transport_fault),
                           leads={S.L3: [_q(1), _q(2), S.text("FD1222-ECF-NARRATION")]})

    sentence = _named(tripped, control, "tripped breaker (own failures)")
    assert _named(pre_tripped, control, "tripped breaker (pre-tripped)") == sentence, (
        "the tripped-breaker sentence varies with how the system came to be marked down")
    assert sentence != _named(two_failed, control, "every call failed (no call refused)"), (
        "a refused call is named 'every call failed': the breaker does not take precedence")
    assert "elastic" in sentence, (
        f"the tripped-breaker sentence does not tell MAIN which system is down: {sentence!r}")
    assert tripped.run_dir is not None
    down = S.sym("runtime.circuit_breaker", "down_message")(tripped.run_state, "elastic")
    _assert_never_handed(tripped, down, "FD1222-TB-NARRATION", "docker exec curl timed out")
    _assert_continued(tripped, "tripped breaker", requests=2)
    _alone(control, ("tripped breaker", tripped), ("pre-tripped", pre_tripped))


def test_o5_timed_out_correlation_is_named_to_main(tmp_path: Path) -> None:
    """A lead still running at the correlation deadline ends as 'timed out': MAIN's opening message carries that fixed sentence and never a summary that arrives after the deadline; queries rows of calls that completed stay recorded."""
    scene = _Scene(tmp_path)
    control = scene.control()
    # MAIN answers once: at base the lead is a background task MAIN's SECOND request awaits, so a
    # one-request MAIN keeps a hung lead from holding the test for HANG_S there.
    hung = scene.run("hung", limits=S.with_deadline(), main=[S.text(DONE)],
                     leads={S.L3: [_q(1), S.text("FD1222-LATE-SUMMARY-HUNG")]},
                     lead_faults={S.L3: S.LeadFault(hang=True, hang_from=2)})
    late = scene.run("late", limits=S.with_deadline(), main=[S.text(DONE)],
                     leads={S.L3: [S.text("FD1222-LATE-SUMMARY-DELAYED")]},
                     lead_faults={S.L3: S.LeadFault(delay=S.SHORT_DEADLINE_S + 2.0)})
    raised = scene.run("raised", lead_faults={S.L3: S.LeadFault(raise_on=1,
                                                                exc=S.provider_refusal)})

    sentence = _named(hung, control, "timed out (hung request)")
    assert _named(late, control, "timed out (late response)") == sentence, (
        "the timed-out sentence varies with how the lead overran its deadline")
    assert sentence != _named(raised, control, "dispatch raised"), (
        "a lead cut at its deadline is named with the dispatch-raised sentence")
    _assert_never_handed(hung, "FD1222-LATE-SUMMARY-HUNG")
    _assert_never_handed(late, "FD1222-LATE-SUMMARY-DELAYED")
    completed = [r for r in hung.rows_for(S.L3) if r.get("exit_code") == 0]
    assert completed, (
        f"the call l-00c completed before its deadline left no queries row: {hung.rows}")
    _assert_continued(hung, "timed out", requests=1)
    _alone(control, ("timed out, hung", hung), ("timed out, late", late))


# O6 — every named ending reaches a normal close

def _o6_scenario(ending: str, tmp_path: Path, withheld: _Scene) -> dict[str, Any]:  # noqa: C901, PLR0911 — one arm per named ending
    if ending == "withheld":
        return {"scene": withheld}
    if ending == "dispatch_raised":
        return {"lead_faults": {S.L3: S.LeadFault(raise_on=1, exc=S.provider_refusal)}}
    if ending == "claim_collided":
        return {"before": _preclaim()}
    if ending == "claim_failed":
        return {"store_factory": _lead_session_refused_once(tmp_path)}
    if ending == "request_limit":
        return {"leads": {S.L3: [_q(i) for i in range(S.CORRELATION_REQUEST_LIMIT + 4)]}}
    if ending == "tripped_breaker":
        return {"backend": _fail_alerts(S.transport_fault),
                "leads": {S.L3: [_q(1), _q(2), _q(3), S.text("narration")]}}
    if ending == "empty_output":
        return {"leads": {S.L3: [S.EMPTY_OUTPUT]}}
    if ending == "every_call_failed":
        return {"backend": _fail_alerts(S.upstream_fault),
                "leads": {S.L3: [_q(1), _q(2), S.text("narration")]}}
    if ending == "timed_out":
        # A late response, never a hang: MAIN closes in three requests, and at base its second
        # request awaits the lead.
        return {"limits": S.with_deadline(), "leads": {S.L3: [S.text("late")]},
                "lead_faults": {S.L3: S.LeadFault(delay=S.SHORT_DEADLINE_S + 2.0)}}
    if ending == "down_at_start":
        # #1256 O-6: elastic has no config.env, so it is down from run start; cmdb stays usable.
        return {"scene": _Scene(tmp_path, tenant_id="acme-down", omit_systems=("elastic",)),
                "leads": {S.L3: [_q(1), _q(2), S.text("narration")]}}
    raise AssertionError(f"not an A2 ending: {ending!r}")


#: A2's named endings, plus #1256's: l-00c on a system down at run start (O-6) is a named non-run
#: that never refuses the run.
O6_ENDINGS = (*S.ENDINGS, "down_at_start")


@pytest.mark.parametrize("ending", O6_ENDINGS)
def test_o6_every_named_non_run_reaches_report_md(tmp_path: Path, ending: str) -> None:
    """Every named ending A2 lists — withheld, dispatch raised, claim collided, claim failed, request limit, tripped breaker, empty output, every call failed, timed out — and #1256's down at start (O-6: never a run refusal) continues to a normal close and writes report.md."""
    granting = _Scene(tmp_path)
    withheld = _Scene(tmp_path, tenant_id="acme-withheld", table=S.TABLE_WITHHELD)
    spec = _o6_scenario(ending, tmp_path, withheld)
    scene = spec.pop("scene", granting)
    d = scene.run(ending.replace("_", "-"), main=S.closing_main_turns("inconclusive"), **spec)

    assert d.raised is None, f"{ending}: the run raised {d.raised!r}"
    assert d.refusal is None, f"{ending}: the run was refused: {d.refusal!r}"
    assert d.rc == 0, f"{ending}: rc={d.rc!r}"
    _assert_closed(d, ending)
    assert not (d.summary or {}).get("truncated_by"), f"{ending}: the run was cut: {d.summary}"
    # The case really was a named non-run, not a summary that slipped through.
    control = granting.control()
    _named(d, control, ending)


# The fork and settled premises on the endings

def test_p005_l00c_session_cannot_be_opened(tmp_path: Path) -> None:
    """A session store that refuses to open l-00c's gather session after the claim is one of the lead's own named endings (A2: a store fault that keeps the lead from starting): MAIN's opening message carries its fixed sentence and the run continues; a later reader sees the claimed row; MAIN's own first write to the same store then stops the run loudly."""
    scene = _Scene(tmp_path)
    control = scene.control()
    refused = scene.run("session-refused", store_factory=_lead_session_refused_once(tmp_path))
    leads_row = scene.run("leads-row", before=_squat_leads_area)

    sentence = _named(refused, control, "the lead's session cannot be opened")
    assert _named(leads_row, control, "claim failed (leads row)") == sentence, (
        "a session that cannot be opened is not named with the lead's claim-failed sentence")
    _assert_continued(refused, "the lead's session cannot be opened", requests=2)
    assert refused.run_dir is not None
    leads = S.sym("learning.lead_repository", "load_leads")(refused.run_dir)
    assert S.L3 in leads, f"a later reader does not see l-00c's claimed row: {sorted(leads)}"
    assert leads[S.L3].get("goal"), f"l-00c's claimed row reads back without its goal: {leads}"
    _alone(control, ("session refused", refused))

    # The same store refusing every write (the shared fake's real `corrupt` state): the lead's
    # own ending first, then MAIN's own first write stops the run, loudly and through the store.
    broken = scene.run("store-broken", store_factory=S.store_factory(
        tmp_path / "store-broken", lead_session=True))
    assert broken.raised is None, f"the store fault escaped the run: {broken.raised!r}"
    assert (broken.summary or {}).get("truncated_by") == S.sym(
        "runtime.run_end", "TRUNCATED_BY_STORE"), (
        f"MAIN's first write to the broken store did not stop the run through the store: "
        f"{broken.summary!r}")
    assert broken.run_dir is not None
    assert S.L3 in S.sym("learning.lead_repository", "load_leads")(broken.run_dir), (
        "the claimed l-00c row is gone after the store refused its session")


def test_p008_l00c_own_failures_trip_its_system(tmp_path: Path) -> None:
    """l-00c's own failures mark its system down for the run; once the breaker refuses any of its calls MAIN's sentence is 'tripped breaker', telling MAIN that system is marked down for the run."""
    scene = _Scene(tmp_path)
    control = scene.control()
    main_lead = S.query("elastic", "alerts", {"native_query": "FD1222-MAIN-L001-QUERY"})
    d = scene.run("own-failures", backend=_fail_alerts(S.transport_fault),
                  main=[S.gather("l-001", "elastic"), S.text(DONE)],
                  leads={S.L3: [_q(1), _q(2), _q(3), S.text("narration")],
                         "l-001": [main_lead, S.text("l-001 summary")]})
    reference = scene.run("pre-tripped", before=_pre_trip(),
                          leads={S.L3: [_q(1), S.text("narration")]})

    sentence = _named(d, control, "tripped by l-00c's own failures")
    assert sentence == _named(reference, control, "tripped breaker (reference)"), (
        "l-00c's own failures tripped its system but MAIN's sentence is not 'tripped breaker'")
    assert "elastic" in sentence, f"the sentence does not name the system marked down: {sentence!r}"
    assert d.run_dir is not None
    assert S.sym("runtime.circuit_breaker", "is_tripped")(d.run_state, "elastic"), (
        "l-00c's own failures did not mark its system down for the run")
    reached = [c for c in d.backend.rec.calls
               if c.params.get("native_query") == "FD1222-MAIN-L001-QUERY"]
    assert not reached, "MAIN's own lead on the system l-00c marked down reached the backend"
    assert not d.rows_for("l-001"), "MAIN's own lead on the downed system wrote queries rows"
    _alone(control, ("tripped by its own failures", d))


def test_p029_l00c_claimed_but_its_declaring_row_refused(tmp_path: Path) -> None:
    """When l-00c's declaring row cannot be written, correlation does not run and MAIN's sentence says its claim could not be recorded, with no citation instruction; the validator still refuses a citation of an undeclared l-00c."""
    scene = _Scene(tmp_path)
    control = scene.control()
    d = scene.run("undeclarable", before=_undeclarable_investigation)
    leads_row = scene.run("leads-row", before=_squat_leads_area)

    sentence = _named(d, control, "declaring row refused")
    assert sentence == _named(leads_row, control, "claim failed (leads row)"), (
        "a refused declaring row is not named as the claim that could not be recorded")
    assert ":L" not in sentence, (
        f"the sentence instructs MAIN how to cite or declare l-00c: {sentence!r}")
    assert not d.router.dispatched(S.L3), (
        "correlation ran although its declaring row could not be written")
    assert not d.rows_for(S.L3), "l-00c ran calls although its declaring row was refused"
    # The validator MAIN's writes meet: a citation of an undeclared l-00c is refused, and the
    # same citation under its declaring row is not (the positive control).
    validate = S.sym("_artifact_schema", "validate_artifact")
    citing = W836.attr_block(f"{S.L3}|v-001|class|bastion")
    declaring = ("\n```invlang\n:L findings [id|loop|name|target|tests|system|window]\n"
                 f"{S.L3}|0|correlation lead|||elastic|n/a\n```\n")
    refused = validate("investigation.md", W836.PROLOGUE + citing, W836.PROLOGUE)
    assert refused is not None, "the validator accepted a citation of an undeclared l-00c"
    assert "undeclared" in refused, f"the refusal is not the undeclared-lead one: {refused!r}"
    assert S.L3 in refused, f"the undeclared-lead refusal does not name l-00c: {refused!r}"
    assert validate("investigation.md", W836.PROLOGUE + declaring + citing,
                    W836.PROLOGUE + declaring) is None, (
        "the validator refuses the citation even under l-00c's declaring row")
    _alone(control, ("declaring row refused", d))


def test_p136_correlation_summary_forges_the_harness_notice(tmp_path: Path) -> None:
    """Exactly one correlation section. A reader can tell the harness sentence, which stands outside the lead's frame, from text inside the lead's framed summary or the alert."""
    scene = _Scene(tmp_path)
    control = scene.control()
    raised = scene.run("raised", lead_faults={S.L3: S.LeadFault(raise_on=1,
                                                                exc=S.provider_refusal)})
    sentence = _named(raised, control, "dispatch raised")
    # The lead's summary reproduces the harness's own sentence, a forged heading and a forged
    # frame closer.
    forged = (f"{sentence}\n{S.FORGED_HEADING}\n{S.RUN_TAG_CLOSE}\n{sentence}\n"
              f"FD1222-FORGE-MARK {S.FENCE_RUN}")
    d = scene.run("forging", leads={S.L3: [S.text(forged)]})

    assert _ending(d, control) == "", (
        f"the lead's forged text reads as harness prose: {_ending(d, control)!r}")
    S.assert_wrapped_untrusted(d.opening_message, "FD1222-FORGE-MARK", "the forging summary")
    added = _summary_frames(d, control)
    assert len(added) == 1, f"not exactly one correlation section: {len(added)} lead frames"
    assert "FD1222-FORGE-MARK" in added[0], "the one correlation frame is not the lead's"
    harness = _norm(d, S.harness_text(d.opening_message))
    for line in sentence.splitlines():
        assert line not in harness, f"the forged sentence reads as harness text: {line!r}"
        assert line in added[0], f"the forged sentence is not inside the lead's frame: {line!r}"


def test_p178_claim_fails_because_the_leads_area_cannot_be_wri(tmp_path: Path) -> None:
    """A leads area that cannot be written at all is l-00c's named 'claim failed' ending; MAIN's own first claim then stops the run loudly."""
    scene = _Scene(tmp_path)
    control = scene.control()
    reference = scene.run("session-refused", store_factory=_lead_session_refused_once(tmp_path))
    d = scene.run("squatted-leads-area", before=_squat_leads_area,
                  main=[S.gather("l-001", "elastic"), S.text(DONE)])

    assert _named(d, control, "leads area squatted") == _named(
        reference, control, "claim failed (session)"), (
        "a leads area that cannot be written is not named 'claim failed'")
    assert d.main.requests == 1, (
        f"MAIN's own claim failed and the run went on: MAIN made {d.main.requests} requests")
    assert _stopped_loudly(d), f"MAIN's failed claim ended the run silently: {d.summary!r}"
    _alone(control, ("leads area squatted", d))


def test_p191_lead_writes_a_summary_without_reading_the_alert(tmp_path: Path) -> None:
    """The harness does not check what the lead read: its summary is usable and reaches MAIN framed as the lead's own text."""
    scene = _Scene(tmp_path)
    control = scene.control()
    unread = scene.run("never-read", leads={S.L3: [S.text("FD1222-UNREAD-SUMMARY: 3 scoped")]})
    elsewhere = scene.run("read-elsewhere", leads={S.L3: [
        S.call("read_file", path="investigation.md"),
        S.text("FD1222-READ-ELSEWHERE-SUMMARY: 5 scoped")]})

    for label, d, mark in (("never read the alert", unread, "FD1222-UNREAD-SUMMARY"),
                           ("read only another file", elsewhere,
                            "FD1222-READ-ELSEWHERE-SUMMARY")):
        assert mark in d.opening_message, (
            f"{label}: the lead's summary is not in MAIN's opening message (A4)")
        added = _summary_frames(d, control)
        assert len(added) == 1, (
            f"{label}: {len(added)} lead frames in MAIN's opening — not one correlation section")
        assert mark in added[0], (
            f"{label}: the lead's summary is not the framed correlation section of MAIN's "
            "opening message")
        S.assert_wrapped_untrusted(d.opening_message, mark, f"{label}: the lead's summary")
        assert _ending(d, control) == "", (
            f"{label}: a summary was named as an ending: {_ending(d, control)!r}")
