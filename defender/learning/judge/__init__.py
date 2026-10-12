"""The family judge: grades an archived branched episode against each world's contrast (#1234).

`grade_episode` is called by `learning/branch/cli.py` after the archive step, and is also
callable directly without the launcher.

The judge MODEL files findings; code routes them (P-c). Flow, per episode:
1. The gates: a non-positive `JUDGE_DRAWS` is refused naming the knob, before anything else; a
   world or the family row a stopped pass left `queueing` refuses the re-run naming it (A6);
   a manifest predating the oracle is stamped not-graded (O15, ahead of the outcome gate);
   pre-flight's `outcome.yaml` must say `accepted`; O5 counts the failed worlds; the family
   stamp must certify the siblings comparable; the control must be usable (A3).
2. `runs.read_run_set` — every run through the one usability read (`family.read_world`).
3. Per planted world, in manifest order, unless its row is already `queued`: `render.render`
   + `render.world_sections` (A9's cap) + `run._build_prompt`; one model call per draw through
   the injected `judge=` seam, each reply through `run.validate_reply` (a refused reply is asked
   again within `_REPLY_ATTEMPTS`; a failed call is not), written to `worlds/<X>/judge/<n>.yaml`;
   then `route.combine_draws` (A7) and `route.fate` per filed finding (A13); the world's rows
   are committed `queueing` -> append through `state=` -> `queued` (A6).
4. The family call, once (a `queued` family row is final): every usable run's computed
   sections (`render.family_sections`), family-scope world findings only, combined by union,
   committed the same way.
5. `judge.yaml` written last with the user record's found gaps recomputed (A2).
"""

from __future__ import annotations

import json
import logging
from dataclasses import field, fields as dataclass_fields
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any

from pydantic import AfterValidator, TypeAdapter, ValidationError


# `JudgeRefused` lives in `_errors.py` to avoid an import cycle; re-exported here.
from defender._model import model  # noqa: E402
from defender.learning.core.state import FINDINGS, QUESTIONER_FINDINGS, LearningState  # noqa: E402
from defender.learning.core.retired import (  # noqa: E402
    RETIRED_LANES,
    retired_keys,
    retired_row_names,
)
from defender.learning.judge._errors import JudgeRefused  # noqa: E402

from defender._episode_handle import Episode  # noqa: E402
from defender._io import Bound, NotPlainEntry, bind  # noqa: E402
from defender.run_repository import WIRE_LOG_NAMES  # noqa: E402
from defender._episode_paths import LAYOUT  # noqa: E402
from defender.learning.branch import outcome as outcome_mod  # noqa: E402
from defender.learning.judge import calls as calls_mod  # noqa: E402
from defender.learning.judge import enqueue as enqueue_mod  # noqa: E402
from defender.learning.judge import family as family_mod  # noqa: E402
from defender.learning.judge import render as render_mod  # noqa: E402
from defender.learning.judge import route as route_mod  # noqa: E402
from defender.learning.judge import run as run_mod  # noqa: E402
from defender.learning.judge.runs import RunSet, failed_row, read_run_set  # noqa: E402
from defender.runtime.branch._family import ManifestPredatesOracle  # noqa: E402
from defender import _yaml

if TYPE_CHECKING:
    from defender.run_repository import RunsRepository

_logger = logging.getLogger(__name__)

#: The judge's own operator knobs — no `DEFENDER_` prefix, matching `QUESTIONER_EFFORT`. Model
#: and effort are read through `config.judge_model`/`judge_effort`, not spelled here.
DRAWS_KNOB = "JUDGE_DRAWS"
CAP_KNOB = "JUDGE_PAYLOAD_CAP"

#: The not-graded stamp's word for a manifest the judge cannot read as a family of this design (O15).
MANIFEST_REFUSED = "manifest refused"
#: The stamp's word for an `accepted` family with no readable family stamp.
NOT_COMPARABLE = outcome_mod.NOT_COMPARABLE
#: The stamp's word for a family whose control run is not usable (A3): every contrast is
#: against the control, so no world is judged.
CONTROL_UNUSABLE = "control unusable"

#: `judge.yaml`'s `validity` (O5, M19=A): its own field, never a family word.
USABLE, UNUSABLE = "usable", "unusable"

#: A world row's and the family row's commit state (A6): written `queueing` before the row's
#: findings are appended, `queued` after. No key: the row completed no draw (re-graded).
STATE_KEY = "state"
QUEUEING, QUEUED = "queueing", "queued"
#: The family call's label: its draw directory, agent ids and finding ids.
FAMILY_LABEL = "family"

#: The user record's lists (design M7, A2, A7; R1 (c)). `gap_findings` holds the findings
#: whose resolving conduct pointers are all blocked calls (gap-only, A1): beside the serving
#: findings, never inside them.
NAMED_GAPS, FOUND_GAPS = "named_gaps", "found_gaps"
SERVING_FINDINGS, UNKEYED_NAMED_GAPS, GAP_FINDINGS = (
    "serving_findings", "unkeyed_named_gaps", "gap_findings")
_USER_LISTS = (NAMED_GAPS, FOUND_GAPS, SERVING_FINDINGS, UNKEYED_NAMED_GAPS, GAP_FINDINGS)

#: How many times one draw asks again after a reply the validator refused (N22: an invalid
#: reply is retried as a whole). A failed CALL is not retried here — the model client already
#: retried it (M03), and a bare re-run grades the world later.
_REPLY_ATTEMPTS = 3


def _judge_model() -> str:
    """The judge's model, through `config`'s accessor so the default lives in one place."""
    from defender.learning.core.config import judge_model

    return judge_model()


def _judge_effort() -> str:
    from defender.learning.core.config import judge_effort

    return judge_effort()


def _judge_draws() -> int:
    from defender._env import env_int

    return env_int(DRAWS_KNOB, 1)


def _judge_cap() -> int:
    from defender._env import env_int

    return env_int(CAP_KNOB, 20000)


@model
class NotGradedStamp:
    """Why the pass declined to grade an episode: the word it stopped on and its reason."""

    outcome: str
    reason: str


def _ledger_entries_name_a_lane(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """What the record asks of a ledger entry is what its writer asks
    (`enqueue.check_disposition_entry`): it names its finding and takes one of the lanes."""
    for entry in entries:
        enqueue_mod.check_disposition_entry(entry)
    return entries


def _rows_name_their_world(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The one thing the record asks of a world row beyond being a mapping: it names its world.
    Every other key belongs to the row's declared owners and is carried as written."""
    for row in rows:
        if not isinstance(row.get("world"), str):
            raise ValueError(f"a world row does not name its world: {row!r}")
    return rows


def _empty_user() -> dict[str, list[dict[str, Any]]]:
    return {name: [] for name in _USER_LISTS}


@model
class EpisodeGrade:
    """`grade_episode`'s return value and the schema of `judge.yaml`, in both directions.

    Strict (no coercion), so a document of the wrong shape fails at the constructor.
    `episode_dir` and `graded_worlds` are derived: never written, recomputed from the rows on
    every read (`_DERIVED`).

    Each world row carries its combined draws (`route.combine_draws`: `bucket`, `systems`,
    `draws`, `measured`, `not_measured_reason`, `draws_disagree`, `world_label_doubted`),
    `completed_draws`/`malformed_replies`, and its commit `state` (A6); a world that could not
    be judged carries `ungradable` and its reason instead. `family` is the family call's own
    row; `user` the user record (named, found, serving, unkeyed and gap-only entries);
    `dispositions` the ledger — one `{finding_id, lane, reason}` per filed finding (A13).
    """

    episode_dir: Path
    worlds: Annotated[list[dict[str, Any]], AfterValidator(_rows_name_their_world)] = field(
        default_factory=list)
    graded_worlds: frozenset[str] = field(default_factory=frozenset)
    #: O5's verdict on the family (M19=A): `usable`, `unusable`, or `None` where the pass never
    #: counted (a manifest refusal, an outcome other than `accepted`/`unusable`).
    validity: str | None = None
    family: dict[str, Any] | None = None
    user: dict[str, list[dict[str, Any]]] = field(default_factory=_empty_user)
    #: The ledger, in walk order. `None` for a `not_graded` stamp; a pass that walked nothing
    #: writes `[]`.
    dispositions: Annotated[list[dict[str, Any]],
                            AfterValidator(_ledger_entries_name_a_lane)] | None = None
    enqueued_rows: int = 0
    enqueued_to: str = ""
    world_enqueued_rows: int = 0
    world_enqueued_to: str = ""
    draws: dict[str, int] = field(default_factory=dict)
    knobs: dict[str, Any] = field(default_factory=dict)
    lessons_commit: str | None = None
    not_graded: NotGradedStamp | None = None


#: Fields not written to the file: the path, and the set re-derived from the rows so no
#: top-level list can disagree with them.
_DERIVED = frozenset({"episode_dir", "graded_worlds"})


def _known_keys(record: type, doc: dict[Any, Any]) -> dict[Any, Any]:
    """`doc` minus string keys the schema does not name, so a newer (or older) record still
    reads. A reader-side tolerance only: `@model` still refuses unknown keywords at
    construction. A non-string key is kept, for the constructor's own `TypeError`."""
    names = {f.name for f in dataclass_fields(record)}
    return {k: v for k, v in doc.items() if not isinstance(k, str) or k in names}


def _existing_grade(episode_dir: Path) -> dict[str, Any] | None:
    # Screened read: this is the idempotency record in a box-reachable tree, and a planted one
    # would stop the pass from ever running. Nothing at the name is an ordinary ungraded episode.
    with bind(Path(episode_dir)) as bound:
        return family_mod.screened_yaml_mapping(bound, LAYOUT.judge, what="the family grade")


def _gate(bound: Bound) -> tuple[str, str, dict[str, Any] | None, dict[str, dict[str, Any]]]:
    """Pre-flight's outcome word and reason, the record itself, and every world O5 counts as
    failed. An absent, empty or torn record is the "no record" state (`outcome.NO_RECORD`):
    never `accepted`, its reason naming the missing record (M05=A, PCO-02)."""
    try:
        record = outcome_mod.read_outcome(bound)
    except outcome_mod.OutcomeUnreadable as missing:
        return outcome_mod.NO_RECORD, str(missing), None, {}
    return (str(record["outcome"]), record["reason"], record,
            outcome_mod.failed_worlds(bound, record))


def _run_world_draws(  # noqa: C901, PLR0913 — one loop over draws and their bounded re-asks
    episode: Episode, label: str, *, judge: Any, draws: int, model: str, effort: str,
    prompt: str, scope: str = "world", served_systems: list[str] | None = None,
    shown_its_facts: bool | None = None,
) -> tuple[int, dict[int, dict[str, Any]], int, str | None]:
    """Call the judge `draws` times over `prompt`, writing one `worlds/<X>/judge/<n>.yaml` per
    draw. Returns `(completed_draws, draw documents by index, malformed replies, the last
    refusal's reason)`.

    A failed call writes a draw record naming its failure and is not asked again. A reply the
    validator refuses is counted and asked again, up to `_REPLY_ATTEMPTS` asks per draw; a draw
    whose every ask was refused writes nothing. Documents are returned, not read back: the pass
    routes what it just produced, never a stale file from an earlier attempt."""
    from defender.learning.core.config import StageWiring
    from defender.runtime.agent_role import AgentRole

    world = episode.world(label)
    completed = 0
    documents: dict[int, dict[str, Any]] = {}
    malformed = 0
    refusal: str | None = None
    for n in range(draws):
        doc: dict[str, Any] | None = None
        for attempt in range(_REPLY_ATTEMPTS):
            agent_id = f"judge:{label}:{n}" if attempt == 0 else f"judge:{label}:{n}:{attempt}"
            wiring = StageWiring(
                prompt_path=run_mod._ROLE_PROMPT, model=model, effort=effort,
                trace_name=WIRE_LOG_NAMES.agent_trace(agent_id), label=agent_id)
            try:
                reply_text = judge(prompt, role=AgentRole.JUDGE, agent_id=agent_id,
                                   wiring=wiring)
            # Every class: `run_stage` re-raises `StageAbort`/`FatalConfigError` unwrapped and
            # an injected seam may raise anything; one bad call must not discard the other
            # worlds.
            except Exception as failed:  # noqa: BLE001 — one draw's blast radius
                doc = {"failure_reason": f"{type(failed).__name__}: {failed}"}
                _write_wire_log(episode, agent_id=agent_id, prompt=prompt,
                                reply=None, failure=f"{type(failed).__name__}: {failed}")
                break
            _write_wire_log(episode, agent_id=agent_id, prompt=prompt,
                            reply=reply_text, failure=None)
            try:
                reply = run_mod.validate_reply(reply_text, scope=scope,
                                               served_systems=served_systems,
                                               shown_its_facts=shown_its_facts)
            except JudgeRefused as refused:
                malformed += 1
                refusal = str(refused)
                continue
            doc = run_mod.draw_document(reply, scope=scope)
            completed += 1
            break
        if doc is None:
            # Every ask refused: nothing is written (the raw replies are on the wire log), and
            # an earlier pass's file at this index is removed so the page never shows it as
            # this pass's.
            try:
                world.draw(n).delete()
            except NotPlainEntry as stuck:
                _logger.warning(f"world {label!r}: the earlier draw {world.draw(n).path.name} "
                                f"was not removed ({stuck})")
            continue
        documents[n] = doc
        # Not contained: a link planted at this sink refuses the pass.
        world.draw(n).write(_yaml.safe_dump(doc, sort_keys=False))
    return completed, documents, malformed, refusal


def _write_wire_log(
    episode: Episode, *, agent_id: str, prompt: str, reply: str | None, failure: str | None,
) -> None:
    """The judge's wire-log record — the whole framed prompt and reply verbatim, one file per
    call, under `wire_logs/` so the existing wire-log policy denial covers it. Written here
    because the injected `judge=` seam carries no logger. Its own file name, never the
    wiring's `trace_name` (which `run_stage` streams to)."""
    name = WIRE_LOG_NAMES.agent_framed_trace(agent_id)
    row = {"agent_id": agent_id, "prompt": prompt, "reply": reply, "failure": failure,
           "wire_log_written_at": name}
    # Best-effort: a planted link (`OSError`) or an unserialisable reply (`TypeError`) here
    # must not cost the grade.
    try:
        episode.wire_log(name).write(json.dumps(row) + "\n")
    except Exception as unwritable:  # noqa: BLE001 — observability, never the grade
        _logger.warning(f"the wire log for {agent_id} could not be written ({unwritable!r}); the "
                        "draw itself is unaffected")


def _stamp_not_graded(episode: Episode, word: str, reason: str, *, validity: str | None = None,
                      worlds: list[dict[str, Any]] | None = None) -> EpisodeGrade:
    """Write and return a not-graded record: no model call, no findings."""
    record = EpisodeGrade(episode_dir=episode.dir, validity=validity, worlds=worlds or [],
                          not_graded=NotGradedStamp(outcome=word, reason=reason))
    _write_judge_yaml(episode, record)
    return record


def _default_judge_seam(episode_dir: Path) -> Any:
    """The production `(prompt, *, role, agent_id, wiring) -> str` for every judge call:
    `run_stage` under the judge's own deny-all role. `wiring` comes from the caller.

    `deps=JudgeDeps()` decides the role (`build_stage_agent` reads `type(deps).role`); the
    `role` kwarg is ignored. Imports are inside `invoke` so passes that never call the model
    skip the provider import."""
    def invoke(prompt: str, *, role: Any = None, agent_id: str = "judge", wiring: Any = None,
               **_kw: Any) -> str:
        from defender.learning._pydantic_stage import run_stage
        from defender.learning.core.config import StageContext, subagent_timeout
        from defender.learning.judge.run import JudgeDeps

        if wiring is None:
            raise JudgeRefused(
                f"the judge seam was called for {agent_id!r} with no StageWiring — the model, "
                "the effort and the trace name all arrive on it, so there is nothing to call")
        return run_stage(
            stage="judge", wiring=wiring,
            ctx=StageContext(learning_run_dir=Path(episode_dir), user=prompt, request_limit=1,
                             wall_clock_timeout=subagent_timeout()),
            deps=JudgeDeps(),
        )

    return invoke


def grade_episode(  # noqa: PLR0913 — the orchestration's whole configuration surface
    runs: RunsRepository, episode_id: str, *, judge: Any = None,
    state: LearningState, draws: int | None = None, git_show: Any = None,
) -> EpisodeGrade:
    """Grade episode `episode_id` of `runs`'s tenant (#1105 PR 2: the judge takes the
    repository and an id). Its door is `runs.episode_files(episode_id)`, held for the whole
    pass: a bad id, an unusable episodes root, a missing episode, a file at its name, or a
    container whose record names another tenant (or none) is `JudgeRefused`, and nothing is
    created. Every queue append goes through `state`."""
    import yaml

    configured = draws if draws is not None else _judge_draws()
    if configured < 1:
        # Before anything else: a pass with no draw would commit every world with nothing.
        raise JudgeRefused(f"{DRAWS_KNOB}={configured}: the number of judge draws per world must "
                           "be a positive integer")
    try:
        with _open_episode(runs, episode_id) as episode:
            resolved_judge = judge if judge is not None else _default_judge_seam(episode.dir)
            return _grade_episode(episode, judge=resolved_judge, draws=configured,
                                  git_show=git_show, state=state)
    except JudgeRefused:
        raise
    # Every input-driven failure arrives as `JudgeRefused`, which is what the launcher catches.
    except (OSError, ValueError, TimeoutError, yaml.YAMLError) as bad:
        raise JudgeRefused(f"episode {episode_id}: {bad!r}") from bad


def _open_episode(runs: RunsRepository, episode_id: str) -> Episode:
    """The pass's one handle, through the judge's door. A missing episode is refused, never
    recreated by the not-graded stamp."""
    from defender._tenant import TenantRefused

    try:
        return runs.episode_files(episode_id)
    except FileNotFoundError as missing:
        raise JudgeRefused(f"episode {episode_id}: no such episode directory") from missing
    except (OSError, ValueError, TenantRefused) as refused:
        raise JudgeRefused(f"episode {episode_id}: {refused}") from refused


def _refuse_queueing(prior: EpisodeGrade) -> None:
    """A row a stopped pass left `queueing` may already have rows on a queue (A6): the re-run
    cannot tell which, so it refuses naming the row, before any model call or append."""
    for row in prior.worlds:
        if row.get(STATE_KEY) == QUEUEING:
            raise JudgeRefused(
                f"world {row['world']!r} is left {QUEUEING!r} in {LAYOUT.judge}: a pass stopped "
                "between its append and its commit, so some of its findings may be on the "
                "defender or questioner queue already. Check both queues for its finding ids, "
                f"then set its {STATE_KEY} to {QUEUED!r} or remove it; the re-run is refused")
    family = prior.family or {}
    if family.get(STATE_KEY) == QUEUEING:
        raise JudgeRefused(
            f"the {FAMILY_LABEL} row is left {QUEUEING!r} in {LAYOUT.judge}: a pass stopped "
            "between the family call's append and its commit, so some of its findings may be "
            "on the questioner queue already. Check the queue for its finding ids, then set its "
            f"{STATE_KEY} to {QUEUED!r} or remove it; the re-run is refused")


def _grade_episode(
    episode: Episode, *, judge: Any, draws: int, git_show: Any, state: LearningState,
) -> EpisodeGrade:
    # A not-graded stamp never short-circuits, so a repaired episode can still be graded. A
    # recorded grade is carried row by row: `queued` rows are final, the rest re-graded.
    existing = read_grade(episode.dir)
    prior = existing if existing is not None and existing.not_graded is None else None
    if prior is not None:
        _refuse_queueing(prior)
    return _Pass(episode, judge=judge, draws=draws, git_show=git_show, state=state,
                 prior=prior).grade()


def _label_of(finding_id: str) -> str | None:
    """The world half of `<episode>/<world>/<draw>/<index>`."""
    parts = finding_id.rsplit("/", 3)
    return parts[1] if len(parts) == 4 else None


class _Pass:
    """One grading pass's state: the rows, the ledger and the user record it writes, and the
    queue counts. Each commit (A6) writes the whole record as it stands."""

    def __init__(self, episode: Episode, *, judge: Any, draws: int, git_show: Any,
                 state: LearningState, prior: EpisodeGrade | None) -> None:
        self.episode = episode
        self.bound = episode.view()
        self.judge = judge
        self.draws = draws
        self.state = state
        self.prior = prior
        self.git_show = _memoized_show(
            git_show if git_show is not None else render_mod._git_show_default)
        self.rows: dict[str, dict[str, Any]] = {}
        self.family: dict[str, Any] | None = prior.family if prior is not None else None
        self.ledger: list[dict[str, Any]] = []
        self.user = _empty_user()
        self.enqueued = 0
        self.world_enqueued = 0
        self.knobs: dict[str, Any] = {}
        self.lessons_commit: str | None = None
        self.run_id = Path(episode.dir).name

    # -- the gates -----------------------------------------------------------------------

    def grade(self) -> EpisodeGrade:
        bound, episode = self.bound, self.episode
        try:
            manifest = family_mod.read_manifest(bound)
        except JudgeRefused as refused:
            if isinstance(refused.__cause__, ManifestPredatesOracle) \
                    and _gate(bound)[0] == outcome_mod.NO_RECORD:
                return _stamp_not_graded(episode, MANIFEST_REFUSED, str(refused))
            raise
        word, reason, record, failed = _gate(bound)
        if word != outcome_mod.ACCEPTED:
            return _stamp_not_graded(
                episode, word,
                reason or f"the episode's {LAYOUT.outcome} outcome is {word!r}, not 'accepted'",
                validity=UNUSABLE if word == outcome_mod.UNUSABLE else None)
        worlds = family_mod.non_control_worlds(manifest)
        unusable = outcome_mod.unusable_reason(failed)
        if unusable is not None:
            return _stamp_not_graded(episode, outcome_mod.UNUSABLE, unusable, validity=UNUSABLE,
                                     worlds=[
                failed_row(w, failed[w["world_id"]]) if w["world_id"] in failed else
                {"world": w["world_id"], "ungradable": True,
                 "ungradable_reason": "the family is unusable (O5): not judged"}
                for w in worlds])
        not_comparable = outcome_mod.not_comparable_reason(bound)
        if not_comparable is not None:
            return _stamp_not_graded(episode, NOT_COMPARABLE, not_comparable)
        runs = read_run_set(bound, manifest, episode_dir=episode.dir, failed=failed)
        if runs.control not in runs.usable:
            return _stamp_not_graded(
                episode, CONTROL_UNUSABLE,
                f"the control run {runs.control!r} is not usable "
                f"({runs.excluded.get(runs.control)}): every world is judged against it, so "
                "none is judged", worlds=[runs.rows[w["world_id"]] for w in worlds])
        return self._grade_runs(manifest, record, failed, runs)

    # -- the pass ------------------------------------------------------------------------

    def _grade_runs(  # noqa: C901 — the carry-over of `queued` rows, then the world loop, kept whole
            self, manifest: dict[str, Any], record: dict[str, Any] | None,
            failed: dict[str, dict[str, Any]], runs: RunSet) -> EpisodeGrade:
        bound, prior = self.bound, self.prior
        self.model, self.effort, self.cap = _judge_model(), _judge_effort(), _judge_cap()
        self.knobs = {"draws": self.draws, "model": self.model, "effort": self.effort,
                      "payload_cap": self.cap}
        self.manifest, self.record, self.runs = manifest, record, runs
        self.served_systems = run_mod.served_systems_of(manifest)
        self.samples = family_mod.read_samples_record(bound)
        # The noise context: pre-flight's record (its failed worlds named there once), then
        # every other excluded world and why.
        self.noise = render_mod.render_family_text(record, failed) + \
            render_mod.excluded_text(runs, failed)

        prior_rows = {r["world"]: r for r in (prior.worlds if prior is not None else [])}
        kept: set[str] = set()
        for world in family_mod.non_control_worlds(manifest):
            label = world["world_id"]
            prior_row = prior_rows.get(label)
            if prior_row is not None and prior_row.get(STATE_KEY) == QUEUED:
                self.rows[label] = prior_row
                kept.add(label)
                continue
            row = dict(runs.rows[label])
            if label not in runs.usable:
                row.update(measured=False, not_measured_reason=row.get("ungradable_reason"))
            self.rows[label] = row
        if self.family is not None and self.family.get(STATE_KEY) == QUEUED:
            kept.add(FAMILY_LABEL)
        else:
            self.family = None
        # A `queued` row's ledger and user entries are final; every other row's are re-decided.
        if prior is not None:
            self.ledger = [e for e in prior.dispositions or ()
                           if _label_of(str(e.get("finding_id"))) in kept]
            for name in _USER_LISTS:
                self.user[name] = [e for e in prior.user.get(name) or ()
                                   if isinstance(e, dict) and e.get("world") in kept]

        self.lessons_commit = _pass_lessons_commit(bound, runs.planted)
        if self.lessons_commit is None and prior is not None:
            self.lessons_commit = prior.lessons_commit
        for label in list(self.rows):
            if label not in kept and label in runs.usable:
                self._grade_world(label)
        if FAMILY_LABEL not in kept:
            self._grade_family()
        return self._write()

    def _alert_key(self, labels: list[str]) -> str | None:
        """The rule key of `labels`' alert (OB14: a row's own world's), `None` with none."""
        from defender.learning.core.persist import derive_alert_rule_key

        alert = render_mod.episode_alert(self.bound, labels)
        return derive_alert_rule_key(alert) if alert else None

    def _grade_world(self, label: str) -> None:
        row = self.rows[label]
        try:
            ctx = render_mod.render(
                self.episode.dir, label, git_show=self.git_show,
                lessons_commit=self.lessons_commit, payload_cap=self.cap,
                facts=self.runs.usable[label], samples=self.samples, manifest=self.manifest,
                bound=self.bound, family_text=self.noise, runs=self.runs)
            prompt = run_mod._build_prompt(ctx, sections=render_mod.world_sections(
                ctx, self.manifest))
            self.episode.world(label).draws.ensure()
        except (JudgeRefused, OSError, ValueError, TimeoutError) as world_failed:
            reason = f"{type(world_failed).__name__}: {world_failed}"
            row.update(completed_draws=0, malformed_replies=0, bucket=None, measured=False,
                       not_measured_reason=reason, draws_failed_reason=reason)
            return
        completed, documents, malformed, refusal = _run_world_draws(
            self.episode, label, judge=self.judge, draws=self.draws, model=self.model,
            effort=self.effort, prompt=prompt, served_systems=self.served_systems,
            shown_its_facts=ctx.shown_its_facts)
        scope = self.runs.scope(self.bound, manifest=self.manifest, outcome=self.record,
                                samples=self.samples, focus=label)
        answered = {n: doc for n, doc in documents.items() if "failure_reason" not in doc}
        filed = {n: route_mod.assess_draw(n, doc, scope) for n, doc in answered.items()}
        verdict = route_mod.combine_draws({
            n: route_mod.draw_verdict(answered[n], filed[n], focus=label) for n in answered})
        row.pop("draws_failed_reason", None)
        row.update(completed_draws=completed, malformed_replies=malformed,
                   bucket=verdict.bucket, systems=verdict.systems, draws=verdict.draws,
                   measured=verdict.measured, not_measured_reason=verdict.not_measured_reason,
                   draws_disagree=verdict.disagree,
                   **{enqueue_mod.WORLD_LABEL_DOUBTED: verdict.doubted})
        failures = [d["failure_reason"] for d in documents.values() if "failure_reason" in d]
        if failures:
            row["draws_failed_reason"] = failures[0]
        if not completed:
            # Not graded, with the reason: the call's fault, or the validator's last refusal.
            cause = failures[0] if failures else refusal
            if cause is not None:
                row["not_measured_reason"] = f"no draw completed: {cause}"
            row.pop(STATE_KEY, None)
            return
        alert_key = self._alert_key([label])
        defender_rows: list[dict[str, Any]] = []
        world_rows: list[dict[str, Any]] = []
        all_filed = [item for n in sorted(filed) for item in filed[n]]
        for item in all_filed:
            fid = f"{self.run_id}/{label}/{item.draw}/{item.index}"
            lane, why = route_mod.fate(item, focus=label, verdict=verdict, samples=self.samples,
                                       served_systems=self.served_systems)
            lane, why = self._place(item, fid, lane, why, label=label, verdict=verdict,
                                    alert_key=alert_key, defender_rows=defender_rows,
                                    world_rows=world_rows)
            self.ledger.append(enqueue_mod.disposition_entry(fid, lane, why))
        self.user[NAMED_GAPS].extend(route_mod.gap_entries(all_filed, verdict, world=label))
        self._commit(row, defender_rows, world_rows)

    def _place(self, item: route_mod.Filed, fid: str, lane: str, why: str | None, *,  # noqa: PLR0913 — one finding's whole hand-over
               label: str, verdict: route_mod.WorldVerdict | None, alert_key: str | None,
               defender_rows: list[dict[str, Any]], world_rows: list[dict[str, Any]],
               ) -> tuple[str, str | None]:
        """Turn one finding's lane into its queue row or user-record entry; return the lane it
        ends in (a row its channel's rule refuses is `unqueueable`, naming why)."""
        a = item.assessment
        finding = item.finding
        if lane in (route_mod.LANE_DEFENDER, route_mod.LANE_QUESTIONER):
            defender = lane == route_mod.LANE_DEFENDER
            row = enqueue_mod.build_finding_row(
                run_id=self.run_id, label=label, draw=str(item.draw), index=item.index,
                subject=run_mod.SUBJECT_DEFENDER if defender else run_mod.SUBJECT_WORLD,
                finding=finding, alert_rule_key=alert_key, citations=a.citations,
                contrast=a.contrast,
                world_label_doubted=bool(verdict.doubted) if verdict is not None else False)
            try:
                if defender:
                    enqueue_mod._validate_row(row, episode_dir=self.episode.dir)
                    defender_rows.append(row)
                else:
                    enqueue_mod._validate_world_row(row, episode_dir=self.episode.dir)
                    world_rows.append(row)
            except JudgeRefused as refused:
                return route_mod.LANE_UNQUEUEABLE, str(refused)
            return lane, why
        if lane == route_mod.LANE_USER_RECORD:
            entry: dict[str, Any] = {"finding_id": fid, "world": label, "kind": item.kind,
                     **{k: finding.get(k) for k in ("bucket", "systems", "claim", "root_cause",
                                                    "what", "how") if k in finding},
                     "citations": a.citations}
            if item.kind == route_mod.KIND_GAP:
                # A keyed listed gap is on `named_gaps` by its blocked call (`gap_entries`).
                if not a.blocked_keys:
                    self.user[UNKEYED_NAMED_GAPS].append(entry)
            elif a.gap_only:
                self.user[GAP_FINDINGS].append(entry)
            else:
                self.user[SERVING_FINDINGS].append(entry)
        return lane, why

    def _commit(self, row: dict[str, Any], defender_rows: list[dict[str, Any]],
                world_rows: list[dict[str, Any]]) -> None:
        """A6: `queueing` written, the rows this pass built from its own draws appended through
        `state` (`enqueue.enqueue_report`, A8), `queued` written. A stop between the two writes
        leaves the row `queueing`, which a re-run refuses."""
        row[STATE_KEY] = QUEUEING
        self._write()
        report = enqueue_mod.enqueue_report(
            self.episode.dir, row, state=self.state,
            drawn=enqueue_mod.DrawnRows(defender=defender_rows, world=world_rows))
        self.enqueued += report.appended
        self.world_enqueued += report.world_appended
        row[STATE_KEY] = QUEUED
        self._write()

    def _grade_family(self) -> None:
        family: dict[str, Any] = {"completed_draws": 0, "malformed_replies": 0}
        self.family = family
        try:
            sections = render_mod.family_sections(self.manifest, self.runs, self.noise,
                                                  cap=self.cap)
            prompt = run_mod._build_family_prompt(sections=sections)
            self.episode.world(FAMILY_LABEL).draws.ensure()
            completed, documents, malformed, refusal = _run_world_draws(
                self.episode, FAMILY_LABEL, judge=self.judge, draws=self.draws,
                model=self.model, effort=self.effort, prompt=prompt, scope="family",
                served_systems=self.served_systems)
        except Exception as family_failed:  # noqa: BLE001 — the family call's own fault costs only itself, never the already-committed worlds
            family["draws_failed_reason"] = f"{type(family_failed).__name__}: {family_failed}"
            return
        family.update(completed_draws=completed, malformed_replies=malformed)
        failures = [d["failure_reason"] for d in documents.values() if "failure_reason" in d]
        if failures:
            family["draws_failed_reason"] = failures[0]
        if not completed:
            if refusal is not None and not failures:
                family["malformed_reason"] = refusal
            return
        scope = self.runs.scope(self.bound, manifest=self.manifest, outcome=self.record,
                                samples=None, focus=None)
        alert_key = self._alert_key(self.runs.planted)
        world_rows: list[dict[str, Any]] = []
        for n in sorted(documents):
            if "failure_reason" in documents[n]:
                continue
            for item in route_mod.assess_draw(n, documents[n], scope):
                fid = f"{self.run_id}/{FAMILY_LABEL}/{n}/{item.index}"
                lane, why = route_mod.fate(item, focus=None, verdict=None, samples=None,
                                           served_systems=self.served_systems)
                lane, why = self._place(item, fid, lane, why, label=FAMILY_LABEL, verdict=None,
                                        alert_key=alert_key, defender_rows=[],
                                        world_rows=world_rows)
                self.ledger.append(enqueue_mod.disposition_entry(fid, lane, why))
        self._commit(family, [], world_rows)

    def _write(self) -> EpisodeGrade:
        """The record as it stands, written whole; the found gaps recomputed (A2)."""
        runs = self.runs
        not_replayable = (self.record or {}).get("not_replayable")
        self.user[FOUND_GAPS] = calls_mod.found_gaps(
            [(label, facts.token, facts.table_rows, facts.ledger_rows)
             for label, facts in runs.usable.items()],
            j3=runs.j3, not_replayable=not_replayable if isinstance(not_replayable, list) else ())
        rows = list(self.rows.values())
        out = EpisodeGrade(
            episode_dir=self.episode.dir, worlds=rows, validity=USABLE,
            family=self.family, user={k: list(v) for k, v in self.user.items()},
            dispositions=list(self.ledger),
            enqueued_rows=self.enqueued, enqueued_to=self.state.describe(FINDINGS),
            world_enqueued_rows=self.world_enqueued,
            world_enqueued_to=self.state.describe(QUESTIONER_FINDINGS),
            draws={"configured": self.draws,
                   "completed": max((r.get("completed_draws") or 0 for r in rows), default=0)},
            knobs=self.knobs, lessons_commit=self.lessons_commit)
        out.graded_worlds = frozenset(
            r["world"] for r in rows if family_mod.is_gradable_row(r))
        _write_judge_yaml(self.episode, out)
        return out


def _memoized_show(show: Any) -> Any:
    """`show`, answering each `(cwd, rev, path)` once per pass. `cwd` is in the key so the
    wrapper honours the seam's full contract."""
    seen: dict[tuple[str, str, str], Any] = {}

    def invoke(cwd: Path, rev: str, path: str) -> Any:
        key = (str(cwd), str(rev), str(path))
        if key not in seen:
            seen[key] = show(cwd, rev, path)
        return seen[key]

    return invoke


def _pass_lessons_commit(bound: Bound, labels: list[str]) -> str | None:
    """The commit every lesson body in this pass is read at: the first graded world's
    provenance stamp, resolved once so the record and every render agree."""
    for label in labels:
        commit = render_mod._read_provenance(
            bound.under(LAYOUT.world(label).dir)).get("commit")
        if commit is not None:
            return str(commit)
    return None


def read_grade(episode_dir: Path) -> EpisodeGrade | None:
    """The episode's recorded grade off `judge.yaml`, or `None` when there is none.

    The one reader, shared with the episode page and the re-run. A record carrying a name
    #1234 retired (`_retired_names_in`) is `JudgeRefused` naming it, before anything is read
    (A4). Otherwise absent fields take defaults and unknown keys are dropped, never read; a
    planted link, a non-mapping or a schema failure is `JudgeRefused`. A `not_graded` stamp
    reads back as a grade carrying it.
    """
    episode_dir = Path(episode_dir)
    doc = _existing_grade(episode_dir)
    return None if doc is None else _grade_from_document(episode_dir, doc)


def _retired_names_in(doc: dict[str, Any]) -> list[str]:
    """Every place `doc` (a `judge.yaml` mapping) carries a retired name (`core/retired`): a
    retired field at top level, on a world row, a world row's draw or the family row; the
    retired finding type as a world row's or a draw's `bucket`; a retired ledger lane. `[]` for
    a record of the new shape. Each place reads as `<where>: <names>`."""
    found: list[str] = []

    def note(where: str, names: list[str]) -> None:
        if names:
            found.append(f"{where}: {', '.join(names)}")

    note("top level", retired_keys(doc))
    worlds = doc.get("worlds")
    for row in worlds if isinstance(worlds, list) else ():
        if not isinstance(row, dict):
            continue
        where = f"world {row.get('world')!r}"
        note(where, retired_row_names(row, type_key="bucket"))
        draws = row.get("draws")
        for draw in draws if isinstance(draws, list) else ():
            if isinstance(draw, dict):
                note(f"{where} draw {draw.get('draw')!r}",
                     retired_row_names(draw, type_key="bucket"))
    family = doc.get("family")
    if isinstance(family, dict):
        note(f"the {FAMILY_LABEL} row", retired_keys(family))
    ledger = doc.get("dispositions")
    for entry in ledger if isinstance(ledger, list) else ():
        lane = entry.get("lane") if isinstance(entry, dict) else None
        if isinstance(lane, str) and lane in RETIRED_LANES:
            note(f"ledger entry {entry.get('finding_id')!r}", [f"lane {lane}"])
    return found


def _grade_from_document(episode_dir: Path, doc: dict[str, Any]) -> EpisodeGrade:
    retired = _retired_names_in(doc)
    if retired:
        # Before the unknown-key drop: a retired field is never read as the old design meant
        # it, and never silently dropped as though it were merely unknown (A4).
        raise JudgeRefused(
            f"{LAYOUT.judge} carries names #1234 retired ({'; '.join(retired)}): a record "
            "written before the change is refused by name, for the re-run and the page alike — "
            "move it aside to grade the episode afresh")
    # Strictly validated; a wrong shape is refused, not re-graded (a planted record must not
    # buy model calls — a human deletes the file). `TypeError` too: non-string YAML keys fail
    # as keywords before pydantic runs.
    try:
        fields = _known_keys(EpisodeGrade, {k: v for k, v in doc.items() if k not in _DERIVED})
        if isinstance(fields.get("not_graded"), dict):
            fields["not_graded"] = NotGradedStamp(**_known_keys(NotGradedStamp,
                                                                fields["not_graded"]))
        if isinstance(fields.get("user"), dict):
            fields["user"] = {**_empty_user(), **fields["user"]}
        record = EpisodeGrade(**fields, episode_dir=episode_dir)
    except (ValidationError, TypeError) as bad:
        raise JudgeRefused(f"{LAYOUT.judge} is not a family grade record: {bad}") from bad
    record.graded_worlds = frozenset(
        r["world"] for r in record.worlds if family_mod.is_gradable_row(r))
    return record


#: Built once: constructing a `TypeAdapter` is a schema build.
_GRADE_ADAPTER: TypeAdapter[EpisodeGrade] = TypeAdapter(EpisodeGrade)


def _write_judge_yaml(episode: Episode, record: EpisodeGrade) -> None:
    doc = _GRADE_ADAPTER.dump_python(record, mode="json", exclude=set(_DERIVED))
    # The stamp is present or absent, never null.
    if doc["not_graded"] is None:
        del doc["not_graded"]
    episode.judge.write(_yaml.safe_dump(doc, sort_keys=False))


__all__ = ["EpisodeGrade", "JudgeRefused", "NotGradedStamp", "grade_episode", "read_grade"]
