"""The family judge: grades an archived branched episode.

`grade_episode` is called by `learning/branch/cli.py` after the archive step, and is also
callable directly without the launcher.

The judge MODEL decides each world's bucket (O11); no code path computes one. Flow, per episode
with no final `judge.yaml`:
1. The gate: a manifest predating the oracle is stamped not-graded with that reason (O15,
   ahead of the outcome gate, F-11); then pre-flight's `outcome.yaml` must say exactly
   `accepted`, else the episode is stamped not-graded with the word and reason (an absent or
   torn record is the distinct "no record" state, M05=A); then O5: two or more failed worlds
   (pre-flight's plus every world's own record, S9) make the family `unusable` — recorded, with
   no model call.
2. `family.read_world` per non-control world that did not fail, then `render.render` +
   `run._build_prompt`/`validate_reply` — one model call per world per draw, through the
   injected `judge=` seam, written to `worlds/<X>/judge/<n>.yaml`. A reply the validator
   refuses is asked again, a bounded number of times; a failed call is not.
3. The family-level call: the family's word (`verdict_word`, a `JUDGE_OUTCOME_ENUM` member).
4. `enqueue.enqueue_report` — one `FindingRow` per kept finding.
5. `episodes/<id>/judge.yaml` — written last, after the enqueue, so its presence certifies the
   whole pass. A record in which every judgeable world completed a draw is final; a bare
   re-run grades only the worlds that did not.
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
from defender.learning.judge._errors import JudgeRefused  # noqa: E402

from defender._episode_handle import Episode  # noqa: E402
from defender._io import Bound, NotPlainEntry, bind  # noqa: E402
from defender._vocab import JUDGE_OUTCOME_ENUM  # noqa: E402
from defender.run_repository import WIRE_LOG_NAMES  # noqa: E402
from defender._episode_paths import LAYOUT  # noqa: E402
from defender.learning.branch import outcome as outcome_mod  # noqa: E402
from defender.learning.judge import enqueue as enqueue_mod  # noqa: E402
from defender.learning.judge import family as family_mod  # noqa: E402
from defender.learning.judge import render as render_mod  # noqa: E402
from defender.learning.judge import run as run_mod  # noqa: E402
from defender.runtime.branch._family import ManifestPredatesOracle, episode_token_for  # noqa: E402
from defender import _yaml

if TYPE_CHECKING:
    from defender.run_repository import RunsRepository

_logger = logging.getLogger(__name__)

#: The judge's own operator knobs — no `DEFENDER_` prefix, matching `QUESTIONER_EFFORT`. Model
#: and effort are read through `config.judge_model`/`judge_effort`, not spelled here.
DRAWS_KNOB = "JUDGE_DRAWS"
CAP_KNOB = "JUDGE_PAYLOAD_CAP"

#: `judge.yaml`'s `episode_outcome` for an episode this pass did not grade. Not in
#: `_vocab.JUDGE_OUTCOME_ENUM`: that is the family's word, shared by three schemas, while "not
#: graded" is a fact about this record alone.
NOT_GRADED = "not-graded"

#: The stamp's word for a manifest the judge cannot read as a family of this design (O15) —
#: not an outcome word, since the outcome record was never consulted.
MANIFEST_REFUSED = "manifest refused"

#: The stamp's word for an `accepted` family with no readable family stamp: `verify_family`
#: withheld it, so its worlds are not comparable and the pass grades none of them (PR #1232
#: round 7; the retired `incomplete` used to keep such a family away from the judge).
NOT_COMPARABLE = outcome_mod.NOT_COMPARABLE

#: `judge.yaml`'s `validity` (O5, M19=A): its own field, never a family word.
USABLE, UNUSABLE = "usable", "unusable"

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


@model
class EpisodeGrade:
    """`grade_episode`'s return value and the schema of `judge.yaml`, in both directions.

    Strict (no coercion), so a document of the wrong shape fails at the constructor.
    `episode_dir` and `graded_worlds` are derived: never written, recomputed from the rows on
    every read (`_DERIVED`).

    Each world row carries the judge model's own `bucket` and `systems` (`None` where no valid
    reply gave one, or where the draws disagree — every draw's answer is on `draws`), its
    `findings`, and `completed_draws`/`malformed_replies`; a world that could not be judged
    carries `ungradable` and its reason instead.
    """

    episode_dir: Path
    worlds: Annotated[list[dict[str, Any]], AfterValidator(_rows_name_their_world)] = field(
        default_factory=list)
    verdict_word: str = "undecidable"
    graded_worlds: frozenset[str] = field(default_factory=frozenset)
    episode_outcome: str = "gradable"
    #: O5's verdict on the family (M19=A): `usable`, `unusable`, or `None` where the pass never
    #: counted (a manifest refusal, an outcome other than `accepted`/`unusable`).
    validity: str | None = None
    enqueued_rows: int = 0
    enqueued_to: str = ""
    draws: dict[str, int] = field(default_factory=dict)
    knobs: dict[str, Any] = field(default_factory=dict)
    lessons_commit: str | None = None
    queue_malformed_rows: int = 0
    world_queue_malformed_rows: int = 0
    #: Findings this pass could not turn into a queue row, one line each naming the finding
    #: and why.
    unqueueable_findings: list[str] = field(default_factory=list)
    not_graded: NotGradedStamp | None = None
    #: The family-level call's majority word (a `JUDGE_OUTCOME_ENUM` member), or `None`.
    family_outcome: str | None = None
    #: The family call's own fault and malformed count: `family_outcome: None` alone cannot
    #: tell "ran, no majority" from "its draw sink was refused".
    family_failed_reason: str | None = None
    family_malformed_replies: int = 0
    family_completed_draws: int = 0
    world_enqueued_rows: int = 0
    world_enqueued_to: str = ""
    #: Every `subject: world` row this pass built — not enqueued: the questioner channel dedups
    #: on `finding_id`, so on a re-grade `world_enqueued_rows` is 0 while this is full.
    world_findings: list[dict[str, Any]] = field(default_factory=list)
    #: The ledger: `{finding_id, lane, reason}` per finding touched, in walk order. The page
    #: renders this rather than re-deciding lanes. `None` for an older record or a
    #: `not_graded` stamp; a pass that walked nothing writes `[]`.
    dispositions: Annotated[list[dict[str, Any]],
                            AfterValidator(_ledger_entries_name_a_lane)] | None = None


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


def _prepare_world_prompt(  # noqa: PLR0913 — the render's own inputs, threaded from the pass
    episode: Episode, label: str, *, bound: Bound, payload_cap: int, git_show: Any,
    facts: family_mod.WorldFacts | None, lessons_commit: str | None, manifest: dict[str, Any],
    samples: dict[str, Any], family_text: str,
) -> str:
    """One world's whole framed prompt, with its draw directory made.

    Its own frame so the caller can contain a fault here (all of it touches the box-reachable
    episode tree) to this world."""
    judge_input = render_mod.render(
        episode.dir, label, git_show=git_show, payload_cap=payload_cap, facts=facts,
        lessons_commit=lessons_commit, manifest=manifest,
        samples=samples, family_text=family_text, bound=bound)
    episode.world(label).draws.ensure()
    return run_mod._build_prompt(judge_input)


def _run_world_draws(  # noqa: C901, PLR0913 — one loop over draws and their bounded re-asks
    episode: Episode, label: str, *, judge: Any, draws: int,
    model: str, effort: str, prompt: str, scope: str = "world",
    served_systems: list[str] | None = None,
) -> tuple[int, dict[int, dict[str, Any]], int]:
    """Call the judge `draws` times over `prompt`, writing one `worlds/<X>/judge/<n>.yaml` per
    draw. Returns `(completed_draws, draw documents by index, malformed replies)`.

    A failed call writes a draw record naming its failure and is not asked again. A reply the
    validator refuses is counted and asked again, up to `_REPLY_ATTEMPTS` asks per draw; a draw
    whose every ask was refused writes nothing. Documents are returned, not read back, because a
    retry does not clean up stale files from a wider earlier attempt."""
    from defender.learning.core.config import StageWiring
    from defender.runtime.agent_role import AgentRole

    world = episode.world(label)
    world_dir = world.dir.path

    completed = 0
    documents: dict[int, dict[str, Any]] = {}
    malformed = 0
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
                                               served_systems=served_systems)
            except JudgeRefused:
                malformed += 1
                continue
            doc = run_mod._draw_document(reply, world_dir=world_dir, scope=scope)
            completed += 1
            break
        if doc is None:
            # Every ask refused: nothing is written (the raw replies are on the wire log), and
            # an earlier pass's file at this index is removed so a disk re-read cannot queue
            # its findings as this pass's.
            try:
                world.draw(n).delete()
            except NotPlainEntry as stuck:
                # Only the core's refusal of something not plain at the draw's name is
                # contained: it is left for the reap scan, and a later disk read counts it
                # unreadable, so it costs this draw, not the pass. Any other failure (a denied
                # or read-only tree, a linked folder on the way) would leave a stale plain draw
                # to be queued as this pass's, so it stops the pass.
                _logger.warning(f"world {label!r}: the earlier draw {world.draw(n).path.name} "
                                f"was not removed ({stuck})")
            continue
        documents[n] = doc
        # Not contained: a link planted at this sink refuses the pass. The draw file is what
        # the enqueue reads back, so an aliased one is not an observability fault.
        world.draw(n).write(_yaml.safe_dump(doc, sort_keys=False))
    return completed, documents, malformed


def _write_wire_log(
    episode: Episode, *, agent_id: str, prompt: str, reply: str | None, failure: str | None,
) -> None:
    """The judge's wire-log record — the whole framed prompt and reply verbatim, one file per
    call, under `wire_logs/` so the existing wire-log policy denial covers it. Written here
    because the injected `judge=` seam carries no logger.

    Its own file name (from `agent_id`), not the wiring's `trace_name`: `run_stage` streams the
    real request/response records to that path, and a replace-mode write there would destroy
    them."""
    # Name sanitisation and the framed suffix come from `WIRE_LOG_NAMES`, so the episode page
    # can pair this file with the unframed trace the seam writes.
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


def _majority(documents: dict[int, dict[str, Any]], n_completed: int, key: str,
              word: str) -> bool:
    """Did more than half of this pass's completed draws answer `word` under `key`?

    Counted over this pass's documents, never the draw directory, where stale files from a
    wider earlier attempt could outvote it."""
    if n_completed == 0:
        return False
    votes = sum(1 for doc in documents.values() if doc.get(key) == word)
    return votes * 2 > n_completed


def _world_answers(row: dict[str, Any], documents: dict[int, dict[str, Any]]) -> None:
    """Record the judge model's answers for one world on its row: every completed draw's own
    `bucket`/`systems` on `draws`, and the row's `bucket`/`systems` only where every draw gave
    the same one — disagreeing draws are flagged, never reduced to a bucket of the pass's own.
    Copied off the draw documents (`run._draw_document` owns the bucket) here and nowhere
    else."""
    answered = [(n, doc) for n, doc in sorted(documents.items()) if "bucket" in doc]
    row["draws"] = [{"draw": n, "bucket": doc.get("bucket"), "systems": doc.get("systems")}
                    for n, doc in answered]
    buckets = {doc.get("bucket") for _n, doc in answered}
    systems = {tuple(doc.get("systems") or ()) for _n, doc in answered}
    row["bucket"] = next(iter(buckets)) if len(buckets) == 1 else None
    row["systems"] = list(next(iter(systems))) if len(systems) == 1 else None
    if len(buckets) > 1 or len(systems) > 1:
        row["draws_disagree"] = True
    row["findings"] = [{**finding, "draw": n} for n, doc in answered
                       for finding in doc.get("findings") or () if isinstance(finding, dict)]


def _failed_row(world: dict[str, Any], entry: dict[str, Any]) -> dict[str, Any]:
    """The row of a world O5 counts as failed (N22): an explicit entry built from its own
    record or pre-flight's result — never judged, no bucket, no findings."""
    from defender._vocab import normalized_disposition

    reason = entry.get("reason")
    detail = entry.get("detail")
    return {"world": world["world_id"],
            "declared": normalized_disposition(world.get("disposition_declared")),
            "ungradable": True, "failed_world": entry,
            "ungradable_reason": f"{reason}" + (f" — {detail}" if detail else "")}


def _ungraded_labels(record: EpisodeGrade) -> list[str]:
    """The judgeable worlds of a recorded grade that completed no draw — what a bare re-run
    grades. Empty: the record is final."""
    return [row["world"] for row in record.worlds
            if family_mod.is_gradable_row(row) and not row.get("completed_draws")]


def _stamp_not_graded(episode: Episode, word: str, reason: str, *, validity: str | None = None,
           worlds: list[dict[str, Any]] | None = None) -> EpisodeGrade:
    """Write and return a not-graded record: no model call, no findings."""
    record = EpisodeGrade(episode_dir=episode.dir, episode_outcome=NOT_GRADED,
                          validity=validity, worlds=worlds or [],
                          not_graded=NotGradedStamp(outcome=word, reason=reason))
    _write_judge_yaml(episode, record)
    return record


def _default_judge_seam(episode_dir: Path) -> Any:
    """The production `(prompt, *, role, agent_id, wiring) -> str` for every judge call:
    `run_stage` under the judge's own deny-all role. `wiring` comes from the caller.

    `deps=JudgeDeps()` decides the role (`build_stage_agent` reads `type(deps).role`); the
    `role` kwarg is ignored. No `tools=`/`verbs=` are passed, since either would widen a role
    that holds no grants.

    Imports are inside `invoke` so passes that never call the model (already graded, or not
    `accepted`) skip the provider import, which sits outside `grade_episode`'s error
    conversion."""
    def invoke(prompt: str, *, role: Any = None, agent_id: str = "judge", wiring: Any = None,
              **_kw: Any) -> str:
        from defender.learning._pydantic_stage import run_stage
        from defender.learning.core.config import StageContext, subagent_timeout
        from defender.learning.judge.run import JudgeDeps

        # Required: without it `run_stage` fails with an opaque `AttributeError`.
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
    repository and an id). Its door is `runs.episode_files(episode_id)`, the episode owner's
    handle alone, held for the whole pass (one descriptor while the judge is paid, none after):
    a bad id, an unusable episodes root, a missing episode or a file at its name is
    `JudgeRefused`, and nothing is created. The judge reads only the episode it is handed — no
    tenant's runs (J3)."""
    import yaml

    try:
        with _open_episode(runs, episode_id) as episode:
            resolved_judge = judge if judge is not None else _default_judge_seam(episode.dir)
            return _grade_episode(episode, judge=resolved_judge, draws=draws,
                                  git_show=git_show, state=state)
    except JudgeRefused:
        raise
    # Every input-driven failure arrives as `JudgeRefused`, which is what the launcher catches:
    # e.g. a decode error in an archived document, a YAML error in a draw file, a `ValueError`
    # from the guarded mkdir, a timeout on the queue lock.
    except (OSError, ValueError, TimeoutError, yaml.YAMLError) as bad:
        raise JudgeRefused(f"episode {episode_id}: {bad!r}") from bad


def _open_episode(runs: RunsRepository, episode_id: str) -> Episode:
    """The pass's one handle, through the judge's door: every read through its view, every
    write through it. A missing episode is refused, never recreated by the not-graded stamp;
    the owner's refusals (a bad id, an unusable root, a file at the name) are `JudgeRefused`."""
    try:
        return runs.episode_files(episode_id)
    except FileNotFoundError as missing:
        raise JudgeRefused(f"episode {episode_id}: no such episode directory") from missing
    except (OSError, ValueError) as refused:
        raise JudgeRefused(f"episode {episode_id}: {refused}") from refused


def _grade_episode(
    episode: Episode, *, judge: Any, draws: int | None, git_show: Any, state: LearningState,
) -> EpisodeGrade:
    # An existing grade in which every judgeable world completed a draw is final (N22); one with
    # worlds left ungraded is re-run for those worlds only; a not-graded stamp never
    # short-circuits, so a repaired episode can still be graded.
    existing = read_grade(episode.dir)
    prior: EpisodeGrade | None = None
    if existing is not None and existing.not_graded is None:
        if not _ungraded_labels(existing):
            return existing
        prior = existing
    return _grade_bound_episode(
        episode.view(), episode, judge=judge, draws=draws, git_show=git_show, state=state,
        prior=prior)


def _grade_bound_episode(  # noqa: PLR0913, PLR0915, PLR0912, C901 — one orchestration, kept whole
    bound: Bound, episode: Episode, *, judge: Any, draws: int | None,
    git_show: Any, state: LearningState, prior: EpisodeGrade | None,
) -> EpisodeGrade:
    episode_dir = episode.dir
    # The manifest first, ahead of the outcome gate (O15, F-11), so a pre-oracle archive is
    # named for what it is rather than for its missing outcome record. Such an archive (no
    # outcome record — the old launcher never wrote one) is stamped not-graded with the
    # predates-the-oracle reason. Beside an outcome record it is refused instead: pre-flight
    # runs only over a manifest the runtime loader admitted, so an old field there was written
    # after launch. Any other manifest refusal refuses the pass.
    try:
        manifest = family_mod.read_manifest(bound)
    except JudgeRefused as refused:
        if isinstance(refused.__cause__, ManifestPredatesOracle) \
                and _gate(bound)[0] == outcome_mod.NO_RECORD:
            return _stamp_not_graded(episode, MANIFEST_REFUSED, str(refused))
        raise
    word, reason, record, failed = _gate(bound)
    if word != outcome_mod.ACCEPTED:
        # Never the `gradable` default: an unexamined episode must not read like a cleared one.
        return _stamp_not_graded(episode, word,
                      reason or f"the episode's {LAYOUT.outcome} outcome is {word!r}, not "
                                f"'accepted'",
                      validity=UNUSABLE if word == outcome_mod.UNUSABLE else None)

    worlds = family_mod.non_control_worlds(manifest)
    unusable = outcome_mod.unusable_reason(failed)
    if unusable is not None:
        # O5 (S9): counted from pre-flight's failed worlds plus every world's own record, with
        # no model call. Every row is bucketless; the failed ones say why.
        return _stamp_not_graded(episode, outcome_mod.UNUSABLE, unusable, validity=UNUSABLE, worlds=[
            _failed_row(w, failed[w["world_id"]]) if w["world_id"] in failed else
            {"world": w["world_id"], "ungradable": True,
             "ungradable_reason": "the family is unusable (O5): not judged"}
            for w in worlds])
    not_comparable = outcome_mod.not_comparable_reason(bound)
    if not_comparable is not None:
        # The family stamp is `verify_family`'s certificate that the siblings ran one commit,
        # one knowledge revision and one tenant on clean (or waived) trees. Without it the
        # worlds' differences measure nothing: no model call, nothing queued.
        return _stamp_not_graded(episode, NOT_COMPARABLE, not_comparable)

    configured_draws = draws if draws is not None else _judge_draws()
    model, effort, cap = _judge_model(), _judge_effort(), _judge_cap()
    knobs = {"draws": configured_draws, "model": model, "effort": effort, "payload_cap": cap}

    # Manifest, samples and pre-flight's record are each read once and threaded into every
    # render, so every world's prompt comes off the same documents.
    served_systems = run_mod.served_systems_of(manifest)
    samples = family_mod.read_samples_record(bound)
    family_text = render_mod.render_family_text(record, failed)
    episode_token = episode_token_for(family_mod.episode_id_of(manifest))
    prior_rows = {r["world"]: r for r in (prior.worlds if prior is not None else [])}
    regrade = set(_ungraded_labels(prior)) if prior is not None else None

    rows: list[dict[str, Any]] = []
    facts: dict[str, family_mod.WorldFacts] = {}
    for world in worlds:
        label = world["world_id"]
        if regrade is not None and label not in regrade and label in prior_rows:
            rows.append(prior_rows[label])
            continue
        if label in failed:
            rows.append(_failed_row(world, failed[label]))
            continue
        row, read = family_mod.read_world(bound, world, episode_dir=episode_dir,
                                          episode_token=episode_token)
        rows.append(row)
        if read is not None:
            facts[label] = read
    gradable = list(facts)

    # Per-pass facts, resolved once and threaded into every render: the record's
    # `lessons_commit` must be the one the worlds rendered against.
    lessons_commit = _pass_lessons_commit(bound, gradable)
    if lessons_commit is None and prior is not None:
        lessons_commit = prior.lessons_commit
    # One `git show` per (commit, path) for the pass, memoized around the injected seam.
    git_show = _memoized_show(git_show if git_show is not None else render_mod._git_show_default)

    per_world_draws: dict[str, dict[int, dict[str, Any]]] = {}
    row_of = {row["world"]: row for row in rows}
    for label in gradable:
        row = row_of[label]
        # Setup faults (box-reachable tree) are contained to this world, so earlier worlds'
        # paid-for draws still reach `judge.yaml`.
        try:
            prompt = _prepare_world_prompt(
                episode, label, bound=bound, payload_cap=cap, git_show=git_show,
                facts=facts[label], lessons_commit=lessons_commit,
                manifest=manifest, samples=samples, family_text=family_text)
        except (JudgeRefused, OSError, ValueError, TimeoutError) as world_failed:
            # Distinguishes "setup failed" from "ungradable" (both have 0 completed draws).
            row.update(completed_draws=0, malformed_replies=0, bucket=None, findings=[],
                       draws_failed_reason=f"{type(world_failed).__name__}: {world_failed}")
            continue
        # Draws are not contained here: the loop contains call and reply failures itself, and
        # a link planted at its write sink must refuse the pass.
        completed, documents, malformed = _run_world_draws(
            episode, label, judge=judge, draws=configured_draws, model=model, effort=effort,
            prompt=prompt, served_systems=served_systems)
        per_world_draws[label] = documents
        # A reply that failed validation is a draw that ran and produced nothing usable, which
        # is a different state from a draw that never ran; the record says which.
        row.update(completed_draws=completed, malformed_replies=malformed)
        failures = [d["failure_reason"] for d in documents.values() if "failure_reason" in d]
        if failures:
            row["draws_failed_reason"] = failures[0]
        else:
            row.pop("draws_failed_reason", None)
        _world_answers(row, documents)

    # The family-level call gives the family's word. It runs once per episode (a re-run for
    # missing worlds keeps the recorded word) and is an addition: its own fault costs only its
    # own contribution.
    family_documents: dict[int, dict[str, Any]] = {}
    family_completed = 0
    family_malformed = 0
    family_failed_reason: str | None = None
    family_outcome: str | None = None
    if prior is not None and prior.family_completed_draws:
        family_completed = prior.family_completed_draws
        family_malformed = prior.family_malformed_replies
        family_outcome = prior.family_outcome
    else:
        try:
            family_prompt = run_mod._build_family_prompt(manifest=manifest, rows=rows,
                                                          family_text=family_text)
            episode.world("family").draws.ensure()
            family_completed, family_documents, family_malformed = _run_world_draws(
                episode, "family", judge=judge, draws=configured_draws, model=model,
                effort=effort, prompt=family_prompt, scope="family")
        except Exception as family_failed:  # noqa: BLE001 — the family call's own fault costs only itself, never the already-completed per-world draws
            family_documents = {}
            family_completed = 0
            family_failed_reason = f"{type(family_failed).__name__}: {family_failed}"
        for candidate in sorted(JUDGE_OUTCOME_ENUM):
            if _majority(family_documents, family_completed, "verdict_word", candidate):
                family_outcome = candidate
                break

    # A world the model called spoilt (`discard`/`corpus-contradiction`) spoils the family;
    # discard wins over corpus-contradiction so the answer does not depend on manifest order.
    episode_outcome = "gradable"
    for blocking in ("discard", "corpus-contradiction"):
        if any(_majority(per_world_draws[label], row_of[label].get("completed_draws", 0),
                         "episode_outcome", blocking) for label in per_world_draws) \
                or family_outcome == blocking \
                or (prior is not None and prior.episode_outcome == blocking):
            episode_outcome = blocking
            break
    verdict_word = (episode_outcome if episode_outcome != "gradable"
                    else family_outcome or "undecidable")

    enqueued_to = state.describe(FINDINGS)
    world_enqueued_to = state.describe(QUESTIONER_FINDINGS)
    # Always called: a blocked outcome closes only the defender lane (`enqueue_report` reads
    # `verdict_word`), never the world lane. Only this pass's draws are handed over, so a
    # re-run never appends a world it did not just grade.
    report = enqueue_mod.enqueue_report(
        episode_dir, {"verdict_word": verdict_word, "worlds": rows},
        state=state, drawn=per_world_draws, family_drawn=family_documents,
        served_systems=served_systems, samples=samples)

    record_out = EpisodeGrade(
        episode_dir=episode_dir, worlds=rows, verdict_word=verdict_word,
        episode_outcome=episode_outcome, validity=USABLE,
        enqueued_rows=report.appended, enqueued_to=enqueued_to,
        draws={"configured": configured_draws,
               "completed": max((r.get("completed_draws", 0) for r in rows), default=0)},
        knobs=knobs, lessons_commit=lessons_commit,
        queue_malformed_rows=report.queue_malformed_rows,
        world_queue_malformed_rows=report.world_queue_malformed_rows,
        unqueueable_findings=[*(prior.unqueueable_findings if prior else []),
                              *report.unqueueable],
        family_outcome=family_outcome, family_failed_reason=family_failed_reason,
        family_malformed_replies=family_malformed, family_completed_draws=family_completed,
        world_enqueued_rows=report.world_appended, world_enqueued_to=world_enqueued_to,
        world_findings=[*(prior.world_findings if prior else []), *report.world_rows],
        dispositions=[*((prior.dispositions or []) if prior else []), *report.dispositions],
    )
    record_out.graded_worlds = frozenset(
        r["world"] for r in record_out.worlds if family_mod.is_gradable_row(r))
    _write_judge_yaml(episode, record_out)
    return record_out


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

    The one reader, shared with the episode page. Absent fields take defaults and unknown keys
    are ignored; a planted link, a non-mapping or a schema failure is `JudgeRefused`. A
    `not_graded` stamp reads back as a grade carrying it.
    """
    episode_dir = Path(episode_dir)
    doc = _existing_grade(episode_dir)
    return None if doc is None else _grade_from_document(episode_dir, doc)


def _grade_from_document(episode_dir: Path, doc: dict[str, Any]) -> EpisodeGrade:
    # Strictly validated; a wrong shape is refused, not re-graded (a planted record must not
    # buy model calls — a human deletes the file). The writer replaces atomically, so a bad
    # shape is never a torn write. `TypeError` too: non-string YAML keys fail as keywords
    # before pydantic runs.
    try:
        fields = _known_keys(EpisodeGrade, {k: v for k, v in doc.items() if k not in _DERIVED})
        # Built explicitly: in Python-mode strict validation a nested dataclass admits only an
        # instance of itself, so a well-shaped mapping would be refused.
        if isinstance(fields.get("not_graded"), dict):
            fields["not_graded"] = NotGradedStamp(**_known_keys(NotGradedStamp, fields["not_graded"]))
        record = EpisodeGrade(**fields, episode_dir=episode_dir)
    except (ValidationError, TypeError) as bad:
        raise JudgeRefused(f"{LAYOUT.judge} is not a family grade record: {bad}") from bad
    # Assigned rather than `replace`d, which would re-validate and copy every row.
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
