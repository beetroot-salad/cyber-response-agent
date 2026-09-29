"""The family judge: grades an archived branched episode.

`grade_episode` is called by `learning/branch/cli.py` after the archive step, and is also
callable directly without the launcher.

Flow, per `accepted` episode with no existing `judge.yaml`:
1. `family.grade_family` — the mechanical pass, per non-control world.
2. `render.render` + `run._build_prompt`/`validate_reply` — one model call per graded world
   per draw, through the injected `judge=` seam, written to `worlds/<X>/judge/<n>.yaml`.
3. The episode's outcome — `gradable`, `discard` (mechanical-first, and before any world's
   corpus-contradiction, so the answer does not depend on manifest order) or
   `corpus-contradiction` — decided from the review record and this pass's own draws.
4. `enqueue.enqueue_report` — for a `gradable` episode, one `FindingRow` per surviving
   defender finding; world findings are enqueued regardless of outcome.
5. `episodes/<id>/judge.yaml` — written last, after the enqueue, so its presence certifies the
   whole pass.
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from dataclasses import field, fields as dataclass_fields
from pathlib import Path
from typing import Annotated, Any

from pydantic import AfterValidator, TypeAdapter, ValidationError


# `JudgeRefused` lives in `_errors.py` to avoid an import cycle; re-exported here.
from defender._model import model  # noqa: E402
from defender.learning.judge._errors import JudgeRefused  # noqa: E402

from defender._episode_handle import Episode  # noqa: E402
from defender._io import Bound, NotPlainEntry, bind  # noqa: E402
from defender._run_paths import WIRE_LOG_NAMES  # noqa: E402
from defender._episode_paths import LAYOUT  # noqa: E402
from defender.learning.judge import enqueue as enqueue_mod  # noqa: E402
from defender.learning.judge import family as family_mod  # noqa: E402
from defender.learning.judge import render as render_mod  # noqa: E402
from defender.learning.judge import run as run_mod  # noqa: E402

_logger = logging.getLogger(__name__)

#: The judge's own operator knobs — no `DEFENDER_` prefix, matching `QUESTIONER_EFFORT`. Model
#: and effort are read through `config.judge_model`/`judge_effort`, not spelled here.
DRAWS_KNOB = "JUDGE_DRAWS"
CAP_KNOB = "JUDGE_PAYLOAD_CAP"

#: `judge.yaml`'s `episode_outcome` for an episode this pass did not grade. Not in
#: `_vocab.JUDGE_OUTCOME_ENUM`: that is the family's word, shared by three schemas, while "not
#: graded" is a fact about this record alone.
NOT_GRADED = "not-graded"

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
    """Why the pass declined to grade an episode: the review's outcome word and its reason."""

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
    `episode_dir` and the three `frozenset` fields are derived: never written, recomputed from
    the rows on every read (`_DERIVED`).
    """

    episode_dir: Path
    worlds: Annotated[list[dict[str, Any]], AfterValidator(_rows_name_their_world)] = field(
        default_factory=list)
    verdict_word: str = "undecidable"
    graded_worlds: frozenset[str] = field(default_factory=frozenset)
    episode_outcome: str = "gradable"
    enqueued_rows: int = 0
    enqueued_to: str = ""
    draws: dict[str, int] = field(default_factory=dict)
    knobs: dict[str, Any] = field(default_factory=dict)
    lessons_commit: str | None = None
    discard_evidence: dict[str, Any] = field(default_factory=dict)
    queue_malformed_rows: int = 0
    world_queue_malformed_rows: int = 0
    #: Findings this pass could not turn into a queue row, one line each naming the finding
    #: and why.
    unqueueable_findings: list[str] = field(default_factory=list)
    not_graded: NotGradedStamp | None = None
    #: The family-level call's majority outcome word (`_REPLY_OUTCOME_ENUM`, a different
    #: vocabulary from `verdict_word`).
    family_outcome: str | None = None
    #: The family call's own fault and malformed count: `family_outcome: None` alone cannot
    #: tell "ran, no majority" from "its draw sink was refused".
    family_failed_reason: str | None = None
    family_malformed_replies: int = 0
    world_enqueued_rows: int = 0
    world_enqueued_to: str = ""
    #: `withheld_worlds`/`measuring_worlds` partition `graded_worlds`.
    withheld_worlds: frozenset[str] = field(default_factory=frozenset)
    measuring_worlds: frozenset[str] = field(default_factory=frozenset)
    #: Every `subject: world` row this pass built — not enqueued: the questioner channel dedups
    #: on `finding_id`, so on a re-grade `world_enqueued_rows` is 0 while this is full.
    world_findings: list[dict[str, Any]] = field(default_factory=list)
    #: `{finding, world, reason}` for every withheld defender finding — which finding and why,
    #: since the draw document it came off may not survive.
    withheld_findings: list[dict[str, Any]] = field(default_factory=list)
    #: The ledger: `{finding_id, lane, reason}` per finding touched, in walk order. The page
    #: renders this rather than re-deciding lanes. `None` for an older record or a
    #: `not_graded` stamp; a pass that walked nothing writes `[]`.
    dispositions: Annotated[list[dict[str, Any]],
                            AfterValidator(_ledger_entries_name_a_lane)] | None = None


#: Fields not written to the file: the path, and the three sets re-derived from the rows so no
#: top-level list can disagree with them.
_DERIVED = frozenset({"episode_dir", "graded_worlds", "withheld_worlds", "measuring_worlds"})


def _known_keys(record: type, doc: dict[Any, Any]) -> dict[Any, Any]:
    """`doc` minus string keys the schema does not name, so a newer record still reads. A
    reader-side tolerance only: `@model` still refuses unknown keywords at construction. A
    non-string key is kept, for the constructor's own `TypeError`."""
    names = {f.name for f in dataclass_fields(record)}
    return {k: v for k, v in doc.items() if not isinstance(k, str) or k in names}


def _existing_grade(episode_dir: Path) -> dict[str, Any] | None:
    # Screened read: this is the idempotency record in a box-reachable tree, and a planted one
    # would stop the pass from ever running. Nothing at the name is an ordinary ungraded episode.
    with bind(Path(episode_dir)) as bound:
        return family_mod.screened_yaml_mapping(bound, LAYOUT.judge, what="the family grade")


def _episode_outcome_from_review(review: dict[str, Any]) -> tuple[str, str]:
    if not review:
        return "incomplete", f"no {LAYOUT.review} on disk"
    episode = review.get("episode")
    outcome = episode.get("outcome") if isinstance(episode, dict) else None
    reason = episode.get("reason") if isinstance(episode, dict) else None
    return (str(outcome) if isinstance(outcome, str) else "incomplete", str(reason or ""))


#: Where the review records the capture's disagreement with itself: on each world's
#: `consistency` block (not the episode block), under this name.
_DRIFT_KEYS_FIELD = "control_mismatch_keys"


def _envelope_key(envelope: Any) -> str | None:
    """The discriminating call's identity, in the same encoding every recorded key uses
    (`family.mapping_key`), so the drift check can match."""
    if not isinstance(envelope, dict):
        return None
    return family_mod.mapping_key(envelope)


def _control_drift_keys(review: dict[str, Any]) -> list[Any]:
    """The keys the review recorded the capture as having disagreed with itself on.

    Unioned across every world's block rather than picking the control: each block carries the
    control's list, and this reader has the review but not the manifest's roles."""
    worlds = review.get("worlds")
    if not isinstance(worlds, dict):
        return []
    keys: list[Any] = []
    for result in worlds.values():
        consistency = result.get("consistency") if isinstance(result, dict) else None
        found = consistency.get(_DRIFT_KEYS_FIELD) if isinstance(consistency, dict) else None
        if isinstance(found, list):
            keys.extend(found)
    return keys


def _control_drift_discard(doc: dict[str, Any], review: dict[str, Any]) -> bool:
    """Mechanical-first `discard`: the discriminator envelope's key is among the review's
    control-drift keys — the capture disagreed with itself on the discriminating call.

    Takes the already-parsed documents so the whole pass reads one copy of each."""
    key = _envelope_key(family_mod.discriminator_of(doc).get("envelope"))
    if key is None:
        return False
    return key in _control_drift_keys(review)


def _prepare_world_prompt(  # noqa: PLR0913 — the render's own inputs, threaded from the pass
    episode: Episode, label: str, *, bound: Bound, payload_cap: int, git_show: Any,
    facts: family_mod.WorldFacts | None, lessons_commit: str | None,
    union: tuple[list[dict[str, Any]], dict[str, Any]], manifest: dict[str, Any],
    review: dict[str, Any], samples: dict[str, Any],
) -> str:
    """One world's whole framed prompt, with its draw directory made.

    Its own frame so the caller can contain a fault here (all of it touches the box-reachable
    episode tree) to this world. No `runs_base`: the caller always passes the pass's union, so
    `render` never walks the runs base per world."""
    judge_input = render_mod.render(
        episode.dir, label, git_show=git_show, payload_cap=payload_cap, facts=facts,
        lessons_commit=lessons_commit, union=union, manifest=manifest,
        review=review, samples=samples, bound=bound)
    episode.world(label).draws.ensure()
    return run_mod._build_prompt(judge_input)


def _run_world_draws(
    episode: Episode, label: str, *, judge: Any, draws: int,
    model: str, effort: str, prompt: str, scope: str = "world",
) -> tuple[int, dict[str, int], dict[int, dict[str, Any]], int]:
    """Call the judge `draws` times over `prompt`, writing one `worlds/<X>/judge/<n>.yaml` per
    draw. Returns `(completed_draws, bucket_spread, draw documents by index, malformed replies)`.

    A failed call writes a draw record naming its failure; a malformed reply writes nothing and
    is counted; either way the loop continues. Documents are returned, not read back, because
    a retry does not clean up stale files from a wider earlier attempt."""
    from defender.learning.core.config import StageWiring
    from defender.runtime.agent_role import AgentRole

    world = episode.world(label)
    world_dir = world.dir.path

    completed = 0
    spread: Counter[str] = Counter()
    documents: dict[int, dict[str, Any]] = {}
    malformed = 0
    for n in range(draws):
        agent_id = f"judge:{label}:{n}"
        wiring = StageWiring(
            prompt_path=run_mod._ROLE_PROMPT, model=model, effort=effort,
            trace_name=WIRE_LOG_NAMES.agent_trace(agent_id), label=agent_id)
        reply_text: str | None = None
        doc: dict[str, Any]
        try:
            reply_text = judge(prompt, role=AgentRole.JUDGE, agent_id=agent_id,
                               wiring=wiring)
        # Every class: `run_stage` re-raises `StageAbort`/`FatalConfigError` unwrapped and an
        # injected seam may raise anything; one bad call must not discard the other worlds.
        except Exception as failed:  # noqa: BLE001 — one draw's blast radius
            doc = {"failure_reason": f"{type(failed).__name__}: {failed}"}
            _write_wire_log(episode, agent_id=agent_id, prompt=prompt,
                            reply=None, failure=f"{type(failed).__name__}: {failed}")
        else:
            _write_wire_log(episode, agent_id=agent_id, prompt=prompt,
                            reply=reply_text, failure=None)
            try:
                reply = run_mod.validate_reply(reply_text, scope=scope)
            except JudgeRefused:
                # Costs one draw, not the episode. Nothing is written (the raw reply is on the
                # wire log), and an earlier pass's file at this index is removed so a disk
                # re-read cannot queue its findings as this pass's.
                malformed += 1
                try:
                    world.draw(n).delete()
                except NotPlainEntry as stuck:
                    # Only the core's refusal of something not plain at the draw's name is
                    # contained: it is left for the reap scan, and a later disk read counts it
                    # unreadable, so it costs this draw, not the pass. Any other failure (a
                    # denied or read-only tree, a linked folder on the way) would leave a stale
                    # plain draw to be queued as this pass's, so it stops the pass.
                    _logger.warning(f"world {label!r}: the earlier draw {world.draw(n).path.name} "
                                    f"was not removed ({stuck})")
                continue
            doc = run_mod._draw_document(reply, world_dir=world_dir, scope=scope)
            completed += 1
            for finding in doc["findings"]:
                spread[finding["bucket"]] += 1
        import yaml

        documents[n] = doc
        # Not contained: a link planted at this sink refuses the pass. The draw file is what
        # the enqueue reads back, so an aliased one is not an observability fault.
        world.draw(n).write(yaml.safe_dump(doc, sort_keys=False))
    return completed, dict(spread), documents, malformed


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


def _majority_outcome(documents: dict[int, dict[str, Any]], n_completed: int,
                     word: str) -> bool:
    """Did more than half of this pass's completed draws vote `word`?

    Counted over this pass's documents, never the draw directory, where stale files from a
    wider earlier attempt could outvote it."""
    if n_completed == 0:
        return False
    votes = sum(1 for doc in documents.values() if doc.get("episode_outcome") == word)
    return votes * 2 > n_completed


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
    episode_dir: Path, *, runs_base: Path, judge: Any = None,
    draws: int | None = None, git_show: Any = None, queue_dir: Path | None = None,
) -> EpisodeGrade:
    """#1078 D4/J48 (design correction R-A3): `runs_base` is a REQUIRED keyword — no tool
    falls back to a default base or skips its check when it has none. It threads into both the
    world-label collision probe (`family._check_world_labels`) and the sibling union
    (`render.sibling_union`)."""
    import yaml

    episode_dir = Path(episode_dir)
    resolved_judge = judge if judge is not None else _default_judge_seam(episode_dir)
    try:
        return _grade_episode(episode_dir, judge=resolved_judge, runs_base=runs_base,
                              draws=draws, git_show=git_show, queue_dir=queue_dir)
    except JudgeRefused:
        raise
    # Every input-driven failure arrives as `JudgeRefused`, which is what the launcher catches:
    # e.g. a decode error in an archived document, a YAML error in a draw file, a `ValueError`
    # from the guarded mkdir, a timeout on the queue lock.
    except (OSError, ValueError, TimeoutError, yaml.YAMLError) as bad:
        raise JudgeRefused(f"episode {episode_dir}: {bad!r}") from bad


def _grade_episode(  # noqa: PLR0913, PLR0915, PLR0912, C901 — one orchestration, kept whole
    episode_dir: Path, *, judge: Any, runs_base: Path | None, draws: int | None,
    git_show: Any, queue_dir: Path | None,
) -> EpisodeGrade:
    # An existing grade short-circuits; a not-graded stamp does not, so a repaired episode can
    # still be graded.
    existing = read_grade(episode_dir)
    if existing is not None and existing.not_graded is None:
        return existing

    # One handle for the pass: every read through its view, every write through it. A missing
    # episode is refused, never recreated by the not-graded stamp.
    try:
        episode = Episode.open(episode_dir)
    except FileNotFoundError as missing:
        raise JudgeRefused(f"episode {episode_dir}: no such episode directory") from missing
    with episode:
        return _grade_bound_episode(
            episode.view(), episode, judge=judge, runs_base=runs_base, draws=draws,
            git_show=git_show, queue_dir=queue_dir)


def _grade_bound_episode(  # noqa: PLR0913, PLR0915, PLR0912, C901 — see `_grade_episode`
    bound: Bound, episode: Episode, *, judge: Any, runs_base: Path | None, draws: int | None,
    git_show: Any, queue_dir: Path | None,
) -> EpisodeGrade:
    episode_dir = episode.dir
    review = family_mod.read_review_record(bound) or {}
    outcome, reason = _episode_outcome_from_review(review)
    if outcome != "accepted":
        reason = reason or f"the episode's {LAYOUT.review} outcome is {outcome!r}, not 'accepted'"
        # Never the `gradable` default: an unexamined episode must not read like a cleared one.
        record = EpisodeGrade(episode_dir=episode_dir, episode_outcome=NOT_GRADED,
                              not_graded=NotGradedStamp(outcome=outcome, reason=reason))
        _write_judge_yaml(episode, record)
        return record

    configured_draws = draws if draws is not None else _judge_draws()
    model, effort, cap = _judge_model(), _judge_effort(), _judge_cap()
    knobs = {"draws": configured_draws, "model": model, "effort": effort, "payload_cap": cap}

    manifest = family_mod.read_manifest(bound)
    # Manifest, review and samples are each parsed once and threaded into both `grade_family`
    # and every `render`, so the mechanical rows and the prompt come off the same documents.
    samples = family_mod.read_samples_record(bound)
    grade = family_mod.grade_family(episode_dir, manifest=manifest, review=review,
                                    samples=samples, bound=bound, runs_base=runs_base)
    gradable = [row["world"] for row in grade.worlds if family_mod.is_gradable_row(row)]

    # Per-pass facts, resolved once and threaded into every render: every world shares one
    # alert, and the record's `lessons_commit` must be the one the worlds rendered against. The
    # runs-base walk is skipped when no world is gradable, since no render would consume it.
    lessons_commit = _pass_lessons_commit(bound, gradable)
    # One `git show` per (commit, path) for the pass, memoized around the injected seam.
    git_show = _memoized_show(git_show if git_show is not None else render_mod._git_show_default)
    union = render_mod.sibling_union(
        Path(runs_base) if runs_base is not None and gradable else None,
        alert_id=_pass_alert_id(bound, gradable),
        source_run_id=manifest.get("source_run_id"))

    per_world_completed: dict[str, int] = {}
    per_world_spread: dict[str, dict[str, int]] = {}
    per_world_draws: dict[str, dict[int, dict[str, Any]]] = {}
    per_world_malformed: dict[str, int] = {}
    per_world_failed: dict[str, str] = {}
    for label in gradable:
        # Setup faults (box-reachable tree) are contained to this world, so earlier worlds'
        # paid-for draws still reach `judge.yaml`.
        try:
            prompt = _prepare_world_prompt(
                episode, label, bound=bound, payload_cap=cap, git_show=git_show,
                facts=grade.world_facts.get(label), lessons_commit=lessons_commit, union=union,
                manifest=manifest, review=review, samples=samples)
        except (JudgeRefused, OSError, ValueError, TimeoutError) as world_failed:
            per_world_failed[label] = f"{type(world_failed).__name__}: {world_failed}"
            per_world_completed[label] = 0
            per_world_spread[label] = {}
            per_world_draws[label] = {}
            per_world_malformed[label] = 0
            continue
        # Draws are not contained here: the loop contains call and reply failures itself, and
        # a link planted at its write sink must refuse the pass.
        completed, spread, documents, malformed = _run_world_draws(
            episode, label, judge=judge, draws=configured_draws,
            model=model, effort=effort, prompt=prompt)
        per_world_completed[label] = completed
        per_world_spread[label] = spread
        per_world_draws[label] = documents
        per_world_malformed[label] = malformed

    for row in grade.worlds:
        label = row["world"]
        row["completed_draws"] = per_world_completed.get(label, 0)
        row["spread"] = per_world_spread.get(label, {})
        # A reply that failed validation is a draw that ran and produced nothing usable, which
        # is a different state from a draw that never ran; the record says which.
        row["malformed_replies"] = per_world_malformed.get(label, 0)
        if label in per_world_failed:
            # Distinguishes "setup failed" from "ungradable" (both have 0 completed draws).
            row["draws_failed_reason"] = per_world_failed[label]
        # This world's model-drawn world findings join the mechanical ones; withholding applies
        # to the defender lane only.
        if "world_findings" in row:
            # Drop findings citing a sample for a pattern this world was not shown, per pattern.
            # No `or []`: `None` (never recorded) is `cites_sample`'s blanket refusal.
            unavailable_patterns = row.get("sample_unavailable_patterns")
            for draw_doc in per_world_draws.get(label, {}).values():
                for finding in draw_doc.get("findings") or []:
                    if not isinstance(finding, dict) or finding.get("subject") != run_mod.SUBJECT_WORLD:
                        continue
                    if run_mod.cites_sample(finding, unavailable_patterns=unavailable_patterns):
                        continue
                    row["world_findings"].append(finding)

    # The family-level call always runs (an episode with nothing to separate is what it exists
    # to report) and is an addition: its own fault costs only its own contribution.
    family_documents: dict[int, dict[str, Any]] = {}
    family_completed = 0
    family_malformed = 0
    # Recorded, so a refused write sink is distinguishable from "no majority".
    family_failed_reason: str | None = None
    try:
        family_prompt = run_mod._build_family_prompt(manifest=manifest, grade=grade,
                                                      review=review)
        episode.world("family").draws.ensure()
        family_completed, _family_spread, family_documents, family_malformed = (
            _run_world_draws(episode, "family", judge=judge, draws=configured_draws,
                             model=model, effort=effort, prompt=family_prompt,
                             scope="family"))
    except Exception as family_failed:  # noqa: BLE001 — the family call's own fault costs only itself, never the already-completed per-world draws
        family_documents = {}
        family_completed = 0
        family_malformed = 0
        family_failed_reason = f"{type(family_failed).__name__}: {family_failed}"
    family_outcome: str | None = None
    if family_completed:
        for word in sorted(run_mod._REPLY_OUTCOME_ENUM):
            if _majority_outcome(family_documents, family_completed, word):
                family_outcome = word
                break

    episode_outcome = "gradable"
    discard_evidence = {
        "review_pointer":
            f"{episode_dir.name}/{LAYOUT.review}#worlds.*.consistency.{_DRIFT_KEYS_FIELD}"}
    # Discard wins across the whole family before corpus-contradiction is considered, so the
    # outcome does not depend on manifest order.
    if _control_drift_discard(manifest, review) or any(
            _majority_outcome(per_world_draws[label], per_world_completed[label], "discard")
            for label in per_world_completed):
        episode_outcome = "discard"
    elif any(
            _majority_outcome(per_world_draws[label], per_world_completed[label],
                              "corpus-contradiction")
            for label in per_world_completed):
        episode_outcome = "corpus-contradiction"

    verdict_word = episode_outcome if episode_outcome != "gradable" else grade.verdict_word

    pending_file, _lock_file = enqueue_mod._queue_paths(queue_dir)
    questioner_file, _questioner_lock = enqueue_mod._questioner_queue_paths(queue_dir)
    enqueued_to = str(pending_file)
    world_enqueued_to = str(questioner_file)
    # Always called: a blocked outcome closes only the defender lane (`enqueue_report` reads
    # `verdict_word`), never the world lane. Passed as a mapping to avoid re-validating and
    # copying every world row in a new `FamilyGrade`.
    report = enqueue_mod.enqueue_report(
        episode_dir, {"verdict_word": verdict_word, "worlds": grade.worlds},
        queue_dir=queue_dir, drawn=per_world_draws, family_drawn=family_documents)
    enqueued_rows = report.appended
    queue_malformed_rows = report.queue_malformed_rows
    world_queue_malformed_rows = report.world_queue_malformed_rows
    unqueueable = report.unqueueable
    world_enqueued_rows = report.world_appended
    withheld_findings = report.withheld_findings

    record = EpisodeGrade(
        episode_dir=episode_dir, worlds=grade.worlds, verdict_word=verdict_word,
        graded_worlds=grade.graded_worlds, episode_outcome=episode_outcome,
        enqueued_rows=enqueued_rows, enqueued_to=enqueued_to,
        draws={"configured": configured_draws,
              "completed": max(per_world_completed.values(), default=0)},
        knobs=knobs, lessons_commit=lessons_commit, discard_evidence=discard_evidence,
        queue_malformed_rows=queue_malformed_rows,
        world_queue_malformed_rows=world_queue_malformed_rows, unqueueable_findings=unqueueable,
        family_outcome=family_outcome, family_failed_reason=family_failed_reason,
        family_malformed_replies=family_malformed, world_enqueued_rows=world_enqueued_rows,
        world_enqueued_to=world_enqueued_to, withheld_worlds=grade.withheld_worlds,
        measuring_worlds=grade.measuring_worlds, world_findings=report.world_rows,
        withheld_findings=withheld_findings, dispositions=report.dispositions,
    )
    _write_judge_yaml(episode, record)
    return record




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


def _pass_alert_id(bound: Bound, labels: list[str]) -> Any:
    """The alert this episode's worlds all investigate (they share one source run) — the
    union's key. Through `render.episode_alert`, the same rule the enqueue uses."""
    return render_mod.episode_alert(bound, labels).get("alert_id")


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
    graded = frozenset(r["world"] for r in record.worlds if family_mod.is_gradable_row(r))
    measuring = frozenset(
        r["world"] for r in record.worlds
        if r["world"] in graded and r.get("withheld_reason") is None)
    # Assigned rather than `replace`d, which would re-validate and copy every row.
    record.graded_worlds = graded
    record.withheld_worlds = graded - measuring
    record.measuring_worlds = measuring
    return record


#: Built once: constructing a `TypeAdapter` is a schema build.
_GRADE_ADAPTER: TypeAdapter[EpisodeGrade] = TypeAdapter(EpisodeGrade)


def _write_judge_yaml(episode: Episode, record: EpisodeGrade) -> None:
    import yaml

    doc = _GRADE_ADAPTER.dump_python(record, mode="json", exclude=set(_DERIVED))
    # The stamp is present or absent, never null.
    if doc["not_graded"] is None:
        del doc["not_graded"]
    episode.judge.write(yaml.safe_dump(doc, sort_keys=False))


__all__ = ["EpisodeGrade", "JudgeRefused", "NotGradedStamp", "grade_episode", "read_grade"]
