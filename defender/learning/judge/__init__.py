"""The family judge: grades an archived branched episode (#921).

`grade_episode` is the orchestration entry point `learning/branch/cli.py` calls at the tail of
`_run_episode`, after the archive step and before the return (J10). It is also the launcher-
independent entry point every test in this suite drives directly.

Flow, per `accepted` episode with no existing `judge.yaml`:
1. `learning.judge.family.grade_family` — the mechanical five-fact pass, per non-control world.
2. `learning.judge.render.render` + `learning.judge.run._build_prompt`/`validate_reply` — one
   model call per graded world per draw, through the injected `judge=` seam, written to
   `worlds/<X>/judge/<n>.yaml`.
3. The episode's outcome — `gradable`, `discard` (mechanical-first, or a world's majority) or
   `corpus-contradiction` (a world's majority) — decided from the review record and the draws.
4. `learning.judge.enqueue.enqueue` — for a `gradable` episode, one `FindingRow` per surviving
   finding; nothing for `discard`/`corpus-contradiction` (O7).
5. `episodes/<id>/judge.yaml` — written LAST, after the enqueue (J11), carrying the enqueued
   row count and every world's completed-draw count, so its presence certifies the whole pass.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# `JudgeRefused` lives in `_errors.py`, its own module, so every submodule below can import it
# without a package-`__init__` import cycle; re-exported here as the ONE class object every
# caller — including `_triplet_947.refusals()`'s `sym("learning.judge", "JudgeRefused")` — sees.
from defender.learning.judge._errors import JudgeRefused  # noqa: E402

from defender._env import env_str  # noqa: E402
from defender._io import guarded_mkdir, read_jsonl_rows_report, write_guarded  # noqa: E402
from defender.learning.judge import enqueue as enqueue_mod  # noqa: E402
from defender.learning.judge import family as family_mod  # noqa: E402
from defender.learning.judge import render as render_mod  # noqa: E402
from defender.learning.judge import run as run_mod  # noqa: E402

#: The judge's own three model knobs — no `DEFENDER_` prefix (run1/G23: a judge knob spelled
#: with one would be unsettable, matching `QUESTIONER_EFFORT`'s own convention).
DRAWS_KNOB = "JUDGE_DRAWS"
MODEL_KNOB = "JUDGE_MODEL"
EFFORT_KNOB = "JUDGE_EFFORT"
CAP_KNOB = "JUDGE_PAYLOAD_CAP"


def _judge_model() -> str:
    return env_str(MODEL_KNOB, "kimi-k3")


def _judge_effort() -> str:
    return env_str(EFFORT_KNOB, "medium")


def _judge_draws() -> int:
    from defender._env import env_int

    return env_int(DRAWS_KNOB, 1)


def _judge_cap() -> int:
    from defender._env import env_int

    return env_int(CAP_KNOB, 20000)


@dataclass
class EpisodeGrade:
    """`grade_episode`'s return value — the same shape `judge.yaml` is written as."""

    episode_dir: Path
    worlds: list[dict[str, Any]] = field(default_factory=list)
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
    not_graded: dict[str, Any] | None = None


def _judge_yaml_path(episode_dir: Path) -> Path:
    return Path(episode_dir) / "judge.yaml"


def _existing_grade(episode_dir: Path) -> dict[str, Any] | None:
    import yaml

    path = _judge_yaml_path(episode_dir)
    if not path.is_file():
        return None
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as bad:
        raise JudgeRefused(f"{path} exists but could not be read as a family grade: {bad}") from bad
    if not isinstance(doc, dict):
        raise JudgeRefused(f"{path} exists but is not a family grade document")
    return doc


def _episode_outcome_from_review(episode_dir: Path) -> tuple[str, str]:
    import yaml

    path = Path(episode_dir) / "review.yaml"
    if not path.is_file():
        return "incomplete", "no review.yaml on disk"
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as bad:
        raise JudgeRefused(f"{path} could not be read: {bad}") from bad
    episode = doc.get("episode") if isinstance(doc, dict) else None
    outcome = episode.get("outcome") if isinstance(episode, dict) else None
    reason = episode.get("reason") if isinstance(episode, dict) else None
    return (str(outcome) if isinstance(outcome, str) else "incomplete", str(reason or ""))


def _envelope_key(envelope: Any) -> str | None:
    if not isinstance(envelope, dict):
        return None
    return json.dumps([envelope.get("system"), envelope.get("verb"), envelope.get("params")])


def _control_drift_discard(episode_dir: Path) -> bool:
    """Mechanical-first `discard`: the discriminator envelope's key is among the review's
    `control_drift_keys` — the capture disagreed with itself on the discriminating call."""
    import yaml

    doc = family_mod._raw_manifest(episode_dir)
    key = _envelope_key(doc.get("discriminator", {}).get("envelope"))
    review_path = Path(episode_dir) / "review.yaml"
    if key is None or not review_path.is_file():
        return False
    try:
        review = yaml.safe_load(review_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        return False
    drift_keys = (review.get("episode") or {}).get("control_drift_keys") or []
    return key in drift_keys


def _run_world_draws(  # noqa: PLR0913 — one world's whole per-draw configuration surface
    episode_dir: Path, label: str, *, judge: Any, runs_base: Path | None, draws: int,
    model: str, effort: str, payload_cap: int, git_show: Any,
) -> tuple[int, dict[str, int]]:
    """Render once, call the judge `draws` times, write one `worlds/<X>/judge/<n>.yaml` per
    draw. Returns `(completed_draws, bucket_spread)`. A malformed reply propagates immediately
    (nothing partial is left behind for THIS draw); a failed call writes a draw record naming
    its own failure and the loop continues to the next draw."""
    from defender.learning.core.config import RunUnprocessable, StageWiring
    from defender.runtime.agent_role import AgentRole

    world_dir = Path(episode_dir) / "worlds" / label
    judge_input = render_mod.render(
        episode_dir, label, runs_base, git_show=git_show, payload_cap=payload_cap)
    prompt = run_mod._build_prompt(judge_input, world_label=label)

    draw_dir = world_dir / "judge"
    guarded_mkdir(draw_dir, base=episode_dir)

    completed = 0
    spread: Counter[str] = Counter()
    for n in range(draws):
        agent_id = f"judge:{label}:{n}"
        trace_name = f"{agent_id}_trace.jsonl"
        wiring = StageWiring(
            prompt_path=run_mod._ROLE_PROMPT, model=model, effort=effort,
            trace_name=trace_name, label=agent_id)
        reply_text: str | None = None
        doc: dict[str, Any]
        try:
            reply_text = judge(prompt, role=AgentRole.QUESTIONER, agent_id=agent_id,
                               wiring=wiring)
        except RunUnprocessable as failed:
            doc = {"failure_reason": f"RunUnprocessable: {failed}"}
            _write_wire_log(episode_dir, trace_name, agent_id=agent_id, prompt=prompt,
                            reply=None, failure=str(failed))
        else:
            _write_wire_log(episode_dir, trace_name, agent_id=agent_id, prompt=prompt,
                            reply=reply_text, failure=None)
            reply = run_mod.validate_reply(reply_text)
            doc = run_mod._draw_document(reply, world_dir=world_dir)
            completed += 1
            for finding in doc["findings"]:
                spread[finding["bucket"]] += 1
        import yaml

        write_guarded(draw_dir / f"{n}.yaml", yaml.safe_dump(doc, sort_keys=False),
                     mode="replace")
    return completed, dict(spread)


def _write_wire_log(
    episode_dir: Path, trace_name: str, *, agent_id: str, prompt: str, reply: str | None,
    failure: str | None,
) -> None:
    """The judge's own wire-log record — the whole framed prompt and the whole reply
    verbatim, one file per call, at `<episode_dir>/wire_logs/<agent_id>_trace.jsonl` (the same
    `wire_logs/` component the runtime's own `observe.stage_trace_path` writes under, so the
    existing `files.names_wire_log_dir` policy denial — a path-COMPONENT test — covers it with
    no policy change). Written by this pass directly rather than left to `run_stage`, because
    the injected `judge=` seam stands in for the whole call and carries no logger of its own.
    """
    from defender.runtime.observe import stage_trace_path

    path = stage_trace_path(Path(episode_dir), trace_name)
    row = {"agent_id": agent_id, "prompt": prompt, "reply": reply, "failure": failure}
    write_guarded(path, json.dumps(row) + "\n", mode="replace")


def _majority_outcome(episode_dir: Path, label: str, n_completed: int, word: str) -> bool:
    if n_completed == 0:
        return False
    votes = 0
    for path in sorted((Path(episode_dir) / "worlds" / label / "judge").glob("*.yaml")):
        import yaml

        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if doc.get("episode_outcome") == word:
            votes += 1
    return votes * 2 > n_completed


def _default_judge_seam(episode_dir: Path) -> Any:
    """The production `(prompt, *, role, agent_id, wiring) -> str` for every judge call, built
    the way `seams.model_seam` builds the questioner's — `run_stage` under the SAME
    `QuestionerDeps`/`AgentRole.QUESTIONER` key (D2), differing only in that the judge's own
    `wiring` (model/effort/trace name) arrives from the caller rather than being built here."""
    from defender.learning._pydantic_stage import run_stage
    from defender.learning.branch.questioner import QuestionerDeps
    from defender.learning.core.config import StageContext, subagent_timeout

    def invoke(prompt: str, *, role: Any = None, agent_id: str = "judge", wiring: Any = None,
              **_kw: Any) -> str:
        return run_stage(
            stage="judge", wiring=wiring,
            ctx=StageContext(learning_run_dir=Path(episode_dir), user=prompt, request_limit=1,
                             wall_clock_timeout=subagent_timeout()),
            deps=QuestionerDeps(),
        )

    return invoke


def grade_episode(  # noqa: PLR0913 — the orchestration's whole configuration surface
    episode_dir: Path, *, judge: Any = None, runs_base: Path | None = None,
    draws: int | None = None, git_show: Any = None, queue_dir: Path | None = None,
) -> EpisodeGrade:
    episode_dir = Path(episode_dir)
    resolved_judge = judge if judge is not None else _default_judge_seam(episode_dir)
    try:
        return _grade_episode(episode_dir, judge=resolved_judge, runs_base=runs_base,
                              draws=draws, git_show=git_show, queue_dir=queue_dir)
    except JudgeRefused:
        raise
    except OSError as bad:
        raise JudgeRefused(f"episode {episode_dir}: {bad}") from bad


def _grade_episode(  # noqa: PLR0913, PLR0915, C901 — one orchestration, deliberately not split (its own steps are the demand)
    episode_dir: Path, *, judge: Any, runs_base: Path | None, draws: int | None,
    git_show: Any, queue_dir: Path | None,
) -> EpisodeGrade:
    outcome, reason = _episode_outcome_from_review(episode_dir)
    if outcome != "accepted":
        reason = reason or f"the episode's review.yaml outcome is {outcome!r}, not 'accepted'"
        record = EpisodeGrade(episode_dir=episode_dir, not_graded={"outcome": outcome,
                                                                    "reason": reason})
        _write_judge_yaml(episode_dir, record)
        return record

    existing = _existing_grade(episode_dir)
    if existing is not None:
        return _grade_from_document(episode_dir, existing)

    configured_draws = draws if draws is not None else _judge_draws()
    model, effort, cap = _judge_model(), _judge_effort(), _judge_cap()
    knobs = {"draws": configured_draws, "model": model, "effort": effort, "payload_cap": cap}

    grade = family_mod.grade_family(episode_dir)

    per_world_completed: dict[str, int] = {}
    per_world_spread: dict[str, dict[str, int]] = {}
    lessons_commit: str | None = None
    for row in grade.worlds:
        label = row["world"]
        if row.get("ungradable"):
            continue
        completed, spread = _run_world_draws(
            episode_dir, label, judge=judge, runs_base=runs_base, draws=configured_draws,
            model=model, effort=effort, payload_cap=cap, git_show=git_show)
        per_world_completed[label] = completed
        per_world_spread[label] = spread
        if lessons_commit is None:
            provenance = render_mod._read_provenance(Path(episode_dir) / "worlds" / label)
            lessons_commit = provenance.get("commit")

    for row in grade.worlds:
        label = row["world"]
        row["completed_draws"] = per_world_completed.get(label, 0)
        row["spread"] = per_world_spread.get(label, {})

    episode_outcome = "gradable"
    discard_evidence = {
        "review_pointer": f"{episode_dir.name}/review.yaml#episode.control_drift_keys"}
    if _control_drift_discard(episode_dir):
        episode_outcome = "discard"
    else:
        for label in per_world_completed:
            if _majority_outcome(episode_dir, label, per_world_completed[label], "discard"):
                episode_outcome = "discard"
                break
            if _majority_outcome(episode_dir, label, per_world_completed[label],
                                 "corpus-contradiction"):
                episode_outcome = "corpus-contradiction"
                break

    verdict_word = episode_outcome if episode_outcome != "gradable" else grade.verdict_word

    pending_file, _lock_file = enqueue_mod._queue_paths(queue_dir, episode_dir)
    enqueued_to = str(pending_file)
    enqueued_rows = 0
    queue_malformed_rows = 0
    if episode_outcome == "gradable":
        enqueued_rows = enqueue_mod.enqueue(
            episode_dir,
            family_mod.FamilyGrade(episode_dir=episode_dir, worlds=grade.worlds,
                                   verdict_word=verdict_word,
                                   graded_worlds=grade.graded_worlds),
            queue_dir=queue_dir)
        _rows, queue_malformed_rows = read_jsonl_rows_report(pending_file)

    record = EpisodeGrade(
        episode_dir=episode_dir, worlds=grade.worlds, verdict_word=verdict_word,
        graded_worlds=grade.graded_worlds, episode_outcome=episode_outcome,
        enqueued_rows=enqueued_rows, enqueued_to=enqueued_to,
        draws={"configured": configured_draws,
              "completed": max(per_world_completed.values(), default=0)},
        knobs=knobs, lessons_commit=lessons_commit, discard_evidence=discard_evidence,
        queue_malformed_rows=queue_malformed_rows,
    )
    _write_judge_yaml(episode_dir, record)
    return record


def _grade_from_document(episode_dir: Path, doc: dict[str, Any]) -> EpisodeGrade:
    return EpisodeGrade(
        episode_dir=episode_dir, worlds=list(doc.get("worlds") or []),
        verdict_word=doc.get("verdict_word", "undecidable"),
        graded_worlds=frozenset(
            r["world"] for r in (doc.get("worlds") or []) if not r.get("ungradable")),
        episode_outcome=doc.get("episode_outcome", "gradable"),
        enqueued_rows=doc.get("enqueued_rows", 0), enqueued_to=doc.get("enqueued_to", ""),
        draws=doc.get("draws", {}), knobs=doc.get("knobs", {}),
        lessons_commit=doc.get("lessons_commit"),
        discard_evidence=doc.get("discard_evidence", {}),
        queue_malformed_rows=doc.get("queue_malformed_rows", 0),
        not_graded=doc.get("not_graded"),
    )


def _write_judge_yaml(episode_dir: Path, record: EpisodeGrade) -> None:
    import yaml

    doc: dict[str, Any] = {
        "worlds": record.worlds, "verdict_word": record.verdict_word,
        "episode_outcome": record.episode_outcome, "enqueued_rows": record.enqueued_rows,
        "enqueued_to": record.enqueued_to, "draws": record.draws, "knobs": record.knobs,
        "lessons_commit": record.lessons_commit, "discard_evidence": record.discard_evidence,
        "queue_malformed_rows": record.queue_malformed_rows,
    }
    if record.not_graded is not None:
        doc["not_graded"] = record.not_graded
    write_guarded(_judge_yaml_path(episode_dir), yaml.safe_dump(doc, sort_keys=False),
                 mode="replace")


__all__ = ["EpisodeGrade", "JudgeRefused", "grade_episode"]
