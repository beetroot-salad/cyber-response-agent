"""The family judge: grades an archived branched episode (#921).

`grade_episode` is the orchestration entry point `learning/branch/cli.py` calls at the tail of
`_run_episode`, after the archive step and before the return (J10). It is also the launcher-
independent entry point every test in this suite drives directly.

Flow, per `accepted` episode with no existing `judge.yaml`:
1. `learning.judge.family.grade_family` — the mechanical five-fact pass, per non-control world.
2. `learning.judge.render.render` + `learning.judge.run._build_prompt`/`validate_reply` — one
   model call per graded world per draw, through the injected `judge=` seam, written to
   `worlds/<X>/judge/<n>.yaml`.
3. The episode's outcome — `gradable`, `discard` (mechanical-first, and BEFORE any world's
   corpus-contradiction, so the answer does not depend on manifest order) or
   `corpus-contradiction` — decided from the review record and THIS pass's own draws.
4. `learning.judge.enqueue.enqueue_report` — for a `gradable` episode, one `FindingRow` per
   surviving finding; nothing for `discard`/`corpus-contradiction` (O7).
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

from defender._io import guarded_mkdir, write_guarded  # noqa: E402
from defender.learning.judge import enqueue as enqueue_mod  # noqa: E402
from defender.learning.judge import family as family_mod  # noqa: E402
from defender.learning.judge import render as render_mod  # noqa: E402
from defender.learning.judge import run as run_mod  # noqa: E402

#: The judge's own operator knobs — no `DEFENDER_` prefix (run1/G23: a judge knob spelled with
#: one would be unsettable, matching `QUESTIONER_EFFORT`'s own convention). MODEL and EFFORT are
#: deliberately NOT spelled here: they are `config.judge_model`/`judge_effort`'s knobs and this
#: module reads them through those accessors, so a second constant naming the same env var would
#: be a second place for one name to live. See `run.py`'s docstring on the sharing.
DRAWS_KNOB = "JUDGE_DRAWS"
CAP_KNOB = "JUDGE_PAYLOAD_CAP"

#: `judge.yaml`'s `episode_outcome` for an episode this pass DID NOT grade. Not a member of
#: `_vocab.JUDGE_OUTCOME_ENUM` and deliberately not put there: that vocabulary is the FAMILY's
#: word, which three schemas have to agree on, and "nothing was graded" is a fact about this
#: record alone (`_vocab.py`'s own admission rule).
NOT_GRADED = "not-graded"


def _judge_model() -> str:
    """The judge's model, through `config`'s accessor rather than a second reading of the same
    env var. `config.judge_model()` IS `env_str("JUDGE_MODEL", "kimi-k3")` — spelling that here
    made a byte-identical copy, so the two judges could drift to different DEFAULTS while still
    being impossible to configure APART. See `run.py`'s docstring on why they are one knob."""
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
    #: Findings this pass could not turn into a queue row, one line each naming the finding
    #: and why. Dropped rather than raised on, so the drop is said out loud instead of read
    #: later as a finding the model never emitted.
    unqueueable_findings: list[str] = field(default_factory=list)
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


def _read_review(episode_dir: Path) -> dict[str, Any]:
    """`review.yaml`, parsed once per pass. `{}` when there is none."""
    import yaml

    path = Path(episode_dir) / "review.yaml"
    if not path.is_file():
        return {}
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as bad:
        raise JudgeRefused(f"{path} could not be read: {bad}") from bad
    return doc if isinstance(doc, dict) else {}


def _episode_outcome_from_review(review: dict[str, Any]) -> tuple[str, str]:
    if not review:
        return "incomplete", "no review.yaml on disk"
    episode = review.get("episode")
    outcome = episode.get("outcome") if isinstance(episode, dict) else None
    reason = episode.get("reason") if isinstance(episode, dict) else None
    return (str(outcome) if isinstance(outcome, str) else "incomplete", str(reason or ""))


#: Where `review.py` actually records the capture's disagreement with itself: on the CONTROL
#: world's own consistency block, not on the episode block, and under this name. The judge used
#: to look for `episode.control_drift_keys`, which no writer in this repo has ever emitted — so
#: the mechanical-first `discard` arm below could not fire on a real episode at all.
_DRIFT_KEYS_FIELD = "control_mismatch_keys"


def _envelope_key(envelope: Any) -> str | None:
    """The discriminating call's identity, in the SAME encoding every recorded key uses.

    Through `family.mapping_key`, the one home for that encoding: the ledger row's key and this
    one MUST agree for the drift check below to match anything, and they were two independent
    `def`s doing the same three coercions around `ledger.request_key` — which the
    duplicate-helper gate cannot see, because it keys on the symbol name."""
    if not isinstance(envelope, dict):
        return None
    return family_mod.mapping_key(envelope)


def _control_drift_keys(review: dict[str, Any]) -> list[Any]:
    """The keys the review recorded the capture as having disagreed with itself on.

    They live per world, on the CONTROL arm's `consistency` block (`review._review_world`
    returns `control_mismatch_keys`, and `_record` files each world's result under
    `worlds[<label>]`). Read across every world's block rather than by naming the control's
    label: which arm is the control is the manifest's `role`, and this reader already has the
    review in hand and not the manifest — a non-control world's block carries the control's
    list copied in, so the union is the same set either way."""
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
    """Mechanical-first `discard`: the discriminator envelope's key is among the keys the review
    recorded as control drift — the capture disagreed with itself on the discriminating call.

    Takes the two documents rather than re-reading them: `family.yaml` was being parsed by
    `grade_family`, by this check, by the orchestration for `source_run_id` and once more per
    world inside `render`, and `review.yaml` twice — five and two parses of two files that one
    pass has already read, with no guarantee they are identical across them."""
    key = _envelope_key(family_mod.discriminator_of(doc).get("envelope"))
    if key is None:
        return False
    return key in _control_drift_keys(review)


def _run_world_draws(  # noqa: PLR0913 — one world's whole per-draw configuration surface
    episode_dir: Path, label: str, *, judge: Any, runs_base: Path | None, draws: int,
    model: str, effort: str, payload_cap: int, git_show: Any,
    facts: family_mod.WorldFacts | None, lessons_commit: str | None,
    union: tuple[list[dict[str, Any]], dict[str, Any]],
) -> tuple[int, dict[str, int], dict[int, dict[str, Any]], int]:
    """Render once, call the judge `draws` times, write one `worlds/<X>/judge/<n>.yaml` per
    draw. Returns `(completed_draws, bucket_spread, this pass's draw documents KEYED BY DRAW
    INDEX, malformed replies)`. A failed call writes a draw record naming its own failure; a MALFORMED REPLY
    writes nothing at all and is counted — and both let the loop continue to the next draw.

    The documents are RETURNED rather than left to be read back: they are what this pass
    produced, and a reader that re-globs the draw directory cannot tell them from a stale file
    a wider earlier attempt left behind (P4: a retry clobbers, it does not clean up)."""
    from defender.learning.core.config import RunUnprocessable, StageWiring
    from defender.runtime.agent_role import AgentRole

    world_dir = Path(episode_dir) / "worlds" / label
    judge_input = render_mod.render(
        episode_dir, label, runs_base, git_show=git_show, payload_cap=payload_cap, facts=facts,
        lessons_commit=lessons_commit, union=union)
    prompt = run_mod._build_prompt(judge_input, world_label=label)

    draw_dir = world_dir / "judge"
    guarded_mkdir(draw_dir, base=episode_dir)

    completed = 0
    spread: Counter[str] = Counter()
    documents: dict[int, dict[str, Any]] = {}
    malformed = 0
    for n in range(draws):
        agent_id = f"judge:{label}:{n}"
        wiring = StageWiring(
            prompt_path=run_mod._ROLE_PROMPT, model=model, effort=effort,
            trace_name=f"{agent_id}_trace.jsonl", label=agent_id)
        reply_text: str | None = None
        doc: dict[str, Any]
        try:
            reply_text = judge(prompt, role=AgentRole.QUESTIONER, agent_id=agent_id,
                               wiring=wiring)
        except RunUnprocessable as failed:
            doc = {"failure_reason": f"RunUnprocessable: {failed}"}
            _write_wire_log(episode_dir, agent_id=agent_id, prompt=prompt,
                            reply=None, failure=str(failed))
        else:
            _write_wire_log(episode_dir, agent_id=agent_id, prompt=prompt,
                            reply=reply_text, failure=None)
            try:
                reply = run_mod.validate_reply(reply_text)
            except JudgeRefused:
                # ONE DRAW, not the episode. A malformed reply is a model failure of the same
                # kind as the transport failure above, and containing one while propagating the
                # other threw away every already-completed world's draws and left no
                # `judge.yaml` at all — the blast radius the enqueue path refuses for a single
                # unusable finding. NOTHING IS WRITTEN TO THE DRAW DIRECTORY for it, because
                # nothing may be read off a reply that failed validation; the raw bytes are
                # already on the wire log above, which is where an operator looks for them.
                malformed += 1
                # AND THE INDEX IS CLEARED. P4 says a retry clobbers each draw file in place
                # and cleans nothing up, so writing nothing here would leave an EARLIER pass's
                # `<n>.yaml` standing at an index this pass produced no answer for — and the
                # enqueue, which reads the draw directory back, would queue that older pass's
                # findings as this one's. Removing it is what makes "this pass wrote nothing at
                # index n" true on disk as well as in memory.
                (draw_dir / f"{n}.yaml").unlink(missing_ok=True)
                continue
            doc = run_mod._draw_document(reply, world_dir=world_dir)
            completed += 1
            for finding in doc["findings"]:
                spread[finding["bucket"]] += 1
        import yaml

        documents[n] = doc
        write_guarded(draw_dir / f"{n}.yaml", yaml.safe_dump(doc, sort_keys=False),
                     mode="replace")
    return completed, dict(spread), documents, malformed


def _write_wire_log(
    episode_dir: Path, *, agent_id: str, prompt: str, reply: str | None, failure: str | None,
) -> None:
    """The judge's own wire-log record — the whole framed prompt and the whole reply verbatim,
    one file per call, under the same `wire_logs/` component the runtime's own
    `observe.stage_trace_path` writes to (so the existing `files.names_wire_log_dir` policy
    denial — a path-COMPONENT test — covers it with no policy change). Written by this pass
    directly rather than left to `run_stage`, because the injected `judge=` seam stands in for
    the whole call and carries no logger of its own.

    ITS OWN FILE NAME, and that is the whole point of this function taking `agent_id` rather
    than the wiring's `trace_name`. `run_stage` opens a `RequestLogger` on
    `stage_trace_path(episode_dir, wiring.trace_name)` and streams the real request/response
    records into it; writing this one-line summary to that same path with `mode="replace"`
    DESTROYED it after every draw — every tool call, retry and token count the production seam
    had just recorded, gone, and invisible to a suite in which every judge call is injected and
    so never opens the real logger."""
    from defender.runtime.observe import stage_trace_path

    path = stage_trace_path(Path(episode_dir), f"{agent_id}_framed_trace.jsonl")
    row = {"agent_id": agent_id, "prompt": prompt, "reply": reply, "failure": failure}
    write_guarded(path, json.dumps(row) + "\n", mode="replace")


def _majority_outcome(documents: dict[int, dict[str, Any]], n_completed: int,
                     word: str) -> bool:
    """Did more than half of THIS pass's completed draws vote `word`?

    Over the documents this pass produced, never over the draw directory: counting votes off
    disk while dividing by this pass's completed count mixes two populations, so a re-grade at
    a NARROWER draw count could be carried by the stale files a wider attempt left behind (P4
    says nothing cleans them up) — two votes out of two stale files beating a two-draw pass
    that voted the other way."""
    if n_completed == 0:
        return False
    votes = sum(1 for doc in documents.values() if doc.get("episode_outcome") == word)
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
    import yaml

    episode_dir = Path(episode_dir)
    resolved_judge = judge if judge is not None else _default_judge_seam(episode_dir)
    try:
        return _grade_episode(episode_dir, judge=resolved_judge, runs_base=runs_base,
                              draws=draws, git_show=git_show, queue_dir=queue_dir)
    except JudgeRefused:
        raise
    # EVERY input-driven failure arrives as this design's own refusal, not as whichever native
    # class the input happened to produce. `OSError` alone left at least four live escapes —
    # a `UnicodeDecodeError` (a `ValueError`) out of an archived document, a `yaml.YAMLError`
    # (which is not a `ValueError`) out of a draw file, a `ValueError` out of the guarded mkdir
    # on a manifest-authored path, a `TimeoutError` waiting on the queue lock — and each of
    # them reached the launcher as a bare traceback past a handler that names `JudgeRefused`.
    except (OSError, ValueError, TimeoutError, yaml.YAMLError) as bad:
        raise JudgeRefused(f"episode {episode_dir}: {bad!r}") from bad


def _grade_episode(  # noqa: PLR0913, PLR0915, C901 — one orchestration, deliberately not split (its own steps are the demand)
    episode_dir: Path, *, judge: Any, runs_base: Path | None, draws: int | None,
    git_show: Any, queue_dir: Path | None,
) -> EpisodeGrade:
    # THE EXISTING RECORD IS CONSULTED FIRST, and a NOT-GRADED stamp does not count as one. An
    # episode that was skipped because its review said `incomplete` can be repaired and graded
    # afterwards; reading the outcome first meant the refusal stamp was found on the second
    # attempt and returned as though it were the grade, so a repaired episode answered with the
    # old refusal forever.
    existing = _existing_grade(episode_dir)
    if existing is not None and not existing.get("not_graded"):
        return _grade_from_document(episode_dir, existing)

    review = _read_review(episode_dir)
    outcome, reason = _episode_outcome_from_review(review)
    if outcome != "accepted":
        reason = reason or f"the episode's review.yaml outcome is {outcome!r}, not 'accepted'"
        # `episode_outcome` says NOT-GRADED, never the `gradable` default: the field is what a
        # reader keys on to tell what happened to an episode, and an episode nothing looked at
        # reporting the same word as one the judge cleared is the one answer it must not give.
        record = EpisodeGrade(episode_dir=episode_dir, episode_outcome=NOT_GRADED,
                              not_graded={"outcome": outcome, "reason": reason})
        _write_judge_yaml(episode_dir, record)
        return record

    configured_draws = draws if draws is not None else _judge_draws()
    model, effort, cap = _judge_model(), _judge_effort(), _judge_cap()
    knobs = {"draws": configured_draws, "model": model, "effort": effort, "payload_cap": cap}

    manifest = family_mod._raw_manifest(episode_dir)
    grade = family_mod.grade_family(episode_dir)
    gradable = [row["world"] for row in grade.worlds if not row.get("ungradable")]

    # BOTH PER-PASS FACTS, RESOLVED ONCE AND THREADED (J8's own sentence, and J9's union with
    # it). Every world of one episode investigates the same alert, so the sibling union's answer
    # is identical for all of them while the walk costs one `alert.json` read and one report
    # parse per run under the operator's whole runs base; and `lessons_commit` was read per
    # world inside `render` AND read a second time out here purely to fill the record, so the
    # value the record carried could disagree with what worlds 2..N actually rendered against.
    lessons_commit = _pass_lessons_commit(episode_dir, gradable)
    # ONE `git show` PER (commit, path) FOR THE PASS. `lessons_commit` is a per-pass constant
    # and the corpus is small, so N worlds loading the same lesson spawned N subprocesses for
    # the same bytes. The memo wraps the injected seam rather than living inside `render`, so
    # the render keeps taking a plain `(cwd, rev, path) -> str | None` and a caller that wants
    # no memo simply does not add one.
    git_show = _memoized_show(git_show if git_show is not None else render_mod._git_show_default)
    union = render_mod.sibling_union(
        Path(runs_base) if runs_base is not None else None,
        alert_id=_pass_alert_id(episode_dir, gradable),
        source_run_id=manifest.get("source_run_id"))

    per_world_completed: dict[str, int] = {}
    per_world_spread: dict[str, dict[str, int]] = {}
    per_world_draws: dict[str, dict[int, dict[str, Any]]] = {}
    per_world_malformed: dict[str, int] = {}
    for label in gradable:
        completed, spread, documents, malformed = _run_world_draws(
            episode_dir, label, judge=judge, runs_base=runs_base, draws=configured_draws,
            model=model, effort=effort, payload_cap=cap, git_show=git_show,
            facts=grade.world_facts.get(label), lessons_commit=lessons_commit, union=union)  # noqa: E501
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

    episode_outcome = "gradable"
    discard_evidence = {
        "review_pointer":
            f"{episode_dir.name}/review.yaml#worlds.*.consistency.{_DRIFT_KEYS_FIELD}"}
    # DISCARD IS MECHANICAL-FIRST, and that has to mean first across the WHOLE family, not
    # first within whichever world the loop reached first. Checking both words per world and
    # breaking on either made the episode's outcome depend on manifest order: one world voting
    # discard and another voting corpus-contradiction answered differently depending on which
    # was listed first, in a pass whose own docstring calls itself order-independent (O3).
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
    enqueued_to = str(pending_file)
    enqueued_rows = 0
    queue_malformed_rows = 0
    unqueueable: list[str] = []
    if episode_outcome == "gradable":
        # The malformed count comes back FROM the append, measured under the queue's own lock:
        # reading the shared queue again afterwards raced every other appender on it.
        report = enqueue_mod.enqueue_report(
            episode_dir,
            family_mod.FamilyGrade(episode_dir=episode_dir, worlds=grade.worlds,
                                   verdict_word=verdict_word,
                                   graded_worlds=grade.graded_worlds),
            queue_dir=queue_dir, drawn=per_world_draws)
        enqueued_rows = report.appended
        queue_malformed_rows = report.queue_malformed_rows
        unqueueable = report.unqueueable

    record = EpisodeGrade(
        episode_dir=episode_dir, worlds=grade.worlds, verdict_word=verdict_word,
        graded_worlds=grade.graded_worlds, episode_outcome=episode_outcome,
        enqueued_rows=enqueued_rows, enqueued_to=enqueued_to,
        draws={"configured": configured_draws,
              "completed": max(per_world_completed.values(), default=0)},
        knobs=knobs, lessons_commit=lessons_commit, discard_evidence=discard_evidence,
        queue_malformed_rows=queue_malformed_rows, unqueueable_findings=unqueueable,
    )
    _write_judge_yaml(episode_dir, record)
    return record




def _memoized_show(show: Any) -> Any:
    """`show`, answering each `(rev, path)` once per pass and replaying the answer after."""
    seen: dict[tuple[str, str], Any] = {}

    def invoke(cwd: Path, rev: str, path: str) -> Any:
        key = (str(rev), str(path))
        if key not in seen:
            seen[key] = show(cwd, rev, path)
        return seen[key]

    return invoke


def _pass_lessons_commit(episode_dir: Path, labels: list[str]) -> str | None:
    """The commit every lesson body in this pass is read at — J8's "resolved once per pass".

    The FIRST graded world's provenance stamp, which is what the record has always reported;
    resolving it here rather than letting each world fall back to its own inside `render` is
    what makes the record's value and the rendered value the same value."""
    for label in labels:
        commit = render_mod._read_provenance(Path(episode_dir) / "worlds" / label).get("commit")
        if commit is not None:
            return str(commit)
    return None


def _pass_alert_id(episode_dir: Path, labels: list[str]) -> Any:
    """The alert this episode's worlds all investigate — the union's key.

    Read off the first graded world that carries one: every world of a family branches from one
    source run and therefore one alert, which is exactly why the union is a per-pass fact."""
    for label in labels:
        alert_id = render_mod._world_alert_id(Path(episode_dir) / "worlds" / label)
        if alert_id is not None:
            return alert_id
    return None


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
        unqueueable_findings=list(doc.get("unqueueable_findings") or []),
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
        "unqueueable_findings": record.unqueueable_findings,
    }
    if record.not_graded is not None:
        doc["not_graded"] = record.not_graded
    write_guarded(_judge_yaml_path(episode_dir), yaml.safe_dump(doc, sort_keys=False),
                 mode="replace")


__all__ = ["EpisodeGrade", "JudgeRefused", "grade_episode"]
