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
import sys
from collections import Counter
from dataclasses import field
from pathlib import Path
from typing import Annotated, Any

from pydantic import AfterValidator, ConfigDict, TypeAdapter, ValidationError
from pydantic.dataclasses import dataclass


# `JudgeRefused` lives in `_errors.py`, its own module, so every submodule below can import it
# without a package-`__init__` import cycle; re-exported here as the ONE class object every
# caller — including `_triplet_947.refusals()`'s `sym("learning.judge", "JudgeRefused")` — sees.
from defender.learning.judge._errors import JudgeRefused  # noqa: E402

from defender._io import guarded_mkdir, write_guarded  # noqa: E402
from defender.learning.branch.archive import (  # noqa: E402
    DRAWS_DIRNAME,
    JUDGE_NAME,
    REVIEW_NAME,
    WORLDS_DIRNAME,
)
from defender.learning.judge import enqueue as enqueue_mod  # noqa: E402
from defender.learning.judge import family as family_mod  # noqa: E402
from defender.learning.judge import render as render_mod  # noqa: E402
from defender.learning.judge import run as run_mod  # noqa: E402

#: The judge's own operator knobs — no `DEFENDER_` prefix (run1/G23: a judge knob spelled with
#: one would be unsettable, matching `QUESTIONER_EFFORT`'s own convention). MODEL and EFFORT are
#: deliberately NOT spelled here: they are `config.judge_model`/`judge_effort`'s knobs and this
#: module reads them through those accessors, so a second constant naming the same env var would
#: be a second place for one name to live. `run.py`'s docstring records who ELSE reads those
#: two names — the collision did not leave with the old pipeline judge.
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
    made a byte-identical copy, so a reader of this name could drift to a different DEFAULT
    while still being impossible to configure APART. That caveat outlived the old pipeline
    judge it was written about: `evals/oracle_golden/judge.py` reads the same two env vars with
    its own defaults. `run.py`'s docstring carries the collision."""
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
class NotGradedStamp:
    """Why the pass declined to grade an episode: the review's outcome word and its reason."""

    outcome: str
    reason: str


def _rows_name_their_world(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The one thing the record asks of a world row beyond being a mapping: it names its world.
    Every other key belongs to the row's declared owners and is carried as written."""
    for row in rows:
        if not isinstance(row.get("world"), str):
            raise ValueError(f"a world row does not name its world: {row!r}")
    return rows


@dataclass(config=ConfigDict(strict=True))
class EpisodeGrade:
    """`grade_episode`'s return value — the same shape `judge.yaml` is written as.

    THE SCHEMA OF THE RECORD, in both directions: `_write_judge_yaml` dumps this class and
    `_grade_from_document` constructs it from the file's keys, so the field list is spelled
    here and nowhere else. A pydantic dataclass, STRICT: every construction — the live pass's
    and the read-back's alike — validates each field by type, with no coercion (`"3"` is not
    an `int`, a list is not a `frozenset`), and a document of the wrong shape is a
    `ValidationError` at the constructor rather than a value of the wrong type in a field.
    `episode_dir` and the three `frozenset` fields are DERIVED — never written, re-computed
    from the rows on every read (`_DERIVED`).
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
    #: and why. Dropped rather than raised on, so the drop is said out loud instead of read
    #: later as a finding the model never emitted.
    unqueueable_findings: list[str] = field(default_factory=list)
    not_graded: NotGradedStamp | None = None
    #: #1007's family-level half (M5): the family draw's own majority-resolved outcome word
    #: (`_REPLY_OUTCOME_ENUM` — never the family's `verdict_word`, a different vocabulary), and
    #: how many family-level rows this pass enqueued and where.
    family_outcome: str | None = None
    #: M5's own fault and its own malformed count, named the way a world's `draws_failed_reason`
    #: / `malformed_replies` are: `family_outcome: None` alone cannot tell a call that ran and
    #: reached no majority from one whose draw sink was refused.
    family_failed_reason: str | None = None
    family_malformed_replies: int = 0
    world_enqueued_rows: int = 0
    world_enqueued_to: str = ""
    #: The withholding ladder's own record (O4/M3): every graded world's `withheld_reason`,
    #: named — `withheld_worlds`/`measuring_worlds` partition `graded_worlds`.
    withheld_worlds: frozenset[str] = field(default_factory=frozenset)
    measuring_worlds: frozenset[str] = field(default_factory=frozenset)
    #: Every `subject: world` row this pass BUILT and handed to the appender (mechanical,
    #: per-world model draws and the family draw alike), for an in-process caller that wants
    #: them without re-reading the queue file. NOT "enqueued": this is
    #: `EnqueueReport.world_rows`, and the questioner channel dedups on `finding_id`, so a
    #: re-grade builds every row again and appends none — `world_enqueued_rows` is what
    #: actually reached the queue, and the two disagree on any re-grade.
    world_findings: list[dict[str, Any]] = field(default_factory=list)
    #: O4/F7: `{finding, world, reason}` for every defender finding this pass withheld rather
    #: than enqueued (`enqueue.EnqueueReport.withheld_findings`) — the operator artifact O4
    #: promises: not merely THAT a world's defender findings were withheld (`withheld_worlds`
    #: already says that), but WHICH finding and why, since the draw document it came off is
    #: not part of this design's write set.
    withheld_findings: list[dict[str, Any]] = field(default_factory=list)


#: The record's fields that are not the file's: the path it was read from, and the three sets
#: `_grade_from_document` re-derives from the rows' own `ungradable`/`withheld_reason` (#1007)
#: so no top-level list can disagree with what the rows themselves say.
_DERIVED = frozenset({"episode_dir", "graded_worlds", "withheld_worlds", "measuring_worlds"})


def _judge_yaml_path(episode_dir: Path) -> Path:
    return Path(episode_dir) / JUDGE_NAME


def _existing_grade(episode_dir: Path) -> dict[str, Any] | None:
    # THE SCREENED READ, the ONE `family.screened_yaml_mapping` makes for the manifest too and
    # for the same stated reason: this file sits in the episode dir, a tree a sibling box's rw
    # bind reaches, so an entry at its name may be a link the model planted — and `is_file()`/
    # `read_text` follow the link the write side refuses. This is the IDEMPOTENCY record: a
    # planted document that parses as a mapping and carries no `not_graded` makes
    # `_grade_from_document` return an attacker-supplied grade and the pass never runs at all.
    # NOTHING AT THIS NAME (`None`) is an ordinary ungraded episode, while SOMETHING that is not
    # the record is the refusal.
    return family_mod.screened_yaml_mapping(_judge_yaml_path(episode_dir),
                                            what="the family grade")


def _episode_outcome_from_review(review: dict[str, Any]) -> tuple[str, str]:
    if not review:
        return "incomplete", f"no {REVIEW_NAME} on disk"
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


def _prepare_world_prompt(  # noqa: PLR0913 — the render's own inputs, threaded from the pass
    episode_dir: Path, label: str, *, payload_cap: int, git_show: Any,
    facts: family_mod.WorldFacts | None, lessons_commit: str | None,
    union: tuple[list[dict[str, Any]], dict[str, Any]], manifest: dict[str, Any],
    review: dict[str, Any], samples: dict[str, Any],
) -> str:
    """One world's whole framed prompt, and its draw directory made.

    ITS OWN FRAME, so the caller can contain a fault here to the world it is about. Everything
    in it touches the box-reachable episode tree — the render reads the archived document, the
    report and each lead's summary; `guarded_mkdir` refuses a stale entry standing at
    `worlds/<X>/judge` (P4: a retry clobbers and cleans nothing up) — and it all used to sit
    inside the per-draw loop's frame but OUTSIDE both of that loop's containment arms, so a
    fault on world N ended the whole pass with worlds 1..N-1's model calls already paid for and
    no `judge.yaml` written. The per-draw SINK below stays uncontained on purpose; only the
    setup is contained.

    NO `runs_base`. `render` reads it only on the `union is None` fallback, and the caller always
    hands the pass's own union over (J9) — so the argument was dead configuration that read as
    live: set here it changed nothing, and "fixing" `render` to prefer it would reintroduce the
    per-world walk of the operator's whole runs base J9 exists to remove."""
    judge_input = render_mod.render(
        episode_dir, label, git_show=git_show, payload_cap=payload_cap, facts=facts,
        lessons_commit=lessons_commit, union=union, manifest=manifest,
        review=review, samples=samples)
    guarded_mkdir(Path(episode_dir) / WORLDS_DIRNAME / label / DRAWS_DIRNAME, base=episode_dir)
    return run_mod._build_prompt(judge_input)


def _run_world_draws(
    episode_dir: Path, label: str, *, judge: Any, draws: int,
    model: str, effort: str, prompt: str, scope: str = "world",
) -> tuple[int, dict[str, int], dict[int, dict[str, Any]], int]:
    """Call the judge `draws` times over `prompt`, writing one `worlds/<X>/judge/<n>.yaml` per
    draw. Returns `(completed_draws, bucket_spread, this pass's draw documents KEYED BY DRAW
    INDEX, malformed replies)`. A failed call writes a draw record naming its own failure; a MALFORMED REPLY
    writes nothing at all and is counted — and both let the loop continue to the next draw.

    The documents are RETURNED rather than left to be read back: they are what this pass
    produced, and a reader that re-globs the draw directory cannot tell them from a stale file
    a wider earlier attempt left behind (P4: a retry clobbers, it does not clean up)."""
    from defender.learning.core.config import StageWiring
    from defender.runtime.agent_role import AgentRole

    world_dir = Path(episode_dir) / WORLDS_DIRNAME / label
    draw_dir = world_dir / DRAWS_DIRNAME

    completed = 0
    spread: Counter[str] = Counter()
    documents: dict[int, dict[str, Any]] = {}
    malformed = 0
    for n in range(draws):
        agent_id = f"judge:{label}:{n}"
        wiring = StageWiring(
            prompt_path=run_mod._ROLE_PROMPT, model=model, effort=effort,
            trace_name=f"{agent_id.replace(':', '_')}_trace.jsonl", label=agent_id)
        reply_text: str | None = None
        doc: dict[str, Any]
        try:
            reply_text = judge(prompt, role=AgentRole.JUDGE, agent_id=agent_id,
                               wiring=wiring)
        # EVERY class the seam can raise, not `RunUnprocessable` alone — which is what this
        # loop's own docstring already claims ("a failed call writes a draw record naming its
        # own failure ... and both let the loop continue to the next draw"). `run_stage`
        # deliberately re-raises `StageAbort` and `FatalConfigError` rather than wrapping them,
        # and an injected seam may raise anything at all, so a misconfigured model or one bad
        # transport class unwound the WHOLE pass — every already-completed world's draws
        # thrown away and no `judge.yaml` written — which is precisely the blast radius the
        # malformed-reply arm below was added to eliminate. The class is named in the record.
        except Exception as failed:  # noqa: BLE001 — one draw's blast radius, see above
            doc = {"failure_reason": f"{type(failed).__name__}: {failed}"}
            _write_wire_log(episode_dir, agent_id=agent_id, prompt=prompt,
                            reply=None, failure=f"{type(failed).__name__}: {failed}")
        else:
            _write_wire_log(episode_dir, agent_id=agent_id, prompt=prompt,
                            reply=reply_text, failure=None)
            try:
                reply = run_mod.validate_reply(reply_text, scope=scope)
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
            doc = run_mod._draw_document(reply, world_dir=world_dir, scope=scope)
            completed += 1
            for finding in doc["findings"]:
                spread[finding["bucket"]] += 1
        import yaml

        documents[n] = doc
        # NOT CONTAINED, deliberately: `test_921_both_episode_write_sinks_go_through_write_guarded`
        # pins that a link planted at this sink REFUSES the pass rather than being written
        # through or noted and passed over. The draw file is the artifact the enqueue reads back,
        # so an aliased one is not an observability fault.
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

    # THE SAME NAME SANITISATION THE QUESTIONER'S SEAM APPLIES (`seams.model_seam`:
    # `agent_id.replace(':', '_')`). `agent_id` is `judge:<label>:<n>`, and a trace file called
    # `judge:b:0_framed_trace.jsonl` is a name that seam deliberately does not produce.
    path = stage_trace_path(
        Path(episode_dir), f"{agent_id.replace(':', '_')}_framed_trace.jsonl")
    row = {"agent_id": agent_id, "prompt": prompt, "reply": reply, "failure": failure,
           "wire_log_written_at": path.name}
    # BEST-EFFORT, like every other observability writer in this repo (`_deps._record_lesson_load`
    # takes the same posture for the same reason). This sink is under the episode dir — a tree a
    # sibling box has an rw bind on — so a link planted at this name makes `write_guarded` raise
    # `OSError`, and a non-serialisable `reply` off the injected seam makes `json.dumps` raise
    # `TypeError`. Called from inside BOTH per-draw containment arms, neither of which names
    # those classes, either one refused the ENTIRE pass: every already-completed world's draws
    # discarded and no `judge.yaml` at all — an observability fault costing the grade. The draw
    # file two frames down is the artifact the enqueue reads back and stays uncontained.
    try:
        write_guarded(path, json.dumps(row) + "\n", mode="replace")
    except Exception as unwritable:  # noqa: BLE001 — see above: observability, never the grade
        print(f"[judge] the wire log for {agent_id} could not be written ({unwritable!r}); the "
              "draw itself is unaffected", file=sys.stderr)


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
    the way `seams.model_seam` builds the questioner's — `run_stage` under a deny-all key —
    but under the judge's OWN one since #1008: `JudgeDeps`, and therefore
    `AgentRole.JUDGE`'s definition (D2). It differs from the questioner's seam in that the
    judge's `wiring` (model/effort/trace name) arrives from the caller rather than being built
    here.

    THE DEPS CLASS IS WHAT DECIDES THE ROLE, not the `role` kwarg above it. `build_stage_agent`
    reads `type(deps).role` and looks the definition up in `AGENTS`
    (`learning/_pydantic_stage.py`), so `deps=JudgeDeps()` is the line that makes a draw run as
    the judge; the kwarg is the caller's declaration, and every production seam in the tree
    ignores it. Nothing is passed to `run_stage` besides `deps` and the wiring — in particular
    no `tools=` and no `verbs=`, either of which would widen the registered definition at call
    time and hand a grant to a role whose whole posture is holding none.

    THE IMPORTS ARE INSIDE `invoke`, not out here. `_pydantic_stage` imports `pydantic_ai` at
    module scope, and this seam is built for every `grade_episode` call that was handed no
    `judge=` — including the two that never make a model call at all (an episode with an
    existing `judge.yaml`, and one whose review says anything but `accepted`). Built eagerly it
    charged those passes the whole provider import, and could DIE on it: the build sits above
    `grade_episode`'s own `try`, so an `ImportError` or a provider `FatalConfigError` left the
    package as its own native class, past the conversion this module's docstring says makes
    every failure arrive as this design's refusal."""
    def invoke(prompt: str, *, role: Any = None, agent_id: str = "judge", wiring: Any = None,
              **_kw: Any) -> str:
        from defender.learning._pydantic_stage import run_stage
        from defender.learning.core.config import StageContext, subagent_timeout
        from defender.learning.judge.run import JudgeDeps

        # `wiring` IS REQUIRED, and the default is what makes the signature honest about it.
        # `run_stage`'s first statement is `label = wiring.label`, so a caller following the
        # published shape and omitting it got `AttributeError: 'NoneType' object has no
        # attribute 'label'` from deep inside the stage driver — swallowed by the draw loop's
        # per-draw handler and recorded as a `failure_reason` naming no configuration problem.
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


def _grade_episode(  # noqa: PLR0913, PLR0915, PLR0912, C901 — one orchestration, deliberately not split (its own steps are the demand)
    episode_dir: Path, *, judge: Any, runs_base: Path | None, draws: int | None,
    git_show: Any, queue_dir: Path | None,
) -> EpisodeGrade:
    # THE EXISTING RECORD IS CONSULTED FIRST, and a NOT-GRADED stamp does not count as one. An
    # episode that was skipped because its review said `incomplete` can be repaired and graded
    # afterwards; reading the outcome first meant the refusal stamp was found on the second
    # attempt and returned as though it were the grade, so a repaired episode answered with the
    # old refusal forever.
    # THROUGH `read_grade`, the one reader (#1025 O8) — the page reads the record the same way.
    existing = read_grade(episode_dir)
    if existing is not None and existing.not_graded is None:
        return existing

    review = family_mod.read_review_record(episode_dir)
    outcome, reason = _episode_outcome_from_review(review)
    if outcome != "accepted":
        reason = reason or f"the episode's {REVIEW_NAME} outcome is {outcome!r}, not 'accepted'"
        # `episode_outcome` says NOT-GRADED, never the `gradable` default: the field is what a
        # reader keys on to tell what happened to an episode, and an episode nothing looked at
        # reporting the same word as one the judge cleared is the one answer it must not give.
        record = EpisodeGrade(episode_dir=episode_dir, episode_outcome=NOT_GRADED,
                              not_graded=NotGradedStamp(outcome=outcome, reason=reason))
        _write_judge_yaml(episode_dir, record)
        return record

    configured_draws = draws if draws is not None else _judge_draws()
    model, effort, cap = _judge_model(), _judge_effort(), _judge_cap()
    knobs = {"draws": configured_draws, "model": model, "effort": effort, "payload_cap": cap}

    manifest = family_mod.raw_manifest(episode_dir)
    # THE PARSE THIS PASS ALREADY MADE. `grade_family` read and parsed `family.yaml` a second
    # time from the same directory — a tree a box can reach — so nothing held the two documents
    # in agreement, and one pass paid for two reads of the file that says which worlds exist.
    # `review=review` likewise hands over the record this frame already read, so `grade_family`
    # does not read `review.yaml` a second time (#1007).
    # ONCE PER PASS, at the same boundary `review` is read at, and threaded into BOTH readers —
    # `grade_family` for the mechanical rows and every `render` below for the prompt section
    # that claims to explain them. Read twice, the row and the prompt could come off two
    # different parses of a file the box can reach.
    samples = family_mod.read_samples_record(episode_dir)
    grade = family_mod.grade_family(episode_dir, manifest=manifest, review=review,
                                    samples=samples)
    gradable = [row["world"] for row in grade.worlds if family_mod.is_gradable_row(row)]

    # BOTH PER-PASS FACTS, RESOLVED ONCE AND THREADED (J8's own sentence, and J9's union with
    # it). Every world of one episode investigates the same alert, so the sibling union's answer
    # is identical for all of them while the walk costs one `alert.json` read and one report
    # parse per run under the operator's whole runs base; and `lessons_commit` was read per
    # world inside `render` AND read a second time out here purely to fill the record, so the
    # value the record carried could disagree with what worlds 2..N actually rendered against.
    # AND ONLY WHEN THERE IS A WORLD TO RENDER FOR. Both facts exist to be threaded into
    # `render`, and `render` runs once per GRADABLE world — so an episode whose worlds are all
    # ungradable (no `disposition_declared`, an absent archive, a malformed document) paid for a
    # walk of the operator's entire runs base, one `alert.json` read and one report parse per run
    # dir on it, to build a union no render would consume. The record it would have carried is
    # the same either way: `lessons_commit` is `None` and the union is empty.
    lessons_commit = _pass_lessons_commit(episode_dir, gradable)
    # ONE `git show` PER (commit, path) FOR THE PASS. `lessons_commit` is a per-pass constant
    # and the corpus is small, so N worlds loading the same lesson spawned N subprocesses for
    # the same bytes. The memo wraps the injected seam rather than living inside `render`, so
    # the render keeps taking a plain `(cwd, rev, path) -> str | None` and a caller that wants
    # no memo simply does not add one.
    git_show = _memoized_show(git_show if git_show is not None else render_mod._git_show_default)
    union = render_mod.sibling_union(
        Path(runs_base) if runs_base is not None and gradable else None,
        alert_id=_pass_alert_id(episode_dir, gradable),
        source_run_id=manifest.get("source_run_id"))

    per_world_completed: dict[str, int] = {}
    per_world_spread: dict[str, dict[str, int]] = {}
    per_world_draws: dict[str, dict[int, dict[str, Any]]] = {}
    per_world_malformed: dict[str, int] = {}
    per_world_failed: dict[str, str] = {}
    for label in gradable:
        # CONTAINED TO THE WORLD IT IS ABOUT, the same rule `family._grade_world` applies to the
        # mechanical half (J5 tier 2) and `_run_world_draws` applies to one draw. The setup half
        # of that call — `render`, `guarded_mkdir(worlds/<X>/judge)`, `_build_prompt` — sits
        # OUTSIDE both of those containments and touches the same box-reachable episode tree: a
        # stale entry at the draw directory's name (P4: a retry clobbers and cleans nothing up),
        # a permission fault on a summary read, an unreadable archived document. Uncontained,
        # any of them ended the whole pass on world N with worlds 1..N-1's model calls already
        # paid for, their draw files on disk, and NO `judge.yaml` — the exact blast radius the
        # per-draw and per-append arms exist to eliminate.
        try:
            prompt = _prepare_world_prompt(
                episode_dir, label, payload_cap=cap, git_show=git_show,
                facts=grade.world_facts.get(label), lessons_commit=lessons_commit, union=union,
                manifest=manifest, review=review, samples=samples)
        except (JudgeRefused, OSError, ValueError, TimeoutError) as world_failed:
            per_world_failed[label] = f"{type(world_failed).__name__}: {world_failed}"
            per_world_completed[label] = 0
            per_world_spread[label] = {}
            per_world_draws[label] = {}
            per_world_malformed[label] = 0
            continue
        # THE DRAWS THEMSELVES ARE NOT CONTAINED HERE. The per-draw loop already contains a
        # transport failure and a malformed reply, and its WRITE SINK is deliberately outside
        # both: `test_921_both_episode_write_sinks_go_through_write_guarded` pins that a link
        # planted at `worlds/<X>/judge/<n>.yaml` refuses the pass rather than being written
        # through or noted and passed over.
        completed, spread, documents, malformed = _run_world_draws(
            episode_dir, label, judge=judge, draws=configured_draws,
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
            # NAMED ON THE ROW, never silent. A world whose draws could not even be set up ran
            # nothing, so its `completed_draws` is 0 for the same reason an ungradable world's
            # is — and without this the two are indistinguishable on the record.
            row["draws_failed_reason"] = per_world_failed[label]
        # #1007 M3/M4: this world's OWN model-drawn `subject: world` findings, joined onto the
        # mechanical ones family.py already put on the row — withholding is about the DEFENDER
        # lane alone, so a withheld world's own world-subject findings still stand
        # (`test_a_withheld_world_is_still_drawn_and_still_yields_world_findings`).
        if "world_findings" in row:
            # A1(b) — a world whose sample went unavailable (#1007 M4/O5) admits no finding
            # that cites `samples.yaml#<that pattern>` as its evidence, whatever its bucket;
            # every other world-subject finding still stands. `sample_unavailable_patterns`
            # (not the blanket `sample_unavailable` bool) is what `cites_sample` checks the
            # citation's own fragment against, so a two-pattern world's finding about the
            # pattern it WAS shown is never refused for a gap in a sibling staged pattern.
            # `.get(...)` WITHOUT `or []` — see `enqueue_report`'s own copy of this gate: an
            # ABSENT list is `None`, which `cites_sample` documents as the blanket refusal, and
            # an EMPTY one is "measured, nothing unavailable". Collapsing them turns A1(b) off
            # for exactly the rows that never recorded the fact.
            unavailable_patterns = row.get("sample_unavailable_patterns")
            for draw_doc in per_world_draws.get(label, {}).values():
                for finding in draw_doc.get("findings") or []:
                    if not isinstance(finding, dict) or finding.get("subject") != run_mod.SUBJECT_WORLD:
                        continue
                    if run_mod.cites_sample(finding, unavailable_patterns=unavailable_patterns):
                        continue
                    row["world_findings"].append(finding)

    # M5: the family-level call — UNCONDITIONAL (even an episode with nothing to separate is
    # exactly the one this call exists to say so about) and an ADDITION to the pass: its own
    # fault (a bad prompt build, every draw failing) costs only its own contribution and never
    # unwinds what the per-world draws already produced
    # (`test_a_faulted_family_draw_isolates_and_leaves_verdict_word_intact`).
    family_documents: dict[int, dict[str, Any]] = {}
    family_completed = 0
    family_malformed = 0
    # NAMED ON THE RECORD, never silent — the same rule `row["draws_failed_reason"]` applies to
    # a world whose setup failed. Containment is not the same thing as silence: this arm also
    # catches the DELIBERATELY UNCONTAINED refusals of `_run_world_draws`' own write sink (a
    # link planted at `worlds/family/judge/<n>.yaml`) and of `guarded_mkdir` (an aliased
    # `worlds/family`), and with nothing written and nothing logged `family_outcome: null` read
    # identically for "the call ran and no word won a majority", "every reply was malformed"
    # and "a planted alias refused the write". `family_malformed_replies` likewise: the
    # per-world lane records its count on the row and this lane threw its away.
    family_failed_reason: str | None = None
    try:
        family_prompt = run_mod._build_family_prompt(manifest=manifest, grade=grade,
                                                      review=review)
        guarded_mkdir(Path(episode_dir) / WORLDS_DIRNAME / "family" / DRAWS_DIRNAME,
                      base=episode_dir)
        family_completed, _family_spread, family_documents, family_malformed = (
            _run_world_draws(episode_dir, "family", judge=judge, draws=configured_draws,
                             model=model, effort=effort, prompt=family_prompt,
                             scope="family"))
    except Exception as family_failed:  # noqa: BLE001 — the family call is an addition to the pass (M5); its own fault costs only itself, never the already-completed per-world draws
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
            f"{episode_dir.name}/{REVIEW_NAME}#worlds.*.consistency.{_DRIFT_KEYS_FIELD}"}
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
    questioner_file, _questioner_lock = enqueue_mod._questioner_queue_paths(queue_dir)
    enqueued_to = str(pending_file)
    world_enqueued_to = str(questioner_file)
    # UNCONDITIONAL (#1007 O7/N2): a `discard`/`corpus-contradiction` episode blocks the
    # DEFENDER lane alone — `enqueue_report`'s own `defender_blocked` gate reads `verdict_word`
    # for that — but the WORLD lane (mechanical findings, per-world and family model-drawn
    # world findings) is never gated on the defender's own outcome
    # (`test_an_unqueueable_defender_finding_does_not_suppress_the_world_findings`).
    report = enqueue_mod.enqueue_report(
        episode_dir,
        family_mod.FamilyGrade(episode_dir=episode_dir, worlds=grade.worlds,
                               verdict_word=verdict_word, graded_worlds=grade.graded_worlds),
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
        withheld_findings=withheld_findings,
    )
    _write_judge_yaml(episode_dir, record)
    return record




def _memoized_show(show: Any) -> Any:
    """`show`, answering each `(cwd, rev, path)` once per pass and replaying the answer after.

    `cwd` IS IN THE KEY even though the one in-tree caller always passes `REPO_ROOT`: this
    wrapper advertises the wrapped seam's whole three-argument contract, so a memo keyed on two
    of the three replays the first checkout's answer — a `None` included — for a second one."""
    seen: dict[tuple[str, str, str], Any] = {}

    def invoke(cwd: Path, rev: str, path: str) -> Any:
        key = (str(cwd), str(rev), str(path))
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
        commit = render_mod._read_provenance(
            Path(episode_dir) / WORLDS_DIRNAME / label).get("commit")
        if commit is not None:
            return str(commit)
    return None


def _pass_alert_id(episode_dir: Path, labels: list[str]) -> Any:
    """The alert this episode's worlds all investigate — the union's key.

    Read off the first graded world that carries one: every world of a family branches from one
    source run and therefore one alert, which is exactly why the union is a per-pass fact.
    Through `render.episode_alert`, the one home for WHICH world's `alert.json` answers — the
    enqueue derives every row's `alert_rule_key` from that same call, and two spellings of "the
    first world that carries an alert" picked different worlds for the two."""
    return render_mod.episode_alert(Path(episode_dir), labels).get("alert_id")


def read_grade(episode_dir: Path) -> EpisodeGrade | None:
    """The episode's recorded grade, read off `judge.yaml` — or `None` when there is none.

    THE ONE READER (#1025 O8): the same screened read and the same strict conversion
    `grade_episode` itself uses when it finds an existing record, exposed so the episode page
    reads the record through this package rather than re-parsing the YAML. Tolerant only of
    ABSENCE — a field the file does not carry takes the schema's default (a pre-#1007 record
    reads with `family_outcome: None`), and a key the schema does not name is ignored. A record
    that is not one — a planted link at the name, a document that is not a mapping, a record
    that fails the schema (`EpisodeGrade`, strictly: a present field of the wrong type is
    refused, never defaulted) — is `JudgeRefused`, exactly as it is for the pass. A
    `not_graded` stamp reads back as a grade carrying that stamp; deciding what to do about it
    is the caller's.
    """
    # COERCED HERE, as `grade_episode` coerces its own argument: the record's `episode_dir` is
    # typed `Path`, and a `str` caller (a page reading the path off YAML) otherwise got a record
    # unequal to the one `grade_episode` returns for the same episode.
    episode_dir = Path(episode_dir)
    doc = _existing_grade(episode_dir)
    return None if doc is None else _grade_from_document(episode_dir, doc)


def _grade_from_document(episode_dir: Path, doc: dict[str, Any]) -> EpisodeGrade:
    # VALIDATED AGAINST THE SCHEMA, strictly, and a document that fails is REFUSED — never
    # defaulted field by field and never let out as a bare `TypeError`/`KeyError`. `judge.yaml`
    # lives in the episode dir, a tree a box can reach, and the writer stages and `os.replace`s
    # so it never leaves a torn file: a record of the wrong shape (`verdict_word: null`,
    # `world_findings: 5`, a `not_graded` stamp with no reason, a row naming no world) is one
    # the pass never wrote, and the same answer the manifest gets — `JudgeRefused`, the one
    # class `grade_episode`'s handler converts at. Refused, not re-graded: a planted record
    # must not buy three model calls per launch, and the fix is a human deleting the file.
    # `TypeError` BESIDE `ValidationError`: the keys are the file's, and a YAML mapping may key
    # on `1:` / `true:` / `null:` — splatted as keywords those raise `TypeError: keywords must
    # be strings` out of the constructor, before pydantic sees a single field, and `TypeError`
    # is not in `grade_episode`'s conversion set — the bare traceback this comment promises
    # never leaves.
    try:
        record = EpisodeGrade(
            **{k: v for k, v in doc.items() if k not in _DERIVED}, episode_dir=episode_dir)
    except (ValidationError, TypeError) as bad:
        raise JudgeRefused(
            f"{_judge_yaml_path(episode_dir)} is not a family grade record: {bad}") from bad
    graded = frozenset(r["world"] for r in record.worlds if family_mod.is_gradable_row(r))
    measuring = frozenset(
        r["world"] for r in record.worlds
        if r["world"] in graded and r.get("withheld_reason") is None)
    # ASSIGNED, not `dataclasses.replace`d: `replace` re-runs the constructor — every field
    # through the strict validator a second time, `worlds` and each row copied again — to set
    # three sets derived off rows the constructor has just admitted. No `validate_assignment`
    # is configured, so the three are plain attribute writes onto the validated record.
    record.graded_worlds = graded
    record.withheld_worlds = graded - measuring
    record.measuring_worlds = measuring
    return record


#: The record's serializer, built ONCE: `TypeAdapter` construction is a schema build, and the
#: writer is called once per pass — there is no reason to rebuild it per write.
_GRADE_ADAPTER: TypeAdapter[EpisodeGrade] = TypeAdapter(EpisodeGrade)


def _write_judge_yaml(episode_dir: Path, record: EpisodeGrade) -> None:
    import yaml

    doc = _GRADE_ADAPTER.dump_python(record, mode="json", exclude=set(_DERIVED))
    # The stamp is a KEY THAT IS PRESENT OR ABSENT, never null: `not_graded is None` is what
    # `_grade_episode` reads to tell a grade from a stamp, and the file says it the same way.
    if doc["not_graded"] is None:
        del doc["not_graded"]
    write_guarded(_judge_yaml_path(episode_dir), yaml.safe_dump(doc, sort_keys=False),
                 mode="replace")


__all__ = ["EpisodeGrade", "JudgeRefused", "NotGradedStamp", "grade_episode", "read_grade"]
