from __future__ import annotations

import dataclasses
from pathlib import Path

from defender._run_id import CASE_STABLE_REQUIRED, is_case_stable_id
from defender._run_paths import (
    ALERT,
    PROVENANCE,
    GATHER_SUMMARIES_DIRNAME,
    LESSONS_LOADED,
    SERVED_PREFIX,
    TRACE_SUFFIX,
    WIRE_LOG_DIR,
    _check_component,
    _check_index,
    _confine,
)

#: The episode-layout names (#1077 D1) — the OWNER's spellings. `learning/branch/archive.py`,
#: `ledger.py`, `timing.py`, `staging.py`, `runtime/branch/_family.py` and
#: `scripts/visualize/visualize_episode.py` still carry their own; D7 step 3 migrates them
#: onto these, and `test_no_episode_layout_constant_survives_outside_the_owner` is red until
#: it does.
FAMILY_NAME = "family.yaml"
REVIEW_NAME = "review.yaml"
SAMPLES_NAME = "samples.yaml"
JUDGE_NAME = "judge.yaml"
TIMING_NAME = "timing.json"
STAGED_NAME = "staged.yaml"
LEARNING_HTML_NAME = "learning.html"

WORLDS_DIRNAME = "worlds"
RUNS_DIRNAME = "runs"
SERVED_DIRNAME = SERVED_PREFIX.rstrip("/")
JUDGE_DRAWS_DIRNAME = "judge"
BASE_FILENAME = "base.jsonl"
PRIMING_LOCK_NAME = f"{SERVED_PREFIX}.priming"
RUN_DIR_POINTER_NAME = "run_dir"

#: The archive projection's own flat spellings (D5/N5): the two sidecars, which live beside a
#: run dir keyed by run id (`<run>.scrub-verdict.json`) and are re-homed under the world as a
#: bare `<kind>.json` — names the archive OWNS because no run dir carries them. Every other
#: archived name is the run dir's own and is imported from `_run_paths`, not re-spelled.
ARCHIVED_SCRUB_VERDICT_NAME = "scrub_verdict.json"
ARCHIVED_RUN_END_NAME = "run_end.json"


@dataclasses.dataclass(frozen=True)
class EpisodePaths:
    """One episode's directories and its accessors — the episode-layout owner (#1077 D1).

    Every accessor resolves relative to ``episode_dir``. The layout NAMES live here; the
    episodes ROOT's resolution stays in `learning/branch/cli.episodes_root` — a configured
    location this module deliberately does not know how to find.
    """

    episode_dir: Path

    # -- episode-root records -----------------------------------------------------------------

    @property
    def family(self) -> Path:
        return self.episode_dir / FAMILY_NAME

    @property
    def family_stamp(self) -> Path:
        """The family stamp shares `_run_paths.PROVENANCE`'s spelling at the episode root — a
        DIFFERENT shape at the same file name (#1025 fk-8/J12)."""
        return self.episode_dir / PROVENANCE

    @property
    def review(self) -> Path:
        return self.episode_dir / REVIEW_NAME

    @property
    def samples(self) -> Path:
        return self.episode_dir / SAMPLES_NAME

    @property
    def judge(self) -> Path:
        return self.episode_dir / JUDGE_NAME

    @property
    def timing(self) -> Path:
        return self.episode_dir / TIMING_NAME

    @property
    def staged(self) -> Path:
        return self.episode_dir / STAGED_NAME

    @property
    def learning_html(self) -> Path:
        return self.episode_dir / LEARNING_HTML_NAME

    @property
    def served(self) -> Path:
        return self.episode_dir / SERVED_DIRNAME

    @property
    def served_base(self) -> Path:
        return self.served / BASE_FILENAME

    @property
    def priming_lock(self) -> Path:
        return self.episode_dir / PRIMING_LOCK_NAME

    @property
    def runs(self) -> Path:
        return self.episode_dir / RUNS_DIRNAME

    # -- composing accessors — decision 2's shape+containment rule applies to every one --------

    def served_world(self, token: str) -> Path:
        """`served/<episode token>.<label>.jsonl`. The token is `_family.world_token_for`'s
        composition, which is where decision 12's delimiter refusal lives: the LABEL may not
        carry `.`, so the label is always the text after the token's last dot — the episode
        token before it legitimately holds dots (`episode_token_for` folds every `-` of the
        episode id onto `.`). Here only the case-stability rule is re-asked of that label."""
        token = _check_component(token, what="token")
        _head, sep, label = token.rpartition(".")
        if sep and not is_case_stable_id(label):
            raise ValueError(f"{label!r} is not case-stable ({CASE_STABLE_REQUIRED})")
        target = self.served / f"{token}.jsonl"
        return _confine(target, self.episode_dir, what="served_world")

    def judge_draw(self, label: str, n: int) -> Path:
        """`worlds/<label>/judge/<n>.yaml`."""
        label = _check_component(label, what="label")
        n = _check_index(n, what="n")
        target = self.episode_dir / WORLDS_DIRNAME / label / JUDGE_DRAWS_DIRNAME / f"{n}.yaml"
        return _confine(target, self.episode_dir, what="judge_draw")

    def stage_trace(self, stage: str) -> Path:
        """`wire_logs/<stage>.trace.jsonl` — the episode-root wire trace of one learning stage.
        Shares `_run_paths.TRACE_SUFFIX` rather than re-spelling it (claim: one reused
        constant, not two)."""
        stage = _check_component(stage, what="stage")
        target = self.episode_dir / WIRE_LOG_DIR / f"{stage}{TRACE_SUFFIX}"
        return _confine(target, self.episode_dir, what="stage_trace")

    def sibling_run_dir(self, episode_id: str, label: str) -> Path:
        """`runs/<episode_id>-<label>` — byte for byte as today (O3). Decision 20's
        case-stability refusal applies to the freshly-authored `label`, and so does decision
        12's delimiter refusal: an episode id ALWAYS carries `-` (`episode_id_for` derives it
        as `<source run>-n<turn>`), so it is the label being `-`-free that keeps the pair
        recoverable from the composed id — `ep-a-b` is `(ep-a, b)`, never `(ep, a-b)`."""
        episode_id = _check_component(episode_id, what="episode_id")
        label = _check_component(label, what="label")
        if "-" in label:
            raise ValueError(
                f"label {label!r} carries '-', the sibling run id's own delimiter — two "
                "distinct (episode, label) pairs would compose to one run directory")
        if not is_case_stable_id(label):
            raise ValueError(f"{label!r} is not case-stable ({CASE_STABLE_REQUIRED})")
        target = self.runs / f"{episode_id}-{label}"
        return _confine(target, self.episode_dir, what="sibling_run_dir")

    def world_dir(self, label: str) -> Path:
        """`worlds/<label>`."""
        label = _check_component(label, what="label")
        if not is_case_stable_id(label):
            raise ValueError(f"{label!r} is not case-stable ({CASE_STABLE_REQUIRED})")
        target = self.episode_dir / WORLDS_DIRNAME / label
        return _confine(target, self.episode_dir, what="world_dir")

    def run_dir_pointer(self, label: str) -> Path:
        """`worlds/<label>/run_dir` — a TEXT pointer, never a link (archive.py's own docstring
        on why)."""
        label = _check_component(label, what="label")
        target = self.episode_dir / WORLDS_DIRNAME / label / RUN_DIR_POINTER_NAME
        return _confine(target, self.episode_dir, what="run_dir_pointer")

    # -- the archive projection's flat spellings, per label ------------------------------------

    def gather_summaries(self, label: str) -> Path:
        return self.world_dir(label) / GATHER_SUMMARIES_DIRNAME

    def lessons_loaded(self, label: str) -> Path:
        return self.world_dir(label) / LESSONS_LOADED

    def alert(self, label: str) -> Path:
        return self.world_dir(label) / ALERT

    def draws(self, label: str) -> Path:
        return self.world_dir(label) / JUDGE_DRAWS_DIRNAME
