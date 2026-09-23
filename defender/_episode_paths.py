from __future__ import annotations

import dataclasses
from pathlib import Path, PurePosixPath

from defender._run_id import CASE_STABLE_REQUIRED, is_case_stable_id
from defender._run_paths import (
    ALERT,
    PROVENANCE,
    GATHER_SUMMARIES_DIRNAME,
    INVESTIGATION,
    LESSONS_LOADED,
    REPORT,
    SERVED_PREFIX,
    TRACE_SUFFIX,
    WIRE_LOG_DIR,
    _check_component,
    _check_index,
    _confine,
)

#: The episode-layout names (#1077 D1) — the OWNER's spellings, and the only place in the tree
#: they are written. D7 finished the job D1 started: no module outside this one BINDS any of
#: them any more (`archive.py`, `ledger.py`, `timing.py`, `staging.py`,
#: `runtime/branch/_family.py` and `visualize_episode.py` used to re-bind them under local
#: aliases). An alias IS a second spelling — it is safe exactly until its home drops the name,
#: and then every downstream importer breaks at once with no gate having seen anything, which
#: is what happened to `SERVED_DIRNAME`/`BASE_FILENAME` in this issue's own first pass.
#: `scripts/lint/lint_run_records.py`'s import arm now refuses the alias outright.
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


def _check_label(label: object, *, what: str = "label") -> str:
    """A world label: a plain component that is also case-stable (decision 20). Two distinct
    labels that differ only in case would otherwise compose to one directory on a
    case-insensitive filesystem, and the archive would silently merge two worlds."""
    label = _check_component(label, what=what)
    if not is_case_stable_id(label):
        raise ValueError(f"{label!r} is not case-stable ({CASE_STABLE_REQUIRED})")
    return label


# ==========================================================================================
# THE LAYOUT — every episode record as a path RELATIVE to the episode dir.
#
# One spelling, two views (#1077 D7). The layout composes; `EpisodePaths` roots it at a real
# directory and applies decision 2's containment check. The relative view is not a
# convenience: the episode tree's readers are `_io.Bound` handles, which address records by a
# name relative to the root they hold and never by an absolute path (that is the point of the
# handle — it is the only value that ever held the root's spelling). Before D7 those readers
# hand-composed their relative names from imported constants, which is the same drift as a
# hand-composed absolute path and was invisible to the gate for the same reason. `Bound.read`,
# `read_jsonl` and `under` all take `str | PurePath`, so the layout hands them a PATH and no
# record name is ever spelled by a caller.
# ==========================================================================================


@dataclasses.dataclass(frozen=True)
class WorldLayout:
    """One archived world's records, relative to the EPISODE dir — `worlds/<label>/...`.

    The archive projects a source run dir into this shape, so most of these names are the run
    dir's own (imported from `_run_paths`, never re-spelled); the two sidecars are re-homed
    under names only the archive uses, because no run dir carries them.
    """

    label: str

    @property
    def dir(self) -> PurePosixPath:
        return PurePosixPath(WORLDS_DIRNAME) / self.label

    @property
    def report(self) -> PurePosixPath:
        return self.dir / REPORT

    @property
    def investigation(self) -> PurePosixPath:
        return self.dir / INVESTIGATION

    @property
    def provenance(self) -> PurePosixPath:
        """The world's own flat run stamp — the same spelling as the episode-root FAMILY
        stamp, a different shape at the same file name (#1025 fk-8/J12)."""
        return self.dir / PROVENANCE

    @property
    def scrub_verdict(self) -> PurePosixPath:
        return self.dir / ARCHIVED_SCRUB_VERDICT_NAME

    @property
    def run_end(self) -> PurePosixPath:
        return self.dir / ARCHIVED_RUN_END_NAME

    @property
    def lessons_loaded(self) -> PurePosixPath:
        return self.dir / LESSONS_LOADED

    @property
    def alert(self) -> PurePosixPath:
        return self.dir / ALERT

    @property
    def gather_summaries(self) -> PurePosixPath:
        return self.dir / GATHER_SUMMARIES_DIRNAME

    def gather_summary(self, lead_id: str) -> PurePosixPath:
        return self.gather_summaries / f"{_check_component(lead_id, what='lead_id')}.md"

    @property
    def draws(self) -> PurePosixPath:
        return self.dir / JUDGE_DRAWS_DIRNAME

    def draw(self, n: int) -> PurePosixPath:
        return self.draws / f"{_check_index(n, what='n')}.yaml"

    @property
    def run_dir_pointer(self) -> PurePosixPath:
        """`worlds/<label>/run_dir` — a TEXT pointer, never a link (archive.py's docstring on
        why)."""
        return self.dir / RUN_DIR_POINTER_NAME

    @property
    def review(self) -> PurePosixPath:
        return self.dir / REVIEW_NAME

    @property
    def samples(self) -> PurePosixPath:
        return self.dir / SAMPLES_NAME

    @property
    def judge(self) -> PurePosixPath:
        return self.dir / JUDGE_NAME


@dataclasses.dataclass(frozen=True)
class EpisodeLayout:
    """Every episode record, relative to the episode dir. Stateless — see `LAYOUT`."""

    # -- episode-root records ------------------------------------------------------------------

    @property
    def family(self) -> PurePosixPath:
        return PurePosixPath(FAMILY_NAME)

    @property
    def family_stamp(self) -> PurePosixPath:
        return PurePosixPath(PROVENANCE)

    @property
    def review(self) -> PurePosixPath:
        return PurePosixPath(REVIEW_NAME)

    @property
    def samples(self) -> PurePosixPath:
        return PurePosixPath(SAMPLES_NAME)

    @property
    def judge(self) -> PurePosixPath:
        return PurePosixPath(JUDGE_NAME)

    @property
    def timing(self) -> PurePosixPath:
        return PurePosixPath(TIMING_NAME)

    @property
    def staged(self) -> PurePosixPath:
        return PurePosixPath(STAGED_NAME)

    @property
    def learning_html(self) -> PurePosixPath:
        return PurePosixPath(LEARNING_HTML_NAME)

    @property
    def served(self) -> PurePosixPath:
        return PurePosixPath(SERVED_DIRNAME)

    @property
    def served_base(self) -> PurePosixPath:
        return self.served / BASE_FILENAME

    @property
    def priming_lock(self) -> PurePosixPath:
        return PurePosixPath(PRIMING_LOCK_NAME)

    @property
    def runs(self) -> PurePosixPath:
        return PurePosixPath(RUNS_DIRNAME)

    @property
    def worlds(self) -> PurePosixPath:
        return PurePosixPath(WORLDS_DIRNAME)

    # -- composing ------------------------------------------------------------------------------

    def world(self, label: str) -> WorldLayout:
        """One archived world's records. The label is checked HERE, once, so every record
        under it is composed from a name already judged."""
        return WorldLayout(_check_label(label))

    def served_world(self, token: str) -> PurePosixPath:
        """`served/<episode token>.<label>.jsonl`. The token is `_family.world_token_for`'s
        composition, which is where decision 12's delimiter refusal lives: the LABEL may not
        carry `.`, so the label is always the text after the token's last dot — the episode
        token before it legitimately holds dots (`episode_token_for` folds every `-` of the
        episode id onto `.`). Here only the case-stability rule is re-asked of that label."""
        token = _check_component(token, what="token")
        _head, sep, label = token.rpartition(".")
        if sep and not is_case_stable_id(label):
            raise ValueError(f"{label!r} is not case-stable ({CASE_STABLE_REQUIRED})")
        return self.served / f"{token}.jsonl"

    def stage_trace(self, stage: str) -> PurePosixPath:
        """`wire_logs/<stage>.trace.jsonl` — the episode-root wire trace of one learning stage.
        Shares `_run_paths.TRACE_SUFFIX` rather than re-spelling it (claim: one reused
        constant, not two)."""
        stage = _check_component(stage, what="stage")
        return PurePosixPath(WIRE_LOG_DIR) / f"{stage}{TRACE_SUFFIX}"

    def sibling_run_dir(self, episode_id: str, label: str) -> PurePosixPath:
        """`runs/<episode_id>-<label>` — byte for byte as today (O3). Decision 20's
        case-stability refusal applies to the freshly-authored `label`, and so does decision
        12's delimiter refusal: an episode id ALWAYS carries `-` (`episode_id_for` derives it
        as `<source run>-n<turn>`), so it is the label being `-`-free that keeps the pair
        recoverable from the composed id — `ep-a-b` is `(ep-a, b)`, never `(ep, a-b)`."""
        episode_id = _check_component(episode_id, what="episode_id")
        if "-" in str(label):
            raise ValueError(
                f"label {label!r} carries '-', the sibling run id's own delimiter — two "
                "distinct (episode, label) pairs would compose to one run directory")
        label = _check_label(label)
        return self.runs / f"{episode_id}-{label}"


#: The layout, as one value. Stateless, so one instance serves every caller.
LAYOUT = EpisodeLayout()


@dataclasses.dataclass(frozen=True)
class EpisodePaths:
    """One episode's directories and its accessors — the episode-layout owner (#1077 D1).

    Every accessor resolves relative to ``episode_dir``. The layout NAMES live in ``LAYOUT``
    (relative, for the bound readers) and this class roots them at a real directory, applying
    decision 2's containment check to every composed one. The episodes ROOT's resolution stays
    in `learning/branch/cli.episodes_root` — a configured location this module deliberately
    does not know how to find.

    Reach the relative form through ``.rel`` (`EpisodePaths(d).rel.family`) or ``LAYOUT``
    directly when no directory is in hand; a `_io.Bound` reader wants that form and never an
    absolute path.
    """

    episode_dir: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "episode_dir", Path(self.episode_dir))

    @property
    def rel(self) -> EpisodeLayout:
        """This episode's layout in relative form — the same names, for a bound reader."""
        return LAYOUT

    def _at(self, rel: PurePosixPath, *, what: str) -> Path:
        return _confine(self.episode_dir / rel, self.episode_dir, what=what)

    # -- episode-root records -----------------------------------------------------------------

    @property
    def family(self) -> Path:
        return self.episode_dir / LAYOUT.family

    @property
    def family_stamp(self) -> Path:
        """The family stamp shares `_run_paths.PROVENANCE`'s spelling at the episode root — a
        DIFFERENT shape at the same file name (#1025 fk-8/J12)."""
        return self.episode_dir / LAYOUT.family_stamp

    @property
    def review(self) -> Path:
        return self.episode_dir / LAYOUT.review

    @property
    def samples(self) -> Path:
        return self.episode_dir / LAYOUT.samples

    @property
    def judge(self) -> Path:
        return self.episode_dir / LAYOUT.judge

    @property
    def timing(self) -> Path:
        return self.episode_dir / LAYOUT.timing

    @property
    def staged(self) -> Path:
        return self.episode_dir / LAYOUT.staged

    @property
    def learning_html(self) -> Path:
        return self.episode_dir / LAYOUT.learning_html

    @property
    def served(self) -> Path:
        return self.episode_dir / LAYOUT.served

    @property
    def served_base(self) -> Path:
        return self.episode_dir / LAYOUT.served_base

    @property
    def priming_lock(self) -> Path:
        return self.episode_dir / LAYOUT.priming_lock

    @property
    def runs(self) -> Path:
        return self.episode_dir / LAYOUT.runs

    @property
    def worlds(self) -> Path:
        return self.episode_dir / LAYOUT.worlds

    # -- composing accessors — decision 2's shape+containment rule applies to every one --------

    def world(self, label: str) -> WorldPaths:
        """One archived world, rooted at this episode. Every record the archive projects into
        it is an accessor on the returned handle — the archive's source/destination pairing is
        then two accessors and no names at all."""
        return WorldPaths(self.episode_dir, LAYOUT.world(label))

    def served_world(self, token: str) -> Path:
        return self._at(LAYOUT.served_world(token), what="served_world")

    def judge_draw(self, label: str, n: int) -> Path:
        """`worlds/<label>/judge/<n>.yaml`."""
        return self._at(LAYOUT.world(label).draw(n), what="judge_draw")

    def stage_trace(self, stage: str) -> Path:
        return self._at(LAYOUT.stage_trace(stage), what="stage_trace")

    def sibling_run_dir(self, episode_id: str, label: str) -> Path:
        return self._at(LAYOUT.sibling_run_dir(episode_id, label), what="sibling_run_dir")

    def world_dir(self, label: str) -> Path:
        """`worlds/<label>`."""
        return self._at(LAYOUT.world(label).dir, what="world_dir")

    def run_dir_pointer(self, label: str) -> Path:
        return self._at(LAYOUT.world(label).run_dir_pointer, what="run_dir_pointer")

    # -- the archive projection's flat spellings, per label ------------------------------------

    def gather_summaries(self, label: str) -> Path:
        return self._at(LAYOUT.world(label).gather_summaries, what="gather_summaries")

    def lessons_loaded(self, label: str) -> Path:
        return self._at(LAYOUT.world(label).lessons_loaded, what="lessons_loaded")

    def alert(self, label: str) -> Path:
        return self._at(LAYOUT.world(label).alert, what="alert")

    def draws(self, label: str) -> Path:
        return self._at(LAYOUT.world(label).draws, what="draws")


@dataclasses.dataclass(frozen=True)
class WorldPaths:
    """One archived world's records, rooted at a real episode directory.

    Carries the relative layout beside the root so a caller can hand either form out: `.rel`
    for a bound reader, the accessor itself for a filesystem path. Containment is checked on
    every absolute form, exactly as on `EpisodePaths`.
    """

    episode_dir: Path
    rel: WorldLayout

    @property
    def label(self) -> str:
        return self.rel.label

    def _at(self, rel: PurePosixPath, *, what: str) -> Path:
        return _confine(self.episode_dir / rel, self.episode_dir, what=what)

    @property
    def dir(self) -> Path:
        return self._at(self.rel.dir, what="world_dir")

    @property
    def report(self) -> Path:
        return self._at(self.rel.report, what="report")

    @property
    def investigation(self) -> Path:
        return self._at(self.rel.investigation, what="investigation")

    @property
    def provenance(self) -> Path:
        return self._at(self.rel.provenance, what="provenance")

    @property
    def scrub_verdict(self) -> Path:
        return self._at(self.rel.scrub_verdict, what="scrub_verdict")

    @property
    def run_end(self) -> Path:
        return self._at(self.rel.run_end, what="run_end")

    @property
    def lessons_loaded(self) -> Path:
        return self._at(self.rel.lessons_loaded, what="lessons_loaded")

    @property
    def alert(self) -> Path:
        return self._at(self.rel.alert, what="alert")

    @property
    def gather_summaries(self) -> Path:
        return self._at(self.rel.gather_summaries, what="gather_summaries")

    def gather_summary(self, lead_id: str) -> Path:
        return self._at(self.rel.gather_summary(lead_id), what="gather_summary")

    @property
    def draws(self) -> Path:
        return self._at(self.rel.draws, what="draws")

    def draw(self, n: int) -> Path:
        return self._at(self.rel.draw(n), what="judge_draw")

    @property
    def run_dir_pointer(self) -> Path:
        return self._at(self.rel.run_dir_pointer, what="run_dir_pointer")

    @property
    def review(self) -> Path:
        return self._at(self.rel.review, what="review")

    @property
    def samples(self) -> Path:
        return self._at(self.rel.samples, what="samples")

    @property
    def judge(self) -> Path:
        return self._at(self.rel.judge, what="judge")
