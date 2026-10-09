from __future__ import annotations

import dataclasses
from pathlib import Path, PurePosixPath

from defender._run_id import CASE_STABLE_REQUIRED, is_case_stable_id
from defender.run_repository._layout import (
    RUN_LAYOUT,
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

#: The episode-layout names — the only place they are spelled. Other modules must not re-bind
#: them under local aliases (`scripts/lint/lint_run_records.py` refuses that).
FAMILY_NAME = "family.yaml"
REVIEW_NAME = "review.yaml"
SAMPLES_NAME = "samples.yaml"
JUDGE_NAME = "judge.yaml"
TIMING_NAME = "timing.json"
STAGED_NAME = "staged.yaml"
LEARNING_HTML_NAME = "learning.html"

WORLDS_DIRNAME = "worlds"
#: Each sibling's own record of why its world ended without a full run (#1224):
#: `world_records/<label>.yaml`, written once by the sibling that went unservable.
WORLD_RECORDS_DIRNAME = "world_records"
#: Each world's oracle-side store (#1224): `oracle/<label>/`, one writer per world.
ORACLE_DIRNAME = "oracle"
RUNS_DIRNAME = "runs"
SERVED_DIRNAME = SERVED_PREFIX.rstrip("/")
JUDGE_DRAWS_DIRNAME = "judge"
BASE_FILENAME = "base.jsonl"
PRIMING_LOCK_NAME = f"{SERVED_PREFIX}.priming"
RUN_DIR_POINTER_NAME = "run_dir"

#: The archive's names for the two sidecars, which live beside a run dir keyed by run id and
#: are re-homed under the world as a bare `<kind>.json`. Other archived names are the run
#: dir's own, from `run_repository._layout`.
ARCHIVED_SCRUB_VERDICT_NAME = "scrub_verdict.json"
ARCHIVED_RUN_END_NAME = "run_end.json"


def _check_label(label: object, *, what: str = "label") -> str:
    """A world label: a plain, case-stable component — labels differing only in case would
    merge into one directory on a case-insensitive filesystem."""
    label = _check_component(label, what=what)
    if not is_case_stable_id(label):
        raise ValueError(f"{label!r} is not case-stable ({CASE_STABLE_REQUIRED})")
    return label


def check_minted_token(token: object) -> str:
    """A served-world token being minted (`<episode token>.<label>`): a plain component that is
    case-stable as a whole, so two tokens differing only in case are never two files on a host
    that folds them to one. Every minted token is (the episode token is casefolded, the label
    case-stable). Readers of an existing token use the shape check on `LAYOUT.served_world`."""
    token = _check_component(token, what="token")
    if not is_case_stable_id(token):
        raise ValueError(f"{token!r} is not case-stable ({CASE_STABLE_REQUIRED})")
    return token


# ==========================================================================================
# THE LAYOUT — every episode record as a path relative to the episode dir.
#
# `EpisodePaths` roots it at a real directory with a containment check. The relative view
# exists for `_io.Bound` readers, which address records relative to the root they hold and
# never by absolute path, so no caller spells a record name.
# ==========================================================================================


@dataclasses.dataclass(frozen=True)
class ArchivedWorldLeaves:
    """One archived world's records relative to the world dir, for readers bound at
    `worlds/<label>/`. `WorldLayout` (episode-relative) composes from this, so each leaf is
    spelled once.
    """

    @property
    def report(self) -> PurePosixPath:
        return PurePosixPath(REPORT)

    @property
    def investigation(self) -> PurePosixPath:
        return PurePosixPath(INVESTIGATION)

    @property
    def provenance(self) -> PurePosixPath:
        """The world's own flat run stamp — same file name as the episode-root family stamp,
        different shape."""
        return PurePosixPath(PROVENANCE)

    @property
    def scrub_verdict(self) -> PurePosixPath:
        """The scrub verdict's name inside the archive — not the sidecar's run-id-keyed
        spelling, since the world directory already identifies it."""
        return PurePosixPath(ARCHIVED_SCRUB_VERDICT_NAME)

    @property
    def run_end(self) -> PurePosixPath:
        return PurePosixPath(ARCHIVED_RUN_END_NAME)

    @property
    def lessons_loaded(self) -> PurePosixPath:
        return PurePosixPath(LESSONS_LOADED)

    @property
    def alert(self) -> PurePosixPath:
        return PurePosixPath(ALERT)

    @property
    def gather_summaries(self) -> PurePosixPath:
        return PurePosixPath(GATHER_SUMMARIES_DIRNAME)

    def gather_summary(self, lead_id: str) -> PurePosixPath:
        """`gather_summaries/<lead_id>.md`.

        No component check, unlike `RunPaths.gather_summary`: that one composes a name about to
        be written, while this reads a name already on disk that may not fit the strict shape
        (` spaced`, `.hidden`). Traversal is refused by `family.names_one_file` and by
        `_io.Bound`'s name grammar instead.
        """
        return self.gather_summaries / f"{lead_id}.md"

    @property
    def draws(self) -> PurePosixPath:
        return PurePosixPath(JUDGE_DRAWS_DIRNAME)

    def draw(self, n: int) -> PurePosixPath:
        return self.draws / f"{_check_index(n, what='n')}.yaml"

    @property
    def run_dir_pointer(self) -> PurePosixPath:
        """`run_dir` — a text pointer, never a link."""
        return PurePosixPath(RUN_DIR_POINTER_NAME)

    @property
    def review(self) -> PurePosixPath:
        return PurePosixPath(REVIEW_NAME)

    @property
    def samples(self) -> PurePosixPath:
        return PurePosixPath(SAMPLES_NAME)

    @property
    def judge(self) -> PurePosixPath:
        return PurePosixPath(JUDGE_NAME)


#: The archived world's leaf names, as one value.
WORLD_LEAVES = ArchivedWorldLeaves()


@dataclasses.dataclass(frozen=True)
class WorldLayout:
    """One archived world's records relative to the episode dir — `worlds/<label>/...`.
    Every record is `dir / WORLD_LEAVES.<name>`.
    """

    label: str

    @property
    def dir(self) -> PurePosixPath:
        return PurePosixPath(WORLDS_DIRNAME) / self.label

    @property
    def report(self) -> PurePosixPath:
        return self.dir / WORLD_LEAVES.report

    @property
    def investigation(self) -> PurePosixPath:
        return self.dir / WORLD_LEAVES.investigation

    @property
    def provenance(self) -> PurePosixPath:
        return self.dir / WORLD_LEAVES.provenance

    @property
    def scrub_verdict(self) -> PurePosixPath:
        return self.dir / WORLD_LEAVES.scrub_verdict

    @property
    def run_end(self) -> PurePosixPath:
        return self.dir / WORLD_LEAVES.run_end

    @property
    def lessons_loaded(self) -> PurePosixPath:
        return self.dir / WORLD_LEAVES.lessons_loaded

    @property
    def alert(self) -> PurePosixPath:
        return self.dir / WORLD_LEAVES.alert

    @property
    def gather_summaries(self) -> PurePosixPath:
        return self.dir / WORLD_LEAVES.gather_summaries

    def gather_summary(self, lead_id: str) -> PurePosixPath:
        return self.dir / WORLD_LEAVES.gather_summary(lead_id)

    @property
    def draws(self) -> PurePosixPath:
        return self.dir / WORLD_LEAVES.draws

    def draw(self, n: int) -> PurePosixPath:
        return self.dir / WORLD_LEAVES.draw(n)

    @property
    def run_dir_pointer(self) -> PurePosixPath:
        return self.dir / WORLD_LEAVES.run_dir_pointer

    @property
    def review(self) -> PurePosixPath:
        return self.dir / WORLD_LEAVES.review

    @property
    def samples(self) -> PurePosixPath:
        return self.dir / WORLD_LEAVES.samples

    @property
    def judge(self) -> PurePosixPath:
        return self.dir / WORLD_LEAVES.judge


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

    def world_record(self, label: str) -> PurePosixPath:
        """`world_records/<label>.yaml` — one world's own record (#1224). Shape check only."""
        return PurePosixPath(WORLD_RECORDS_DIRNAME) / f"{_check_component(label, what='label')}.yaml"

    def oracle_dir(self, label: str) -> PurePosixPath:
        """`oracle/<label>/` — one world's oracle-side store (#1224). Shape check only."""
        return PurePosixPath(ORACLE_DIRNAME) / _check_component(label, what="label")

    # -- composing ------------------------------------------------------------------------------

    def run(self, run_dir_name: str) -> PurePosixPath:
        """`runs/<run dir name>` — an existing sibling run dir, by its on-disk name. Shape check
        only; the minting rules live on `sibling_run_dir`.
        """
        return self.runs / _check_component(run_dir_name, what="run_dir_name")

    def run_page(self, run_dir_name: str) -> PurePosixPath:
        """`runs/<run dir name>/runtime.html` — the episode page's link to one sibling's page,
        spanning the episode and run layouts."""
        return self.run(run_dir_name) / RUN_LAYOUT.runtime_html

    def world(self, label: str) -> WorldLayout:
        """One archived world's records, by label.

        Shape check only: readers must be able to open an existing directory whose label is not
        case-stable. Case stability is enforced where a label is minted (`EpisodePaths.world`,
        `world_dir`, `sibling_run_dir`).
        """
        return WorldLayout(_check_component(label, what="label"))

    def served_world(self, token: str) -> PurePosixPath:
        """`served/<episode token>.<label>.jsonl`, by the token a manifest already declares.
        Shape check only, as for `world`; `EpisodePaths.served_world` enforces case stability.
        """
        return self.served / f"{_check_component(token, what='token')}.jsonl"

    def stage_trace(self, stage: str) -> PurePosixPath:
        """`wire_logs/<stage>.trace.jsonl` — the episode-root wire trace of one learning stage."""
        stage = _check_component(stage, what="stage")
        return PurePosixPath(WIRE_LOG_DIR) / f"{stage}{TRACE_SUFFIX}"

    def wire_log(self, name: str) -> PurePosixPath:
        """`wire_logs/<name>` — an episode-root wire log by its full file name (the judge's
        framed trace, named by `WIRE_LOG_NAMES`). One component."""
        return PurePosixPath(WIRE_LOG_DIR) / _check_component(name, what="wire log name")

    def sibling_run_dir(self, episode_id: str, label: str) -> PurePosixPath:
        """`runs/<episode_id>-<label>`. The label must be case-stable and `-`-free: episode ids
        always contain `-`, so a `-`-free label keeps `ep-a-b` unambiguously `(ep-a, b)`."""
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
class OracleStorePaths:
    """The records of one world's oracle-side store, rooted at `root` (`oracle/<label>/` under
    the episode, or wherever the caller placed the store): frozen forged rows, recorded facts,
    the served-answer cache, the oracle-side ledger, the world's live base answers and the
    oracle's spend trace (#1224)."""

    root: Path

    @property
    def forged(self) -> Path:
        return Path(self.root) / "forged.jsonl"

    @property
    def facts(self) -> Path:
        return Path(self.root) / "facts.jsonl"

    @property
    def answers(self) -> Path:
        return Path(self.root) / "answers.jsonl"

    @property
    def ledger(self) -> Path:
        return Path(self.root) / "ledger.jsonl"

    @property
    def base(self) -> Path:
        return Path(self.root) / BASE_FILENAME

    @property
    def trace(self) -> Path:
        return Path(self.root) / "trace.jsonl"

    def all(self) -> tuple[Path, ...]:
        return (self.forged, self.facts, self.answers, self.ledger, self.base, self.trace)


@dataclasses.dataclass(frozen=True)
class EpisodePaths:
    """One episode's directories and accessors, rooted at ``episode_dir`` with a containment
    check on every composed path. The relative form is ``.rel`` / ``LAYOUT``. Locating the
    episodes root is `learning/branch/cli.episodes_root`'s job, not this module's.
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

    def at(self, rel: PurePosixPath, *, what: str = "path") -> Path:
        """Root one of `LAYOUT`'s relative paths at this episode, with containment checked —
        the read side's way to an absolute path, without the minting accessors' case-stability
        rule.
        """
        return self._at(rel, what=what)

    # -- episode-root records -----------------------------------------------------------------

    @property
    def family(self) -> Path:
        return self.episode_dir / LAYOUT.family

    @property
    def family_stamp(self) -> Path:
        """The family stamp: `_layout.PROVENANCE`'s file name, different shape."""
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

    # -- composing accessors — shape + containment checked on every one ------------------------

    def world(self, label: str) -> WorldPaths:
        """One archived world, rooted at this episode. The write side, so the label must be
        case-stable.
        """
        return WorldPaths(self.episode_dir, LAYOUT.world(_check_label(label)))

    def served_world(self, token: str) -> Path:
        """`served/<episode token>.<label>.jsonl` — the minting side. The label is the text
        after the last dot (`_family.world_token_for` forbids dots in labels) and must be
        case-stable.
        """
        return self._at(LAYOUT.served_world(check_minted_token(token)), what="served_world")

    def judge_draw(self, label: str, n: int) -> Path:
        """`worlds/<label>/judge/<n>.yaml`."""
        return self._at(LAYOUT.world(_check_label(label)).draw(n), what="judge_draw")

    def stage_trace(self, stage: str) -> Path:
        return self._at(LAYOUT.stage_trace(stage), what="stage_trace")

    def sibling_run_dir(self, episode_id: str, label: str) -> Path:
        return self._at(LAYOUT.sibling_run_dir(episode_id, label), what="sibling_run_dir")

    def world_dir(self, label: str) -> Path:
        """`worlds/<label>`."""
        return self._at(LAYOUT.world(_check_label(label)).dir, what="world_dir")

    def run_dir_pointer(self, label: str) -> Path:
        return self._at(LAYOUT.world(_check_label(label)).run_dir_pointer,
                        what="run_dir_pointer")

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
    """One archived world's records, rooted at a real episode directory; `.rel` gives the
    relative form. Containment is checked on every absolute path.
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
