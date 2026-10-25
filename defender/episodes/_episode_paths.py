from __future__ import annotations

from defender.records._locations import (RunsBase)

import dataclasses
from pathlib import Path, PurePosixPath

from defender.records._run_id import episode_id_fault, uuid_id_fault
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
#: them under local aliases (`tooling/lint/lint_run_records.py` refuses that).
FAMILY_NAME = "family.yaml"
#: The host-written arm roster (#1187): `{world_id: arm run id}` for every world the manifest
#: declares, written once when the episode reaches RUNS and never by a sibling.
ARM_ROSTER_NAME = "arms.json"
REVIEW_NAME = "review.yaml"
SAMPLES_NAME = "samples.yaml"
JUDGE_NAME = "judge.yaml"
TIMING_NAME = "timing.json"
STAGED_NAME = "staged.yaml"
#: Pre-flight's write-once episode outcome record (#1224): accepted, unusable or refused.
OUTCOME_NAME = "outcome.yaml"
#: Why `verify_family` withheld the family stamp: written only when it did, so the judge can
#: name the reason it stamps a stampless family `not comparable`.
NOT_COMPARABLE_NAME = "not_comparable.yaml"
LEARNING_HTML_NAME = "learning.html"
#: The source run's alert and its record, copied into the episode at launch (#1222 A1): the
#: judge's whole input about the alert, and the sibling runs' own input.
#: The run's alert record inside a world's archive, beside its `alert.json`.
ARCHIVED_ALERT_RECORD_NAME = "alert_record.json"
SOURCE_ALERT_NAME = "source_alert.json"
SOURCE_RECORD_NAME = "source_record.json"
#: The family's knowledge pin (#1108 P4, flow 7, O-PIN): the one knowledge commit every sibling
#: reads and the judge reads lesson bodies at, decided by the launcher from the source run's
#: host-held knowledge record and created once, here, where no box writes.
KNOWLEDGE_PIN_NAME = "knowledge_pin.json"

WORLDS_DIRNAME = "worlds"
#: Each sibling's own record of why its world ended without a full run (#1224):
#: `world_records/<world_id>.yaml`, written once by the sibling that went unservable.
WORLD_RECORDS_DIRNAME = "world_records"
#: Each world's oracle-side store (#1224): `oracle/<world_id>/`, one writer per world.
ORACLE_DIRNAME = "oracle"
RUNS_DIRNAME = "runs"
SERVED_DIRNAME = SERVED_PREFIX.rstrip("/")
JUDGE_DRAWS_DIRNAME = "judge"
BASE_FILENAME = "base.jsonl"
#: The primer's skip record (#1255 D6): the calls the source asked whose answer the recording
#: lacks because the call failed or its payload was unreadable.
UNRECORDED_FILENAME = "unrecorded.jsonl"
PRIMING_LOCK_NAME = f"{SERVED_PREFIX}.priming"

#: The archive's names for the two sidecars, which live beside a run dir keyed by run id and
#: are re-homed under the world as a bare `<kind>.json`. Other archived names are the run
#: dir's own, from `run_repository._layout`.
ARCHIVED_SCRUB_VERDICT_NAME = "scrub_verdict.json"
ARCHIVED_RUN_END_NAME = "run_end.json"
#: The run's call join (`RunPaths.call_join`, #1255 G4/G6), re-homed under the world beside the
#: query table it joins to the served ledger.
ARCHIVED_CALL_JOIN_NAME = "call_join.jsonl"


class EpisodeRefused(ValueError):
    """The episode owner refused an episode id, before any path was built from it. The message
    is operator-ready; each door adds its own prefix."""


def refuse_bad_episode_id(episode_id: object) -> str:  # lint-dup: ok — one rule, two error classes: `_family` raises `FamilyError` for a manifest; the episode owner raises `EpisodeRefused` before any path is built (both state the rule once, in `_run_id.episode_id_fault`)
    """`episode_id`, when it may name an episode folder under `<T>/episodes` — canonical
    lowercase UUID text (`_run_id.episode_id_fault`, the one statement of the rule) — else
    `EpisodeRefused`, before any path is built from it. Kept beside the layout, not in the
    handle, so the handle stays a pure holder (#1133 D6': it defines no public function); the
    handle re-exports it, where the doors' callers look for it."""
    if type(episode_id) is not str:
        raise EpisodeRefused(f"an episode id must be text, not {type(episode_id).__name__}")
    if (why := episode_id_fault(episode_id)) is not None:
        raise EpisodeRefused(why)
    return episode_id


def _check_world_id(world_id: object) -> str:
    """A world's stored identity: canonical UUID text, independent of its world_id."""
    if (why := uuid_id_fault(world_id, "world")) is not None:
        raise ValueError(why)
    assert isinstance(world_id, str)
    return world_id


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
    `worlds/<world_id>/`. `WorldLayout` (episode-relative) composes from this, so each leaf is
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
    def alert_record(self) -> PurePosixPath:
        """The run's alert record, archived beside the alert it vouches for."""
        return PurePosixPath(ARCHIVED_ALERT_RECORD_NAME)

    @property
    def gather_summaries(self) -> PurePosixPath:
        return PurePosixPath(GATHER_SUMMARIES_DIRNAME)

    @property
    def executed_queries(self) -> PurePosixPath:
        """The archived query table: the sibling run's own, copied under the world. It carries
        no call id (#1255 G4); the judge joins it to the served ledger through `call_join`."""
        return PurePosixPath(RUN_LAYOUT.executed_queries)

    @property
    def call_join(self) -> PurePosixPath:
        """The run's call join (#1255 G4/G6): `(lead_id, seq)` -> call id for every table row
        the run itself wrote; a table row with no line here is inherited (seeded)."""
        return PurePosixPath(ARCHIVED_CALL_JOIN_NAME)

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
    """One archived world's records relative to the episode dir — `worlds/<world_id>/...`.
    Every record is `dir / WORLD_LEAVES.<name>`.
    """

    world_id: str

    def __post_init__(self) -> None:
        _check_world_id(self.world_id)

    @property
    def dir(self) -> PurePosixPath:
        return PurePosixPath(WORLDS_DIRNAME) / self.world_id

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
    def alert_record(self) -> PurePosixPath:
        return self.dir / WORLD_LEAVES.alert_record

    @property
    def gather_summaries(self) -> PurePosixPath:
        return self.dir / WORLD_LEAVES.gather_summaries

    @property
    def executed_queries(self) -> PurePosixPath:
        return self.dir / WORLD_LEAVES.executed_queries

    @property
    def call_join(self) -> PurePosixPath:
        return self.dir / WORLD_LEAVES.call_join

    def gather_summary(self, lead_id: str) -> PurePosixPath:
        return self.dir / WORLD_LEAVES.gather_summary(lead_id)

    @property
    def draws(self) -> PurePosixPath:
        return self.dir / WORLD_LEAVES.draws

    def draw(self, n: int) -> PurePosixPath:
        return self.dir / WORLD_LEAVES.draw(n)

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
    def arm_roster(self) -> PurePosixPath:
        """`arms.json` — the episode's arm roster (#1187), present once the episode reached
        RUNS."""
        return PurePosixPath(ARM_ROSTER_NAME)

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
    def family_draws(self) -> PurePosixPath:
        return PurePosixPath(JUDGE_DRAWS_DIRNAME)

    def family_draw(self, n: int) -> PurePosixPath:
        return self.family_draws / f"{_check_index(n, what='draw')}.yaml"

    @property
    def timing(self) -> PurePosixPath:
        return PurePosixPath(TIMING_NAME)

    @property
    def staged(self) -> PurePosixPath:
        return PurePosixPath(STAGED_NAME)

    @property
    def outcome(self) -> PurePosixPath:
        return PurePosixPath(OUTCOME_NAME)

    @property
    def not_comparable(self) -> PurePosixPath:
        return PurePosixPath(NOT_COMPARABLE_NAME)

    @property
    def learning_html(self) -> PurePosixPath:
        return PurePosixPath(LEARNING_HTML_NAME)

    @property
    def source_alert(self) -> PurePosixPath:
        return PurePosixPath(SOURCE_ALERT_NAME)

    @property
    def source_record(self) -> PurePosixPath:
        return PurePosixPath(SOURCE_RECORD_NAME)

    @property
    def knowledge_pin(self) -> PurePosixPath:
        return PurePosixPath(KNOWLEDGE_PIN_NAME)

    @property
    def served(self) -> PurePosixPath:
        return PurePosixPath(SERVED_DIRNAME)

    @property
    def served_base(self) -> PurePosixPath:
        return self.served / BASE_FILENAME

    @property
    def served_unrecorded(self) -> PurePosixPath:
        """The primer's skip record beside the base (#1255 D6): each call the source asked
        whose answer the base lacks because the call failed or its payload was unreadable."""
        return self.served / UNRECORDED_FILENAME

    @property
    def priming_lock(self) -> PurePosixPath:
        return PurePosixPath(PRIMING_LOCK_NAME)

    @property
    def runs(self) -> PurePosixPath:
        return PurePosixPath(RUNS_DIRNAME)

    @property
    def worlds(self) -> PurePosixPath:
        return PurePosixPath(WORLDS_DIRNAME)

    @property
    def world_records(self) -> PurePosixPath:
        """`world_records/` — every world's own record (#1224)."""
        return PurePosixPath(WORLD_RECORDS_DIRNAME)

    def world_record(self, world_id: str) -> PurePosixPath:
        """`world_records/<world_id>.yaml` — one world's own record (#1224). Shape check only."""
        return PurePosixPath(WORLD_RECORDS_DIRNAME) / f"{_check_world_id(world_id)}.yaml"

    def oracle_dir(self, world_id: str) -> PurePosixPath:
        """`oracle/<world_id>/` — one world's oracle-side store (#1224). Shape check only."""
        return PurePosixPath(ORACLE_DIRNAME) / _check_world_id(world_id)

    # -- composing ------------------------------------------------------------------------------

    def run(self, run_dir_name: str) -> PurePosixPath:
        """`runs/<run dir name>` — a sibling run dir, by its on-disk name: the arm id the roster
        holds (#1187). Shape check only; the id rule is `RunId`'s.
        """
        return self.runs / _check_component(run_dir_name, what="run_dir_name")

    def run_page(self, run_dir_name: str) -> PurePosixPath:
        """`runs/<run dir name>/runtime.html` — the episode page's link to one sibling's page,
        spanning the episode and run layouts."""
        return self.run(run_dir_name) / RUN_LAYOUT.runtime_html

    def world(self, world_id: str) -> WorldLayout:
        """One archived world's records, by its canonical UUID."""
        return WorldLayout(_check_world_id(world_id))

    def served_world(self, world_id: str) -> PurePosixPath:
        """The ledger named by a canonical world UUID persisted in the manifest."""
        return self.served / f"{_check_world_id(world_id)}.jsonl"

    def stage_trace(self, stage: str) -> PurePosixPath:
        """`wire_logs/<stage>.trace.jsonl` — the episode-root wire trace of one learning stage."""
        stage = _check_component(stage, what="stage")
        return PurePosixPath(WIRE_LOG_DIR) / f"{stage}{TRACE_SUFFIX}"

    def wire_log(self, name: str) -> PurePosixPath:
        """`wire_logs/<name>` — an episode-root wire log by its full file name (the judge's
        framed trace, named by `WIRE_LOG_NAMES`). One component."""
        return PurePosixPath(WIRE_LOG_DIR) / _check_component(name, what="wire log name")


#: The layout, as one value. Stateless, so one instance serves every caller.
LAYOUT = EpisodeLayout()


#: `oracle/<world_id>/collisions.jsonl` — see `OracleStorePaths.collisions`.
COLLISIONS_FILENAME = "collisions.jsonl"


@dataclasses.dataclass(frozen=True)
class OracleStorePaths:
    """The records of one world's oracle-side store, rooted at `root` (`oracle/<world_id>/` under
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

    @property
    def collisions(self) -> Path:
        """A frozen forged row's identifier that this world's real data later carried too
        (M12=A: the row stays frozen; the collision is recorded for the judge)."""
        return Path(self.root) / COLLISIONS_FILENAME

    def all(self) -> tuple[Path, ...]:
        return (self.forged, self.facts, self.answers, self.ledger, self.base, self.trace,
                self.collisions)


@dataclasses.dataclass(frozen=True)
class EpisodePaths:
    """One episode's directories and accessors, rooted at ``episode_dir`` with a containment
    check on every composed path. The relative form is ``.rel`` / ``LAYOUT``. Locating the
    episodes folder (`<T>/episodes/`) is `run_repository`'s job, not this module's.
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
        """Root one of `LAYOUT`'s relative paths at this episode, checking containment."""
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
    def arm_roster(self) -> Path:
        return self.episode_dir / LAYOUT.arm_roster

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
    def family_draws(self) -> Path:
        return self.episode_dir / LAYOUT.family_draws

    def family_draw(self, n: int) -> Path:
        return self._at(LAYOUT.family_draw(n), what="family_draw")

    @property
    def timing(self) -> Path:
        return self.episode_dir / LAYOUT.timing

    @property
    def staged(self) -> Path:
        return self.episode_dir / LAYOUT.staged

    @property
    def source_alert(self) -> Path:
        """The source run's alert, as launch copied it into the episode (#1222 A1)."""
        return self.episode_dir / LAYOUT.source_alert

    @property
    def source_record(self) -> Path:
        """The source run's record, copied beside `source_alert`."""
        return self.episode_dir / LAYOUT.source_record

    @property
    def knowledge_pin(self) -> Path:
        """The family's knowledge pin, created once by the launcher."""
        return self.episode_dir / LAYOUT.knowledge_pin

    @property
    def outcome(self) -> Path:
        return self.episode_dir / LAYOUT.outcome

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
    def served_unrecorded(self) -> Path:
        return self.episode_dir / LAYOUT.served_unrecorded

    @property
    def priming_lock(self) -> Path:
        return self.episode_dir / LAYOUT.priming_lock

    @property
    def runs(self) -> RunsBase:
        return RunsBase(self.episode_dir / LAYOUT.runs)

    @property
    def worlds(self) -> Path:
        return self.episode_dir / LAYOUT.worlds

    # -- composing accessors — shape + containment checked on every one ------------------------

    def world(self, world_id: str) -> WorldPaths:
        """One archived world, rooted at this episode and addressed by canonical UUID."""
        return WorldPaths(self.episode_dir, LAYOUT.world(_check_world_id(world_id)))

    def served_world(self, world_id: str) -> Path:
        """The world UUID's ledger; labels never participate in its filename."""
        return self._at(LAYOUT.served_world(_check_world_id(world_id)), what="served_world")

    def judge_draw(self, world_id: str, n: int) -> Path:
        """`worlds/<world_id>/judge/<n>.yaml`."""
        return self._at(LAYOUT.world(_check_world_id(world_id)).draw(n), what="judge_draw")

    def stage_trace(self, stage: str) -> Path:
        return self._at(LAYOUT.stage_trace(stage), what="stage_trace")

    def world_dir(self, world_id: str) -> Path:
        """`worlds/<world_id>`."""
        return self._at(LAYOUT.world(_check_world_id(world_id)).dir, what="world_dir")

    # -- the archive projection's flat spellings, per world_id ------------------------------------

    def gather_summaries(self, world_id: str) -> Path:
        return self._at(LAYOUT.world(world_id).gather_summaries, what="gather_summaries")

    def lessons_loaded(self, world_id: str) -> Path:
        return self._at(LAYOUT.world(world_id).lessons_loaded, what="lessons_loaded")

    def alert(self, world_id: str) -> Path:
        return self._at(LAYOUT.world(world_id).alert, what="alert")

    def draws(self, world_id: str) -> Path:
        return self._at(LAYOUT.world(world_id).draws, what="draws")


@dataclasses.dataclass(frozen=True)
class WorldPaths:
    """One archived world's records, rooted at a real episode directory; `.rel` gives the
    relative form. Containment is checked on every absolute path.
    """

    episode_dir: Path
    rel: WorldLayout

    @property
    def world_id(self) -> str:
        return self.rel.world_id

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
    def call_join(self) -> Path:
        return self._at(self.rel.call_join, what="call_join")

    @property
    def lessons_loaded(self) -> Path:
        return self._at(self.rel.lessons_loaded, what="lessons_loaded")

    @property
    def alert(self) -> Path:
        return self._at(self.rel.alert, what="alert")

    @property
    def alert_record(self) -> Path:
        return self._at(self.rel.alert_record, what="alert_record")

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
    def review(self) -> Path:
        return self._at(self.rel.review, what="review")

    @property
    def samples(self) -> Path:
        return self._at(self.rel.samples, what="samples")

    @property
    def judge(self) -> Path:
        return self._at(self.rel.judge, what="judge")
