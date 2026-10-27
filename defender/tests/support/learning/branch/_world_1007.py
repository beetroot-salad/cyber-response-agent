"""Shared machinery for #1007's grade-the-world spec — NO test scripts."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import json
from pathlib import Path
from typing import Any

from defender import _yaml
from defender.tests.support.learning.judge._judge_921 import ledger_row
from defender.tests.support.learning.branch._triplet_947 import (  # noqa: F401 — re-exported: one spelling per fixture
    BRANCH_MESSAGE_ID,
    EPISODE_ID,
    EVENTS_PATTERN,
    SERVED_SYSTEMS,
    FakeAgent,
    assert_wrapped_untrusted,
    base_world,
    configured_layout,
    episode,
    fact,
    family_doc,
    mod,
    no_preflight,
    outside_untrusted_frames,
    refusals,
    runs_base,
    world_doc,
)

# ---------------------------------------------------------------------------------------
# The names #1007 introduces, spelled ONCE: the contract graph joins the code by name, so a
# private synonym here would silently break the join.
# ---------------------------------------------------------------------------------------

#: `defender/lessons-questioner/`, the second authored corpus (accessor: `lessons_questioner_dir`).
QUESTIONER_CORPUS_DIRNAME = "lessons-questioner"

#: `_pending/questioner_findings.jsonl`, the second queue channel: its OWN `append_lock` and
#: `consumed` file but the SHARED drain lock, so two curators never hold the worktree at once.
QUESTIONER_QUEUE_FILENAME = "questioner_findings.jsonl"

#: The `_CURATOR_MODULES` keys of the two curators the author drain triggers: the questioner's
#: and the defender-side `author`.
QUESTIONER_CURATOR_MODULE = "questioner_curator"
DEFENDER_CURATOR_MODULE = "author"

#: The two `subject` literals, matched exactly (no case-fold, no trim), so the appender's guard
#: and the bucket selector agree by construction.
SUBJECT_DEFENDER = "defender"
SUBJECT_WORLD = "world"

SAMPLES_NAME = "samples.yaml"
JUDGE_NAME = "judge.yaml"
OUTCOME_NAME = "outcome.yaml"

#: The served system every default fixture here names (one of `_triplet_947.SERVED_SYSTEMS`).
SYSTEM = "elastic"


# ---------------------------------------------------------------------------------------
# The episode's new artifacts, as builders. A new scenario is a few lines of data.
# ---------------------------------------------------------------------------------------


def write_yaml(path: Path, doc: Any) -> Path:

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return path


def read_yaml(path: Path) -> Any:

    return _yaml.safe_load(path.read_text(encoding="utf-8"))


#: One real answer document, as the source run's capture recorded it.
SAMPLE_DOCUMENT = {
    "@timestamp": "2026-07-28T16:00:00Z",
    "host": {"name": "web-1"},
    "event": {"action": "ssh_login", "outcome": "success"},
    "user": {"name": "svc-deploy"},
}


def samples_document(*, system: str = SYSTEM, verb: str = "esql",
                     answers: list[str] | None = None) -> dict[str, Any]:
    """`{system: {verbs: {verb: [answer text]}}}` — `samples.yaml`'s shipped shape
    (`cli.system_samples`), one served system with one verb."""
    texts = answers if answers is not None else [json.dumps(SAMPLE_DOCUMENT, sort_keys=True)]
    return {system: {"verbs": {verb: list(texts)}}}


def served_row(*, world: str = "b", key: str = "k1", source: str = "oracle",
               payload_text: str | None = None, **extra: Any) -> dict[str, Any]:
    """One `served/<world>.jsonl` row, `ServedCall.row()`-shaped, built on `ledger_row` so
    `world_id` is the COMPOSED world token a real row carries, not the archive label.
    `source: oracle` is a call the world's live oracle answered.
    """
    asked = {"index": EVENTS_PATTERN, "window": "24h", "scope_key": "host.name"}
    row = ledger_row(
        source=source, world_label=world, params=dict(asked), asked_params=asked,
        payload=payload_text if payload_text is not None else json.dumps(
            {"hits": [{"_id": "d1"}]}, sort_keys=True))
    row["correlation_key"] = key
    row.update(extra)
    return row


# ---------------------------------------------------------------------------------------
# The graded episode: built and judged by #1234's own builders (`_spec1234`), never a copy.
# ---------------------------------------------------------------------------------------


def contrast_family(tmp_path: Path, monkeypatch, worlds: Any = None, **kw: Any) -> Any:
    """`_spec1234.family(tmp_path, worlds, **kw)` (control `a`, planted `b` and `c` by
    default), with the learning state root inside `tmp_path`, as #1234's conftest does."""
    from defender.tests.learning.judge.contrast_contracts import _spec1234 as S

    Path(tmp_path).mkdir(parents=True, exist_ok=True)  # a scenario's own subfolder (`tmp_path / "clean"`)
    S.isolate_learning_state(tmp_path, monkeypatch)
    return S.family(tmp_path, worlds, **kw)


# ---------------------------------------------------------------------------------------
# The queues and the corpora.
# ---------------------------------------------------------------------------------------


def loop_paths(tmp_path: Path, *, repo_root: Path | None = None):
    """A `LoopPaths` rooted in `tmp_path`. `state_dir` is kept apart from `repo_root` (queues are
    mutable state, corpora checked-in trees) so a scenario can move one without the other.
    """
    cfg = mod("learning.core.config")
    root = repo_root if repo_root is not None else tmp_path / "repo"
    (root / "defender").mkdir(parents=True, exist_ok=True)
    (tmp_path / "learning-state").mkdir(parents=True, exist_ok=True)  # never created lazily (#1135)
    return cfg.LoopPaths(repo_root=root, state_dir=tmp_path / "learning-state")


def learning_state(paths: Any):
    """A `LearningState` handle over `paths`' state root (#1135) — what every verb taking `state=` wants."""
    return mod("learning.core.state").LearningState.open(paths)


def queue_rows(paths: Any, channel: Any) -> list[dict]:
    """Every row on a state `Channel`'s queue under `paths`' state root, in written order; a
    missing file reads as no rows."""
    path = location_path(paths.state_root) / channel.queue
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def questioner_lesson(paths: Any, name: str = "q-lesson", *, body: str = "Ask the corpus.",
                      systems: list[str] | None = None, **frontmatter: Any) -> Path:
    """One `<name>.md` in the questioner corpus. Its selection key `systems` is frontmatter: a
    lesson is shown at call 1 when its systems meet the episode's served systems.
    """

    corpus = Path(paths.lessons_questioner_dir)
    corpus.mkdir(parents=True, exist_ok=True)
    meta: dict[str, Any] = {"name": name, "systems": list(systems if systems is not None
                                                          else [SYSTEM])}
    meta.update(frontmatter)
    path = corpus / f"{name}.md"
    path.write_text(
        "---\n" + _yaml.safe_dump(meta, sort_keys=False) + "---\n" + body + "\n",
        encoding="utf-8")
    return path


def questioner_lesson_raw(paths: Any, name: str, *, frontmatter: str,
                          body: str = "Ask the corpus.") -> Path:
    """One `<name>.md` whose frontmatter is written as RAW TEXT, not through a dumper."""
    corpus = Path(paths.lessons_questioner_dir)
    corpus.mkdir(parents=True, exist_ok=True)
    path = corpus / f"{name}.md"
    path.write_text("---\n" + frontmatter.rstrip("\n") + "\n---\n" + body + "\n",
                    encoding="utf-8")
    return path


__all__ = [
    "DEFENDER_CURATOR_MODULE", "EPISODE_ID", "EVENTS_PATTERN", "JUDGE_NAME", "OUTCOME_NAME",
    "QUESTIONER_CORPUS_DIRNAME", "QUESTIONER_CURATOR_MODULE", "QUESTIONER_QUEUE_FILENAME",
    "SERVED_SYSTEMS", "SAMPLES_NAME", "SAMPLE_DOCUMENT", "SUBJECT_DEFENDER", "SUBJECT_WORLD",
    "SYSTEM",
    "FakeAgent",
    "assert_wrapped_untrusted", "base_world", "configured_layout", "contrast_family",
    "episode", "fact", "family_doc",
    "loop_paths", "mod",
    "outside_untrusted_frames", "queue_rows",
    "questioner_lesson", "questioner_lesson_raw",
    "read_yaml", "refusals",
    "runs_base", "samples_document", "served_row",
    "world_doc", "write_yaml",
]
