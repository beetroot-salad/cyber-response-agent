"""Shared machinery for #1007's grade-the-world spec — NO test scripts."""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender import _yaml
from defender.tests.support.learning.judge._judge_921 import (  # noqa: F401 — re-exported: the judge-side builders
    ALERT_ID,
    STATE_DIR_ENV,
    accepted_episode,
    archived_judge_world as archived_world,
    judge_record,
    ledger_row,
    write_ledger,
)
from defender.tests.support.learning.branch._triplet_947 import (  # noqa: F401 — re-exported: one spelling per fixture
    ALERTS_PATTERN,
    AS_OF,
    BRANCH_MESSAGE_ID,
    CLEAN,
    CONFIGURED,
    DEFENDER,
    EPISODE_ID,
    EPISODES_BASE_ENV,
    EVENTS_PATTERN,
    RUNS_BASE_ENV,
    SERVED_SYSTEMS,
    SOURCE_RUN_ID,
    WORLDS,
    Fault,
    FakeAdapters,
    FakeAgent,
    FakeSpawn,
    FakeTransport,
    assert_wrapped_untrusted,
    base_capture,
    base_world,
    capture_call,
    captured_row,
    configured_layout as _configured_layout_947,
    current_tenant,
    episode,
    fact,
    family_doc,
    mod,
    no_preflight,
    outside_untrusted_frames,
    provenance_record,
    refusals,
    report_text,
    runs_base,
    sibling_run_dir,
    sym,
    untrusted_frames,
    world_doc,
    fixture_world_id,
    world_id,
    write_family,
)

# ---------------------------------------------------------------------------------------
# The names #1007 introduces. Spelled ONCE, because the graph's address space and the code's
# symbol table join BY NAME (schema.md, "Coin ids from the code's name"): a private synonym
# here would cost the join, silently.
# ---------------------------------------------------------------------------------------

#: `defender/lessons-questioner/` — the second authored corpus (M7/D3). The path accessor pair
#: the graph binds as boundary `lessons_questioner_dir` lives on `_paths.DefenderPaths`, beside
#: `lessons_dir` / `lessons_dir_rel`, because that class is the one owner of corpus directory
#: NAMES (its own docstring: the names stay owned by `_paths.py` alone).
QUESTIONER_CORPUS_DIRNAME = "lessons-questioner"
QUESTIONER_CORPUS_REL = "defender/lessons-questioner/"

#: `_pending/questioner_findings.jsonl` — the second queue channel (M6). A2 (§7) settled its
#: lock topology: its OWN `append_lock` and `consumed` file, and the SHARED drain lock, so two
#: curators never hold the worktree at once.
QUESTIONER_QUEUE_FILENAME = "questioner_findings.jsonl"

#: The `_CURATOR_MODULES` key and the drain-trigger module name for M7's curator. `author` is
#: the incumbent defender-side one; after this change the fixed dict has a fourth key and the
#: drain triggers exactly these two.
QUESTIONER_CURATOR_MODULE = "questioner_curator"
DEFENDER_CURATOR_MODULE = "author"

#: The two `subject` literals. Exactly two string literals, no case-fold and no trim anywhere
#: (the graph's `subject` domain) — which is what makes the appender's guard and the bucket
#: selector agree by construction.
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


def read_yaml_record(bound: Any, name: str) -> Any:
    """`read_yaml`'s twin in the `reader=` seam's shape — `(bound, name)`, never a path (#1049
    d-21, RF-R2): the record's text comes off the bound primitive and is parsed; an absent
    record is `None`, the seam's typed absent answer; a refused one is a fixture fault here."""

    read = bound.read(name)
    assert read.refusal is None, f"fixture fault: {read.refusal}"
    return None if read.absent else _yaml.safe_load(read.text)


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


def write_samples(episode_dir: Path, samples: dict[str, Any] | None = None) -> Path:
    """Materialise `<episode>/samples.yaml`."""
    return write_yaml(Path(episode_dir) / SAMPLES_NAME,
                      samples if samples is not None else samples_document())


def write_outcome(episode_dir: Path, *, outcome: str = "accepted", reason: str = "",
                  family_stamp: bool = True) -> Path:
    """Materialise pre-flight's `<episode>/outcome.yaml` — the record the judge's gate reads —
    through the production writer (`learning/branch/outcome.py::write_outcome`). An `accepted`
    family also gets `verify_family`'s family stamp unless `family_stamp=False` (PR #1232
    round 7: only a stamped family is graded)."""
    from defender.episodes._episode_handle import Episode
    from defender.learning.branch.outcome import write_outcome as _write
    from defender.tests.support.learning.judge._judge_921 import comparable_family_stamp

    ep = Path(episode_dir)
    with Episode.open(ep) as handle:
        _write(handle, outcome, reason=reason)
    if family_stamp and outcome == "accepted":
        comparable_family_stamp(ep)
    return ep / OUTCOME_NAME


def configured_layout(tmp_path: Path, monkeypatch) -> tuple[Path, Path, Path]:
    """`_triplet_947.configured_layout`, plus the LEARNING STATE ROOT pointed inside `tmp_path`.

    The judge's appender writes to the ONE configured queue, resolved through
    `config.loop_paths()`. A scenario that left this root ambient would append its fixture rows
    into the developer's — and CI's — real `learning/_pending/`, which is a shared sink no test
    may touch. Environment steering through the resolver the shipped code already reads.
    """
    base, src, root = _configured_layout_947(tmp_path, monkeypatch)
    (tmp_path / "learning-state").mkdir(parents=True, exist_ok=True)  # never created lazily (#1135)
    monkeypatch.setenv(STATE_DIR_ENV, str(tmp_path / "learning-state"))
    return base, src, root


def served_row(*, world: str = "b", key: str = "k1", source: str = "oracle",
               payload_text: str | None = None, **extra: Any) -> dict[str, Any]:
    """One `served/<world>.jsonl` row, `ServedCall.row()`-shaped.

    Built on `_judge_921.ledger_row` so `world_id` is the COMPOSED world token a real row
    carries — never the short archive label. `source: oracle` is a call the world's live
    oracle answered (#1224); `asked_params` and `params` are the one form the model asked.
    """
    asked = {"index": EVENTS_PATTERN, "window": "24h", "scope_key": "host.name"}
    row = ledger_row(
        source=source, world_label=world, params=dict(asked), asked_params=asked,
        payload=payload_text if payload_text is not None else json.dumps(
            {"hits": [{"_id": "d1"}]}, sort_keys=True))
    row["correlation_key"] = key
    row.update(extra)
    return row


def write_served(episode_dir: Path, world: str, rows: list[dict]) -> Path:
    """Materialise one world's served ledger under `<episode>/served/`.

    Through `_judge_921.write_ledger` so the FILENAME is the composed world token rather than
    the short archive label — a reader opening `served/<label>.jsonl` finds nothing, and a
    fixture that spelled the short name would make every ledger assertion pass on an empty read.
    """
    return write_ledger(episode_dir, world, list(rows))


# ---------------------------------------------------------------------------------------
# The graded episode. #1234 replaced the reply this suite once scripted (`findings` with a
# `subject` key, `episode_outcome`, the family `verdict_word`) with three filed lists and typed
# pointers, and made a run usable only through its call-id-joined records (A3, A12) — so a
# graded scenario here is built and judged by #1234's own builders (`_spec1234`: `family`,
# `inv`, `wf`, `world_reply`, `family_reply`, `judge`, `grade`), never by a copy of them.
# ---------------------------------------------------------------------------------------


def contrast_family(tmp_path: Path, monkeypatch, worlds: Any = None, **kw: Any) -> Any:
    """`_spec1234.family(tmp_path, worlds, **kw)` (control `a`, planted `b` and `c` by
    default), with the learning state root pointed inside `tmp_path` — what #1234's own
    conftest does for its suite, done here per scenario. (#1187 O9: the episode lands under the
    data root's tenant, `<T>/episodes/`; no episodes root is configured.)"""
    from defender.tests.learning.judge.contrast_contracts import _spec1234 as S

    Path(tmp_path).mkdir(parents=True, exist_ok=True)  # a scenario's own subfolder (`tmp_path / "clean"`)
    S.isolate_learning_state(tmp_path, monkeypatch)
    return S.family(tmp_path, worlds, **kw)


@dataclass
class RecordingReader:
    """A counting wrapper over any single-argument read, as an injection seam.

    A demand that needs "how many times was this read" as an OBSERVATION rather than an
    inspection wraps the read in this. A counter that only counts leaves the
    argument unpinned, so every call's argument is recorded too.
    """

    inner: Any
    calls: list[Any] = field(default_factory=list)

    def __call__(self, *a: Any, **kw: Any) -> Any:
        self.calls.append((a, dict(kw)))
        return self.inner(*a, **kw)

    @property
    def count(self) -> int:
        return len(self.calls)


# ---------------------------------------------------------------------------------------
# The one place this suite drives a REAL primitive over a REAL response: `elastic_adapter`.
#
# `_search`'s normalization strips `took`, `_shards` and the per-hit `_id` before the ledger
# ever sees a payload. The claim is about what the primitive DOES to a raw cluster response, so
# a test writes a raw cluster response and runs the real adapter over it.
# ---------------------------------------------------------------------------------------

#: A `docker` on the run's own PATH that answers the curl lane from a JSON file the test wrote,
#: and records nothing it does not need to. The shebang is the RUNNING interpreter's absolute
#: path because the child's PATH holds this directory alone.
_ES_DOCKER_SHIM = r'''
import json
import os
import sys

argv = sys.argv[1:]
if "inspect" in argv:
    sys.stdout.write('"/canary-1"\t"elasticsearch:8"\n')
elif "sh" in argv:
    with open(os.environ["ES_RESPONSE_FILE"], encoding="utf-8") as fh:
        sys.stdout.write(fh.read().strip())
    sys.stdout.write("\n200")
else:
    sys.stdout.write("")
'''

#: A RAW Elasticsearch search response, carrying every incidental field `_search` discards.
#: `took` moves with cluster load, `_shards` moves with the cluster's own topology, and `_id`
#: is minted per indexed document — so two reads of one unchanged corpus differ on all three.
RAW_ES_RESPONSE = {
    "took": 37,
    "timed_out": False,
    "_shards": {"total": 3, "successful": 3, "skipped": 0, "failed": 0},
    "hits": {
        "total": {"value": 2, "relation": "eq"},
        "max_score": 1.0,
        "hits": [
            {"_index": "logs-000001", "_id": "AXbQ1", "_score": 1.0,
             "_source": {"host": {"name": "web-1"}, "event": {"action": "ssh_login"}}},
            {"_index": "logs-000001", "_id": "AXbQ2", "_score": 1.0,
             "_source": {"host": {"name": "web-2"}, "event": {"action": "ssh_login"}}},
        ],
    },
}


def elastic_ctx(tmp_path: Path, *, response: dict | None = None):
    """A real `VerbContext` whose transport reaches a `docker` shim answering `response`.

    Environment steering through the ctx the production caller already builds — `query_tool`
    constructs a `VerbContext(defender_dir=…, run_dir=…, env=…)` and the transport forks into
    exactly that env — so nothing here patches a module attribute.
    """
    verbs = mod("runtime.verbs")
    bindir = tmp_path / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    shim = bindir / "docker"
    shim.write_text(f"#!{sys.executable}\n{_ES_DOCKER_SHIM}", encoding="utf-8")
    shim.chmod(0o755)
    payload = tmp_path / "es-response.json"
    payload.write_text(json.dumps(response if response is not None else RAW_ES_RESPONSE),
                       encoding="utf-8")
    defender_dir = tmp_path / "defender"
    defender_dir.mkdir(parents=True, exist_ok=True)
    # #1107: the elastic config lives in the RUN's tenant folder; the ctx carries the record
    # resolved from it, never the process env.
    from defender.tests.tenancy.tenant_1107_settings import _spec1107 as spec1107
    tenants_root = tmp_path / "tenants"
    folder = spec1107.plant(tenants_root, marker="spec1007", configs=spec1107.config_texts(
        "spec1007", events_index=EVENTS_PATTERN, alerts_index=ALERTS_PATTERN))
    spec1107.set_key(folder, "elastic", "ELASTIC_DOCKER_CONTEXT", "spec-1007")
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    return verbs.VerbContext(
        defender_dir=defender_dir, run_dir=run_dir, tenant=spec1107.resolve(tenants_root),
        env={"PATH": str(bindir), "ES_RESPONSE_FILE": str(payload)},
    )


# ---------------------------------------------------------------------------------------
# The queues and the corpora.
# ---------------------------------------------------------------------------------------


def loop_paths(tmp_path: Path, *, repo_root: Path | None = None):
    """A `LoopPaths` rooted in `tmp_path` — the shipped injection seam every drain frame takes.

    `state_dir` is separated from `repo_root` deliberately: the queues are mutable state and
    the corpora are checked-in trees, and a scenario about one must be able to move it without
    moving the other.
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
    """Every row on a state `Channel`'s queue under `paths`' state root, in written order.
    Missing file reads as no rows, which is the honest answer for a pass that enqueued nothing."""
    path = paths.state_root / channel.queue
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def questioner_lesson(paths: Any, name: str = "q-lesson", *, body: str = "Ask the corpus.",
                      systems: list[str] | None = None, **frontmatter: Any) -> Path:
    """One `<name>.md` in the questioner corpus — the shape `_corpus.iter_lessons` globs.

    The selection key (`systems`) lives in the frontmatter because that is what M8's selector
    reads (#1224 O12): a lesson is shown at call 1 when its systems share a member with the
    episode's served systems.
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
    "ALERTS_PATTERN", "AS_OF", "BRANCH_MESSAGE_ID", "CLEAN", "CONFIGURED", "DEFENDER",
    "DEFENDER_CURATOR_MODULE", "EPISODES_BASE_ENV", "EPISODE_ID",
    "EVENTS_PATTERN", "JUDGE_NAME", "OUTCOME_NAME",
    "QUESTIONER_CORPUS_DIRNAME", "QUESTIONER_CORPUS_REL", "QUESTIONER_CURATOR_MODULE",
    "QUESTIONER_QUEUE_FILENAME", "RAW_ES_RESPONSE", "RUNS_BASE_ENV", "SERVED_SYSTEMS",
    "SAMPLES_NAME", "SAMPLE_DOCUMENT", "SOURCE_RUN_ID", "SUBJECT_DEFENDER", "SUBJECT_WORLD",
    "SYSTEM", "WORLDS",
    "FakeAdapters", "FakeAgent", "FakeTransport",
    "Fault", "RecordingReader",
    "archived_world", "assert_wrapped_untrusted", "base_capture",
    "base_world", "capture_call", "captured_row", "configured_layout", "contrast_family",
    "elastic_ctx",
    "episode", "fact", "family_doc",
    "loop_paths", "mod",
    "outside_untrusted_frames", "provenance_record", "queue_rows",
    "questioner_lesson", "questioner_lesson_raw",
    "read_yaml", "refusals", "report_text",
    "runs_base", "samples_document", "served_row", "sibling_run_dir", "sym",
    "untrusted_frames", "world_doc", "fixture_world_id", "write_family",
    "write_outcome", "write_samples", "write_served", "write_yaml",
]
