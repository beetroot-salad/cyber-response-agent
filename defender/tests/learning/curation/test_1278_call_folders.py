"""#1278 A1 (O8, O9): each curator call runs in a private folder of its own, holding only its trace.

The three curators (lessons, questioner, pitfalls) run as the drain runs them: `author_drain` and
`lead_author_drain` over the published fixture tenant with their own default steps, the store at
`DEFENDER_DATABASE_DSN`, and only the model replaced, by a wire endpoint (`WireModel`) that reads
files for the curator and answers. What the model was shown and what its tools answered are read off
the wire; the folders are read off the disk. The folder is found by `(tenant, drain batch id, stage,
ordinal)` through `defender.learning.call_folders.call_folder` (interface request; stages "lessons",
"questioner", "pitfalls"; ordinals count from 1 per stage within a drain batch) under the tenant's
scratch location `tenant.scratch` (interface request, a registered location type, #1210).
"""
from __future__ import annotations

import importlib
import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.support.jobs._jobs1342 import register_tenant  # noqa: E402
from defender.tests.support.learning.core._declared870 import shim_row  # noqa: E402
from defender.tests.support.learning.core._store1278 import (  # noqa: E402
    DSN_ENV,
    FINDING,
    QUESTIONER,
    batches,
    call,
    finding,
    world_finding,
)
from defender.tests.support.learning.curation._callfolder1278 import (  # noqa: E402
    MODEL,
    MODEL_ENV,
    Conversation,
    WireModel,
    files_below,
)
from defender.tests.support.shared._locations_1210 import location_path  # noqa: E402
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: E402, F401 — fixture
from defender.tests.tenancy.tenant_1108_p4._drain_support import (  # noqa: E402
    BoxSpy,
    author_drain,
    drain_paths,
    lead_author_drain,
    product_repo,
)
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, published_tenant  # noqa: E402

pytestmark = pytest.mark.postgres

#: In the order the two drains call them: the author tick runs lessons then questioner; the lead tick, pitfalls.
STAGES = ("lessons", "questioner", "pitfalls")
LEGACY_CANARY = "CANARY-LEGACY-LEARNING-STATE-1278"
OTHER_CALL_CANARY = "CANARY-ANOTHER-CALLS-FOLDER-1278"
PREVIOUS_DRAIN = "previous-drain"


def _folders() -> Any:
    return importlib.import_module("defender.learning.call_folders")


def _tenant_root(tenant: Any) -> Path:
    return Path(location_path(tenant.tenant_root))


def _scratch(tenant: Any) -> Path:
    return Path(location_path(tenant.scratch))


def _salt(conversation: Conversation) -> str:
    """The run-salted frame tag the call's own user prompt carries: unique to the call."""
    return re.search(r"run-([0-9a-f]{32})", conversation.first_user).group(1)  # type: ignore[union-attr]


@pytest.fixture
def world(tmp_path, data_root, migrated_database, monkeypatch):  # noqa: F811 — the imported fixture
    """The fixture tenant published for real and active in the database, every curator waking at one item."""
    with published_tenant(tmp_path / "forge", root=data_root) as t:
        bind_forge(t)
        register_tenant(migrated_database, t.tenant_id)
        monkeypatch.setenv(DSN_ENV, migrated_database)
        for var in ("LEARNING_AUTHOR_THRESHOLD", "LEARNING_QUESTIONER_THRESHOLD", "LEARNING_PITFALLS_THRESHOLD"):
            monkeypatch.setenv(var, "1")
        for var in MODEL_ENV:
            monkeypatch.setenv(var, MODEL)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "k-1278")
        paths = drain_paths(t, product_repo(tmp_path, adapters=("cmdb",)))
        yield SimpleNamespace(t=t, dsn=migrated_database, paths=paths, tmp=tmp_path, monkeypatch=monkeypatch)


def _seed(w: Any, tag: str) -> None:
    tid = w.t.tenant_id
    call(w.dsn, "publish_findings", tid, f"run-{tag}", [finding(f"f-{tag}")], kind=FINDING)
    call(w.dsn, "publish_findings", tid, f"run-{tag}", [world_finding(f"w-{tag}")], kind=QUESTIONER)
    call(w.dsn, "add_pitfall", tid, shim_row(f"{tag}-run:1"))


def _plant(w: Any) -> None:
    """What a curator must not reach: files in the old learning root's place, and a folder of a call of another drain."""
    root = _tenant_root(w.t.tenant) / "learning"
    for rel in ("_pending/findings.jsonl", "_pending_leads/pitfalls.jsonl"):
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(LEGACY_CANARY + "\n", encoding="utf-8")
    other = _folders().call_folder(w.t.tenant, PREVIOUS_DRAIN, "lessons", 1, make=True)
    (other / "canary.txt").write_text(OTHER_CALL_CANARY + "\n", encoding="utf-8")


def _run(w: Any, wire: WireModel, *, tag: str = "a") -> list[BoxSpy]:
    """Seed one item per curator, then one author tick (lessons, questioner) and one lead tick (pitfalls), each on its
    own default step; the boxes the ticks were given."""
    w.monkeypatch.setenv("ANTHROPIC_BASE_URL", wire.url)
    _seed(w, tag)
    author, lead = BoxSpy(), BoxSpy()
    author_drain(w.t, w.paths, trigger=None, box=author)
    lead_author_drain(w.t, w.paths, box=lead)
    return [author, lead]


def _shown_file(conversation: Conversation) -> str:
    """A file the call's own prompt points the model at, spelled as the prompt spells it: the pitfalls curator's first
    handed-off surface under the `draft_root` it is shown; a lessons curator's first manifest lesson under the
    `lessons_dir` it is shown."""
    messages = json.loads(conversation.first_user)
    text = "\n".join(str(block.get("text", "")) for message in messages
                     for block in (message["content"] if isinstance(message["content"], list) else [{"text": message["content"]}]))
    draft = re.search(r"^draft_root: (\S+)$", text, re.M)
    if draft:
        surface = re.search(r'"path": "([^"]+)"', text)
        return f"{draft.group(1).rstrip('/')}/{surface.group(1)}" if surface else "NO-SURFACE-IN-THE-PROMPT"
    corpus = re.search(r"^lessons_dir: (\S+)$", text, re.M)
    lesson = re.search(r"corpus_manifest>\n([\w.-]+)\n", text)
    return f"{corpus.group(1).rstrip('/')}/{lesson.group(1)}.md" if corpus and lesson else "NO-LESSON-IN-THE-PROMPT"


class Probe:
    """The model's side of O8. Each call reads a lesson or skill file its prompt points it at (the control,
    `_shown_file`), then tries to reach the old learning root's files and another call's folder as it would if one of
    its own workspace roots were that place (`<root>/findings.jsonl`, `<root>/<other call folder>/canary.txt`, ...),
    and by host path. It snapshots the batch rows as they stand while the call is in flight. `labels[i]` says what the
    i-th path tries to reach."""

    def __init__(self, w: Any) -> None:
        self.w = w
        self.asked: dict[int, list[str]] = {}
        self.labels: dict[int, list[str]] = {}
        self.rows: dict[int, list[tuple[str, str, str]]] = {}
        self.conversations: list[Conversation] = []

    def __call__(self, conversation: Conversation) -> list[str]:
        w = self.w
        if conversation not in self.conversations:
            self.conversations.append(conversation)
        index = self.conversations.index(conversation)
        self.rows[index] = [(b.id, b.lane, b.phase) for b in batches(w.dsn, w.t.tenant_id)]
        other = _folders().call_folder(w.t.tenant, PREVIOUS_DRAIN, "lessons", 1, make=False)
        asked, labels = [_shown_file(conversation)], ["control"]
        roots = conversation.roots_line().removeprefix("Workspace roots:").split(",")
        for root in (r.strip() for r in roots if r.strip()):
            for rel in ("findings.jsonl", "pitfalls.jsonl", "_pending/findings.jsonl", "_pending_leads/pitfalls.jsonl"):
                asked.append(f"{root}/{rel}")
                labels.append("legacy")
            for rel in (f"{other.name}/canary.txt", "canary.txt", f"../{other.name}/canary.txt"):
                asked.append(f"{root}/{rel}")
                labels.append("other-call")
        for path in files_below(_scratch(w.t.tenant)) + files_below(_tenant_root(w.t.tenant) / "learning"):
            asked.append(str(path))
            labels.append("other-call" if _scratch(w.t.tenant) in path.parents else "legacy")
        self.asked[index], self.labels[index] = asked, labels
        return asked

    def answers(self, index: int) -> list[dict]:
        blocks = self.conversations[index].requests[1]["messages"][-1]["content"]
        by_id = {b["tool_use_id"]: b for b in blocks if b.get("type") == "tool_result"}
        return [by_id[f"toolu_{i}"] for i in range(len(self.asked[index]))]


@pytest.fixture
def ticked(world):
    """Both drains, once, with the model reading what it is not to reach."""
    _plant(world)
    probe = Probe(world)
    with WireModel(probe) as wire:
        boxes = _run(world, wire)
    assert len(wire.calls) == 3, f"expected one model call per curator, saw {len(wire.calls)}: the drains did not reach the model"
    return SimpleNamespace(w=world, probe=probe, wire=wire, boxes=boxes)


def _working(ticked: Any, stage: str) -> tuple[str, str, str]:
    """The one working batch row as the stage's call ran: `(id, lane, phase)`."""
    [row] = [b for b in ticked.probe.rows[STAGES.index(stage)] if b[2] == "working"]
    return row


def _folder(ticked: Any, stage: str) -> Path:
    return _folders().call_folder(ticked.w.t.tenant, _working(ticked, stage)[0], stage, 1, make=False)


# --- O8 -------------------------------------------------------------------------------------------------------


@pytest.mark.parametrize("stage", STAGES)
def test_o8_a_curators_model_reads_what_it_was_shown_but_nothing_of_the_learning_state_nor_another_calls_folder(ticked, stage):
    """Through the drain's own path, each curator's read gate allows the file it was shown and refuses the old root and every other call's folder. (O8)"""
    index = STAGES.index(stage)
    probe = ticked.probe
    asked, answers = probe.asked[index], probe.answers(index)
    assert {"legacy", "other-call"} <= set(probe.labels[index]), "the probe found nothing planted to read: the refusal proves nothing"
    assert not answers[0].get("is_error"), f"control: {stage} cannot read the file it was shown ({asked[0]}): {answers[0]}"
    for path, label, answer in zip(asked[1:], probe.labels[index][1:], answers[1:], strict=True):
        assert answer.get("is_error"), f"{stage}: reading {path} ({label}) was not refused: {answer}"
    seen = ticked.wire.calls[index].answers()
    assert LEGACY_CANARY not in seen
    assert OTHER_CALL_CANARY not in seen


@pytest.mark.parametrize("stage", STAGES)
def test_o8_what_a_curators_model_is_shown_of_its_workspace_names_no_host_path_of_the_learning_state_or_a_call_folder(ticked, stage):
    """The system prompt and first user message hold a roots line and no host path of `<T>/learning` or the scratch area. (O8, P7)"""
    conversation = ticked.wire.calls[STAGES.index(stage)]
    shown = conversation.system + conversation.first_user
    assert conversation.roots_line(), "the harness preamble carries no `Workspace roots:` line"
    for hidden in (_tenant_root(ticked.w.t.tenant) / "learning", _scratch(ticked.w.t.tenant)):
        assert str(hidden) not in shown, f"{stage}: the model was shown {hidden}"
    assert "_pending" not in shown, f"{stage}: the model was shown a legacy stage folder"


def test_o8_a_curators_lesson_read_leaves_no_load_row_anywhere(ticked):
    """The curators read a lesson (the control read) and no lessons_loaded row appears: curator loads are not recorded. (A1 decision)"""
    assert list(ticked.w.tmp.rglob("lessons_loaded.jsonl")) == []


# --- O9 and call identity -------------------------------------------------------------------------------------


@pytest.mark.parametrize("stage", STAGES)
def test_o9_every_call_that_reached_the_model_leaves_its_trace_in_the_folder_its_key_names(ticked, stage):
    """The call's drain batch id, stage and ordinal find a folder holding only that call's trace. (O9, P7)"""
    conversation, folder = ticked.wire.calls[STAGES.index(stage)], _folder(ticked, stage)
    assert folder.is_dir(), f"no folder for ({stage}, drain batch {_working(ticked, stage)[0]}, call 1): {folder}"
    assert _working(ticked, stage)[0] in folder.name, f"the folder name does not carry the drain batch id: {folder.name}"
    files = files_below(folder)
    assert files, f"{stage}: the call left no trace in {folder}"
    assert all(p.relative_to(folder).parts[0] == "wire_logs" for p in files), \
        f"{stage}: the call folder holds more than the trace: {[str(p.relative_to(folder)) for p in files]}"
    text = "\n".join(p.read_text(encoding="utf-8") for p in files)
    assert _salt(conversation) in text, f"{stage}: the trace in {folder} is not this call's"
    assert all(_salt(c) not in text for c in ticked.wire.calls if c is not conversation), \
        f"{stage}: the folder holds another call's conversation"


def test_call_identity_the_author_calls_share_the_ticks_batch_and_the_pitfalls_call_has_a_lead_lane_batch_row_in_before_it(ticked):
    """Lessons and questioner are keyed by one author batch row; the pitfalls call by a lead-lane row already working when it ran. (A1 call identity)"""
    lessons, questioner, pitfalls = (_working(ticked, s) for s in STAGES)
    assert lessons == questioner, "the two author-lane calls are not one drain batch"
    assert pitfalls[0] != lessons[0], "the pitfalls call is not keyed by a batch of its own"
    assert pitfalls[1] != lessons[1], "the pitfalls call is not keyed by a lead-lane batch"
    folders = [_folder(ticked, s) for s in STAGES]
    assert len(set(folders)) == 3, folders
    assert all(f.is_dir() for f in folders), folders
    assert _folders().call_folder(ticked.w.t.tenant, lessons[0], "lessons", 2, make=False) != folders[0]


def test_the_call_folder_is_under_the_tenant_scratch_location_and_under_no_learning_root_draft_or_box_mount(ticked):
    """Each call folder is below the scratch location, outside `<T>/learning`, the batch drafts and every mount the drains' boxes were given. (A1, D10)"""
    tenant = ticked.w.t.tenant
    scratch = _scratch(tenant).resolve()
    learning = (_tenant_root(tenant) / "learning").resolve()
    drafts = Path(location_path(tenant.drafts)).resolve()
    mounts = [Path(m.source).resolve() for box in ticked.boxes for r in box.requests for m in r.mounts]
    assert mounts, "the drains' boxes were handed no mounts: the check proves nothing"
    for stage in STAGES:
        folder = _folder(ticked, stage).resolve()
        assert folder.is_relative_to(scratch), (stage, folder, scratch)
        assert not folder.is_relative_to(learning), (stage, folder)
        assert not folder.is_relative_to(drafts), (stage, folder)
        for mount in mounts:
            assert not folder.is_relative_to(mount), (stage, folder, mount)
            assert not mount.is_relative_to(folder), (stage, folder, mount)


def test_the_scratch_location_is_a_registered_tenant_location_that_holds_worktrees_beside_the_call_folders(world):
    """`tenant.scratch` is a #1210 location type served by the records door; `worktrees/` is below it and not under `<T>/learning`. (A1, D10)"""
    from defender.records import formats

    tenant = world.t.tenant
    kind = getattr(formats, type(tenant.scratch).__name__)
    assert isinstance(tenant.scratch, kind)
    scratch = _scratch(tenant).resolve()
    worktrees = Path(location_path(tenant.worktrees)).resolve()
    assert worktrees.is_relative_to(scratch), worktrees
    assert not worktrees.is_relative_to((_tenant_root(tenant) / "learning").resolve()), worktrees
    assert _folders().call_folder(tenant, "b-1278", "lessons", 1, make=False).resolve().is_relative_to(scratch)


# --- O9: kept -------------------------------------------------------------------------------------------------


def test_o9_a_trace_is_kept_after_the_drain_ends_and_through_the_next_drain(world):
    """The first drain's call folders are byte-identical after a second drain over new work. (O9: nothing deletes a trace)"""
    with WireModel() as wire:
        _run(world, wire, tag="a")
        before = {p: p.read_bytes() for p in files_below(_scratch(world.t.tenant))}
        assert before, "the first drain left no call folder"
        _run(world, wire, tag="b")
    after = {p: p.read_bytes() for p in files_below(_scratch(world.t.tenant))}
    assert {p: after.get(p) for p in before} == before, "a trace of the first drain was removed or changed"
    assert len(after) > len(before), "the second drain left no trace of its own"


def test_o9_a_call_whose_model_request_was_refused_still_leaves_its_trace(world):
    """A call that reached the model and failed leaves its trace in its folder after the drain handles the fault. (O9)"""
    with WireModel(fail=400) as wire:
        _run(world, wire)
        assert wire.calls, "the drain never reached the model"
    traces = [p for p in files_below(_scratch(world.t.tenant)) if "wire_logs" in p.parts]
    assert traces, "a call that reached the model and failed left no trace"
    assert all(p.stat().st_size for p in traces)


# --- O10: writes ------------------------------------------------------------------------------------------------


def test_o10_the_drains_write_nothing_under_the_tenants_learning_folder(world):
    """Two ticks that claim, run three curators and end leave `<T>/learning` exactly as it was: no queue, lock, worktree or commit record. (O10, D10)"""
    root = _tenant_root(world.t.tenant) / "learning"

    def tree() -> list[str]:
        return sorted(p.relative_to(root).as_posix() for p in root.rglob("*")) if root.exists() else ["<absent>"]

    before = tree()
    with WireModel() as wire:
        _run(world, wire)
        assert len(wire.calls) == 3, "the ticks did not run the three curators: the observation proves nothing"
    assert tree() == before


# --- the folder key, without a drain ----------------------------------------------------------------------------


def test_the_call_folder_key_is_stable_and_every_part_of_it_separates_folders(world):
    """The same (tenant, batch, stage, ordinal) names one folder; changing the batch, stage or ordinal names another. (A1 call identity)"""
    tenant, key = world.t.tenant, _folders().call_folder
    base = key(tenant, "b-1278", "lessons", 1, make=True)
    assert base.is_dir()
    assert key(tenant, "b-1278", "lessons", 1, make=False) == base
    others = {key(tenant, "b-1279", "lessons", 1, make=False), key(tenant, "b-1278", "questioner", 1, make=False),
              key(tenant, "b-1278", "lessons", 2, make=False)}
    assert base not in others
    assert len(others) == 3


@pytest.mark.parametrize("shape", ["symlink", "file"])
def test_a_planted_entry_where_a_call_folder_goes_is_refused(world, tmp_path, shape):
    """Making a call folder over a planted link or file raises and creates nothing through the link (moved from #1135's `stage_dir` lane-folder case; A1)"""
    tenant, key = world.t.tenant, _folders().call_folder
    at = key(tenant, "b-1278", "lessons", 1, make=False)
    outside = tmp_path / "outside-call-folder"
    outside.mkdir()
    at.parent.mkdir(parents=True, exist_ok=True)
    if shape == "symlink":
        at.symlink_to(outside, target_is_directory=True)
    else:
        at.write_text("not a folder\n", encoding="utf-8")
    with pytest.raises(Exception):  # noqa: B017, PT011 — which error is the implementation's; that it refuses is the contract
        key(tenant, "b-1278", "lessons", 1, make=True)
    assert list(outside.iterdir()) == [], "something was created through the link"
