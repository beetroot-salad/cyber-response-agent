"""Fork lineage stays host-side and model-visible run records stay neutral."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import dataclasses
from pathlib import Path
from typing import Any

import pytest

from defender.records import _provenance
from defender.records import RunPaths
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.tenancy._launch_publish_p4 import RunWithPublish

LEARNING_LOOP_PAGE = "skills/handbook/content/learning-loop.md"
PAGE_SPELLINGS = (LEARNING_LOOP_PAGE,
                  "skills/handbook/content/../content/learning-loop.md",
                  "skills/handbook/../handbook/content/learning-loop.md")
CONTROL_PAGE = "skills/handbook/content/runtime-loop.md"


def test_p4_the_family_manifest_declares_no_continuation_prompt():
    family = T.sym("episodes._family", "Family")
    names = {f.name for f in dataclasses.fields(family)}
    assert {"source_run_id", "branch_message_id", "as_of"} <= names, names
    assert "continuation_prompt" not in names, (
        "the family manifest still declares the operator's continuation prompt (P4: the arm "
        "resumes with no user message)")


def test_p4_a_manifest_without_a_continuation_prompt_loads():
    parse = T.sym("episodes._family", "parse_family")
    doc = T.family_doc()
    doc.pop("continuation_prompt", None)

    family = parse(doc)

    assert family.branch_message_id == T.BRANCH_MESSAGE_ID
    assert [w.label for w in family.worlds] == list(T.WORLDS)


@pytest.fixture
def _tmp_roots(tmp_path, monkeypatch):
    """Both configured roots inside `tmp_path` (as `test_947_triplet_sibling`)."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))


class _Lifecycle:
    """The lifecycle seam as a recorder: it keeps the arm's run folder and runs nothing."""

    def __init__(self) -> None:
        self.run_dir: Path | None = None

    def __call__(self, **kw: Any) -> dict:
        self.run_dir = kw["run"].run_dir
        return {"output": "done", "requests": 1, "truncated_by": None}


def _launch_arm(tmp_path: Path, world: str) -> tuple[Path, Path, Path]:
    """`run.main --tenant T --episode <id> --world <world>` over the fixture episode, lifecycle recorded."""
    base, src = location_path(T.runs_base)(tmp_path)
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src)))
    T.plant_roster(ep)
    lifecycle = _Lifecycle()
    # #1108 P4 (OD14, O11): run.main handed the in-process launch-time publish.
    rc = RunWithPublish(T.mod("run")).main(
        ["--tenant", T.SOURCE_TENANT, "--episode", ep.name, "--world", world],
        lifecycle=lifecycle, visualize=lambda *_a, **_k: None,
        preflight=lambda *_a, **_k: 0)
    assert rc == 0, f"the arm never reached its lifecycle (rc={rc})"
    assert lifecycle.run_dir is not None, f"the arm never reached its lifecycle (rc={rc})"
    return lifecycle.run_dir, ep, base


@pytest.mark.usefixtures("_tmp_roots")
@pytest.mark.parametrize("world", ["a", "b"])
def test_p3_an_arms_run_folder_carries_no_lineage(tmp_path, world):
    import base64
    import json
    import zlib

    from defender.tests.support.runtime.state import _1255_identity as IDN
    from defender.tests.support.runtime.state import _1255_run_records as RR

    arm, ep, base = _launch_arm(tmp_path, world)
    token = T.world_id(ep, world)

    stamp = _provenance.read(RunPaths(arm).provenance)
    if stamp is not None:
        assert stamp.parent_run_id is None, (
            f"the arm's stamp names its parent run {stamp.parent_run_id!r} inside the box")
        assert stamp.fork_turn is None, (
            f"the arm's stamp names its fork turn {stamp.fork_turn!r} inside the box")
        assert stamp.world_id is None, (
            f"the arm's stamp carries a world id {stamp.world_id!r} inside the box")
    RR.assert_only_run_records(arm, f"world {world}'s arm", RR.table_rows(arm))
    lineage = {"world id": token, "episode id": ep.name, "source run id": T.SOURCE_RUN_ID}
    record = json.dumps([token, T.SOURCE_RUN_ID]).encode()
    for how, raw in (("plain", record), ("zlib", zlib.compress(record))):
        planted = base64.b64encode(raw).decode("ascii")
        assert IDN.encoded_hits(f"w-{planted}", lineage), (
            f"positive control: the encoded scan does not find a base64-encoded lineage record "
            f"({how})")
    files = [(str(p.relative_to(arm)), p.read_bytes()) for p in sorted(arm.rglob("*"))
             if p.is_file()]
    assert files, "fixture: the arm's run folder holds no file to scan"
    carriers = IDN.files_carrying(files, lineage)
    assert carriers == {}, f"the arm's run folder carries its lineage in {carriers}"

    record = (ep / "family.yaml").read_text(encoding="utf-8")
    assert T.SOURCE_RUN_ID in record, "the episode's host-side record no longer names the source run and branch point"
    assert str(T.BRANCH_MESSAGE_ID) in record, "the episode's host-side record no longer names the source run and branch point"


def _checkout_as_shown(first_request: str) -> str:
    """The checkout path as the model is shown it."""
    from defender.tests.e2e._replay_harness import DEFENDER

    for line in first_request.splitlines():
        if line.startswith("run_dir:"):
            return "/defender" if line.split(":", 1)[1].strip().startswith("/runs/") else str(DEFENDER)
    raise AssertionError("the opening prompt names no run_dir coordinate")


class _PageReader:
    """Model that reads requested pages using the checkout path shown in its prompt."""

    __name__ = "PageReader"

    def __init__(self, *, tool: str = "read_file", shown: Any = None) -> None:
        self.tool = tool
        self._shown = shown
        self.calls = 0
        self.seen: list[str] = []
        self.requests: list[list[Any]] = []
        self.pages = [*PAGE_SPELLINGS, CONTROL_PAGE]

    def __call__(self, messages, info):
        from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart

        from defender.tests.e2e._replay_harness import messages_text

        self.requests.append(list(messages))
        self.seen.append(messages_text(messages))
        self.calls += 1
        if self.calls > len(self.pages):
            return ModelResponse(parts=[TextPart(content="Read what I could.")])
        checkout = _checkout_as_shown(self._shown() if self._shown is not None else self.seen[0])
        path = f"{checkout}/{self.pages[self.calls - 1]}"
        args = {"path": path} if self.tool == "read_file" else {"command": f"cat {path}"}
        return ModelResponse(parts=[ToolCallPart(tool_name=self.tool, args=args)])

    def answer(self, n: int) -> list[Any]:
        """The parts answering the `n`-th call (1-based): the tail of request `n+1`."""
        return list(self.requests[n][-1].parts)


def _refused(parts: list[Any]) -> bool:
    from pydantic_ai.messages import RetryPromptPart

    return any(isinstance(p, RetryPromptPart) for p in parts)


def _content(parts: list[Any]) -> str:
    return "\n".join(str(getattr(p, "content", "")) for p in parts)


def _first_line(page: str) -> str:
    from defender.tests.e2e._replay_harness import DEFENDER

    return (DEFENDER / page).read_text(encoding="utf-8").strip().splitlines()[0]


def _assert_page_refused(reader: _PageReader, who: str) -> None:
    control = len(PAGE_SPELLINGS) + 1
    assert reader.calls >= control + 1, f"{who} never got its answers"
    unreachable = (f"{who} could not read the neighbouring handbook page either — the probe is "
                   f"not reaching the gate: {_content(reader.answer(control))[:200]!r}")
    assert not _refused(reader.answer(control)), unreachable
    assert _first_line(CONTROL_PAGE) in _content(reader.answer(control)), unreachable
    for n, spelling in enumerate(PAGE_SPELLINGS, start=1):
        answer = reader.answer(n)
        assert _first_line(LEARNING_LOOP_PAGE) not in _content(answer), (
            f"{who} read the page that explains branching as {spelling!r}: "
            f"{_content(answer)[:200]!r}")
        assert _refused(answer) or "denied" in _content(answer).lower(), (
            f"{who}'s read of the page that explains branching as {spelling!r} was not refused: "
            f"{_content(answer)[:200]!r}")


@pytest.mark.e2e
@pytest.mark.parametrize("tool", ["read_file", "bash"])
def test_p3_main_cannot_read_the_page_that_explains_branching(tmp_path, tool):
    pytest.importorskip("pydantic_ai")
    from defender.tests.support.runtime.state import _1255_snapshot as S

    reader = _PageReader(tool=tool)
    S.drive_source(tmp_path, (), main=reader)

    _assert_page_refused(reader, f"MAIN (through {tool})")


@pytest.mark.e2e
def test_p3_a_gather_lead_cannot_read_the_page_that_explains_branching(tmp_path):
    pytest.importorskip("pydantic_ai")
    from defender.tests.support.runtime.state import _1255_snapshot as S

    main = S.Recorder([S.dispatch("l-001"), S.done()])
    lead = _PageReader(tool="read_file", shown=lambda: main.seen[0])

    S.drive_source(tmp_path, (), main=main, leads={"l-001": lead})

    _assert_page_refused(lead, "a gather lead")
