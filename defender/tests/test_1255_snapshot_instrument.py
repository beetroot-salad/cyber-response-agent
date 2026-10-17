"""#1255 slice A — the instrument adds nothing (P4) and arm-only facts live outside the box (P3).

Design rev 4: "Continuation prompt gone from BranchSpec, family manifest and branch CLI" (D1,
P4); "`provenance.json` (world id, parent run, fork turn) moves out of the run folder into the
episode's host-side record. The handbook page that explains branching
(`skills/handbook/content/learning-loop.md`) leaves the investigator's read scope" (P3).

The BranchSpec half of the first sentence is `test_920_branch_seam::
test_branch_spec_carries_no_continuation_prompt`; the CLI half is `test_947_branch_cli`. This
file holds the manifest half, the arm's run-folder stamp, and the read scope.

Entry surfaces: the manifest's own parser (`_family.parse_family`, what `load_family` runs),
the sibling's real entry point `run.main(--episode … --world …)` with the lifecycle recorded
(the stamp is written before any investigation starts, so no driver is needed to observe it),
and a driven natural run whose MAIN and gather models ask the gate for the page.
"""
from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Any

import pytest

from defender import _provenance
from defender.run_repository import RunPaths
from defender.tests import _triplet_947 as T

LEARNING_LOOP_PAGE = "skills/handbook/content/learning-loop.md"
#: The branching page by more than one spelling of its path (contract-repair finding F-P3a):
#: P3 takes the PAGE out of read scope, not one string — a gate that refuses an operand by its
#: unresolved spelling passed a probe that asked only by the canonical one. Each `..` climb
#: below names the same file under the checkout.
PAGE_SPELLINGS = (LEARNING_LOOP_PAGE,
                  "skills/handbook/content/../content/learning-loop.md",
                  "skills/handbook/../handbook/content/learning-loop.md")
#: A neighbouring handbook page in the same folder: the positive control for the refusal —
#: the read scope must lose ONE page, not the handbook.
CONTROL_PAGE = "skills/handbook/content/runtime-loop.md"


# --------------------------------------------------------------------------------------
# P4: the family manifest carries no continuation prompt.
# --------------------------------------------------------------------------------------


def test_p4_the_family_manifest_declares_no_continuation_prompt():
    """P4/D1: the loaded `Family` has no `continuation_prompt` — there is nothing for an arm to
    be told on arrival, so nothing in the manifest to carry it. Positive control: the fields
    the arm IS launched from (source run, branch point, T0) are still declared."""
    family = T.sym("runtime.branch._family", "Family")
    names = {f.name for f in dataclasses.fields(family)}
    assert {"source_run_id", "branch_message_id", "as_of"} <= names, names
    assert "continuation_prompt" not in names, (
        "the family manifest still declares the operator's continuation prompt (P4: the arm "
        "resumes with no user message)")


def test_p4_a_manifest_without_a_continuation_prompt_loads():
    """P4/D1: a manifest that carries no `continuation_prompt` is a complete manifest — the
    parser `load_family` runs accepts it. Today the parser refuses it ("must be a non-empty
    string"), which is the reversed rule."""
    parse = T.sym("runtime.branch._family", "parse_family")
    doc = T.family_doc()
    doc.pop("continuation_prompt", None)

    family = parse(doc)

    assert family.branch_message_id == T.BRANCH_MESSAGE_ID
    assert [w.world_id for w in family.worlds] == list(T.WORLDS)


# --------------------------------------------------------------------------------------
# P3: no lineage in the arm's run folder.
# --------------------------------------------------------------------------------------


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
    """`run.main --tenant T --episode <id> --world <world>` over the fixture episode, lifecycle
    recorded. Returns `(arm run folder, episode dir, the source's runs base)`."""
    from defender import _tenant

    base, src = T.runs_base(tmp_path)
    ep = T.episode(tmp_path, doc=T.family_doc(source_run_dir=str(src)),
                   root=tmp_path / "episodes-root")
    (ep / "runs").mkdir(exist_ok=True)
    _tenant.ensure_runs_base_record(ep / "runs", T.SOURCE_TENANT)
    lifecycle = _Lifecycle()
    rc = T.mod("run").main(
        ["--tenant", T.SOURCE_TENANT, "--episode", ep.name, "--world", world],
        lifecycle=lifecycle, visualize=lambda *_a, **_k: None,
        preflight=lambda *_a, **_k: 0)
    assert rc == 0 and lifecycle.run_dir is not None, f"the arm never reached its lifecycle (rc={rc})"
    return lifecycle.run_dir, ep, base


@pytest.mark.usefixtures("_tmp_roots")
@pytest.mark.parametrize("world", ["a", "b"])
def test_p3_an_arms_run_folder_carries_no_lineage(tmp_path, world):
    """P3/O2: the arm's run folder — the box's mount — holds no arm-only fact. Its stamp
    names no parent run and no fork turn and is not stamped with the arm's world token, and no
    file in the folder carries that token. The control world (`a`) and a counterfactual one
    (`b`) alike.

    The stamp's world id is the design's too ("`provenance.json` (world id, parent run, fork
    turn) moves out of the run folder"): an arm's stamp, where it keeps one, carries no world
    id, or the one a NATURAL run of its tenant is stamped with (the tenant's base world) — the
    natural shape. A world id that merely avoids spelling the episode token (contract-repair
    finding F-P3b: the lineage base64-encoded into `world_id`) is neither.

    And "no file carries the lineage" is held by STRUCTURE, then under ENCODING. The folder
    holds only a run's records, by name (`_1255_run_records.assert_only_run_records`: the
    layout's named records, each table row's lead claim, summary and own payload — no
    `wire_logs/*` or other wildcard; positive control: it flags planted records), since a
    lineage record under a name of its own passed an encoded scan zlib-compressed
    (contract-repair finding F2-P3b: `wire_logs/lineage.jsonl`). And each of the arm's lineage
    identities (world token, episode token, episode id) is also looked for as a derived form
    and inside every base64/hex run of every file, decoded and, where compressed, inflated
    (`_1255_identity.encoded_hits`; positive control: it finds the world token in an encoded
    lineage record, plain and zlib-compressed).

    The lineage is not lost, it is host-side: the episode's own record still names the source
    run and the branch point (the positive control — the facts exist, just not in the box)."""
    import base64
    import json
    import zlib

    from defender.tests import _1255_identity as IDN
    from defender.tests import _1255_run_records as RR

    arm, ep, base = _launch_arm(tmp_path, world)
    token = T.world_token(world)
    natural_world = T.mod("_tenant").read_tenant(base).base_world_id

    stamp = _provenance.read(RunPaths(arm).provenance)
    if stamp is not None:
        assert getattr(stamp, "parent_run_id", None) is None, (
            f"the arm's stamp names its parent run {stamp.parent_run_id!r} inside the box")
        assert getattr(stamp, "fork_turn", None) is None, (
            f"the arm's stamp names its fork turn {stamp.fork_turn!r} inside the box")
        assert T.EPISODE_TOKEN not in str(getattr(stamp, "world_id", None) or ""), (
            f"the arm's stamp names its episode's world {stamp.world_id!r} inside the box")
        assert getattr(stamp, "world_id", None) in (None, natural_world), (
            f"the arm's stamp carries a world id {stamp.world_id!r} that is neither absent nor "
            f"a natural run's ({natural_world!r}) — the world id moves out of the run folder")
    RR.assert_only_run_records(arm, f"world {world}'s arm", RR.table_rows(arm))
    lineage = {"world token": token, "episode token": T.EPISODE_TOKEN, "episode id": ep.name}
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
    assert T.SOURCE_RUN_ID in record and str(T.BRANCH_MESSAGE_ID) in record, (
        "the episode's host-side record no longer names the source run and branch point")


# --------------------------------------------------------------------------------------
# P3: the page explaining branching is outside the investigator's read scope.
# --------------------------------------------------------------------------------------


def _checkout_as_shown(first_request: str) -> str:
    """The checkout path as the model is shown it.

    The model view (slice B, P1) fixes the checkout at `/defender` and the run folder at
    `/runs/current`; before it lands, the model is shown host paths. Which world this run is in
    is read off the opening prompt's own `run_dir:` coordinate, so the probe below asks for the
    page by the path the MODEL would use either way — a host path handed to a run under the
    model view is refused for a different reason and would make the refusal arm vacuous."""
    from defender.tests.e2e._replay_harness import DEFENDER

    for line in first_request.splitlines():
        if line.startswith("run_dir:"):
            return "/defender" if line.split(":", 1)[1].strip().startswith("/runs/") else str(DEFENDER)
    raise AssertionError("the opening prompt names no run_dir coordinate")


class _PageReader:
    """A scripted model that reads the branching page by each of `PAGE_SPELLINGS`, then the
    control page, then stops — by the checkout path the model is shown (`shown()`: the request
    text that shows it; by default this model's own first request). Keeps every request so each
    answer can be inspected."""

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
    """P3 (G11 reversed): MAIN's request to read `learning-loop.md` — by `read_file`, or by the
    granted `cat`, and by each of `PAGE_SPELLINGS` (the canonical path and two `..` climbs that
    name the same file) — is refused by the gate; the same request for a neighbouring handbook
    page is answered with its content (the positive control: the refusal is about the page)."""
    pytest.importorskip("pydantic_ai")
    from defender.tests import _1255_snapshot as S

    reader = _PageReader(tool=tool)
    S.drive_source(tmp_path, (), main=reader)

    _assert_page_refused(reader, f"MAIN (through {tool})")


@pytest.mark.e2e
def test_p3_a_gather_lead_cannot_read_the_page_that_explains_branching(tmp_path):
    """P3: the gather role is an investigator too — a lead's `read_file` of `learning-loop.md`,
    by each of `PAGE_SPELLINGS`, is refused, while the neighbouring page reads (positive
    control). The lead reads by the checkout path MAIN's opening shows (a lead's own prompt
    names none)."""
    pytest.importorskip("pydantic_ai")
    from defender.tests import _1255_snapshot as S

    main = S.Recorder([S.dispatch("l-001"), S.done()])
    lead = _PageReader(tool="read_file", shown=lambda: main.seen[0])

    S.drive_source(tmp_path, (), main=main, leads={"l-001": lead})

    _assert_page_refused(lead, "a gather lead")
