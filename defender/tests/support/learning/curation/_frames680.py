"""Shared harness for the #680 stage-frame tests: real prompt producers and bound tool scenes."""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath

from defender.agents import (
    CORPUS_AUTHOR_DEF,
    LEAD_AUTHOR_DEF,
    MAIN_DEF,
)
from defender.learning.author import shared as author_shared
from defender.learning.author.curator_engine import CuratorDeps
from defender.learning.core.config import LoopPaths
from defender.learning.leads import lead_author, pitfalls_curator
from defender.investigation.agent_definition import RunScope, bind
from defender.box import BoxResult
from defender.investigation.tools import _tool_bash, _tool_read_file
from defender.tests.support.runtime.state._1255_view import model_path
from defender.tests.support.learning.curation._curator1134 import corpus_view, open_state
from defender.tests.support.shared.contracts._repo import seed_adapter_stubs


SALT_RE = re.compile(r"<run-([0-9a-f]+)-([^>]+)>\n(.*?)\n</run-\1-\2>", re.DOTALL)
ROOT = Path(__file__).resolve().parents[5]
DEFENDER = ROOT / "defender"
STAGE_SALT = "5a" * 16
RUN_SALT = "c3" * 16
FRAME_RE = re.compile(
    r"<run-(?P<salt>[0-9a-f]+)-(?P<tag>[^>\n]+)>\n"
    r"(?P<body>.*?)\n</run-(?P=salt)-(?P=tag)>",
    re.DOTALL,
)


class Box:
    def __init__(self, result: BoxResult | Exception):
        self.result = result
        self.calls = []

    def run_parsed(self, pipelines, *, command, cwd, timeout):
        self.calls.append((pipelines, command, cwd, timeout))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _shared_module():
    import defender._untrusted as untrusted

    return untrusted


def _frames(prompt: str):
    return list(SALT_RE.finditer(prompt))


@dataclass(frozen=True)
class PromptObservation:
    producer: str
    prompt: str
    expected_tags: tuple[str, ...]
    required_bodies: tuple[str, ...]
    salt: str


def _shape(observation: PromptObservation):
    """Return raw model-seam observations; tests own all policy assertions."""
    matches = _frames(observation.prompt)
    tags = tuple(m.group(2) for m in matches)
    bodies = tuple(m.group(3) for m in matches)
    salts = tuple(m.group(1) for m in matches)
    gaps: list[str] = []
    cursor = 0
    for match in matches:
        gaps.append(observation.prompt[cursor : match.start()])
        cursor = match.end()
    gaps.append(observation.prompt[cursor:])
    return tags, bodies, salts, tuple(gaps)


def _assert_frame_envelope(observation: PromptObservation, tags, salts, gaps) -> None:
    """The three properties every frame set has; each assert carries its own message, so a
    failure names the invariant that broke."""
    assert tags == observation.expected_tags, (
        f"{observation.producer}: framed sections are {tags}, expected "
        f"{observation.expected_tags}"
    )
    assert salts == (observation.salt,) * len(observation.expected_tags), (
        f"{observation.producer}: a frame carries a salt that is not {observation.salt!r} "
        f"— got {salts}"
    )
    assert all(not gap.strip() for gap in gaps), (
        f"{observation.producer}: unframed text sits between the frames — "
        f"{[g for g in gaps if g.strip()]}"
    )


def assert_producer_shape(observation: PromptObservation) -> None:
    """A real producer emitted its ordered frames with every template slot substituted: a
    surviving `{salt}`/`{content}` means the template itself shipped, and a frame salted with
    the literal `{salt}` confines nothing while still looking framed.
    """
    tags, bodies, salts, gaps = _shape(observation)
    _assert_frame_envelope(observation, tags, salts, gaps)
    for required in observation.required_bodies:
        assert any(required in body for body in bodies), (
            f"{observation.producer}: required content {required!r} is in no frame body"
        )
    assert "{salt}" not in observation.prompt, (
        f"{observation.producer}: an unsubstituted {{salt}} reached the model"
    )
    assert "{content}" not in observation.prompt, (
        f"{observation.producer}: an unsubstituted {{content}} reached the model"
    )


def _curator_prompt(tmp_path: Path, *, hostile="ROW-BODY", rows=None, salt="5a" * 16):
    rows = [{"lesson": hostile}] if rows is None else rows
    prompt = author_shared.build_curator_user_prompt(
        rows,
        "batch",
        corpus=corpus_view(tmp_path),
        corpus_dir=tmp_path,
        corpus_dir_rel="lessons",
        label="rows",
        salt=salt,
    )
    return PromptObservation(
        "build_curator_user_prompt",
        prompt,
        ("reader_contract", "curator_context", "corpus_manifest", "lesson_rows"),
        (hostile,),
        salt,
    )


def _capture_spawn(call, *, salt: str):
    captured = {}

    def fake(**kwargs):
        captured.update(kwargs)
        return 0

    call(spawn=fake, salt=salt)
    return captured["user_prompt"], captured["salt"]


def _lead_author_prompt(
    tmp_path: Path, _monkeypatch, *, hostile="HANDOFF-BODY", salt="5a" * 16
):
    run = tmp_path / "run"
    run.mkdir(parents=True)

    def call(*, spawn, salt):
        return lead_author.invoke_agent(
            run,
            [{"goal": hostile}],
            repo_root=tmp_path,
            spawn=spawn,
            salt=salt,
        )

    prompt, actual_salt = _capture_spawn(call, salt=salt)
    return PromptObservation(
        "lead_author.invoke_agent",
        prompt,
        ("reader_contract", "lead_author_context", "handoffs", "pending_system_drafts"),
        (hostile,),
        actual_salt,
    )


def _pitfalls_prompt(
    tmp_path: Path, _monkeypatch, *, hostile="PITFALL-BODY", salt="5a" * 16
):
    def call(*, spawn, salt):
        return pitfalls_curator._invoke_pitfalls_agent(
            [{"system": "test", "stderr_digest": hostile}],
            state=open_state(LoopPaths(repo_root=tmp_path, state_dir=tmp_path / "state")),
            repo_root=tmp_path,
            spawn=spawn,
            salt=salt,
        )

    prompt, actual_salt = _capture_spawn(call, salt=salt)
    return PromptObservation(
        "_invoke_pitfalls_agent",
        prompt,
        ("reader_contract", "pitfalls_context", "pitfalls_handoffs"),
        (hostile,),
        actual_salt,
    )


def _all_prompt_observations(
    tmp_path: Path, monkeypatch, hostile: str, *, salt="5a" * 16
):
    """Drive every bound real producer; no assertions are shared across owners."""
    return (
        _curator_prompt(tmp_path / "curator", hostile=hostile, salt=salt),
        _lead_author_prompt(
            tmp_path / "lead-author", monkeypatch, hostile=hostile, salt=salt
        ),
        _pitfalls_prompt(
            tmp_path / "pitfalls", monkeypatch, hostile=hostile, salt=salt
        ),
    )


def _deps(tmp_path: Path, definition, *, box=None):
    run = tmp_path / "run"
    dfn = tmp_path / "tree" / "defender"
    run.mkdir(parents=True)
    dfn.mkdir(parents=True)
    return bind(definition, run, defender_dir=dfn, box=box)




def _lead_author_deps_scene(tmp_path: Path, result: BoxResult):
    repo = tmp_path / "tree"
    defender_dir = repo / "defender"
    skills = defender_dir / "skills"
    run = tmp_path / "run"
    skills.mkdir(parents=True)
    run.mkdir(parents=True)
    # `system` must be a declared system (#772): the rm grant is compiled per system the tree
    # has an adapter for, not over an anonymous `<name>/_draft/` shape.
    seed_adapter_stubs(defender_dir, ("system",))
    deps = bind(LEAD_AUTHOR_DEF, run, defender_dir=defender_dir, box=Box(result))
    return deps, skills, "rm defender/skills/system/_draft/lesson.md"


def _lead_author_draft_scene(tmp_path: Path, result: BoxResult):
    """A real LEAD_AUTHOR binding over a batch draft's agent root (`RunScope(tenant_agent=)`),
    where the lane writes `<draft>/agent/skills/`. Returns `(deps, the draft's skills dir, an
    admitted rm)`: the rm targets the draft, not the product tree `_lead_author_deps_scene`
    spells."""
    defender_dir = tmp_path / "tree" / "defender"
    agent = tmp_path / "draft" / "agent"
    skills = agent / "skills"
    run = tmp_path / "run"
    (skills / "system").mkdir(parents=True)
    run.mkdir(parents=True)
    # As above: `system` must be a system the product has an adapter for (#772).
    seed_adapter_stubs(defender_dir, ("system",))
    deps = bind(LEAD_AUTHOR_DEF, run, defender_dir=defender_dir, box=Box(result),
                scope=RunScope(tenant_agent=agent))
    target = deps.view.to_model(skills / "system" / "_draft" / "lesson.md")
    return deps, skills, f"rm {target}"


def _learning_read_deps(tmp_path: Path, *, box=None):
    """A bound corpus-author scene with a real cross-stage add-dir, for `_drive_learning_read`
    and `_drive_learning_bash`: the corpus author is the learning role holding both
    `read_file` and `bash`. Returns `(deps, add_dir)`.
    """
    add_dir = tmp_path / "cross-stage"
    add_dir.mkdir(parents=True, exist_ok=True)
    run = tmp_path / "deps" / "run"
    dfn = tmp_path / "deps" / "tree" / "defender"
    run.mkdir(parents=True, exist_ok=True)
    (dfn / "lessons").mkdir(parents=True, exist_ok=True)
    # `bind` refuses this role without `corpus_name` (its corpus is per-spawn); spelled here so
    # `_deps` stays role-agnostic.
    deps = bind(
        CORPUS_AUTHOR_DEF, run, defender_dir=dfn,
        scope=RunScope(
            add_dirs=(add_dir,), corpus_name="lessons",
            model_roots=((PurePosixPath("/inputs/shared"), add_dir),),
            # `bind` rejects an empty confine for this role: it would widen reads to the whole
            # defender dir (#512). The curated corpus is the confine production gives it.
            read_confine=(dfn / "lessons",),
        ), box=box,
    )
    return deps, add_dir


def _corpus_author_deps_scene(tmp_path: Path, result: BoxResult):
    repo = tmp_path / "tree"
    corpus = repo / "defender" / "lessons"
    run = tmp_path / "run"
    corpus.mkdir(parents=True)
    run.mkdir(parents=True)
    deps = CuratorDeps.for_run(
        run,
        repo,
        corpus,
        box=None,
    )
    deps = replace(deps, box=Box(result))
    assert deps.role is CORPUS_AUTHOR_DEF.role
    return deps, corpus, f"cat {deps.view.to_model(corpus / 'lesson.md')}"




def _main_bash(tmp_path, payload):
    fake = Box(BoxResult(0, payload, b""))
    deps = _deps(tmp_path, MAIN_DEF, box=fake)
    artifact = deps.run_dir / "report.md"
    artifact.write_text("admitted main read")
    # MAIN's deps from `bind` carry the model view, so the operand is the path the model holds
    # (`/runs/current/report.md`); the host path is refused (#1255).
    return _tool_bash(deps, f"cat {model_path(artifact, run_dir=deps.run_dir)}")


# Frame primitives


def _expected_frame(body: str, tag: str, salt: str = STAGE_SALT) -> str:
    return f"<run-{salt}-{tag}>\n{body}\n</run-{salt}-{tag}>"


def frame_salt_of(text: str, tag: str = "untrusted") -> str:
    """The salt of the first `tag` frame in `text`, read rather than predicted: `wrap_fresh`
    (#875) mints a tool-return frame's salt after the content is in hand, so no caller can know
    it. Prompt-section frames still share one caller-owned salt (`_expected_frame`)."""
    m = re.search(rf"<run-([0-9a-f]+)-{re.escape(tag)}>", text)
    assert m is not None, f"no <run-…-{tag}> frame in: {text[:400]!r}"
    return m.group(1)


def assert_one_frame(text: str, body: str, tag: str = "untrusted") -> str:
    """`text` is exactly one `tag` frame around `body`, verbatim, with nothing outside it:
    `_expected_frame` for a tool return, whose salt is fresh. Returns the salt."""
    salt = frame_salt_of(text, tag)
    assert text == f"<run-{salt}-{tag}>\n{body}\n</run-{salt}-{tag}>", (
        f"not exactly one verbatim {tag} frame:\n{text[:600]!r}"
    )
    return salt


def _drive_frame(body: str, tag: str = "payload", salt: str = STAGE_SALT) -> str:
    """Drive the primitive without asserting policy on behalf of a test owner."""
    return _shared_module().wrap(body, tag, salt)


@dataclass(frozen=True)
class BashResultSpec:
    rc: int = 0
    out: bytes = b""
    err: bytes = b""


class RecordingBox:
    """Data-driven expensive-boundary fake; it records the real tool's request."""

    def __init__(self, result: BashResultSpec):
        self.result = result
        self.calls: list[dict] = []

    def run_parsed(
        self, pipelines, *, command: str, cwd: Path, timeout: float
    ) -> BoxResult:
        self.calls.append(
            {"pipelines": pipelines, "command": command, "cwd": cwd, "timeout": timeout}
        )
        return BoxResult(self.result.rc, self.result.out, self.result.err)




def _drive_learning_read(
    tmp_path: Path, body: str, *, name: str = "lead.md", in_run_dir: bool = False
) -> str:
    """One learning-stage `read_file`, through the real tool."""
    deps, comparison = _learning_read_deps(tmp_path)
    artifact = (deps.run_dir if in_run_dir else comparison) / name
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(body, encoding="utf-8")
    return _tool_read_file(deps, deps.view.to_model(artifact))


def _drive_learning_bash(
    tmp_path: Path, *, stdout: bytes = b"", stderr: bytes = b"", rc: int = 0
) -> str:
    fake = RecordingBox(BashResultSpec(rc=rc, out=stdout, err=stderr))
    deps, _add_dir = _learning_read_deps(tmp_path, box=fake)
    # Inside the corpus: the curator's `cat` grant reaches only there, and a refused command
    # never reaches the framing under test.
    artifact = deps.corpus_dir / "lead.md"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("the executor boundary is injected", encoding="utf-8")
    command = f"cat {deps.view.to_model(artifact)}"
    return _tool_bash(deps, command)


