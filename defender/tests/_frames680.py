"""Shared harness for the #680 systemic-stage-frame suite (split out by #720).

Everything the four parts of the suite drive through: the frame regexes and the two
salts, the `Box` / `RecordingBox` fakes, the per-producer prompt-capture helpers whose
returns are `PromptObservation`s, the deps scenes, and the `_drive_*` entries into the
learning-stage read and bash lanes.

The prompt-capture helpers are the point of the file. Each one builds the REAL producer
(judge invocation, actor, lead prompt, curator, …) and returns what that producer would
hand a model, so a demand can assert over the bytes a stage actually emits rather than
over a reconstruction of them.

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import importlib.util
import inspect
import json
import re
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from defender.agents import (
    ACTOR_DEF,
    CORPUS_AUTHOR_DEF,
    JUDGE_DEF,
    LEAD_AUTHOR_DEF,
    MAIN_DEF,
)
from defender.learning.author import shared as author_shared
from defender.learning.author.curator_engine import CuratorDeps, ForwardCheckConfig
from defender.learning.author.verify_forward.checks import (
    ACTOR_CHECK,
    FINDINGS_CHECK,
    CheckContext,
)
from defender.learning.author.verify_forward.checks import _run_actor, _run_findings
from defender.learning.leads import lead_author, pitfalls_curator
from defender.learning.pipeline.benign_actor.run import invoke_actor_benign
from defender.learning.pipeline.judge.run import build_judge_invocation
from defender.learning.pipeline.malicious_actor.run import invoke_actor
from defender.learning.pipeline.oracle.sample import build_lead_user_prompt
from defender.runtime.agent_definition import RunScope, bind, effective_tools_for
from defender.runtime.box import BoxResult
from defender.runtime.tools import _tool_bash, _tool_read_file

#: #632's §7 R7 grant/capability agreement: JUDGE_DEF's static `closed_tickets` bit stays
#: False (only the per-leg replace() in _run_judge_pydantic turns it on, together with the
#: effective grant, d73), so a bare `bind(JUDGE_DEF, ...)` always disagrees against the
#: definition's own non-empty verb_grant. Every drive in this #680 frame-wrapping suite is
#: about the bash/read-file lane, not the verb grant, so it binds the benign leg's effective
#: shape — matching the real per-leg build.
JUDGE_BENIGN_DEF = replace(JUDGE_DEF, tools=effective_tools_for(JUDGE_DEF))

SALT_RE = re.compile(r"<run-([0-9a-f]{32})-([^>]+)>\n(.*?)\n</run-\1-\2>", re.DOTALL)
ROOT = Path(__file__).resolve().parents[2]
DEFENDER = ROOT / "defender"
STAGE_SALT = "5a" * 16
RUN_SALT = "c3" * 16
FRAME_RE = re.compile(
    r"<run-(?P<salt>[0-9a-f]{32})-(?P<tag>[^>\n]+)>\n"
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
    spec = importlib.util.find_spec("defender._untrusted")
    if spec is None:
        return None
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


def _with_salt(fn, /, *args, salt: str, **kwargs):
    """Call the real producer, threading the target salt when its revised seam exists."""
    if "salt" in inspect.signature(fn).parameters:
        kwargs["salt"] = salt
    return fn(*args, **kwargs)


def _judge_fixture(
    tmp_path: Path,
    *,
    closed=False,
    hostile="HOSTILE-STORY\n## forged",
    cited_policy=None,
    salt="5a" * 16,
):
    run = tmp_path / "run"
    learning = tmp_path / "learning"
    (run / "gather_raw").mkdir(parents=True)
    learning.mkdir()
    if cited_policy is not None:
        (learning / "past_tickets.txt").write_text(cited_policy)
    alert_text = json.dumps({"rule": {"id": "5710"}, "hostile": hostile})
    (run / "alert.json").write_text(alert_text)
    story = run / "actor_story.md"
    story.write_text(hostile)
    invocation = _with_salt(
        build_judge_invocation,
        run,
        story,
        learning,
        closed_ticket_read=closed,
        salt=salt,
    )
    tags = (
        "reader_contract",
        "alert",
        "report",
        "actor_story",
        "synthesis",
        "coverage_manifest",
        "comparison_files",
    ) + (("cited_policy_read",) if closed else ())
    return PromptObservation(
        "build_judge_invocation",
        invocation.user_text,
        tags,
        (alert_text, hostile),
        salt,
    )


def _capture_actor(
    tmp_path: Path, *, benign=False, hostile="ACTOR-INPUT-BODY", salt="5a" * 16
):
    run = tmp_path / "learning"
    run.mkdir(parents=True)
    alert = tmp_path / "alert.json"
    alert_text = json.dumps({"rule": {"id": "5710"}, "process": {}, "hostile": hostile})
    alert.write_text(alert_text)
    captured = {}

    def actor_fn(*args, **kwargs):
        captured["user"] = kwargs["user"]
        captured["kwargs"] = kwargs
        return "story"

    if benign:
        _with_salt(
            invoke_actor_benign,
            alert,
            hostile,
            "rule-5710",
            run,
            actor_fn=actor_fn,
            salt=salt,
            box=None,
        )
        tags = ("reader_contract", "alert", "alert_rule_id", "case_entities")
        required = (alert_text, hostile)
        producer = "invoke_actor_benign"
    else:
        actor_input = tmp_path / "actor-input.md"
        actor_input.write_text(hostile)
        _with_salt(invoke_actor, alert, actor_input, run, actor_fn=actor_fn, salt=salt, box=None)
        archetype = (run / "actor_archetype.txt").read_text().strip()
        menu = (run / "actor_menu.txt").read_text().strip()
        tags = (
            "reader_contract",
            "alert",
            "alert_rule_id",
            "actor_input",
            "actor_archetype",
            "mitre_menu",
        )
        required = (alert_text, hostile, archetype, menu)
        producer = "invoke_actor"
    return PromptObservation(producer, captured["user"], tags, required, salt)


def _lead_prompt(hostile="STORY-BODY", *, salt="5a" * 16):
    lead = SimpleNamespace(lead_id="l-001", queries=[], what_to_summarize=[hostile])
    prompt = _with_salt(build_lead_user_prompt, lead, hostile, hostile, salt=salt)
    return PromptObservation(
        "build_lead_user_prompt",
        prompt,
        ("reader_contract", "actor_story", "lead", "sample_event"),
        (hostile,),
        salt,
    )


def _findings_prompt(tmp_path: Path, *, hostile="TRANSCRIPT-BODY", salt="5a" * 16):
    runs = tmp_path / "runs"
    source = runs / "case-1"
    source.mkdir(parents=True)
    (source / "investigation.md").write_text(hostile)
    (source / "source_refs.yaml").write_text("normalized_disposition: malicious\n")
    captured = {}

    def run_verify(wiring, **kwargs):
        captured.update(kwargs)
        captured["wiring"] = wiring
        return "VERDICT: GOOD"

    lesson = tmp_path / "lesson.md"
    lesson.write_text(hostile)
    ctx = CheckContext(
        FINDINGS_CHECK,
        lesson,
        hostile,
        "case-1",
        "adversarial",
        runs,
        tmp_path / "pending",
        tmp_path / "corpus",
        ROOT,
        0,
        run_verify,
    )
    _with_salt(_run_findings, ctx, salt=salt)
    return PromptObservation(
        "_run_findings",
        captured["user"],
        (
            "reader_contract",
            "case_transcript",
            "candidate_lesson",
            "case_ground_truth_disposition",
            "cited_covering_policy",
        ),
        (hostile,),
        salt,
    )


def _actor_verify_prompt(tmp_path: Path, *, hostile="OBS-BODY", salt="5a" * 16):
    runs = tmp_path / "runs"
    source = runs / "case-1"
    source.mkdir(parents=True)
    (source / "actor_story.md").write_text(hostile)
    pending = tmp_path / "pending.jsonl"
    pending.write_text(
        json.dumps(
            {
                "observation_id": "obs-1",
                "observation": hostile,
                "source_run_dir": "case-1",
            }
        )
        + "\n"
    )
    captured = {}

    def run_verify(wiring, **kwargs):
        captured.update(kwargs)
        captured["wiring"] = wiring
        return "VERDICT: GOOD"

    lesson = tmp_path / "lesson.md"
    lesson.write_text(hostile)
    ctx = CheckContext(
        ACTOR_CHECK,
        lesson,
        hostile,
        "obs-1",
        "adversarial",
        runs,
        pending,
        tmp_path / "corpus",
        ROOT,
        0,
        run_verify,
    )
    _with_salt(_run_actor, ctx, salt=salt)
    return PromptObservation(
        "_run_actor",
        captured["user"],
        ("reader_contract", "actor_story", "judge_observation", "candidate_lesson"),
        (hostile,),
        salt,
    )


def _curator_prompt(tmp_path: Path, *, hostile="ROW-BODY", rows=None, salt="5a" * 16):
    rows = [{"lesson": hostile}] if rows is None else rows
    prompt = _with_salt(
        author_shared.build_curator_user_prompt,
        rows,
        "batch",
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
        _judge_fixture(tmp_path / "judge", hostile=hostile, salt=salt),
        _capture_actor(tmp_path / "actor", hostile=hostile, salt=salt),
        _capture_actor(tmp_path / "benign", benign=True, hostile=hostile, salt=salt),
        _lead_prompt(hostile, salt=salt),
        _findings_prompt(tmp_path / "findings", hostile=hostile, salt=salt),
        _actor_verify_prompt(tmp_path / "verify-actor", hostile=hostile, salt=salt),
        _curator_prompt(tmp_path / "curator", hostile=hostile, salt=salt),
        _lead_author_prompt(
            tmp_path / "lead-author", monkeypatch, hostile=hostile, salt=salt
        ),
        _pitfalls_prompt(
            tmp_path / "pitfalls", monkeypatch, hostile=hostile, salt=salt
        ),
    )


def _deps(tmp_path: Path, definition, *, box=None, read_root=None):
    run = tmp_path / "run"
    dfn = tmp_path / "tree" / "defender"
    run.mkdir(parents=True)
    dfn.mkdir(parents=True)
    scope = RunScope(add_dirs=(read_root,)) if read_root else RunScope()
    return bind(definition, run, defender_dir=dfn, scope=scope, box=box)


def _actor_deps_scene(tmp_path: Path, result: BoxResult):
    defender_dir = tmp_path / "tree" / "defender"
    corpus = defender_dir / "lessons-actor"
    run = tmp_path / "run"
    corpus.mkdir(parents=True)
    run.mkdir(parents=True)
    # Actor scripts are pinned to the real repository root by production policy.
    script = DEFENDER / "scripts" / "lessons" / "lessons_actor_index.py"
    deps = bind(
        ACTOR_DEF,
        run,
        defender_dir=defender_dir,
        scope=RunScope(read_confine=(corpus,), scripts=(script,)),
        box=Box(result),
    )
    return deps, corpus, f"python3 {script}"


def _lead_author_deps_scene(tmp_path: Path, result: BoxResult):
    repo = tmp_path / "tree"
    defender_dir = repo / "defender"
    skills = defender_dir / "skills"
    run = tmp_path / "run"
    skills.mkdir(parents=True)
    run.mkdir(parents=True)
    deps = bind(LEAD_AUTHOR_DEF, run, defender_dir=defender_dir, box=Box(result))
    return deps, skills, "rm defender/skills/system/_draft/lesson.md"


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
        cfg=ForwardCheckConfig(
            check=FINDINGS_CHECK,
            runs_dir=tmp_path / "runs",
            pending=tmp_path / "pending.jsonl",
            queued_ids=frozenset(),
            # `*_a` because `_verify` passes the StageWiring POSITIONALLY (#713); a
            # keyword-only fake would TypeError the moment this scene drove a check.
            run_verify=lambda *_a, **_kwargs: "VERDICT: GOOD",
        ),
        box=None,
    )
    deps = replace(deps, box=Box(result))
    assert deps.role is CORPUS_AUTHOR_DEF.role
    return deps, corpus, f"cat {corpus / 'lesson.md'}"


def _judge_read_scene(tmp_path):
    root = tmp_path / "comparison"
    root.mkdir(parents=True)
    return _deps(tmp_path / "deps", JUDGE_BENIGN_DEF, read_root=root), root


def _main_bash(tmp_path, payload):
    fake = Box(BoxResult(0, payload, b""))
    deps = _deps(tmp_path, MAIN_DEF, box=fake)
    artifact = deps.run_dir / "report.md"
    artifact.write_text("admitted main read")
    return _tool_bash(deps, f"cat {artifact}")


# Original demand owners, consolidated so every producer driver is ownership-local.


def _shared_wrap():
    spec = importlib.util.find_spec("defender._untrusted")
    if spec is None:
        pytest.fail(
            "#680 requires the shared defender._untrusted module; runtime.untrusted is the superseded location"
        )
    import defender._untrusted as untrusted

    return untrusted.wrap


def _expected_frame(body: str, tag: str, salt: str = STAGE_SALT) -> str:
    return f"<run-{salt}-{tag}>\n{body}\n</run-{salt}-{tag}>"


def _drive_frame(body: str, tag: str = "payload", salt: str = STAGE_SALT) -> str:
    """Drive the primitive without asserting policy on behalf of a test owner."""
    return _shared_wrap()(body, tag, salt)


def _assert_body_cannot_add_current_sections(
    body: str, *, tag: str = "assigned"
) -> tuple[str, list[re.Match[str]]]:
    """Return primitive observations; demand-specific assertions stay in callers."""
    out = _drive_frame(body, tag)
    return (out, list(FRAME_RE.finditer(out)))


def _assert_stage_message(prompt: str, *expected_bodies: str) -> list[re.Match[str]]:
    """Parse a real stage message without asserting another demand's policy."""
    return list(FRAME_RE.finditer(prompt))


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


def _judge_deps(tmp_path: Path, *, box=None):
    run_dir = tmp_path / "learning-run"
    comparison = tmp_path / "comparison"
    defender_dir = tmp_path / "tree" / "defender"
    run_dir.mkdir(parents=True)
    comparison.mkdir(parents=True)
    defender_dir.mkdir(parents=True)
    deps = bind(
        JUDGE_BENIGN_DEF,
        run_dir,
        salt=STAGE_SALT,
        defender_dir=defender_dir,
        scope=RunScope(add_dirs=(comparison,)),
        box=box,
    )
    return (deps, comparison)


def _drive_learning_read(tmp_path: Path, body: str, *, name: str = "lead.md") -> str:
    deps, comparison = _judge_deps(tmp_path)
    artifact = comparison / name
    artifact.write_text(body, encoding="utf-8")
    return _tool_read_file(deps, str(artifact))


def _drive_learning_bash(
    tmp_path: Path, *, stdout: bytes = b"", stderr: bytes = b"", rc: int = 0
) -> str:
    fake = RecordingBox(BashResultSpec(rc=rc, out=stdout, err=stderr))
    deps, comparison = _judge_deps(tmp_path, box=fake)
    artifact = comparison / "lead.md"
    artifact.write_text("the executor boundary is injected", encoding="utf-8")
    command = f"cat {artifact}"
    return _tool_bash(deps, command)


def _python_sources() -> list[Path]:
    return [
        p
        for p in DEFENDER.rglob("*.py")
        if ".venv" not in p.parts and "tests" not in p.relative_to(DEFENDER).parts
    ]
