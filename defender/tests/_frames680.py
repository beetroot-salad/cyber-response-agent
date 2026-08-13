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

SALT_RE = re.compile(r"<run-([0-9a-f]+)-([^>]+)>\n(.*?)\n</run-\1-\2>", re.DOTALL)
ROOT = Path(__file__).resolve().parents[2]
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


def _assert_frame_envelope(observation: PromptObservation, tags, salts, gaps) -> None:
    """The three properties that make a frame set a frame set at all.

    Every one of the thirty-five shape assertions in this suite's two test modules
    restates these, so they are stated once. Each carries its own message: a helper that
    hides WHICH invariant broke would trade thirty-four copies for a worse failure.
    """
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


def assert_body_survives(observation: PromptObservation, hostile: str) -> None:
    """A hostile body reached the model as EXACT body data inside one real frame.

    This is the whole adversarial contract, and its point is negative: whatever the
    hostile string tried to impersonate — a sibling section, a closing delimiter, the
    reader contract itself — the frame set the model sees is unchanged, and the string is
    still sitting inside a body rather than having become structure.
    """
    tags, bodies, salts, gaps = _shape(observation)
    _assert_frame_envelope(observation, tags, salts, gaps)
    assert any(hostile == body or hostile in body for body in bodies), (
        f"{observation.producer}: the hostile body did not survive verbatim inside any "
        f"frame — it was transformed, split, or promoted to structure"
    )


def assert_producer_shape(observation: PromptObservation) -> None:
    """A real producer emitted its ordered frames with every template slot substituted.

    The two placeholder checks are not decoration. `{salt}` or `{content}` surviving into
    the prompt means the producer shipped its TEMPLATE to the model — a frame whose salt
    is the literal four characters `{salt}` matches nothing and confines nothing, while
    still looking framed to a reader.
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


def frame_salt_of(text: str, tag: str = "untrusted") -> str:
    """The salt of the first `tag` frame in `text` — recovered by READING it, never predicted.

    `wrap_fresh` (#875) mints a tool-return frame's salt AFTER the content is in hand, so a
    caller cannot know it in advance. That is the property, not an inconvenience: a test that
    could predict the delimiter would be asserting the very thing the design removed. The
    message-assembly frames (a stage's prompt sections) still share one caller-owned salt, and
    `_expected_frame` above stays correct for those."""
    m = re.search(rf"<run-([0-9a-f]+)-{re.escape(tag)}>", text)
    assert m is not None, f"no <run-…-{tag}> frame in: {text[:400]!r}"
    return m.group(1)


def assert_one_frame(text: str, body: str, tag: str = "untrusted") -> str:
    """`text` is EXACTLY one `tag` frame around `body`, verbatim, with nothing outside it.

    The post-#875 spelling of `assert out == _expected_frame(body, tag)` for a TOOL RETURN.
    Returns the salt, for callers that go on to assert about it."""
    salt = frame_salt_of(text, tag)
    assert text == f"<run-{salt}-{tag}>\n{body}\n</run-{salt}-{tag}>", (
        f"not exactly one verbatim {tag} frame:\n{text[:600]!r}"
    )
    return salt


def _drive_frame(body: str, tag: str = "payload", salt: str = STAGE_SALT) -> str:
    """Drive the primitive without asserting policy on behalf of a test owner."""
    return _shared_wrap()(body, tag, salt)


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
        defender_dir=defender_dir,
        scope=RunScope(add_dirs=(comparison,)),
        box=box,
    )
    return (deps, comparison)


def _drive_learning_read(
    tmp_path: Path, body: str, *, name: str = "lead.md", in_run_dir: bool = False
) -> str:
    """One learning-stage `read_file`, through the real tool.

    `in_run_dir` puts the artifact where PRODUCTION puts it. For a learning stage the run dir is
    not private workspace — it is the SHARED cross-stage directory: `benign_actor/run.py:47` and
    `run_cycle.py:97` write `past_tickets.txt` and the actor story into it, and the judge's own
    closed-ticket capture lands at `ticket_reads/{seq}.json`. This harness staged those under
    `comparison/` instead, which is a real add-dir but the wrong one, and that spelling is what
    kept #849's F-11 (run-dir reads arriving unframed) out of view here."""
    deps, comparison = _judge_deps(tmp_path)
    artifact = (deps.run_dir if in_run_dir else comparison) / name
    artifact.parent.mkdir(parents=True, exist_ok=True)
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
