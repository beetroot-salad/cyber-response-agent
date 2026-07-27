"""Every env-backed knob in `learning/core/config.py` is read at CALL time (#717).

The file used to carry two idioms for one job: half the knobs froze at first import
(`ACTOR_MODEL = os.environ.get(...)`, `SUBAGENT_TIMEOUT = env_int(...)`) while the
equivalents beside them read lazily (`merge_mode()`, `pitfalls_threshold()`). The frozen
half could not be moved by a test without `importlib.reload`, so a `monkeypatch.setenv`
silently did nothing — the shape behind `LEARNING_AUTHOR_MAX_ATTEMPTS` being set in the
DLQ suite and ignored by the code under test.

Two guards, because either alone is weak: the structural one keeps a NEW knob from
quietly reintroducing the frozen idiom, and the behavioral one proves the accessors
actually observe an environment changed after import.

Module-level constants BUILT from these accessors still snapshot at their own import —
`directions.py`'s two `JudgeWiring`s are the deliberate remaining case, and they say so.
That is a different (and visible) thing from config.py owning the freeze.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from defender.learning.core import config  # type: ignore[import-not-found]

_ENV_READERS = {"env_int", "env_str", "env_bool"}


def _reads_env(node: ast.AST) -> bool:
    """Whether an expression reaches the environment: `env_int(...)`/`env_str(...)`/
    `env_bool(...)`, or `os.environ` by `.get(...)`, subscript, or bare reference.

    Direct reads only — a module-level call to a local helper that reads env inside
    (`state_dir=_env_state_dir()` on DEFAULT_PATHS) is not traced through. That one is a
    path, not a knob, and `learning_state_root()` is its live accessor."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Name):
            if sub.func.id in _ENV_READERS:
                return True
        # `os.environ` is an Attribute node whichever way it is then used — `.get(...)`,
        # `[...]`, or handed around bare — so one check covers all three.
        elif isinstance(sub, ast.Attribute) and sub.attr == "environ":
            return True
    return False


def test_no_module_level_env_read_in_loop_config():
    """The structural guard. A module-level `X = <reads env>` is the frozen idiom; every
    knob belongs in a `def`, where the read happens per call."""
    tree = ast.parse(Path(config.__file__).read_text(encoding="utf-8"))
    frozen = [
        f"line {node.lineno}: {ast.unparse(node)}"
        for node in tree.body
        if isinstance(node, ast.Assign | ast.AnnAssign) and _reads_env(node.value)
    ]
    assert not frozen, (
        "learning/core/config.py reads the environment at MODULE level:\n  "
        + "\n  ".join(frozen)
        + "\nSince #717 every env-backed knob is a call-time accessor "
        "(`def actor_model() -> str: return env_str(...)`), so a test can move it with "
        "monkeypatch.setenv and no importlib.reload. Add the knob as a function."
    )


@pytest.mark.parametrize(
    ("accessor", "var", "raw", "expected"),
    [
        ("actor_model", "ACTOR_MODEL", "kimi-k2.6", "kimi-k2.6"),
        ("oracle_model", "ORACLE_MODEL", "deepseek-v4", "deepseek-v4"),
        ("judge_effort", "JUDGE_EFFORT", "high", "high"),
        ("verifier_timeout", "LEARNING_VERIFIER_TIMEOUT_SECONDS", "42", 42),
        ("author_max_attempts", "LEARNING_AUTHOR_MAX_ATTEMPTS", "10", 10),
        ("subagent_timeout", "LEARNING_SUBAGENT_TIMEOUT_SECONDS", "99", 99),
        ("repo_lock_wait_seconds", "LEARNING_REPO_LOCK_WAIT_SECONDS", "7", 7),
    ],
)
def test_accessor_sees_an_env_set_after_import(monkeypatch, accessor, var, raw, expected):
    """The behavioral guard, spanning both coercions (str + int) and all four knob
    families (stage models/efforts, timeouts, retry caps, lock waits). `config` was
    imported at collection time; the setenv lands after that and must still be seen."""
    monkeypatch.setenv(var, raw)
    assert getattr(config, accessor)() == expected


def test_accessor_returns_the_default_when_unset(monkeypatch):
    """The other half of the contract: the default is the accessor's, not a stale read of
    whatever the environment held when the module first loaded."""
    monkeypatch.delenv("LEARNING_AUTHOR_MAX_ATTEMPTS", raising=False)
    monkeypatch.delenv("ACTOR_MODEL", raising=False)
    assert config.author_max_attempts() == 3
    assert config.actor_model() == "glm-5.2"


# ===========================================================================
# #713 — the grouping objects must not re-freeze what #717 unfroze
# ===========================================================================

# The stage ENGINES — the entry points whose signatures the passthrough guard polices.
_STAGE_MODULES = (
    "learning/pipeline/_pydantic_stage.py",
    "learning/pipeline/actor_engine.py",
    "learning/pipeline/oracle_engine.py",
    "learning/pipeline/judge/engine_pydantic.py",
    "learning/author/curator_engine.py",
    "learning/author/verify_forward/engine.py",
    "learning/leads/lead_author_engine.py",
)

# Every module that CONSTRUCTS a wiring or a context — the engines above plus the spawn
# boundaries, which is where the env-backed knobs are actually read. The freeze guard has to
# span all of them: `malicious_actor/run.py` builds `StageWiring(ACTOR_PROMPT, actor_model(),
# ...)` a few lines under a block of module constants, and hoisting it there would freeze
# ACTOR_MODEL at import exactly as surely as doing it inside an engine.
_WIRING_SITES = _STAGE_MODULES + (
    "learning/core/directions.py",
    "learning/leads/_lead_spine.py",
    "learning/author/curator.py",
    "learning/author/lessons/run.py",
    "learning/pipeline/malicious_actor/run.py",
    "learning/pipeline/benign_actor/run.py",
    "learning/pipeline/oracle/run.py",
    "learning/pipeline/judge/run.py",
)

# `directions.py` snapshots these two deliberately and says so at its line 28: an A/B run
# pins the judge model for the whole process. They are the ONLY grandfathered pair; anything
# else built at import time is the #717 regression coming back through the new objects.
_GRANDFATHERED = {"ADVERSARIAL_WIRING", "BENIGN_WIRING"}

_GROUPING_TYPES = {"StageWiring", "StageContext", "JudgeWiring"}


def _defender_root() -> Path:
    return Path(config.__file__).resolve().parents[2]


def _constructs_a_grouping_object(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            f = sub.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            if name in _GROUPING_TYPES:
                return True
            # `StageWiring.for_batch(...)` reads os.getpid() and the caller's live knobs;
            # at module level it would freeze both just as surely.
            if name == "for_batch":
                return True
    return False


def _targets(node: ast.Assign | ast.AnnAssign) -> list[str]:
    """Every bare NAME bound by this assignment, including through tuple/list unpacking.

    Walking the targets (rather than reading `.id` off the top level only) matters for the
    exemption below: a target list that yields NO names must not be treated as 'all of its
    names are grandfathered'. `A, B = StageWiring(...), StageWiring(...)` binds a Tuple, and
    a top-level-only reader returns `[]` for it."""
    targets = [node.target] if isinstance(node, ast.AnnAssign) else list(node.targets)
    return [
        sub.id
        for t in targets
        for sub in ast.walk(t)
        if isinstance(sub, ast.Name)
    ]


@pytest.mark.parametrize("rel", _WIRING_SITES)
def test_no_module_level_stage_wiring_or_context(rel):
    """A `StageWiring`/`StageContext` built at import time freezes whatever env-backed knob
    it carries — `model`, `effort`, `wall_clock_timeout` (`subagent_timeout()`) — which is
    exactly the freeze #717 removed and #713's grouping could quietly reintroduce.

    Lint cannot see this: bundling the parameters into a module constant DELETES the
    PLR0913 suppression and passes `ruff check defender` while the knob stops moving. So
    the structural guard is the control, and it names its two grandfathered exceptions."""
    path = _defender_root() / rel
    tree = ast.parse(path.read_text(encoding="utf-8"))
    frozen = []
    for node in tree.body:
        if not isinstance(node, ast.Assign | ast.AnnAssign):
            continue
        if node.value is None or not _constructs_a_grouping_object(node.value):
            continue
        names = _targets(node)
        # `names and ...` on purpose: an EMPTY name set is vacuously a subset of the
        # grandfathered pair, so an assignment to something that is not a bare name
        # (`obj.attr = ...`, `d["k"] = ...`) would otherwise exempt itself.
        if names and set(names) <= _GRANDFATHERED:
            continue
        frozen.append(f"{rel}:{node.lineno}: {', '.join(names) or ast.unparse(node)}")
    assert not frozen, (
        "a stage wiring/context is constructed at MODULE level:\n  "
        + "\n  ".join(frozen)
        + "\nBuild it per call, at the spawn boundary — an import-time construction "
        "freezes its env-backed knobs past monkeypatch.setenv (#717/#713)."
    )


# ===========================================================================
# #713 — a per-batch spawn's trace name stays unique on (batch_id, pid)
# ===========================================================================

# The spawn boundaries that stand up ONE batch of an authoring drain. Each used to let
# `run_curator_stage` / `run_author_stage` derive the trace name for it; since #713 each
# builds the wiring itself, so the uniqueness now depends on each one reaching `for_batch`.
_BATCH_SPAWN_SITES = (
    "learning/author/curator.py",
    "learning/author/lessons/run.py",
    "learning/leads/_lead_spine.py",
)


@pytest.mark.parametrize("rel", _BATCH_SPAWN_SITES)
def test_batch_spawn_boundaries_build_their_wiring_via_for_batch(rel):
    """`StageWiring.for_batch` is the ONLY builder that keys `trace_name` on (batch_id, pid).
    A drain that constructs the wiring directly — `StageWiring(..., trace_name=
    "curator_trace.jsonl")` — still spawns and still traces, but two concurrent drain
    PROCESSES sharing one pending dir then interleave into a single file, and the second
    `RequestLogger` truncates the first one's trace.

    Structural because there is no injection seam below these entry points: `invoke_agent`
    imports `curator_engine` locally and calls `run_curator_stage` with its production
    `run_author` default, so a behavioral test would have to `monkeypatch.setattr` a module
    global — which this repo's ratcheted `lint_monkeypatch` gate refuses. The behavioral half
    lives at `test_curator_glm_engine.py::test_stage_refuses_a_wiring_that_did_not_come_from_
    for_batch` (the stage rejects a batch-less wiring) and at
    `test_curator_glm_survival.py::test_trace_per_spawn_distinct` (`for_batch` really does
    separate two spawns); this guard is what binds those to the production callers."""
    path = _defender_root() / rel
    tree = ast.parse(path.read_text(encoding="utf-8"))
    direct = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
        if name in _GROUPING_TYPES - {"StageContext"}:
            direct.append(f"{rel}:{node.lineno}: {ast.unparse(node.func)}(...)")
    assert not direct, (
        "a per-batch spawn boundary builds its wiring directly:\n  " + "\n  ".join(direct)
        + "\nUse StageWiring.for_batch(..., batch_id=...) — it is what keys trace_name on "
        "(batch_id, pid), so concurrent drain processes never share one trace file (#713)."
    )


def _is_blob_annotation(ann: ast.expr | None) -> bool:
    """A `dict` parameter, subscripted or not — `dict[str, Any]` is the same bag."""
    if isinstance(ann, ast.Subscript):
        ann = ann.value
    return isinstance(ann, ast.Name) and ann.id == "dict"


@pytest.mark.parametrize("rel", _STAGE_MODULES)
def test_stage_entry_points_take_no_passthrough_blob(rel):
    """The grouping must not be bought with a bag. `**kwargs`, `*args` or a `dict` parameter
    would get every engine under ruff's `max-args = 8` while keeping the call untyped —
    the same defect in a costume, and one the DI-seam fakes could not discriminate.

    All three costumes, not just `**kwargs`: `*args` forwards positionally with no names at
    all, and `dict[str, Any]` is exactly as opaque as a bare `dict`."""
    path = _defender_root() / rel
    tree = ast.parse(path.read_text(encoding="utf-8"))
    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if not (node.name.startswith("_run_") or node.name in {
            "run_stage", "build_stage_agent", "run_curator_stage", "run_author_stage",
        }):
            continue
        if node.args.kwarg is not None:
            offenders.append(f"{rel}:{node.lineno} {node.name}(**{node.args.kwarg.arg})")
        if node.args.vararg is not None:
            offenders.append(f"{rel}:{node.lineno} {node.name}(*{node.args.vararg.arg})")
        for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            if _is_blob_annotation(arg.annotation):
                offenders.append(f"{rel}:{node.lineno} {node.name}({arg.arg}: dict)")
    assert not offenders, (
        "a stage entry point takes an untyped passthrough:\n  " + "\n  ".join(offenders)
        + "\nGroup the parameters into StageWiring/StageContext instead (#713)."
    )
