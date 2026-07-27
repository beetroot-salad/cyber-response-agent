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

# The stage engines, plus the one module that legitimately holds wirings as constants.
_STAGE_MODULES = (
    "learning/pipeline/_pydantic_stage.py",
    "learning/pipeline/actor_engine.py",
    "learning/pipeline/oracle_engine.py",
    "learning/pipeline/judge/engine_pydantic.py",
    "learning/author/curator_engine.py",
    "learning/author/verify_forward/engine.py",
    "learning/leads/lead_author_engine.py",
    "learning/core/directions.py",
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
    if isinstance(node, ast.AnnAssign):
        return [node.target.id] if isinstance(node.target, ast.Name) else []
    return [t.id for t in node.targets if isinstance(t, ast.Name)]


@pytest.mark.parametrize("rel", _STAGE_MODULES)
def test_no_module_level_stage_wiring_or_context(rel):
    """A `StageWiring`/`StageContext` built at import time freezes whatever env-backed knob
    it carries — `model`, `effort`, `wall_clock_timeout` (`subagent_timeout()`) — which is
    exactly the freeze #717 removed and #713's grouping could quietly reintroduce.

    Lint cannot see this: bundling the parameters into a module constant DELETES the
    PLR0913 suppression and passes `ruff check defender` while the knob stops moving. So
    the structural guard is the control, and it names its two grandfathered exceptions."""
    path = _defender_root() / rel
    tree = ast.parse(path.read_text(encoding="utf-8"))
    frozen = [
        f"{rel}:{node.lineno}: {', '.join(_targets(node))}"
        for node in tree.body
        if isinstance(node, ast.Assign | ast.AnnAssign)
        and node.value is not None
        and _constructs_a_grouping_object(node.value)
        and not set(_targets(node)) <= _GRANDFATHERED
    ]
    assert not frozen, (
        "a stage wiring/context is constructed at MODULE level:\n  "
        + "\n  ".join(frozen)
        + "\nBuild it per call, at the spawn boundary — an import-time construction "
        "freezes its env-backed knobs past monkeypatch.setenv (#717/#713)."
    )


@pytest.mark.parametrize("rel", _STAGE_MODULES[:-1])
def test_stage_entry_points_take_no_passthrough_blob(rel):
    """The grouping must not be bought with a bag. `**kwargs` or a bare `dict` parameter
    would get every engine under ruff's `max-args = 8` while keeping the call untyped —
    the same defect in a costume, and one the DI-seam fakes could not discriminate."""
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
        for arg in (*node.args.args, *node.args.kwonlyargs):
            ann = arg.annotation
            if isinstance(ann, ast.Name) and ann.id == "dict":
                offenders.append(f"{rel}:{node.lineno} {node.name}({arg.arg}: dict)")
    assert not offenders, (
        "a stage entry point takes an untyped passthrough:\n  " + "\n  ".join(offenders)
        + "\nGroup the parameters into StageWiring/StageContext instead (#713)."
    )
