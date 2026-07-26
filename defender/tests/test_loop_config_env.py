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
