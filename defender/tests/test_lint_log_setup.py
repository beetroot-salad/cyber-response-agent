"""Tests for the lint_log_setup gate: every defender program configures logging or says why not."""
from __future__ import annotations

import ast

import pytest

from defender.tests._by_path import import_lint_lib, load_lint_gate

_GATE = load_lint_gate("lint_log_setup")
_AST = import_lint_lib("_astlib")

_SETUP = "    from defender._log import configure_from_env\n    configure_from_env()\n"


def _verdict(src: str) -> list[bool]:
    """Per top-level main guard in `src`: does it configure logging?"""
    tree = ast.parse(src)
    env = _AST.module_env(tree)
    return [_GATE._calls_setup(n, env) for n in tree.body if _GATE._is_main_guard(n)]


@pytest.mark.parametrize("guard", [
    'if __name__ == "__main__":',
    'if "__main__" == __name__:',
    'if __name__ == "__main__" and ok:',
])
def test_a_main_guard_is_recognised_in_every_spelling_that_only_runs_as_a_program(guard):
    assert _verdict(f"{guard}\n{_SETUP}    main()\n") == [True]


def test_an_or_is_not_a_guard_it_runs_on_import_too():
    assert _verdict(f'if __name__ == "__main__" or x:\n{_SETUP}') == []


@pytest.mark.parametrize("src", [
    'if __name__ == "__main__":\n    from defender import _log\n    _log.configure_from_env()\n    main()\n',
    'from defender._log import configure_from_env as setup\n'
    'if __name__ == "__main__":\n    setup()\n    main()\n',
])
def test_the_setup_counts_however_it_is_imported(src):
    assert _verdict(src) == [True]


@pytest.mark.parametrize("src", [
    # after the program has already run (and exited)
    'if __name__ == "__main__":\n    sys.exit(main())\n' + _SETUP,
    # buried in a nested function the guard never calls
    'if __name__ == "__main__":\n    def f():\n        from defender._log import configure_from_env\n'
    '        configure_from_env()\n    main()\n',
    # a local function that only shares the name
    'def configure_from_env():\n    pass\nif __name__ == "__main__":\n    configure_from_env()\n',
    # no setup at all
    'if __name__ == "__main__":\n    main()\n',
])
def test_a_setup_that_does_not_run_first_or_is_not_ours_does_not_count(src):
    assert _verdict(src) == [False]


@pytest.mark.gate
def test_the_real_tree_is_clean():
    assert _GATE._scan() == []
