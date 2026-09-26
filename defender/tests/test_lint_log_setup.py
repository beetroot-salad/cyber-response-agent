"""Tests for the lint_log_setup gate: every defender program configures logging or says why not."""
from __future__ import annotations

import ast

import pytest

from defender.tests._by_path import load_lint_gate

_GATE = load_lint_gate("lint_log_setup")


def _guards(src: str) -> list[ast.stmt]:
    return [n for n in ast.parse(src).body if _GATE._is_main_guard(n)]


@pytest.mark.parametrize("src", [
    'if __name__ == "__main__":\n    main()\n',
    'if __name__ == "__main__" and ok:\n    main()\n',
])
def test_a_main_guard_is_recognised_alone_or_inside_an_and(src):
    assert len(_guards(src)) == 1


@pytest.mark.parametrize(("src", "configured"), [
    ('if __name__ == "__main__":\n    main()\n', False),
    ('if __name__ == "__main__":\n'
     '    from defender._log import configure_from_env\n    configure_from_env()\n    main()\n', True),
    ('if __name__ == "__main__":\n    _log.configure_from_env()\n    main()\n', True),
])
def test_the_setup_call_counts_in_either_spelling(src, configured):
    [guard] = _guards(src)
    assert _GATE._calls_setup(guard) is configured


def test_the_real_tree_is_clean():
    assert _GATE._scan() == []
