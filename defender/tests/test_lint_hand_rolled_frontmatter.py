"""lint_hand_rolled_frontmatter: flags hand-rolled frontmatter parsing outside the canonical parser."""
from __future__ import annotations

from pathlib import Path


from defender.tests._by_path import load_lint_gate

_GATE = load_lint_gate("lint_hand_rolled_frontmatter")


_FIND = 'def f_find(t):\n    return t.find("\\n---", 4)\n'
_SPLIT = 'def f_split(t):\n    return t.split("---", 2)\n'
_STARTS = 'def f_starts(t):\n    return t.startswith("---")\n'
_REGEX = 'import re\n\ndef f_regex(t):\n    return re.search(r"^---\\s*\\n", t)\n'
_REGEX_CLOSING = 'import re\n\ndef f_regex_closing(t):\n    return re.search(r"\\n---", t[4:])\n'


def _pyfile(tree: Path, rel: str, src: str) -> Path:
    p = tree / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src, encoding="utf-8")
    return p


def _by_function(findings) -> dict[str, list]:
    out: dict[str, list] = {}
    for f in findings:
        parts = f.fingerprint.split(":")
        func = parts[-2] if len(parts) >= 2 else "?"
        out.setdefault(func, []).append(f)
    return out


def test_d_lint_flags_each_idiom(tmp_path):
    gate = _GATE
    tree = tmp_path / "scope"
    _pyfile(tree, "idioms.py", _FIND + "\n" + _SPLIT + "\n" + _STARTS + "\n" + _REGEX)

    findings = gate._scan(tree)
    assert all("idioms.py" in f.fingerprint for f in findings)
    flagged_funcs = set(_by_function(findings))
    for func in ("f_find", "f_split", "f_starts", "f_regex"):
        assert func in flagged_funcs, f"{func} idiom must be flagged"
    assert gate.main([], scope=tree, baseline_path=tmp_path / "empty.json") == 1


def test_d_lint_flags_the_raw_closing_fence_regex(tmp_path):
    gate = _GATE
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", _REGEX_CLOSING)

    findings = gate._scan(tree)
    assert findings, "the raw closing-fence regex must be flagged"
    assert [f.fingerprint.split(":")[-1] for f in findings] == ["regex"]
    assert all("f_regex_closing" in f.fingerprint for f in findings)
    assert gate.main([], scope=tree, baseline_path=tmp_path / "empty.json") == 1


def test_d_lint_writer_fstrings_clean(tmp_path):
    gate = _GATE
    tree = tmp_path / "scope"
    clean = (
        '"""A module docstring mentioning --- and \\n--- fences."""\n'
        "def emit(y, text):\n"
        '    frag = f"---\\nid: {y}\\n---\\n"      # JoinedStr writer, not a parse\n'
        '    sep = "--- stdout ---"                # plain Constant separator\n'
        '    if "\\n---" in text:                  # in-containment Compare (waived)\n'
        "        pass\n"
        "    return frag + sep\n"
    )
    _pyfile(tree, "writer.py", clean)
    assert gate._scan(tree) == [], "writers/constants/in-checks must not be flagged"

    _pyfile(tree, "reader.py", _FIND)
    findings = gate._scan(tree)
    assert findings
    assert all("reader.py" in f.fingerprint for f in findings)


def test_d_lint_tests_excluded(tmp_path):
    gate = _GATE
    tree = tmp_path / "scope"
    _pyfile(tree, "test_reader.py", _FIND)
    assert gate._scan(tree) == []
    _pyfile(tree, "reader.py", _FIND)
    assert any("reader.py" in f.fingerprint for f in gate._scan(tree))


def test_d_lint_canonical_exempt(tmp_path):
    gate = _GATE
    tree = tmp_path / "scope"
    _pyfile(tree, "_frontmatter.py", _FIND)
    assert gate._scan(tree) == []
    _pyfile(tree, "other.py", _FIND)
    assert any("other.py" in f.fingerprint for f in gate._scan(tree))


def test_d_lint_suppression(tmp_path):
    gate = _GATE
    on = tmp_path / "on"
    _pyfile(on, "s.py", 'def f(t):\n    return t.find("\\n---", 4)  # lint-frontmatter: ok — canonical-ish\n')
    assert gate._scan(on) == []
    off = tmp_path / "off"
    _pyfile(off, "s.py",
            "# lint-frontmatter: ok — far above\n"
            "def f(t):\n"
            "    x = 1\n"
            "    y = 2\n"
            '    return t.find("\\n---", 4)\n')
    assert gate._scan(off), "a marker outside the node span must not suppress"
    bare = tmp_path / "bare"
    _pyfile(bare, "s.py", 'def f(t):\n    return t.find("\\n---", 4)  # lint-frontmatter: ok\n')
    assert gate._scan(bare) == []


def test_d_lint_fingerprint_dedup(tmp_path):
    gate = _GATE
    tree = tmp_path / "scope"
    src = (
        "def same(t):\n"
        '    a = t.find("\\n---", 4)\n'
        '    b = t.find("\\n---", 8)\n'
        "    return a, b\n"
        "\n"
        "def two(t):\n"
        '    a = t.find("\\n---", 4)\n'
        '    b = t.split("---", 2)\n'
        "    return a, b\n"
    )
    _pyfile(tree, "dedup.py", src)
    by_func = _by_function(gate._scan(tree))
    assert len(by_func.get("same", [])) == 1
    assert len(by_func.get("two", [])) == 2


def test_aliased_re_import_is_flagged(tmp_path):
    gate = _GATE
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", (
        "import re as regex\n\n"
        'def f(t):\n    return regex.compile(r"\\A---\\n")\n'
    ))
    assert gate._scan(tree)


def test_from_import_re_is_flagged(tmp_path):
    gate = _GATE
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", (
        "from re import search\n\n"
        'def f(t):\n    return search(r"^---\\n(.*?)\\n---", t)\n'
    ))
    assert gate._scan(tree)
