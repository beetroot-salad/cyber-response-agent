"""Characterization + intent tests for the lint_unsafe_jsonl_io gate (#602)."""
from __future__ import annotations

import json

from pathlib import Path


from defender.tests.support.shared.contracts._by_path import load_lint_gate

_GATE = load_lint_gate("lint_unsafe_jsonl_io")


def _pyfile(tree: Path, rel: str, src: str) -> Path:
    p = tree / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src, encoding="utf-8")
    return p


def _write_baseline(path: Path, fingerprints: list[str]) -> None:
    path.write_text(
        json.dumps({"//": "test", "entries": {fp: "" for fp in fingerprints}}) + "\n",
        encoding="utf-8",
    )


def _flags(tmp_path: Path, src: str) -> bool:
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", src)
    return bool(_GATE._scan(tree))


def _reader(imp: str, call: str) -> str:
    """A hand-rolled per-line JSON reader — the #446 torn-line crash shape."""
    return (
        f"{imp}\n"
        "def read(p):\n"
        "    rows = []\n"
        "    with open(p) as fh:\n"
        "        for line in fh:\n"
        f"            rows.append({call}(line))\n"
        "    return rows\n"
    )


def _appender(imp: str, call: str) -> str:
    """A hand-rolled JSONL append — json.dumps + a newline onto an append handle."""
    return (
        f"{imp}\n"
        "def append(p, row):\n"
        '    with open(p, "a") as fh:\n'
        f'        fh.write({call}(row) + "\\n")\n'
    )


def test_scan_and_ratchet_contract(tmp_path):
    gate = _GATE
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", _reader("import json", "json.loads"))

    findings = gate._scan(tree)
    assert findings, "a hand-rolled per-line json.loads reader must be flagged"
    assert all("prod.py" in f.fingerprint for f in findings)

    empty = tmp_path / "empty.json"
    assert gate.main([], scope=tree, baseline_path=empty) == 1
    bp = tmp_path / "bp.json"
    _write_baseline(bp, [f.fingerprint for f in findings])
    assert gate.main([], scope=tree, baseline_path=bp) == 0
    assert gate.main([], scope=tmp_path / "nope") == 2


def test_flags_the_spelled_reader(tmp_path):
    assert _flags(tmp_path, _reader("import json", "json.loads"))


def test_flags_the_spelled_appender(tmp_path):
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", _appender("import json", "json.dumps"))
    assert any(f.fingerprint.endswith(":append") for f in _GATE._scan(tree))


def test_splitlines_on_a_plain_value_is_clean(tmp_path):
    """A subprocess stdout string has no torn-file failure mode — deliberately
    NOT matched, and the refactor must not widen into it."""
    assert not _flags(tmp_path, (
        "import json\n"
        "def read(out):\n"
        "    return [json.loads(x) for x in out.splitlines()]\n"
    ))


def test_suppression(tmp_path):
    assert not _flags(tmp_path, (
        "import json\n"
        "def read(p):\n"
        "    rows = []\n"
        "    with open(p) as fh:\n"
        "        for line in fh:  # lint-jsonl-io: ok — deliberate\n"
        "            rows.append(json.loads(line))\n"
        "    return rows\n"
    ))


def test_aliased_json_reader_is_flagged(tmp_path):
    assert _flags(tmp_path, _reader("import json as j", "j.loads"))


def test_from_import_json_reader_is_flagged(tmp_path):
    assert _flags(tmp_path, _reader("from json import loads", "loads"))


def test_aliased_json_appender_is_flagged(tmp_path):
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", _appender("import json as j", "j.dumps"))
    assert any(f.fingerprint.endswith(":append") for f in _GATE._scan(tree))


def test_append_handle_from_a_module_opener_is_flagged(tmp_path):
    for imp, opener in (
        ("import codecs", "codecs.open"),
        ("import io", "io.open"),
        ("import gzip", "gzip.open"),
    ):
        tree = tmp_path / opener.replace(".", "_")
        _pyfile(tree, "prod.py", (
            f"import json\n{imp}\n"
            "def append(p, row):\n"
            f'    with {opener}(p, "a") as fh:\n'
            '        fh.write(json.dumps(row) + "\\n")\n'
        ))
        assert any(
            f.fingerprint.endswith(":append") for f in _GATE._scan(tree)
        ), f"{opener} append handle went unrecognised"


def test_a_read_mode_module_opener_is_not_an_append_handle(tmp_path):
    tree = tmp_path / "scope"
    _pyfile(tree, "prod.py", (
        "import json, codecs\n"
        "def dump(p, row):\n"
        '    with codecs.open(p, "r") as fh:\n'
        '        fh.write(json.dumps(row) + "\\n")\n'
    ))
    assert not any(f.fingerprint.endswith(":append") for f in _GATE._scan(tree))
