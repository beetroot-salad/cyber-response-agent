"""defender-lessons CLI: frontmatter-only grep + tag enumeration.

The load-bearing guarantee is that pattern matching and output are scoped to
the YAML frontmatter — the freeform body must never false-match a tag query
nor leak into the `<path>\\t<description>` surface.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "lessons" / "lessons_fm.py"


def _load(tmp_lessons: Path):
    spec = importlib.util.spec_from_file_location("lessons_fm", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    mod.REPO_ROOT = tmp_lessons.parent
    mod.LESSONS_DIR = tmp_lessons
    return mod


def _write(d: Path, name: str, fm: str, body: str = "body text") -> None:
    (d / name).write_text(f"---\n{fm}\n---\n\n{body}\n")


@pytest.fixture
def corpus(tmp_path):
    d = tmp_path / "lessons"
    d.mkdir()
    _write(
        d, "falco-one.md",
        "name: falco-one\n"
        "description: falco lesson one\n"
        "source_signature: [v2-falco-suspicious-network-tool]\n"
        "telemetry_source: [falco, zeek]\n"
        "attack_phase: [execution]",
        # body deliberately mentions sshd to prove the body is NOT searched
        body="this body talks about telemetry_source: sshd at length",
    )
    _write(
        d, "sshd-one.md",
        "name: sshd-one\n"
        "description: sshd lesson one\n"
        "source_signature: [v2-cross-tier-ssh-pivot]\n"
        "telemetry_source: [sshd, auditd]\n"
        "attack_phase: [persistence]",
    )
    _write(d, "_TEMPLATE.md", "name: t\ndescription: d")  # underscore → skipped
    return d


def _out(capsys):
    return capsys.readouterr().out


def test_grep_matches_frontmatter_only(corpus, capsys):
    """A 'telemetry_source:.*sshd' pattern matches the sshd lesson's frontmatter
    but NOT the falco lesson whose *body* mentions sshd."""
    mod = _load(corpus)
    assert mod.main(["prog", r"telemetry_source:.*\bsshd\b"]) == 0
    out = _out(capsys)
    assert "sshd-one.md" in out
    assert "falco-one.md" not in out


def test_grep_ands_patterns(corpus, capsys):
    mod = _load(corpus)
    assert mod.main([
        "prog",
        "source_signature:.*v2-cross-tier-ssh-pivot",
        "attack_phase:.*persistence",
    ]) == 0
    out = _out(capsys)
    assert "sshd-one.md" in out
    assert "falco-one.md" not in out


def test_output_is_path_tab_description_no_body(corpus, capsys):
    mod = _load(corpus)
    assert mod.main(["prog", "name: sshd-one"]) == 0
    line = _out(capsys).strip()
    assert line.endswith("\tsshd lesson one")
    assert "body" not in line


def test_bare_call_lists_whole_corpus(corpus, capsys):
    mod = _load(corpus)
    assert mod.main(["prog"]) == 0
    out = _out(capsys)
    assert "falco-one.md" in out
    assert "sshd-one.md" in out
    assert "_TEMPLATE.md" not in out  # underscore-prefixed skipped


def test_tags_enumerates_values_with_counts(corpus, capsys):
    mod = _load(corpus)
    assert mod.main(["prog", "--tags", "telemetry_source"]) == 0
    out = _out(capsys)
    assert "telemetry_source:" in out
    for tok in ("sshd", "falco", "zeek", "auditd"):
        assert tok in out


def test_tags_all_dimensions(corpus, capsys):
    mod = _load(corpus)
    assert mod.main(["prog", "--tags"]) == 0
    out = _out(capsys)
    for dim in ("source_signature:", "telemetry_source:", "attack_phase:"):
        assert dim in out


def test_bad_regex_exits_2(corpus, capsys):
    mod = _load(corpus)
    assert mod.main(["prog", "["]) == 2


def test_unknown_dimension_exits_2(corpus, capsys):
    mod = _load(corpus)
    assert mod.main(["prog", "--tags", "nonsense"]) == 2


# --- iter_lessons: the shared corpus iterator behind all three lesson CLIs ---


def test_iter_lessons_skips_undecodable_bytes(tmp_path, capsys):
    """``iter_lessons`` promises to warn-and-skip a malformed lesson so one bad file never takes
    the caller down. That has to cover the READ, not just the PARSE: ``read_text()`` raises
    ``UnicodeDecodeError`` on undecodable bytes, and it is a ``ValueError`` — NOT an ``OSError`` —
    so a guard around the parse alone lets it escape. Live blast radius: the gray-box actor runs
    ``lessons_actor_index`` / ``lessons_env_retrieve`` on its bash lane mid-run."""
    from defender.scripts.lessons._lessons_common import iter_lessons

    corpus = tmp_path / "lessons"
    corpus.mkdir()
    (corpus / "good.md").write_text("---\nname: good\n---\nbody\n")
    (corpus / "corrupt.md").write_bytes(b"---\nname: c\n---\n\xff\xfe not utf-8\n")
    (corpus / "unfenced.md").write_text("no fence at all\n")  # the parse-side control

    yielded = [p.stem for p, _fm in iter_lessons(corpus)]  # must not raise

    assert yielded == ["good"]  # the well-formed sibling survives both bad files
    err = capsys.readouterr().err
    assert "corrupt" in err  # the undecodable one was warn-skipped …
    assert "unfenced" in err  # … alongside the unparseable one
