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
    _write(d, "_TEMPLATE.md", "name: t\ndescription: d")
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
    assert "_TEMPLATE.md" not in out


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




def test_iter_lessons_skips_undecodable_bytes(tmp_path, capsys):
    """``iter_lessons`` promises to warn-and-skip a malformed lesson so one bad file never takes
    the caller down. That has to cover the READ, not just the PARSE: ``read_text()`` raises
    ``UnicodeDecodeError`` on undecodable bytes, and it is a ``ValueError`` — NOT an ``OSError`` —
    so a guard around the parse alone lets it escape. Live blast radius: the gray-box actor runs
    ``lessons_actor_index`` / ``lessons_env_retrieve`` on its bash lane mid-run.

    #584 SUPERSEDES the 2-tuple destructure below: ``iter_lessons`` now yields a frozen ``Lesson``
    dataclass. The warn-and-skip property this test pins is unchanged."""
    from defender.scripts.lessons._lessons_common import iter_lessons

    corpus = tmp_path / "lessons"
    corpus.mkdir()
    (corpus / "good.md").write_text("---\nname: good\n---\nbody\n")
    (corpus / "corrupt.md").write_bytes(b"---\nname: c\n---\n\xff\xfe not utf-8\n")
    (corpus / "unfenced.md").write_text("no fence at all\n")

    yielded = [lesson.path.stem for lesson in iter_lessons(corpus)]

    assert yielded == ["good"]
    err = capsys.readouterr().err
    assert "corrupt" in err
    assert "unfenced" in err




def test_show_is_confined_to_the_corpus(corpus, tmp_path, capsys):
    """``--show`` is the ONE lesson read that takes a model-supplied path, and nothing upstream
    confines it: ``defender-lessons`` is an allowed main-loop shim and the bash allowlist pins the
    program token, not its operands (the reader lane compiles shims as ``defender-lessons(?: .*)?``),
    so the read never reaches ``decide_read``'s {run_dir, defender_dir} allowlist.

    Unconfined it was a frontmatter-DISCLOSURE primitive for any fenced file the process could
    read. Pinned here on a file outside the corpus carrying a secret: it must not be printed."""
    mod = _load(corpus)
    outside = tmp_path / "not-a-lesson.md"
    outside.write_text("---\napi_key: sk-live-DEADBEEF\n---\nbody\n")

    rc = mod.cmd_show([str(outside)])

    assert rc == 2
    out = capsys.readouterr().out
    assert "sk-live-DEADBEEF" not in out
    assert "api_key" not in out


def test_show_does_not_leak_an_existence_oracle(corpus, tmp_path, capsys):
    """The off-corpus and the absent path must fail IDENTICALLY. They used to be distinguishable
    ("malformed frontmatter" vs "no such lesson"), which is a file-existence oracle over the whole
    filesystem on the main agent's bash lane — exactly what ``_tool_edit_file`` gates itself
    against. A confinement check that still reports WHY is not a confinement check."""
    mod = _load(corpus)
    exists_outside = tmp_path / "exists.md"
    exists_outside.write_text("no frontmatter fence here\n")
    absent = tmp_path / "definitely-absent.md"

    rc_exists = mod.cmd_show([str(exists_outside)])
    err_exists = capsys.readouterr().err
    rc_absent = mod.cmd_show([str(absent)])
    err_absent = capsys.readouterr().err

    assert rc_exists == rc_absent == 2
    assert err_exists.replace(str(exists_outside), "P") == err_absent.replace(str(absent), "P")


def test_show_does_not_follow_a_symlink_out_of_the_corpus(corpus, tmp_path, capsys):
    """The confinement resolves BEFORE it compares, so a symlink planted in the corpus cannot
    smuggle an out-of-tree target back in. (The curator writes into this corpus; a lexical-only
    prefix check would be one authored symlink away from the disclosure above.)"""
    mod = _load(corpus)
    secret = tmp_path / "secret.md"
    secret.write_text("---\napi_key: sk-live-DEADBEEF\n---\nbody\n")
    (corpus / "innocent.md").symlink_to(secret)

    rc = mod.cmd_show([str(corpus / "innocent.md")])

    assert rc == 2
    assert "sk-live-DEADBEEF" not in capsys.readouterr().out


def test_show_reads_a_real_lesson_and_pins_the_encoding(corpus, capsys):
    """The confinement must not break the documented use — and the read is pinned ``utf-8`` like
    the shared walk's, so an accented lesson does not traceback out of ``main()`` where the walk
    would have warn-skipped it. ``--show`` prints the frontmatter only, never the body."""
    _write(corpus, "cafe.md", "name: cafe\ndescription: exfil via café proxy", body="BODYMARKER")
    mod = _load(corpus)

    rc = mod.cmd_show([str(corpus / "cafe.md")])

    out = capsys.readouterr().out
    assert rc == 0
    assert "café" in out
    assert "BODYMARKER" not in out
