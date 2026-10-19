"""Executable spec for #584 — the last fold of the walk-duplication arc (#577 → #582 → #584)."""
from __future__ import annotations

import importlib
import importlib.util
import subprocess
import sys
import textwrap
from pathlib import Path

from defender.tests.support.shared.contracts._by_path import load_trace_lesson


from defender.learning.frontend import serialize  # noqa: E402
from defender.hooks import record_lesson_load  # noqa: E402

from defender.tests.support.shared.contracts._locale import C_LOCALE_ENV  # noqa: E402
from defender.tests.learning.curation.test_curator_manifest import _findings_lesson  # noqa: E402
from defender.tests.learning.retrieval.test_trace_lesson import _mk_run  # noqa: E402
from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H1105  # #1105 PR 2 (J8, declared change 10)

WORKSPACE_ROOT = Path(__file__).resolve().parents[4]
DEFENDER = WORKSPACE_ROOT / "defender"

#: The tenant whose runs the tracer walks — #1105 PR 2 (J8, declared change 10).
TID = H1105.T_ID


def _tenant_runs() -> Path:
    """The tenant's natural runs folder `<data root>/<T>/runs`, with its tenant record — #1105 PR 2 (J8, declared..."""
    from defender.tests.support.shared.contracts._data_root_1078 import current_data_root

    root = current_data_root()
    H1105.tenant(root, TID)
    runs = root / TID / "runs"
    runs.mkdir(exist_ok=True)
    return runs


def _corpus_of(tmp_path: Path, *stems: str, name: str = "lessons") -> Path:
    corpus = tmp_path / name
    corpus.mkdir(parents=True, exist_ok=True)
    for stem in stems:
        _findings_lesson(corpus, stem)
    return corpus


def _frontmatter_error_members(corpus: Path) -> dict[str, str]:
    """The five FrontmatterError members of the corpus domain, one file each."""
    (corpus / "unfenced.md").write_text("no frontmatter fence at all\n")
    (corpus / "no-close.md").write_text("---\nname: nc\nnever closes the fence\n")
    (corpus / "bad-yaml.md").write_text("---\nname: [unclosed\n---\nbody\n")
    (corpus / "null-doc.md").write_text("---\n\n---\nbody\n")
    (corpus / "bom.md").write_bytes(b"\xef\xbb\xbf---\nname: bom\n---\nbody\n")
    return {
        "unfenced.md": "missing leading fence",
        "no-close.md": "missing closing fence",
        "bad-yaml.md": "invalid YAML",
        "null-doc.md": "a non-mapping (None) document",
        "bom.md": "a UTF-8 BOM before the fence",
    }


def _undecodable(corpus: Path, name: str = "undecodable.md") -> Path:
    p = corpus / name
    p.write_bytes(b"---\nname: c\n---\n\xff\xfe not utf-8\n")
    return p


def _oserror_members(corpus: Path) -> dict[str, str]:
    """The two OSError members reachable as ROOT. A ``chmod 000`` file is VACUOUS here — the suite runs as euid..."""
    (corpus / "foo.md").mkdir()
    (corpus / "dead.md").symlink_to(corpus / "nowhere-at-all.md")
    return {"foo.md": "IsADirectoryError", "dead.md": "FileNotFoundError"}


def _crlf_lesson(corpus: Path, stem: str = "crlf") -> Path:
    """A CRLF lesson whose BODY contains a line that looks like frontmatter. Both halves matter: the CRLF pins..."""
    p = corpus / f"{stem}.md"
    p.write_bytes(
        b"---\r\n"
        b"name: crlf\r\n"
        b"telemetry_source: [sshd, auditd]\r\n"
        b"---\r\n"
        b"body mentions telemetry_source: sshd here\r\n"
    )
    return p


def _fixture_defender(tmp_path: Path) -> Path:
    """A fake ``defender/`` root with the three corpus dirs — the tree ``build_view(defender_dir=)`` is pointed..."""
    root = tmp_path / "defender"
    for d in ("lessons", "lessons-actor", "lessons-environment"):
        (root / d).mkdir(parents=True)
    return root


def _titles(view: dict) -> set[str]:
    return {rec["title"] for g in view["groups"].values() for rec in g["lessons"]}


def _records(view: dict) -> list[dict]:
    return [rec for g in view["groups"].values() for rec in g["lessons"]]


def test_d2_fm_and_raw_are_discriminable_by_value(tmp_path):
    """demand: d2 — the positional-swap fault stated on the VALUES, not on the shape."""
    mod = importlib.import_module("defender.knowledge._corpus")
    lesson = next(iter(mod.iter_lessons(_corpus_of(tmp_path, "good"))))

    assert isinstance(lesson.fm, dict)
    assert lesson.fm["telemetry_source"] == ["sshd", "auditd"]
    assert isinstance(lesson.raw, str)
    assert "telemetry_source: [sshd, auditd]" in lesson.raw
    assert "'telemetry_source':" not in lesson.raw


def test_d3_raw_is_the_slice_the_parser_consumed(tmp_path, capsys):
    """demand: d3 — ``Lesson.raw`` is EXACTLY the text between the fences that ``parse_frontmatter`` handed..."""
    mod = importlib.import_module("defender.knowledge._corpus")
    corpus = tmp_path / "lessons"
    corpus.mkdir()
    _crlf_lesson(corpus)

    lesson = next(iter(mod.iter_lessons(corpus)))
    assert capsys.readouterr().err == ""

    assert "\r" not in lesson.raw
    assert lesson.raw == "name: crlf\ntelemetry_source: [sshd, auditd]"
    assert not lesson.raw.startswith("---")
    assert not lesson.raw.endswith("---")
    assert "body mentions" not in lesson.raw
    assert lesson.body == "body mentions telemetry_source: sshd here"


def test_d5_utf8_pin_saves_a_valid_lesson_under_a_c_locale(tmp_path):
    """demand: d5 (domain-outcome, R4: READ_ENCODING crosses_validation) — ``iter_lessons`` reads with an..."""
    corpus = tmp_path / "lessons"
    corpus.mkdir()
    (corpus / "cafe-lesson.md").write_bytes(
        "---\nname: cafe-lesson\ndescription: café au lait\n---\nbody\n".encode()
    )
    (corpus / "ascii-lesson.md").write_text("---\nname: ascii-lesson\n---\nbody\n")

    script = textwrap.dedent(f"""
        import locale, sys
        sys.path.insert(0, {str(WORKSPACE_ROOT)!r})
        from pathlib import Path
        from defender.knowledge._corpus import iter_lessons
        print("enc=" + locale.getencoding())
        stems = sorted(lesson.path.stem for lesson in iter_lessons(Path({str(corpus)!r})))
        print("stems=" + ",".join(stems))
    """)
    proc = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True,
        env=C_LOCALE_ENV,
    )
    assert proc.returncode == 0, f"the C-locale walk did not complete:\n{proc.stderr}"
    assert "enc=ANSI_X3.4-1968" in proc.stdout, f"the C locale did not take: {proc.stdout!r}"
    assert "stems=ascii-lesson,cafe-lesson" in proc.stdout, (
        "the café lesson was warn-SKIPPED under a C locale — the read is still locale-dependent:"
        f"\nstdout={proc.stdout!r}\nstderr={proc.stderr!r}"
    )


def test_d6_empty_frontmatter_mapping_is_yielded(tmp_path, capsys):
    """demand: d6 (domain-outcome, R4: the FALSY member of a falsy_valid domain) — a lesson whose frontmatter is..."""
    mod = importlib.import_module("defender.knowledge._corpus")
    corpus = _corpus_of(tmp_path, "normal")
    (corpus / "empty-fm.md").write_text("---\n{}\n---\nbody\n")

    by_stem = {lesson.path.stem: lesson for lesson in mod.iter_lessons(corpus)}
    assert set(by_stem) == {"normal", "empty-fm"}
    assert by_stem["empty-fm"].fm == {}
    assert by_stem["empty-fm"].body == "body"
    assert capsys.readouterr().err == ""


def test_d7_frontmatter_error_members_are_warn_skipped_by_name(tmp_path, capsys):
    """demand: d7 (domain-outcome, R4) — every ``FrontmatterError`` member of the corpus domain is warn-skipped,..."""
    mod = importlib.import_module("defender.knowledge._corpus")
    corpus = _corpus_of(tmp_path, "good")
    members = _frontmatter_error_members(corpus)

    yielded = [lesson.path.stem for lesson in mod.iter_lessons(corpus)]
    assert yielded == ["good"]

    err = capsys.readouterr().err
    for name, why in members.items():
        assert name in err, f"{name} ({why}) was not named on stderr"
        assert err.count(name) == 1, f"{name} warned more than once"


def test_d9_oserror_members_are_warn_skipped(tmp_path, capsys):
    """demand: d9 (domain-outcome, R4) — the OSError arm of the guard, exercised by the two members that reach it..."""
    mod = importlib.import_module("defender.knowledge._corpus")
    corpus = _corpus_of(tmp_path, "good")
    members = _oserror_members(corpus)

    yielded = [lesson.path.stem for lesson in mod.iter_lessons(corpus)]
    assert yielded == ["good"]

    err = capsys.readouterr().err
    for name, exc in members.items():
        assert name in err, f"{name} ({exc}) was not named on stderr"


def test_d12_build_view_takes_a_defaulted_corpus_root(tmp_path):
    """demand: d12 (seam) — ``build_view`` gains a DEFAULTED corpus-root parameter, ``build_view(defender_dir:..."""
    root = _fixture_defender(tmp_path)
    _findings_lesson(root / "lessons", "fixture-only-lesson")

    view = serialize.build_view(defender_dir=root)
    assert _titles(view) == {"fixture-only-lesson"}

    real = serialize.build_view()
    assert set(real["groups"]) == {"defender", "actor", "environment", "questioner"}  # 1007 M7: a fourth group
    assert _titles(real) != _titles(view)
    assert all(g["lessons"] for g in real["groups"].values())


def test_d13_source_path_keys_off_the_injected_root(tmp_path):
    """demand: d13 — ``_normalize`` computes ``source_path`` relative to ``defender_dir.parent``, not the module..."""
    root = _fixture_defender(tmp_path)
    _findings_lesson(root / "lessons", "fixture-lesson")

    rec = _records(serialize.build_view(defender_dir=root))[0]
    assert rec["source_path"] == "defender/lessons/fixture-lesson.md"
    assert not Path(rec["source_path"]).is_absolute()

    for real in _records(serialize.build_view()):
        assert real["source_path"].startswith("defender/lessons")
        assert (WORKSPACE_ROOT / real["source_path"]).is_file()


def test_d14_frontend_truth_table_has_no_silent_subtraction(tmp_path, capsys):
    """demand: d14 — the FULL classification truth table over one fixture corpus, not a membership check."""
    root = _fixture_defender(tmp_path)
    corpus = root / "lessons"
    _findings_lesson(corpus, "good")
    (corpus / "empty-fm.md").write_text("---\n{}\n---\nbody\n")
    _frontmatter_error_members(corpus)
    _undecodable(corpus)
    (corpus / "_TEMPLATE.md").write_text("---\nname: t\n---\nbody\n")

    view = serialize.build_view(defender_dir=root)
    assert _titles(view) == {"good", "empty-fm", "unfenced", "no-close", "bad-yaml", "null-doc",
                             "bom", "undecodable"}
    assert {rec["group"] for rec in _records(view)} == {"defender"}
    by_title = {rec["title"]: rec for rec in _records(view)}
    assert by_title["empty-fm"]["status"] == "live"
    for skipped in ("unfenced", "no-close", "bad-yaml", "null-doc", "bom", "undecodable"):
        assert by_title[skipped]["status"] == "malformed", skipped

    err = capsys.readouterr().err
    for name in ("unfenced.md", "no-close.md", "bad-yaml.md", "null-doc.md", "bom.md",
                 "undecodable.md"):
        assert name in err, f"{name} was dropped without being named on stderr"
    assert "_TEMPLATE" not in err


def test_d15_empty_mapping_record_shape(tmp_path):
    """demand: d15 (shape) — the ``{}``-lesson's rendered RECORD, field by field: ``title == path.stem`` (no..."""
    root = _fixture_defender(tmp_path)
    (root / "lessons" / "empty-fm.md").write_text("---\n{}\n---\nthe body\n")

    rec = _records(serialize.build_view(defender_dir=root))[0]
    assert rec["title"] == "empty-fm"
    assert rec["description"] == ""
    assert rec["status"] == "live"
    assert rec["metadata"] == {}
    assert rec["body"] == "the body"
    assert set(rec) >= {"group", "title", "description", "status", "source_path", "metadata", "body"}


def test_d16_build_completes_despite_a_bad_lesson(tmp_path, capsys):
    """demand: d16 — with an UNDECODABLE lesson AND an OSError lesson (a directory named ``foo.md``) in the..."""
    root = _fixture_defender(tmp_path)
    corpus = root / "lessons"
    _findings_lesson(corpus, "survivor")
    _undecodable(corpus)
    _oserror_members(corpus)

    view = serialize.build_view(defender_dir=root)
    assert _titles(view) == {"survivor", "undecodable", "foo", "dead"}
    assert {r["title"] for r in _records(view) if r["status"] != "malformed"} == {"survivor"}

    err = capsys.readouterr().err
    for name in ("undecodable.md", "foo.md", "dead.md"):
        assert name in err


def test_d17_stdout_stays_a_json_protocol(tmp_path, capsys):
    """demand: d17 (negative) — ``serialize.py --stdout`` is an api preview, i.e. a PROTOCOL: over a corpus..."""
    root = _fixture_defender(tmp_path)
    corpus = root / "lessons"
    _findings_lesson(corpus, "good")
    _frontmatter_error_members(corpus)
    _undecodable(corpus)

    serialize.build_view(defender_dir=root)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "undecodable.md" in captured.err


def test_d21_trace_all_walks_the_shared_iterator(tmp_path, capsys):
    tl = load_trace_lesson("trace_lesson_584")
    _tenant_runs()  # #1105 PR 2 (J8, declared change 10)
    corpus = _corpus_of(tmp_path, "alpha", "beta")
    (corpus / "_TEMPLATE.md").write_text("---\nname: t\ndescription: template\n---\nbody\n")
    (corpus / "unfenced.md").write_text("no fence at all\n")
    _undecodable(corpus)

    rc = tl.main(["--all", "--lessons-dir", str(corpus), "--tenant", TID])  # #1105 PR 2 (J8, declared change 10)
    captured = capsys.readouterr()
    assert rc == 0, captured.err

    lines = [ln for ln in captured.out.splitlines() if ln.strip()]
    assert [ln.split("\t")[0] for ln in lines] == ["alpha", "beta", "undecodable", "unfenced"]
    assert all(len(ln.split("\t")) == 4 for ln in lines)
    marker_rows = [ln for ln in lines if "(malformed lesson" in ln]
    assert [ln.split("\t")[0] for ln in marker_rows] == ["undecodable", "unfenced"]
    assert "_TEMPLATE" not in captured.out
    assert "unfenced.md" in captured.err
    assert "undecodable.md" in captured.err



def test_d22_missing_lessons_dir_follows_the_seam(tmp_path, capsys):
    """demand: d22 — the ``if not lessons_dir.is_dir(): return 1`` guard keys on the RESOLVED dir, not on the..."""
    tl = load_trace_lesson("trace_lesson_584")
    missing = tmp_path / "no-such-corpus"

    # #1105 PR 2 (J8, declared change 10): `--tenant` is required
    assert tl.main(["--all", "--lessons-dir", str(missing), "--tenant", TID]) == 1
    err = capsys.readouterr().err
    assert f"no lessons dir: {missing}" in err
    assert str(tl.LESSONS_DIR) not in err


def test_d23_lesson_identity_is_the_stem_cross_module(tmp_path, capsys):
    tl = load_trace_lesson("trace_lesson_584")
    _tenant_runs()  # #1105 PR 2 (J8, declared change 10)
    corpus = _corpus_of(tmp_path / "defender", "foo-bar")
    lesson_path = corpus / "foo-bar.md"

    oracle = record_lesson_load.lesson_name(str(lesson_path))
    assert oracle == "foo-bar"

    # #1105 PR 2 (J8, declared change 10)
    assert tl.main(["--all", "--lessons-dir", str(corpus), "--tenant", TID]) == 0, capsys.readouterr().err
    first_column = capsys.readouterr().out.splitlines()[0].split("\t")[0]
    assert first_column == oracle



def test_d23b_stem_wins_when_the_frontmatter_name_disagrees(tmp_path, capsys):
    tl = load_trace_lesson("trace_lesson_584")
    corpus = tmp_path / "defender" / "lessons"
    corpus.mkdir(parents=True)
    (corpus / "foo-bar.md").write_text(
        "---\nname: foo_bar\ndescription: d\ncreated_at: 2026-06-04\n---\nbody\n"
    )
    runs = _tenant_runs()  # #1105 PR 2 (J8, declared change 10): run ids, `--tenant`
    _mk_run(runs, "case-a", disposition="malicious",
            loads=[{"lesson_name": "foo-bar", "ts": "2026-06-05T00:00:00+00:00"}])

    assert tl.main(["--all", "--lessons-dir", str(corpus), "--tenant", TID]) == 0, capsys.readouterr().err
    assert capsys.readouterr().out.splitlines() == ["foo-bar\td\t1\t0"]



def test_d24_single_lesson_path_keeps_its_own_guarded_read(tmp_path, capsys):
    """demand: d24 — ``iter_lessons`` is a DIRECTORY walk and structurally cannot serve ``trace_lesson <name>``,..."""
    tl = load_trace_lesson("trace_lesson_584")
    _tenant_runs()  # #1105 PR 2 (J8, declared change 10)
    corpus = _corpus_of(tmp_path, "good")
    _undecodable(corpus, "corrupt.md")
    base = ["--lessons-dir", str(corpus), "--tenant", TID]

    assert tl.main(["nope", *base]) == 1
    assert f"no such lesson: {corpus / 'nope.md'}" in capsys.readouterr().err

    assert tl.main(["corrupt", *base]) == 1
    err = capsys.readouterr().err
    assert "corrupt.md" in err
    assert "Traceback" not in err
    assert len([ln for ln in err.splitlines() if ln.strip()]) == 1

    assert tl.main(["good", *base]) == 0
    assert capsys.readouterr().out.startswith("# good")
