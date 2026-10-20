"""Review hardening for the corpus fold: utf-8 write pin under a C locale, pre-flight tolerance of unreadable lessons, one discovery rule, on_skip, Lesson.raw, windowed --all counts."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from defender.tests.support.shared.contracts._by_path import load_trace_lesson

from defender.knowledge._corpus import iter_lesson_paths, iter_lessons
from defender._frontmatter import parse_frontmatter, split_frontmatter
from defender.learning.author.lessons.run import build_author_config, existing_finding_ids
from defender.learning.core.config import LoopPaths
from defender.tests.support.learning.curation._curator1134 import author_trees
from defender.tests.support.shared.contracts._locale import C_LOCALE_ENV
from defender.tests.learning.retrieval.test_trace_lesson import _mk_run  # noqa: E402
from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H1105  # #1105 PR 2 (J8, declared change 10)
from defender.tests.support.learning.curation._curator1134 import open_state

WORKSPACE_ROOT = Path(__file__).resolve().parents[4]

#: The tenant whose runs the tracer walks — #1105 PR 2 (J8, declared change 10).
TID = H1105.T_ID


def _tenant_runs() -> Path:
    """The tenant's natural runs folder `<data root>/<T>/runs`, with its tenant record — #1105 PR 2
    (J8, declared change 10): the tracer takes a required `--tenant` and walks that tenant's runs
    (`--runs-dir` is gone)."""
    from defender.tests.support.shared.contracts._data_root_1078 import current_data_root

    root = current_data_root()
    H1105.tenant(root, TID)
    runs = root / TID / "runs"
    runs.mkdir(exist_ok=True)
    return runs


def _load_trace_lesson():
    return load_trace_lesson("trace_lesson_586")


def _corpus_with_an_em_dash(tmp_path: Path) -> Path:
    """A corpus whose description carries U+2014 — the real corpus's most common non-ASCII char."""
    d = tmp_path / "lessons"
    d.mkdir()
    (d / "em-dash.md").write_bytes(
        "---\nname: em-dash\ndescription: auth-log leads expose logins — not post-auth behavior\n"
        "---\nbody\n".encode()
    )
    (d / "ascii.md").write_text("---\nname: ascii\ndescription: plain\n---\nbody\n")
    return d


def test_the_utf8_pin_covers_the_write_not_only_the_read(tmp_path):
    corpus = _corpus_with_an_em_dash(tmp_path)
    script = (
        f"import sys; sys.path.insert(0, {str(WORKSPACE_ROOT)!r})\n"
        "import locale\n"
        "from pathlib import Path\n"
        "from defender.knowledge._corpus import iter_lessons\n"
        "from defender._io import use_utf8_stdio\n"
        "use_utf8_stdio()\n"
        "print('enc=' + locale.getencoding())\n"
        f"for lesson in iter_lessons(Path({str(corpus)!r})):\n"
        "    print(lesson.fm['description'])\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, env=C_LOCALE_ENV,
    )

    assert proc.returncode == 0, f"printing a lesson under a C locale crashed:\n{proc.stderr}"
    assert "enc=ANSI_X3.4-1968" in proc.stdout, f"the C locale did not take: {proc.stdout!r}"
    assert "—" in proc.stdout, "the em-dash did not survive the write side of the round trip"


def test_the_real_lessons_cli_survives_a_c_locale_over_the_real_corpus(tmp_path):
    proc = subprocess.run(
        [str(WORKSPACE_ROOT / "defender/bin/defender-lessons")],
        capture_output=True, text=True, env=C_LOCALE_ENV,
    )

    assert proc.returncode == 0, f"defender-lessons died under a C locale:\n{proc.stderr}"
    assert "Traceback" not in proc.stderr
    assert proc.stdout.count("\n") > 1


def test_the_curator_preflight_tolerates_what_the_walk_tolerates(tmp_path, capsys):
    """demand (review) — ``iter_lessons`` warn-SKIPS an unreadable lesson, so the id pre-flight
    sitting beside it must not CRASH on one."""
    paths = LoopPaths(repo_root=tmp_path)
    cfg = build_author_config(paths, trees=author_trees(paths), state=open_state(paths))
    d = cfg.corpus_dir
    d.mkdir(parents=True, exist_ok=True)  # the trees made the mount point (a drain's always exists)
    (d / "good.md").write_text("---\nname: good\nsource_finding_ids: [o-1]\n---\nbody\n")
    (d / "dangling.md").symlink_to(d / "never-existed.md")

    ids = existing_finding_ids(cfg)

    assert ids == {"o-1"}
    assert [lesson.path.name for lesson in iter_lessons(d)] == ["good.md"]


def test_the_discovery_rule_has_one_definition(tmp_path):
    """demand (review) — the pre-flight's signature and the walk must not restate the discovery rule
    at each other."""
    d = tmp_path / "lessons"
    d.mkdir()
    (d / "b.md").write_text("---\nname: b\n---\nbody\n")
    (d / "a.md").write_text("---\nname: a\n---\nbody\n")
    (d / "_TEMPLATE.md").write_text("---\nname: t\n---\nbody\n")
    (d / "notes.txt").write_text("not markdown")
    (d / "unfenced.md").write_text("no fence")

    discovered = iter_lesson_paths(d)

    assert [p.name for p in discovered] == ["a.md", "b.md", "unfenced.md"]
    walked = {lesson.path for lesson in iter_lessons(d)}
    assert walked < set(discovered)
    assert iter_lesson_paths(d / "does-not-exist") == []


def test_on_skip_receives_exactly_the_warn_skipped_paths(tmp_path, capsys):
    d = tmp_path / "lessons"
    d.mkdir()
    (d / "good.md").write_text("---\nname: good\n---\nbody\n")
    (d / "unfenced.md").write_text("no fence")
    (d / "undecodable.md").write_bytes(b"---\nname: u\n---\n\xff")
    (d / "_TEMPLATE.md").write_text("no fence either")

    skipped: list[Path] = []
    yielded = [lesson.path.name for lesson in iter_lessons(d, on_skip=skipped.append)]

    assert yielded == ["good.md"]
    assert [p.name for p in skipped] == ["undecodable.md", "unfenced.md"]
    assert "_TEMPLATE" not in capsys.readouterr().err


def test_lesson_raw_is_the_slice_the_parser_consumed(tmp_path):
    """demand (review) — ``Lesson.raw`` comes back FROM the parser that computed the fence offsets,
    rather than being re-derived by the walk with its own ``text[4:find("\\n---", 4)]``."""
    text = "---\nname: x\ndescription: d\n---\n\nbody --- with a fence-like line\n"
    fm, raw, body = split_frontmatter(text)

    assert raw == "name: x\ndescription: d"
    assert "body" not in raw
    assert (fm, body) == parse_frontmatter(text)

    (corpus := tmp_path / "lessons").mkdir()
    (corpus / "x.md").write_text(text)
    lesson = next(iter(iter_lessons(corpus)))
    assert lesson.raw == raw


def test_all_windows_each_count_on_the_lessons_created_at(tmp_path, capsys):
    tl = _load_trace_lesson()
    corpus = tmp_path / "lessons"
    corpus.mkdir()
    (corpus / "rewritten.md").write_text(
        "---\nname: rewritten\ndescription: d\ncreated_at: 2026-06-04\n---\nbody\n"
    )
    runs = _tenant_runs()  # #1105 PR 2 (J8, declared change 10): run ids, `--tenant`
    _mk_run(runs, "case-old", disposition="benign",
            loads=[{"lesson_name": "rewritten", "ts": "2026-06-01T00:00:00+00:00"}])
    _mk_run(runs, "case-new", disposition="malicious",
            loads=[{"lesson_name": "rewritten", "ts": "2026-06-05T00:00:00+00:00"}])

    assert tl.main(["--all", "--lessons-dir", str(corpus), "--tenant", TID]) == 0, capsys.readouterr().err

    assert capsys.readouterr().out.splitlines() == ["rewritten\td\t1\t0"]
