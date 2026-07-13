"""Review hardening for the #584 corpus fold (found in review on PR #586).

Three defects the fold left standing in the code it was folding. Each is pinned here against its
fix; none of them is a restatement of the #584 spec (``test_corpus_fold_584.py``), which stands
as approved.

1. **The utf-8 pin was applied to the READ only.** ``iter_lessons`` reads with
   ``encoding="utf-8"`` so a valid UTF-8 lesson survives a C-locale box — but every corpus CLI
   then *prints* that lesson's text through a stdout still decoding under the ambient locale. 42
   checked-in lessons carry non-ASCII (em-dashes in ``description`` above all), so under the same
   locale ``iter_lessons``' own pin is tested against (d5), a bare ``defender-lessons`` over the
   real corpus died with an ascii ``UnicodeEncodeError`` partway through — the defender's
   PLAN-time retrieval exiting non-zero on a silently truncated corpus. Same locale dependence as
   the read bug, one direction over.

2. **The curator's cache signature restated the discovery rule and dropped its robustness.**
   ``existing_observation_ids`` kept a hand-rolled glob for its mtime signature, whose ``stat()``
   was unguarded where the walk's read is guarded — so a dangling symlink (a distinguished member
   of the corpus domain in #584's OWN spec graph, which demands it be warn-skipped) crashed the
   whole curator drain before the agent ever ran.

3. **``iter_lessons`` re-derived the parser's fence offsets** to slice ``Lesson.raw``, the one
   duplicate of the frontmatter parse the "one walk, one reader" fold left in place.
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

from defender._corpus import iter_lesson_paths, iter_lessons
from defender._frontmatter import parse_frontmatter, split_frontmatter
from defender.learning.author.curator import existing_observation_ids
from defender.tests.test_trace_lesson import _mk_run  # noqa: E402

WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
TL_PATH = WORKSPACE_ROOT / "defender" / "learning" / "ops" / "trace_lesson.py"


def _load_trace_lesson():
    """Load the CLI by path — the project idiom for scripts that are run, not imported."""
    spec = importlib.util.spec_from_file_location("trace_lesson_586", TL_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = mod  # @dataclass resolves cls.__module__ through sys.modules
    spec.loader.exec_module(mod)
    return mod

# The locale that makes the ambient-encoding bug observable. CPython >=3.7 COERCES a bare C locale
# to C.UTF-8 (PEP 538) and would hide it, so coercion and UTF-8 mode are both disabled — exactly
# what #584's own d5 test does to drive the read side.
_C_LOCALE_ENV = {
    "PATH": "/usr/bin:/bin",
    "PYTHONCOERCECLOCALE": "0",
    "PYTHONUTF8": "0",
    "LC_ALL": "C",
    "LANG": "C",
}


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
    """demand (review) — a corpus CLI must PRINT a non-ASCII lesson under a C locale, not just read
    one. The read pin alone moves the crash from ``read_text`` to ``print``; it does not remove it.

    Driven in a subprocess because the locale is process-wide, and asserted on the em-dash actually
    reaching stdout — a test that only checked the exit code would stay green against a CLI that
    "handled" the error by dropping the lesson, which is the silent data loss the pin exists to
    prevent."""
    corpus = _corpus_with_an_em_dash(tmp_path)
    script = (
        f"import sys; sys.path.insert(0, {str(WORKSPACE_ROOT)!r})\n"
        "import locale\n"
        "from pathlib import Path\n"
        "from defender._corpus import iter_lessons\n"
        "from defender._io import use_utf8_stdio\n"
        "use_utf8_stdio()\n"
        "print('enc=' + locale.getencoding())\n"
        f"for lesson in iter_lessons(Path({str(corpus)!r})):\n"
        "    print(lesson.fm['description'])\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, env=_C_LOCALE_ENV,
    )

    assert proc.returncode == 0, f"printing a lesson under a C locale crashed:\n{proc.stderr}"
    assert "enc=ANSI_X3.4-1968" in proc.stdout, f"the C locale did not take: {proc.stdout!r}"
    assert "—" in proc.stdout, "the em-dash did not survive the write side of the round trip"


def test_the_real_lessons_cli_survives_a_c_locale_over_the_real_corpus(tmp_path):
    """demand (review) — the end-to-end control for the unit above, on the REAL corpus through the
    REAL entrypoint. This is the command ``SKILL.md`` §Lessons tells the defender to run at PLAN:
    before the fix it exited 1 partway through the corpus, having emitted a truncated listing."""
    proc = subprocess.run(
        [sys.executable, str(WORKSPACE_ROOT / "defender/scripts/lessons/lessons_fm.py")],
        capture_output=True, text=True, env=_C_LOCALE_ENV,
    )

    assert proc.returncode == 0, f"defender-lessons died under a C locale:\n{proc.stderr}"
    assert "Traceback" not in proc.stderr
    assert proc.stdout.count("\n") > 1  # it listed a corpus, it did not stop at the first em-dash


def test_the_curator_preflight_tolerates_what_the_walk_tolerates(tmp_path, capsys):
    """demand (review) — ``iter_lessons`` warn-SKIPS an unreadable lesson, so the id pre-flight
    sitting beside it must not CRASH on one. Its mtime cache signature stat'ed the corpus
    unguarded, so a dangling symlink — a member of the corpus domain #584's own spec graph says
    must be warn-skipped — raised ``FileNotFoundError`` out of the curator drain, before the agent
    ever ran. Exercised on the pre-flight, not on the helper, so it pins the drain's survival."""
    d = tmp_path / "lessons"
    d.mkdir()
    (d / "good.md").write_text("---\nname: good\nsource_observation_ids: [o-1]\n---\nbody\n")
    (d / "dangling.md").symlink_to(d / "never-existed.md")

    ids = existing_observation_ids(d)  # must not raise

    assert ids == {"o-1"}  # the well-formed sibling still contributes its id
    assert [lesson.path.name for lesson in iter_lessons(d)] == ["good.md"]  # walk agrees


def test_the_discovery_rule_has_one_definition(tmp_path):
    """demand (review) — the pre-flight's signature and the walk must not restate the discovery
    rule at each other. They now share ``iter_lesson_paths``, so the set of files the signature
    covers is BY CONSTRUCTION the set the walk yields from.

    The drift this closes is one-directionally dangerous: a signature seeing fewer files than the
    walk leaves the cache stale on a modified lesson, an already-consumed observation id reads as
    unconsumed, and the curator authors a duplicate of a lesson it cannot see."""
    d = tmp_path / "lessons"
    d.mkdir()
    (d / "b.md").write_text("---\nname: b\n---\nbody\n")
    (d / "a.md").write_text("---\nname: a\n---\nbody\n")
    (d / "_TEMPLATE.md").write_text("---\nname: t\n---\nbody\n")  # underscore → skipped
    (d / "notes.txt").write_text("not markdown")  # non-.md → skipped
    (d / "unfenced.md").write_text("no fence")  # DISCOVERED, but unparseable

    discovered = iter_lesson_paths(d)

    assert [p.name for p in discovered] == ["a.md", "b.md", "unfenced.md"]  # sorted, `_`/non-md out
    # Discovery is a superset of the walk by exactly the malformed members — never the reverse.
    walked = {lesson.path for lesson in iter_lessons(d)}
    assert walked < set(discovered)
    assert iter_lesson_paths(d / "does-not-exist") == []  # a missing corpus is empty, not an error


def test_on_skip_receives_exactly_the_warn_skipped_paths(tmp_path, capsys):
    """``on_skip`` is the walk's own report of what it skipped (#590): it must fire for every
    warn-skipped DISCOVERED lesson (malformed and unreadable alike), in walk order, and never
    for a well-formed lesson or a file the discovery rule excludes — so a consumer that
    accounts for skipped lessons (``trace_lesson --all``'s marker rows) needs no second glob
    to diff against, and nothing to race."""
    d = tmp_path / "lessons"
    d.mkdir()
    (d / "good.md").write_text("---\nname: good\n---\nbody\n")
    (d / "unfenced.md").write_text("no fence")  # discovered, unparseable → skipped
    (d / "undecodable.md").write_bytes(b"---\nname: u\n---\n\xff")  # discovered, unreadable → skipped
    (d / "_TEMPLATE.md").write_text("no fence either")  # excluded by discovery → NOT a skip

    skipped: list[Path] = []
    yielded = [lesson.path.name for lesson in iter_lessons(d, on_skip=skipped.append)]

    assert yielded == ["good.md"]
    assert [p.name for p in skipped] == ["undecodable.md", "unfenced.md"]  # walk (sorted) order
    assert "_TEMPLATE" not in capsys.readouterr().err  # excluded-by-discovery is not "skipped"


def test_lesson_raw_is_the_slice_the_parser_consumed(tmp_path):
    """demand (review) — ``Lesson.raw`` comes back FROM the parser that computed the fence offsets,
    rather than being re-derived by the walk with its own ``text[4:find("\\n---", 4)]``.

    The old duplicate was safe only by borrowing an invariant of another module's internals, and it
    failed SILENTLY: widen ``parse_frontmatter``'s grammar (a tolerated BOM, a ``...`` close fence)
    and the walk's ``find`` returns -1, ``raw`` becomes the whole document minus its last character,
    and ``cmd_grep`` — the frontmatter-ONLY grep — starts matching on body text. Pinned by tying
    ``raw`` to the parser's own output."""
    text = "---\nname: x\ndescription: d\n---\n\nbody --- with a fence-like line\n"
    fm, raw, body = split_frontmatter(text)

    assert raw == "name: x\ndescription: d"  # exactly between the fences
    assert "body" not in raw  # the grep surface cannot see the body
    assert (fm, body) == parse_frontmatter(text)  # the 2-value view is the same parse

    (corpus := tmp_path / "lessons").mkdir()
    (corpus / "x.md").write_text(text)
    lesson = next(iter(iter_lessons(corpus)))
    assert lesson.raw == raw  # the walk yields the parser's slice, not its own


def test_all_windows_each_count_on_the_lessons_created_at(tmp_path, capsys):
    """demand (review) — ``--all`` must window each lesson's case count to loads at/after that
    lesson's ``created_at`` (its CURRENT incarnation), not report a lifetime total.

    This property was structurally protected on main, where ``--all`` and the single-lesson path
    shared one ``lesson_meta()`` helper that three tests asserted on. #584 deletes that helper and
    inlines the extraction TWICE; the single-lesson copy is still pinned, the ``--all`` copy is
    pinned by nothing — mutating it to ``created_at = None`` leaves the whole suite green. Every
    ``--all`` test in the #584 spec is vacuous on the window: three use empty runs dirs (0 hits
    either way) and the fourth's fixture lesson carries no ``created_at`` at all, so the window
    never engages.

    Driven with a load on BOTH sides of ``created_at``, so an unwindowed count reads 2 and a
    windowed one reads 1. The failure is silent — exit 0, a plausible number — and the number is
    the entire product of the CLI: a rewritten lesson would inherit the case count of the lesson it
    replaced."""
    tl = _load_trace_lesson()
    corpus = tmp_path / "lessons"
    corpus.mkdir()
    (corpus / "rewritten.md").write_text(
        "---\nname: rewritten\ndescription: d\ncreated_at: 2026-06-04\n---\nbody\n"
    )
    runs = tmp_path / "runs"
    runs.mkdir()
    # the PREVIOUS incarnation's load — before created_at, must NOT be counted
    _mk_run(runs, "caseOld", disposition="benign",
            loads=[{"lesson_name": "rewritten", "ts": "2026-06-01T00:00:00+00:00"}])
    # the current incarnation's load — after created_at, must be counted
    _mk_run(runs, "caseNew", disposition="malicious",
            loads=[{"lesson_name": "rewritten", "ts": "2026-06-05T00:00:00+00:00"}])

    assert tl.main(["--all", "--lessons-dir", str(corpus), "--runs-dir", str(runs)]) == 0

    assert capsys.readouterr().out.splitlines() == ["rewritten\td\t1"]  # 1, not 2
