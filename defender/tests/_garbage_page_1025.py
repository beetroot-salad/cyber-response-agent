"""The garbage-page control for #1025's page suite — an INSTRUMENT, never a test.

WHY THIS EXISTS. `spec-graph nullstub` proves a suite discriminates by running it against a
null object every attribute of which is callable, falsy and equal to nothing. For a
whole-page-render suite that instrument is structurally thin (90-mechanical.md §1): the null
`render_episode` returns a null, `_episode_1025.render()`'s `Path(out) == …` conversion throws
`TypeError` for every test that reaches the page through the shared helper, and 151 of 179
tests fail on that ONE line — which proves the helper is wired, not that any test's content
assertion can fail. Nothing in that run distinguishes a suite that reads the page from one
that only checks the file exists. The human's decision at the second §7 sitting
(71-resolutions-f.md, row "90 §1") was the non-recommended option: build a second instrument —
a stub `render_episode` that returns the REAL path and writes an empty or garbage page — and
prove every content-asserting test goes red against it.

THREE STUBS, each a stronger lie than the last, selected by `GARBAGE_PAGE_1025=<mode>`:

  empty     — `learning.html` is written with zero bytes.
  garbage   — a well-formed but content-free document (`<!doctype html>…skeleton…</html>`):
              a `<title>`, a `<header>`, six empty sections under NO ids the suite names.
  skeleton  — the sharpest: every ANCHOR the suite reaches for exists (the six `sec-*`
              sections, `stage-timing` and a `stage-<step>` row per `STEPS` member, a
              `world-<x>` / `leads-<x>` pair per directory the stub can list under `worlds/`
              and `runs/`, four `vd-tile`s, a `vd-badge`, a `vd-meta`, a `vd-acct`), each
              holding the word "skeleton" and nothing derived from any record. A test that
              only checks its anchor exists is GREEN here; a test that reads content is red on
              its own assertion rather than on a missing section.

`main(argv)` in every mode is equally dumb: it writes the page for `argv[0]` (swallowing the
`OSError` a file or a missing directory raises), prints the path and returns 0 — no refusal
arm, no stderr line, no `family.yaml` check.

The stub is injected into `sys.modules` under the page module's name by a pytest plugin
(`pytest_configure`), so no file is ever written into `defender/scripts/visualize/` and nothing
is left behind when the run dies. Its code object carries the page module's file name, so
`_episode_1025.when_inside`'s frame marker sees it (the fault-injection tests then fail on
their own `seen["hit"]` control, not on a timeout).

HOW TO RUN (from the repo root, the shared venv, PYTHONPATH at the worktree root):

    PYTHONPATH=. defender/.venv/bin/python -m defender.tests._garbage_page_1025 \
        [--modes empty,garbage,skeleton] [--record defender/tests/_garbage_page_1025.record.md]

It runs the five suite files once per mode (no xdist; the plugin records per-test outcomes in
the process that ran them), classifies every test — `green` (the finding: a test the stub
satisfies), `red-content` (the test's own observation refused the page: an `AssertionError`
or a `pytest.raises` that saw no raise on a suite/fixture line, or a lookup on the test's own
line), `red-head` (a reason independent of the page, verified by message — `HEAD_REASONS`:
the launcher hook that does not call the page on HEAD, a reader screen or accessor that does
not exist yet, a lint gate, a subprocess that cannot import an in-memory module, an in-frame
fault injection the stub is too fast for), `red-other` (raised outside the suite: the stub
itself crashed, or a census read the stub's non-existent file), `skipped` — and writes the
record beside this file. Read the record; the frontier
that commissioned the run copies its summary.

NEVER COLLECTED: the file name does not match `test_*.py`, it defines no `test_` function,
and the plugin installs nothing unless `GARBAGE_PAGE_1025` is set. It is committed beside the
fixture because the human asked for the instrument and its run record to live with the suite
(71-resolutions-f.md) — a re-run after any suite change is one command.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import subprocess
import sys
import types
from collections import Counter
from pathlib import Path
from typing import Any

PAGE_MODULE = "defender.scripts.visualize.visualize_episode"
PAGE_FILE = "visualize_episode.py"
PAGE_NAME = "learning.html"
MODES = ("empty", "garbage", "skeleton")
MODE_ENV = "GARBAGE_PAGE_1025"
OUT_ENV = "GARBAGE_PAGE_1025_OUT"
SUITE = tuple(f"defender/tests/test_1025_page_{part}.py"
              for part in ("contract", "verdict", "worlds", "stages", "records"))
CONTENT_FILES = tuple(Path(p).name for p in SUITE) + ("_episode_1025.py",)
STEPS = ("questioner", "staging", "review", "verify", "runs", "judge")

#: Tests whose red against the stub is a HEAD-missing dependency or an instrument limit — a
#: reason INDEPENDENT of the page's content — keyed by a test-name fragment and verified by
#: the failure message (a test here that instead fails on the page is counted as red-content):
#: the launcher hook that does not call the page on HEAD, the root-stamp accessor and the
#: world-archive screen that do not exist yet, the two lint gates, a subprocess that cannot
#: import an in-memory module, and the in-frame fault injection a microsecond stub is too
#: fast for (`when_inside` re-arms every millisecond).
HEAD_REASONS: tuple[tuple[str, str, str], ...] = (
    ("the_launcher_renders_the_page_after_the_judge_frame", "the launcher did not write", "launcher hook absent on HEAD"),
    ("a_render_fault_is_printed_and_changes_neither", "", "launcher hook absent on HEAD"),
    ("held_teardown_fault_after_a_completed_grade", "the launcher did not write", "launcher hook absent on HEAD"),
    ("how_the_operator_learns_where_the_page_is", "", "launcher hook absent on HEAD"),
    ("an_episode_with_no_judge_yaml_still_renders", "the launcher did not write", "launcher hook absent on HEAD"),
    ("a_sibling_process_exited_non_zero", "the launcher did not write", "launcher hook absent on HEAD"),
    ("the_root_stamp_reader_lives_in_the_record_names_home", "FAMILY_STAMP_NAME", "accessor absent on HEAD"),
    ("grade_episode_reads_world_archive_through_the_same_screen", "is None", "reader screen absent on HEAD"),
    ("judge_render_reads_world_archive_through_the_same_screen", "DID NOT RAISE", "reader screen absent on HEAD"),
    ("the_four_baseline_entries_naming_this_page", "", "vulture baseline (not a page test)"),
    ("the_new_modules_tree_reads_are_censused", "", "tree-read lint census (not a page test)"),
    ("byte_identity_across_two_interpreter_processes", "ModuleNotFoundError", "a subprocess cannot import the in-memory stub"),
    ("an_interrupt_during_the_render", "DID NOT RAISE", "fault injection: the stub is too fast for when_inside"),
    ("a_render_that_raises_midway_keeps_the_previous_page", "DID NOT RAISE", "fault injection: the stub is too fast for when_inside"),
    ("judge_yaml_replaced_by_a_concurrent_re_grade", "never landed", "fault injection: the stub is too fast for when_inside"),
    ("draw_or_judge_yaml_record_is_rewritten_mid_render", "never landed", "fault injection: the stub is too fast for when_inside"),
)

# ---------------------------------------------------------------------------------------
# The stub — dumb on purpose. It decides nothing and reads no record.
# ---------------------------------------------------------------------------------------

_STUB_SOURCE = '''
import os
import sys
from pathlib import Path

MODE = %(mode)r
PAGE_NAME = %(page_name)r
STEPS = %(steps)r


def _labels(episode_dir):
    """Directory names only — the one thing a garbage page may lift off the tree."""
    out = []
    worlds = Path(episode_dir) / "worlds"
    if worlds.is_dir():
        out.extend(sorted(p.name for p in worlds.iterdir()))
    runs = Path(episode_dir) / "runs"
    if runs.is_dir():
        for p in sorted(runs.iterdir()):
            out.append(p.name.split("-", 1)[-1] if "-" in p.name else p.name)
    seen = []
    for label in out:
        if label not in seen:
            seen.append(label)
    return seen


def _document(episode_dir):
    if MODE == "empty":
        return b""
    if MODE == "garbage":
        return ("<!doctype html><html><head><meta charset=\\"utf-8\\"><title>skeleton</title></head>"
                "<body><header>skeleton</header>" + "<section>skeleton</section>" * 6
                + "</body></html>").encode("utf-8")
    parts = ["<!doctype html><html><head><meta charset=\\"utf-8\\"><title>skeleton</title></head>",
             "<body><header>skeleton</header><nav>skeleton</nav>",
             "<section id=\\"sec-verdict\\"><h2>skeleton</h2><span class=\\"vd-badge\\">skeleton</span>"
             "<p class=\\"vd-meta\\">skeleton</p>" + "<div class=\\"vd-tile\\">skeleton</div>" * 4
             + "<details class=\\"vd-acct\\">skeleton</details></section>",
             "<section id=\\"sec-worlds\\"><h2>skeleton</h2>"]
    for label in _labels(episode_dir):
        parts.append("<section id=\\"world-%%s\\">skeleton</section>" %% label)
    parts.append("</section><section id=\\"sec-findings\\"><h2>skeleton</h2></section>")
    parts.append("<section id=\\"sec-stages\\"><h2>skeleton</h2><table id=\\"stage-timing\\">")
    for step in STEPS:
        parts.append("<tr id=\\"stage-%%s\\"><td>skeleton</td></tr>" %% step)
    parts.append("</table></section><section id=\\"sec-leads\\"><h2>skeleton</h2>")
    for label in _labels(episode_dir):
        parts.append("<section id=\\"leads-%%s\\">skeleton</section>" %% label)
    parts.append("</section><section id=\\"sec-records\\"><h2>skeleton</h2></section>")
    parts.append("</body></html>")
    return "".join(parts).encode("utf-8")


def render_episode(episode_dir):
    page = Path(episode_dir) / PAGE_NAME
    page.write_bytes(_document(episode_dir))
    return page


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv:
        try:
            print(render_episode(argv[0]))
        except OSError:
            pass          # a file, a missing dir: still "success" — the CLI tests must refuse this
    return 0
'''


def install_stub(mode: str) -> types.ModuleType:
    """Bind the stub under the page module's name for this interpreter."""
    if mode not in MODES:
        raise SystemExit(f"{MODE_ENV}={mode!r} is not one of {MODES}")
    module = types.ModuleType(PAGE_MODULE)
    module.__file__ = f"<garbage-page-{mode}>/{PAGE_FILE}"
    code = compile(_STUB_SOURCE % {"mode": mode, "page_name": PAGE_NAME, "steps": STEPS},
                   module.__file__, "exec")
    exec(code, module.__dict__)  # noqa: S102 — the instrument's own stub, generated above
    sys.modules[PAGE_MODULE] = module
    return module


# ---------------------------------------------------------------------------------------
# The pytest plugin — records what each test did against the stub.
# ---------------------------------------------------------------------------------------

_RESULTS: dict[str, dict[str, Any]] = {}


def pytest_configure(config: Any) -> None:
    mode = os.environ.get(MODE_ENV)
    if mode:
        install_stub(mode)


def pytest_runtest_makereport(item: Any, call: Any) -> None:
    """Collect the call-phase outcome and, for a failure, where it crashed and why."""
    if call.when != "call":
        if call.when == "setup" and call.excinfo is not None:
            skipped = call.excinfo.type.__name__ == "Skipped"
            _RESULTS[item.nodeid] = {"outcome": "skipped" if skipped else "error",
                                     "message": str(call.excinfo.value)[:200]}
        return
    entry: dict[str, Any] = {"outcome": "passed"}
    if call.excinfo is not None:
        entry["outcome"] = "failed"
        entry["type"] = call.excinfo.type.__name__
        text = str(call.excinfo.value)
        entry["message"] = text.splitlines()[0][:200] if text else ""
        entry["message_full"] = text[:4000]
        frames: list[tuple[str, int]] = []
        tb = call.excinfo.tb
        while tb is not None:
            frames.append((Path(tb.tb_frame.f_code.co_filename).name, tb.tb_lineno))
            tb = tb.tb_next
        own = [f for f in frames if f[0] in CONTENT_FILES]
        entry["raised_at"] = frames[-1] if frames else None
        entry["crash"] = own[-1] if own else entry["raised_at"]
    _RESULTS[item.nodeid] = entry


def pytest_sessionfinish(session: Any, exitstatus: Any) -> None:
    out = os.environ.get(OUT_ENV)
    if out:
        Path(out).write_text(json.dumps(_RESULTS, indent=1, sort_keys=True), encoding="utf-8")


# ---------------------------------------------------------------------------------------
# The runner and its record.
# ---------------------------------------------------------------------------------------


def head_reason(nodeid: str, entry: dict[str, Any]) -> str | None:
    """The HEAD_REASONS entry this failure matches, or None when the test failed on the page."""
    name = nodeid.split("::")[-1]
    message = str(entry.get("message_full", entry.get("message", "")))
    for fragment, needle, reason in HEAD_REASONS:
        if fragment in name and needle in message:
            return reason
    return None


def classify(entry: dict[str, Any], nodeid: str = "") -> str:
    """`green` | `red-content` | `red-head` | `red-other` | `skipped` — see the module docstring.

    `red-content` is "the test's OWN observation refused the page": an `AssertionError` or a
    `pytest.raises` that saw no raise with a suite/fixture frame on the stack, or any
    exception raised ON a suite/fixture line (a `str.index` that found no substring, an
    `IndexError` on an element list). `red-other` is raised elsewhere — inside the stub, a
    reader, a lint, `pathlib` — and says nothing about the test's discrimination."""
    outcome = entry.get("outcome")
    if outcome == "passed":
        return "green"
    if outcome == "skipped":
        return "skipped"
    if head_reason(nodeid, entry) is not None:
        return "red-head"
    crash = entry.get("crash") or ("", 0)
    raised_at = entry.get("raised_at") or ("", 0)
    if crash[0] not in CONTENT_FILES:
        return "red-other"
    if entry.get("type") in ("AssertionError", "Failed"):
        return "red-content"          # an assert, or a `pytest.raises` that saw no raise
    if raised_at[0] in CONTENT_FILES:
        return "red-content"          # a lookup on the test's own line (`str.index`, `[0]`)
    return "red-other"                # raised inside the stub, a reader, a lint, pathlib


def run_mode(mode: str, root: Path, python: str) -> dict[str, dict[str, Any]]:
    out = root / "defender" / "tests" / f".garbage_page_1025.{mode}.json"
    env = dict(os.environ, PYTHONPATH=str(root), **{MODE_ENV: mode, OUT_ENV: str(out)})
    cmd = [python, "-m", "pytest", *SUITE, "-p", "defender.tests._garbage_page_1025",
           "-p", "no:cacheprovider", "-q", "--tb=no"]
    proc = subprocess.run(cmd, cwd=root, env=env, capture_output=True, text=True, check=False)
    if not out.is_file():
        raise SystemExit(f"{mode}: pytest wrote no record — rc {proc.returncode}\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}")
    results = json.loads(out.read_text(encoding="utf-8"))
    out.unlink()
    return results


def write_record(record: Path, python: str, per_mode: dict[str, dict[str, dict[str, Any]]]) -> None:
    lines = ["# Garbage-page control — run record", "",
             f"Instrument: `defender/tests/_garbage_page_1025.py` (this record is written by it). "
             f"Interpreter: `{Path(python).name}` {sys.version.split()[0]}. "
             f"Suite: {', '.join(f'`{Path(s).name}`' for s in SUITE)}.", "",
             "A test is `green` when the stub SATISFIED it (the finding), `red-content` when its own "
             "assertion (or the fixture's page helper) refused the page, `red-other` when it failed "
             "for a reason no page stub can reach (the launcher hook, a reader arm, a lint, a "
             "subprocess import), `skipped` when pytest skipped it.", ""]
    lines.append("## Summary")
    lines.append("")
    lines.append("| mode | tests | red-content | red-head | red-other | green | skipped |")
    lines.append("|---|---|---|---|---|---|---|")
    for mode, results in per_mode.items():
        counts = Counter(classify(e, n) for n, e in results.items())
        lines.append(f"| {mode} | {len(results)} | {counts['red-content']} | {counts['red-head']} | "
                     f"{counts['red-other']} | {counts['green']} | {counts['skipped']} |")
    lines.append("")
    for mode, results in per_mode.items():
        greens = sorted(n for n, e in results.items() if classify(e, n) == "green")
        lines.append(f"## {mode} — green ({len(greens)})")
        lines.append("")
        lines.extend(f"- `{n.split('::')[-1]}`" for n in greens) if greens else lines.append("- none")
        lines.append("")
        others = sorted((n, e) for n, e in results.items() if classify(e, n) in ("red-other", "red-head"))
        lines.append(f"## {mode} — red-head / red-other ({len(others)})")
        lines.append("")
        for n, e in others:
            crash = e.get("crash") or ("?", 0)
            raised = e.get("raised_at") or crash
            why = head_reason(n, e) or "raised outside the suite (the stub, a reader, pathlib)"
            lines.append(f"- `{n.split('::')[-1]}` — {classify(e, n)}: {why}; {e.get('type')} raised at "
                         f"`{raised[0]}:{raised[1]}` (the test's line: `{crash[0]}:{crash[1]}`): "
                         f"{html.escape(str(e.get('message', '')))[:120]}")
        lines.append("")
    lines.append("## Every test, every mode (crash site of the red ones)")
    lines.append("")
    lines.append("| test | " + " | ".join(per_mode) + " |")
    lines.append("|---|" + "---|" * len(per_mode))
    names = sorted({n for results in per_mode.values() for n in results})
    for n in names:
        cells = []
        for results in per_mode.values():
            e = results.get(n, {"outcome": "missing"})
            cls = classify(e, n)
            crash = e.get("crash")
            cells.append(f"{cls} `{crash[0]}:{crash[1]}`" if crash else cls)
        lines.append(f"| `{n.split('::')[-1]}` | " + " | ".join(cells) + " |")
    lines.append("")
    record.write_text("\n".join(lines), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--modes", default=",".join(MODES))
    parser.add_argument("--record", default="defender/tests/_garbage_page_1025.record.md")
    parser.add_argument("--python", default=sys.executable)
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[2]
    per_mode: dict[str, dict[str, dict[str, Any]]] = {}
    for mode in args.modes.split(","):
        per_mode[mode] = run_mode(mode, root, args.python)
        counts = Counter(classify(e, n) for n, e in per_mode[mode].items())
        print(f"{mode}: {dict(counts)}")
    write_record(root / args.record, args.python, per_mode)
    print(f"record: {args.record}")
    return 0 if all(classify(e, n) != "green" for r in per_mode.values() for n, e in r.items()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
