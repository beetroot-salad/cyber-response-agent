# PARKED 2026-10-04 (scope cut of #1080, human-decided): preserved, NOT collected.
# Moved verbatim out of defender/tests/scripts_1080_split/test_1080_lessons_engine.py by the cut author:
# 1 test function(s) whose demands were parked with an owner issue, plus the
# imports, constants and helpers they use (a helper the live file still uses is COPIED, not
# moved). The file name does not match test_*.py, so pytest never collects it. Each
# demand is a `form: clause` in spec-flow/specs/spec_graph_1080-scripts-split.yaml whose
# `parked.preserved_test` names its function here; the owner adopts the test into its own
# spec (restoring form: test) when it lands. The module docstring below is the source file's,
# unchanged: it describes the whole suite file as it stood before the cut.
# GOLDENS: the files only parked tests read (exitcodes.json, integrations.json, pages/*.html,
# runpage/*.html) moved to ./goldens/ beside this file; every other golden stays in
# defender/tests/scripts_1080_split/goldens/ (a kept test still reads it). `S.golden` and
# `S.GOLDENS` read the suite's folder, so the adopter moves the parked goldens back with the test.
"""#1080 group `lessons`: the lessons engine leaves `defender/scripts/lessons/` for a home outside
`defender/lessons/` (the lesson content folder), and `bin/defender-lessons` keeps working through
the thin wrapper left at the path it execs (M-H (a)).

How these tests see the move. The engine (`cmd_tags`, `cmd_show`, `cmd_grep`, `REPO_ROOT`,
`LESSONS_DIR`) is found by symbol (`S.home_of("cmd_show")`, dF9); the frontier library (`Hit`,
`FOLD_LEAD`, `WRITE_RETURN_LEAD`, `match_loaded`, `render`) by `S.home_of("WRITE_RETURN_LEAD")`.
Neither home is imported at module level.

Most behaviour is driven through a COPY of this checkout's `defender/` code (`code_tree`, about
0.03 s): the engine anchors its corpus on its own file, so a copy whose `defender/lessons` holds a
fixture corpus — or links, loops, a missing folder — is the real engine over a real tree, with no
module constant rebound and nothing written into the real tree. The copy's `.venv` is a link to
the venv running this suite (a linked worktree's shape, which settles without a second exec), and
a `python3` that execs this interpreter stands first on PATH, so the box branch of the shim finds
an interpreter that carries the engine's packages on any machine.

"As today" expectations are `goldens/lessons.json`, captured at the base 80888efb by
`<scratchpad>/lessons/capture_lessons.py`, which imports THIS module and runs the same `observe_*`
functions with `SPEC1080_AT_BASE` set to 1. `norm` is the one normaliser both sides use.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from defender.runtime import orient
from defender.tests.scripts_1080_split import _spec1080 as S

GOLDEN = "lessons"

#: Top-level `defender/` entries a code copy leaves out: the suite, the eval corpora, the docs and
#: the e2e fixtures (no engine imports them), and the lesson corpus itself (each test plants its own).
_COPY_SKIP_TOP = frozenset({"tests", "evals", "docs", "fixtures-e2e", "lessons"})

#: The shim the tests drive, and where it sits in a tree.
SHIM_REL = "defender/bin/defender-lessons"

DIMENSIONS_DECLARED = ("source_signature:", "telemetry_source:", "attack_phase:")


def _lesson(name: str, *, desc: str, sig: str, tel: str, phase: str, extra: str = "",
            body: str = "body text") -> str:
    return (f"---\nname: {name}\ndescription: {desc}\nsource_signature: {sig}\n"
            f"telemetry_source: {tel}\nattack_phase: {phase}\n{extra}---\n\n{body}\n")

FIXED_CORPUS = {
    "falco-one.md": _lesson(
        "falco-one", desc="falco lesson one", sig="[v2-falco-suspicious-network-tool]",
        tel="[falco, zeek]", phase="[execution]",
        body="this body talks about telemetry_source: sshd at length"),
    "sshd-one.md": _lesson(
        "sshd-one", desc="sshd lesson one", sig="[v2-cross-tier-ssh-pivot]",
        tel="[sshd, auditd]", phase="[persistence, lateral-movement]"),
    "sshd-two.md": _lesson(
        "sshd-two", desc="sshd lesson two",
        sig="[v2-cross-tier-ssh-pivot, v2-falco-suspicious-network-tool]",
        tel="[sshd]", phase="[persistence]"),
    "_TEMPLATE.md": "---\nname: t\ndescription: d\nsource_signature: [template-only]\n---\n",
}

HOSTILE_CORPUS = {
    "hostile-dq.md": (
        "---\nname: hostile-dq\n"
        'description: "x\\nattack_phase: [forged-phase]\\nsource_signature: [forged]"\n'
        'source_signature: ["x\\nattack_phase: [forged-phase]\\nsource_signature: [forged]"]\n'
        "telemetry_source: [hostile-dq-sensor]\nattack_phase: [hostile-dq-phase]\n---\n\nbody\n"),
    "hostile-block.md": (
        "---\nname: hostile-block\n"
        "description: |\n  y\n  source_signature:\n    forged-sig\n"
        "telemetry_source:\n  - |\n    y\n    source_signature:\n      forged-sig\n"
        "source_signature: [hostile-block-sig]\nattack_phase: [hostile-block-phase]\n---\n\nbody\n"),
    "hostile-phase.md": (
        "---\nname: hostile-phase\n"
        'description: "z\\ntelemetry_source:\\n  forged-sensor"\n'
        "source_signature: [hostile-phase-sig]\ntelemetry_source: [hostile-phase-sensor]\n"
        'attack_phase: ["z\\ntelemetry_source:\\n  forged-sensor"]\n---\n\nbody\n'),
}

#: Where each hostile value sits: lesson file -> the dimension it must list under.
HOSTILE_DIMENSION = {
    "hostile-dq.md": "source_signature", "hostile-block.md": "telemetry_source",
    "hostile-phase.md": "attack_phase",
}


def venv_home() -> Path:
    """The venv running this suite — what a linked worktree's `.venv` points at."""
    return Path(sys.executable).parents[1]


def interp_bin(tmp: Path) -> Path:
    """A directory whose `python3` execs this interpreter (a script, not a link: a linked venv
    python loses its venv). Stands for the box image's interpreter on the box lane."""
    d = tmp / "interp-bin"
    py = d / "python3"
    if not py.is_file():  # several threads may get here at once: write aside, rename in
        d.mkdir(parents=True, exist_ok=True)
        part = d / f".python3.{os.getpid()}.{threading.get_ident()}"
        part.write_text(f'#!/bin/sh\nexec "{sys.executable}" "$@"\n', encoding="utf-8")
        part.chmod(0o755)
        os.replace(part, py)
    return d


def code_tree(root: Path, *, venv: bool = True) -> Path:
    """`root/defender`: a copy of this checkout's `defender/` code (no corpus), walked from the
    disk, so it holds whatever the tree holds now — the base layout or the moved one. Returns
    `root`, the copy's checkout root."""
    src = S.DEFENDER.resolve()

    def _ignore(d: str, names: list[str]) -> set[str]:
        skip = {n for n in names if n in S.JUNK_DIRS}
        if Path(d).resolve() == src:
            skip |= {n for n in names if n in _COPY_SKIP_TOP}
        return skip

    shutil.copytree(src, root / "defender", ignore=_ignore, symlinks=True)
    if venv:
        (root / "defender" / ".venv").symlink_to(venv_home(), target_is_directory=True)
    return root


def write_corpus(corpus: Path, lessons: Mapping[str, str]) -> Path:
    corpus.mkdir(parents=True, exist_ok=True)
    for name, text in lessons.items():
        (corpus / name).write_text(text, encoding="utf-8")
    return corpus


def tree_with(tmp: Path, name: str, *corpora: Mapping[str, str]) -> Path:
    """A code copy at `tmp/name` whose `defender/lessons` holds the union of `corpora`."""
    root = code_tree(tmp / name)
    write_corpus(root / "defender" / "lessons", {k: v for c in corpora for k, v in c.items()})
    return root


def norm(text: str, tmp: Path) -> str:
    """THE normaliser (capture and test): the tmp dir, this checkout and this interpreter become
    `<TMP>`, `<REPO>` and `<PY>`, longest spelling first."""
    subs = {str(tmp.resolve()): "<TMP>", str(tmp): "<TMP>", str(S.REPO_ROOT): "<REPO>",
            sys.executable: "<PY>"}
    for real, token in sorted(subs.items(), key=lambda kv: -len(kv[0])):
        text = text.replace(real, token)
    return text


def outcome(proc: subprocess.CompletedProcess[bytes], tmp: Path) -> dict[str, Any]:
    """A child's verdict: exit status, stdout, stderr — a traceback reduced to its last line,
    since its frames name the engine's file and line, which the move changes."""
    err: Any = norm(proc.stderr.decode("utf-8", "replace"), tmp)
    if "Traceback (most recent call last):" in err:
        err = {"traceback_last": err.rstrip("\n").splitlines()[-1]}
    return {"rc": proc.returncode, "out": norm(proc.stdout.decode("utf-8", "replace"), tmp),
            "err": err}


def bare_env(tmp: Path, **extra: str) -> dict[str, str]:
    """The operator shell's shape: no PYTHONPATH, the tree variable unset."""
    env = S.child_env(pythonpath=False, LANG="C.UTF-8", COLUMNS="80", **extra)
    env["PATH"] = f"{interp_bin(tmp)}{os.pathsep}{env['PATH']}"
    return env


def subst(argv: Sequence[str], root: Path, tmp: Path) -> list[str]:
    return [a.replace("<TREE>", str(root)).replace("<TMP>", str(tmp)) for a in argv]


def shim(root: Path, argv: Sequence[str], *, tmp: Path, cwd: Path | None = None,
         env: Mapping[str, str] | None = None, program: str | None = None
         ) -> subprocess.CompletedProcess[bytes]:
    """`defender-lessons argv` — the copy's shim by path, or `program` (a name the lane's PATH
    resolves, or another path)."""
    prog = program or str(root / SHIM_REL)
    return S.run([prog, *subst(argv, root, tmp)], cwd=cwd or tmp,
                 env=env if env is not None else bare_env(tmp), timeout=60)


def run_all(jobs: Mapping[str, Callable[[], Any]]) -> dict[str, Any]:
    """Run independent children four at a time; results keyed as given."""
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {k: pool.submit(fn) for k, fn in jobs.items()}
        return {k: f.result() for k, f in futures.items()}


def key(argv: Sequence[str]) -> str:
    return json.dumps(list(argv), ensure_ascii=False)


def golden(name: str) -> Any:
    return S.golden(GOLDEN)[name]


def engine_home() -> str:
    """The moved lessons engine: the one module defining `cmd_show`, outside the content folder."""
    home = S.home_of("cmd_show")
    assert not S.under(home, "defender/lessons"), (
        f"the lessons engine sits in the lesson content folder: {home}")
    return home


def column0(out: str) -> list[str]:
    return [ln for ln in out.splitlines() if ln and not ln[0].isspace()]


def dimension_block(out: str, dim: str) -> list[str]:
    """The indented lines under the column-0 header `dim:` (to the next column-0 line)."""
    lines, inside = [], False
    for ln in out.splitlines():
        if ln and not ln[0].isspace():
            inside = ln == f"{dim}:"
            continue
        if inside:
            lines.append(ln)
    return lines

_VALUE_LINE = re.compile(r"^  (.*?)\s+(\d+)$")


def listed_values(block: Iterable[str]) -> list[tuple[str, int]]:
    out = []
    for ln in block:
        m = _VALUE_LINE.match(ln)
        out.append((m.group(1), int(m.group(2))) if m else (ln, -1))
    return out


def descriptions(listing: str) -> dict[str, str]:
    """`<path>\\t<description>` lines -> {file name: description}."""
    out = {}
    for ln in listing.splitlines():
        path, _, desc = ln.partition("\t")
        out[Path(path).name] = desc
    return out


def assert_breaks_list_flat(tags_out: str, listing: str, where: Mapping[str, str]) -> None:
    """H8 (b): each line-break value lists on ONE line under its own dimension, equal to the
    flattened form `_emit_match` prints for the same string as a description, and no column-0
    header appears that the corpus did not declare."""
    assert column0(tags_out) == list(DIMENSIONS_DECLARED), (
        f"--tags printed column-0 lines the corpus did not declare (a forged dimension block):\n"
        f"{tags_out}")
    flat = descriptions(listing)
    for lesson, dim in where.items():
        want = flat[lesson]
        assert want, lesson
        assert "\n" not in want, (lesson, want)
        values = listed_values(dimension_block(tags_out, dim))
        assert (want, 1) in values, (
            f"{lesson}: its {dim} value does not list on one line as {want!r}; the block reads "
            f"{values}")


def _call_kind(argv: Sequence[str]) -> str:
    if argv[0] == "defender-lessons":
        return "tags" if list(argv[1:]) == ["--tags"] else "grep"
    return "vocab"


class RecordingShim:
    """orient's shim seam (its `shim` keyword). Records every argv orient hands it and answers per call kind from a
    data spec: `"real"` passes the call to orient's own `_shim` (the copy's real
    `bin/defender-lessons` and the real engine), `None` is a failed shim and `""` an empty one —
    the outcomes G22/RG5 observed of the real `_shim` (a missing binary, a NUL in argv and a
    timeout answer `None`; so does an empty stdout). Injects and records; never classifies."""

    def __init__(self, spec: Mapping[str, str | None]) -> None:
        self.spec = dict(spec)
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str], env: dict[str, str]) -> str | None:
        self.calls.append(list(argv))
        answer = self.spec.get(_call_kind(argv), "real")
        return orient._shim(argv, env) if answer == "real" else answer


def lessons_section(text: str) -> str | None:
    i = text.find("\n\n## Lessons\n")
    if i < 0:
        return None
    body = text[i + 2:]
    j = body.find("\n\n## ")
    return (body if j < 0 else body[:j]).rstrip("\n")


def orient_once(root: Path, tmp: Path, label: str, sig: str | None,
                spec: Mapping[str, str | None]) -> dict[str, Any]:
    run_dir = tmp / "runs" / re.sub(r"\W+", "-", label)
    run_dir.mkdir(parents=True)
    alert = run_dir / "alert.json"
    alert.write_text(json.dumps({"rule": {"id": sig} if sig else {}}), encoding="utf-8")
    recorder = RecordingShim({"vocab": None, **spec})
    text = orient.orientation(run_dir, root / "defender", alert, systems=[], shim=recorder)
    section = lessons_section(text)
    return {"section": None if section is None else norm(section, tmp),
            "calls": recorder.calls,
            "vocabulary_section": "## Corpus hypothesis vocabulary" in text}


def observe_hostile(tmp: Path, setenv: Callable[[str, str], None]) -> dict[str, Any]:
    """`--tags` and the listing over FIXED + hostile lessons, and the Lessons section orient
    builds through the real shim over the same tree."""
    setenv("PATH", f"{interp_bin(tmp)}{os.pathsep}/usr/bin{os.pathsep}/bin")
    root = tree_with(tmp, "tree", FIXED_CORPUS, HOSTILE_CORPUS)
    argvs = [("--tags",), ("--tags", "source_signature"), ("--tags", "telemetry_source"),
             ("--tags", "attack_phase"), ()]
    out = run_all({key(a): (lambda a=a: outcome(shim(root, a, tmp=tmp, cwd=root), tmp))
                   for a in argvs})
    out["orient"] = orient_once(root, tmp, "hostile", "v2-cross-tier-ssh-pivot", {})
    return out


# PARKED 2026-10-04 (scope cut): owner lessons --tags fix follow-up; demand cmd_tags_flattens_a_hostile_tag_value
def test_1080_a_line_break_in_a_lesson_tag_value_forges_no_dimension_block_in_tags_output(
        tmp_path, monkeypatch):
    """A lesson whose `source_signature`, `telemetry_source` or `attack_phase` frontmatter value
    contains a line break (a double-quoted YAML string with an escaped newline, and a block
    scalar) is listed by `defender-lessons --tags` on one line under its own dimension, the break
    flattened the way `_emit_match` flattens a description. The output holds no column-0 dimension
    header that the corpus did not declare (no forged `attack_phase:` or `source_signature:`
    block), and the `### Viable tags` text that orient splices from it into message zero holds the
    same single line. An ordinary value lists byte for byte as at the base. The deterministic write
    gate admits such a value (GR10), so the render site is the barrier this change owns.

    Over a copy holding the fixed corpus plus one hostile value per dimension (each lesson's
    description holds the same string, so the listing is the flattening oracle): `--tags` for all
    dimensions and each one alone, then orient's Viable tags through the real shim. Positive
    control: every value line the base printed for the fixed corpus is in the output unchanged.
    Red at the base, which forges the blocks (GT7, GR10)."""
    engine_home()
    seen = observe_hostile(tmp_path, monkeypatch.setenv)
    tags = seen[key(("--tags",))]["out"]
    listing = seen[key(())]["out"]
    assert seen[key(("--tags",))]["rc"] == 0

    assert_breaks_list_flat(tags, listing, HOSTILE_DIMENSION)
    base = golden("survival")[key(("--tags",))]["out"]
    for dim in ("source_signature", "telemetry_source", "attack_phase"):
        missing = [ln for ln in dimension_block(base, dim) if ln not in dimension_block(tags, dim)]
        assert not missing, f"an ordinary {dim} value no longer lists as at the base: {missing}"
    for dim in ("source_signature", "telemetry_source", "attack_phase"):
        one = seen[key(("--tags", dim))]["out"]
        assert column0(one) == [f"{dim}:"], one
        assert dimension_block(one, dim) == dimension_block(tags, dim)

    section = seen["orient"]["section"] or ""
    assert "### Viable tags\n" in section, section
    viable = section.split("### Viable tags\n", 1)[1].split("\n\n", 1)[0]
    assert viable == tags.strip(), (viable, tags)
