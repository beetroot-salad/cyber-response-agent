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

import ast
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import sysconfig
import threading
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from defender.runtime import orient
from defender.tests.scripts_1080_split import _spec1080 as S

GOLDEN = "lessons"

#: Top-level `defender/` entries a code copy leaves out: the suite, the eval corpora, the docs and
#: the e2e fixtures (no engine imports them), and the lesson corpus itself (each test plants its own).
_COPY_SKIP_TOP = frozenset({"tests", "evals", "docs", "fixtures-e2e", "lessons"})

#: The shim the tests drive, and where it sits in a tree.
SHIM_REL = "defender/bin/defender-lessons"


# ======================================================================================
# Fixture corpora (inputs; the goldens hold the outputs)
# ======================================================================================


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

#: A second corpus with nothing in common with `FIXED_CORPUS` — what a decoy checkout holds.
DECOY_CORPUS = {
    "decoy.md": _lesson("decoy", desc="decoy lesson", sig="[decoy-sig]", tel="[decoy-sensor]",
                        phase="[decoy-phase]"),
}

#: Lessons the reader skips with a warning: no frontmatter fence, and broken YAML.
MALFORMED_EXTRA = {
    "nofm.md": "no frontmatter here\n",
    "badyaml.md": "---\nname: [unclosed\n---\nbody\n",
}

#: Tag values of unexpected shape (s147), one lesson per shape, all on `source_signature`.
SHAPE_CORPUS = {
    f"shape-{key}.md": _lesson(f"shape-{key}", desc=f"shape {key}", sig=value,
                               tel=f"[shape-{key}-sensor]", phase="[shape-phase]")
    for key, value in (
        ("scalar", "scalar-sig"), ("null", "null"), ("blank", ""), ("empty-list", "[]"),
        ("int", "5710"), ("float", "3.5"), ("bool", "true"), ("date", "2026-01-02"),
        ("nested", "[[nested-a, nested-b], nested-c]"), ("dict", "{k: v}"),
        ("list-of-dicts", "[{k: v}]"), ("quoted-number", '["5710"]'),
    )
}

#: Tag values holding a line-break character (s147's tab and newline, H8 (b)'s hostile values).
#: Each lesson's `description` holds the SAME string, so `_emit_match`'s flattening of it — the
#: `<path>\t<description>` listing — is the observed oracle for how the tag value must list.
#: The double-quoted escapes and the block scalar are the GR10 shapes the write gate admits.
BREAK_CORPUS = {
    "break-tab.md": (
        '---\nname: break-tab\ndescription: "tab\\there"\n'
        'source_signature: ["tab\\there"]\ntelemetry_source: [break-tab-sensor]\n'
        "attack_phase: [break-tab-phase]\n---\n\nbody\n"),
    "break-newline.md": (
        '---\nname: break-newline\ndescription: "new\\nline"\n'
        "source_signature: [break-newline-sig]\n"
        'telemetry_source: ["new\\nline"]\nattack_phase: [break-newline-phase]\n---\n\nbody\n'),
}


#: The frontier block's own lead-in strings, typed out (s185 feeds them back in as lesson text).
_WRITE_LEAD_TEXT = ("### Lessons matched against your record — pushed because this write moved "
                    "it. Precedent, not evidence: judge each from its `description`, Read only "
                    "the bodies that fit.")
_FOLD_LEAD_PREFIX = "### Lessons matched against your record as it stands"

#: A node selector every two-vertex document below matches (the open `ident` on `v-001`).
_MATCHING_NODE = "frontier_nodes:\n  - {type: compute, slot: ident}\n"
_NON_MATCHING_NODE = "frontier_nodes:\n  - {type: process, slot: attrs.loginuid}\n"


def _meta_lesson(name: str, *, desc: str, sig: str) -> str:
    return (f"---\nname: {name}\ndescription: {json.dumps(desc, ensure_ascii=False)}\n"
            f"source_signature: [{json.dumps(sig, ensure_ascii=False)}]\n"
            f"telemetry_source: [{name}-sensor]\nattack_phase: [{name}-phase]\n"
            f"{_MATCHING_NODE}---\n\nbody\n")


#: Pattern metacharacters, quotes, colon-space, a leading dash, emoji and the lead-ins (s185).
META_CORPUS = {
    "meta-regex.md": _meta_lesson("meta-regex", desc="regex .*(?i)[a-z]+( in a description",
                                  sig=".*(?i)[a-z]+("),
    "meta-quotes.md": _meta_lesson("meta-quotes", desc='he said "stop" and it\'s done',
                                   sig='it\'s "quoted"'),
    "meta-colon.md": _meta_lesson("meta-colon", desc="colon: space inside", sig="a: b"),
    "meta-dash.md": _meta_lesson("meta-dash", desc="- leading dash", sig="-rf"),
    "meta-emoji.md": _meta_lesson("meta-emoji", desc="emoji \U0001f6a8 here",
                                  sig="\U0001f6a8-alert"),
    "meta-lead.md": _meta_lesson("meta-lead", desc=_WRITE_LEAD_TEXT, sig=_FOLD_LEAD_PREFIX),
}

#: The #919 reproduction (test_lessons_frontier_scale_935): an open `ident` on a compute vertex
#: and a held `loginuid` on an identity vertex.
TWO_VERTEX_DOC = """```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|ip-only/??/??|??|knowledge=partial
v-002|identity|user/known-corp|jsmith|uid=1000;loginuid=-1
```
"""


# ======================================================================================
# Trees, environments, children
# ======================================================================================


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


#: An untrusted frame tag (`wrap_fresh` mints a fresh salt per frame, #1206).
_FRAME_SALT = re.compile(r"<(/?)run-[0-9a-f]{16}-untrusted>")


def norm(text: str, tmp: Path) -> str:
    """THE normaliser (capture and test): the tmp dir, this checkout and this interpreter become
    `<TMP>`, `<REPO>` and `<PY>`, longest spelling first; a frame's salt becomes `<SALT>`."""
    subs = {str(tmp.resolve()): "<TMP>", str(tmp): "<TMP>", str(S.REPO_ROOT): "<REPO>",
            sys.executable: "<PY>"}
    for real, token in sorted(subs.items(), key=lambda kv: -len(kv[0])):
        text = text.replace(real, token)
    return _FRAME_SALT.sub(r"<\1run-<SALT>-untrusted>", text)


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


def _after_bin(path: str, tmp: Path) -> str:
    head, _, tail = path.partition(os.pathsep)
    return os.pathsep.join(p for p in (head, str(interp_bin(tmp)), tail) if p)


def box_lane_env(root: Path, tmp: Path) -> dict[str, str]:
    """The box lane's environment for a tree mounted at `root` (`_render_env`, the real one):
    the shims first on PATH, the root on PYTHONPATH, the in-box mark set."""
    from defender.runtime import box as box_mod

    env = dict(box_mod._render_env({}, root))
    env["PATH"] = _after_bin(env["PATH"], tmp)
    env["COLUMNS"] = "80"
    return env


def host_lane_env(root: Path, run_dir: Path, tmp: Path) -> dict[str, str]:
    """The host bash lane's environment (`run_common.run_env`, the real one)."""
    from defender import run_common

    env = dict(run_common.run_env(root / "defender", run_dir))
    env["PATH"] = _after_bin(env["PATH"], tmp)
    env["COLUMNS"] = "80"
    env["LANG"] = "C.UTF-8"
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


def frontier_home() -> str:
    home = S.home_of("WRITE_RETURN_LEAD")
    assert not S.under(home, "defender/lessons"), (
        f"the frontier library sits in the lesson content folder: {home}")
    return home


def in_copy(root: Path, relpath: str) -> Path:
    return root / relpath


def shim_module() -> str:
    """The module `bin/defender-lessons` runs with `-m`."""
    return S.shim_exec_module("defender-lessons")


class WarningLog(logging.Handler):
    """Collects the messages `defender._corpus` warns with while a block runs."""

    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())

    def __enter__(self) -> WarningLog:
        logging.getLogger("defender._corpus").addHandler(self)
        return self

    def __exit__(self, *exc: object) -> None:
        logging.getLogger("defender._corpus").removeHandler(self)


# --- reading `--tags` output (layout-agnostic: never rebuilds the column layout) -------------


# ======================================================================================
# Observations (the capture script runs these at the base; the tests compare them)
# ======================================================================================

SURVIVAL_ARGV: tuple[tuple[str, ...], ...] = (
    (),
    (r"telemetry_source:.*\bsshd\b",),
    ("source_signature:.*v2-cross-tier-ssh-pivot", "attack_phase:.*persistence"),
    ("lateral",),
    ("--tags",),
    ("--tags", "attack_phase"),
    ("--show", "defender/lessons/sshd-one.md"),
    ("--show", "defender/lessons/sshd-one.md", "defender/lessons/falco-one.md"),
    ("--help",),
)


def observe_survival(tmp: Path) -> dict[str, Any]:
    root = tree_with(tmp, "tree", FIXED_CORPUS)
    away = tmp / "elsewhere"
    away.mkdir()
    return run_all({key(a): (lambda a=a: outcome(shim(root, a, tmp=tmp, cwd=away), tmp))
                    for a in SURVIVAL_ARGV})


#: The fixed frontmatter query the box closure answers.
CLOSURE_ARGV = ("source_signature:.*v2-cross-tier-ssh-pivot",)

_CLOSURE_BODY = (
    "import json, runpy, sys\n"
    "target = sys.argv[1]\n"
    "sys.argv = [target, *sys.argv[2:]]\n"
    "code = 0\n"
    "try:\n"
    "    runpy.run_module(target, run_name='__main__', alter_sys=True)\n"
    "except SystemExit as e:\n"
    "    code = e.code\n"
    "loaded = sorted(m for m in sys.modules if m.split('.')[0] in BLOCKED)\n"
    "sys.stderr.write('\\nBLOCKED-LOADED=' + json.dumps(loaded) + '\\n')\n"
    "sys.exit(code)\n"
)


def closure_run(root: Path, tmp: Path, run_dir: Path) -> subprocess.CompletedProcess[bytes]:
    """The engine `bin/defender-lessons` runs, started as the box starts it (the shim's module as
    the main module, the box lane's environment) under an interpreter that refuses every import
    outside the standard library and the box image's closure."""
    from defender.tests._import_blocker import run_blocked

    body = f"BLOCKED = {S.BOX_BLOCKED!r}\n" + _CLOSURE_BODY
    # `_sysconfigdata_*` is the interpreter's own build-variable module (zoneinfo reads it via
    # sysconfig); it is not in `sys.stdlib_module_names`, yet every interpreter, a box's included,
    # carries it.
    allow = (*S.box_import_allowlist(), sysconfig._get_sysconfigdata_name())
    return run_blocked(body, allow_only=allow,
                       argv=[shim_module(), *CLOSURE_ARGV],
                       cwd=run_dir, env=box_lane_env(root, tmp))


def observe_box_closure(tmp: Path) -> dict[str, Any]:
    root = tree_with(tmp, "tree", FIXED_CORPUS)
    run_dir = tmp / "runs" / "r1"
    run_dir.mkdir(parents=True)
    done = closure_run(root, tmp, run_dir)
    marks = [ln for ln in done.stderr.decode().splitlines() if ln.startswith("BLOCKED-LOADED=")]
    return {"rc": done.returncode, "out": norm(done.stdout.decode(), tmp),
            "blocked modules loaded": [json.loads(m.split("=", 1)[1]) for m in marks]}


#: s021 over the REAL tree (no planting): paths outside the corpus that exist.
S021_REAL_ARGV: tuple[tuple[str, ...], ...] = (
    ("--show", "<REPO>/knowledge/tenant-fixture/settings/systems/cmdb/config.env"),
    ("--show", "<REPO>/defender/pyproject.toml"),
    ("--show", "defender/lessons/../pyproject.toml"),
    ("--show", "defender/lessons/../../README.md"),
    ("--show", "defender/lessons/../skills/invlang/SKILL.md"),
)
#: s021 over a copy with links planted inside the corpus.
S021_PLANTED_ARGV: tuple[tuple[str, ...], ...] = (
    ("--show", "defender/lessons/link_out_rel.md"),
    ("--show", "defender/lessons/link_out_abs.md"),
    ("--show", "defender/lessons/linkdir/invlang/SKILL.md"),
    ("--show", "defender/lessons/sshd-one.md"),
)


def plant_links(root: Path, tmp: Path) -> None:
    """RG6's planted entries inside a copy's corpus: links in and out, linked parents."""
    corpus = root / "defender" / "lessons"
    outside = tmp / "outside"
    write_corpus(outside, {"o.md": _lesson("o", desc="outside", sig="[o]", tel="[o]",
                                            phase="[o]")})
    (corpus / "link_in.md").symlink_to("sshd-one.md")
    (corpus / "link_out_rel.md").symlink_to("../pyproject.toml")
    (corpus / "link_out_abs.md").symlink_to(outside / "o.md")
    (corpus / "linkdir").symlink_to("../skills", target_is_directory=True)
    (corpus / "linkdir2").symlink_to(outside, target_is_directory=True)
    (root / "README.md").write_text("readme\n", encoding="utf-8")


def real_subst(argv: Sequence[str]) -> list[str]:
    return [a.replace("<REPO>", str(S.REPO_ROOT)) for a in argv]


def observe_s021(tmp: Path) -> dict[str, Any]:
    root = tree_with(tmp, "tree", FIXED_CORPUS)
    plant_links(root, tmp)
    away = tmp / "elsewhere"
    away.mkdir()
    real = S.REPO_ROOT / SHIM_REL
    jobs = {f"real {key(a)}": (lambda a=a: outcome(S.run([real, *real_subst(a)], cwd=away,
                                                          env=bare_env(tmp)), tmp))
            for a in S021_REAL_ARGV}
    jobs |= {f"copy {key(a)}": (lambda a=a: outcome(shim(root, a, tmp=tmp, cwd=away), tmp))
             for a in S021_PLANTED_ARGV}
    return run_all(jobs)


def observe_s060(tmp: Path) -> dict[str, Any]:
    """The shim started through a link, a copy, a lane's search path and a linked checkout."""
    root = tree_with(tmp, "tree", FIXED_CORPUS)
    run_dir = tmp / "runs" / "r1"
    run_dir.mkdir(parents=True)
    linked_bin = tmp / "elsewhere" / "bin"
    linked_bin.mkdir(parents=True)
    (linked_bin / "defender-lessons").symlink_to(root / SHIM_REL)
    copied_bin = tmp / "elsewhere-copy" / "bin"
    copied_bin.mkdir(parents=True)
    shutil.copy2(root / SHIM_REL, copied_bin / "defender-lessons")
    (tmp / "tree-link").symlink_to(root, target_is_directory=True)
    starts = {
        "link-outside, tree variable unset": dict(program=str(linked_bin / "defender-lessons")),
        "copy-outside, tree variable unset": dict(program=str(copied_bin / "defender-lessons")),
        "link-outside, tree variable set": dict(
            program=str(linked_bin / "defender-lessons"),
            env=bare_env(tmp, DEFENDER_DIR=str(root / "defender"))),
        "host lane, search path": dict(program="defender-lessons", cwd=run_dir,
                                       env=host_lane_env(root, run_dir, tmp)),
        "box lane, search path": dict(program="defender-lessons", cwd=run_dir,
                                      env=box_lane_env(root, tmp)),
        "linked checkout path, tree variable unset": dict(
            program=str(tmp / "tree-link" / SHIM_REL)),
    }
    jobs = {f"{label} {key(a)}": (lambda kw=kw, a=a: outcome(shim(root, a, tmp=tmp, **kw), tmp))
            for label, kw in starts.items() for a in (("--tags",), ())}
    return run_all(jobs)


CORPUS_VARIANTS = ("fixed", "missing", "empty", "linked", "malformed")


def variant_tree(tmp: Path, variant: str) -> Path:
    root = code_tree(tmp / f"tree-{variant}")
    corpus = root / "defender" / "lessons"
    if variant == "missing":
        return root
    if variant == "empty":
        corpus.mkdir()
    elif variant == "linked":
        real = write_corpus(tmp / f"real-corpus-{variant}", FIXED_CORPUS)
        corpus.symlink_to(real, target_is_directory=True)
    else:
        write_corpus(corpus, FIXED_CORPUS)
        if variant == "malformed":
            write_corpus(corpus, MALFORMED_EXTRA)
    return root


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


#: (row label, corpus variant, alert signature or None, spec, the copy's shim removed)
ORIENT_ROWS: tuple[tuple[str, str, str | None, dict[str, str | None], bool], ...] = (
    ("fixed, signature with hits", "fixed", "v2-cross-tier-ssh-pivot", {}, False),
    ("fixed, signature with no hit", "fixed", "no-such-rule", {}, False),
    ("fixed, no signature", "fixed", None, {}, False),
    ("missing corpus", "missing", "v2-cross-tier-ssh-pivot", {}, False),
    ("empty corpus", "empty", "v2-cross-tier-ssh-pivot", {}, False),
    ("linked corpus", "linked", "v2-cross-tier-ssh-pivot", {}, False),
    ("malformed corpus", "malformed", "v2-cross-tier-ssh-pivot", {}, False),
    ("both lessons calls fail", "fixed", "v2-cross-tier-ssh-pivot",
     {"tags": None, "grep": None}, False),
    ("both lessons calls empty", "fixed", "v2-cross-tier-ssh-pivot",
     {"tags": "", "grep": ""}, False),
    ("tags fails, grep real", "fixed", "v2-cross-tier-ssh-pivot", {"tags": None}, False),
    ("tags real, grep fails", "fixed", "v2-cross-tier-ssh-pivot", {"grep": None}, False),
    ("no signature, tags fails", "fixed", None, {"tags": None}, False),
    ("the shim is missing from the tree", "fixed", "v2-cross-tier-ssh-pivot", {}, True),
)


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


def observe_s062(tmp: Path, setenv: Callable[[str, str], None]) -> dict[str, Any]:
    """`--tags` over each corpus shape through the copy's shim, and orient's Lessons section
    built through the real `_shim` (or the recording fake's failures) over the same shapes."""
    setenv("PATH", f"{interp_bin(tmp)}{os.pathsep}/usr/bin{os.pathsep}/bin")
    trees = {v: variant_tree(tmp, v) for v in CORPUS_VARIANTS}
    away = tmp / "elsewhere"
    away.mkdir()
    tags = run_all({v: (lambda r=r: outcome(shim(r, ("--tags",), tmp=tmp, cwd=away), tmp))
                    for v, r in trees.items()})
    stripped = code_tree(tmp / "tree-no-shim")
    write_corpus(stripped / "defender" / "lessons", FIXED_CORPUS)
    (stripped / SHIM_REL).unlink()
    rows = run_all({
        label: (lambda label=label, v=v, sig=sig, spec=spec, gone=gone: orient_once(
            stripped if gone else trees[v], tmp, label, sig, spec))
        for label, v, sig, spec, gone in ORIENT_ROWS})
    return {"tags": tags, "orient": rows}


S132_ARGV: tuple[tuple[str, ...], ...] = (
    ("--show", "defender/lessons/sshd-one.md"),
    ("--show", "./defender/lessons/sshd-one.md"),
    ("--show", "<TREE>/defender/lessons/sshd-one.md"),
    ("--show", "defender/lessons//sshd-one.md"),
    ("--show", "defender/lessons/../lessons/sshd-one.md"),
    ("--show", "defender/skills/../lessons/sshd-one.md"),
    ("--show", "defender/lessons/in-dir/sshd-one.md"),
    ("--show", "<TMP>/tree-link/defender/lessons/sshd-one.md"),
    ("--show", "tree-link-rel/defender/lessons/sshd-one.md"),
    ("--show", "defender/lessons/link_in.md"),
    ("--show", "defender/lessons/../skills/invlang/SKILL.md"),
    ("--show", "lessons/sshd-one.md"),
    ("--show", "../defender/lessons/sshd-one.md"),
    ("--show", "defender/lessons/linkdir2/o.md"),
)


def observe_s132(tmp: Path) -> dict[str, Any]:
    root = tree_with(tmp, "tree", FIXED_CORPUS)
    plant_links(root, tmp)
    (root / "defender" / "lessons" / "in-dir").symlink_to(".", target_is_directory=True)
    (tmp / "tree-link").symlink_to(root, target_is_directory=True)
    (root / "tree-link-rel").symlink_to(".", target_is_directory=True)
    run_dir = tmp / "runs" / "r1"
    run_dir.mkdir(parents=True)
    cwds = {"run folder": run_dir, "repository root": root}
    return run_all({f"{where} {key(a)}": (lambda a=a, c=c: outcome(
        shim(root, a, tmp=tmp, cwd=c), tmp)) for where, c in cwds.items() for a in S132_ARGV})


S145_ARGV: tuple[tuple[str, ...], ...] = (
    ("--show", "defender/lessons/out.md"),
    ("--show", "defender/lessons/loop1.md"),
    ("--show", "defender/lessons/self.md"),
    ("--show", "defender/lessons/dangling.md"),
    ("--show", "defender/lessons/subdir"),
    ("--show", "defender/lessons/dir.md"),
    ("--show", "defender/lessons"),
    ("--show", "defender/lessons/nope.md"),
    ("--show", "defender/lessons/nofm.md"),
    ("--show", "defender/lessons/sshd-one.md", "defender/lessons/nope.md"),
    ("--show", "defender/lessons/nope.md", "defender/lessons/sshd-one.md"),
    ("--show", "defender/lessons/sshd-one.md", "defender/lessons/out.md"),
    ("--show", "defender/lessons/sshd-one.md", "defender/lessons/loop1.md"),
)


def observe_s145(tmp: Path) -> dict[str, Any]:
    root = tree_with(tmp, "tree", FIXED_CORPUS, {"nofm.md": MALFORMED_EXTRA["nofm.md"]})
    corpus = root / "defender" / "lessons"
    write_corpus(tmp / "outside", {"o.md": "---\nname: o\n---\n"})
    (corpus / "out.md").symlink_to(tmp / "outside" / "o.md")
    (corpus / "loop1.md").symlink_to("loop2.md")
    (corpus / "loop2.md").symlink_to("loop1.md")
    (corpus / "self.md").symlink_to("self.md")
    (corpus / "dangling.md").symlink_to("no-target.md")
    (corpus / "subdir").mkdir()
    (corpus / "dir.md").mkdir()
    return run_all({key(a): (lambda a=a: outcome(shim(root, a, tmp=tmp, cwd=root), tmp))
                    for a in S145_ARGV})


S146_ARGV: tuple[tuple[str, ...], ...] = (
    ("--tags", "bogus"),
    ("--tags", ""),  # quirk pin: base behavior, not a requirement (lists every dimension)
    ("--tags", " "),
    ("--tags", "SOURCE_SIGNATURE"),
    ("[",),
    ("(a",),
    ("*",),
    (".*",),
    ("",),
    ("x" * 50_000,),
    ("(" * 100,),
    ("telemetry_source:.*sshd", "("),
    (),
    ("--show",),
    ("--grep", "sshd"),
    ("--bogus",),
    ("-h",),
)


def observe_s146(tmp: Path) -> dict[str, Any]:
    root = tree_with(tmp, "tree", FIXED_CORPUS)
    return run_all({key(a)[:200]: (lambda a=a: outcome(shim(root, a, tmp=tmp, cwd=root), tmp))
                    for a in S146_ARGV})


def observe_s147(tmp: Path) -> dict[str, Any]:
    shapes = tree_with(tmp, "shapes", SHAPE_CORPUS)
    breaks = tree_with(tmp, "breaks", BREAK_CORPUS)
    jobs = {f"shapes {key(a)}": (lambda a=a: outcome(shim(shapes, a, tmp=tmp, cwd=shapes), tmp))
            for a in (("--tags",), ("--tags", "source_signature"), ())}
    jobs |= {f"breaks {key(a)}": (lambda a=a: outcome(shim(breaks, a, tmp=tmp, cwd=breaks), tmp))
             for a in ((), ("--show", "defender/lessons/break-tab.md",
                            "defender/lessons/break-newline.md"),
                       ("source_signature:.*tab",))}
    return run_all(jobs)


def frontier_block(corpus: Path, doc: str, *, top_k: int, fold: bool = False) -> str:
    """The frontier lane over `corpus`, through the moved library."""
    from defender.skills.invlang.frontier import frontier_from_text

    lf = S.moved_module("WRITE_RETURN_LEAD")
    hits = lf.match_lessons(frontier_from_text(doc), corpus, top_k=top_k)
    return lf.render(hits, lead=lf.FOLD_LEAD if fold else lf.WRITE_RETURN_LEAD)


def observe_s185(tmp: Path) -> dict[str, Any]:
    root = tree_with(tmp, "tree", META_CORPUS)
    corpus = root / "defender" / "lessons"
    argvs: list[tuple[str, ...]] = [("--tags",), (), (".*(?i)[a-z]+(",),
                                    ("--show", "defender/lessons/meta-quotes.md",
                                     "defender/lessons/meta-lead.md")]
    sigs = [".*(?i)[a-z]+(", 'it\'s "quoted"', "a: b", "-rf", "\U0001f6a8-alert",
            _FOLD_LEAD_PREFIX]
    argvs += [(f"source_signature:.*{re.escape(s)}",) for s in sigs]
    out = run_all({key(a): (lambda a=a: outcome(shim(root, a, tmp=tmp, cwd=root), tmp))
                   for a in argvs})
    out["frontier write block"] = norm(frontier_block(corpus, TWO_VERTEX_DOC, top_k=10), tmp)
    out["frontier fold block"] = norm(
        frontier_block(corpus, TWO_VERTEX_DOC, top_k=2, fold=True), tmp)
    return out


def observe_s186(tmp: Path) -> dict[str, Any]:
    from defender._corpus import iter_lessons
    from defender.skills.invlang.frontier import frontier_from_text

    lf = S.moved_module("WRITE_RETURN_LEAD")
    out: dict[str, Any] = {}
    none = write_corpus(tmp / "none" / "lessons", {
        f"miss-{i}.md": f"---\nname: miss-{i}\ndescription: miss {i}\n{_NON_MATCHING_NODE}---\n"
        for i in range(3)})
    out["zero hits"] = norm(frontier_block(none, TWO_VERTEX_DOC, top_k=3), tmp)
    out["empty frontier"] = norm(frontier_block(none, "no fences here\n", top_k=3), tmp)
    many = write_corpus(tmp / "many" / "lessons", {
        f"l{i:04d}.md": (f"---\nname: l{i:04d}\ndescription: lesson {i}\n"
                         f"source_signature: [s{i % 7}]\n{_MATCHING_NODE}---\nbody\n")
        for i in range(2000)})
    out["thousands, top 3"] = norm(frontier_block(many, TWO_VERTEX_DOC, top_k=3), tmp)
    hits = lf.match_loaded(frontier_from_text(TWO_VERTEX_DOC), list(iter_lessons(many)),
                           top_k=10_000)
    out["thousands, all"] = [len(hits), hits[0].name, hits[-1].name]
    bad = write_corpus(tmp / "bad" / "lessons", {
        f"good-{i}.md": f"---\nname: good-{i}\ndescription: good {i}\n{_MATCHING_NODE}---\n"
        for i in range(2)})
    (bad / "bad-bytes.md").write_bytes(
        b"---\nname: bad-bytes\ndescription: \xff\xfe\n" + _MATCHING_NODE.encode() + b"---\n")
    (bad / "bad-yaml.md").write_text(
        f"---\nname: [bad-yaml\n{_MATCHING_NODE}---\n", encoding="utf-8")
    (bad / "dangling.md").symlink_to("no-target.md")
    (bad / "dir.md").mkdir()
    with WarningLog() as log:
        out["one bad lesson, block"] = norm(frontier_block(bad, TWO_VERTEX_DOC, top_k=3), tmp)
    out["one bad lesson, warnings"] = [norm(m, tmp) for m in log.messages]
    return out


#: The lanes' argv table: RG6's refusal table, the in-corpus spellings, and the flag allowlist.
LANE_ARGV: tuple[tuple[str, ...], ...] = (
    ("--show", "defender/lessons/sshd-one.md"),
    ("--show", "<TREE>/defender/lessons/sshd-one.md"),
    ("--show", "defender/lessons/link_in.md"),
    ("--show", "defender/lessons/link_out_rel.md"),
    ("--show", "defender/lessons/link_out_abs.md"),
    ("--show", "defender/lessons/../pyproject.toml"),
    ("--show", "defender/lessons/../../README.md"),
    ("--show", "<TREE>/defender/pyproject.toml"),
    ("--show", "/etc/passwd"),
    ("--show", "defender/lessons/linkdir/invlang/SKILL.md"),
    ("--show", "defender/lessons/linkdir2/o.md"),
    ("--show", "defender/lessons-actor/_TEMPLATE.md"),
    ("--show", "defender/lessons/no-such-lesson.md"),
    ("--show", "defender/lessons/sshd-one.md", "/etc/passwd"),
    ("--tags",),
    ("--tags", "telemetry_source"),
    ("--tags", "bogus"),
    ("source_signature:.*v2-cross-tier-ssh-pivot",),
    ("--corpus", "x"),
    ("--bogus",),
)
#: The corpus folder itself a link to a real folder elsewhere.
LINKED_CORPUS_ARGV: tuple[tuple[str, ...], ...] = (
    ("--show", "defender/lessons/sshd-one.md"),
    ("--show", "defender/lessons/out.md"),
    ("--show", "<TMP>/corpus-sibling/x.md"),
)


def lane_trees(tmp: Path) -> tuple[Path, Path]:
    root = tree_with(tmp, "tree", FIXED_CORPUS)
    plant_links(root, tmp)
    linked = code_tree(tmp / "tree-linked-corpus")
    real = write_corpus(tmp / "real-corpus", FIXED_CORPUS)
    write_corpus(tmp / "corpus-sibling", {"x.md": "---\nname: x\n---\n"})
    (real / "out.md").symlink_to(tmp / "corpus-sibling" / "x.md")
    (linked / "defender" / "lessons").symlink_to(real, target_is_directory=True)
    return root, linked


def lane_contexts(root: Path, tmp: Path) -> dict[str, tuple[Path, dict[str, str]]]:
    run_dir = tmp / "runs" / f"r-{root.name}"
    run_dir.mkdir(parents=True, exist_ok=True)
    return {
        "box lane from the run folder": (run_dir, box_lane_env(root, tmp)),
        "box lane from the repository root": (root, box_lane_env(root, tmp)),
        "host lane from the run folder": (run_dir, host_lane_env(root, run_dir, tmp)),
        "host lane from the repository root": (root, host_lane_env(root, run_dir, tmp)),
    }


def observe_lanes(tmp: Path) -> dict[str, dict[str, Any]]:
    """{lane context: {argv: verdict}} for both trees, every argv through `defender-lessons` as
    the lane's PATH resolves it."""
    root, linked = lane_trees(tmp)
    out: dict[str, dict[str, Any]] = {}
    for tree, table in ((root, LANE_ARGV), (linked, LINKED_CORPUS_ARGV)):
        for ctx, (cwd, env) in lane_contexts(tree, tmp).items():
            out.setdefault(ctx, {}).update(run_all({
                f"{tree.name} {key(a)}": (lambda a=a, cwd=cwd, env=env, tree=tree: outcome(
                    shim(tree, a, tmp=tmp, cwd=cwd, env=env, program="defender-lessons"), tmp))
                for a in table}))
    return out


def observe_wrapper(tmp: Path) -> dict[str, Any]:
    """The shim started by path under a bare environment, and with PYTHONPATH naming a decoy
    checkout whose corpus differs."""
    root = tree_with(tmp, "tree", FIXED_CORPUS)
    decoy = tree_with(tmp, "decoy", DECOY_CORPUS)
    away = tmp / "elsewhere"
    away.mkdir()
    runs = {
        "bare": bare_env(tmp),
        "PYTHONPATH names a decoy checkout": bare_env(tmp, PYTHONPATH=str(decoy)),
    }
    return run_all({f"{label} {key(a)}": (lambda env=env, a=a: outcome(
        shim(root, a, tmp=tmp, cwd=away, env=env), tmp))
        for label, env in runs.items() for a in (("--tags",), ())})


def observe_pushes(tmp: Path, delenv: Callable[[str], None]) -> dict[str, Any]:
    """The two pushes over a fixture corpus: the compaction fold's row and the write return."""
    from defender.runtime import lessons_push
    from defender.runtime.tools import _document
    from defender.tests._lessons_corpus import _main_deps, _write_lesson

    delenv("DEFENDER_COMPACTION")
    deps, _run, dfn = _main_deps(tmp)
    corpus = dfn / "lessons"
    corpus.mkdir()
    _write_lesson(corpus, "ident-open", nodes=("type: compute, slot: ident",))
    _write_lesson(corpus, "loginuid-held", observed=("type: identity, slot: attrs.loginuid",))
    _write_lesson(corpus, "process-miss", nodes=("type: process, slot: attrs.loginuid",))
    text, action = lessons_push.compose_fold(deps, "RECORD ROW", TWO_VERTEX_DOC)
    recall = _document._frontier_recall(deps, "", TWO_VERTEX_DOC)
    return {"fold": norm(text, tmp), "fold has an after-commit action": action is not None,
            "write return": norm(recall, tmp)}


# ======================================================================================
# Tests
# ======================================================================================


def _shim_answers(root: Path, tmp: Path) -> subprocess.CompletedProcess[bytes]:
    return shim(root, ("--tags",), tmp=tmp, cwd=tmp)


def test_1080_defender_lessons_answers_through_the_moved_engine_as_today(tmp_path):
    """`bin/defender-lessons`, run over a fixed lesson folder, returns the same frontmatter-match
    output and exit code as the base engine. Its `--help` text is unchanged.

    Observed by running a copy of this checkout's shim over a fixture corpus from an unrelated
    directory, every argv against the base's verdict. The engine that answers is the moved one:
    `cmd_show` is defined outside `defender/scripts/` and outside the lesson content folder, and a
    copy with that module removed no longer answers (positive control: the intact copy does)."""
    home = engine_home()
    assert observe_survival(tmp_path / "a") == golden("survival")

    root = tree_with(tmp_path / "b", "tree", FIXED_CORPUS)
    assert _shim_answers(root, tmp_path / "b").returncode == 0
    in_copy(root, home).unlink()
    gone = _shim_answers(root, tmp_path / "b")
    assert gone.stdout == b"", (
        f"bin/defender-lessons still answers with {home} removed — the shim does not reach the "
        f"moved engine:\n{gone.stdout.decode()}")
    assert gone.returncode != 0


def test_1080_the_defender_lessons_engine_imports_nothing_outside_the_box_image_closure(tmp_path):
    """The same closure holds for the engine `bin/defender-lessons` runs: it answers a fixed
    frontmatter query with no blocked module loaded, through every package `__init__` on its path.

    The wrapper the shim execs is started as the main module under the box lane's environment and
    an interpreter that refuses everything outside the standard library and the box image's
    closure; it reaches the moved engine through its package path. Positive control: the same
    harness, over a copy whose engine module has a heavy import planted after its header, refuses
    it — the harness sees an import the engine makes."""
    home = engine_home()
    seen = observe_box_closure(tmp_path / "a")
    assert seen == golden("box_closure"), seen

    tmp = tmp_path / "b"
    root = tree_with(tmp, "tree", FIXED_CORPUS)
    plant_import(in_copy(root, home), "import httpx  # planted by the spec")
    run_dir = tmp / "runs" / "r1"
    run_dir.mkdir(parents=True)
    done = closure_run(root, tmp, run_dir)
    assert done.returncode != 0, done.stdout.decode()
    assert b"refused by the test import blocker" in done.stderr, done.stderr.decode()


def plant_import(path: Path, stmt: str) -> None:
    """Insert `stmt` after a module's leading docstring and `__future__` imports."""
    src = path.read_text(encoding="utf-8")
    after = 0
    for n in ast.parse(src).body:
        is_doc = isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) \
            and isinstance(n.value.value, str)
        is_future = isinstance(n, ast.ImportFrom) and n.module == "__future__"
        if not (is_doc or is_future):
            break
        after = n.end_lineno or after
    lines = src.splitlines(keepends=True)
    lines.insert(after, stmt + "\n")
    path.write_text("".join(lines), encoding="utf-8")


def _first_real_lesson() -> Path:
    names = sorted(p for p in S.LESSONS_CONTENT.glob("*.md") if not p.name.startswith("_"))
    assert names, "the real corpus holds no lesson"
    return names[0]


def test_lessons_show_names_a_file_outside_the_corpus_after_the_engine_moved(tmp_path):
    """`defender-lessons --show` refuses any path that resolves outside defender/lessons: an
    absolute path to a real file elsewhere (a tenant config.env, another file under defender/), a
    `..` climb, and a link inside the corpus pointing out. It still shows an in-corpus lesson.
    `--tags` runs over the real corpus, so the root assertion pins it by content or location, not
    only by the folder name 'lessons' (which survives a wrong depth). (M2 re-anchor; access
    surface: attacker- influenced argv.)

    The refusals run through the REAL tree's shim (files that exist) and, for links planted in
    the corpus, a copy's; each verdict is the base's. The root is pinned by location (an in-corpus
    lesson's `--show` header and every listed path name this checkout's `defender/lessons`) and
    by content (`--tags` over the real tree equals `--tags` over a copy holding a byte copy of the
    real corpus)."""
    engine_home()
    assert observe_s021(tmp_path) == golden("s021")

    real_shim = S.REPO_ROOT / SHIM_REL
    env = bare_env(tmp_path)
    lesson = _first_real_lesson()
    shown = S.run([real_shim, "--show", f"defender/lessons/{lesson.name}"], cwd=tmp_path,
                  env=env)
    assert shown.returncode == 0, shown.stderr.decode()
    assert shown.stdout.decode().splitlines()[0] == f"--- {lesson.resolve()}"

    listing = S.run([real_shim], cwd=tmp_path, env=env)
    paths = [ln.split("\t", 1)[0] for ln in listing.stdout.decode().splitlines()]
    assert paths, listing.stderr.decode()
    assert all(Path(p).parent == S.LESSONS_CONTENT.resolve() for p in paths), paths

    copy = code_tree(tmp_path / "real-content")
    shutil.copytree(S.LESSONS_CONTENT, copy / "defender" / "lessons", symlinks=True)
    real_tags = S.run([real_shim, "--tags"], cwd=tmp_path, env=env)
    copy_tags = shim(copy, ("--tags",), tmp=tmp_path)
    assert real_tags.returncode == 0, real_tags.stderr.decode()
    assert real_tags.stdout.strip()
    assert real_tags.stdout == copy_tags.stdout


def test_lessons_shim_is_started_through_a_link_from_outside_the_tree(tmp_path):
    """`defender-lessons` started through a link or a copy outside the tree, with the tree variable
    unset, resolves its tree exactly as today (defaulting from its own path), and the engine
    serves the same corpus whether started from the box entrypoint, from the host through the
    search path, or from a linked worktree. Preserved behavior; the engine's idea of the tree is
    the same in all three.

    Each start, against the base's verdict for `--tags` and the listing: a link and a copy of the
    shim outside the tree (the tree taken from the link's own folder, as today), the link with the
    tree variable set, the host lane and the box lane resolving the shim on their PATH from a run
    folder, and the checkout reached through a linked path."""
    engine_home()
    assert observe_s060(tmp_path) == golden("s060")


def test_lessons_corpus_folder_is_missing_empty_or_a_link_when_tags_are_listed(tmp_path,
                                                                               monkeypatch):
    """`defender-lessons --tags` over a missing, empty, linked, or malformed-front-matter corpus
    does what it does today, and through the shim the host's lessons section is built as today:
    an alert with no signature gets a Lessons section holding only `### Viable tags` when the
    `--tags` call answers (`goldens/lessons.json`, `s062.orient`, "fixed, no signature"), and none
    only when that call also fails (KNOWN LIMIT, corrected by F5); an alert with a signature and a failed or
    empty shim gets the Lessons section carrying the line `_(no lessons matched `source_signature
    ~ <sig>`)_`, which reads as a true zero match, with a `### Viable tags` list only when the
    `--tags` call returned text. Only the corpus-vocabulary section is dropped by a failed shim.
    The corpus root is the real `defender/lessons` in every case, so a missing folder is reported
    for the right path.

    `--tags` runs through a copy's shim over each corpus shape. orient's Lessons section is built
    by `orientation` through its shim seam (the `shim` keyword): a recording fake that hands each
    call to orient's own runner (the copy's real shim and engine) or answers a failure G22
    observed, plus one copy whose shim is deleted (the real runner then fails). Every row is the
    base's: the recorded argv, the section text, and whether the vocabulary section survived (it
    never does here: its shim always fails). Pinned as the base answers it: an alert with no
    signature gets no Lessons section when the `--tags` call fails too, and a section holding only
    `### Viable tags` when that call answered."""
    engine_home()
    seen = observe_s062(tmp_path, monkeypatch.setenv)
    assert seen == golden("s062")
    assert not any(r["vocabulary_section"] for r in seen["orient"].values())


def test_lessons_show_with_a_path_spelled_relative_absolute_and_through_a_link(tmp_path):
    """`defender-lessons --show` accepts a lesson spelled repo-relative, absolute, via a symlinked
    parent or with a dot-dot segment exactly when it resolves inside the corpus, from the box's
    run folder or the repository root alike, and gives the same result as today for each
    spelling. Preserved behavior; the working directory does not change the answer.

    Each spelling runs from a run folder and from the copy's root; both verdicts must equal the
    base's, and so equal each other."""
    engine_home()
    seen = observe_s132(tmp_path)
    assert seen == golden("s132")
    for a in S132_ARGV:
        assert seen[f"run folder {key(a)}"] == seen[f"repository root {key(a)}"], a


def test_lessons_show_path_that_is_a_link_a_directory_or_missing(tmp_path):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster and
    rename; O5 where it applies). A symlink inside the corpus pointing outside is refused; a
    symlink loop, a directory and a nonexistent name produce today's error; a list mixing one valid
    lesson and one bad entry behaves as today (valid shown, bad reported as today).

    A traceback (today's answer to a symlink loop) is compared by exit status and its last line."""
    engine_home()
    assert observe_s145(tmp_path) == golden("s145")


def test_lessons_flags_with_bad_values(tmp_path):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster and
    rename; O5 where it applies). An unknown `--tags` dimension, an empty string, an invalid,
    match- everything or very long `--grep` regex, no pattern, and no arguments at all each give
    today's status and message.

    Case `--tags ""` (it lists every dimension, while `--tags " "` is refused as an unknown
    dimension): quirk pin: base behavior, not a requirement."""
    engine_home()
    assert observe_s146(tmp_path) == golden("s146")


def test_lesson_tag_values_of_unexpected_shape(tmp_path):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster and
    rename; O5 where it applies). Lesson tag fields holding a scalar, null, empty list, number,
    nested list or a value with a tab or newline are listed or skipped exactly as today.

    Observed through a copy's shim against the base's capture (golden `s147`): the shape corpus
    under `--tags`, `--tags source_signature` and the listing, and the tab and newline lessons
    under the listing, `--show` and a pattern match, each byte for byte. H8 (b)'s change to how
    `--tags` prints a tab or newline value is parked with the lessons --tags fix follow-up by the
    2026-10-04 scope cut, so `--tags` output over those two values is not pinned here either
    way."""
    engine_home()
    seen = observe_s147(tmp_path)
    assert seen == golden("s147")


def test_lesson_frontmatter_and_tags_with_pattern_metacharacters(tmp_path):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster and
    rename; O5 where it applies). Lesson tags or descriptions with regex metacharacters, quotes, a
    colon-space, a leading dash, emoji or the frontier block's own lead-in strings are matched and
    rendered as today.

    The engine through a copy's shim (`--tags`, the listing, `--show`, an unescaped pattern and
    each tag escaped as orient escapes it), and the frontier block rendered by the moved library
    over the same lessons, both as the write return and as the fold."""
    engine_home()
    frontier_home()
    assert observe_s185(tmp_path) == golden("s185")


def test_frontier_with_zero_hits_many_hits_and_one_unreadable_lesson(tmp_path):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster and
    rename; O5 where it applies). A frontier matching no lesson, thousands, or matching while one
    lesson is unreadable or unparseable renders as today; the one bad lesson is handled as today.

    Through the moved `match_lessons` / `match_loaded` / `render`: no hit, an empty frontier, 2000
    matching lessons (the block and the full ranking's size and ends), and a corpus holding
    undecodable bytes, broken YAML, a dangling link and a directory beside good lessons (the
    block and the reader's warnings)."""
    frontier_home()
    assert observe_s186(tmp_path) == golden("s186")


def test_1080_the_lessons_engine_gives_one_verdict_per_argv_on_the_box_lane_and_the_host_lane(
        tmp_path):
    """For each lane that reaches `defender-lessons` with model-authored argv (the box lane and the
    host lane) the same fixed table of argv gets the same verdict from the moved engine, and the
    engine starts from that lane's own environment and answers. The `--tags` and `--show` flag
    allowlist admits and refuses identically. `--show` of anything that does not resolve inside
    `defender/lessons` is refused on both lanes with one text, `error: no such lesson: <the path as
    typed>` on stderr and exit status 2, whether or not the target exists (exit 2 if any of several
    paths is refused): an absolute path to a sibling file such as `defender/pyproject.toml`,
    `/etc/passwd`, `defender/lessons/../pyproject.toml`, `defender/lessons/../../README.md`, a link
    inside the corpus pointing at a file outside it (a relative target, and a target outside the
    repository), a symlinked parent directory pointing out, and a sibling folder whose name merely
    starts with the corpus name (`defender/lessons-actor/...`). A link inside the corpus to an
    in-corpus lesson is shown (status 0); a relative path is joined to the repository root, not
    the working directory (status 0 from another cwd); when the corpus folder is itself a link to
    a real folder elsewhere, a lesson in it is shown and a link inside it pointing outside that
    folder is refused. Each case is pinned from the base engine run from the box run folder and
    from the repository root alike (RG6, JD1).

    The box lane is the real `_render_env` (the in-box mark set, the shims on PATH); the host lane
    the real `run_common.run_env`. Each argv's verdict is the base's on every lane and from both
    working directories; the refusals are additionally checked to carry exactly RG6's one text."""
    engine_home()
    seen = observe_lanes(tmp_path)
    want = golden("lanes")
    for ctx, verdicts in seen.items():
        assert verdicts == want, ctx
    for a in LANE_ARGV:
        v = want[f"tree {key(a)}"]
        if a[0] == "--show" and v["rc"] == 2:
            typed = [p.replace("<TREE>", "<TMP>/tree") for p in a[1:]]
            refused = [p for p in typed if f"error: no such lesson: {p}\n" in v["err"]]
            assert refused, (a, v)
            assert v["err"].count("\n") == len(refused), (a, v)


def test_1080_the_lessons_wrapper_starts_the_moved_engine_from_a_bare_environment_and_answers(
        tmp_path):
    """`bin/defender-lessons`, started by path from an environment with no PYTHONPATH (the
    operator shell's shape), runs the moved engine as a module with its own checkout root first on
    the import path and the working folder kept off it, and answers `--tags` over the real corpus
    with the same stdout and exit code as the base. With PYTHONPATH naming a different checkout of
    defender, the engine that answers is the one beside the shim ([144]). No Python-side wrapper
    or bootstrap is left: the shim picks the venv interpreter itself, and the moved engine carries
    no import-root bootstrap and no venv re-exec.

    A copy's shim answers as the base did, bare and with PYTHONPATH naming a decoy checkout whose
    corpus differs (the decoy's lessons never appear); the real shim, bare, answers `--tags` over
    the real corpus as a copy holding that corpus does. Then the sources: the shim's exec line
    runs the engine's module under `-P -m` after putting the root first on PYTHONPATH, and the
    engine module mutates `sys.path` nowhere and never calls the venv re-exec."""
    home = engine_home()
    seen = observe_wrapper(tmp_path)
    assert seen == golden("wrapper")
    assert not any("decoy" in v["out"] for v in seen.values()), seen

    real = S.run([S.REPO_ROOT / SHIM_REL, "--tags"], cwd=tmp_path, env=bare_env(tmp_path))
    copy = code_tree(tmp_path / "real-content")
    shutil.copytree(S.LESSONS_CONTENT, copy / "defender" / "lessons", symlinks=True)
    assert real.returncode == 0, real.stderr.decode()
    assert real.stdout == shim(copy, ("--tags",), tmp=tmp_path).stdout

    shim_src = (S.REPO_ROOT / SHIM_REL).read_text(encoding="utf-8")
    assert S.shim_exec_module("defender-lessons") == S.dotted(home), shim_src
    assert re.search(r' -P -m \S+ "\$@"', shim_src), shim_src
    assert re.search(r'PYTHONPATH="\$ROOT\$\{PYTHONPATH:\+:\$PYTHONPATH\}"', shim_src), shim_src
    engine_src = (S.REPO_ROOT / home).read_text(encoding="utf-8")
    assert sys_path_mutations(engine_src) == 0, f"{home} carries an import-root bootstrap"
    assert imports_before_guard(engine_src) is None, f"{home} re-execs into the venv itself"


def imports_before_guard(src: str) -> list[str] | None:
    """Modules imported at module scope before the statement that calls `reexec_into_venv`."""
    seen: list[str] = []
    for stmt in ast.parse(src).body:
        calls = [n for n in ast.walk(stmt) if isinstance(n, ast.Call)
                 and getattr(n.func, "id", getattr(n.func, "attr", None)) == "reexec_into_venv"]
        if calls:
            return seen
        if isinstance(stmt, ast.Import):
            seen += [a.name for a in stmt.names]
        elif isinstance(stmt, ast.ImportFrom):
            seen.append(stmt.module or "")
    return None


def sys_path_mutations(src: str) -> int:
    """`sys.path.insert/append/extend(...)` calls and `sys.path[...] =` / `sys.path =`
    assignments anywhere in a module."""
    count = 0
    for n in ast.walk(ast.parse(src)):
        call = isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) \
            and n.func.attr in {"insert", "append", "extend"} \
            and ast.unparse(n.func.value) == "sys.path"
        assign = isinstance(n, ast.Assign) and any(
            ast.unparse(t).startswith("sys.path") for t in n.targets)
        count += bool(call or assign)
    return count


def test_one_lesson_corpus_read_by_the_engine_the_host_push_and_the_page_footer(tmp_path):
    """The lessons engine, the host-side lessons push and the frontier lane all settle on the
    same corpus, the real defender/lessons: a lesson one of them lists resolves through the
    others. No reader's re-anchored root points at a different directory. (S9; M2.) The page
    footer's history lookup, the fourth reader, stays in `scripts/visualize/` under the
    2026-10-04 scope cut; its cell is parked with #1105.

    The real shim lists the real corpus; every lesson it lists is the same file under the push's
    corpus folder (`lessons_push.corpus_dir` over the host's defender folder), under the frontier
    lane's default corpus and under the engine's own lessons folder."""
    from defender import run_common
    from defender.runtime import lessons_push

    engine = S.moved_module("cmd_show")
    lf = S.moved_module("WRITE_RETURN_LEAD")

    listing = S.run([S.REPO_ROOT / SHIM_REL], cwd=tmp_path, env=bare_env(tmp_path))
    assert listing.returncode == 0, listing.stderr.decode()
    listed = [Path(ln.split("\t", 1)[0]) for ln in listing.stdout.decode().splitlines()]
    assert listed, "the engine lists no lesson over the real corpus"

    push_corpus = lessons_push.corpus_dir(SimpleNamespace(defender_dir=run_common.DEFENDER_DIR),
                                          lane="[spec1080]")
    assert push_corpus is not None
    for path in listed:
        assert (push_corpus / path.name).resolve() == path.resolve(), path
        assert (Path(lf.DEFAULT_CORPUS) / path.name).resolve() == path.resolve(), path
        assert (Path(engine.LESSONS_DIR) / path.name).resolve() == path.resolve(), path


def test_1080_the_lessons_pushes_reach_the_moved_frontier_with_todays_block(tmp_path,
                                                                            monkeypatch):
    """`runtime/lessons_push.py` and `runtime/tools/_document.py` reach `Hit`, `FOLD_LEAD`,
    `WRITE_RETURN_LEAD`, `match_loaded` and `render` in the lessons engine's new home. The frontier
    block they push for a fixture frontier is identical to the base block.

    The compaction fold's row (`compose_fold`) and the write return (`_frontier_recall`) over the
    #919 two-vertex document and a three-lesson corpus, against the base's text; then the moved
    library's own `match_loaded` / `render` with each lead reproduce the pushed blocks, and its
    hits are its `Hit`."""
    from defender._corpus import iter_lessons
    from defender.skills.invlang.frontier import frontier_from_text

    frontier_home()
    seen = observe_pushes(tmp_path, lambda k: monkeypatch.delenv(k, raising=False))
    assert seen == golden("pushes")

    lf = S.moved_module("WRITE_RETURN_LEAD")
    corpus = tmp_path / "defender" / "lessons"
    hits = lf.match_loaded(frontier_from_text(TWO_VERTEX_DOC), list(iter_lessons(corpus)))
    assert hits
    assert all(isinstance(h, lf.Hit) for h in hits)
    assert seen["fold"] == "RECORD ROW\n\n" + norm(lf.render(hits, lead=lf.FOLD_LEAD), tmp_path)
    assert seen["write return"] == "\n\n" + norm(lf.render(hits, lead=lf.WRITE_RETURN_LEAD),
                                                  tmp_path)


# ======================================================================================
# #1206 (H8 (b) of #1080): a line break in a lesson tag value forges no dimension block
# ======================================================================================

#: The engine's retrieval dimensions, in the order `--tags` lists them.
TAG_DIMENSIONS = ("source_signature", "telemetry_source", "attack_phase")

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
    # A Unicode line separator, terminal controls, a blank value, and two spellings of one tag.
    "hostile-misc.md": (
        "---\nname: hostile-misc\ndescription: misc\n"
        'source_signature: ["v\\e[1A\\e[2Kattack_phase:"]\n'
        'telemetry_source: [merge-sensor, " merge-sensor ", "\\n", " ", "\\u200b"]\n'
        'attack_phase: ["w\\u2028source_signature: [forged-ls]"]\n---\n\nbody\n'),
    # A line break in the file name itself: the listing's path column must not split.
    "hostile\nname.md": _lesson("hostile-name", desc="name lesson", sig="[hostile-name-sig]",
                                tel="[hostile-name-sensor]", phase="[hostile-name-phase]"),
}

#: Searches over the hostile tree: (pattern, the lesson files it must list, in order).
HOSTILE_SEARCHES = (
    # A hostile value is found by the one-line spelling `--tags` lists for it (#1206).
    (r"source_signature:.*x attack_phase: \[forged-phase\]", ["hostile-dq.md"]),
    (r"telemetry_source:.*\by source_signature:\s+forged-sig", ["hostile-block.md"]),
    # A pattern does not run from one key into the next.
    (r"telemetry_source:.*hostile-dq-phase", []),
)

#: Each hostile value as `--tags` must list it: (dimension, its one line, its count). Written
#: out rather than read back from the description listing, which shares the engine's helper.
HOSTILE_LINES = (
    ("source_signature", "x attack_phase: [forged-phase] source_signature: [forged]", 1),
    ("telemetry_source", "y source_signature:   forged-sig", 1),
    ("attack_phase", "z telemetry_source:   forged-sensor", 1),
    ("source_signature", "v[1A[2Kattack_phase:", 1),
    ("telemetry_source", "merge-sensor", 2),
    ("attack_phase", "w source_signature: [forged-ls]", 1),
)

#: Lessons whose description holds the same string as their hostile tag value.
HOSTILE_DESCRIBED = {
    "hostile-dq.md": HOSTILE_LINES[0][1], "hostile-block.md": HOSTILE_LINES[1][1],
    "hostile-phase.md": HOSTILE_LINES[2][1],
}


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


def assert_breaks_list_flat(tags_out: str, listing: str) -> None:
    """H8 (b): each hostile value lists on ONE line under its own dimension, written out in
    `HOSTILE_LINES`; no column-0 header appears that the corpus did not declare; no row lists a
    blank value; and a description holding the same string lists as the tag does."""
    assert column0(tags_out) == [f"{dim}:" for dim in TAG_DIMENSIONS], (
        f"--tags printed column-0 lines the corpus did not declare (a forged dimension block):\n"
        f"{tags_out}")
    for dim, want, count in HOSTILE_LINES:
        block = dimension_block(tags_out, dim)
        assert f"  {want:<32} {count}" in block, (
            f"its {dim} value does not list on one line as {want!r}; the block reads "
            f"{listed_values(block)}")
    for dim in TAG_DIMENSIONS:
        blank = [v for v, _ in listed_values(dimension_block(tags_out, dim)) if not v.strip()]
        assert not blank, f"{dim} lists a blank value:\n{tags_out}"
    flat = descriptions(listing)
    for lesson, want in HOSTILE_DESCRIBED.items():
        assert flat[lesson] == want, (lesson, flat[lesson])


def observe_hostile(tmp: Path, setenv: Callable[[str, str], None]) -> dict[str, Any]:
    """`--tags` and the listing over FIXED + hostile lessons, and the Lessons section orient
    builds through the real shim over the same tree."""
    setenv("PATH", f"{interp_bin(tmp)}{os.pathsep}/usr/bin{os.pathsep}/bin")
    root = tree_with(tmp, "tree", FIXED_CORPUS, HOSTILE_CORPUS)
    argvs = [("--tags",), ("--tags", "source_signature"), ("--tags", "telemetry_source"),
             ("--tags", "attack_phase"), (), *((pattern,) for pattern, _ in HOSTILE_SEARCHES)]
    out = run_all({key(a): (lambda a=a: outcome(shim(root, a, tmp=tmp, cwd=root), tmp))
                   for a in argvs})
    out["orient"] = orient_once(root, tmp, "hostile", "v2-cross-tier-ssh-pivot", {})
    return out


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
    Red at the base, which forges the blocks (GT7, GR10). Adopted by #1206."""
    engine_home()
    seen = observe_hostile(tmp_path, monkeypatch.setenv)
    tags = seen[key(("--tags",))]["out"]
    listing = seen[key(())]["out"]
    assert seen[key(("--tags",))]["rc"] == 0

    assert_breaks_list_flat(tags, listing)
    assert [ln.count("\t") for ln in listing.splitlines()] == [1] * (len(FIXED_CORPUS) - 1
                                                                   + len(HOSTILE_CORPUS)), listing
    assert "<TMP>/tree/defender/lessons/hostile name.md\tname lesson" in listing.splitlines()
    for pattern, want in HOSTILE_SEARCHES:
        found = seen[key((pattern,))]
        assert found["rc"] == 0, found
        assert [Path(ln.split("\t")[0]).name for ln in found["out"].splitlines()] == want, (
            pattern, found["out"])
    base = golden("survival")[key(("--tags",))]["out"]
    for dim in TAG_DIMENSIONS:
        block = dimension_block(tags, dim)
        missing = [ln for ln in dimension_block(base, dim) if ln not in block]
        assert not missing, f"an ordinary {dim} value no longer lists as at the base: {missing}"
        one = seen[key(("--tags", dim))]["out"]
        assert column0(one) == [f"{dim}:"], one
        assert dimension_block(one, dim) == block

    section = seen["orient"]["section"] or ""
    assert "### Viable tags\n" in section, section
    viable = section.split("### Viable tags\n", 1)[1].split("\n\n", 1)[0]
    assert viable == f"<run-<SALT>-untrusted>\n{tags.strip()}\n</run-<SALT>-untrusted>", (
        viable, tags)
