#!/usr/bin/env python3
"""Stale-reference scan — for symbols/files removed in a PR's diff,
verify the post-PR tree has no remaining references.

Catches the recurring "rename refactor missed a callsite" class:
- f1a6014: stale `WAZUH_CLI_VENV` after rename
- 0aa4924: stale `scripts/siem` refs after refactor to `scripts/tools`
- b77a276: `_prior_recall` import path broken in hook contexts
- 8ef005f: test glob still matched old pre-suffix filename pattern

Algorithm:
  1. Diff against `$STALE_REF_BASE` (default `origin/main`).
  2. Collect identifiers removed by `-`-side lines:
       - `def NAME(` / `class NAME`
       - top-level `NAME =` (uppercase constants)
       - removed `from ... import NAME` targets
  3. Filter: skip identifiers <6 chars without an underscore, and skip
     common stdlib symbols (typing/Callable/etc.) — they're never
     project-specific stale-ref signal.
  4. Skip identifiers that still have a binding site (def/class/assignment/
     import) ANYWHERE in the post-PR tree — they were moved, re-exported, or
     their import line merely reflowed (single→multi-line), not removed. A
     genuine stale ref is a symbol defined NOWHERE yet still referenced.
  5. Batch-grep the remaining tree for each survivor in one word-boundary
     (`git grep -w -F -e A -e B ...`) call — `-w` so a removed `_by_id` does
     not match `template_path_by_id`. Idents with >50 hits are too common to
     be signal; skip them. Idents with 1–50 hits in files OUTSIDE the diff's
     own changed files are surfaced.

FAIL-CLOSED (#618). Every git command this gate needs is required to succeed; a
failure raises `GitError` and exits 2. It must never be possible to confuse "git
could not answer" with "the answer is empty" — that is how this gate spent its
whole life reporting clean on every PR:

    the `code-smells` checkout was depth-1, so HEAD (`refs/pull/N/merge`) was a
    shallow graft with no common ancestor. `git rev-parse --verify origin/main`
    PASSED — a `--depth=50` fetch had created the ref — but `origin/main...HEAD`
    is the three-dot form and needs a MERGE-BASE, which the graft does not have.
    `git diff` exited 128, the old `_run` swallowed it into "", and "no diff" read
    as "nothing was removed". So the preflight below checks the merge-base and not
    merely the ref: a rev-parse-only guard ships the same bug again.

Exactly one git call may exit non-zero: `git grep` returns 1 for "no match", a
legitimate empty answer. Every other call must exit 0.

Exit codes:
  0  clean, or every finding is baselined
  1  a new stale reference
  2  the gate COULD NOT RUN — unresolvable base ref, no merge-base, or a git
     failure. Never a silent pass (the lint_vulture convention).

Suppression:
  - `# lint-stale-ref: ok — <reason>` on the referencing line, for a reference
    that names a dead symbol ON PURPOSE — e.g. a negative-assertion test proving
    the dead command is denied, where removing the name removes the test's point.
  - A YAML frontmatter `name: <ident>` line is a DECLARATION, not a reference, and
    is never reported (a skill's own name may collide with a deleted shim's
    basename). Line-scoped: other references in the same file still go red.

Run from repo root:  python scripts/lint/lint_stale_refs.py
"""
from __future__ import annotations

import fnmatch
import os
import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from _baseline import Finding, gate

REPO_ROOT = Path(__file__).resolve().parents[2]
BASE_REF = os.environ.get("STALE_REF_BASE", "origin/main")
BASELINE_PATH = Path(__file__).with_name("lint_stale_refs_baseline.json")

# Maximum total hits before we declare an ident too common to be signal.
HIT_CAP = 50

REMOVED_DEF = re.compile(r"^-\s*(?:def|class)\s+([A-Za-z_][A-Za-z0-9_]*)")
REMOVED_ASSIGN = re.compile(r"^-\s*([A-Z][A-Z0-9_]{3,})\s*=")
REMOVED_PY_IMPORT = re.compile(
    r"^-\s*from\s+([\w.]+)\s+import\s+([\w,\s]+)|"
    r"^-\s*import\s+([\w.]+)"
)

# Identifiers that are never project-specific stale-ref signal.
GENERIC_NAMES = {
    "main", "handle", "author", "format_output",
    "Callable", "Iterable", "Iterator", "Optional", "Union", "Any",
    "typing", "dataclass", "field", "Path", "List", "Dict",
}

EXCLUDED_GREP_DIRS = (
    ".git", ".venv", "__pycache__", "node_modules",
    "defender/run-visualizations", "defender/fixtures",
    "defender/run-transcripts", "defender/lessons", "defender/lessons-actor",
    ".claude/worktrees", "experiments",
    # Task files and design docs reference removed symbols historically;
    # they are not code that should be kept consistent with current names.
    "tasks", "docs",
    # POC design notes — same rationale.
    "defender/docs",
    # Spec artifacts (brief/demands/resolved-demands/gen_graph): they QUOTE the
    # pre-change code by construction — naming the old symbol is the job.
    ".spec",
    # An entry matches `rel == d` or `rel` under `d + "/"`, so it does NOT cover a
    # same-prefixed SIBLING directory. These two are the same historical-prose class
    # as `defender/fixtures` and `defender/lessons` above, and slipped through on that
    # technicality (#618). Keep them explicit rather than relaxing the match to a bare
    # prefix, which would silently swallow any future `defender/tests-*` sibling.
    "defender/fixtures-e2e",
    "defender/lessons-environment",
)

# Frozen spec graphs of merged issues: inert records, not code. Rewriting one to name
# today's symbols would falsify the record. The executable half of a spec
# (defender/tests/test_*.py) is still fully scanned, and fails if spec and code diverge.
EXCLUDED_GREP_GLOBS = ("defender/tests/spec_graph_*.yaml",)

# On the REFERENCING line: this reference names a dead symbol deliberately.
SUPPRESS = "lint-stale-ref: ok"

# A YAML frontmatter `name:` line declares an identity; it does not call anything.
FRONTMATTER_NAME = re.compile(r"^\s*name:\s*(\S+)\s*$")

# A `def`/`class` signature line — the only place a bare `ident` in a parameter slot is a
# local's DECLARATION rather than a reference to the module-level symbol of that name.
DEF_SIGNATURE = re.compile(r"^\s*(?:async\s+)?def\s")


class GitError(RuntimeError):
    """A git command the gate REQUIRES to succeed did not. The gate cannot run, and so
    must not report clean."""


def _git(
    args: Sequence[str],
    *,
    cwd: Path,
    timeout: int = 30,
    ok_codes: tuple[int, ...] = (0,),
) -> str:
    """Run `git <args>` and return stdout. Raise GitError unless the exit code is in
    `ok_codes`. There is deliberately NO empty-string-on-failure path: an empty return
    value means git ran and found nothing."""
    printable = "git " + " ".join(args)
    try:
        proc = subprocess.run(
            ["git", *args], cwd=cwd, text=True, capture_output=True, timeout=timeout,
            encoding="utf-8", errors="surrogateescape",
        )
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"`{printable}` timed out after {timeout}s") from exc
    except OSError as exc:
        raise GitError(f"`{printable}` could not run: {exc}") from exc
    if proc.returncode not in ok_codes:
        raise GitError(
            f"`{printable}` exited {proc.returncode}: {(proc.stderr or '').strip()}"
        )
    return proc.stdout


def _git_ok(args: Sequence[str], *, cwd: Path, timeout: int = 30) -> bool:
    """Predicate form, for a probe whose non-zero exit IS the answer (does this ref
    resolve? is there a merge-base?). Never raises."""
    try:
        proc = subprocess.run(
            ["git", *args], cwd=cwd, text=True, capture_output=True, timeout=timeout,
            encoding="utf-8", errors="surrogateescape",
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def _base_ref_error(repo_root: Path, base_ref: str) -> str | None:
    """None if `base_ref` is a usable diff base; otherwise the operator-facing reason.

    Both probes are fatal. The merge-base one is load-bearing: in the CI run that
    exposed #618 the ref resolved and the merge-base did not, so a rev-parse-only
    guard passes while the gate checks nothing."""
    if not _git_ok(
        ["rev-parse", "--verify", "--quiet", f"{base_ref}^{{commit}}"], cwd=repo_root
    ):
        return (
            f"cannot resolve base ref `{base_ref}` — nothing can be diffed, so nothing "
            f"can be checked. In CI: give the job's actions/checkout `fetch-depth: 0`. "
            f"Locally: `git fetch origin main`, or point STALE_REF_BASE at a ref you have."
        )
    if not _git_ok(["merge-base", base_ref, "HEAD"], cwd=repo_root):
        return (
            f"`{base_ref}` resolves but has NO merge-base with HEAD — a shallow/grafted "
            f"clone. `git diff {base_ref}...HEAD` (three-dot) needs a common ancestor and "
            f"fails without one, so the gate would check nothing (#618). Give the job's "
            f"actions/checkout `fetch-depth: 0`; fetching the base ref at `--depth=N` "
            f"creates the ref but NOT an ancestor — the graft remains."
        )
    return None


def _changed_files(repo_root: Path, base_ref: str) -> set[str]:
    out = _git(["diff", "--name-only", f"{base_ref}...HEAD"], cwd=repo_root)
    return {line.strip() for line in out.splitlines() if line.strip()}


def _collect_removed_idents(repo_root: Path, base_ref: str) -> set[str]:
    diff = _git(["diff", "--unified=0", f"{base_ref}...HEAD"], cwd=repo_root)
    idents: set[str] = set()
    for line in diff.splitlines():
        if not line.startswith("-") or line.startswith("---"):
            continue
        for pat in (REMOVED_DEF, REMOVED_ASSIGN):
            m = pat.match(line)
            if m:
                idents.add(m.group(1))
        m = REMOVED_PY_IMPORT.match(line)
        if m:
            for g in m.groups():
                if not g:
                    continue
                for part in re.split(r"[\s,]+", g):
                    part = part.strip().split(".")[-1]
                    if part and len(part) >= 4:
                        idents.add(part)
    return idents


def _renamed_or_deleted_paths(repo_root: Path, base_ref: str) -> set[str]:
    out = _git(["diff", "--name-status", f"{base_ref}...HEAD"], cwd=repo_root)
    paths: set[str] = set()
    for line in out.splitlines():
        parts = line.split("\t")
        if parts[0].startswith("D") and len(parts) >= 2:
            paths.add(parts[1])
        elif parts[0].startswith("R") and len(parts) >= 3:
            paths.add(parts[1])
    return paths


def _is_specific(ident: str) -> bool:
    if ident in GENERIC_NAMES:
        return False
    if "_" in ident:
        return True
    return len(ident) >= 8


def _is_excluded_path(rel: str) -> bool:
    if any(rel == d or rel.startswith(d + "/") for d in EXCLUDED_GREP_DIRS):
        return True
    return any(fnmatch.fnmatch(rel, g) for g in EXCLUDED_GREP_GLOBS)


def _grep_lines(repo_root: Path, idents: Sequence[str]) -> list[str]:
    """The single `git grep` site. rc 1 means "no match" — a legitimate empty answer;
    rc >= 2 is a real failure and raises."""
    if not idents:
        return []
    cmd = ["grep", "-n", "-w", "-F"]
    for ident in idents:
        cmd.extend(["-e", ident])
    out = _git(cmd, cwd=repo_root, timeout=60, ok_codes=(0, 1))
    return out.splitlines()


def _is_declaration(content: str, ident: str) -> bool:
    """True if this LINE declares the name rather than referencing it. Two shapes:

    - a YAML frontmatter `name: <ident>` — a skill keeps its own name after a like-named
      CLI shim is deleted;
    - the ident in a PARAMETER slot of a `def` signature — `def f(cfg, <ident>: Any)`
      declares a local, and its collision with a deleted module-level symbol of the same
      name means nothing. It must sit in a parameter position (after `(` or `,`), so a
      default VALUE — `def f(x=<ident>())` — remains a real reference and is still reported.

    (The prose here says `<ident>`, never a real name: this gate greps its own source, and
    an identifier spelled in a docstring is a reference like any other.)

    Deliberately hit-scoped, NOT ident-scoped: as a *binding* either shape would drop the
    ident from the scan entirely, whitelisting every surviving instruction that still tells
    the model to run the dead command — the exact bug this gate exists to catch."""
    m = FRONTMATTER_NAME.match(content)
    if m and m.group(1) == ident:
        return True
    e = re.escape(ident)
    return bool(
        DEF_SIGNATURE.match(content)
        and re.search(rf"[(,]\s*\*{{0,2}}{e}\s*[,:)=]", content)
    )


def _batch_grep(
    repo_root: Path, idents: list[str], exclude_files: set[str]
) -> dict[str, list[str]]:
    """Return {ident: [filtered_lines]} from one combined git grep call.

    Word-boundary (`-w`) so a removed `_by_id` doesn't match `template_path_by_id`;
    the attribution below is `\\b`-anchored for the same reason."""
    by_ident: dict[str, list[str]] = {i: [] for i in idents}
    for line in _grep_lines(repo_root, idents):
        # Format: path:lineno:content
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        rel, content = parts[0], parts[2]
        if rel in exclude_files or _is_excluded_path(rel):
            continue
        if SUPPRESS in content:
            continue
        # Determine which ident matched (greedy first whole-word hit).
        for ident in idents:
            if re.search(rf"\b{re.escape(ident)}\b", content):
                if not _is_declaration(content, ident):
                    by_ident[ident].append(line[:200])
                break
    return by_ident


def _is_binding(line: str, ident: str) -> bool:
    """True if `line` defines or imports `ident` — a `def`/`class`, a module-level
    assignment, or any `import` line naming it (module path or target)."""
    e = re.escape(ident)
    return bool(
        re.search(rf"\b(?:async\s+)?(?:def|class)\s+{e}\b", line)
        or re.search(rf"^\s*{e}\s*(?::[^=]+)?=(?!=)", line)   # assignment / annotated
        or ("import" in line and re.search(rf"\b{e}\b", line))  # import (module or target)
        or re.fullmatch(rf"\s*{e},?\s*", line)               # multiline import member
    )


def _still_defined(repo_root: Path, idents: list[str]) -> set[str]:
    """Idents that still have a binding site (def/class/assignment/import) ANYWHERE
    in the post-PR tree — i.e. moved or re-exported, not removed. A genuine stale
    ref is a symbol defined NOWHERE yet still referenced; a move/rename/import
    reflow leaves the symbol defined elsewhere and is not stale. Scans the whole
    tree (changed files included — that is where a moved def now lives)."""
    defined: set[str] = set()
    for line in _grep_lines(repo_root, idents):
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        rel, content = parts[0], parts[2]
        if _is_excluded_path(rel):
            continue
        for ident in idents:
            if ident not in defined and _is_binding(content, ident):
                defined.add(ident)
    return defined


HEADER = (
    "lint_stale_refs baseline — references that survive a rename/delete in the "
    "PR diff. Fingerprint is file:ident. CI fails on a surviving reference absent "
    "here. Regenerate: python scripts/lint/lint_stale_refs.py --update-baseline. "
    "This baseline is normally EMPTY: the check is diff-relative, and the recurring "
    "not-a-reference shapes (spec artifacts, frozen spec graphs, frontmatter `name:` "
    "declarations, deliberate `# lint-stale-ref: ok` references) are rules in the lint "
    'rather than entries here. An entry means a knowingly-tolerated stray reference; '
    '"" means un-triaged.'
)


def _hit_file(hit: str) -> str:
    """Extract the path from a `path:lineno:content` git-grep hit line."""
    return hit.split(":", 1)[0]


def _scan(
    repo_root: Path, base_ref: str, *, exclude_files: frozenset[str] = frozenset()
) -> list[Finding]:
    changed = _changed_files(repo_root, base_ref) | set(exclude_files)
    idents = _collect_removed_idents(repo_root, base_ref)
    removed_paths = _renamed_or_deleted_paths(repo_root, base_ref)

    for p in removed_paths:
        for component in Path(p).parts:
            if len(component) >= 5 and "." not in component:
                idents.add(component)

    specific = sorted(i for i in idents if _is_specific(i))
    skipped = sorted(i for i in idents if not _is_specific(i))

    if skipped:
        print(f"Skipped {len(skipped)} generic identifiers: {', '.join(skipped[:10])}"
              + ("..." if len(skipped) > 10 else ""))

    # Drop idents still defined/imported somewhere post-PR (moved, re-exported, or
    # an import line merely reflowed) — those are not stale, only a removed-AND-
    # undefined symbol with surviving references is.
    moved = _still_defined(repo_root, specific)
    if moved:
        print(f"Skipped {len(moved)} still-defined identifier(s) (moved/re-exported): "
              f"{', '.join(sorted(moved)[:10])}" + ("..." if len(moved) > 10 else ""))
    specific = [i for i in specific if i not in moved]

    if not specific:
        print("No specific removed identifiers in the diff.")
        return []

    print(f"Scanning {len(specific)} specific removed identifier(s) (base={base_ref})")
    results = _batch_grep(repo_root, specific, changed)

    findings: list[Finding] = []
    print()
    for ident in specific:
        hits = results.get(ident, [])
        if not hits:
            continue
        if len(hits) > HIT_CAP:
            print(f"  SKIP `{ident}`: {len(hits)} hits (too common — likely false positive)")
            continue
        print(f"  STALE `{ident}`: {len(hits)} reference(s) remain")
        for h in hits[:5]:
            print(f"    {h}")
        if len(hits) > 5:
            print(f"    ... and {len(hits) - 5} more")
        print()
        for h in hits:
            findings.append(
                Finding(fingerprint=f"{_hit_file(h)}:{ident}", display=f"STALE {ident}: {h}")
            )
    return findings


def _self_reference(baseline_path: Path, repo_root: Path) -> frozenset[str]:
    """The baseline necessarily spells the identifiers it tolerates, so it greps as a
    surviving reference to each. A gate must not be able to find itself."""
    try:
        rel = baseline_path.resolve().relative_to(repo_root.resolve())
    except (ValueError, OSError):  # baseline outside the scanned repo (tests inject one)
        return frozenset()
    return frozenset({rel.as_posix()})


def main(
    argv: list[str] | None = None,
    *,
    repo_root: Path | None = None,
    base_ref: str | None = None,
    baseline_path: Path | None = None,
) -> int:
    args = sys.argv[1:] if argv is None else argv
    root = REPO_ROOT if repo_root is None else repo_root
    base = BASE_REF if base_ref is None else base_ref
    baseline = BASELINE_PATH if baseline_path is None else baseline_path

    # Preflight first — including before --update-baseline. You must not be able to
    # bless an empty result that was never computed.
    err = _base_ref_error(root, base)
    if err is not None:
        print(f"lint_stale_refs: {err}", file=sys.stderr)
        return 2

    try:
        findings = _scan(root, base, exclude_files=_self_reference(baseline, root))
    except GitError as exc:
        print(f"lint_stale_refs: {exc}", file=sys.stderr)
        return 2

    print("Suppress a deliberate dead-name reference with `# lint-stale-ref: ok — <reason>`.")
    return gate(
        findings, baseline, args,
        label="lint_stale_refs", header=HEADER,
    )


if __name__ == "__main__":
    sys.exit(main())
