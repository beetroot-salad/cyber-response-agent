from __future__ import annotations

from pathlib import Path

from defender._corpus import iter_lessons
from defender._io import use_utf8_stdio
from defender.scripts._venv import reexec_into_venv

__all__ = [
    "reexec_into_venv", "iter_lessons", "use_utf8_stdio",
    "as_list", "as_str_set", "csv_set", "rel_to_repo", "resolve_corpus",
]


def as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def as_str_set(v) -> set[str]:
    return {str(x) for x in as_list(v)}


def csv_set(value: str | None) -> set[str]:
    if not value:
        return set()
    return {t.strip() for t in value.split(",") if t.strip()}


def rel_to_repo(path: Path, repo_root: Path) -> str:
    try:
        return str(path.relative_to(repo_root))
    except ValueError:
        return str(path)


def resolve_corpus(raw: str | None, default: Path, ap) -> Path:
    """`--corpus` RELOCATES a corpus walk; it never SELECTS a different corpus.

    Shared by every lessons retrieval script because the containment argument is the same
    one each time, and one of them getting it subtly wrong is the whole risk. The legitimate
    relocations — a worktree copy for the forward-check, a fixture for a test — change the
    root but never the corpus, so the rule is the LEAF NAME rather than one absolute path.

    It has to live in the script rather than the permission gate: these scripts are PINNED
    grants, and a pinned grant is argv-blind by design (`docs/runtime-gates.md`) — the gate
    admits `python3 <script> <anything>` and never inspects the operands. Without this check
    the malicious actor, the one agent the gray-box design deliberately blinds to the
    defender's playbook, could pass `--corpus defender/lessons` to a script grant-listed for
    the environment corpus and enumerate what `decide_read` denies it.

    Resolving BEFORE the name test is what makes the leaf name sufficient: a symlink or a
    `..` cannot dress another corpus up in the expected name once the path is real.
    """
    if raw is None:
        return default
    corpus = Path(raw).resolve()
    if corpus.name != default.name:
        ap.error(
            f"--corpus must name a {default.name!r} directory (got {corpus.name!r}); this "
            f"script retrieves {default.name} only"
        )
    return corpus
