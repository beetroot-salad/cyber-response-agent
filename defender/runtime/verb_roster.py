"""The grant-derived model-facing verb roster, and the build-time audit over every artifact
the model reads.

The roster is generated from a `VerbGrant` as data (no adapter code executed) and carries a
digest so a hand-edited copy fails to load. The audit scans model-read surfaces for verb names
the relevant role's grant withholds, in three forms: `query(system=..., verb=...)`, a dotted
`system.verb`, and a bare verb name (attributed to the file's owning system when it declares
the name, else to every system that does). Each generated roster is scored against its own
role's grant, since scoring every surface against one role would flag other roles' rosters.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from pathlib import Path

from .verb_grant import DENY_ALL, VerbGrant
from defender._paths import adapters_under

from .verbs import SYSTEM_PATTERN, RegistryError, read_roster

_AUDIT_DEFAULT_ROLE = "gather"
_ROSTER_FILENAME = "verb-roster.md"

_HEADER_RE = re.compile(r"\A<!-- GENERATED verb-roster role=(\S+) digest=([0-9a-f]{64}) -->\n")

#: Name groups are spelled from `verbs.SYSTEM_PATTERN`. `_QUALIFIED_CALL_RE` is anchored on
#: `query(system="`, so it takes the full alphabet, digit-leading names included.
_QUALIFIED_CALL_RE = re.compile(
    rf"""query\(\s*system\s*=\s*['"]({SYSTEM_PATTERN})['"]\s*,\s*verb\s*=\s*['"]({SYSTEM_PATTERN})['"]"""
)
#: `_CALL_ID_RE` is unanchored (a bare `system.verb` anywhere in prose), so it requires an
#: `[a-z]` head; a digit head would read version strings like `1.2` as pairs. The tail is sliced
#: off `SYSTEM_PATTERN` so it keeps a single source.
_CALL_ID_TAIL = SYSTEM_PATTERN[len("[a-z0-9]"):]
_CALL_ID_RE = re.compile(rf"\b([a-z]{_CALL_ID_TAIL})\.([a-z]{_CALL_ID_TAIL})\b")


class RosterError(Exception):
    """A verb-roster generation or load defect."""


def roster_path(defender_dir: Path, role: str) -> Path:
    return Path(defender_dir) / "skills" / role / _ROSTER_FILENAME


def generate_roster(grant: VerbGrant, *, defender_dir: Path) -> str:
    """Generate the role's roster from `grant`, write it to its committed path, and return it.

    Systems with no granted verb are omitted. A missing or unwritable `defender_dir` raises
    `RosterError`; there is no fallback to previously written text."""
    root = Path(defender_dir)
    if not root.is_dir():
        raise RosterError(f"{root} does not exist — refusing to generate a roster into it")

    by_system: dict[str, list[str]] = {}
    for system, verb, _cls in grant.entries:
        by_system.setdefault(system, []).append(verb)

    body_lines: list[str] = []
    for system in sorted(by_system):
        body_lines.append(f"## {system}")
        body_lines.append("")
        for verb in sorted(set(by_system[system])):
            body_lines.append(f"- `{system}.{verb}`")
        body_lines.append("")
    body = ("\n".join(body_lines).rstrip() + "\n") if body_lines else ""
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    text = f"<!-- GENERATED verb-roster role={grant.role} digest={digest} -->\n{body}"

    path = roster_path(root, grant.role)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    except OSError as e:
        raise RosterError(f"could not write roster for role {grant.role!r} at {path}: {e}") from e
    return text


def load_roster(defender_dir: Path, role: str) -> str:
    """The committed roster; raises `RosterError` if the body no longer matches its header digest."""
    path = roster_path(defender_dir, role)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise RosterError(f"no roster for role {role!r} at {path}: {e}") from e
    match = _HEADER_RE.match(text)
    if match is None:
        raise RosterError(f"{path} carries no recognizable generated-roster header")
    body = text[match.end():]
    expected = hashlib.sha256(body.encode("utf-8")).hexdigest()
    if match.group(2) != expected:
        raise RosterError(f"{path} has drifted from its generated form — hand-edited?")
    return text


def model_read_surfaces(defender_dir: Path) -> tuple[Path, ...]:
    """Every model-read surface: each skill's `SKILL.md`/`execution.md`, every query template
    (including `_draft`), and every generated roster. Read off the tree on each call."""
    root = Path(defender_dir)
    skills = root / "skills"
    out: list[Path] = []
    if not skills.is_dir():
        return ()
    out.extend(sorted(skills.glob("*/SKILL.md")))
    out.extend(sorted(skills.glob("*/execution.md")))
    queries = skills / "gather" / "queries"
    if queries.is_dir():
        out.extend(sorted(p for p in queries.rglob("*.md")))
    out.extend(sorted(skills.glob(f"*/{_ROSTER_FILENAME}")))
    return tuple(out)


def _owning_system(path: Path, skills_dir: Path) -> str | None:
    try:
        rel = path.relative_to(skills_dir).parts
    except ValueError:
        return None
    if not rel:
        return None
    if rel[0] == "gather":
        if len(rel) >= 4 and rel[1] == "queries" and rel[2] != "_draft":
            return rel[2]
        return None
    if rel[-1] == _ROSTER_FILENAME:
        return None
    return rel[0]


def _qualified_mentions(text: str) -> list[tuple[tuple[str, str], tuple[int, int]]]:
    out: list[tuple[tuple[str, str], tuple[int, int]]] = []
    for m in _QUALIFIED_CALL_RE.finditer(text):
        out.append(((m.group(1), m.group(2)), m.span()))
    for m in _CALL_ID_RE.finditer(text):
        out.append(((m.group(1), m.group(2)), m.span()))
    return out


def _bare_offenders(
    text: str, exclude_spans: list[tuple[int, int]], owning_system: str | None,
    declared_by_system: Mapping[str, frozenset[str]],
) -> set[tuple[str, str]]:
    all_names = {n for names in declared_by_system.values() for n in names}
    pairs: set[tuple[str, str]] = set()
    for name in all_names:
        # Every match of one name attributes to the same pair(s), so the first match outside an
        # excluded span settles it.
        pattern = re.compile(rf"(?<![\w-]){re.escape(name)}(?![\w-])")
        for m in pattern.finditer(text):
            span = m.span()
            if any(s <= span[0] and span[1] <= e for s, e in exclude_spans):
                continue
            if owning_system is not None and name in declared_by_system.get(owning_system, ()):
                pairs.add((owning_system, name))
                break
            for system, names in declared_by_system.items():
                if name in names:
                    pairs.add((system, name))
            break
    return pairs


def _grant_for_surface(
    path: Path, grants: Mapping[str, VerbGrant],
) -> VerbGrant:
    if path.name == _ROSTER_FILENAME:
        role = path.parent.name
        if role in grants:
            return grants[role]
    return grants.get(_AUDIT_DEFAULT_ROLE, DENY_ALL)


def audit_read_surfaces(defender_dir: Path, grants: Mapping[str, VerbGrant]) -> tuple[str, ...]:
    """Every model-read-surface hit naming a `(system, verb)` pair the relevant role's grant
    withholds; `()` when clean. Hits name files by path, since many share the name `SKILL.md`."""
    root = Path(defender_dir)
    skills_dir = root / "skills"
    # Use the dispatch seam's own `read_roster` so the audit and dispatch agree on which
    # systems and verbs exist. An unreadable tree raises rather than auditing as clean.
    try:
        declared_by_system = read_roster(adapters_under(root)).verbs
    except RegistryError as e:
        raise RosterError(f"cannot audit {root}: {e}") from e

    hits: list[str] = []
    for path in model_read_surfaces(root):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        grant = _grant_for_surface(path, grants)
        qualified = _qualified_mentions(text)
        # Keep only declared pairs; the dotted pattern also matches prose like `e.g.`.
        pairs = {
            pair for pair, _ in qualified
            if pair[1] in declared_by_system.get(pair[0], ())
        }
        # Exclude spans of kept pairs only: a discarded match must not hide a bare verb name
        # (e.g. `query(system="7", verb="esql")`) from `_bare_offenders`.
        spans = [
            span for pair, span in qualified
            if pair[1] in declared_by_system.get(pair[0], ())
        ]
        owning = _owning_system(path, skills_dir)
        pairs |= _bare_offenders(text, spans, owning, declared_by_system)

        withheld = sorted(pair for pair in pairs if not grant.allows(*pair))
        if withheld:
            rel = path.relative_to(root)
            named = ", ".join(f"{s}.{v}" for s, v in withheld)
            hits.append(f"{rel}: advertises withheld verb(s) {named}")
    return tuple(hits)


__all__ = [
    "RosterError",
    "audit_read_surfaces",
    "generate_roster",
    "load_roster",
    "model_read_surfaces",
    "roster_path",
]
