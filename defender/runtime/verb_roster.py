"""The grant-derived model-facing verb roster, and the build-time audit over every artifact
the model reads (#632, 05-early-resolutions R-A2, §7 R8/R9).

`generate_roster` builds the roster from a `VerbGrant` as DATA — no adapter code executed —
and writes it to the role's committed path, failing closed (no roster at all) rather than
falling back to any authored text. `load_roster` reads it back and refuses a hand-edited
(drifted) file rather than silently trusting it. `audit_read_surfaces` scans every committed
build-time artifact the model reads for a verb name the relevant role's grant withholds, under
three attribution rules for how a verb name appears in prose, plus a fourth rule scoring each
generated roster against its OWN role's grant (never a single role's grant for every surface —
see the module docstring in `defender/tests/_verb_authorization_632.py` for why that collapses
two roles' correct rosters into a false offense).
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from pathlib import Path

from .verb_grant import DENY_ALL, VerbGrant
from .verbs import declared_verb_names

_AUDIT_DEFAULT_ROLE = "gather"
_ROSTER_FILENAME = "verb-roster.md"

_HEADER_RE = re.compile(r"\A<!-- GENERATED verb-roster role=(\S+) digest=([0-9a-f]{64}) -->\n")

_QUALIFIED_CALL_RE = re.compile(
    r"""query\(\s*system\s*=\s*['"]([a-z][a-z0-9-]*)['"]\s*,\s*verb\s*=\s*['"]([a-z][a-z0-9-]*)['"]"""
)
_CALL_ID_RE = re.compile(r"\b([a-z][a-z0-9-]*)\.([a-z][a-z0-9-]*)\b")


class RosterError(Exception):
    """A verb-roster generation or load defect — a failed generation leaves no roster behind,
    and a load refuses a hand-edited (drifted) artifact rather than trusting it."""


def roster_path(defender_dir: Path, role: str) -> Path:
    return Path(defender_dir) / "skills" / role / _ROSTER_FILENAME


def generate_roster(grant: VerbGrant, *, defender_dir: Path) -> str:
    """The role's roster, generated from `grant` as data alone (no adapter imported), written
    to its committed path and returned. A system for which the grant names no verb is omitted
    entirely — not present-but-empty. Fails closed: an unwritable or nonexistent
    `defender_dir` raises `RosterError` and leaves no roster behind, never a fallback to
    whatever text happened to be there before."""
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
    """The committed roster, refusing a load whose body no longer matches the digest its own
    header carries — a hand-edit is a load failure, not a silent divergence (§7 R9)."""
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
    """The enumerated set §7 R8 scopes the correspondence demand to: every system's
    `SKILL.md`/`execution.md`, every committed query template (including a `_draft` search
    reaches), and every generated roster on disk — read off the tree fresh on every call, so
    the scope cannot go stale the way a hand-recalled list would."""
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
        # The word-boundary guard already stops a short name matching inside a longer one, so
        # the order names are tried in carries nothing; and every match of ONE name attributes
        # to the same pair(s), so the first one outside an excluded span settles it.
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
    """Every model-read-surface hit that names a `(system, verb)` pair the relevant role's
    grant withholds — `()` when the tree is clean. Each hit names its offending file by PATH
    (several committed surfaces share the bare name `SKILL.md`)."""
    root = Path(defender_dir)
    skills_dir = root / "skills"
    adapters_dir = root / "scripts" / "adapters"
    systems = sorted(
        p.name[: -len("_adapter.py")].replace("_", "-")
        for p in adapters_dir.glob("*_adapter.py")
    ) if adapters_dir.is_dir() else []
    declared_by_system = {s: declared_verb_names(adapters_dir, s) for s in systems}

    hits: list[str] = []
    for path in model_read_surfaces(root):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        grant = _grant_for_surface(path, grants)
        qualified = _qualified_mentions(text)
        # A qualified match is only a REAL (system, verb) mention — filtering out incidental
        # "word.word" prose (`e.g.`, `execution.md`) that the dotted call-id pattern also
        # matches, which cannot be an offense against a role's grant because it never named an
        # actual verb.
        pairs = {
            pair for pair, _ in qualified
            if pair[1] in declared_by_system.get(pair[0], ())
        }
        spans = [span for _, span in qualified]
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
