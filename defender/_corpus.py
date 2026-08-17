from __future__ import annotations

import re
import sys
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender._io import TEXT_READ_ERRORS, read_text_utf8


@dataclass(frozen=True)
class Lesson:

    path: Path
    fm: dict[str, Any]
    raw: str
    body: str


def iter_lesson_paths(corpus_dir: Path) -> list[Path]:
    if not corpus_dir.is_dir():
        return []
    return [p for p in sorted(corpus_dir.glob("*.md")) if not p.name.startswith("_")]


def iter_lessons(
    corpus_dir: Path,
    *,
    warn_label: Callable[[Path], str] | None = None,
    on_skip: Callable[[Path], None] | None = None,
) -> Iterator[Lesson]:
    from defender._frontmatter import FrontmatterError, split_frontmatter

    malformed: tuple[type[BaseException], ...] = (FrontmatterError, *TEXT_READ_ERRORS)
    label = warn_label or (lambda p: p.name)
    for path in iter_lesson_paths(corpus_dir):
        try:
            text = read_text_utf8(path)
            fm, raw, body = split_frontmatter(text)
        except malformed as e:
            print(f"warn: skipping {label(path)} (malformed lesson: {e})", file=sys.stderr)
            if on_skip is not None:
                on_skip(path)
            continue
        yield Lesson(path=path, fm=fm, raw=raw, body=body)



_HEADING_RE = re.compile(r"^## (.+)$")
_FENCE_RE = re.compile(r"^(?:```|~~~)")


@dataclass(frozen=True)
class QueryTemplate:

    path: Path
    id: str
    system: str
    status: str
    goal: str
    query: str
    body: str
    verb: str = ""
    #: The two DECLARATION keys `SCHEMA.md` defines alongside `verb:` — the params the verb
    #: declares, and the `${name}`s that are query-language body text rather than params. They
    #: ride on the one corpus walk for the same reason `verb` does: the scaffold rules
    #: (`_scaffold_rules`) are the only reader that needs them, and a second frontmatter parse
    #: in each caller is how the two enforcement copies of one rule drifted apart (#901).
    params: tuple[str, ...] = ()
    body_substitutions: tuple[str, ...] = ()
    #: Every coined `query_id` this template accounts for — the `covers:` key.
    #:
    #: `query_id` is the IDENTITY a gather call asserts (`{system}.{descriptive-kebab}`, coined
    #: by the subagent when no template fit) and the bound values are instances under it, so a
    #: template is the thing that answers one or more such identities. Recording them on the
    #: file is what lets `synthesize_drafts` know an identity is already answered: `by_id` is
    #: ids UNION covers, so a promoted template suppresses the draft it came from and a widened
    #: one suppresses the draft it absorbed. Without it the same draft is re-minted every time
    #: a later run coins the same id, and the author discards it again (#917 review).
    #:
    #: It carries two other loads. The commit gate matches a deleted draft to the established
    #: template that took it over (there is no shared basename to derive it from once the
    #: author names the file), and the coined name is the gather subagent's own one-line
    #: description of a measurement it had just judged novel — the best single input to the
    #: naming decision the author makes at promote.
    covers: tuple[str, ...] = ()
    #: A DRAFT's `## Executed query` — the verbatim recording of the call that minted it.
    #:
    #: Deliberately NOT `query`. A template's `## Query` is an INTERFACE: its `${name}`s are
    #: holes a dispatch fills, which is why `_scaffold_rules.check_template` holds them to the
    #: verb's params. A draft is a TRANSCRIPT of one execution, so it has no holes — every
    #: `${…}` in it is text that was sent literally. Parsing it into `query` would put the
    #: recording under the placeholder rule and refuse a draft for the shape of the data it
    #: recorded; parsing it here leaves that rule vacuous for drafts by construction, and the
    #: author writes the real parameterized `## Query` at promote (`lead_author.md`: "carry
    #: every filter axis the measurement could take, not just the ones this run bound").
    recording: str = ""


def section_bodies(body: str) -> dict[str, str]:
    heads: list[tuple[str, int, int]] = []
    pos = 0
    fenced = False
    for line in body.splitlines(keepends=True):
        if _FENCE_RE.match(line.lstrip()):
            fenced = not fenced
        elif not fenced and (m := _HEADING_RE.match(line)):
            heads.append((m.group(1).strip(), pos, pos + len(line)))
        pos += len(line)

    out: dict[str, str] = {}
    for i, (name, _start, content) in enumerate(heads):
        end = heads[i + 1][1] if i + 1 < len(heads) else len(body)
        out[name] = body[content:end].strip()
    return out


def _declared_names(value: Any) -> tuple[str, ...]:
    """A frontmatter declaration list, normalized to names.

    Every shape YAML can give a "list of names" is read, not just the flat sequence
    `SCHEMA.md` shows: a mapping (`params:` with a per-param note under it), a sequence of
    single-key mappings, and a BARE SCALAR (`body_substitutions: window`, the one-entry
    spelling) are all natural spellings a template author reaches for, and the first two were
    read by the authoring contract's own oracle before #901 folded it into this walk.
    Dropping them would NOT fail safe for the `params:` rule: `check_template` reports the
    entries a verb does not declare, so an unread declaration is an unenforced one — the rule
    is skipped rather than tightened. For the `body_substitutions:` rule the direction is the
    other way and worse: an unread entry makes `check_template` refuse a `${name}` the author
    DID declare, and on the lead lane's promote that refusal discards the whole batch. Either
    way the answer is to read the shape.

    A shape that is not one of those declares nothing rather than raising: the walk's readers
    depend on a malformed key skipping one template, not on it sinking the corpus.
    """
    if isinstance(value, Mapping):
        return tuple(str(k) for k in value)
    if isinstance(value, str):
        # THE one-entry spelling, and a scalar before the sequence branch because a `str` is
        # iterable: read as a sequence it would declare one name per CHARACTER.
        return (value,)
    if isinstance(value, (list, tuple)):
        out: list[str] = []
        for v in value:
            if isinstance(v, Mapping):
                out.extend(str(k) for k in v)
            elif isinstance(v, str):
                out.append(v)
            elif isinstance(v, (int, float)):
                # `bool` is an `int`, and it is read like one ON PURPOSE. An unquoted `on` /
                # `yes` / `no` is a BOOLEAN to YAML, so excluding it would drop the entry —
                # which is the outcome the paragraph above rules out for this rule, and which
                # disagreed with the `Mapping` branch two lines up, where the same value is a
                # key and gets stringified. `str(True)` is not a name either, and that is the
                # point: `check_template` reports it as an undeclared param, so the author is
                # told their `on` was coerced instead of the declaration going unenforced.
                out.append(str(v))
        return tuple(out)
    if isinstance(value, (int, float)):
        # The scalar twin of the `bool`/number entry above, for the same reason and with the
        # same coercion: `params: on` is a one-entry declaration YAML hands over as `True`.
        return (str(value),)
    return ()


def read_query_template(path: Path) -> tuple[QueryTemplate | None, str]:
    """One template file, as `(template, reason)` — `reason` empty on success, else why the file
    is not a template.

    Split out of the walk so a caller holding ONE path (the loop's commit gate, which is handed
    changed paths by git and not a directory to walk) reads it through the same parser the
    corpus does. Returning the reason rather than printing it is what lets that caller refuse a
    commit *with* the reason; `iter_query_templates` keeps the warn-and-skip behavior its
    readers depend on."""
    try:
        text = read_text_utf8(path)
    except TEXT_READ_ERRORS as e:
        return None, f"malformed template: {e}"
    return parse_query_template(text, path)


def parse_query_template(text: str, path: Path) -> tuple[QueryTemplate | None, str]:
    """`read_query_template` for content already in hand, with `path` supplying only the
    LOCATION facts (the file's system, and the template's own `path` field).

    Split from the read because the commit gate has to ask the same questions of a version of
    the file that is not on disk: matching a DELETED draft to the established template that
    took it over means parsing the draft's pre-image out of `git show HEAD:…`, and comparing a
    modified template against what it replaced means parsing both. Routing those through the
    corpus's own parser is what keeps "what the gate thinks this file declares" and "what every
    reader thinks it declares" the same answer."""
    from defender._frontmatter import FrontmatterError, parse_frontmatter

    try:
        fm, body = parse_frontmatter(text)
    except FrontmatterError as e:
        return None, f"malformed template: {e}"
    tid = fm.get("id")
    if not tid or not isinstance(tid, str):
        return None, "malformed template: no `id:`"
    status = fm.get("status")
    sections = section_bodies(body)
    parent = path.parent
    system = parent.parent.name if parent.name == "_draft" else parent.name
    verb = fm.get("verb")
    return QueryTemplate(
        path=path,
        id=tid,
        system=system,
        status=status if isinstance(status, str) else "",
        goal=sections.get("Goal", ""),
        query=sections.get("Query", ""),
        recording=sections.get("Executed query", ""),
        body=body,
        verb=verb if isinstance(verb, str) else "",
        params=_declared_names(fm.get("params")),
        body_substitutions=_declared_names(fm.get("body_substitutions")),
        # Through `_declared_names` like the declaration keys, for its shape tolerance rather
        # than for its name semantics: a one-entry `covers: cmdb.network-map` is the spelling a
        # hand-editing author reaches for, and read as a sequence a `str` would yield one entry
        # per character. What rides here are `query_id`s, not param names.
        covers=_declared_names(fm.get("covers")),
    ), ""


def iter_query_templates(catalog_dir: Path) -> Iterator[QueryTemplate]:
    if not catalog_dir.is_dir():
        return
    paths = sorted(
        list(catalog_dir.glob("*/*.md")) + list(catalog_dir.glob("*/_draft/*.md"))
    )
    for path in paths:
        template, reason = read_query_template(path)
        if template is None:
            print(f"warn: skipping {path.name} ({reason})", file=sys.stderr)
            continue
        yield template
