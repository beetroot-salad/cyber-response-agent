"""Grep defender lesson FRONTMATTER (only) + enumerate viable tags."""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from defender._frontmatter import FrontmatterError, split_frontmatter
from defender._untrusted import wrap_fresh
from defender.knowledge._corpus import Lesson
from defender.investigation.lessons_engine._lessons_common import (
    NoAgentRoot,
    agent_knowledge,
    iter_lessons,
    use_utf8_stdio,
)
from defender._io import read_text_utf8

DIMENSIONS = ("source_signature", "telemetry_source", "attack_phase")


def _emit_match(lesson: Lesson) -> None:
    # The path prints as is: the loader skips a lesson whose file name is not one printable line.
    print(f"{lesson.path.resolve()}\t{lesson.line('description')}")


def lessons_dir() -> Path:
    """The run's own runtime corpus: `$DEFENDER_AGENT_DIR/lessons` (#1108 P4, O2)."""
    return agent_knowledge().lessons_dir


def cmd_grep(patterns: list[str], signature: str | None = None) -> int:
    try:
        regexes = [re.compile(p, re.IGNORECASE) for p in patterns]
    except re.error as e:
        print(f"error: bad regex: {e}", file=sys.stderr)
        return 2
    for lesson in iter_lessons(lessons_dir()):
        # A signature is a key: the whole entry, equal as text, never a pattern over it.
        if signature is not None and signature not in lesson.lines("source_signature"):
            continue
        text = lesson.match_text()
        if all(rx.search(text) for rx in regexes):
            _emit_match(lesson)
    return 0


def cmd_tags(field: str | None) -> int:
    fields = [field] if field else list(DIMENSIONS)
    if field and field not in DIMENSIONS:
        print(f"error: unknown dimension {field!r}; choose from {', '.join(DIMENSIONS)}", file=sys.stderr)
        return 2
    lessons = list(iter_lessons(lessons_dir()))
    for f in fields:
        counts: dict[str, int] = {}
        for lesson in lessons:
            for tag in lesson.lines(f):
                counts[tag] = counts.get(tag, 0) + 1
        print(f"{f}:")
        for val in sorted(counts):
            print(f"  {val:<32} {counts[val]}")
    return 0


def cmd_show(paths: list[str]) -> int:
    rc = 0
    knowledge = agent_knowledge()
    corpus = knowledge.lessons_dir.resolve()
    for raw_path in paths:
        p = Path(raw_path)
        if not p.is_absolute():
            # Repo-relative, as the tenant repo that versions the agent root spells it
            # (`agent/lessons/<name>.md`, #1108 P4 OD6).
            p = knowledge.agent_root.parent / raw_path
        lesson = p.resolve()
        try:
            lesson.relative_to(corpus)
            inside = True
        except ValueError:
            inside = False
        if not inside or not lesson.is_file():
            print(f"error: no such lesson: {raw_path}", file=sys.stderr)
            rc = 2
            continue
        try:
            fm_raw = split_frontmatter(read_text_utf8(lesson))[1]
        except (FrontmatterError, OSError, UnicodeDecodeError) as e:
            print(f"error: {raw_path}: malformed lesson: {e}", file=sys.stderr)
            rc = 2
            continue
        print(f"--- {lesson.resolve()}")
        # The frontmatter as written, for a model to read: framed, as all lesson text bound for
        # a model is (`defender.knowledge._corpus`), so a line of it cannot read as this output's own.
        print(wrap_fresh(fm_raw, "untrusted"))
    return rc


def main(argv: list[str]) -> int:
    use_utf8_stdio()
    ap = argparse.ArgumentParser(
        prog="defender-lessons",
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="frontmatter-only: the body is never matched or printed.",
    )
    ap.add_argument("patterns", nargs="*", help="regex(es) matched against frontmatter; ANDed")
    ap.add_argument("--signature", metavar="SIG",
                    help="only lessons whose source_signature lists SIG exactly (case-sensitive)")
    ap.add_argument("--tags", nargs="?", const="", metavar="DIMENSION",
                    help="enumerate viable tag values (all dimensions, or one named)")
    ap.add_argument("--show", nargs="+", metavar="PATH",
                    help="print only the frontmatter block of the given lesson(s)")
    ns = ap.parse_args(argv[1:])

    try:
        if ns.tags is not None:
            return cmd_tags(ns.tags or None)
        if ns.show:
            return cmd_show(ns.show)
        return cmd_grep(ns.patterns, ns.signature)
    except NoAgentRoot as missing:
        print(f"error: {missing}", file=sys.stderr)
        return 2

if __name__ == "__main__":  # lint-log-setup: ok — a model tool — its stderr is read back by the model as plain text
    sys.exit(main(sys.argv))
