from __future__ import annotations

import re
from pathlib import Path

import yaml

from defender._report import ReportRead, read_report
from defender._yaml import safe_load
from defender.learning.core.config import RunUnprocessable




def normalize_disposition(report_path: Path) -> str:
    """The run's disposition, or `RunUnprocessable`.

    `_report.read_report` decides what the value means; this refuses an unreadable headline
    with a typed error the drain can dead-letter, never a guess. Each refusal carries the
    report's head, the operator's only view of what the model wrote.
    """
    read = read_report(report_path)
    if read.disposition is None:
        raise RunUnprocessable(_unprocessable_reason(read, report_path))
    return read.disposition


def _unprocessable_reason(read: ReportRead, report_path: Path) -> str:
    if not read.text:
        return str(read.reason)
    head = "\n".join(read.text.splitlines()[:30])
    return f"{read.reason}\n--- {report_path} (head) ---\n{head}"


class MalformedReply(ValueError):
    """A model reply that is not exactly one bare document. The message names the shape."""


# An unindented line ending in a closing think tag (alone or closing a line of reasoning); no
# opening tag is required. Column 0, so a tag quoted in an indented block scalar doesn't end a
# prelude. Only searched in a bare reply that doesn't already load as a mapping, so a tag
# quoted inside a valid or fenced document never moves the boundary. Residual gap: a broken
# bare reply quoting a column-0 close tag may be cut inside the quote.
_THINK_CLOSE_LINE = re.compile(
    r"^(?:\S[^\n]*?)?</(?:think(?:ing)?|[a-zA-Z_][\w-]*?think[a-zA-Z_]*)>[ \t]*$", re.MULTILINE)
_FENCE_LINE = re.compile(r"^```", re.MULTILINE)
_FENCE_OPENER = re.compile(r"```[A-Za-z0-9_+-]*[ \t]*")
_ONE_FENCED_DOCUMENT = re.compile(r"\A```([A-Za-z0-9_+-]*)[ \t]*\n(.*)\n```[ \t]*\Z", re.DOTALL)


def reply_document_text(text: str) -> str:
    """The bare document text of one model reply, or `MalformedReply` naming the shape.

    A reply is one document or it is malformed; the parser never guesses which of several
    blocks the model meant, since guessing silently records wrong verdicts. In order: CRLF and
    a leading BOM are normalised; a bare reply that doesn't load as a mapping may have a
    reasoning prelude ending in a think-close line, which is dropped; the remainder is exactly
    one fenced block (any tag) or unfenced text. A column-0 ``` line inside is a second block
    unless the text loads as one mapping. Loading and schema validation are the consumer's
    job; the loads here are shape tests.
    """
    s = text.replace("\r\n", "\n").lstrip("\ufeff").strip()
    if not s:
        raise MalformedReply("empty reply")
    loads = not s.startswith("```") and _loads_as_mapping(s)
    if not s.startswith("```") and not loads:
        prelude = _THINK_CLOSE_LINE.search(s)
        if prelude:
            rest = s[prelude.end():].strip()
            if not rest:
                raise MalformedReply("a closing think tag with no document following it")
            s = rest
            loads = not s.startswith("```") and _loads_as_mapping(s)
    if not s.startswith("```"):
        if _FENCE_LINE.search(s) and not loads:
            raise MalformedReply("a fence inside the reply — the document must be bare")
        return s
    fenced = _ONE_FENCED_DOCUMENT.match(s)
    if not fenced:
        raise MalformedReply(_fenced_shape(s))
    body = fenced.group(2).strip()
    if not body:
        raise MalformedReply("empty fence")
    if _FENCE_LINE.search(body) and not _loads_as_mapping(body):
        raise MalformedReply("a second fence — the reply must hold exactly one document")
    return body


def _loads_as_mapping(s: str) -> bool:
    """Does the text load as one YAML mapping? Not merely "loads": prose plus a fenced block
    loads as one plain scalar."""
    try:
        return isinstance(safe_load(s), dict)
    except yaml.YAMLError:
        return False


def _fenced_shape(s: str) -> str:
    """Why a reply that opens with a fence is not one fenced document, for the refusal."""
    lines = s.split("\n")
    closers = [i for i, line in enumerate(lines) if i and line.startswith("```")]
    if not closers:
        return "no closing fence"
    if not _FENCE_OPENER.fullmatch(lines[0]):
        return f"an opening fence line carrying more than a tag ({lines[0].strip()!r})"
    if len(closers) > 1:
        return "a second fence — the reply must hold exactly one document"
    first = closers[0]
    if lines[first].rstrip(" \t") != "```":
        return f"closing fence with trailing characters ({lines[first].strip()!r})"
    if any(line.strip() for line in lines[first + 1:]):
        return "text after the closing fence"
    return "empty fence"
