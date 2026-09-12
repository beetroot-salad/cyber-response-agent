from __future__ import annotations

import re
from pathlib import Path

from defender._report import ReportRead, read_report
from defender.learning.core.config import RunUnprocessable




def normalize_disposition(report_path: Path) -> str:
    """The run's disposition, or `RunUnprocessable`.

    What the value MEANS is `_report.read_report`'s single decision. What stays here is the
    loop's REACTION: a case whose headline it cannot read is refused with a typed error the
    drain can dead-letter, never guessed at. The head-of-file dump accompanies every refusal —
    it is the operator's only view of what the model actually wrote.
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


# A closing think tag on a line of its own at column 0, trailing spaces allowed. Anchored to a
# whole line rather than searched, because a column-0 `</…>` line cannot sit inside loadable
# YAML (`safe_load` refuses it) while one quoted inside a block scalar is indented and untouched
# — so untrusted text quoted in the reply cannot move the parse boundary. No opening tag is
# required: the recorded prelude shape has none.
_THINK_CLOSE_LINE = re.compile(
    r"^</(?:think(?:ing)?|[a-zA-Z_][\w-]*?think[a-zA-Z_]*)>[ \t]*$", re.MULTILINE)
_FENCE_LINE = re.compile(r"^```", re.MULTILINE)
_ONE_FENCED_DOCUMENT = re.compile(r"\A```([A-Za-z0-9_+-]*)[ \t]*\n(.*)\n```[ \t]*\Z", re.DOTALL)


def reply_document_text(text: str) -> str:
    """The bare document text of one model reply, or `MalformedReply` naming the shape.

    A reply is one document, or it is malformed — the parser does not guess which of several
    blocks the model meant (#1018: every attempt at guessing recorded a wrong verdict silently
    on some other shape). In order: CRLF and a leading BOM are normalised; a reasoning prelude
    ending in a column-0 closing think tag is dropped; the remainder is either exactly one
    fenced block (any tag — a `json` tag on one document is still one document) or unfenced
    text holding no column-0 fence line. An indented ``` or `</think>` inside a block scalar is
    part of the document and stays. Loading and schema validation are the consumer's job.
    """
    s = text.replace("\r\n", "\n").lstrip("\ufeff")
    prelude = _THINK_CLOSE_LINE.search(s)
    if prelude:
        s = s[prelude.end():]
    s = s.strip()
    if not s:
        raise MalformedReply("empty reply")
    if not s.startswith("```"):
        if _FENCE_LINE.search(s):
            raise MalformedReply("a fence inside the reply — the document must be bare")
        return s
    fenced = _ONE_FENCED_DOCUMENT.match(s)
    if not fenced:
        raise MalformedReply(_fenced_shape(s))
    body = fenced.group(2)
    if _FENCE_LINE.search(body):
        raise MalformedReply("a second fence — the reply must hold exactly one document")
    body = body.strip()
    if not body:
        raise MalformedReply("empty fence")
    return body


def _fenced_shape(s: str) -> str:
    """Why a reply that opens with a fence is not one fenced document, for the refusal."""
    lines = s.split("\n")
    closers = [i for i, line in enumerate(lines) if i and line.startswith("```")]
    if not closers:
        return "no closing fence"
    if len(closers) > 1:
        return "a second fence — the reply must hold exactly one document"
    first = closers[0]
    if lines[first].rstrip(" \t") != "```":
        return f"closing fence with trailing characters ({lines[first].strip()!r})"
    if any(line.strip() for line in lines[first + 1:]):
        return "text after the closing fence"
    return "empty fence"
