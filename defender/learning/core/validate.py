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


# A line ENDING in a closing think tag, trailing spaces allowed — on its own line (the recorded
# prelude shape) or closing a line of reasoning (`…so caught.</think>`). No opening tag is
# required: the recorded prelude shape has none. Only a BARE reply that does not already load
# as one mapping is searched for it: a reply opening with a fence has nothing in front of the
# document by construction, and a loadable reply is the document — so a tag quoted inside a
# valid document, or inside a fenced one, never moves the parse boundary. What remains is a
# bare reply that is broken YAML AND quotes a column-0 close tag: the cut may land inside the
# quote, and the consumer's loader is what decides the remainder. A YAML-aware scan would
# close that too; it is not worth its weight against a reply that was already unloadable.
_THINK_CLOSE_LINE = re.compile(
    r"</(?:think(?:ing)?|[a-zA-Z_][\w-]*?think[a-zA-Z_]*)>[ \t]*$", re.MULTILINE)
_FENCE_LINE = re.compile(r"^```", re.MULTILINE)
_FENCE_OPENER = re.compile(r"```[A-Za-z0-9_+-]*[ \t]*")
_ONE_FENCED_DOCUMENT = re.compile(r"\A```([A-Za-z0-9_+-]*)[ \t]*\n(.*)\n```[ \t]*\Z", re.DOTALL)


def reply_document_text(text: str) -> str:
    """The bare document text of one model reply, or `MalformedReply` naming the shape.

    A reply is one document, or it is malformed — the parser does not guess which of several
    blocks the model meant (#1018: every attempt at guessing recorded a wrong verdict silently
    on some other shape). In order: CRLF and a leading BOM are normalised; a bare reply that
    does not already load as one mapping may carry a reasoning prelude ending in a line that
    closes a think tag, which is dropped; the remainder is either exactly one fenced block (any
    tag — a `json` tag on one document is still one document) or unfenced text. A column-0 ```
    line inside either is a second block UNLESS the text loads as one mapping — a fence line
    inside a quoted scalar is document, not a fence. Schema validation is the consumer's job,
    and so is loading the returned text: the loads here are shape tests only.
    """
    s = text.replace("\r\n", "\n").lstrip("\ufeff").strip()
    if not s:
        raise MalformedReply("empty reply")
    if not s.startswith("```") and not _loads_as_mapping(s):
        prelude = _THINK_CLOSE_LINE.search(s)
        if prelude:
            s = s[prelude.end():].strip()
            if not s:
                raise MalformedReply("empty reply")
    if not s.startswith("```"):
        if _FENCE_LINE.search(s) and not _loads_as_mapping(s):
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
    """Does the text load as one YAML mapping? A mapping, not merely "loads": a prose line and a
    fenced block together load as one multi-line plain scalar, and that is not a document."""
    import yaml

    from defender._yaml import safe_load

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
