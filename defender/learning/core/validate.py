from __future__ import annotations

import re
from pathlib import Path

import yaml

from defender._yaml import safe_load
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




#: One fenced block: its opening marker on a line of its own, its body, its closing marker.
#: `MULTILINE` so successive blocks are found in order, `DOTALL` so a body spans lines, and
#: non-greedy so each match ends at its OWN closing marker rather than the reply's last one.
_FENCE_BLOCK = re.compile(
    r"^```(?:yaml|yml)?[^\S\n]*\n(.*?)\n```[^\S\n]*$", re.DOTALL | re.MULTILINE
)


def _is_document(text: str) -> bool:
    """Does `text` load as a YAML MAPPING — the one shape both consumers of
    `strip_yaml_fence` go on to require (`normalize_judge_yaml` -> `validate_reply`, and the
    questioner's `_reply_document`)? Asked here so the fence rules can tell a verdict from
    the prose, log excerpt or code sample a model fences beside it."""
    try:
        return isinstance(safe_load(text), dict)
    except (yaml.YAMLError, RecursionError):
        return False


def _fenced_document(s: str) -> str | None:
    """The body of the reply's ONE fenced document, or `None` when there is not exactly one.

    Zero means every fence holds something else — a quoted log, a code sample — and the
    document, if there is one, is outside them: reducing to a fence would throw it away.
    Two or more means the model wrote a document, then wrote another; nothing here can say
    which one it meant, and picking the first records an abandoned draft as the verdict."""
    bodies = [m.group(1).strip() for m in _FENCE_BLOCK.finditer(s)]
    documents = [body for body in bodies if _is_document(body)]
    return documents[0] if len(documents) == 1 else None


def strip_yaml_fence(text: str) -> str:
    s = text.strip()
    m = re.search(r"</[a-zA-Z_][\w-]*?think[a-zA-Z_]*>\s*\n", s) or re.search(
        r"</think(?:ing)?>\s*\n", s
    )
    if m:
        s = s[m.end():].strip()
    m = re.match(r"\A```(?:yaml|yml)?\s*\n(.*?)\n```\s*\Z", s, re.DOTALL)
    if m:
        s = m.group(1).strip()
    else:
        # ONLY WHEN THE ANCHORED RULE DID NOT FIRE, and only when the reply offers exactly
        # one fenced block that is a document.
        #
        # The guard this replaces was `not s.startswith("```")`, which switched the rule off
        # in the case it exists for: a verdict shaped "whole fence, then a closing sentence"
        # matched neither rule, reached `yaml.safe_load` with its backticks intact, and the
        # draw was refused (#881/O1). But dropping the guard outright let an unanchored,
        # leftmost `re.search` claim the FIRST fence in the reply whatever it held — an
        # abandoned draft the model then corrected, a quoted log, an example block inside an
        # outer fence — and silently return it as the verdict. A wrong grade recorded with no
        # error is worse than the refusal it replaced, so the rule declines to guess: when
        # nothing or more than one thing here is a document, `s` is left as it stands, which
        # is the loud refusal both consumers already handle.
        _reduced = _fenced_document(s)
        if _reduced is not None:
            s = _reduced
    m = re.match(r"\A<([a-zA-Z_][\w-]*)\s*>\s*\n(.*?)\n\s*</\1>\s*\Z", s, re.DOTALL)
    if m:
        s = m.group(2).strip()
    s = re.sub(r"\n\s*</[a-zA-Z_][\w-]*>\s*\Z", "", s)
    s = re.sub(r"\n\s*```\s*\Z", "", s)
    return s


def strip_yaml_preamble(text: str) -> str:
    lines = text.split("\n")
    for i in range(len(lines)):
        candidate = text if i == 0 else "\n".join(lines[i:])
        try:
            doc = safe_load(candidate)
        except yaml.YAMLError:
            continue
        if isinstance(doc, dict):
            if not i:
                return text
            suffix = lines[i:]
            while suffix and not suffix[0].strip():
                del suffix[0]
            return "\n".join(suffix)
    return text


def normalize_judge_yaml(text: str) -> str:
    return strip_yaml_preamble(strip_yaml_fence(text))
