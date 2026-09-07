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
    # UNGUARDED, and the guard it lost was `not s.startswith("```")` — which switched this
    # rule off in exactly the case it exists for. A verdict shaped "whole fence, then a
    # closing sentence" is matched by neither rule: the anchored rule above fails on the
    # trailing prose, and this one was disabled because the fence starts at position 0. The
    # reply then reached `yaml.safe_load` with its backticks intact and the case was refused
    # (#881/O1). For a fence that DOES span the whole string the rule above has already
    # reduced it, so this search is a no-op on that result and the guard bought nothing.
    m = re.search(r"^```(?:yaml|yml)?\s*\n(.*?)\n```", s, re.DOTALL | re.MULTILINE)
    if m:
        s = m.group(1).strip()
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
