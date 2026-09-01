#!/usr/bin/env python3
"""Grade a defender run against the #986 rubric: did the investigation TURN AROUND?

The defect (#986): a lead resolved the alerted entity's real identity — the alert named the
Docker host `soc-playground`, the activity was inside container `db-1` — and the run wrote that
resolution into the record correctly, edges and all, and then kept every governance question
aimed at the host. It closed `inconclusive` on "soc-playground is unregistered in all available
governance systems", while `db-1`'s full governance record had been in hand since loop 1.

WHY AN LLM JUDGE AND NOT A GREP. The failure is not a missing string. `db-1` appears throughout
the failing document, both edges tying it to the host are present, and the container id is on
three separate rows. What is absent is a JUDGEMENT — whether the questions the run went on to
ask were aimed at the entity they were about. A regex cannot read a `ceiling_test` and say
whether its claim is scoped to the thing that was investigated.

WHAT IS NOT JUDGED. Two facts are computed deterministically and handed to the judge as
evidence rather than left for it to find: which governance systems were queried, and with what
`host` parameter, before and after the resolving lead. Those are table lookups, and a judge
that re-derives them can get them wrong.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

#: The four systems whose answers the disposition rested on. Named here rather than inferred:
#: the rubric's D2 asks whether these specifically were re-asked, and a judge left to decide
#: what counts as "governance" will drift between runs and make the arm incomparable.
GOVERNANCE_SYSTEMS = ("cmdb", "identity", "change-mgmt", "ticket")

MODEL = "claude-opus-5"


class Dimension(BaseModel):
    verdict: Literal["yes", "partial", "no"]
    evidence: list[str] = Field(
        description="Verbatim quotes from the run's own artifacts. Empty only for a 'no' that "
        "rests on absence, and then `reasoning` must say what was searched for."
    )
    reasoning: str


class Grade(BaseModel):
    subject_repointed: Dimension = Field(
        description="D1. Did the record restate the ALERTED vertex's identity to the resolved "
        "entity, or otherwise mark which entity the investigation is now about? Edges tying "
        "the two together are NOT this — the failing run already had both of them."
    )
    governance_reasked: Dimension = Field(
        description="D2. After the container was resolved, was any of the four governance "
        "systems queried AGAIN, parameterised on the resolved entity rather than the alerted "
        "one? Name which systems and count them."
    )
    closing_claim_scoped: Dimension = Field(
        description="D3. Does the closing ceiling_test / disposition rationale make its claim "
        "about the entity the run actually investigated? A claim that the alerted host is "
        "absent from every governance system, when the run resolved a different entity and "
        "never re-asked, is 'no'."
    )
    systems_reasked: list[str] = Field(
        description="Which of cmdb/identity/change-mgmt/ticket were re-queried against the "
        "resolved entity. Empty list if none."
    )
    summary: str


RUBRIC = """\
You are grading one run of an automated alert-triage agent, against a single question:
when the run discovered that the entity named in the alert was not the entity the activity
happened on, did it turn around?

BACKGROUND. The alert fires on a Falco sudo burst and names the host `soc-playground`. That
name is what the monitoring tool stamps on every event — it is the outer Docker host. The
activity is inside a container on it. A lead in the run resolves that container's identity.
The container has its own governance record (owner, change window, service accounts); the
outer host has none.

The failure being tested for is NOT a missing row. A run can write the container as a fully
attributed vertex, with correct edges to the host, and still fail — by leaving every
already-asked governance question answered about the wrong entity, and by closing on a claim
scoped to the wrong entity. Judge the turn-around, not the bookkeeping.

GRADE THREE DIMENSIONS.

D1 — subject re-pointed. Did the record restate the alerted vertex's identity, or write
something that marks which entity the investigation is now about? Adding a second vertex for
the container, and edges between them, is NOT sufficient on its own — say `partial` for that,
and reserve `yes` for a restatement of the alerted vertex's own identity cell or an explicit
statement in the record of which entity the disposition is about.

D2 — governance re-asked. The four systems are cmdb, identity, change-mgmt, ticket. Using the
QUERY TABLE below, determine whether any of them was queried again AFTER the resolving lead,
with parameters naming the resolved entity rather than the alerted host. `yes` = two or more;
`partial` = exactly one; `no` = none. List which in `systems_reasked`.

D3 — closing claim scoped. Read the closing `:T conclude` block. Does its `ceiling_test` and
rationale make a claim about the entity the run actually investigated? A ceiling claim that
the ALERTED host is unregistered everywhere — asserted by a run that resolved a different
entity and never re-asked about it — is `no`, because it asserts something the run did not
check.

Quote verbatim from the artifacts for every dimension. Where you grade `no` on absence, say in
`reasoning` what you looked for.
"""


@dataclass(frozen=True)
class RunEvidence:
    run_id: str
    investigation: str
    report: str
    query_table: str
    resolving_lead: str | None


def _query_table(run_dir: Path) -> tuple[str, str | None]:
    """A compact rendering of the executed-query table, and the lead that resolved the container.

    The resolving lead is found by the first query whose PAYLOAD the run attributed to a
    host-state probe of a container id — in practice the `host-state` system. Returned rather
    than judged, because "which lead resolved it" is a table fact and D2 is scored relative to
    it; a judge that guesses the boundary grades the wrong half of the run.
    """
    path = run_dir / "executed_queries.jsonl"
    if not path.exists():
        return "(no executed_queries.jsonl)", None
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    resolving: str | None = None
    for r in rows:
        if r.get("system") == "host-state" and resolving is None:
            resolving = str(r.get("lead_id"))
    lines = [
        f"{r.get('lead_id')}/{r.get('seq')}  {r.get('system')}  {r.get('query_id')}  "
        f"params={json.dumps(r.get('params'), sort_keys=True)}"
        for r in rows
    ]
    return "\n".join(lines), resolving


def gather(run_dir: Path) -> RunEvidence:
    table, resolving = _query_table(run_dir)
    return RunEvidence(
        run_id=run_dir.name,
        investigation=(run_dir / "investigation.md").read_text(encoding="utf-8"),
        report=(run_dir / "report.md").read_text(encoding="utf-8")
        if (run_dir / "report.md").exists()
        else "(no report.md — the run did not close)",
        query_table=table,
        resolving_lead=resolving,
    )


#: A `,` that the next non-space character closes an object or array on — JSON forbids it,
#: models emit it, and `json.loads` rejects the whole document over one byte.
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def _as_json(text: str) -> str:
    """The judge's reply, reduced to the JSON object in it.

    TOLERANT ON PURPOSE, and only of things that cannot change a grade: a markdown fence the
    model wrapped the object in, and a trailing comma before a closing brace. Both are
    formatting, and a run that has already cost a full investigation is not worth discarding
    over either. Anything that would change a VALUE still raises — a malformed grade must
    fail loudly rather than be repaired into a number nobody produced.
    """
    t = text.strip()
    if t.startswith("```"):
        t = (t.split("\n", 1)[1] if "\n" in t else "").rsplit("```", 1)[0].strip()
    return _TRAILING_COMMA.sub(r"\1", t)


def grade(ev: RunEvidence) -> Grade:
    """One graded run, via `claude -p`.

    NOT the Anthropic SDK. The runtime under test bills Fireworks; the only Anthropic
    credential in this environment is an exhausted API key, and `claude -p` falls through to
    the claude.ai login when that key is UNSET — which is why the environment is stripped
    rather than inherited. A set-but-broken key takes precedence and fails closed.

    The whole record is inlined, so the judge has no reason to reach for a tool: everything the
    rubric asks about is in the prompt, and a judge that went reading the repo would be grading
    against the code rather than against the run.
    """
    boundary = (
        f"The lead that resolved the container is `{ev.resolving_lead}`. Queries at or before "
        f"it are BEFORE the resolution; queries after it are the ones D2 asks about."
        if ev.resolving_lead
        else "No host-state lead ran in this run, so nothing resolved the container."
    )
    schema = json.dumps(Grade.model_json_schema(), indent=2)
    prompt = (
        f"{RUBRIC}\n\n{boundary}\n\n"
        "Reply with ONE JSON object and nothing else — no prose, no markdown fence — "
        f"conforming to this schema:\n\n{schema}\n\n"
        f"=== investigation.md ===\n{ev.investigation}\n\n"
        f"=== report.md ===\n{ev.report}\n\n"
        f"=== QUERY TABLE ===\n{ev.query_table}\n"
    )
    env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
    proc = subprocess.run(  # noqa: S603 — fixed argv, no shell, prompt on stdin
        ["claude", "-p", "--model", MODEL],
        input=prompt,
        capture_output=True,
        text=True,
        env=env,
        timeout=1800,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"claude -p failed ({proc.returncode}): {proc.stderr[-2000:]}")
    return Grade.model_validate_json(_as_json(proc.stdout))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("run_dirs", nargs="+", type=Path)
    ap.add_argument("--out", type=Path, default=Path("results/grades.jsonl"))
    args = ap.parse_args()

    args.out.parent.mkdir(parents=True, exist_ok=True)
    grades: list[tuple[str, Grade]] = []
    with args.out.open("w", encoding="utf-8") as fh:
        for d in args.run_dirs:
            ev = gather(d)
            g = grade(ev)
            grades.append((ev.run_id, g))
            fh.write(json.dumps({"run_id": ev.run_id, **g.model_dump()}) + "\n")
            print(
                f"{ev.run_id}: D1={g.subject_repointed.verdict} "
                f"D2={g.governance_reasked.verdict}{g.systems_reasked} "
                f"D3={g.closing_claim_scoped.verdict}"
            )

    # Per-occurrence means with n shown as support, per the experiment-design ranking rule.
    n = len(grades)
    if n:
        print(f"\n--- {n} runs ---")
        for name, get in (
            ("D1 subject re-pointed", lambda g: g.subject_repointed.verdict),
            ("D2 governance re-asked", lambda g: g.governance_reasked.verdict),
            ("D3 closing claim scoped", lambda g: g.closing_claim_scoped.verdict),
        ):
            yes = sum(1 for _, g in grades if get(g) == "yes")
            part = sum(1 for _, g in grades if get(g) == "partial")
            print(f"{name:26s} yes={yes}/{n}  partial={part}/{n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
