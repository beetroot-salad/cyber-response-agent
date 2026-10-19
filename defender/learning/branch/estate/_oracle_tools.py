"""Oracle function schemas and submitted reply contracts."""
from __future__ import annotations










from collections.abc import Mapping

from dataclasses import dataclass, field


from typing import Any















from defender.learning.branch.estate._oracle_attempt import _Attempt as _Attempt





def _schema(properties: dict, required: list[str]) -> dict:
    return {"type": "object", "properties": properties, "required": required,
            "additionalProperties": False}




_ANY: dict = {}


_QUERY_SCHEMA = _schema({"system": {"type": "string"}, "verb": {"type": "string"},
                         "params": {"type": "object"}}, ["system", "verb"])


_SERVED_SCHEMA = _schema({"served": _ANY, "claim": {"type": "object"}}, ["served", "claim"])



#: The oracle's function tools: name, description, argument schema. `submit` is its output.
_ORACLE_TOOLS: tuple[tuple[str, str, dict], ...] = (
    ("run_query", "Read a real system through the gather grant (read verbs only).",
     _QUERY_SCHEMA),
    ("forge", "Stage a forged row of the call's system for one of this world's facts.",
     _schema({"forged_id": {"type": "string"}, "fact_id": {"type": "string"},
              "row": {"type": ["object", "array"]}},
             ["forged_id", "fact_id", "row"])),
    ("record_fact", "Record the value a fact fixes for an entity's field.",
     _schema({"entity": {"type": "string"}, "field": {"type": "string"}, "value": _ANY},
             ["entity", "field", "value"])),
    ("python", "Run Python in the oracle's sandboxed scratch box.",
     _schema({"code": {"type": "string"}}, ["code"])),
    ("check", "Run the host checks on a draft submission.", _SERVED_SCHEMA),
)


_SUBMIT = ("submit", "Submit the served answer and its claim; ends the turn.", _SERVED_SCHEMA)


_VERDICT = ("verdict", "Pass or fail the served answer, with a reason.",
            _schema({"passed": {"type": "boolean"}, "reason": {"type": "string"}},
                    ["passed", "reason"]))




@dataclass
class _Submitted:
    served: Any
    claim: dict
    verdict: dict
    attempt: _Attempt
    #: The frozen-row id collisions this answer serves (M12=A), recorded only once it commits.
    collisions: list[dict] = field(default_factory=list)




@dataclass
class _Outcome:
    """How an oracle run ended: the `submit` call it ended on (`call_id`, and `answer`, that
    call's result as the oracle reads it), and either the verified submission or the failure
    verdict (`told`: already handed over as `answer`)."""

    call_id: str | None
    answer: str
    submitted: _Submitted | None = None
    failure: str = ""
    told: bool = False




def _no_submission(_text: str) -> _Outcome:
    return _Outcome(None, "", failure="the turn ended without a submission: call "
                                      "submit(served, claim) to end a turn")




def _verdict_given(args: Any) -> dict:
    passed = args.get("passed") if isinstance(args, Mapping) else None
    if not isinstance(passed, bool):
        return dict(_NO_VERDICT)
    return {"passed": passed, "reason": str(args.get("reason") or "")}




def _no_verdict(_text: str) -> dict:
    return dict(_NO_VERDICT)




_NO_VERDICT = {"passed": False, "reason": "the verifier produced no usable verdict"}
