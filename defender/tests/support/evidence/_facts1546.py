"""#1546 the one owner of the staged-fact and socket vocabulary: every slice's tests and support import it, none hand-writes a
fact body. Per fact, a SENT builder (what the job sends over its socket) and a STAGED builder (what the helper stages and the
worker reads). Test vocabulary, not policy: builders construct records and never decide an outcome, a stage or a screen.

PICKS (r8 wins where it speaks; otherwise the spelling most slices already used):
- socket verbs `outcome page arms arm progress result` take the record as `record=` (`arm` also `run_id=`); objects move on
  `evidence.put(object=, part=, last=, data=)` and `evidence.pull(owner=, object=, part=)`.
- `page` is `{"page": rendered|render_failed|none}`, sent and staged (an arm's is the `page` field of its `arm/<run id>`).
- `arms` is `{"roster": [{"run_id", "world_id"}]}`; `arm/<run id>` is `{"scrub", "page"}` with no roster inside (PR8).
- `knowledge` is staged as the served shape `{status, commit, stale_kind}`; the record shape `{kind, ...}` is only a source.
- the closing field is `review_outcome`; a readiness `result` carries no knowledge (its own staged `knowledge` fact does).
- a learning outcome is sent with `findings {state: ok, text}` and staged with `screened{rows by channel}` or `refused{reason}`.
- an `End` reads the same for both kinds: `stage`/`failure_reason` (a learning row's `status`/`reason` columns take them).
- a drain's staged `result` is its tick's exit status, an int (`DRAIN_EXIT_STATUS`); a readiness job's knowledge record travels on
  the verb `knowledge` (`VERB_KNOWLEDGE`) and is staged mapped to the served shape.
- pull refusals `out_of_claim | unavailable | store_fault`; the verdict reader is `defender.box._scrub.verdict_state(tree)`.
- the helper's store env is `DEFENDER_EVIDENCE_{ENDPOINT,BUCKET,ACCESS_KEY,SECRET_KEY,REGION}`; `REGION` is optional (the
  lifecycle requires the other four names).
- owner rows never carry a claim column: the claim names its owner (`jobs.claims.<reference column>`).
"""
from __future__ import annotations

from typing import Any

# --- names ------------------------------------------------------------------------------------------------------------------

VERB_OUTCOME, VERB_PAGE, VERB_ARMS, VERB_ARM, VERB_PROGRESS, VERB_RESULT = (
    "outcome", "page", "arms", "arm", "progress", "result")
VERB_KNOWLEDGE = "knowledge"  # a readiness job's knowledge record, which the helper maps once to the served shape
VERB_PUT, VERB_PULL = "evidence.put", "evidence.pull"
RECORD = "record"  # the argument every record verb carries it in

BUNDLE, RUN_PAGE, EPISODE_PAGE = "bundle", "page/runtime.html", "page/learning.html"
OUT_OF_CLAIM, UNAVAILABLE, STORE_FAULT = "out_of_claim", "unavailable", "store_fault"
VERDICT_READER = "defender.box._scrub.verdict_state"
EVIDENCE_ENV_PREFIX = "DEFENDER_EVIDENCE_"
EVIDENCE_ENV_NAMES = ("ENDPOINT", "BUCKET", "ACCESS_KEY", "SECRET_KEY", "REGION")
UP, PENDING, REFUSED = ("uploaded", "pending", "refused")

#: The claim's reference column per kind (a post-step's is the tenant's learning-check hold).
REFERENCE = {"investigation": "investigation_id", "learning": "learning_job_id", "readiness": "host_request_id",
             "adoption": "host_request_id", "drain": "host_request_id", "post-step": "hold_tenant_id"}


def arm_page(run_id: str) -> str:
    return f"page/runs/{run_id}/runtime.html"


def evidence_env(garage: Any) -> dict[str, str]:
    """The helper's store configuration, by env name, from a Garage handle."""
    values = {"ENDPOINT": garage.endpoint, "BUCKET": garage.bucket, "ACCESS_KEY": garage.access_key,
              "SECRET_KEY": garage.secret_key, "REGION": garage.region}
    return {f"{EVIDENCE_ENV_PREFIX}{name}": values[name] for name in EVIDENCE_ENV_NAMES}


# --- started, knowledge ----------------------------------------------------------------------------------------------------

STARTED = {"container": "started"}
COMMIT = "c" * 40
#: STAGED `knowledge`: the served shape, mapped once by the helper.
KNOWLEDGE = {"status": "current", "commit": COMMIT, "stale_kind": None}
#: The source record the helper maps from (a record, never a staged fact).
KNOWLEDGE_RECORD = {"kind": "fresh", "commit": COMMIT, "stale_kind": None, "reason": None}


def staged_knowledge(commit: str = COMMIT, **over: Any) -> dict[str, Any]:
    return {**KNOWLEDGE, "commit": commit, **over}


# --- outcome, investigation ----------------------------------------------------------------------------------------------

def closing_found(disposition: str = "benign", review_outcome: Any = None) -> dict[str, Any]:
    """`closing: found{disposition, review_outcome, summary}`; the others are `{"found": "never_closed"}` and
    `{"found": "could_not_look", "wording": ...}`."""
    return {"found": "record", "disposition": disposition, "review_outcome": review_outcome, "summary": "the summary"}


def sent_inv_outcome(**over: Any) -> dict[str, Any]:
    """What the job sends: today's job-end facts with `scrub`, `closing`, cost and its lower-limit mark. A completed, benign,
    clean run costing 0.42 unless `over`."""
    return {"setup": "done", "box": "started", "report_committed": True, "scrub": "clean", "cut_short": None,
            "closing": closing_found(), "cost_usd": 0.42, "cost_is_lower_limit": False, **over}


def staged_inv_outcome(**over: Any) -> dict[str, Any]:
    """An investigation's outcome is staged as sent (closed shape, no mapping)."""
    return sent_inv_outcome(**over)


# --- outcome, learning ------------------------------------------------------------------------------------------------------

EMPTY_FINDINGS_TEXT = '{"finding": [], "questioner_finding": []}'


def sent_findings(text: str = EMPTY_FINDINGS_TEXT) -> dict[str, Any]:
    """The job's `findings` field: its raw text in the state `ok` (any other state is a malformed field)."""
    return {"state": "ok", "text": text}


def screened(*rows: dict[str, Any], questioner: tuple[dict[str, Any], ...] = ()) -> dict[str, Any]:
    """STAGED `findings: screened{rows by channel}` (channels are the store's kind names)."""
    return {"state": "screened", "rows": {"finding": list(rows), "questioner_finding": list(questioner)}}


def findings_refused(reason: str = "malformed") -> dict[str, Any]:
    """STAGED `findings: refused{reason}`."""
    return {"state": "refused", "reason": reason}


def _learning_fields(status: str, reason: str | None, cost: float) -> dict[str, Any]:
    return {"status": status, "reason": reason, "message": None, "fork_message_id": "m-1", "stage": "judge",
            "sibling_cost_usd": cost}


def sent_learning_outcome(status: str = "completed", *, findings: Any = None, cost: float = 0.0,
                          reason: str | None = None) -> dict[str, Any]:
    """What the job sends: the learning-end fields, cost, and `findings` as raw text in state `ok` unless `findings`."""
    return {**_learning_fields(status, reason, cost), "findings": findings if findings is not None else sent_findings()}


def staged_learning_outcome(status: str = "completed", *, findings: Any = None, cost: float = 0.0,
                            reason: str | None = None) -> dict[str, Any]:
    """What the helper stages after its screen: the same fields with `findings` as `screened{rows}` (none by default) or
    `refused{reason}`; never the job's raw text."""
    return {**_learning_fields(status, reason, cost), "findings": findings if findings is not None else screened()}


# --- page, arms, arm ---------------------------------------------------------------------------------------------------------

def sent_page(state: str = "rendered") -> dict[str, Any]:
    return {"page": state}


staged_page = sent_page  # staged as sent


def roster(*arms: str | tuple[str, str]) -> dict[str, Any]:
    """`arms`: the roster; an entry is a run id (its world id derived) or `(run_id, world_id)`."""
    return {"roster": [{"run_id": a, "world_id": f"w-{a}"} if isinstance(a, str) else {"run_id": a[0], "world_id": a[1]}
                       for a in arms]}


sent_arms = staged_arms = roster


def sent_arm(scrub: str = "clean", page: str = "rendered") -> dict[str, Any]:
    """`arm/<run id>`: the arm's scrub and its page state. The roster is never inside it."""
    return {"scrub": scrub, "page": page}


staged_arm = sent_arm


def arm_facts(**arms: dict[str, Any]) -> dict[str, Any]:
    """Staged facts of the arms by run id: the roster and each `arm/<id>` (`arm_facts(**{"a-1": sent_arm()})`)."""
    return {"arms": roster(*arms), **{f"arm/{run_id}": body for run_id, body in arms.items()}}


# --- progress, result, refused ------------------------------------------------------------------------------------------------

def inv_progress(cost_usd: float = 0.1) -> dict[str, Any]:
    return {"cost_usd": cost_usd}


def learning_progress(sibling_cost_usd: float = 0.1) -> dict[str, Any]:
    return {"fork_message_id": "m-1", "stage": "judge", "sibling_cost_usd": sibling_cost_usd}


READINESS_RESULT = {"outcome": "ready", "warnings": []}
ADOPTION_RESULT = {"outcome": "nothing_to_adopt", "pr_number": None}
#: a drain's `result` is its tick's exit status, an int (`lead_author_drain` returns it; a fatal refusal is raised, never returned);
#: staged as that int and stored in the row's `result` as the same int.
DRAIN_EXIT_STATUS = 0
RESULTS = {"readiness": READINESS_RESULT, "adoption": ADOPTION_RESULT, "drain": DRAIN_EXIT_STATUS}


def refused(name: str, reason: str = "malformed") -> dict[str, Any]:
    """The staged fact `refused/<name>{reason}`, as the fact dict it is (create-once, owes nothing)."""
    return {f"refused/{name}": {"reason": reason}}


def up(status: str = UP, scrub: str | None = None) -> dict[str, Any]:
    """An upload row's decide-input form `{status, scrub}`."""
    return {"status": status, "scrub": scrub}


#: A learning job's arm in the generated record cases: its run id and world id (the roster names it before its `arm` is sent).
ARM_RUN, ARM_WORLD = "7d1f3a52-9b6e-4c08-a1d4-5e2b8c3f6a90", "c4e8b2d1-3a57-4f90-8e16-b7a2d5c9f301"

#: Each verb a job stages a fact through, one case per (kind, record name): (kind, verb, sent record, fact name, staged body).
#: The control of every malformed-record case; the staged body is what the helper leaves (equal to the sent record unless it
#: screens or maps). `arm` is sent with `run_id=ARM_RUN` after `arms` names it, and its fact is `arm/<ARM_RUN>`.
VALID: dict[str, tuple[str, str, Any, str, Any]] = {
    "investigation-outcome": ("investigation", VERB_OUTCOME, sent_inv_outcome(), "outcome", staged_inv_outcome()),
    "learning-outcome": ("learning", VERB_OUTCOME, sent_learning_outcome(), "outcome", staged_learning_outcome()),
    "investigation-page": ("investigation", VERB_PAGE, sent_page(), "page", staged_page()),
    "learning-arms": ("learning", VERB_ARMS, sent_arms((ARM_RUN, ARM_WORLD)), "arms", staged_arms((ARM_RUN, ARM_WORLD))),
    "learning-arm": ("learning", VERB_ARM, sent_arm(), f"arm/{ARM_RUN}", staged_arm()),
    "readiness-result": ("readiness", VERB_RESULT, READINESS_RESULT, "result", READINESS_RESULT),
    "readiness-knowledge": ("readiness", VERB_KNOWLEDGE, KNOWLEDGE_RECORD, "knowledge", KNOWLEDGE),
    "adoption-result": ("adoption", VERB_RESULT, ADOPTION_RESULT, "result", ADOPTION_RESULT),
    "drain-result": ("drain", VERB_RESULT, DRAIN_EXIT_STATUS, "result", DRAIN_EXIT_STATUS),
}

#: The launch fact naming the claim's inputs folder (`.job-inputs/<claim>/`, design "The job's folders"), from which a container
#: builds its `JobTenant`'s `run_knowledge` and `export_folder(pin)`; adopted from the implementation's helper (both kinds).
LAUNCH_INPUTS = "inputs_dir"
