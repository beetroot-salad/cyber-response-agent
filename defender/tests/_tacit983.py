"""The container-root investigation the #983 suites are all written against.

ONE document builder, shared by the unit suites and the e2e replay, because every #983
scenario is the SAME case with one cell moved: a container's UID 0 rewriting the CA bundle
on a build-runner host — the actor class the issue's own transcript dead-ended on, because
no identity system in this deployment holds a record for container UID 0 (claim c7, carried
as given). Each scenario differs only in which `:R` row it writes, so a second hand-built
document per test would be four copies of the same eleven blocks drifting apart.

The blocks are modelled on `examples/example-b-parallel-iam-cmdb.md`, which the shipped
corpus keeps green — so a refusal any of these suites reports is about the cell the scenario
moved and not about a hypothesis block that never validated in the first place.

NOT a test module (the leading underscore keeps pytest from collecting it).
"""

from __future__ import annotations

#: The alerted event's own timestamp. A `:R consultations` window is judged against this:
#: a baseline that does not END before the alert began is a pattern that starts with the
#: incident, which is the incident (design doc, mechanism A's first guard).
ALERT_WHEN = "2026-05-05T03:42:11Z"

#: A window that closes the day before the alert — the shape mechanism A's guard admits.
WINDOW_BEFORE_ALERT = "2026-04-04T00:00:00Z/2026-05-04T00:00:00Z"

#: A window that opens ON the alerted event and runs forward. The pattern IS the incident.
WINDOW_STARTING_AT_ALERT = "2026-05-05T03:42:11Z/2026-06-04T00:00:00Z"

#: The registry entry id the discharging `:R authz` row cites as `anchor_id`, and the id the
#: `entries:` fixture below declares. One name, so a test cannot assert a hit against an entry
#: the fixture spells differently.
ENTRY_ID = "tk-ca-bundle-build-runner"

#: The actor and host the alerted edge names — what a registry entry's `actor_scope` /
#: `host_scope` has to cover for the lookup to be a hit.
ACTOR = "uid-0"
HOST = "build-runner-07.prod"
PATTERN = "rewrite /etc/ssl/certs/ca-bundle.crt"

#: The `:R authz` header this suite writes. `grounding`, `anchor_id` and `basis` are all
#: optional columns the header-driven parser canonicalizes without a parser change; the
#: documented header in `skills/invlang/SKILL.md` names neither of the first two (fork F5).
AUTHZ_HEADER = (
    ":R authz [resolved_by|edge|fulfills|verdict|anchor_kind|grounding|anchor_id|basis|reasoning]"
)

#: The `:R consultations` header. `AnchorConsultation` carries no `fulfills_contract` field,
#: so there is deliberately no `fulfills` column here — the type cannot carry a verdict, which
#: is what makes mechanism A context-only by construction rather than by convention.
CONSULT_HEADER = (
    ":R consultations [resolved_by|anchor_kind|grounding|anchor_id|result|effective_window|reasoning]"
)


def authz_row(
    *,
    verdict: str = "authorized",
    anchor_kind: str = "tacit-knowledge",
    grounding: str = "org-authority",
    anchor_id: str = ENTRY_ID,
    basis: str = "",
    resolved_by: str = "l-001",
    reasoning: str = "registry entry covers uid-0 on build-runner hosts, review_by 2026-09-01",
) -> str:
    """One `:R authz` row under `AUTHZ_HEADER`. An empty cell is DROPPED by the parser, so
    `basis=""` is how a row spells "no basis column value" — which reads as `retry`."""
    return (
        f"{resolved_by}|e-001|ac1|{verdict}|{anchor_kind}|{grounding}|{anchor_id}|{basis}|"
        f'"{reasoning}"'
    )


def consultation_row(
    *,
    anchor_kind: str = "runtime-evidence",
    grounding: str = "telemetry-baseline",
    anchor_id: str = "tk-baseline-30d",
    result: str = "1500 occurrences over 30d; actor uid-0 and host build-runner-07.prod throughout",
    window: str = WINDOW_BEFORE_ALERT,
    reasoning: str = "no adverse outcome fell inside the window",
    resolved_by: str = "l-001",
) -> str:
    """One `:R consultations` row under `CONSULT_HEADER`."""
    return (
        f'{resolved_by}|{anchor_kind}|{grounding}|{anchor_id}|"{result}"|{window}|"{reasoning}"'
    )


_PROLOGUE = """\
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|container-host/internal/known-corp|build-runner-07.prod|kind=container;ip=10.30.1.44
v-002|file|config|/etc/ssl/certs/ca-bundle.crt|
v-003|identity|service-account/known-corp|uid-0|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|wrote|v-001|v-002|{alert_when}|runtime-audit:falco|uid=0;comm=update-ca-trust

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?sanctioned-image-build-step|v-001|runs_on|process|??||null|active
h-002|?adversary-controlled-container-escape|v-001|runs_on|process|??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_parent|"the writing process is the image build's own ca-trust step"
p2|proposed_parent|"the same write appears on every build-runner host in the fleet"

:H h-001.refuts [id|refutes|claim]
r1|p1|"the writing process has no build-pipeline ancestry"

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|{contract_anchor_kind}|"container UID 0 is sanctioned to rewrite the CA bundle on build-runner hosts"|escalate|escalate

:H h-002.preds [id|subject|claim]
p1|proposed_parent|"the writing process is spawned from an interactive session"
p2|proposed_parent|"the process is present on this host alone, not on its fleet peers"

:H h-002.refuts [id|refutes|claim]
r1|p1,p2|"the writing process is build-spawned and matches its fleet peers"

:L findings [id|loop|name|target|tests|system|window]
l-001|1|registry-lookup|v-003|h-001,h-002|{system}|n/a
l-002|1|planned-never-dispatched|v-003|h-001|host-state|n/a
```
"""

_RESOLVED = """\
```invlang
:R attr_updates [resolved_by|target|key|value]
l-001|v-001|attrs.knowledge|full
{rows}
:T resolutions
h-001  null → {h1}   [l-001 {h1_cites} {h1_force} ⟂ e-001 :: {h1_note}]
h-002  null → {h2}   [l-001 r1 {h2_force} ⟂ e-001 :: build-spawned and fleet-wide]

:T close
loop  1
```
"""

_CONCLUDE_BENIGN = """\
```invlang
:T conclude
termination.category   adversarial-refuted
disposition            benign
impact_verdict         none
confidence             high
matched_archetype      sanctioned-image-build-step
summary                "container UID 0 rewriting the CA bundle on build-runner-07.prod is the image build's own ca-trust step, sanctioned by an authored tacit-knowledge registry entry."

:T conclude.surviving [hyp_id|final_weight]
h-001|++
```
"""


#: The close a container-root case reaches TODAY, and the one #983 exists to make avoidable:
#: nothing settled the legitimacy question, so the contract is deferred and the run escalates.
#: `ceiling_test` names `l-002`, the lead that came back empty — the receipt `inconclusive`'s
#: own entry price demands.
_CONCLUDE_INCONCLUSIVE = """\
```invlang
:T conclude
termination.category   exhaustion-escalation
disposition            inconclusive
impact_verdict         none
confidence             low
ceiling_test           state=query-empty ref=l-002 note=host-state proc-tree came back empty for the build container
summary                "container UID 0 rewriting the CA bundle could not be tied to the image build."

:T conclude.surviving [hyp_id|final_weight]
h-001|+
h-002|-

:T conclude.deferred_authz [contract_ref|rationale]
h-001.ac1|"no unexpired registry entry covers uid-0 on this host"

:T conclude.deferred_preds [prediction_ref|rationale]
h-001.p1|"process ancestry telemetry was not collected in the build container"
h-002.p1|"process ancestry telemetry was not collected in the build container"
h-002.p2|"fleet comparison needs host-state on the peers, which was not retrieved"
```
"""


def document(
    *,
    rows: str = "",
    contract_anchor_kind: str = "tacit-knowledge",
    system: str = "tacit-knowledge",
    settled: bool = True,
    conclude: str = "",
) -> str:
    """The investigation, with `rows` spliced into the `:R` block.

    `settled=True` grades `h-001` to `++` and `h-002` to `--` — the shape a benign close
    needs. `settled=False` leaves both at a mild grade, which is what a run whose
    authorization question is still open honestly records.

    `conclude` is appended verbatim; the default writes NO `:T conclude` at all, so a
    scenario can drive the close tool's own entry price rather than the document's.
    """
    strong = dict(
        h1="++", h1_cites="p1,p2", h1_force="severe",
        h1_note="sanctioned by an authored registry entry", h2="--", h2_force="severe",
    )
    mild = dict(
        h1="+", h1_cites="p2", h1_force="mild",
        h1_note="dense recurrence, nothing adverse in the window", h2="-", h2_force="mild",
    )
    prologue = _PROLOGUE.format(
        alert_when=ALERT_WHEN, contract_anchor_kind=contract_anchor_kind, system=system,
    )
    body = _RESOLVED.format(rows=f"\n{rows}\n" if rows else "", **(strong if settled else mild))
    return f"{prologue}\n{body}" + (f"\n{conclude}" if conclude else "")


def benign_document(*, rows: str, **kwargs) -> str:
    """The same document concluding `benign` — the close mechanism B has to make reachable."""
    return document(rows=rows, conclude=_CONCLUDE_BENIGN, **kwargs)


def inconclusive_document(*, rows: str, **kwargs) -> str:
    """The same case concluding `inconclusive` with its contract deferred and its gap named —
    the close a container-root alert reaches when no registry entry answers."""
    kwargs.setdefault("contract_anchor_kind", "tacit-knowledge")
    kwargs.setdefault("settled", False)
    return document(rows=rows, conclude=_CONCLUDE_INCONCLUSIVE, **kwargs)


def authz_block(row: str) -> str:
    return f"{AUTHZ_HEADER}\n{row}\n"


def consult_block(row: str) -> str:
    return f"{CONSULT_HEADER}\n{row}\n"
