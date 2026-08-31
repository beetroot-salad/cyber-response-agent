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

WHAT A REGISTRY HIT COSTS THE DOCUMENT (the anchor-receipt contract, added in the hardening
pass). A `:R authz` row citing `anchor_kind: tacit-knowledge` may not name an `anchor_id` out
of the air: the lead that resolved the row has to have RECORDED the matching entry as its own
lookup outcome first, as a `:R consultations` row on that same lead. So the authorized scene
is TWO rows, not one — `authorized_rows()` builds the pair — and every scenario that fakes a
hit fakes it by moving one cell of that pair (`cited_id=` fabricates the citation, `hit_by=`
moves the recorded hit onto a different lead). See `test_tacit_authz_983`'s
`test_authz_anchor_id_must_match_its_own_leads_recorded_hit` for the check itself.

NOT a test module (the leading underscore keeps pytest from collecting it).
"""

from __future__ import annotations

from pathlib import Path

#: The alerted event's own timestamp. A `:R consultations` window is judged against this:
#: a baseline that does not END before the alert began is a pattern that starts with the
#: incident, which is the incident (design doc, mechanism A's first guard).
ALERT_WHEN = "2026-05-05T03:42:11Z"

#: A window that closes the day before the alert — the shape mechanism A's guard admits.
WINDOW_BEFORE_ALERT = "2026-04-04T00:00:00Z/2026-05-04T00:00:00Z"

#: A window that opens ON the alerted event and runs forward. The pattern IS the incident.
#: Its START is `ALERT_WHEN` spelled character for character, which is what makes it the
#: window a string-equality check catches and every other one below it does not.
WINDOW_STARTING_AT_ALERT = "2026-05-05T03:42:11Z/2026-06-04T00:00:00Z"

#: A window that opens ONE SECOND after the alerted event. Nothing in it is a substring of
#: `ALERT_WHEN`, and it is the same defect as the row above: the "baseline" is entirely made
#: of what happened after the thing being explained.
WINDOW_STARTING_JUST_AFTER_ALERT = "2026-05-05T03:42:12Z/2026-06-04T00:00:00Z"

#: A window that opens six months BEFORE the alert and closes ten weeks after it. Neither
#: endpoint resembles `ALERT_WHEN` as text, and its start genuinely predates the alert — so
#: only an END-vs-alert datetime comparison refuses it. This is the window the hardening pass
#: added: the guard as first written admitted it.
WINDOW_SPANNING_THE_ALERT = "2026-01-09T11:03:47Z/2026-07-19T22:15:00Z"

#: A window whose end is the alerted instant itself. The alert is inside the baseline it is
#: being judged against, by one instant — the boundary the guard has to take strictly.
WINDOW_ENDING_AT_ALERT = "2026-04-05T00:00:00Z/2026-05-05T03:42:11Z"

#: A window no date parser can read. It cannot be judged to predate anything, so it fails
#: CLOSED — and a check that compared strings would accept it, which is the point of keeping
#: it here beside the four above.
WINDOW_UNPARSEABLE = "the-last-30-days"

#: The registry entry id the discharging `:R authz` row cites as `anchor_id`, and the id the
#: `entries:` fixture below declares. One name, so a test cannot assert a hit against an entry
#: the fixture spells differently.
ENTRY_ID = "tk-ca-bundle-build-runner"

#: An `anchor_id` no registry entry carries and no lead ever recorded — the fabrication the
#: anchor-receipt check exists to refuse.
FABRICATED_ENTRY_ID = "tk-ca-bundle-fleetwide"

#: The registry entry's own validity span (`added_at`/`review_by`). It brackets the alert
#: rather than preceding it, and deliberately so: a sanction that stopped being valid before
#: the alert would not cover the alert. It is here to keep mechanism A's window guard HONESTLY
#: SCOPED — the guard is about a `runtime-evidence` BASELINE, and applying it to every
#: consultation would refuse the one row that records a legitimate registry hit.
ENTRY_VALIDITY_WINDOW = "2026-03-01T00:00:00Z/2026-09-01T00:00:00Z"

#: The actor and host the alerted edge names — what a registry entry's `actor_scope` /
#: `host_scope` has to cover for the lookup to be a hit.
ACTOR = "uid-0"
HOST = "build-runner-07.prod"
PATTERN = "rewrite /etc/ssl/certs/ca-bundle.crt"

#: The lead that dispatches the registry lookup, and the one declared in `:L findings` and
#: never dispatched. Spelled once: three suites cite both, and `l-002`'s whole job is to be
#: the id a receipt may not be anchored to.
LEAD = "l-001"
UNDISPATCHED_LEAD = "l-002"

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
    resolved_by: str = LEAD,
    fulfills: str = "ac1",
    reasoning: str = "registry entry covers uid-0 on build-runner hosts, review_by 2026-09-01",
) -> str:
    """One `:R authz` row under `AUTHZ_HEADER`. An empty cell is DROPPED by the parser, so
    `basis=""` is how a row spells "no basis column value" — which reads as `retry`."""
    return (
        f"{resolved_by}|e-001|{fulfills}|{verdict}|{anchor_kind}|{grounding}|{anchor_id}|{basis}|"
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
    resolved_by: str = LEAD,
) -> str:
    """One `:R consultations` row under `CONSULT_HEADER`."""
    return (
        f'{resolved_by}|{anchor_kind}|{grounding}|{anchor_id}|"{result}"|{window}|"{reasoning}"'
    )


def lookup_hit_row(
    *,
    anchor_id: str = ENTRY_ID,
    resolved_by: str = LEAD,
    window: str = ENTRY_VALIDITY_WINDOW,
    result: str = (
        "hit: entry covers actor uid-0, host build-runner-*.prod, pattern "
        "rewrite /etc/ssl/certs/ca-bundle.crt"
    ),
    reasoning: str = "tacit-knowledge.lookup returned one unexpired scope-matching entry",
) -> str:
    """The lead's own record of what `tacit-knowledge.lookup` came back with — a
    `:R consultations` row under the SAME anchor kind the contract is declared under.

    The existing mechanism, not a new one. `AnchorConsultation` (`schema.py`) already carries
    `anchor_kind`, `anchor_id`, `result` and `anchor_query`, it lands on the dispatching lead's
    own `outcome.anchor_consultations`, and it structurally cannot discharge a contract — so
    recording the hit costs the document nothing and buys it nothing on its own. That is
    exactly the property the anchor-receipt check needs: the `:R authz` row still has to be
    written, and it is now checkable against something the same lead already recorded.

    A MISS records no `anchor_id` (there is no entry to name), which is why the check can read
    "this lead recorded a hit on THIS entry" off the id alone without minting a hit/miss
    vocabulary nothing else in the format has.
    """
    return consultation_row(
        anchor_kind="tacit-knowledge", grounding="org-authority", anchor_id=anchor_id,
        result=result, window=window, reasoning=reasoning, resolved_by=resolved_by,
    )


def lookup_miss_row(
    *,
    resolved_by: str = LEAD,
    result: str = "miss: no unexpired entry covers actor uid-0 on build-runner-07.prod",
    reasoning: str = "tacit-knowledge.lookup came back with no matching entry",
) -> str:
    """The same lead recording that the lookup came back EMPTY — no `anchor_id`, because a miss
    has no entry to name. The honest half of the pair, and the row a fabricated citation has to
    sit beside in `test_a_missed_lookup_cannot_be_cited_as_a_hit`."""
    return consultation_row(
        anchor_kind="tacit-knowledge", grounding="org-authority", anchor_id="",
        result=result, window=ENTRY_VALIDITY_WINDOW, reasoning=reasoning,
        resolved_by=resolved_by,
    )


#: The system directory the registry lives under, inside whatever tree is being read
#: (`defender/skills/tacit-knowledge/registry.yaml` in the shipped one, a `tmp_path` in a
#: scenario's). Spelled once because the unit suite writes fixtures with it and the e2e reads
#: the adapter's answer back out of one.
REGISTRY_SYSTEM = "tacit-knowledge"
REGISTRY_RELPATH = ("skills", REGISTRY_SYSTEM, "registry.yaml")


def registry_entry(**overrides) -> dict[str, str]:
    """One well-formed registry entry. Eight fields: the seven the design names plus the `id`
    the `:R authz` row cites as `anchor_id` (fork F1's provisional eighth — without it a
    citation names a `pattern` string, and every edit becomes a silent re-identification).

    Lives here rather than in the registry suite because the e2e drives the real adapter
    against a fixture tree and needs the same entry (`lint-dup`); the ids the two suites move
    are the ids this module already names."""
    base = {
        "id": ENTRY_ID,
        "pattern": PATTERN,
        "actor_scope": ACTOR,
        "host_scope": "build-runner-*.prod",
        "added_by": "sre-platform@example.invalid",
        "added_at": "2026-03-01",
        "review_by": "2026-08-01",
        "justification": "image build's own ca-trust step; no identity system holds UID 0",
    }
    base.update(overrides)
    return base


def write_registry(root: Path, *entries: dict) -> Path:
    """A registry file under a throwaway tree, written as YAML BY HAND.

    Hand-written rather than dumped, because the file is a HUMAN-EDITED artifact and the loader
    has to read what a human commits — a round trip through the same dumper the loader's parser
    feeds would be an oracle re-deriving itself (`lint-oracle`'s shape)."""
    path = root.joinpath(*REGISTRY_RELPATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["entries:"]
    for entry in entries:
        first = True
        for key, value in entry.items():
            lines.append(f"{'  - ' if first else '    '}{key}: {value!r}")
            first = False
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


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
{h2_authz}
:L findings [id|loop|name|target|tests|system|window]
l-001|1|registry-lookup|v-003|h-001,h-002|{system}|n/a
l-002|1|planned-never-dispatched|v-003|h-001|host-state|n/a
```
"""

#: The SECOND live authorization contract, declared under the surviving adversary hypothesis
#: so it stays on the frontier for as long as `h-002` does. Opt-in (`second_contract=True`):
#: it exists for `test_exhausted_drops_only_its_own_contract`, where one contract cannot show
#: whether a `basis=exhausted` row cleared ITS contract or the whole frontier.
_SECOND_CONTRACT = """
:H h-002.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac2|e-001|change-mgmt|"the CA bundle rewrite was carried out under an approved change"|escalate|escalate
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
    second_contract: bool = False,
    conclude: str = "",
) -> str:
    """The investigation, with `rows` spliced into the `:R` block.

    `settled=True` grades `h-001` to `++` and `h-002` to `--` — the shape a benign close
    needs. `settled=False` leaves both at a mild grade, which is what a run whose
    authorization question is still open honestly records.

    `system` is `l-001`'s `:L findings` system cell — the document's own record of WHICH
    system that lead queried, which is what `basis=exhausted` is checked against.

    `second_contract=True` declares `h-002.ac2` beside `h-001.ac1`, so a frontier assertion
    can tell "this row cleared its own contract" from "this row cleared the frontier".

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
        h2_authz=_SECOND_CONTRACT if second_contract else "",
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


def authz_block(*rows: str) -> str:
    return AUTHZ_HEADER + "\n" + "".join(f"{row}\n" for row in rows)


def consult_block(*rows: str) -> str:
    return CONSULT_HEADER + "\n" + "".join(f"{row}\n" for row in rows)


def authorized_rows(
    *,
    hit_id: str = ENTRY_ID,
    cited_id: str | None = None,
    hit_by: str = LEAD,
    resolved_by: str = LEAD,
    baseline: bool = False,
    **authz_kwargs,
) -> str:
    """The rows a REAL registry hit writes: the lead's recorded lookup outcome, then the
    `:R authz` row that cites it.

    Four knobs, one per way a document can claim a hit it does not have:
      * `cited_id` — what the `:R authz` row cites, defaulting to what the lead recorded. Set
        it to something else and the citation is a fabrication.
      * `hit_by` / `resolved_by` — which lead recorded the hit, and which lead the row hangs
        off. Split them and the row is citing another lead's finding as its own.
      * `baseline=True` adds mechanism A's `runtime-evidence` consultation beside the pair,
        which is the shape a real container-root close has (O3 context + O1 authorization).
    """
    consultations = [lookup_hit_row(anchor_id=hit_id, resolved_by=hit_by)]
    if baseline:
        consultations.append(consultation_row())
    return consult_block(*consultations) + authz_block(
        authz_row(
            anchor_id=hit_id if cited_id is None else cited_id,
            resolved_by=resolved_by,
            **authz_kwargs,
        )
    )
