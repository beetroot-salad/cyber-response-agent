"""#632 — shared machinery for the verb-authorization spec suite. NOT a test module.

THE CODE DOES NOT EXIST YET. Every import below names a surface the implementation must
build, so this suite is RED by construction against `d01001e6` — that is the point: the
tests are the contract the code is written against, and a spec that were green at HEAD
would be pinning the bug, not the correction.

The surface this suite pins
---------------------------
`defender/runtime/verb_grant.py` (new)
    `VerbGrant(role, entries)` — a frozen, HASHABLE per-role enumeration of
    `(system, verb, verb_class)` triples. `VERB_CLASSES` is the closed vocabulary
    (§7 R13: closed at two for now). `GrantError` is raised at AUTHORING time for a class
    token outside it and for one `(system, verb)` declared twice with conflicting classes.
    `DENY_ALL` is the empty deny-all default (§7 R7) — never `None`, never absent.

`defender/runtime/verbs.py` (modified)
    `VerbRegistry` — the NOMINALLY TYPED seam (§7 R15). Its constructor requires a
    `VerbGrant`, so an unscoped registry is unconstructable rather than merely un-passed,
    and an entry point rejects a registry-shaped stand-in that never went through it.
    `ModuleVerbRegistry(adapters_dir, grant)` — the grant is now REQUIRED, and the
    constructor runs the load check: every grant entry must resolve against the adapters'
    DECLARED verb names, read cold (§7 R10 — `declared_verb_names`, no adapter import).
    `registry.decide(system, verb) -> VerbDecision` is the one grant decision point;
    `registry.verbs(system)` still returns the UNNARROWED declared map, because narrowing
    it is exactly the shape that collapses a denial into the unknown-verb path (§7 R2).
    `verb_class_of(fn)` reads the class a verb declares via `@verb(verb_class=…)`.

    THE THREE OUTCOMES, and §7 R11 read LITERALLY, which every label in this suite follows:
      GRANTED    — the role's grant names this (system, verb).
      DENIED     — the grant reaches this system but withholds this verb. A policy refusal:
                   no evidence row, a durable denial record.
      UNDECLARED — the verb resolves to nothing, OR the grant reaches this system NOWHERE.
                   Unresolvable: today's queries row, agent-fixable, retry coaching, and no
                   denial record. A wholly ungranted system is therefore never denied — see
                   RS14, recorded because it hollows deny-by-default's reach over newly
                   scaffolded SYSTEMS (a new verb on a system the role already holds is
                   still denied, which is what keeps that obligation non-vacuous).
    `VerbContext(defender_dir, run_dir, env, capture=None)` — `capture` is the transport
    capture seam (phase F, finding 6): a `TransportCapture` sink each adapter records its
    resolved outbound request into, before sending.

`defender/runtime/agent_definition.py` (modified)
    `AgentDefinition.verb_grant` (§7 R7: the grant stays on the role definition) and
    `AgentPolicy.verb_allow`, compiled by `compile_policy` beside `bash_allow`.
    `compile_policy_for(defn, run_dir, *, tools=None)` — the EFFECTIVE ToolSet seam: the
    judge switches its verb capability on by a runtime `replace()` after `bind` has already
    compiled its policy (g16), so without this the compiled policy structurally cannot see
    the bit the agreement check is supposed to compare the grant against.

`defender/runtime/observe.py` (modified)
    `POLICY_DENIALS` — ONE fixed policy-denial stream per site, same writer class and same
    filename at the runtime and at the judge, each under its own run directory (§7 R1).
    `RequestLogger.log_policy_denial(...)` writes a BOUNDED, NORMALIZED projection (§7 R12)
    with a timestamp and a sequence, and does NOT swallow a failed write (§7 R2) — unlike
    `log_budget_refusal`, the precedent it deliberately does not inherit.

`defender/runtime/verb_roster.py` (new)
    The grant-derived model-facing roster (05-early-resolutions R-A2) and the build-time
    audit over every artifact the model reads (§7 R8/R9).

    THE AUDIT IS KEYED BY ROLE, not handed an unkeyed bag of grants (170-resolutions F3).
    `audit_read_surfaces(defender_dir, grants)` takes a MAPPING of role -> `VerbGrant` and
    decides, per file, which grant governs it. That is the fourth attribution rule, and it
    exists because the three below cannot express it: they attribute a NAME to a
    `(system, verb)` pair and never to a ROLE, while every role now ships its own generated
    roster. The judge's roster names two ticket verbs gather's grant withholds, so scoring
    the whole tree against one role's grant makes a correct second roster an offence.
      4. A GENERATED ROSTER is scored against ITS OWN ROLE's grant — the role is read off the
         roster's own committed path, which is role-keyed by construction. Every other
         audited surface is scored against `AUDIT_DEFAULT_ROLE`'s grant, because the
         non-roster surfaces have exactly one production consumer (the gather dispatch path).
    Excluding rosters from the audited surface was rejected: it breaks no assertion, which is
    precisely the problem — it is indistinguishable from what a dishonest implementer does to
    clear the red. Under rule 4 that exit is closed by construction, and the test asserts the
    closure directly by scoring the judge's roster against gather's grant and requiring a hit.

    THE ROSTER ADDRESSES A VERB BY ITS (system, verb) PAIR, never by its bare name.
    Authorization is a property of the pair — the suite asserts exactly that at the decision
    point, where `identity.list-roles` is GRANTED to gather while `cmdb.list-roles` is granted
    to nobody. A roster keyed on names cannot express that, and a screen keyed on names forbids
    the granted one: `list-roles` is simultaneously required and forbidden. So each granted verb
    is rendered as its fully qualified `{system}.{verb}` call id — the same id form the queries
    table already keys on — under its own system's section, and `roster_pairs` below is what
    every assertion in this suite reads.

    THE AUDIT DECIDES ON PAIRS TOO, BUT IT MUST READ EVERY FORM THE COMMITTED PROSE USES,
    which is not one syntax (§7 R8, amended). What the grant decides and what the audit can
    SEE are different questions, and collapsing them is how the demand stopped catching its
    own counter-examples: two of the four sites this demand exists to correct name a verb as a
    BARE NAME, one of them the file that tells the model to call a verb the grant withholds.
    An audit that reads only `query(system=…, verb=…)` reports zero offenders over a tree that
    still carries the instruction. Three attribution rules, in order:

      1. QUALIFIED — `query(system='S', verb='v')` or the `S.v` call id. Attributes to (S, v).
      2. BARE, IN ITS OWN SYSTEM'S FILE — a bare `v` under `skills/S/` where S itself declares
         `v`. Attributes to (S, v); this is what keeps a system's own prose about its own
         granted verb clean while the same NAME stays an offender on its sibling.
      3. BARE, ANYWHERE ELSE — a bare declared verb name in a file that attributes to no
         system, or in a system's file for a verb that system does not declare. It attributes
         to nothing, so it is judged against EVERY system declaring that name and is an
         offender if any of those pairs is withheld. The accepted cost is false positives:
         a foreign bare mention of a name some system withholds is flagged even when the
         author meant the granted one, and the correction is to qualify the name. That cost
         is deliberate — rule 2 is the only attribution that can be trusted, and the
         alternative was accepting that a file instructing the model to call a withheld verb
         is permanently out of the audit's reach.

`defender/scripts/adapters/confinement.py` (new)
    D4's two rule forms: the read-endpoint allowlist for the HTTP verbs, matched on the
    RESOLVED request target with the path normalized and the query string dropped
    (§7 R6); and the argv-head + container-target pair rule for host-state, which has no
    URL for the row-shaped rule to apply to (§7 R4). Plus `TransportCapture` — the
    observation seam the endpoint rule is checked through, so the allowlist meets the URLs
    the adapters really build rather than its own declared entries.

    THE ALLOWLIST IS A CONSTRUCTED VALUE, NOT A MODULE LITERAL: `ReadEndpointAllowlist` is a
    validating Mapping constructor that raises `AllowlistError` at AUTHORING time for an entry
    naming no HTTP method, and `READ_ENDPOINT_ALLOWLIST` is what it returned. This is the
    grant's authoring-integrity guarantee applied to the third hand-authored table the model's
    permissions rest on — the per-role grant refuses a bad class token at construction and the
    generated roster must regenerate to its committed bytes, while a method-less allowlist entry
    was caught by a single assertion over a single committed literal and by nothing in
    production. It has to be a Mapping because the endpoint rule's own test reads the table by
    key set, by system and by subscript.

    THE ALLOWLIST KEYS ON `(URL PATTERN, HTTP METHOD)` PAIRS, and the capture seam records
    the method beside the path (170-resolutions F1). An endpoint-only key is UNSATISFIABLE,
    not merely weak: the ticket store's "list the tickets" read and its "create a ticket"
    write are the same resolved path, so one rule over `(system, path)` is asked to admit and
    refuse the identical call. The measurement behind the repair: over the 27 distinct
    (system, path, method) triples every shipped adapter verb and every ticket-writer entry
    point really produces, path alone collides exactly once — on `/tickets` — and path+method
    collides zero times. c17 is NOT overturned by this: it refuted a GLOBAL "an `r` verb may
    not POST", which a per-entry method leaves untouched — elastic's two POST-with-body reads
    are listed pairs and still pass. Every outbound request in the tree already funnels
    through one transport function that takes the method as a required keyword, and it is the
    same function this seam wraps, so the axis costs one recorded field.

    Dropping `/tickets` from the write set was rejected, and the reason is recorded because a
    later reader will re-propose it: it greens the test while unbacking the test's own stated
    purpose — catching a future read-classed verb that wraps the write client, which would
    request exactly that URL under exactly the `ticket` system name.

Fakes inject faults; they never classify. A fake verb records what it was handed and then
returns its payload or raises its fault — every exit code, error class, refusal string,
audit record and breaker outcome asserted downstream is production code's work.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import read_jsonl_rows  # noqa: E402
from defender.runtime import observe  # noqa: E402
from defender.runtime.verb_grant import (  # noqa: E402
    DENY_ALL,
    VERB_CLASSES,
    GrantError,
    VerbGrant,
)
from defender.runtime.verbs import (  # noqa: E402
    DENIED,
    GRANTED,
    UNDECLARED,
    ModuleVerbRegistry,
    VerbContext,
    VerbDecision,
    VerbRegistry,
    declared_verb_names,
    verb_class_of,
)
from defender.tests._closed_ticket_672 import _ticket_registry  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    DEFENDER,
    GOLDEN_AB3,
    ReplayFn,
    Turn,
    VerbRecorder,
    drive,
    materialize,
)

pytestmark = pytest.mark.e2e

SALT = "aabbccddeeff0011"
LEAD = "l-001"
ADAPTERS_DIR = DEFENDER / "scripts" / "adapters"

PAYLOAD = [
    {"@timestamp": "2026-01-01T00:00:00Z", "user.name": "dev.dana", "event.action": "ssh_login"},
]

# The two shipped grants, as the design's census settled them (c18/g4). Held here as
# literals so `test_the_shipped_grants_name_exactly_the_censused_verbs` compares the
# DEFINITION's grant against an independently written list rather than against itself.
GATHER_PAIRS: tuple[tuple[str, str], ...] = (
    ("change-mgmt", "active-changes"), ("change-mgmt", "get-change"),
    ("change-mgmt", "list-changes"),
    ("cmdb", "get-host"), ("cmdb", "list-hosts"),
    ("elastic", "alerts"), ("elastic", "esql"), ("elastic", "query"),
    ("host-state", "authorized-keys"), ("host-state", "container-inspect"),
    ("host-state", "fim-checksum"), ("host-state", "package-list"),
    ("host-state", "passwd"), ("host-state", "proc-tree"),
    ("identity", "can-access"), ("identity", "get-user"), ("identity", "list-roles"),
    ("identity", "list-users"),
    ("threat-intel", "list-indicators"), ("threat-intel", "lookup"),
    ("ticket", "list-tickets"),
)
BENIGN_JUDGE_PAIRS: tuple[tuple[str, str], ...] = (
    ("ticket", "get-ticket"), ("ticket", "key-pattern"), ("ticket", "list-tickets"),
)
# Granted to nobody: in the registry, exercised by no template and no run (c18). `cmdb`'s
# entry is the collision — `identity.list-roles` above IS granted to gather, so this pair can
# only be screened for as a pair.
UNGRANTED_PAIRS: tuple[tuple[str, str], ...] = (
    ("cmdb", "list-roles"), ("identity", "list-authorized-hosts"),
)
# The four verbs today's committed skill prose advertises with copy-paste call examples,
# one of them as an instruction to use it (g10). The correspondence demand fails on these
# until the change lands.
WITHHELD_FROM_GATHER: tuple[tuple[str, str], ...] = (
    ("ticket", "get-ticket"), ("ticket", "key-pattern"), *UNGRANTED_PAIRS,
)
HEALTH_CHECK = "health-check"
JUDGE_ROLE = "judge"
GATHER_ROLE = "gather"

# The store's real list envelope. `list_tickets` answers `{"total", "tickets"}` and the
# gather-side screen enforces that shape as a CONTRACT (`ticket_screen.screen_list` files a
# bare array as malformed), so a fake handing back a bare list is not a lighter fixture — it
# is a different observable, and one no correct implementation can score as a clean read.
# Written here once because two demands share it: the granted-call positive control and the
# self-case exclusion.
def ticket_envelope(*keys: str) -> dict:
    return {"tickets": [{"key": k, "status": "closed"} for k in keys], "total": len(keys)}


# The evidence surface a denial must conserve: the payload tree and the queries table, both
# under the run dir. Scoped deliberately — `llm_requests.jsonl` and the tool trace move on
# every model call, so folding them in would make conservation unassertable, while these two
# are exactly what the run allocated and exactly what an implementation that "leaves nothing
# behind" by DELETING evidence would have to disturb.
EVIDENCE_SURFACE = ("gather_raw", "executed_queries.jsonl")


def evidence_snapshot(run_dir: Path) -> dict[str, bytes]:
    """Every file on the run's evidence surface, relative path -> exact bytes.

    Bytes, not a listing: the exploit this exists to catch deletes a file and re-creates a
    shorter one, which a name-set comparison cannot see."""
    out: dict[str, bytes] = {}
    for name in EVIDENCE_SURFACE:
        p = run_dir / name
        if p.is_file():
            out[name] = p.read_bytes()
        elif p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_file():
                    out[str(f.relative_to(run_dir))] = f.read_bytes()
    return out


class WatchingReplay(ReplayFn):
    """A replay model that snapshots the run's evidence surface at every model request.

    This is how conservation is observed from INSIDE one real run rather than by comparing
    two runs: the gather leg is called once to emit its query and again once the tool result
    comes back, so consecutive snapshots straddle exactly the call under test. Comparing two
    separate runs could not work — the artifacts carry timestamps and a run id."""

    def __init__(self, turns: list[Turn], run_dir: Path):
        super().__init__(turns)
        self.run_dir = run_dir
        self.snapshots: list[dict[str, bytes]] = []

    def __call__(self, messages, info):  # noqa: ANN001 — the framework's callable protocol
        self.snapshots.append(evidence_snapshot(self.run_dir))
        return super().__call__(messages, info)

# One verb name, withheld on one system and granted on another. It is the reason every roster
# assertion in this suite reads pairs: `list-roles` must appear (identity grants it to gather)
# and must not appear (cmdb's is granted to nobody), and no rendering satisfies both halves of
# a name-keyed screen.
COLLIDING_VERB = "list-roles"
GRANTED_COLLIDING_PAIR = ("identity", COLLIDING_VERB)
WITHHELD_COLLIDING_PAIR = ("cmdb", COLLIDING_VERB)

_CALL_ID = re.compile(r"\b([a-z][a-z0-9-]*)\.([a-z][a-z0-9-]*)\b")
_VERB_KWARG = re.compile(r"""verb\s*=\s*["']([a-z][a-z0-9-]*)["']""")

SYSTEMS: tuple[str, ...] = tuple(sorted(
    {s for s, _ in (*GATHER_PAIRS, *BENIGN_JUDGE_PAIRS, *UNGRANTED_PAIRS)}
))


def declared_verbs_everywhere() -> frozenset[str]:
    """Every verb NAME the shipped adapters declare, read cold off the real tree."""
    return frozenset(
        v for system in SYSTEMS for v in declared_verb_names(ADAPTERS_DIR, system)
    )


def bare_only_surfaces(files, verb_names: frozenset[str]) -> tuple[Path, ...]:
    """The committed files that name a declared verb ONLY as a bare name — no `S.v` call id
    and no `verb='v'` keyword anywhere in them.

    This is the CONTROL on the audit's instrument, and it is computed off the real tree on
    every run rather than pinned as a list, so it cannot go stale the way a hand-recalled
    enumeration would. A pair-only audit is blind to exactly these files, and one of them is
    the file that tells the model to use a verb the grant withholds. Any assertion that the
    real tree is clean is worth nothing unless something also proves the audit can SEE these
    files at all: a green over a corpus the instrument cannot read is the escape this demand
    was minted to prevent."""
    out = []
    for p in files:
        try:
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        qualified = {m.group(2) for m in _CALL_ID.finditer(text)} | set(_VERB_KWARG.findall(text))
        if qualified & verb_names:
            continue  # a pair audit already reaches this file
        if any(re.search(rf"(?<![\w-]){re.escape(v)}(?![\w-])", text) for v in verb_names):
            out.append(p)
    return tuple(sorted(out))


def roster_pairs(text: str) -> set[tuple[str, str]]:
    """Every `(system, verb)` pair a roster text advertises, read off the qualified
    `{system}.{verb}` call ids it renders.

    This is the roster's rendered shape as a contract, not a parsing convenience. A verb name
    on its own does not say what it authorizes, so a roster that renders bare names cannot be
    screened at all — the withheld set and the granted set share a name. Every assertion that
    a verb IS advertised goes through this function too, so a roster which renders nothing
    parseable fails its positive half rather than passing its negative one vacuously."""
    return {(m.group(1), m.group(2)) for m in _CALL_ID.finditer(text)}


def grant_of(role: str, pairs, *, verb_class: str = "r") -> VerbGrant:
    """A `VerbGrant` over `pairs`, every entry expecting `verb_class`."""
    return VerbGrant(role=role, entries=tuple((s, v, verb_class) for s, v in pairs))


def shipped_grants() -> dict[str, VerbGrant]:
    """The role -> grant mapping the real-tree audit is handed: every role that ships a
    generated roster, keyed by the role its roster is committed under.

    Built from the shipped definitions rather than from literals, because what this mapping
    must cover is "every role with a roster on disk" — a literal list would go stale the
    first time a third role gets one, and the audit would then score that role's roster
    against gather's grant and report an offence that is not one."""
    from defender.learning.pipeline.judge.engine_pydantic import JUDGE_DEF
    from defender.runtime.driver import GATHER_DEF

    return {GATHER_ROLE: GATHER_DEF.verb_grant, JUDGE_ROLE: JUDGE_DEF.verb_grant}


def scoped_ticket_registry(rec: VerbRecorder, pairs, **kw) -> ScopedFakeVerbs:
    """The #672 ticket verb table, rescoped by a real `VerbGrant` — the same declared param
    surfaces the executed probe found, so the judge's real tools still bind their real params.
    `**kw` reaches the #672 fake's own fault-spec (e.g. `declare_key_pattern=False`, the
    misconfigured-store shape).

    This is the seam through which the judge's grant reaches its stage build: the stage takes
    its verb registry as an argument, and a registry carries the grant it was scoped by."""
    fake = _ticket_registry(rec, **kw)
    return ScopedFakeVerbs({"ticket": dict(fake.verbs("ticket"))}, grant_of(JUDGE_ROLE, pairs))


class ScopedFakeVerbs(VerbRegistry):
    """The injected registry: a REAL `VerbRegistry` subclass over a plain
    `{system: {verb: fn}}` table, scoped by a real `VerbGrant`.

    It is a subclass and not a duck-typed stand-in on purpose — §7 R15 makes the seam
    nominally typed, so a table that merely answers the registry's questions is exactly
    what the entry point must refuse. It makes no admission decision of its own: an
    undeclared system raises `KeyError`, and `decide()` — the grant decision — is the base
    class's, which is production code."""

    def __init__(self, table: Mapping[str, Mapping[str, Callable[..., Any]]], grant: VerbGrant):
        super().__init__(grant)
        self._table = {s: dict(v) for s, v in table.items()}

    def systems(self) -> tuple[str, ...]:
        return tuple(sorted(self._table))

    def verbs(self, system: str) -> Mapping[str, Callable[..., Any]]:
        return self._table[system]


class RegistryShaped:
    """A registry-SHAPED object that never went through `VerbRegistry.__init__` — the
    duck-typed stand-in §7 R15 requires the seam to reject. It answers every question the
    registry answers, which is precisely why `unconstructable` is hollow without a type."""

    def __init__(self, table: Mapping[str, Mapping[str, Callable[..., Any]]]):
        self._table = {s: dict(v) for s, v in table.items()}

    def systems(self) -> tuple[str, ...]:
        return tuple(sorted(self._table))

    def verbs(self, system: str) -> Mapping[str, Callable[..., Any]]:
        return self._table[system]

    def decide(self, system: str, verb: str) -> Any:  # answers the question, holds no grant
        return VerbDecision(outcome=GRANTED, fn=self._table[system][verb], refusal=None)


def recording_table(rec: VerbRecorder, systems_verbs: Mapping[str, tuple[str, ...]],
                    *, raises: BaseException | None = None) -> dict:
    """A verb table whose every entry records what it was handed and then returns `PAYLOAD`
    (or raises `raises`). It classifies nothing."""

    def make(verb: str):
        def fn(ctx: VerbContext, *, native_query: str = "FROM logs", **rest: Any):
            rec.record(verb, ctx, {"native_query": native_query, **rest})
            if raises is not None:
                raise raises
            return PAYLOAD
        return fn

    return {s: {v: make(v) for v in verbs} for s, verbs in systems_verbs.items()}


class _Run:
    """One driven replay: the run dir, the two replay models, and every surface a denial
    is asserted against — the evidence table, the payload tree, the breaker, and the
    policy-denial stream."""

    def __init__(self, run_dir: Path, main: ReplayFn, gather: ReplayFn):
        self.run_dir, self.main, self.gather = run_dir, main, gather

    @property
    def rows(self) -> list[dict]:
        p = self.run_dir / "executed_queries.jsonl"
        return read_jsonl_rows(p) if p.is_file() else []

    @property
    def denials(self) -> list[dict]:
        p = self.run_dir / observe.POLICY_DENIALS
        return read_jsonl_rows(p) if p.is_file() else []

    @property
    def payload_files(self) -> list[Path]:
        """The payloads a QUERY CALL allocates: `gather_raw/{lead_id}/{seq}.json`, inside the
        lead-scoped subdirectory and nowhere else.

        Scoped, not globbed. Dispatch writes one flat `gather_raw/{lead_id}.lead.json`
        sidecar at the ROOT of this tree before any query runs, consumes no sequence number
        and does not create the lead-scoped subdirectory at all — so a recursive glob of the
        whole tree conflates run state with query state and demands an empty tree no correct
        implementation can produce. The two never share a directory level; that measured
        disjointness is what makes this property assertable."""
        root = self.run_dir / "gather_raw" / LEAD
        return sorted(p for p in root.rglob("*.json") if p.is_file()) if root.is_dir() else []

    @property
    def snapshots(self) -> list[dict[str, bytes]]:
        """The evidence-surface snapshots taken at each gather model request, present only
        when the drive asked for them."""
        return getattr(self.gather, "snapshots", [])

    @property
    def gather_saw(self) -> str:
        return self.gather.seen[-1] if self.gather.seen else ""

    @property
    def gather_delta(self) -> str:
        """The model-visible text the drive ADDED past the first request — the channel a tool
        result or a refusal comes back on.

        `seen` entries are cumulative flattened histories, so this delta is exactly what the
        tool calls contributed. Assertions that something is ABSENT need it: the ambient
        gather prompt names the tree, the run and the systems, so `not in seen[-1]` can fail
        for reasons that have nothing to do with the tool result under test."""
        if not self.gather.seen:
            return ""
        head = self.gather.seen[0]
        assert self.gather.seen[-1].startswith(head), \
            "the flattened history is not append-only — the delta is not the drive's own result"
        return self.gather.seen[-1][len(head):]

    @property
    def breaker(self) -> dict:
        p = self.run_dir / "circuit_breaker.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}


def q(system: str, verb: str, params: dict | None = None, query_id: str | None = None) -> Turn:
    """One scripted `query` tool call — the model-facing shape of the tool under test."""
    args: dict = {"system": system, "verb": verb, "params": params or {}}
    if query_id is not None:
        args["query_id"] = query_id
    return Turn(tool_calls=[("query", args)])


DONE = Turn(text="Summary: measured the lead.")


def run_gather(tmp_path: Path, *, verbs, turns: list[Turn], system: str = "elastic",
               run_id: str = "vauth632", watch: bool = False) -> _Run:
    """Drive a REAL run: main dispatches one gather lead, the nested gather agent replays
    `turns` against the INJECTED scoped registry. Everything between the two fakes —
    dispatch, the query tool, the grant decision, the capture capability, the breaker, the
    two tables and the policy-denial stream — is production code.

    `watch` snapshots the evidence surface at every gather model request, which is what the
    conservation half of the denial demand reads."""
    run_dir = materialize(tmp_path, GOLDEN_AB3)
    main = ReplayFn([
        Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": system, "goal": "measure this lead",
            "what_to_summarize": ["auth events"],
        })]),
        Turn(text="Investigation complete."),
    ])
    gather = WatchingReplay(turns, run_dir) if watch else ReplayFn(turns)
    drive(run_dir, run_id=run_id, salt=SALT, main=main, gather=gather, verbs=verbs)
    return _Run(run_dir, main, gather)


__all__ = [
    "ADAPTERS_DIR",
    "BENIGN_JUDGE_PAIRS",
    "COLLIDING_VERB",
    "EVIDENCE_SURFACE",
    "GATHER_ROLE",
    "WatchingReplay",
    "evidence_snapshot",
    "shipped_grants",
    "ticket_envelope",
    "DENIED",
    "DENY_ALL",
    "DONE",
    "GATHER_PAIRS",
    "GRANTED",
    "GRANTED_COLLIDING_PAIR",
    "GrantError",
    "HEALTH_CHECK",
    "JUDGE_ROLE",
    "LEAD",
    "PAYLOAD",
    "SALT",
    "SYSTEMS",
    "UNDECLARED",
    "UNGRANTED_PAIRS",
    "VERB_CLASSES",
    "WITHHELD_COLLIDING_PAIR",
    "WITHHELD_FROM_GATHER",
    "ModuleVerbRegistry",
    "RegistryShaped",
    "ScopedFakeVerbs",
    "VerbContext",
    "VerbDecision",
    "VerbGrant",
    "VerbRegistry",
    "bare_only_surfaces",
    "declared_verb_names",
    "declared_verbs_everywhere",
    "grant_of",
    "q",
    "recording_table",
    "roster_pairs",
    "run_gather",
    "scoped_ticket_registry",
    "verb_class_of",
]
