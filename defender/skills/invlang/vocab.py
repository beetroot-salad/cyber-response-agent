
from __future__ import annotations

from defender._vocab import DISPOSITION_VALUES

# The one vocabulary in this module that invlang does NOT define — every other slot below is
# invlang's own domain. `disposition` is the run's headline, carried by `report.md` too and
# validated there by a different schema, so it is imported from the project-general vocabulary
# rather than restated: two schemas spelling out the same keywords eventually disagree.
DISPOSITION: tuple[str, ...] = DISPOSITION_VALUES

#: The four buckets, and THE closed set a `:T resolutions` `after` cell is judged against.
#: Closed rather than "anything that is not a null spelling", because the cell is an
#: unvalidated `\S+` and the open reading makes a misspelling cheaper than the truth — it would
#: discharge every prediction the row cites while skipping the gates that fire on `++` and on
#: `STRONG_WEIGHTS`. `validate._resolution_move` is the one reader.
#:
#: The head spells "no weight" two ways — `∅` (the format grammar's) and `null` (what the
#: SKILL's worked examples, both shipped e2e goldens and every test corpus write). Neither is a
#: bucket, so both fall out of the positive test above without a second set to keep in step.
WEIGHT_BUCKETS: tuple[str, ...] = ("++", "+", "-", "--")
WEIGHT_ORDER: dict[str | None, int] = {"--": 0, "-": 1, None: 2, "+": 3, "++": 4}
STRONG_WEIGHTS: frozenset[str] = frozenset({"++", "--"})
REFUTED_WEIGHT: str = "--"
#: The other pole, named for the same reason `REFUTED_WEIGHT` is: `_walkers.live_hypothesis_ids`
#: asks "is this one refuted" and `validate._check_prediction_completeness` asks "is this one
#: confirmed", and a literal at either site drifts from the bucket list above without a test
#: noticing.
CONFIRMED_WEIGHT: str = "++"
assert STRONG_WEIGHTS.issubset(WEIGHT_BUCKETS), (
    "STRONG_WEIGHTS must be a subset of WEIGHT_BUCKETS"
)
assert REFUTED_WEIGHT in STRONG_WEIGHTS, "REFUTED_WEIGHT must be a strong weight"
assert CONFIRMED_WEIGHT in STRONG_WEIGHTS, "CONFIRMED_WEIGHT must be a strong weight"
#: How a `:H` row's `weight` cell spells "no weight yet". `_hypothesis_record` maps it to
#: `None`; the token itself needs an owner because the messages that quote it back to the
#: author must spell what the author wrote.
NULL_WEIGHT: str = "null"
#: BOTH null spellings a `:T resolutions` arrow accepts. `docs/dense-investigation-format.md`
#: gives the cells as `{∅, ++, +, -, --}` and the corpus writes `null` in the same slot, so a
#: check that knows only one of the two refuses documents the format documents.
NULL_WEIGHT_CELLS: tuple[str, ...] = (NULL_WEIGHT, "∅")
#: Every token a weight cell may hold, for the closed-vocabulary check the two write sites
#: share. Without it the `after` cell is an unvalidated `\S+`, and a misspelled grade is the
#: cheapest row in the language: it skips the strong-move provenance gate and the `++`
#: coverage gate alike, where the honest spelling is refused for what it leaves open.
WEIGHT_CELL_VALUES: tuple[str, ...] = (*WEIGHT_BUCKETS, *NULL_WEIGHT_CELLS)


#: What a `:H <h>.authz` row's `edge_ref` says when the contract stands against the
#: hypothesis's PROPOSED edge rather than an observed one. The parser writes it for a row that
#: names no edge, and the review's ablation writes it over a row whose edge it withheld — so a
#: contract never cites an id that is absent from the world the reader is looking at. One home
#: for the two, because the second is only correct while it is spelled exactly like the first.
UNOBSERVED_EDGE_REF: str = "proposed"


TYPES: tuple[str, ...] = (
    "compute", "process", "thread", "memory-region", "module",
    "session", "identity", "storage", "database", "network-device",
    "file", "socket", "configuration", "application", "app-object",
    "credential",
)

RELATIONS: tuple[str, ...] = (
    "spawned", "executed", "loaded_by", "opened", "connected_to",
    "read", "wrote", "created", "deleted", "modified", "listed",
    "runs_on", "contained_in",
    "authenticated_as", "authenticated_via", "initiated_by",
    "triggered_by", "escalated_privilege", "assumed_role",
    "granted_consent", "issued",
    "member_of", "identified_as", "component_of",
    "attempted_auth", "governs",
)

ANCHOR_KINDS: tuple[str, ...] = (
    "iam-policy", "gpo", "cap-rule", "change-mgmt",
    "data-classification-policy", "k8s-policy", "federation-policy",
    "endpoint-policy", "approved-source-list", "runtime-evidence",
    "tacit-knowledge",
    "other",
)

#: `:R authz`' `basis` cell on an `indeterminate` verdict (#983 mechanism C) — WHY the question
#: is unsettled, which is the one thing that separates a contract worth another retrieval loop
#: from one no registry in this deployment can ever answer.
#:
#: `retry` is the DEFAULT and what an absent cell reads as: another registry or lead for this
#: contract has not been tried yet, or none exists yet but one could be added. `exhausted` says
#: every anchor kind applicable to this contract's predicate was actually queried this run and
#: none answered — a claim about DISPATCH, so it is checked against the run's own transcript
#: (`validate/_gating._check_authz_basis`) the way a `ceiling_test` receipt's `ref` is.
#:
#: The pair moves the retrieval FRONTIER and nothing else: `verdict: indeterminate` and its
#: forced `on_indet` escalation are untouched by either value.
AUTHZ_INDET_BASIS: tuple[str, ...] = ("retry", "exhausted")

#: `:R consultations`' `grounding` cell. `docs/investigation-language.md`'s v2.10 delta note
#: splits the axis in two — `authorization_resolutions[].grounding_kind ∈ {org-authority,
#: past-case}` against `anchor_consultations[].grounding_kind ∈ {org-authority,
#: telemetry-baseline}` — and this is the consultation half, closed here so the split is
#: enforced rather than documented.
#:
#: `past-case` is absent DELIBERATELY, not by oversight: a baseline consultation grounded on a
#: past case is precedent-by-similarity, the non-obligation #983's own discussion examined and
#: rejected. `telemetry-baseline` is the mirror omission on the authorization side — a
#: statistical pattern is context, never a verdict (`_check_authz_row_grounding`).
CONSULTATION_GROUNDING: tuple[str, ...] = ("org-authority", "telemetry-baseline")

#: How a `tacit-knowledge` `:R consultations` row records WHAT THE LOOKUP CAME BACK WITH, as the
#: first token of its `result` cell (`hit: ...` / `miss: ...`).
#:
#: A RULE rather than the convention it started as. The anchor receipt reads "this lead came
#: back holding this entry" off the presence of an `anchor_id`, and the convention that a miss
#: names none is not something the presence of a cell can enforce — a `result` saying `miss` and
#: an `anchor_id` beside it is a document contradicting itself, and it was accepted. Closing it
#: needs the outcome to be a value the validator can read, and the cheapest such value is the
#: one the format already writes: `lookup` returns `matched: entry | None`, so the row's own
#: first token is a two-member vocabulary and not free text.
TACIT_LOOKUP_OUTCOMES: tuple[str, ...] = ("hit", "miss")

#: Anchor kind → the ONE gather system that can answer it. PARTIAL on purpose (#983 fork F8).
#:
#: Minted so `basis=exhausted` can be checked against WHICH system a lead actually went to —
#: the lead's own `:L findings` `system` cell, which projects to
#: `FindingRecord.query_details.system`. Without the join, "this lead came back with something"
#: is satisfied by a lead that never went near the registry the claim is about (an ORIENT
#: bookkeeping `:R attr_updates` row is enough).
#:
#: Three kinds have one obvious system each and are mapped. The rest — `gpo`, `cap-rule`,
#: `other` and the others — do not, and inventing a system per member would mint a second closed
#: vocabulary to drift against the adapter set. An unmapped kind falls back to the looser
#: retrieval-came-back check; `validate/_gating._check_authz_basis` states what that costs.
ANCHOR_KIND_SYSTEMS: dict[str, str] = {
    "iam-policy": "identity",
    "change-mgmt": "change-mgmt",
    "tacit-knowledge": "tacit-knowledge",
}

assert set(ANCHOR_KIND_SYSTEMS) < set(ANCHOR_KINDS), (
    "ANCHOR_KIND_SYSTEMS must be keyed on real anchor kinds, and must stay PARTIAL — a "
    "mapping covering every kind is a system-per-member vocabulary, which is what the "
    "fallback exists to avoid"
)

AUTH_KINDS: tuple[str, ...] = (
    "siem-event", "runtime-audit", "authoritative-source",
    "client-asserted", "inferred-structural",
)

STRONG_AUTH_KINDS: frozenset[str] = frozenset(
    {"siem-event", "runtime-audit", "authoritative-source"}
)
assert STRONG_AUTH_KINDS.issubset(AUTH_KINDS), (
    "STRONG_AUTH_KINDS must be a subset of AUTH_KINDS"
)

#: The impact axis — orthogonal to authorization and integrity, and closed at five columns.
#:
#: `IMPACT_DIMENSION` is what an `:L l-NNN.impact_preds` row predicts about; `IMPACT_VERDICT`
#: is what a `:R impact` row grades it to. `CONCLUDE_IMPACT_VERDICT` is the roll-up over those
#: rows and adds exactly one value — `none`, "the investigation declared no impact predicates",
#: which no single row can say. Derived rather than restated so the two cannot drift by a
#: value; the extra member is the whole difference.
#:
#: All five are in `SLOTS`, so `defender-invlang enum impact.dimension` answers and
#: `skills/invlang/SKILL.md` can point at the enum instead of restating the values — the one
#: rule the SKILL's §Closed vocabularies states about itself ("not preloaded — look them up").
#: A vocabulary spelled out in an injected prompt is a second copy that goes stale silently.
#:
#: REGISTERED IS NOT ARMED, and the two are different steps on purpose. Rules #29 and #30
#: refuse on the three `impact.*` ones — new columns on a block nothing in the tree writes
#: yet, taught in the same change that arms them. The two `conclude.impact_*` ones are
#: TAUGHT ONLY: they are existing `:T conclude` scalars the SKILL has never given a
#: vocabulary, both shipped e2e goldens already hold an `impact_verdict` outside it (and each
#: is replayed through the write gate from its own `tool_trace.jsonl`), and refusing on a
#: vocabulary the runtime prompt never stated denies a run for a rule the model was never
#: given. Registering them is the teaching step that has to land first; see
#: `validate._check_impact_closure` and `docs/decisions/defender-invlang-enforcement-ramp.md`.
IMPACT_DIMENSION: tuple[str, ...] = (
    "confidentiality", "integrity", "availability", "scope",
)

IMPACT_VERDICT: tuple[str, ...] = ("within", "exceeds", "indeterminate")

CONCLUDE_IMPACT_VERDICT: tuple[str, ...] = ("none", *IMPACT_VERDICT)

#: Impact grounding excludes `past-case` and says so by omission: impact is per-instance
#: reasoning about THIS event's consequence, and a past case establishes what a CATEGORY of
#: event was allowed to do. `_check_impact_resolution_refs` names the exclusion in its refusal,
#: because "not in the enum" reads as a typo where the omission is a judgment.
IMPACT_GROUNDING: tuple[str, ...] = (
    "telemetry-baseline", "business-owner-attestation", "dlp-policy",
)

#: `conclude.impact_severity`. `null` is a MEMBER, not an absence: it is what the cell carries
#: when the verdict does not warrant a severity, and the format writes the word.
IMPACT_SEVERITY: tuple[str, ...] = ("null", "low", "moderate", "high")


#: `monitoring-agent` rather than `monitoring`, because the enum is now READ: until #986 armed
#: `validate._check_vocab_class_cells` nothing tested a `class` cell against these values, and
#: the SKILL had drifted to its own spelling — `skills/invlang/SKILL.md` §Open questions teaches
#: `class=monitoring-agent/??/known-corp` and its `:R attr_updates` worked example refines to
#: `monitoring-agent/internal/known-corp`. A model writes what the prompt showed it, so the
#: prompt's spelling is the one the catalog has to hold; carrying BOTH would be the two-spellings
#: -for-one-role the closed vocabulary exists to prevent. The corpus was moved with it.
COMPUTE_ROLE: tuple[str, ...] = (
    "monitoring-agent", "web-server", "app-server", "database-server",
    "mail-server", "dns-server", "dns-resolver", "domain-controller",
    "directory-server", "file-server", "bastion", "egress-host",
    "workstation", "byod", "mobile-device", "build-runner",
    "dev-tools", "kiosk", "iot", "container-host", "function-runtime",
    "ip-only", "unknown",
)

COMPUTE_ZONE: tuple[str, ...] = (
    "internal", "dmz", "partner", "regulated", "internet",
    "cloud-managed", "unknown",
)

PROVENANCE: tuple[str, ...] = (
    "known-corp", "known-partner", "novel", "anonymous",
)

COMPUTE_KIND: tuple[str, ...] = (
    "physical", "vm", "container", "function", "pod", "mobile",
)

IDENTITY_KIND: tuple[str, ...] = (
    "user", "group", "role", "service-account",
    "application-principal", "federated-user", "unknown",
)

APPLICATION_VENDOR: tuple[str, ...] = (
    "salesforce", "slack", "github", "gitlab", "bitbucket",
    "m365", "gsuite", "jira", "confluence", "servicenow", "workday",
    "okta", "entra", "auth0", "ping",
    "aws-account", "azure-tenant", "gcp-project",
    "datadog", "splunk", "snowflake", "databricks",
    "other",
)

APPLICATION_TRUST: tuple[str, ...] = (
    "corp-tenant", "partner-tenant", "external-tenant", "unknown",
)

SESSION_CLASS: tuple[str, ...] = (
    "interactive", "api", "federated", "service", "scheduled", "unknown",
)

STORAGE_KIND: tuple[str, ...] = (
    "object-store", "block", "file", "secrets", "nfs", "archive",
)

DATABASE_KIND: tuple[str, ...] = (
    "relational", "nosql", "graph", "columnar", "cache", "search-index",
)

NETWORK_DEVICE_KIND: tuple[str, ...] = (
    "firewall", "router", "switch", "load-balancer", "waf", "proxy",
    "vpn-gateway",
)

SOCKET_PROTOCOL: tuple[str, ...] = (
    "tcp", "udp", "tls", "dns", "http", "https", "smtp", "ldap",
    "smb", "rdp", "ssh", "unix",
)

CONFIGURATION_KIND: tuple[str, ...] = (
    "registry-key", "gpo", "iam-policy", "cap-rule", "sysctl",
    "systemd-unit", "cron-entry", "k8s-config", "app-config",
    "env-var", "firewall-rule",
)

APP_OBJECT_KIND: tuple[str, ...] = (
    "email", "chat-message", "ticket", "channel", "repo", "record",
    "document", "secret-stored", "pipeline", "api-resource",
    "calendar-event", "dashboard",
)

CREDENTIAL_KIND: tuple[str, ...] = (
    "access-key", "password-hash", "kerberos-ticket", "oauth-token",
    "jwt", "api-token", "ssh-key", "client-cert", "saml-assertion",
    "session-cookie", "refresh-token",
)


#: `:H h-NNN.attr_preds`' `target` cell — WHICH of the hypothesis's three objects carries the
#: predicted attribute. A closed set rather than a `v-*`/`e-*` id: the proposed parent and the
#: proposed edge do not exist yet, so there is no id to point at, and the attached vertex is
#: already named by the hypothesis's own `attached_to`. Here rather than beside the rule that
#: refuses against it, so `invlang vocab attr-pred.target` can enumerate what the refusal wants.
ATTR_PRED_TARGETS: tuple[str, ...] = (
    "proposed_parent", "attached_vertex", "proposed_edge",
)


#: The author-facing lookup registry behind `defender-invlang enum`. `test_invlang_vocab` pins
#: the key set so a slot arrives as an acknowledged edit: what the runtime prompts inline is the
#: COMMAND (`defender/SKILL.md`), never the values, so a slot is a new thing an author can look
#: up rather than more prompt to read. `WEIGHT_CELL_VALUES` stays out — no cell sends an author
#: here for it, and `:T resolutions` teaches the five buckets where the arrow is written.
SLOTS: dict[str, tuple[str, ...]] = {
    "disposition": DISPOSITION,
    "types": TYPES,
    "relations": RELATIONS,
    "anchor-kinds": ANCHOR_KINDS,
    "auth-kinds": AUTH_KINDS,
    "authz.basis": AUTHZ_INDET_BASIS,
    "consultation.grounding": CONSULTATION_GROUNDING,
    "consultation.lookup_outcome": TACIT_LOOKUP_OUTCOMES,
    "impact.dimension": IMPACT_DIMENSION,
    "impact.verdict": IMPACT_VERDICT,
    "impact.grounding": IMPACT_GROUNDING,
    "conclude.impact_verdict": CONCLUDE_IMPACT_VERDICT,
    "conclude.impact_severity": IMPACT_SEVERITY,
    "compute.role": COMPUTE_ROLE,
    "compute.zone": COMPUTE_ZONE,
    "compute.provenance": PROVENANCE,
    "compute.kind": COMPUTE_KIND,
    "identity.kind": IDENTITY_KIND,
    "identity.provenance": PROVENANCE,
    "application.vendor": APPLICATION_VENDOR,
    "application.trust": APPLICATION_TRUST,
    "session.class": SESSION_CLASS,
    "storage.kind": STORAGE_KIND,
    "database.kind": DATABASE_KIND,
    "network-device.kind": NETWORK_DEVICE_KIND,
    "socket.protocol": SOCKET_PROTOCOL,
    "configuration.kind": CONFIGURATION_KIND,
    "app-object.kind": APP_OBJECT_KIND,
    "credential.kind": CREDENTIAL_KIND,
    "attr-pred.target": ATTR_PRED_TARGETS,
}


#: The SHAPE of a `class` cell, per vertex type — how many slash-separated slots it carries,
#: and which enum fills each one. `skills/invlang/SKILL.md` §Classification grammar states this
#: table in prose and nothing in the tree could read it, which is what deferred all three of
#: #935's defects at once: the frontier retrieval had to GUESS a cell's arity from the cell
#: itself, and a cell that names fewer slots than its type has says nothing about WHICH ones it
#: left out. `class=ip-only/??` on a `compute` vertex is the same claim as `ip-only/??/??`, and
#: only the type can say so.
#:
#: Spelled as the `SLOTS` keys rather than as a bare integer, so the table carries which
#: vocabulary fills each position and the assert below can hold it against the registry. An
#: arity that is only a number drifts from the grammar it claims to describe with nothing to
#: notice — and the enum names are what an author is sent to look up when a slot is wrong.
#:
#: A type absent here takes ONE slot, which is why `session`, `process` and the artifact types
#: are not listed at 1 rather than listed: SKILL.md gives them as "single sub-kind token" by
#: DEFAULT, so an entry per type would be a second place to add one whenever a type is minted.
CLASS_GRAMMAR: dict[str, tuple[str, ...]] = {
    "compute": ("compute.role", "compute.zone", "compute.provenance"),
    "identity": ("identity.kind", "identity.provenance"),
    "application": ("application.vendor", "application.trust"),
}

#: What a type absent from `CLASS_GRAMMAR` carries — SKILL.md's "all others".
DEFAULT_CLASS_ARITY: int = 1

#: The two suffixes a SINGLE-slot type's `class` cell can be spelled under in `SLOTS`, in the
#: order they are tried. SKILL.md gives the arity-1 cell as "a single sub-kind token (prefer the
#: corresponding `attrs.kind` enum where the type has one)", and the registry above follows the
#: cell's own noun: `session` names its one token a CLASS (`session.class`), while `storage`,
#: `database`, `credential` and the rest name theirs a KIND. A type with neither — `process`
#: (image basename), `socket` (whose only enum is `socket.protocol`, an attribute), `file`,
#: `module` — has no closed vocabulary for that cell at all, and gets none imposed on it here.
_SINGLE_SLOT_SUFFIXES: tuple[str, ...] = ("class", "kind")

assert set(CLASS_GRAMMAR).issubset(TYPES), (
    "CLASS_GRAMMAR keys must be known vertex types"
)
assert all(slot in SLOTS for slots in CLASS_GRAMMAR.values() for slot in slots), (
    "every CLASS_GRAMMAR position must name a slot `enum` can answer"
)


def class_arity(vertex_type: str) -> int:
    """How many slots a `class` cell on `vertex_type` carries.

    Answers `DEFAULT_CLASS_ARITY` for anything not in `CLASS_GRAMMAR`, INCLUDING a type outside
    `TYPES` — this table states the grammar, it does not police the type, and
    `_check_vocab_vertices` is where an unknown type is refused. The one caller
    (`scripts/lessons/lessons_frontier._class_pins`) widens to whatever the cell itself declares
    before using this, so an off-vocabulary type is never TRUNCATED by the default here.

    ABSENCE is the question, not falsiness (`defender/CLAUDE.md` §Conventions: prefer
    `is not None` over `or`). `len(...) or DEFAULT_CLASS_ARITY` answers 1 for a type entered
    here as `()` — the spelling for "this type carries no class cell at all" — which is the
    one answer that entry cannot mean.
    """
    slots = CLASS_GRAMMAR.get(vertex_type)
    return DEFAULT_CLASS_ARITY if slots is None else len(slots)


def class_slot_keys(vertex_type: str) -> tuple[str, ...]:
    """Which `SLOTS` enum judges each position of a `class` cell on `vertex_type`.

    `class_arity` answers HOW MANY slots the cell carries; this answers WHICH vocabulary each
    one is drawn from, which is what `validate._check_vocab_class_cells` needs to refuse
    `compute|container/...` — `container` is a `COMPUTE_KIND`, the vertex's deployment form,
    and the first slot of a `compute` class tuple is its ROLE (#986).

    EMPTY, not a one-slot fallback, for a type whose single token no enum closes: `process`
    carries an image basename and `socket` a free sub-kind, so there is nothing to test them
    against and an empty tuple is how this table says so. That is why `class_arity` is not
    `len(...)` of this — the two questions have different answers for exactly those types.
    """
    grammar = CLASS_GRAMMAR.get(vertex_type)
    if grammar is not None:
        return grammar
    return tuple(
        key for suffix in _SINGLE_SLOT_SUFFIXES
        if (key := f"{vertex_type}.{suffix}") in SLOTS
    )[:DEFAULT_CLASS_ARITY]


def attr_slot_key(vertex_type: str, attribute: str) -> str | None:
    """The `SLOTS` enum an `attrs.<attribute>` cell on `vertex_type` is closed by, or `None`
    where the pair names no closed vocabulary.

    Keyed on the PAIR, never on the attribute name alone: `kind` is a closed set on `compute`
    (`compute.kind`) and free text on a type that registers no enum for it, and the six
    `impact.*` / `conclude.*` / `attr-pred.target` keys in `SLOTS` are not vertex attributes at
    all — a lookup by bare name would hand a vertex the grading vocabulary of a resolution row.

    A `CLASS_GRAMMAR` POSITION is not an attribute either, and is excluded for the same reason.
    `compute.role` / `compute.zone` / `compute.provenance` (and `identity.*`, `application.*`)
    close a slash-slot of the `class` cell; SKILL.md registers no `attrs.role` and no
    `attrs.zone`, so an author writing `role=primary` (a database primary) or
    `zone=us-east-1a` (a cloud AZ) means a free attribute that happens to share a word with a
    class slot — and closing it against the class enum refuses an honest write while advising a
    vocabulary that answers a different question. The arity-1 types are NOT excluded: SKILL.md
    §Classification grammar says the single token IS "the corresponding `attrs.kind` enum where
    the type has one", so `storage`'s `attrs.kind` and its `class` cell are one vocabulary by
    construction, and `compute.kind` / `socket.protocol` are attribute enums to begin with.

    The head has to BE a vertex type, and `vertex_slots_holding` filters the same way. The pair
    is built from the row's own `type` cell, which `_check_vocab_vertices` refuses but does not
    stop the walk on — so without this, `v-001|impact|x|y|dimension=bogus` reached
    `impact.dimension` and earned a second refusal quoting the grading vocabulary of a
    resolution row, which is exactly what keying on the pair exists to prevent.
    """
    if vertex_type not in TYPES:
        return None
    key = f"{vertex_type}.{attribute}"
    if key not in SLOTS or key in CLASS_GRAMMAR.get(vertex_type, ()):
        return None
    return key


def vertex_slots_holding(value: str, *, other_than: str) -> tuple[str, ...]:
    """Every VERTEX slot other than `other_than` whose enum holds `value` — same type first.

    Here rather than in `validate`, for the reason `class_slot_keys` and `attr_slot_key` are:
    this is a membership question about THIS module's registry, and a reader that walks `SLOTS`
    itself is a second interpreter of the catalog that drifts the moment a key is added.

    VERTEX slots only — a key whose head is a `TYPES` member. `SLOTS` also registers
    `disposition`, `types`, `relations`, `anchor-kinds`, `auth-kinds` and the `impact.*` /
    `conclude.*` / `attr-pred.target` grading vocabularies, and none of them can ever close a
    cell on a vertex: pointing an author at `enum relations` because `created` happens to be a
    relation, when the cell under their cursor is a `storage.kind`, is worse than no hint at all.

    SAME TYPE FIRST because the category confusion this serves (#986) is confusion between two
    axes of ONE type — `container` is a `compute.kind` written into `compute.role`. A cross-type
    hit is still reported when nothing on the type matches, because it names the OTHER move an
    author has: "`proxy` is a `network-device.kind`" says the vertex is the wrong type, not the
    cell.
    """
    head = f"{other_than.split('.')[0]}."
    hits = [
        key for key, allowed in SLOTS.items()
        if key != other_than and key.split(".")[0] in TYPES and value in allowed
    ]
    return tuple(sorted(hits, key=lambda k: not k.startswith(head)))


def list_slots() -> list[str]:
    return sorted(SLOTS)


def get_enum(slot: str) -> tuple[str, ...]:
    try:
        return SLOTS[slot]
    except KeyError as exc:
        raise ValueError(
            f"unknown slot {slot!r}; choose from {list_slots()}"
        ) from exc
