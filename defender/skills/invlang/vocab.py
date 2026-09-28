
from __future__ import annotations

from defender._vocab import DISPOSITION_VALUES

# The one vocabulary here that invlang does not own: `disposition` is also validated in
# `report.md`, so it is imported from the project-wide vocabulary rather than restated.
DISPOSITION: tuple[str, ...] = DISPOSITION_VALUES

#: The four buckets: the closed set a `:T resolutions` `after` cell is judged against
#: (`validate._resolution_move`). Closed, because an open reading would let a misspelling
#: discharge predictions while skipping the `++` and strong-move gates. The two "no weight"
#: spellings (`∅`, `null`) are not buckets.
WEIGHT_BUCKETS: tuple[str, ...] = ("++", "+", "-", "--")
WEIGHT_ORDER: dict[str | None, int] = {"--": 0, "-": 1, None: 2, "+": 3, "++": 4}
STRONG_WEIGHTS: frozenset[str] = frozenset({"++", "--"})
REFUTED_WEIGHT: str = "--"
#: The other pole, named so no call site hard-codes the literal.
CONFIRMED_WEIGHT: str = "++"
assert STRONG_WEIGHTS.issubset(WEIGHT_BUCKETS), (
    "STRONG_WEIGHTS must be a subset of WEIGHT_BUCKETS"
)
assert REFUTED_WEIGHT in STRONG_WEIGHTS, "REFUTED_WEIGHT must be a strong weight"
assert CONFIRMED_WEIGHT in STRONG_WEIGHTS, "CONFIRMED_WEIGHT must be a strong weight"
#: How a `:H` row's `weight` cell spells "no weight yet" (projected as `None`); messages quote
#: it back verbatim.
NULL_WEIGHT: str = "null"
#: Both null spellings a `:T resolutions` arrow accepts: the format grammar's `∅` and the
#: corpus's `null`.
NULL_WEIGHT_CELLS: tuple[str, ...] = (NULL_WEIGHT, "∅")
#: Every token a weight cell may hold. Without this closed check a misspelled grade would skip
#: every weight-keyed gate.
WEIGHT_CELL_VALUES: tuple[str, ...] = (*WEIGHT_BUCKETS, *NULL_WEIGHT_CELLS)


#: What a `:H <h>.authz` row's `edge_ref` says when the contract stands against the proposed
#: edge rather than an observed one. Written by the parser for a row naming no edge, and by the
#: review's ablation over an edge it withheld, so both must share this spelling.
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

#: `:R authz`' `basis` cell on an `indeterminate` verdict: why the question is unsettled.
#:
#: `retry` (the default when absent): another registry or lead could still be tried.
#: `exhausted`: every applicable anchor kind was queried this run and none answered; checked
#: against the run's transcript (`validate/_gating._check_authz_basis`). Only the retrieval
#: frontier reacts to this; the verdict and its escalation are unchanged.
AUTHZ_INDET_BASIS: tuple[str, ...] = ("retry", "exhausted")

#: `:R consultations`' `grounding` cell. `past-case` is excluded: grounding a baseline on a
#: past case is precedent-by-similarity. (The authorization side conversely excludes
#: `telemetry-baseline`: a statistical pattern is context, never a verdict.)
CONSULTATION_GROUNDING: tuple[str, ...] = ("org-authority", "telemetry-baseline")

#: The outcome of a `tacit-knowledge` `:R consultations` lookup, as the first token of its
#: `result` cell (`hit: ...` / `miss: ...`). Closed so the validator can refuse a `miss` row
#: that also names an `anchor_id`.
TACIT_LOOKUP_OUTCOMES: tuple[str, ...] = ("hit", "miss")

#: Anchor kind → the one gather system that can answer it, so `basis=exhausted` can be checked
#: against the system a lead actually queried. Partial by design: kinds without one obvious
#: system fall back to a looser check rather than minting a second vocabulary to drift.
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

#: The impact axis, orthogonal to authorization and integrity.
#:
#: `IMPACT_DIMENSION` is what an `:L l-NNN.impact_preds` row predicts about; `IMPACT_VERDICT`
#: is what a `:R impact` row grades it to. `CONCLUDE_IMPACT_VERDICT` is the roll-up and adds
#: only `none` ("no impact predicates declared"). All are in `SLOTS` so the SKILL can point at
#: `enum` rather than restate values.
#:
#: Registered is not armed: rules #29/#30 refuse on the `impact.*` vocabularies, but the two
#: `conclude.impact_*` ones are taught only, since the runtime SKILL never stated them and
#: recorded goldens already use other values (see `validate._check_impact_closure` and
#: `docs/decisions/defender-invlang-enforcement-ramp.md`).
IMPACT_DIMENSION: tuple[str, ...] = (
    "confidentiality", "integrity", "availability", "scope",
)

IMPACT_VERDICT: tuple[str, ...] = ("within", "exceeds", "indeterminate")

CONCLUDE_IMPACT_VERDICT: tuple[str, ...] = ("none", *IMPACT_VERDICT)

#: Impact grounding excludes `past-case`: impact is about this event's consequence, which a
#: past case cannot establish. `_check_impact_resolution_refs` refuses it by name.
IMPACT_GROUNDING: tuple[str, ...] = (
    "telemetry-baseline", "business-owner-attestation", "dlp-policy",
)

#: `conclude.impact_severity`. `null` is a member: the written value when no severity applies.
IMPACT_SEVERITY: tuple[str, ...] = ("null", "low", "moderate", "high")


#: `monitoring-agent` rather than `monitoring`: it is the spelling the SKILL's examples teach,
#: and a model writes what the prompt showed it. Only one spelling per role.
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


#: `:H h-NNN.attr_preds`' `target` cell: which of the hypothesis's three objects carries the
#: predicted attribute. A closed set rather than an id, since the proposed objects have none.
#: Kept here so `enum attr-pred.target` can list it.
ATTR_PRED_TARGETS: tuple[str, ...] = (
    "proposed_parent", "attached_vertex", "proposed_edge",
)


#: The author-facing lookup registry behind `defender-invlang enum`. Runtime prompts name the
#: command, never the values. `test_invlang_vocab` pins the key set. `WEIGHT_CELL_VALUES` is
#: omitted: `:T resolutions` teaches the buckets inline.
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


#: The shape of a `class` cell per vertex type: the `SLOTS` enum filling each slash-separated
#: position. Needed because a cell may name fewer slots than its type has (`ip-only/??` on a
#: `compute` vertex means `ip-only/??/??`), and only the type says so. Spelled as `SLOTS` keys
#: so the assert below holds it against the registry. Types absent here take one slot.
CLASS_GRAMMAR: dict[str, tuple[str, ...]] = {
    "compute": ("compute.role", "compute.zone", "compute.provenance"),
    "identity": ("identity.kind", "identity.provenance"),
    "application": ("application.vendor", "application.trust"),
}

#: What a type absent from `CLASS_GRAMMAR` carries.
DEFAULT_CLASS_ARITY: int = 1

#: The `SLOTS` suffixes a single-slot type's `class` cell may be closed by, in order tried
#: (`session.class`, `storage.kind`, ...). Types with neither (`process`, `file`, ...) have no
#: closed vocabulary for the cell.
_SINGLE_SLOT_SUFFIXES: tuple[str, ...] = ("class", "kind")

assert set(CLASS_GRAMMAR).issubset(TYPES), (
    "CLASS_GRAMMAR keys must be known vertex types"
)
assert all(slot in SLOTS for slots in CLASS_GRAMMAR.values() for slot in slots), (
    "every CLASS_GRAMMAR position must name a slot `enum` can answer"
)


def class_arity(vertex_type: str) -> int:
    """How many slots a `class` cell on `vertex_type` carries.

    Answers `DEFAULT_CLASS_ARITY` for anything not in `CLASS_GRAMMAR`, including an unknown
    type (refused elsewhere, by `_check_vocab_vertices`). Tests absence, not falsiness, so a
    type entered as `()` has arity 0.
    """
    slots = CLASS_GRAMMAR.get(vertex_type)
    return DEFAULT_CLASS_ARITY if slots is None else len(slots)


def class_slot_keys(vertex_type: str) -> tuple[str, ...]:
    """Which `SLOTS` enum judges each position of a `class` cell on `vertex_type`.

    Empty for a type whose single token no enum closes (`process`, `socket`), which is why
    `class_arity` is not `len()` of this.
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

    Keyed on the (type, attribute) pair: `kind` is closed on some types and free on others,
    and non-vertex keys like `impact.dimension` must never close a vertex attribute (so the
    type must be a real vertex type). `CLASS_GRAMMAR` positions are excluded too: `role=` or
    `zone=` as an attribute is free text that happens to share a word with a class slot.
    Arity-1 types are not excluded, since their `class` token and `attrs.kind` share one enum.
    """
    if vertex_type not in TYPES:
        return None
    key = f"{vertex_type}.{attribute}"
    if key not in SLOTS or key in CLASS_GRAMMAR.get(vertex_type, ()):
        return None
    return key


def vertex_slots_holding(value: str, *, other_than: str) -> tuple[str, ...]:
    """Every VERTEX slot other than `other_than` whose enum holds `value` — same type first.

    Used to hint at a category confusion. Only vertex slots (head in `TYPES`) are considered;
    other vocabularies can never close a vertex cell. Same-type hits sort first, since the usual
    confusion is between two axes of one type (`container` is a `compute.kind`, not a
    `compute.role`); a cross-type hit suggests the vertex type itself is wrong.
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
