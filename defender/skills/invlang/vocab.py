
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
    "other",
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


COMPUTE_ROLE: tuple[str, ...] = (
    "monitoring", "web-server", "app-server", "database-server",
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


def list_slots() -> list[str]:
    return sorted(SLOTS)


def get_enum(slot: str) -> tuple[str, ...]:
    try:
        return SLOTS[slot]
    except KeyError as exc:
        raise ValueError(
            f"unknown slot {slot!r}; choose from {list_slots()}"
        ) from exc
