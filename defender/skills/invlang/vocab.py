
from __future__ import annotations

from defender._vocab import DISPOSITION_VALUES

# The one vocabulary in this module that invlang does NOT define — every other slot below is
# invlang's own domain. `disposition` is the run's headline, carried by `report.md` too and
# validated there by a different schema, so it is imported from the project-general vocabulary
# rather than restated: two schemas spelling out the same keywords eventually disagree.
DISPOSITION: tuple[str, ...] = DISPOSITION_VALUES

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

#: How a `:T resolutions` head spells "no weight" — BOTH spellings. `∅` is the format
#: grammar's; `null` is what `skills/invlang/SKILL.md`'s worked examples, both shipped e2e
#: goldens and every test corpus actually write. They reach `ResolutionRecord.before` /
#: `after` verbatim, so a reader asking "did this row move the hypothesis anywhere" has to
#: know both — testing one spelling reads the other as a real move.
NULL_WEIGHTS: frozenset[str] = frozenset({"∅", "null"})
assert not (NULL_WEIGHTS & set(WEIGHT_BUCKETS)), (
    "NULL_WEIGHTS names the ABSENCE of a bucket and must not name one"
)


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
}


def list_slots() -> list[str]:
    return sorted(SLOTS)


def get_enum(slot: str) -> tuple[str, ...]:
    try:
        return SLOTS[slot]
    except KeyError as exc:
        raise ValueError(
            f"unknown slot {slot!r}; choose from {list_slots()}"
        ) from exc
