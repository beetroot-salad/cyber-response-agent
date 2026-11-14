# `connect` — decisions

The irreversible calls behind this skill, for whoever edits it next. Each
is load-bearing — change one only on purpose. The *how* is in `SKILL.md`,
`configure.md` and `adapter.md`; this is just the *why*, kept short.

- **The skill never handles secret values.** `config.env` and `access.yaml`
  hold non-secret settings only; the operator stores a credential with the
  credential proxy, which applies it by the declared scheme, so a generated
  adapter never holds one and can't improvise the credential boundary. An LLM
  context is not an auditable credential store — this is the single most
  important property of the layer.

- **Native queries pass through unmodified.** A query source takes its
  native language as-is; a lookup source keys on an identifier. No
  translation layer — the agent already knows these languages, and a
  translator is permanent bug surface and lost expressivity.

- **Native, server-side aggregation is the default; download-and-reduce
  is a fallback.** When a source has a query language that aggregates
  server-side (ES|QL/SPL/KQL/SQL), the adapter exposes it and returns the
  computed answer. The gather redesign showed that downloading payloads
  and reducing them adapter- or agent-side was the dominant cost, and
  aggregating server-side in a language the model already knows removed
  it. A filter-only source falls back to native-filter passthrough plus
  `defender-sql` (sandboxed SQL the model drives) over the adapter's JSON
  payload; we don't write a bespoke reducer. The ladder is in `adapter.md`
  ("Prefer native aggregation").

- **The adapter conforms to the gather subagent, not the reverse.** The
  gather subagent (Haiku) is the adapter's client. On any cosmetic choice
  — verb names, param names — the adapter matches what a
  fresh-context Haiku reaches for. We document a divergence only when
  it's an irreducible vendor constraint, never to teach the client our
  aesthetics. This keeps the instruction surface minimal. (See
  `adapter.md` → the alignment loop.)

- **Adapters are generated fresh, never copied from a vendor template
  library.** A vendored adapter rots silently against API changes; a
  freshly generated one is anchored to current knowledge and tested
  immediately. A template library is also CI, version pinning, and a
  per-vendor PR queue for a marginal speedup.

- **The bundled example is a greenfield seed, not a mandate to duplicate.**
  On a fresh tree connect copies `example_adapter.py`; on a populated tree it
  conforms to the conventions the existing adapters already use. Either way
  the transport is the shared proxied one — an adapter reaches its system
  only through the credential proxy (#1391), so it never writes its own. A
  second parallel pattern (duplicate transport/config schemes) is exactly
  the drift per-system consistency exists to avoid, and it fragments the
  prior the gather subagent relies on.

- **The query catalog grows post-merge; connect seeds only a couple
  templates.** Which measurements characterize real alerts isn't knowable
  from API docs at connect time — it's exactly what the offline
  lead-author extracts from real runs. Speculative templates rot.

- **An adapter the product carries is configured, never regenerated.** The catalog's adapters
  are reviewed product code; a second, generated copy of one is drift with no reviewer. Connect
  generates only for a system the catalog lacks (#1401).

- **MCP-reached systems come with #1494.** Connect offers an MCP path once a run can call an MCP
  server's tools; until then, knowledge for such a system would route the orchestrator to a
  system gather cannot call.

- **The check is agreed before anything is built, and run through the credential proxy.** A check
  written after the build is shaped by what was built. Its answer must be falsifiable (a value a
  wrong credential, base or mapping would not give), and it carries a negative control whose
  failure is the red: before the build every check fails for "nothing is there", which proves
  nothing. It runs through the proxy because that is how production reaches the system; a call
  from the maintainer's session would prove a path no run takes (#1401, #1493).

- **A system that writes is checked by writing, on something disposable.** A read-only health
  check proves the address and the credential, not that the write the product makes is allowed.
  Later investigations read a ticket's comments as its history, so the write goes only to a
  ticket the maintainer names as disposable (#1401).

- **Human review gate.** connect branches the product half and proposes the tenant
  half (`tenant.py propose`, a review PR on the tenant forge); it does not merge
  or push. Generated code does not go live without a human reading the
  diff.

- **One system per invocation.** Scope creep is the enemy of a clean
  review diff.
