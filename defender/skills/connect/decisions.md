# `connect` — decisions

The irreversible calls behind this skill, for whoever edits it next. Each
is load-bearing — change one only on purpose. The *how* is in `SKILL.md`,
`adapter.md`, and `mcp.md`; this is just the *why*, kept short.

- **Secrets live in the environment; the skill never handles values.**
  `config.env` holds non-secret config and the *names* of the env vars
  that hold secrets. The transport reads a secret only from the run's
  scrubbed `ctx.env` by the name `config.env` declares — never from
  `config.env` itself, never from the driver's `os.environ` — so a
  generated adapter can't improvise the credential boundary and can't leak
  a provider key into a forked child. An LLM context is not an auditable
  credential store — this is the single most important property of the layer.

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
  On a fresh tree connect copies `example_adapter.py` and writes its own
  transport; on a populated tree it conforms to the shared transport module
  and conventions the existing adapters already use — one shared module per
  tree, never two. A
  second parallel pattern (duplicate transport/config schemes) is exactly
  the drift per-system consistency exists to avoid, and it fragments the
  prior the gather subagent relies on.

- **The query catalog grows post-merge; connect seeds only a couple
  templates.** Which measurements characterize real alerts isn't knowable
  from API docs at connect time — it's exactly what the offline
  lead-author extracts from real runs. Speculative templates rot.

- **MCP and a generated adapter are peer paths, not a hierarchy.** Writing
  an adapter is heavier than pointing at a maintained MCP server, but neither
  is the "real" way to connect. The interview routes; the maintainer decides.
  The one defender-specific tilt: only the adapter path's output flows
  through the capture path into the queries table, so an MCP system is
  thinner in the offline learning loop. That's a cost to weigh, not a
  disqualifier.

- **Human review gate.** connect branches and stages; it does not merge
  or push. Generated code does not go live without a human reading the
  diff.

- **One system per invocation.** Scope creep is the enemy of a clean
  review diff.
