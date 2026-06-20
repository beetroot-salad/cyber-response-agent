# `connect` — decisions

The irreversible calls behind this skill, for whoever edits it next. Each
is load-bearing — change one only on purpose. The *how* is in `SKILL.md`,
`cli-adapter.md`, and `mcp.md`; this is just the *why*, kept short.

- **Secrets live in the environment; the skill never handles values.**
  `config.env` holds non-secret config and the *names* of the env vars
  that hold secrets. One audited code path resolves credentials
  (`_adapter.resolve_auth`), so a generated adapter can't improvise the
  credential boundary. An LLM context is not an auditable credential
  store — this is the single most important property of the layer.

- **Native queries pass through unmodified.** A query source takes its
  native language as-is; a lookup source keys on an identifier. No
  translation layer — the agent already knows these languages, and a
  translator is permanent bug surface and lost expressivity.

- **The CLI conforms to the gather subagent, not the reverse.** The
  gather subagent (Haiku) is the adapter's client. On any cosmetic choice
  — flag names, verb names, ordering — the adapter matches what a
  fresh-context Haiku reaches for. We document a divergence only when
  it's an irreducible vendor constraint, never to teach the client our
  aesthetics. This keeps the instruction surface minimal. (See
  `cli-adapter.md` → the alignment loop.)

- **Adapters are generated fresh, never copied from a vendor template
  library.** A vendored adapter rots silently against API changes; a
  freshly generated one is anchored to current knowledge and tested
  immediately. A template library is also CI, version pinning, and a
  per-vendor PR queue for a marginal speedup.

- **The query catalog grows post-merge; connect seeds only a couple
  templates.** Which measurements characterize real alerts isn't knowable
  from API docs at connect time — it's exactly what the offline
  lead-author extracts from real runs. Speculative templates rot.

- **MCP and CLI are peer paths, not a hierarchy.** Writing a CLI is
  heavier than pointing at a maintained MCP server, but neither is the
  "real" way to connect. The interview routes; the maintainer decides.
  The one defender-specific tilt: only the CLI path's `--raw` output
  flows through the capture wrapper into the queries table, so an MCP
  system is thinner in the offline learning loop. That's a cost to weigh,
  not a disqualifier.

- **Human review gate.** connect branches and stages; it does not merge
  or push. Generated code does not go live without a human reading the
  diff.

- **One system per invocation.** Scope creep is the enemy of a clean
  review diff.
