# Splitting a large contract

Split only the thorough pass, and only when it can't fit one focused context. The sketch, spike and design check stay whole, and the split happens after them, once the design check has settled what the slices share.

Cut along coherent obligations and ownership, not file or test counts. The danger of any split is a guarantee that falls between slices: identity, atomicity, partial progress, ordering and cross-surface behavior. Keep coupled invariants in one slice, or assign their integration scenarios to someone explicitly, so that the slices plus the integration tests cover the whole contract. If a slice needs most of its siblings' context, the cut runs through the coupled core; keep that region together even if slices end up uneven.

Each slice starts with everything it needs and no dependency on another writer's unfinished choices: the current design, its obligations and owned files, the relevant part of the code map, and the shared machinery's interface. An interface wrapping an external system must be grounded in that system's real behavior, failures included.

Shared fixtures and helpers have one owner, often the orchestrator, who builds them first. Others request changes through the orchestrator rather than editing them concurrently. The orchestrator dispatches every writer directly; a worker that coordinates nested workers by polling is a pattern to avoid.

A fan-out over callers, resources or execution contexts is only as complete as the list behind it. Record how that list was found, including subprocess, harness, CLI and shared-store paths, because no union of covered obligations can reveal a context nobody listed. Keep one whole-system impact check, and leave the census that depends on real code to the code stage, explicitly.

Reconcile returned slices by obligation, finding and assertion IDs, not counts, and run the shared scenarios before calling the contract ready for review. An amendment that adds a mechanism or changes a flow may invalidate the cut: re-check the affected boundaries and keep the rest.
