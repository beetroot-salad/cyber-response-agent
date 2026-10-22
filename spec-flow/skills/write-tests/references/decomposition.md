# Decomposing a large contract

Read only when the suite or its review cannot fit in one focused context. The sketch and design check are never decomposed; split only the thorough pass, after the design check has settled what the slices share. Decompose work by coherent obligations and stable ownership boundaries; a fixed number of tests or files is not a sound cut.

Before dispatch, each slice needs a closed dossier: current design and decisions, owned obligations/files, relevant facts and interfaces, shared test machinery, and acceptance that can be checked without waiting for another writer to invent its semantics. A proposed interface wrapping an external system needs grounding in the real system's behavior, including relevant failures; a written signature alone does not establish that behavior.

Keep coupled invariants together or assign their integration scenarios explicitly. Identity, atomicity, partial progress, ordering and cross-surface guarantees cannot disappear between slices. The union of slice assertions plus integration assertions must cover the whole contract. Distinguish splitting **work** from adding independent **readings** of the same work.

Assign shared fixtures/helpers one owner. Other writers request changes through the orchestrator; they do not concurrently edit shared files. The orchestrator can build/integrate common machinery itself. Dispatch writers directly, each with owned files; avoid sub-coordinators that poll nested workers. Review can also split, but retain a reader with enough whole-flow context to challenge composition and reconcile findings.

A fan-out over callers, resources or execution contexts is only as complete as the census behind it. Record its scope and search evidence, including relevant subprocess/harness/CLI paths and shared-store consumers. A union of covered obligations cannot detect a context nobody listed; retain a whole-system impact check and defer the implementation-derived context census explicitly until real code exists.

If a slice needs most of its siblings' context, the cut may cross the coupled core. Keep that region together rather than force equally sized work. New mechanisms or amended flows may invalidate the cut and census; reevaluate affected boundaries without discarding unrelated evidence.

Reconcile returned work by obligation, finding and assertion IDs, not matching counts. Integrate and execute shared scenarios before calling the contract reviewed. Report missing coverage, conflicting fixture assumptions, and unexercised assertions explicitly.
