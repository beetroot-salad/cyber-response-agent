"""Emit spec_graph_575-grant-gate.yaml from a Python structure (so it is valid by construction)."""
import yaml

D = lambda i, k, f, b, o, r=None: {
    "id": i, "kind": k, "form": f, "binds": b, "outcome": {"nl": o},
    **({"rejected": [{"nl": x} for x in r]} if r else {})
}

demands = [
 # §A containment model
 D("a1","behavior","test",["decide_bash","Grant.pattern","Grant.scope"],
   "A command is allowed only if it matches a grant's pattern AND every operand PROGRAMS extracts resolves into that grant's scope."),
 D("a2","negative","test",["Grant.pattern","Grant.pins_path"],
   "No unmarked grant's compiled pattern embeds a path; the three program-operand grants carry pins_path=True.",
   ["Write an execute-extractor for python3/rm instead. Rejected: python3 -c puts the flag itself in the argv slot, and rm unlinks the LINK rather than resolve()'s target."]),
 D("a3","behavior","test",["under"],"under(root, tail) fullmatches against the RESOLVED path."),
 D("a4","negative","test",["GATHER_RAW_SHAPE","RUN_NO_RAW_SHAPE","CORPUS_MD_SHAPE"],
   "No path shape uses an any-byte-but-NUL class; the machine-generated gather_raw shape is tight (gather_raw/l-N/N.json)."),
 D("a5","negative","test",["decide_bash","Grant.scope","read_surface.access[bash]"],
   "A symlink inside run_dir pointing outside it is DENIED for cat on the bash lane."),
 D("a6","behavior","test",["decide_bash","Grant.scope"],
   "A symlink inside run_dir pointing to another in-root file is ALLOWED, so a5 denies for escape rather than because symlinks are banned. This is a5's positive control."),
 D("a7","behavior","test",["decide_bash"],
   "A symlink loop raises RuntimeError inside resolve() and the gate fails closed with a DENY, never an escaping exception."),
 D("a8","behavior","test",["decide_bash","Grant.scope"],
   "resolve(strict=False) does not raise on a missing path, so a not-yet-written gather_raw payload still scope-matches and gather may cat it."),
 D("a9","behavior","test",["decide_bash"],
   "An embedded-NUL operand raises ValueError inside resolve() and the gate fails closed with a DENY."),
 D("a10","behavior","test",["Grant.scope","resolve_roots"],
   "Scope patterns anchor on the RESOLVED root, so a run_dir reached through a symlinked base still admits its own files."),
 D("a11","behavior","test",["decide_bash"],
   "A relative operand is rebased on defender_dir.parent, the cwd the executor uses, before it is resolved."),
 D("a12","behavior","test",["decide_bash"],
   "Every pipe stage is operand-gated: an in-scope cat piped into a cat of /etc/passwd is DENIED on the second stage."),
 # §B PROGRAMS + OPENS_NOTHING
 D("b1","behavior","test",["PROGRAMS","PROGRAMS.domain.distinguished[cat]","PROGRAMS.domain.distinguished[OPENS_NOTHING]"],
   "PROGRAMS maps cat to the real extractor and every other granted program to OPENS_NOTHING."),
 D("b2","behavior","test",["compile_policy","PROGRAMS.domain.distinguished[absent]"],
   "compile_policy RAISES when a grant names a program absent from PROGRAMS: loud at compile, never fail-open at first decide."),
 D("b3","behavior","test",["compile_policy","_corpus_author_policy"],
   "Every AgentPolicy in the registry passes the program-table validation, including CORPUS_AUTHOR's, which is built directly and never calls compile_policy today."),
 D("b4","domain-outcome","test",["_cat_input_files"],
   "_cat_input_files returns None (DENY) for every unrecognized dash-prefixed token, and the known boolean bundles extract their file operands correctly."),
 D("b5","domain-outcome","test",["_cat_input_files"],
   "A cat whose operand follows a bare double-dash still DENIES out of scope: post-double-dash tokens are appended as file operands and are therefore scope-checked."),
 D("b6","domain-outcome","test",["_cat_input_files"],
   "A bare dash is stdin and extracts no operand, so the stdin pipe shape still allows."),
 D("b7","negative","test",["PROGRAMS.domain.distinguished[OPENS_NOTHING]","read_surface.access[bash]"],
   "Every OPENS_NOTHING program's shape regex admits no file-opening or arg-consuming flag (wc files0-from, grep -f/-e/-r/--file, jq -f/-L/--rawfile/--slurpfile, tail -f, head -c FILE all DENY), because the gate skips the scope check for them entirely."),
 D("b8","negative","test",["PROGRAMS.domain.distinguished[OPENS_NOTHING]","Grant.pattern"],
   "Structurally, no OPENS_NOTHING grant's pattern admits a long option or a dash-prefixed positional, so the single-dash-bundle and no-leading-dash conventions become enforced properties a future grammar author cannot silently drop.",
   ["Leave it as the convention it is today (gnu_flags.bundle emits single-dash only). Rejected: that is exactly what let the judge's unrestricted cat shape be written."]),
 # §C behavior-change ledger
 D("c1","domain-outcome","test",["Grant.pattern","read_surface.access[bash]"],
   "The file-operand viewer forms now DENY and their cat-piped equivalents ALLOW, for grep, head, tail and wc alike."),
 D("c2","negative","test",["MAIN_DEF.bash_allow","GATHER_DEF.bash_allow"],
   "ls and cd are denied in every form for main and gather, while the surviving programs still allow."),
 D("c3","negative","test",["MAIN_DEF.bash_allow"],
   "Main has no recursive-descent primitive: recursive ls and recursive grep both deny, so no path under run_dir is reachable without naming it."),
 D("c4","survival","test",["Grant.pattern","gather_query_template"],
   "The shipped query template's literal piped-jq command still allows for gather; a shipped template the gate denies is a documented dead command."),
 D("c5","domain-outcome","test",["decide_bash","RAW_MARKER"],
   "The RAW_MARKER substring scan is gone: a main command that merely MENTIONS gather_raw in a grep pattern now ALLOWS, where at HEAD it denies purely because the command string contains the literal text."),
 D("c6","survival","test",["CORPUS_AUTHOR_DEF.bash_allow","curator_prompt"],
   "On the curator lane a grep with a file operand denies, its cat-piped equivalent allows, and ls of the lessons dir denies because the corpus manifest shipped in #574 replaces the listing."),
 # §D read surface
 D("d1","domain-outcome","test",["GATHER_RAW_SHAPE","MAIN_DEF.bash_allow","GATHER_DEF.bash_allow"],
   "A cat of a gather_raw payload ALLOWS for gather and DENIES for main, by positive enumeration rather than a substring clamp."),
 D("d2","behavior","test",["decide_read","read_surface.access[read-tool]"],
   "decide_read of a gather_raw payload DENIES for main with a reason naming gather_raw, and the e2e deny-tail substring still matches.",
   ["Relax the e2e assertion to the generic deny reason. Rejected: that silently loosens a security assertion."]),
 D("d3","negative","test",["is_untrusted_read","GATHER_RAW_SHAPE"],
   "is_untrusted_read is still True for a gather_raw payload so the read stays salt-tag wrapped; removing RAW_MARKER must not untag the primary attacker-influenced channel."),
 D("d4","parity","test",["read_surface.access[bash]","read_surface.access[read-tool]"],
   "The path-shape tuple decide_read enforces IS the same object the cat grant's scope carries, so the two surfaces cannot drift, and a policy whose two lists differ fails the parity harness."),
 D("d5","parity","test",["read_surface.access[bash]","read_surface.access[read-tool]"],
   "The allow-matrix: for every agent and path in a fixed corpus, the read-tool verdict equals the bash-lane cat verdict."),
 D("d6","negative","test",["read_surface.access[bash]","read_surface.access[read-tool]","denylist"],
   "The secret denylist still applies INSIDE scope: a dot-env file whose name matches the corpus markdown shape still denies, and so does an ssh-key path."),
 # §E pins_path grants
 D("e1","negative","test",["JUDGE_DEF.bash_allow","ticket_grant"],
   "A judge ticket command WITHOUT the require-closed flag DENIES and with it ALLOWS; the mandatory-flag lookahead is the security property, and a boolean-flag allowlist would silently make it optional."),
 D("e2","behavior","test",["JUDGE_DEF.bash_allow","ticket_grant"],
   "The adversarial judge, bound with no ticket CLI, has no ticket grant at all, so even the well-formed require-closed command denies."),
 D("e3","behavior","test",["ticket_grant"],
   "The require-closed flag cannot be smuggled inside a quoted operand, because the NUL token-space sentinel keeps every space in the joined argv a true token boundary."),
 D("e4","behavior","test",["ACTOR_DEF.bash_allow","LEAD_AUTHOR_DEF.bash_allow"],
   "The actor's pinned python script and the lead author's rm of a skills markdown file still allow, while an arbitrary script path and a traversing rm deny."),
 # §F routing / layering
 D("f1","seam","test",["BashDecision","interacts(tool_bash->bash_exec)"],
   "BashDecision still carries pipelines, adapter_argv and sql_pipe, all three consumed by the tool's capture path, and Grant.route tags reader-lane grants only."),
 D("f2","behavior","test",["decide_bash","_decide_adapter"],
   "Adapter classification stays structural and runs AFTER the reader lane declines, so the ORDER is pinned and not merely the verdict."),
 D("f3","survival","test",["_decide_adapter","ADAPTER_DENY_REASON","ADAPTER_STANDALONE_REASON"],
   "Both specific adapter deny reasons survive as the substrings the e2e deny-tail asserts."),
 D("f4","behavior","test",["_decide_adapter","Route"],
   "The sanctioned two-stage adapter-into-defender-sql pipe allows for gather with a correct split, and an adapter piped into a viewer denies."),
 D("f5","negative","test",["runtime_package"],
   "No module under runtime imports a private symbol from the learning package (lazy and function-body imports count) and nothing under runtime enumerates agents, while the relocated agents module DOES import the six defs, proving the scan can see one."),
 D("f6","shape","test",["interacts(tool_bash->bash_exec).payload"],
   "The argv EXECUTED is the argv GATED: run_parsed receives exactly the pipelines the decision carries, so no validator/executor parser differential can reopen.",
   ["Re-parse the command string in the executor. Rejected: that differential is what shell=False plus the single-parse decision exist to close."]),
 # §G prompt surface
 D("g1","negative","test",["deny_reason","_overflow_filter_hint"],
   "No deny reason and no overflow hint names a program the agent cannot run: each program-looking word is checked against that agent's OWN lane, not against a hardcoded dead-name list."),
 D("g2","behavior","test",["_overflow_filter_hint","_lane_admits"],
   "The overflow hint still reaches the jq branch for main and gather, the sql branch for the judge, and the read-tool fold for the rest, and _lane_admits goes through the real decide seam rather than fullmatching over a tuple that now holds Grants."),
 # §H lifecycle
 D("h1","behavior","test",["compile_policy_for"],"compile_policy_for is idempotent for the same definition and roots."),
 D("h2","uniqueness","test",["compile_policy_for","resolve_roots"],
   "No cross-run bleed: two run dirs compiled in one process yield policies whose scopes anchor on their OWN run dir, which matters because gather binds per dispatch, many times per run."),
 D("h3","survival","test",["denylist"],
   "An empty denylist axis contributes no lookahead and does not brick the reader lane."),
 D("h4","behavior","test",["compile_policy_for","resolve_roots","LEAD_AUTHOR_DEF.bash_allow"],
   "Grants anchor on the defender_dir and run_dir THREADED IN, never on the import-time PATHS constant: a lead author bound with a worktree defender_dir gets an rm grant anchored on the WORKTREE's skills dir, and the main checkout's skills dir DENIES. Both re-exec drivers (replay_actor, harness_lead) relocate the tree anchor onto whatever tree they run in."),
 # §I CLI
 D("i1","behavior","test",["defender_policy_cli"],
   "defender-policy show prints each agent's read, write and bash grants with their scopes, and an exempt grant reports its PATTERN as the containment rather than a misleading empty scope."),
 D("i2","parity","test",["defender_policy_cli","decide_bash"],
   "defender-policy explain reports the same verdict and the same matched-grant or deny-reason as decide_bash, so the CLI is a second consumer of the gate and never a second implementation."),
 D("i3","negative","test",["defender_policy_cli","NON_ADAPTER_SHIMS"],
   "defender-policy is not a shim in any agent lane, since adding it to the shim taxonomy would hand every agent policy introspection for free."),
 # waivers
 D("w1","behavior","waiver",["runtime_package"],
   "Net LOC across the permission package and agent_definition does not increase. A review property, not observable behavior: checked at human review."),
 D("w2","behavior","waiver",["interacts(tool_bash->bash_exec)"],
   "A wedging stage such as tail -f is bounded by the bash timeout, not by the gate. b7 pins the DENY; the timeout is out of scope."),
]

B = lambda i, p, f=None: {"id": i, "provenance": p, "facets": f or {}}

structure = {
 "axes": ["agent_role", "program", "operand_path", "via", "run_dir"],
 "actors": [
   {"id":"decide_bash","frame":"leg","provenance":"code"},
   {"id":"decide_read","frame":"leg","provenance":"code"},
   {"id":"compile_policy","frame":"leg","provenance":"code"},
   {"id":"compile_policy_for","frame":"composition","provenance":"code"},
   {"id":"tool_bash","frame":"composition","provenance":"code"},
   {"id":"defender_policy_cli","frame":"leg","provenance":"design"},
   {"id":"_corpus_author_policy","frame":"leg","provenance":"code"},
   {"id":"run_investigation","frame":"composition","provenance":"code"},
   {"id":"replay_actor","frame":"composition","provenance":"code"},
   {"id":"harness_lead","frame":"composition","provenance":"code"},
 ],
 "boundaries": [
   {"id":"read_surface","provenance":"code","facets":{
      "access":{"constraints_by_via":{
         "bash":{"trust":"attacker-influenced","constraints":["confine","denylist","resolve"]},
         "read-tool":{"trust":"attacker-influenced","constraints":["confine","denylist","resolve"]}}},
      "identity":{"key_axes":["operand_path"],
         "evidence":{"nl":"The resolved operand path is the full key, read off files.read_allowed_path and the cat grant's scope, which the design makes the same shape objects."},
         "sharing":"unique-key"}}},
   {"id":"PROGRAMS","provenance":"design","facets":{
      "domain":{"type":"enum",
         "refinement":{"nl":"Which files does this program's argv open? cat has a real extractor; every other granted program opens nothing; an ABSENT program is a compile-time error."},
         "default":"OPENS_NOTHING","distinguished":["cat","OPENS_NOTHING","absent"],
         "falsy_valid":False,"documented_alternatives":[]}}},
   B("Grant.pattern","design"), B("Grant.scope","design"),
   {"id":"Grant.pins_path","provenance":"design","facets":{
      "domain":{"type":"bool",
         "refinement":{"nl":"True for the three grants whose operand IS the program (actor python script, rm, judge ticket CLI); their pattern legitimately pins a path and carries the mandatory require-closed lookahead."},
         "default":False,"distinguished":[True,False],"falsy_valid":True,"documented_alternatives":[]}}},
   B("ticket_grant","code"), B("denylist","code"), B("RAW_MARKER","code"),
   B("is_untrusted_read","code"), B("_overflow_filter_hint","code"), B("deny_reason","code"),
   B("_lane_admits","code"), B("curator_prompt","code"), B("gather_query_template","code"),
   B("runtime_package","code"), B("BashDecision","code"),
   B("BashGrammar","code"), B("read_shapes","code"), B("reader_patterns_for","code"), B("raw_reads","code"),
   B("GATHER_RAW_SHAPE","design"), B("RUN_NO_RAW_SHAPE","design"), B("CORPUS_MD_SHAPE","design"),
   B("under","design"), B("Route","design"), B("_cat_input_files","code"), B("resolve_roots","code"),
   B("_decide_adapter","code"), B("ADAPTER_DENY_REASON","code"), B("ADAPTER_STANDALONE_REASON","code"),
   B("NON_ADAPTER_SHIMS","code"),
   B("MAIN_DEF.bash_allow","code"), B("GATHER_DEF.bash_allow","code"), B("JUDGE_DEF.bash_allow","code"),
   B("ACTOR_DEF.bash_allow","code"), B("LEAD_AUTHOR_DEF.bash_allow","code"), B("CORPUS_AUTHOR_DEF.bash_allow","code"),
   {"id":"bash_exec","provenance":"code","facets":{
      "payload":{"parts":[{"role":"argv","source":"const:decision.pipelines"}],
         "invariants":["all-slots-bound"],
         "nl":"run_parsed receives exactly the pipelines the gate already parsed: the single-parse decision that collapses the validator/executor differential."}}},
 ],
 "interacts": [
   {"from":"decide_bash","to":"read_surface","mode":"read","via":"bash","provenance":"design"},
   {"from":"decide_read","to":"read_surface","mode":"read","via":"read-tool","provenance":"design"},
   {"from":"decide_bash","to":"PROGRAMS","mode":"read","via":"api","provenance":"design"},
   {"from":"compile_policy","to":"PROGRAMS","mode":"read","via":"api","provenance":"design"},
   {"from":"_corpus_author_policy","to":"PROGRAMS","mode":"read","via":"api","provenance":"design"},
   {"from":"decide_bash","to":"Grant.pattern","mode":"read","via":"api","provenance":"design"},
   {"from":"decide_bash","to":"Grant.scope","mode":"read","via":"api","provenance":"design"},
   {"from":"decide_bash","to":"Grant.pins_path","mode":"read","via":"api","provenance":"design"},
   {"from":"decide_bash","to":"ticket_grant","mode":"read","via":"api","provenance":"code"},
   {"from":"decide_read","to":"denylist","mode":"read","via":"api","provenance":"code"},
   {"from":"decide_bash","to":"denylist","mode":"read","via":"api","provenance":"code"},
   {"from":"is_untrusted_read","to":"RAW_MARKER","mode":"read","via":"api","provenance":"code"},
   {"from":"tool_bash","to":"bash_exec","mode":"invoke","via":"subprocess","provenance":"code","sends":"payload","transport":"subprocess"},
   {"from":"tool_bash","to":"BashDecision","mode":"read","via":"api","provenance":"code"},
   {"from":"tool_bash","to":"_overflow_filter_hint","mode":"read","via":"api","provenance":"code"},
   {"from":"_overflow_filter_hint","to":"_lane_admits","mode":"read","via":"api","provenance":"code"},
   {"from":"defender_policy_cli","to":"decide_bash","mode":"invoke","via":"api","provenance":"design"},
   {"from":"decide_bash","to":"RAW_MARKER","mode":"remove","via":"bash","provenance":"design"},
   {"from":"decide_read","to":"read_shapes","mode":"remove","via":"read-tool","provenance":"design"},
   {"from":"compile_policy","to":"BashGrammar","mode":"remove","via":"api","provenance":"design"},
   {"from":"compile_policy","to":"reader_patterns_for","mode":"remove","via":"api","provenance":"design"},
   {"from":"decide_bash","to":"raw_reads","mode":"remove","via":"api","provenance":"design"},
   {"from":"curator_prompt","to":"read_surface","mode":"read","via":"bash","provenance":"code"},
   {"from":"gather_query_template","to":"read_surface","mode":"read","via":"bash","provenance":"code"},
   {"from":"deny_reason","to":"read_surface","mode":"read","via":"bash","provenance":"code"},
 ],
 "drives": [
   {"from":"compile_policy_for","to":"compile_policy","provenance":"code","multiplicity":"serial"},
   {"from":"run_investigation","to":"tool_bash","provenance":"code","multiplicity":"serial"},
   {"from":"tool_bash","to":"decide_bash","provenance":"code","multiplicity":"serial"},
   {"from":"replay_actor","to":"run_investigation","provenance":"code","multiplicity":"serial"},
   {"from":"harness_lead","to":"compile_policy_for","provenance":"code","multiplicity":"serial"},
 ],
}

O = lambda rule, el, by, w: {"rule": rule, "element": el, "discharged_by": by, "witness": w}

gate = {
 "evaluated": [{"rule":"R0","fired":True},{"rule":"R1","fired":True},{"rule":"R2","fired":False},
               {"rule":"R3","fired":True},{"rule":"R4","fired":True},{"rule":"R5","fired":True}],
 "obligations": [
   O("R3","read_surface.access[bash]","d4","Read surface reached via bash AND read-tool. The design claims parity becomes structural, so a demand must FALSIFY it (a policy whose two lists differ must fail the harness), not merely sample paths that happen to agree."),
   O("R3","read_surface.access[read-tool]","d5","Per constraint-by-via cell: confine must hold on BOTH vias for the same agent and path. The allow-matrix over a fixed corpus."),
   O("R3","read_surface.access[bash]","d6","The denylist constraint is enforced on the read-tool via today; it must still be enforced on the bash via INSIDE scope, since a dot-env file matches the corpus markdown shape."),
   O("R3","read_surface.access[read-tool]","d2","The gather_raw confine constraint is enforced on the bash via by positive enumeration; the read-tool via loses raw_reads and must enforce it too, or main can read_file any payload."),
   O("R3","read_surface.access[read-tool]","d3","is_untrusted_read keys on RAW_MARKER to salt-tag payload reads; removing the marker without a shape-based replacement fails the prompt-injection defense OPEN."),
   O("R4","PROGRAMS.domain.distinguished[cat]","b1","The one member with a real extractor."),
   O("R4","PROGRAMS.domain.distinguished[absent]","b2","The absent member must FAIL LOUD. It replaces today's silent pass-through, where an untabled program is simply ungated."),
   O("R4","PROGRAMS.domain.distinguished[OPENS_NOTHING]","b7","OPENS_NOTHING is the DEFAULT member and it skips the scope check entirely, so its shape regex is the sole containment. Every file-opening flag must be exercised against it."),
   O("R4","Grant.pins_path.domain.distinguished[true]","e1","pins_path true is the exempt member; the judge's mandatory require-closed lookahead lives inside that exemption and must be exercised on BOTH sides."),
   O("R5","PROGRAMS.domain.distinguished[OPENS_NOTHING]","b8","SAFE-BY-CONSTRUCTION (R5's judgment extension). A future author can declare a program OPENS_NOTHING and write a shape admitting a file-opening flag; the gate then skips the scope check and the program opens a file nobody checked. Assert the grammar CANNOT be built unsafe, not merely that today's grammars happen to be safe."),
   O("R5","read_surface","c1","The file-operand viewer forms are removed; the cat-piped substitute must demonstrably complete."),
   O("R5","read_surface","c2","ls and cd are removed from the lane."),
   O("R5","gather_query_template","c4","The one shipped jq template is a live consumer of the bash lane; it must still run."),
   O("R5","curator_prompt","c6","The curator prompts positively instruct an ls of the lessons dir and a grep with a file operand; both are removed. The substitute is the #574 manifest plus cat-into-grep."),
   O("R5","deny_reason","g1","Three deny reasons NAME the removed programs (main and gather policies name ls; the adapter reason says to filter the persisted payload FILE with jq/grep). A reason naming a dead program teaches a dead command."),
   O("R5","_lane_admits","g2","_lane_admits fullmatches over policy.bash_allow: an AttributeError in production, in the overflow path, the moment that tuple holds Grants."),
   O("R5","RAW_MARKER","c5","Removing the substring scan LOOSENS: a command merely MENTIONING gather_raw is no longer denied. Verified against HEAD. Pin the new verdict as an examined change, not a regression."),
   O("R5","reader_patterns_for","h2","reader_patterns_for is an lru_cache of size one and gather binds per DISPATCH; whatever replaces it must not bleed across run dirs."),
   O("R5","BashGrammar","f1","adapters and adapter_sql_pipe leave BashGrammar, but tools still consumes decision.adapter_argv and .sql_pipe; the Decision contract must survive."),
   O("R0","harness_lead","h4","check_actors: harness_lead and replay_actor re-exec as subprocesses and RELOCATE the tree anchor (#562). The lead author binds with defender_dir=<worktree> and requires_explicit_tree; if a grant's scope is compiled from the module-level PATHS constant rather than the threaded defender_dir, a worktree run gets grants anchored on the MAIN CHECKOUT."),
   O("R1","interacts(tool_bash->bash_exec).payload","f6","The gate parses once and the executor runs decision.pipelines. Nothing asserts that what run_parsed RECEIVES is what the gate GATED: capture the inbound argv at the seam, or a parser differential can reopen silently."),
 ],
 "holes": [
   {"rule":"R0","element":"Grant.pins_path","resolved_to":"a2","resolution":
    "The design's no-pattern-embeds-a-path invariant is FALSE for three grants whose operand IS the program (actor python script, rm path, judge ticket CLI). Human chose an explicit pins_path exemption marker over execute-extractors: python -c puts the flag in the argv slot; rm unlinks the LINK not resolve()'s target; and require-closed is a MANDATORY flag that a boolean-flag allowlist would silently make optional. The invariant becomes: no UNMARKED pattern embeds a path."},
   {"rule":"R0","element":"_corpus_author_policy","resolved_to":"b3","resolution":
    "CORPUS_AUTHOR builds AgentPolicy DIRECTLY, so compile_policy's fail-loud PROGRAMS check never fires for the one denylist-free lane; and its prompts need grep WITH a file operand, which a global OPENS_NOTHING mapping makes a fail-open. Human chose: keep cat the sole opener and PROGRAMS global; move the curator prompts to cat-into-grep and replace ls with the #574 manifest; validate EVERY policy against the table."},
   {"rule":"R0","element":"read_surface.access[read-tool]","resolved_to":"d3","resolution":
    "read_shapes and raw_reads were to be deleted with NO stated replacement on the read tool: decide_read would fall back to root-only (main could read_file any gather_raw payload) and is_untrusted_read would stop salt-tagging the attacker-influenced channel. Human chose a broad-minus-carve-out read scope (the run subtree minus gather_raw, plus the tight machine-generated gather_raw shape), with is_untrusted_read keyed on the SHAPE rather than the substring."},
   {"rule":"R0","element":"GATHER_RAW_SHAPE","resolved_to":"d5","resolution":
    "The design's path shapes were factually WRONG: the real layout carries a lead-id directory level the design omitted, plus a sibling leads-table file; and alert.json and the queries table were missing entirely, while main's write_allow is already the WHOLE run subtree, so a four-shape read enumeration was both a narrowing and incoherent with writes. Re-grounded against record_query.py."},
   {"rule":"R0","element":"Route","resolved_to":"f2","resolution":
    "Route was specified as a per-Grant field, but the adapter-sql capture is a TWO-stage relation while a Grant matches ONE stage; adapters are not in bash_allow today (they route structurally after the reader lane declines, an ordering an existing test pins) and produce two SPECIFIC deny reasons the e2e deny-tail asserts as substrings, which a positive-enumeration list cannot produce. Human chose: adapter classification stays structural; Grant.route tags reader-lane grants only."},
 ],
 "pre_discharged": [
   {"rule":"R4","element":"_cat_input_files.domain","by":"b4"},
   {"rule":"R5","element":"read_shapes","by":"d4"},
 ],
}

handoff = {
 "forks": [
  "F0 Decision's shape: does BashDecision keep adapter_argv and sql_pipe, or switch purely to route? RESOLVED: keep them as the route's payload, because tools consumes them and feeds the circuit breaker. Grant.route tags reader-lane grants only. (demand f1)",
  "F1 the RAW_MARKER substring scan: dropping it is a SECOND behavior change the issue's parity criterion did not name. VERIFIED against HEAD: main's cat-report-piped-into-grep-gather_raw DENIES today purely because the command string contains the literal text; under positive enumeration it ALLOWS. RESOLVED: intended, it is the point of positive enumeration. Pinned as an examined change (demand c5), not a regression.",
  "F2 is jq retired? The conversation said jq is effectively retired, but the resolved design keeps it as a stdin-only filter. DISSOLVED: piped jq works at HEAD for both agents, so stdin-only jq is genuinely zero-change, and the one shipped template is ALREADY in the piped form, so there is no template rewrite. (demand c4)",
  "F3 program-operand grants: RESOLVED to an explicit pins_path exemption. See gate.holes[0]. The judge's mandatory require-closed lookahead is the load-bearing case.",
  "F4 the curator lane: RESOLVED to cat-into-grep plus the #574 manifest. See gate.holes[1]. This is behavior change #4.",
  "F5 the read surface: RESOLVED to broad-minus-carve-out. See gate.holes[2].",
  "F6 adapter routing: RESOLVED to leave it structural. See gate.holes[4].",
 ],
 "deviations": [
  "The formal-slot closed-vocabulary check was done BY HAND: the #537 spec_graph linter does not exist yet.",
  "Step 4 (diff-by-address) ran COLLAPSED: the lead aligned the five derivations' stubs directly rather than spawning a separate diff agent. Two misreadings were caught and corrected in the process. An enumerator claimed a post-double-dash operand is not extracted (it is: post-double-dash tokens are appended, so believing it would have shipped a fail-open; pinned as demand b5), and another claimed a broken symlink raises OSError (it does not: resolve with strict=False returns the target, so it denies via SCOPE; pinned as a8).",
  "grep's arg-consuming flag facts (demand b7) come from gnu_flags.py plus GNU documentation, NOT from the runtime binary: the dev box ships ugrep, not GNU grep. cat, wc, head and tail WERE verified against coreutils 9.7, which matches the runtime image. Per the #579/#581 lesson, b7 must be re-validated against the RUNTIME container's grep before merge.",
 ],
 "behavior_change_ledger": [
  "1. The file-operand form of grep, head, tail, wc and jq now requires a cat-pipe prefix (demand c1).",
  "2. ls and cd are gone: main, gather, AND the curator lane (demands c2, c6).",
  "3. The RAW_MARKER substring scan is gone, so a command merely MENTIONING gather_raw is no longer denied for that reason (demand c5).",
  "4. The curator's grep-with-file becomes cat-into-grep, and its ls of the lessons dir becomes the #574 manifest (demand c6).",
 ],
}

doc = {
 "schema_version": 1,
 "design": "#575 (issue body plus its Resolved-forks addendum)",
 "base": "09e0a93cd6e43939d89182e97e5a9c567e654f7c",
 "demands": demands,
 "structure": structure,
 "gate": gate,
 "handoff": handoff,
}

out = "defender/tests/spec_graph_575-grant-gate.yaml"
with open(out, "w") as f:
    yaml.safe_dump(doc, f, sort_keys=False, width=100, allow_unicode=True)
print("wrote", out)
