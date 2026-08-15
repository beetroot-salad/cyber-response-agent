# Environment corpus and invlang vocabulary (2026-08-12, revised 2026-08-15)

## Status

**Design + one shipped defect.** Split out of `learning-architecture-redesign.md`,
which grew an environment section longer than its training-loop subject. The two
docs have different readers and different timelines: the training loop is
unbuilt, while everything here concerns a corpus that exists today (15 facts) and
a vocabulary that is already drifting in production runs.

### The 2026-08-15 revision demoted this document, and improved it

An earlier version of this section claimed the corpus was **the grounding
substrate** for the questioner — its world knowledge and placeholder vocabulary —
and therefore on the training loop's critical path. **That claim is withdrawn.**
The training doc's §Grounding by falsification search replaces it: the questioner
declares a story, predicts the data that would falsify it, and searches for that
data, so grounding happens per story on the discriminating axis rather than
against a corpus read up front.

What that costs this document is its urgency-by-association. What it buys is a
cleaner subject, because the two halves that were fused can now separate:

- **The vocabulary defect (§The vocabulary defect, §The current schema) is
  independent and still live.** Class slot values are unvalidated and drifting.
  That blocks entity selectors as a retrieval key for the *defender*, regardless
  of what the questioner does, and it is the part of this document with a shipped
  bug behind it.
- **The interpretation-cache argument survives, aimed at one class.** §Cache
  economics already grades semantics half-life "~never" and highest value per
  entry; falsification search re-derives everything *except* that class. So the
  corpus this document should end up describing is the semantics corpus, and the
  right way to size it is to feel the cost of re-deriving rather than to design it
  in advance.
- **Referent and norm caching lose their strongest customer.** They were carrying
  the questioner. §Cache economics still argues norms are expensive and
  slow-moving, but the reader they serve is now the defender alone.

One dependency still points the other way: **the environment-defect judge bucket**
(the training doc §The discriminator spine) remains one of this corpus's
producers.

`§`-references below without qualification are to sections of this document.

## Why this corpus is different from the others

`defender/lessons/` teaches the defender how to reason. `lessons-actor/` teaches
an attacker what works. This corpus states **what is true of the deployment** —
which makes it the only corpus whose contents can be *wrong* rather than merely
unhelpful, and the only one that goes stale on its own.

## Environment memory is an interpretation cache

The valuable content is not the data, it is the **reading**.
`svc-monitoring-network-probe-cadence-baseline` stores an observation (origin
`canary-1`, ~10 nc/hour, `first_seen` three days before the window, no covering
ticket) *and* an interpretation (at that rate one more occurrence stands out
rather than blending into an absent baseline). Live baselining regenerates the
first and not the second.

The second is where the defender has demonstrably failed. In the motivating case (the
training doc §Empirical grounding) the defender had the `nc` events in hand and read
them as a
multi-stage attack chain when they were the baseline generator doing its job. The
rows were available; the reading was wrong.

So the corpus is not compensating for data the defender cannot reach. It is
compensating for **a judgment it would plausibly get wrong re-deriving under
partial information**, which implies an authoring criterion the corpus does not
have today:

> Cache an interpretation only when a competent reader looking at the same rows
> would plausibly read them differently. If the reading is obvious from the data,
> let the defender derive it — otherwise you pay staleness risk for nothing.

## The clusters

Environment questions sort into four kinds by what the fact *does* to an
investigation, plus one that does not belong:

**Referent — "what is this thing?"** Identifier → entity and its class tuple.
`jump-box-1-ip-assignment`, `container-1df4bcd65ee4-role`.

**Norm — "what is normal here?"** Distributional; needs a baseline window and a
shape-matched control. `svc-monitoring-network-probe-cadence-baseline`.

**Semantics — "what does this answer license?"** About the instrument, not the
deployment. `cmdb-indexes-by-hostname-not-ip`,
`container-uid-namespace-isolation`.

**Sanctioned path — "how is this supposed to happen?"** Normative.
`authorized-keys-host-cr-baseline`.

**Encounter-class — "what does the standard investigation for this alert look
at?"** `sshd-success-preauthentication-shell-envelope` states that the lead set
for that rule targets auth telemetry and that in-session shell activity is
outside it. That is a fact about the **defender's playbook**, not the deployment.
It sits in this corpus because the corpus's reader is the actor and it is
gray-box blind-spot knowledge. If the corpus becomes questioner grounding plus
defender world model, this class must split off.

## Cache economics decide what belongs

The axis is **cost-to-derive × staleness half-life**, not churn alone:

| Cluster | Cost to derive | Half-life | Natural key | Needed at | Verdict |
|---|---|---|---|---|---|
| Referent | one lookup | node: slow / alias: weeks | the identifier | ORIENT | **cache the node, never the alias edge** |
| Norm | baseline + control window + a judgment | months | (entity, activity) | ORIENT, ANALYZE | cache; highest value |
| Semantics | requires a *surprise* | ~never | (system, query shape) | GATHER, ANALYZE | cache; highest value per entry |
| Sanctioned path | moderate | quarters | (activity, asset class) | ANALYZE | cache |
| Encounter-class | — | per playbook edit | **alert rule** | actor-only | does not belong here |

Four things fall out:

**Only the class that does not belong keys naturally on the alert rule.** That is
an independent confirmation that `alert_rule_ids` is the wrong anchor — it is
correct for exactly the one class to be removed.

**Referent facts split, and the corpus currently caches the wrong half.** The
*node* — that a host exists, its role, what it is for — is slow-moving and worth
persisting. The *alias edge* mapping an identifier to that node is the volatile
part and is trivial to re-derive, so it should be resolved live by placeholder
binding. `container-1df4bcd65ee4-role` and `jump-box-1-ip-assignment` are the
corpus's most fragile files precisely because they cached the edge and not the
node. §The data model gives this its structural form.

**Norm facts are the expensive ones and are needed earliest.** They are what
"unusual" means, so they are load-bearing at ORIENT before the defender has done
any work.

**Reading a null safely requires two clusters at once.** Compare
`authorized-keys-host-cr-baseline` — *"a missing CR is positive evidence of
anomaly, not an absence of evidence"*, because 26 records exist and zero are for
this host (a **norm** fact) — with `cmdb-indexes-by-hostname-not-ip`, where a null
*"means 'lookup by IP is unsupported,' not 'host is absent'"* (a **semantics**
fact). Both are nulls; one is meaningful and one is an artifact of how the
question was asked. The defender cannot safely read any null without one fact
from each cluster, and misreading one is exactly what the training doc §Empirical
grounding
records.

## Staleness, verification, and its limits

**Each cached fact should carry its derivation query and the value observed at
record time.** Then staleness stops being unanswerable and becomes one call:
re-run, compare. If the observation holds the interpretation stands; if it moved,
the reading needs revisiting. `authorized-keys-host-cr-baseline` is already
almost this — "zero approved change records for this host across 26 total
records" is precisely checkable — it just does not say how to check it.

**The query is derivation metadata, not the key** (§The data model).

**The policy is per-case, not global.** Retrieval hands the defender the cached
interpretation *and* its derivation query; whether to spend a call is decided by
how much weight the fact is about to carry. invlang already has the vocabulary:
`WEIGHT_BUCKETS` with `STRONG_WEIGHTS = {++, --}`. A fact about to support a
strong move gets re-verified; one riding at `+`/`-` takes the cache.

**Invalidation is nearly free.** Any run that queries the same ground for its own
reasons is an incidental re-verification — a run that observes 40/hour against a
cached ~10/hour has contradicted the cache, and the system can notice without a
dedicated freshness pass. This is "training does the mining" read in the other
direction: the query stream that populates the cache is the stream that
invalidates it.

Two limits to hold onto:

- **Verification catches staleness, not birth defects.** An interpretation that
  was wrong when written survives re-verification looking healthy, because the
  observation still holds. That is the promotion bar's job, not the cache's.
- **The failure is asymmetric and points the wrong way.** A stale *referent*
  fails loudly — the lookup errors or resolves to nothing. A stale *norm* fails
  **silently and toward benign**: "this identity normally pulls 40k" applied after
  that job was decommissioned excuses exactly the pull that needed catching. That
  asymmetry argues for making verify-when-load-bearing mandatory for the norm
  class rather than leaving it to judgment.

## The data model

**The key is the subject, not the query.** A query carries a time window the fact
is not about, param bindings that restate the subject, adapter dialect coupling,
and no canonical form (many queries establish one fact, so it never dedupes) —
and decisively, **procedures do not compose**. You cannot traverse from one query
to another. Subjects reference each other; that is what makes the graph possible.

**Environment facts are graph-shaped, and the edge vocabulary already exists.**
`skills/invlang/vocab.py` defines 26 relations, and the source layout already
groups the standing ones:

```
"spawned", "executed", "loaded_by", "opened", "connected_to",
"read", "wrote", "created", "deleted", "modified", "listed",
"runs_on", "contained_in",                          <- standing
"authenticated_as", "authenticated_via", "initiated_by",
"triggered_by", "escalated_privilege", "assumed_role",
"granted_consent", "issued",
"member_of", "identified_as", "component_of",       <- standing
"attempted_auth", "governs",                        <- governs: standing
```

The split is not formalized — no constant, no doc — but it is there. **Event
relations are what an investigation records; standing relations are what the
environment corpus holds.** Same vocabulary, different tense: the per-case invlang
companion is the event subgraph, the environment corpus is the standing subgraph
over the same nodes.

Two immediate payoffs:

- **`identified_as` is the alias edge** — the CMDB-vs-Falco-vs-Docker problem, and
  what `jump-box-1-ip-assignment` and `container-1df4bcd65ee4-role` encode as flat
  prose today. It also refines "do not cache referents": the **node** is stable
  and worth persisting, the **alias edges** are the volatile part and should be
  resolved live. Those two files cached the edge, not the node.
- **`governs` is the sanctioned-path edge.**

**Values may be other keys, and may be multi-valued.** Norm facts are
set-valued (an identity runs on six roles) and the natural match is containment,
so single-valued forces either explosion into N facts or stringification that
loses matching.

**MV forces one field.** An observed set read as a complete set is the null-reading
trap at the schema level: "runs on these six roles" derived from observation
almost never means "and nowhere else." Every MV value needs an explicit
`observed | exhaustive` marker, or it silently asserts closure it never
established.

A skeleton, with the claim shape varying by cluster:

```yaml
subject:  compute/dev-ws-4                 # a node — the key
relation: read                             # when the fact is about an edge
object:   database/db-1                    # a value that IS another key
claim:
  kind: norm                               # referent | norm | semantics | sanctioned
  measure: {rows_per_run: 40000, cadence: nightly}
  scope: observed                          # observed | exhaustive
derivation:
  query: {...}                             # metadata, not identity
  observed_value: 41320
  observed_at: 2026-07-14
interpretation: >
  40k from this identity against this store is routine volume; the
  discriminating signal is the initiating host, not the count.
```

**Greppability is preserved, not traded away.** Keep flat markdown files, put
references in frontmatter as **typed tokens** (`compute/dev-ws-4`), and derive the
graph by resolving them. Grep still finds every mention of a node by its token;
the graph is a view, not a database. This is the same posture as lessons already
having grep and no index.

Three decisions that need making rather than defaulting:

1. **Node-keyed or edge-keyed** — probably both, by cluster: referent facts key on
   a node, norm and sanctioned-path facts on an edge.
2. **The `observed | exhaustive` marker** above.
3. **Semantics facts do not fit the entity graph, and they are the highest-value
   class.** Their subject is `(system, verb, param-shape)` — an *instrument*, not a
   deployment entity. The graph needs a second node family that is not invlang's.
      This is the real modeling strain, and the training doc §Open questions carries its
   default: two
   discriminated subject shapes in one schema (`entity/…` and `instrument/…`),
   rather than a synthetic vertex type pretending an instrument is a host.

## The current schema, and what changes

`lessons-environment/_TEMPLATE.md` today:

```yaml
subject:            # OPTIONAL — kebab referent; the fold/equivalence key
alert_rule_ids: []  # REQUIRED, non-empty — THE ANCHOR
entities:           # CONJUNCTIVE invlang {type, class} selectors
relevance_criteria: # one-line predicate the actor scans
mutable: true
status: live        # live | stale (+ superseded_by)
recorded_at:        # batch id
source_observation_ids: []
```

**What is already right:** the body convention (state the standing truth, not "do
X"), which is the mechanics-not-likelihood rule the whole corpus needs;
`mutable`/`status`/`superseded_by` as a real staleness mechanism (the gap is that
nothing *drives* the flip); and `source_observation_ids` as a provenance slot an
oracle-authored fact can populate with query/response references.

**`alert_rule_ids` is removed.** It is required and non-empty today, and a lesson
with a disjoint anchor is skipped — so the questioner, which writes before an
alert exists, has no value for the mandatory key. `cmdb-indexes-by-hostname-not-ip`
shows the damage: a universal truth about how the CMDB is indexed, keyed to two
rule ids, unretrievable for any other alert. Entity/topic selectors become the
primary key, which raises the stakes on the vocabulary defect below.

**Retrieval must gain a broadening mode.** `entities` is conjunctive AND, so it
only ever narrows; there is no "everything known about this deployment region"
query, which is exactly what grounding needs.

**The curator's retrieval check needs a second form.** It re-runs retrieval with
the source case's real prologue entities, which is genuine protection against a
selector unsatisfiable by its own birth case — but a questioner-facing fact has no
source-case prologue, so "is it retrievable" must be asked against a topic query
instead.

## The vocabulary defect that blocks this

Making entity selectors the primary key requires the type/class vocabulary to be
trustworthy. It currently is not.

**`type` is well controlled.** 16 values in `skills/invlang/vocab.py::TYPES`,
served as `defender-invlang enum types`, and **validated** —
`validate.py::_check_vocab_vertices` rejects an unknown vertex type.

**`class` slot values are not validated at all.** The grammar is documented
(`compute` = `<role>/<zone>/<provenance>`, `identity` = `<kind>/<provenance>`,
etc.) and the slot enums exist in `vocab.py` (`COMPUTE_ROLE`, `COMPUTE_ZONE`,
`COMPUTE_KIND`, …), served via `enum compute.zone`. Nothing consumes them for
checking: `validate.py` checks `type`, `relation`, `auth_kind` and `anchor_kind`,
and treats `class` purely structurally (`??` open slots, refinement-key form).

**It has already drifted.** Sampling real investigations, the distinct `compute`
tuples are `web-server/prod/known-corp`, `workstation/preprod/known-corp`,
`monitoring/internal/known-corp`, `ip-only/internet/novel`. `enum compute.zone`
is `internal | dmz | partner | regulated | internet | cloud-managed | unknown` —
so `prod` and `preprod` are off-enum.

**Two docs teach the wrong grammar.** `lessons-environment/_TEMPLATE.md` says
`compute = <role>/<zone>/<kind>`, and `lessons_env_retrieve.py`'s help gives
`web-server/internal/container` as its worked example. Slot 3 is `provenance`;
`container` is a `compute.kind` value. Both documents that teach curators how to
write selectors are wrong about the same slot.

**Why it happened: the agent never enumerates.** A complete investigation trace
(`fixtures-e2e/golden-sshpivot-ab3/tool_trace.jsonl`) shows every tool call —
read `alert.json`, read `skills/invlang/SKILL.md`, `cat` two lessons,
`defender-invlang hypothesis-vocabulary`, `defender-invlang hypothesis-shape`,
four `write_file`, four `gather`, `close_investigation`. **Zero `enum` calls.**
The skill says *"They are not preloaded into this skill — look them up when you
need a value"*, and the agent never concludes that it needs to. It did call
`hypothesis-vocabulary` and `hypothesis-shape` — purpose-built commands answering
a question it was actively holding. `enum compute.zone` requires first suspecting
that one's natural word might be wrong, which a confident agent filling a slot
will not do.

`type` survived anyway because it has two protections the class slots lack: it
appears in SKILL.md's grammar table and every worked example, *and* the validator
rejects unknown values.

**The drift is slot-specific and diagnostic.** `role` and `provenance` values are
all in-enum; `zone` values are not. `compute.zone` encodes *network topology*,
but the word "zone" reads to any practitioner as *deployment tier*. Two concepts
competing for one slot name.

That yields a general test worth adopting: **the vocabulary's sole consumer is
the agent, so naturalness is measurable.** Sample what the agent writes when it
does not enumerate and diff against the enum. Agreement means the name and the
concept agree; divergence means the slot name invites a different concept.

**The failure is silent in both directions.** `_selector_satisfied` is pure string
comparison, and the retrieval help tells its reader *"No output = nothing
matched: reason from the alert and general operations knowledge."* A vocabulary
mismatch is indistinguishable from "nothing relevant exists."

**The fixes, in order of value:**

1. **Inline the catalogs into SKILL.md.** All 21 catalogs, 211 values, are
   **2,436 characters** against SKILL.md's **24,400** — 10% of one file. The
   "don't preload, look them up" trade saves that and buys a corpus whose class
   slots are both unread and unvalidated. Put the values where the agent
   demonstrably already looks.
2. **Validate class slots, dispatched on type**, in the validator that already
   checks `type`, and run lesson selectors through the same check at author time.
   Greppability helps the agent *choose*; validation is what makes a wrong choice
   *visible*.
3. **Fix `zone`** — rename the slot to what the enum means, or widen the enum to
   what the name means.
4. **Then add corpus-derived counts** (`internal (47) prod (12) dmz (3)`) as the
   discovery surface, with the enum as the floor and a novel value as a flagged
   review item rather than a hard error. That keeps the vocabulary responsive to
   what is natural without letting drift compound silently.

Placeholder binding (the training doc §Placeholders and binding) is the third and
strongest check,
because it tests for a referent rather than for spelling.

## Producers

**Today both feeds are judge-emitted from actor directions**, and the curator
lives inside the benign-actor author package:

| Feed | Emitted by | Queue | Curator |
|---|---|---|---|
| FP direction | benign judge `environment_observations` | `_pending/environment_observations.jsonl` | `author_actor_benign.py` |
| Adversarial (#298) | malicious judge — positive facts from a refuted misprediction | `_pending/actor_environment_observations.jsonl` | `author_actor_env.py` |

Both fold into one corpus through `learning/author/benign_actor/prompt.md` ("You
are the **environment lessons curator**"), gated by a deterministic retrieval
check and committing their own batch. **Deferring the actor work therefore
orphans the corpus.**

That was an argument for urgency while the questioner depended on this corpus. It
no longer is — with the grounding-substrate role retired (§Status), an orphaned
corpus is a corpus that stops growing, not a blocked training loop. The miner
below is still the right replacement; it is no longer on anyone's critical path,
and it should be sequenced on its own merits.

**The replacement is one mechanism with two feeds.** Both the oracle and the
runtime are the same thing: a component holding a corpus of (query, response)
pairs against the real deployment. In training that is the oracle; at runtime it
is the persisted `executed_queries.jsonl` plus `gather_raw/` payloads, which
already exist per run. One offline miner over that corpus, two inputs.

This reopens what the original draft closed off. It ruled that a training
reviewer only sees synthetic worlds, so an environment fact authored there
describes an invented deployment. With interception, every gather query returns
real data outside the overlay — so a fact is sound as long as its supporting rows
were not patched, and **the applier knows exactly which rows it touched**. Row-level
provenance makes that a mechanical check.

**A fourth judge bucket is an environment fact.** When `ΔT` diverges, is not
explained by the mutation, and is not a reasoning error, the deployment misled the
defender. Add **environment defect** alongside lead-set gap / lead quality /
analyze discipline / decision discipline. The CMDB case in the training doc §Empirical
grounding is
exactly this and needed no adversary to find — a comparison found it.

**Two things this cannot produce**, both of which must come from the runtime feed:
observability facts (rule coverage bounds them — the training doc §What dies), and
semantics facts that only
surface mid-investigation rather than at bind time.

## Retrieval — frontier keying

Two consequences, both load-bearing and both independent of the training loop.

**Retrieval must run per gather loop, not once at PLAN.** A lesson about what a
field does and does not license is only relevant once the field is in hand. In
the motivating case (the training doc §Empirical grounding) the process class was still
`??` when lessons loaded, so no
keying scheme could have surfaced the applicable lesson at that moment.

**Match by containment, not by similarity score.** The frontier has structure —
typed slots with `??`, plus the open hypothesis set — so a lesson declares the
pattern it applies to and matching is mechanical, fewer slots matching more. This
is assembly, not construction: the invlang advisory verb already does
frontier-keyed recall, and the environment corpus already matches by slot-wise
selector containment.

Three gaps close it. The advisory recalls precedent *cases*; lessons need
selectors and become a recall class. Its frontier is hypothesis names only —
`??` slots are out of scope today, and the motivating case's frontier item is
exactly slot-shaped. And the frontier is model-supplied at the prompt;
per-gather-loop retrieval derives it mechanically from the investigation file.
One guard: selectors need a specificity floor — fewer-slots-matching-more makes
an empty selector an every-loop lesson.

**The schema defect this fixes** is the same one §The current schema removes
`alert_rule_ids` for: a lesson's trigger condition is tied to the alert it was
born from, which is right for coverage lessons and wrong for observable-semantics
lessons, whose trigger has nothing to do with which rule fired.

**Correction: the two corpora are broken in opposite directions.** An earlier
draft said flatly that "lessons key on the alert signature they were born from."
That is true of the *environment* corpus, which hard-gates on rule-id disjointness
(`lessons_env_retrieve.py:104`) — a mandatory anchor the questioner cannot even
populate, which is what §The current schema removes it for. It is **not** true of
`defender/lessons/`: `scripts/lessons/lessons_fm.py` greps frontmatter across
`DIMENSIONS = ("source_signature", "telemetry_source", "attack_phase")` with
**model-supplied patterns**, so nothing gates anything — what retrieves is
whatever the model chose to grep for.

The training doc §It is not one case records both failure modes in the same run
corpus. A lesson born on `v2-falco-suspicious-network-tool` reached an
`authorized_keys` case because they share `telemetry_source: falco` and did real
damage there; the loginuid lesson missed its own motivating case because the
model's pattern did not match it. So the defender corpus is not over-keyed but
**under-determined**, and frontier keying is the fix for a genuine gap rather than
a replacement for a gate that exists. Only one of these two corpora has a gate to
remove.

## Sequencing

None of this waits on the training loop, and the first three items are small
enough to do in an afternoon each. Ordered by what unblocks what:

1. **Inline the enum catalogs into `skills/invlang/SKILL.md`** (§The vocabulary
   defect). 211 values, 2,436 characters, against a file already 24,400 — and the
   agent demonstrably reads that file and demonstrably never calls `enum`.
2. **Validate class slots, dispatched on type**, in the validator that already
   checks `type`; run lesson selectors through the same check at author time.
   Until this lands, every downstream item is keyed on an unenforced convention.
3. **Resolve `zone`** — rename the slot to what the enum means, or widen the enum
   to what the name means. `prod`/`preprod` are the forcing case.
4. **Schema change** (§The current schema): drop `alert_rule_ids` as the required
   anchor, promote entity/topic selectors to primary, add the broadening query
   mode, add `derivation` and the `observed | exhaustive` marker.
5. **The miner** (§Producers) — one pass over the (query, response) corpus,
   runtime feed first. An earlier draft called this "the item the training loop is
   actually waiting on"; it is not, since §Status. It earns its place here on its
   own terms: the current producer is being deferred, and without a replacement
   the corpus stops growing.
6. **Frontier retrieval** (§Retrieval) — give the invlang advisory a lessons
   recall class, extend its frontier from open hypotheses to `??` slots, derive
   the frontier mechanically per gather loop.
7. **Corpus-derived vocabulary counts** as the discovery surface, with the enum as
   the floor and a novel value as a flagged review item.

**A migration question sits across items 3 and 4** and has no answer yet: the 15
existing facts were authored under the old schema and the drifted vocabulary. Are
they re-derived, grandfathered, or re-keyed only? Re-keying is cheapest and leaves
the interpretations unaudited, which §Staleness argues is the half that
verification cannot check anyway.

**And the training doc raises the stakes on that answer.** Its §It is not one case
found a *defender* lesson that is actively harmful — it survives its own
forward-check, retrieves across signatures, and causes the defender to report
attack chains that did not happen. It was found by hand. Nothing in either corpus's
authoring path would have caught it, and §Staleness explains why: verification
catches staleness, not birth defects. So the migration question is not only "which
entries are stale" but "which are **wrong**," and re-keying answers neither.
