# Tag-Search Probe

Validates whether a lead query template's `tags` frontmatter matches the vocabulary a reader would naturally reach for when searching for queries mid-investigation. The probe does **not** ask the subagent to reason about tagging — it observes the search terms they produce under a realistic framing, and the main agent compares those terms against the template's declared tags.

## Dispatch

Spawn **two** Haiku subagents in parallel via `Task` (`subagent_type="general-purpose"`, `model="haiku"`). Each runner gets a different investigation scenario that the edited template is supposed to serve, so the vocabulary samples are independent rather than two copies of the same prompt.

For each spawn:

1. **Pick a scenario.** Two plausible cases in which a runtime agent would need this template. Vary the entity type, phase, or pivot direction — e.g., one scenario pivoting on a source IP in GATHER, one pivoting on a username in a follow-up loop. Ground both in the lead's declared purpose; do not invent scenarios the template wasn't built for.
2. **Fabricate a memory dummy.** A short block of what the investigation agent "remembers" at that point: current hypothesis (prefixed `?`), one or two prior lead outcomes with assessments (`++/+/-/--`), and any scratch notes. Keep it tight — the goal is to mimic the shape of the investigate skill's mid-loop context, not to write a full trace.
3. **Fabricate on-the-fly context.** The alert JSON skeleton, the current investigation phase, and the open hypotheses. Match the shape the investigate skill sees at runtime.
4. **Frame the task as a search**, not as a tagging question. Use wording like *"search for queries you need for your next step"* or *"find the query templates relevant to this pivot."* **Never** write *"what tags would you pick"*, *"what tags should this template have"*, or anything that cues the subagent to reason about the tagging system. Framing is the whole point of the probe — cueing tag-reasoning contaminates the sample.
5. **Vary framing across the two spawns.** Different scenario, different wording, different pivot. Two independent draws from the reader-vocabulary distribution.

Substitute the scenario, memory dummy, and context into the subagent prompt template below before passing it to `Task`.

## Main-agent comparison (after probes return)

Collect the `search_terms` arrays from both runners and compare against the `tags` frontmatter on the edited template:

- **Overlap on at least one term per runner** → the template is discoverable from both scenarios; tags are OK.
- **One runner overlaps, the other does not** → the template is discoverable from one angle but invisible from the other. Decide whether to widen the tags or accept the narrower scope deliberately.
- **Zero overlap across both runners** → the template is invisible to the exact investigations it's meant to serve. Rework the tags before accepting the edit.

Record the comparison in self-reflection step 1 (information loss) — an undiscoverable template is a form of information loss even when the query body is intact.

---

## Subagent Prompt Template

The text below is what gets passed to each Haiku runner, once per spawn, with placeholders filled in.

> You are a security investigation agent in the middle of triaging an alert. Below is what you currently know and where you are in the investigation. Your next step requires pulling a SIEM query template from a shared registry.
>
> ## What you remember
>
> {MEMORY_DUMMY}
>
> ## Current alert and phase
>
> {CONTEXT}
>
> ## Your task
>
> {SCENARIO_FRAMING}
>
> The registry is searchable by short tag terms. List the terms you would actually type into the search — the words that come to mind when you think about the query you need right now. Do **not** reason about what tags the registry "should" have or what a tagging system would look like. Just report the terms you would use.
>
> ## Output
>
> ```yaml
> search_terms: [<term1>, <term2>, ...]
> reasoning: "<one sentence on what you are looking for, in your own words>"
> ```
>
> ## Rules
>
> - Return between 2 and 6 search terms.
> - Terms should be short — single words or two-word phrases, not full sentences.
> - Report the terms you would actually search, not the terms you think the registry uses.
> - Do not examine any files on disk. Answer from the scenario alone.
> - If the scenario is malformed or contradictory, output `{"error": "<description>"}` and stop.
