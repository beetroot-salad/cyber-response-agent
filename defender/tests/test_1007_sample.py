"""#1007 — M4: the questioner's own sample, the per-world judge prompt, and the evidence scope.

`samples.yaml` moves the reference document the questioner was shown into the episode archive
so it survives a vanished source run, and the per-world judge is shown that sample plus the
world's reachability block. S7 widens the evidence-pointer resolver for `subject: world`
findings only.

TWO RECORDED DECISIONS SHAPE WHAT IS AND IS NOT ASSERTED HERE:

* **H2 — wrapper yes, filter no.** The `sample` and `review` sections carry the same run-salted
  untrusted frame the existing capture sections carry. `redaction.redact_model_visible` is
  deliberately NOT applied. NO TEST HERE ASSERTS THE `wv-<world>-<stem>` NAMING SCHEME IS
  PROTECTED ON THIS PATH — `review.py`'s already-shipped `envelope_failed = str(fault)` carries
  an adapter fault's detail verbatim into `review.yaml`, which M4 renders into this prompt, and
  the human declined the filter knowingly (accepted gap G-1). The frame stops the text being
  read as instruction; it does not remove the names.
* **H3 / RS-1 — O5 holds WITHIN ONE ATTEMPT.** A re-entered `Step.QUESTIONER` overwrites
  `samples.yaml`, so the byte-identity obligation is scoped to a single attempt, and the
  accepted re-entry behaviour (the second attempt's samples win) is pinned by its own test —
  because a byte-identity test that never exercises a re-entry would pass while the obligation
  is false.

RED AGAINST HEAD is the expected state.
"""
from __future__ import annotations

import json
from pathlib import Path


from defender.tests import _world_1007 as W


def rendered_episode(tmp_path: Path, monkeypatch, *, labels=("b",), samples=None,
                     reachability=None, worlds=None) -> Path:
    _base, _src, root = W.configured_layout(tmp_path, monkeypatch)
    docs = worlds if worlds is not None else [W.base_world()] + [
        W.world_doc(x, ov=W.overlay(elastic=W.elastic_overlay(inject=[{"_id": f"i{x}"}])))
        for x in labels]
    ep = W.episode(tmp_path, doc=W.family_doc(worlds=docs), root=root)
    for label in labels:
        W.archived_world(ep, label)
        W.write_served(ep, label, [W.served_row(world=label)])
    W.write_review(ep, worlds={
        label: W.reviewed_world(
            label=label,
            reachability=reachability if reachability is not None else W.reachability_block(
                capture_replays=[W.replay_entry("k1", differs=True)]))
        for label in labels})
    if samples is not False:
        W.write_samples(ep, samples)
    return ep


def render_prompt(ep: Path, label: str = "b") -> str:
    """The per-world judge's whole prompt, through the real render + prompt builder."""
    render = W.mod("learning.judge.render")
    run = W.mod("learning.judge.run")
    return run._build_prompt(render.render(ep, label))


# ---------------------------------------------------------------------------------------
# M4 — samples.yaml
# ---------------------------------------------------------------------------------------


def test_the_launcher_writes_samples_yaml_at_step_2(tmp_path, monkeypatch):
    """The launcher writes `samples.yaml` at `Step.QUESTIONER`, holding exactly what the
    questioner was handed.

    Observably true: driving the questioner step with a corpus-sample mapping leaves
    `<episode>/samples.yaml` on disk carrying that mapping, keyed by staged pattern. It lives
    in the EPISODE archive, not in the source run, so it survives a source run that is later
    pruned — which is the whole reason O5's claim is checkable at grading time at all.

    What failure looks like: the samples stay in the source run (or in memory), and the judge
    at grading time has nothing to compare a shape-invention claim against.
    """
    cli = W.mod("learning.branch.cli")
    _base, src, root = W.configured_layout(tmp_path, monkeypatch)
    ep = W.episode(tmp_path, root=root)
    samples = W.samples_document()

    cli.write_questioner_samples(ep, samples)

    assert (ep / W.SAMPLES_NAME).is_file(), (
        "`Step.QUESTIONER` wrote no samples.yaml into the episode")
    assert W.read_yaml(ep / W.SAMPLES_NAME) == samples
    assert not (src / W.SAMPLES_NAME).exists(), (
        "the samples were written into the SOURCE run, which a later prune removes")


def test_the_judges_sample_is_byte_identical_to_the_questioners_within_one_attempt(
        tmp_path, monkeypatch):
    """WITHIN ONE ATTEMPT, the judge is shown the same real document per staged pattern that the
    questioner was shown.

    Observably true: the document rendered into the per-world prompt's sample section is
    byte-equal — after one canonical dump on both sides — to the value stored under that
    pattern in `samples.yaml`. That is what makes a `shape-invention` claim decidable: the
    judge and the author saw the same bytes.

    SCOPED, and the scope is the point (RS-1): on a re-entered episode the second attempt's
    samples win, so the judge may be shown attempt N's samples for a world authored in attempt
    N-1 — accepted gap G-2, pinned by
    `test_a_second_attempts_step_2_overwrites_the_first_attempts_samples`.

    What failure looks like: the judge is shown a re-derived or re-formatted sample. Any claim
    the judge makes about a shape the author invented is then made against a document the
    author never saw.
    """
    ep = rendered_episode(tmp_path, monkeypatch)
    stored = W.read_yaml(ep / W.SAMPLES_NAME)[W.EVENTS_PATTERN]

    prompt = render_prompt(ep)

    canonical = json.dumps(stored, sort_keys=True)
    rendered = [json.dumps(json.loads(chunk), sort_keys=True)
                for chunk in _json_objects(prompt)]
    assert canonical in rendered, (
        "the sample rendered into the judge's prompt is not the document samples.yaml holds "
        f"for {W.EVENTS_PATTERN!r}")


def _json_objects(text: str) -> list[str]:
    """Every balanced `{...}` run in `text`, so a rendered document can be compared as JSON
    rather than by substring — a substring test would pass on a prefix."""
    out, depth, start = [], 0, None
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                chunk = text[start:i + 1]
                try:
                    json.loads(chunk)
                except ValueError:
                    pass
                else:
                    out.append(chunk)
    return out


def test_a_missing_sample_sets_sample_unavailable_and_refuses_shape_invention(
        tmp_path, monkeypatch):
    """No sample for a staged pattern means the judge cannot claim the author invented a shape.

    Observably true: with `samples.yaml` holding no entry for the world's staged pattern, the
    world's row reads `sample_unavailable: true` and a `shape-invention` finding for that world
    is refused. The refusal is re-anchored on the EVIDENCE (A1(b)), not on the bucket literal —
    see `test_a_finding_citing_an_unavailable_sample_is_refused_whatever_its_bucket`, because
    an open vocabulary lets a model rename around any single string.

    What failure looks like: the judge grades shape invention against a sample nobody has, and
    the questioner corpus learns that authors invent shapes whenever the sampler was empty.
    """
    judge_mod = W.mod("learning.judge")
    ep = rendered_episode(tmp_path, monkeypatch,
                          samples={W.ALERTS_PATTERN: dict(W.SAMPLE_DOCUMENT)})
    judge = W.FakeJudge(W.reply_document(findings=[W.world_finding(bucket="shape-invention")]))

    result = judge_mod.grade_episode(ep, judge=judge)

    row = {r["world"]: r for r in result.worlds}["b"]
    assert row["sample_unavailable"] is True, (
        f"sample_unavailable is {row.get('sample_unavailable')!r} with no sample for the "
        "world's staged pattern")
    assert [f["bucket"] for f in row["world_findings"]] == [], (
        f"a shape-invention finding stood without a sample: {row['world_findings']}")


def test_a_present_sample_admits_a_shape_invention_finding(tmp_path, monkeypatch):
    """The positive control: WITH a sample, the same finding stands.

    Observably true: an episode identical to the one above except that `samples.yaml` carries
    the world's staged pattern grades `sample_unavailable: false` and keeps the
    `shape-invention` finding. Without this, the refusal above would read as correct on a pass
    that emits no findings at all.

    What failure looks like: the refusal is written too wide and every world finding citing a
    sample is dropped, so the mechanism reads as working while producing nothing.
    """
    judge_mod = W.mod("learning.judge")
    ep = rendered_episode(tmp_path, monkeypatch)
    judge = W.FakeJudge(W.reply_document(findings=[W.world_finding(bucket="shape-invention")]))

    result = judge_mod.grade_episode(ep, judge=judge)

    row = {r["world"]: r for r in result.worlds}["b"]
    assert row["sample_unavailable"] is False
    assert "shape-invention" in [f["bucket"] for f in row["world_findings"]], (
        f"a sample WAS available and the finding was still dropped: {row['world_findings']}")


def test_a_corrupt_or_absent_samples_file_sets_sample_unavailable_for_every_pattern(
        tmp_path, monkeypatch):
    """A corrupt, absent or null-valued samples file is `sample_unavailable` for EVERY pattern —
    never a partial read and never a refusal that ends the pass.

    Observably true: three shapes — no file, unparseable YAML, and a file whose pattern maps to
    null — each grade with `sample_unavailable: true` and a completed `judge.yaml`. The episode
    dir is a tree a box can write, so all three are shapes to meet rather than impossibilities.

    What failure looks like: `yaml.safe_load` raises out of the grading pass, and one damaged
    file costs every world of the episode its grade after every model call has been paid for.
    """
    judge_mod = W.mod("learning.judge")
    for label, prepare in (
            ("absent", lambda ep: (ep / W.SAMPLES_NAME).unlink()),
            ("corrupt", lambda ep: (ep / W.SAMPLES_NAME).write_text(
                "samples: [unclosed\n", encoding="utf-8")),
            ("null", lambda ep: W.write_yaml(ep / W.SAMPLES_NAME,
                                             {W.EVENTS_PATTERN: None})),
    ):
        ep = rendered_episode(tmp_path / label, monkeypatch)
        prepare(ep)

        result = judge_mod.grade_episode(ep, judge=W.FakeJudge(W.reply_document()))

        row = {r["world"]: r for r in result.worlds}["b"]
        assert row["sample_unavailable"] is True, (
            f"the {label} samples file graded as sample_unavailable="
            f"{row.get('sample_unavailable')!r}")
        assert (ep / W.JUDGE_NAME).is_file(), (
            f"the {label} samples file took the whole pass down")


def test_the_writer_pins_one_document_per_pattern_rather_than_relying_on_last_key_wins(
        tmp_path, monkeypatch):
    """The writer pins ONE document per pattern; it does not hand a duplicate-keyed mapping to
    YAML and let last-key-wins decide.

    Observably true: writing samples from a source that offers two documents for one pattern
    refuses, or records exactly one deliberately-chosen document — and the file that lands
    parses to one key with one value. `samples.yaml` is `unique-key` on `(episode, pattern)`,
    and last-key-wins is a decision taken by a serializer rather than by this design.

    What failure looks like: the sampler walks a table and writes as it goes. Which document
    the questioner and the judge both see then depends on `executed_queries.jsonl` ordering,
    and the byte-identity obligation is satisfied against an arbitrary pick.
    """
    cli = W.mod("learning.branch.cli")
    _base, _src, root = W.configured_layout(tmp_path, monkeypatch)
    ep = W.episode(tmp_path, root=root)
    first = {"host": {"name": "web-1"}}
    second = {"host": {"name": "web-2"}}

    try:
        cli.write_questioner_samples(ep, [(W.EVENTS_PATTERN, first),
                                          (W.EVENTS_PATTERN, second)])
    except W.refusals():
        return                       # a refusal is an equally good answer: one document or none
    doc = W.read_yaml(ep / W.SAMPLES_NAME)
    assert list(doc) == [W.EVENTS_PATTERN], f"the file carries {list(doc)}"
    assert doc[W.EVENTS_PATTERN] in (first, second)
    raw = (ep / W.SAMPLES_NAME).read_text(encoding="utf-8")
    assert raw.count(W.EVENTS_PATTERN) == 1, (
        "the pattern was written twice and a YAML load is deciding which one wins")


def test_a_case_differing_overlay_pattern_misses_the_sample_and_refuses_the_finding(
        tmp_path, monkeypatch):
    """A pattern is matched EXACTLY. `LOGS-*` does not find the sample stored under `logs-*`.

    Observably true: a world whose overlay keys a case-differing spelling of the sampled
    pattern grades `sample_unavailable: true` and its sample-citing finding is refused. Index
    patterns are not case-folded anywhere else in this system, and a fuzzy match here would
    hand the judge a document from a corpus the world never staged.

    What failure looks like: a `casefold()` at the lookup. A world staging a differently-cased
    pattern is graded against another corpus's document, and the shape-invention claim is made
    against evidence from somewhere else entirely.
    """
    judge_mod = W.mod("learning.judge")
    ep = rendered_episode(
        tmp_path, monkeypatch,
        worlds=[W.base_world(), W.world_doc("b", ov=W.overlay(
            elastic=W.elastic_overlay(pattern=W.EVENTS_PATTERN.upper(),
                                      inject=[{"_id": "i1"}])))])
    judge = W.FakeJudge(W.reply_document(findings=[W.world_finding(
        bucket="shape-invention", pattern=W.EVENTS_PATTERN.upper(),
        evidence=[f"samples.yaml#{W.EVENTS_PATTERN.upper()}"])]))

    result = judge_mod.grade_episode(ep, judge=judge)

    row = {r["world"]: r for r in result.worlds}["b"]
    assert row["sample_unavailable"] is True, (
        "a case-differing pattern found the sample — the lookup is folding case")
    assert [f["bucket"] for f in row["world_findings"]] == []


def test_a_finding_citing_an_unavailable_sample_is_refused_whatever_its_bucket(
        tmp_path, monkeypatch):
    """The sample-dependent refusal binds to the EVIDENCE, not to a bucket literal.

    Observably true: when a world's row carries `sample_unavailable`, ANY `subject: world`
    finding for that world citing `samples.yaml#<pattern>` is refused — whether its bucket is
    `shape-invention`, an unlisted string, or anything else. A finding for that world citing
    something ELSE stands, which is the control.

    This is A1(b): the open vocabulary (G-3) means a refusal keyed on the string
    `shape-invention` is evadable by renaming, so the refusal is anchored where renaming cannot
    reach it.

    What failure looks like: the refusal reads `if finding.bucket == "shape-invention"`. A
    model that spells the same claim `made-up-field-names` walks straight past it.
    """
    judge_mod = W.mod("learning.judge")
    ep = rendered_episode(tmp_path, monkeypatch,
                          samples={W.ALERTS_PATTERN: dict(W.SAMPLE_DOCUMENT)})
    judge = W.FakeJudge(W.reply_document(findings=[
        W.world_finding(bucket="a-bucket-nobody-listed",
                        evidence=[f"{W.SAMPLES_NAME}#{W.EVENTS_PATTERN}"]),
        W.world_finding(bucket="another-unlisted-bucket", evidence=["review.yaml#worlds"]),
    ]))

    result = judge_mod.grade_episode(ep, judge=judge)

    buckets = [f["bucket"] for f in {r["world"]: r for r in result.worlds}["b"]["world_findings"]]
    assert "a-bucket-nobody-listed" not in buckets, (
        "a finding citing an unavailable sample stood because its bucket was not the literal "
        "the refusal was written against")
    assert "another-unlisted-bucket" in buckets, (
        f"the control failed — a finding citing something else was dropped too: {buckets}")


def test_a_two_pattern_world_names_each_patterns_sample_availability_independently(
        tmp_path, monkeypatch):
    """A world staging TWO elastic patterns is graded — and rendered — per pattern, never
    reduced to one (O5's own falsifier).

    Observably true: with a sample captured for one staged pattern and none for the other,
    `sample_unavailable_patterns` names exactly the missing one (not both, and not neither);
    the per-world prompt carries a real document for the pattern that WAS sampled and an
    explicit "no sample was captured" sentence for the one that was not; and a finding citing
    the AVAILABLE pattern survives while one citing the UNAVAILABLE pattern is refused — in the
    SAME grading pass, over the SAME world.

    What failure looks like: `_world_pattern`'s single-value reduction (the first staged
    pattern alone) makes `sample_unavailable` read `false` because SOME pattern had a sample,
    while the judge is rendered nothing for the pattern it was never shown — a
    `shape-invention` claim then gets made, or refused, against the wrong pattern's evidence.
    """
    judge_mod = W.mod("learning.judge")
    ep = rendered_episode(
        tmp_path, monkeypatch,
        worlds=[W.base_world(), W.world_doc("b", ov=W.overlay(elastic={
            **W.elastic_overlay(W.EVENTS_PATTERN, inject=[{"_id": "i1"}]),
            **W.elastic_overlay(W.ALERTS_PATTERN, inject=[{"_id": "i2"}]),
        }))],
        samples={W.EVENTS_PATTERN: dict(W.SAMPLE_DOCUMENT)})
    judge = W.FakeJudge(W.reply_document(findings=[
        W.world_finding(bucket="cites-the-available-pattern",
                        evidence=[f"{W.SAMPLES_NAME}#{W.EVENTS_PATTERN}"]),
        W.world_finding(bucket="cites-the-unavailable-pattern",
                        evidence=[f"{W.SAMPLES_NAME}#{W.ALERTS_PATTERN}"]),
    ]))

    result = judge_mod.grade_episode(ep, judge=judge)
    prompt = render_prompt(ep)

    row = {r["world"]: r for r in result.worlds}["b"]
    assert row["sample_unavailable_patterns"] == [W.ALERTS_PATTERN], (
        f"expected exactly {W.ALERTS_PATTERN!r} unavailable, got "
        f"{row.get('sample_unavailable_patterns')!r}")
    assert row["sample_unavailable"] is True, (
        "the aggregate bool should still read true — SOME staged pattern lacked a sample")

    buckets = [f["bucket"] for f in row["world_findings"]]
    assert "cites-the-available-pattern" in buckets, (
        "a finding citing the pattern that WAS sampled was refused for a gap in the other one")
    assert "cites-the-unavailable-pattern" not in buckets, (
        "a finding citing the pattern that was NOT sampled stood")

    canonical = json.dumps(dict(W.SAMPLE_DOCUMENT), sort_keys=True)
    rendered = [json.dumps(json.loads(chunk), sort_keys=True)
               for chunk in _json_objects(prompt)]
    assert canonical in rendered, (
        "the judge's prompt carries no rendering of the pattern that WAS sampled")
    assert f"no sample was captured for {W.ALERTS_PATTERN!r}" in prompt, (
        "the judge's prompt says nothing about the second staged pattern at all — reduced to "
        "the first, O5's own falsifier")


# ---------------------------------------------------------------------------------------
# M4 — the per-world prompt
# ---------------------------------------------------------------------------------------


def test_the_per_world_prompt_carries_that_worlds_reachability_block(tmp_path, monkeypatch):
    """The per-world prompt carries THAT world's reachability block — not the episode's, and
    not a sibling's.

    Observably true: rendering world b's prompt in a two-world episode where the blocks differ
    puts b's own `reachable_by_capture` value in the prompt and c's nowhere in it.

    What failure looks like: the whole `review.yaml` is rendered into every world's prompt. The
    judge then grades world b while reading world c's measurements, and — separately — every
    per-world prompt carries every sibling's overlay, which S6 forbids.
    """
    ep = rendered_episode(tmp_path, monkeypatch, labels=("b", "c"))
    doc = W.read_yaml(ep / W.REVIEW_NAME)
    doc["worlds"]["b"]["reachability"]["capture_replays"] = [
        W.replay_entry("b-own-replay-key-marker", differs=True)]
    doc["worlds"]["c"]["reachability"]["capture_replays"] = [
        W.replay_entry("c-sibling-replay-key-marker", differs=False)]
    W.write_yaml(ep / W.REVIEW_NAME, doc)

    prompt = render_prompt(ep, "b")

    assert "b-own-replay-key-marker" in prompt, (
        "world b's prompt carries none of its own reachability measurements — the review "
        "section is not rendered at all")
    assert "c-sibling-replay-key-marker" not in prompt, (
        "world b's prompt carries a sibling's reachability measurements")


def test_the_per_world_prompt_holds_no_siblings_overlay(tmp_path, monkeypatch):
    """No sibling's overlay reaches a world's prompt — nor its wire log.

    Observably true: world b's rendered prompt contains no value that appears only in world c's
    overlay, and the trace written for b's draw contains none either. The prompt is the model's
    whole input, and the wire log is the verbatim copy of it, so a leak the prompt assertion
    catches and the trace assertion does not is a leak that still shipped.

    What failure looks like: the manifest is rendered whole "for context". Every world's judge
    is then told exactly how its siblings differ, which is the one thing a per-world grade must
    not know.
    """
    marker = "sibling-only-marker-value"
    ep = rendered_episode(
        tmp_path, monkeypatch, labels=("b", "c"),
        worlds=[W.base_world(),
                W.world_doc("b", ov=W.overlay(elastic=W.elastic_overlay(inject=[{"_id": "ib"}]))),
                W.world_doc("c", story=marker, ov=W.overlay(
                    patches={"elastic": {"canary-1": {"owner": marker}}}))])

    prompt = render_prompt(ep, "b")

    # THE POSITIVE CONTROL: the GRADED world's own overlay does reach its prompt. Without it
    # this negative is satisfied by a prompt that renders no overlay at all.
    assert "ib" in prompt, (
        "world b's own overlay does not reach its prompt, so the absence asserted below is a "
        "fact about an unrendered section rather than about sibling containment")
    assert marker not in prompt, (
        "a sibling's overlay value reached world b's prompt — the manifest is rendered whole")


def test_the_world_buckets_reach_the_prompt_as_examples_not_as_an_enum(tmp_path, monkeypatch):
    """The four world bucket names reach the prompt as EXAMPLES, phrased so a reader can tell
    they do not close the set.

    Observably true: each of the four names appears in the rendered prompt, and the prompt does
    NOT tell the model the list is exhaustive — no "one of", "must be one of", "only these" or
    "choose from" governs them. The vocabulary is open by human decision (R2), and a prompt
    that says otherwise closes it in the only place that matters for what the model writes.

    What failure looks like: the names are rendered as an enum. The drift the human wanted to
    observe for a few live episodes never happens, and the decision to keep the set open is
    silently reversed in prose.
    """
    ep = rendered_episode(tmp_path, monkeypatch)

    prompt = render_prompt(ep)

    for name in W.EXAMPLE_WORLD_BUCKETS:
        assert name in prompt, f"the example bucket {name!r} does not reach the prompt"
    lowered = prompt.lower()
    window = lowered[max(0, lowered.find("unreachable-difference") - 400):
                     lowered.find("unreachable-difference") + 400]
    for closing in ("must be one of", "one of the following", "only these", "choose from"):
        assert closing not in window, (
            f"the prompt presents the world buckets as a closed set ({closing!r}) — R2 opened "
            "them deliberately")


def test_validate_reply_admits_an_unlisted_world_bucket(tmp_path):
    """An unlisted world bucket is ADMITTED — this is the positive form of the open vocabulary.

    Observably true: a `subject: world` finding whose bucket is a string no list anywhere
    contains validates cleanly and keeps its string. The consequence is accepted knowingly
    (G-3): a drifting bucket reaches the record and the questioner corpus with nothing refusing
    it.

    What failure looks like: a `WORLD_FINDING_TYPES` enum appears "for symmetry". The human
    declined it because these four names are invented and have never fired, and wants live
    episodes to show what the judge actually wants to say before the set closes.
    """
    run = W.mod("learning.judge.run")

    parsed = run.validate_reply(W.reply_text(findings=[
        W.world_finding(bucket="the-story-explains-a-field-the-corpus-lacks")]))

    assert parsed.findings[0].bucket == "the-story-explains-a-field-the-corpus-lacks"
    cfg = W.mod("learning.core.config")
    assert not hasattr(cfg, "WORLD_FINDING_TYPES"), (
        "a WORLD_FINDING_TYPES enum was introduced; R2 kept the world side open this round")


def test_every_attacker_influenced_section_of_the_judge_prompt_carries_the_run_salted_frame(
        tmp_path, monkeypatch):
    """The `sample` and `review` sections carry the SAME run-salted untrusted frame the capture
    sections already carry — parity per cell, at this sink.

    Observably true: the sample document's own text and the review section's own text each
    appear INSIDE a closed `<run-{salt}-untrusted>` frame and nowhere outside one — the same
    two-sided assertion the existing capture sections are held to. Both are attacker-influenced
    by definition: the sample is a document out of the monitored estate and the review block is
    derived from live reads of it.

    THIS IS THE WRAPPER ONLY. `redaction.redact_model_visible` is NOT applied here, by human
    decision, and this test deliberately does not imply otherwise (accepted gap G-1): the frame
    stops the text being read as instruction, and does not remove the `wv-<world>-<stem>` names
    that `review.py`'s already-shipped `envelope_failed` carries verbatim into this prompt.

    What failure looks like: the new sections are spliced in as host text, and a document out
    of the corpus is presented to the judge as part of its own instructions.
    """
    marker_sample = {"host": {"name": "a-sample-marker-host"}}
    marker_fault = "an-envelope-fault-marker"
    ep = rendered_episode(
        tmp_path, monkeypatch,
        samples={W.EVENTS_PATTERN: marker_sample},
        reachability=W.reachability_block(envelope_failed=marker_fault,
                                          capture_replays=[W.replay_entry("k1")]))

    prompt = render_prompt(ep)

    W.assert_wrapped_untrusted(prompt, "a-sample-marker-host", "the questioner's sample")
    W.assert_wrapped_untrusted(prompt, marker_fault, "the review section's fault text")


# ---------------------------------------------------------------------------------------
# S7 — the evidence resolver, widened for one subject only
# ---------------------------------------------------------------------------------------


def test_a_world_findings_evidence_pointer_admits_exactly_three_episode_files(
        tmp_path, monkeypatch):
    """A `subject: world` finding may cite exactly three episode-level files, and nothing else
    at the episode level.

    Observably true: `samples.yaml`, `review.yaml` and `judge.yaml` resolve for a world-subject
    pointer, while a fourth episode-level file — `family.yaml`, `staged.yaml`, anything under
    `served/` — does not. The world's own subtree stays reachable exactly as before.

    What failure looks like: the widen is written as "the episode dir", and a world finding can
    cite a sibling's whole archive — which is precisely the containment J13(a) was written to
    hold and S7 widens only three files' worth.
    """
    run = W.mod("learning.judge.run")
    ep = rendered_episode(tmp_path, monkeypatch)
    W.write_yaml(ep / "staged.yaml", [{"name": "wv-x"}])
    world_dir = ep / "worlds" / "b"

    for allowed in W.WORLD_EVIDENCE_FILES:
        assert run._resolves(allowed, world_dir, subject=W.SUBJECT_WORLD), (
            f"{allowed} does not resolve for a world-subject finding")
    for refused in ("family.yaml", "staged.yaml", "served/base.jsonl", "worlds/a/report.md"):
        assert not run._resolves(refused, world_dir, subject=W.SUBJECT_WORLD), (
            f"{refused} resolved for a world-subject finding — the widen is not three files "
            "wide, it is the whole episode")
    assert run._resolves("report.md", world_dir, subject=W.SUBJECT_WORLD), (
        "the world's own subtree stopped resolving")


def test_a_defender_findings_evidence_pointer_stays_world_dir_only(tmp_path, monkeypatch):
    """The DEFENDER arm is unchanged: world-subtree-only, all three episode files refused.

    Observably true: the same three pointers that resolve for a world-subject finding are
    refused for a defender-subject one, while the world's own `report.md` still resolves. The
    widen is per subject; a widen applied to both is a widen of J13(a)'s deliberate guard for
    the lane that never asked for it.

    What failure looks like: the allowlist is added to `_resolves` unconditionally. Every
    defender finding can then cite the episode's own judge record, and the curator authors
    lessons whose evidence is the grade itself.
    """
    run = W.mod("learning.judge.run")
    ep = rendered_episode(tmp_path, monkeypatch)
    world_dir = ep / "worlds" / "b"

    for widened in W.WORLD_EVIDENCE_FILES:
        assert not run._resolves(widened, world_dir, subject=W.SUBJECT_DEFENDER), (
            f"{widened} resolved for a DEFENDER finding — the widen crossed the subject line")
    assert run._resolves("report.md", world_dir, subject=W.SUBJECT_DEFENDER), (
        "the control failed — the defender arm stopped resolving its own subtree")


def test_traversal_syntax_is_refused_on_every_widened_episode_level_pointer(
        tmp_path, monkeypatch):
    """Traversal is refused on every widened pointer — the allowlist is names, not prefixes.

    Observably true: `../samples.yaml`, `worlds/../../samples.yaml`, an absolute
    `/etc/passwd`, and a symlink planted at `samples.yaml` pointing outside the episode are all
    refused for a world-subject finding. The three names are an ALLOWLIST of resolved targets,
    not a string test a pointer can be dressed up to pass.

    What failure looks like: `pointer.endswith("samples.yaml")`. A model-authored pointer then
    reads any file on the host whose name ends the same way — and the episode dir is a tree a
    box can write, so the symlink arm is a shape to meet rather than a hypothetical.
    """
    run = W.mod("learning.judge.run")
    ep = rendered_episode(tmp_path, monkeypatch)
    world_dir = ep / "worlds" / "b"
    outside = tmp_path / "outside.yaml"
    outside.write_text("secret: 1\n", encoding="utf-8")
    link = ep / "linked.yaml"
    try:
        link.symlink_to(outside)
    except OSError:                                    # a host without symlink permission
        link = None

    for hostile in ("../samples.yaml", "worlds/../../samples.yaml", "/etc/passwd",
                    "samples.yaml/../../../etc/passwd", "./../../samples.yaml"):
        assert not run._resolves(hostile, world_dir, subject=W.SUBJECT_WORLD), (
            f"the traversal pointer {hostile!r} resolved")
    if link is not None:
        assert not run._resolves("linked.yaml", world_dir, subject=W.SUBJECT_WORLD), (
            "a symlink planted in the episode dir resolved as episode-level evidence")


# ---------------------------------------------------------------------------------------
# H3 — re-entry overwrites, and the accepted gap that follows
# ---------------------------------------------------------------------------------------


def test_a_second_attempts_step_2_overwrites_the_first_attempts_samples(
        tmp_path, monkeypatch):
    """THE ACCEPTED RE-ENTRY BEHAVIOUR, PINNED: the second attempt's samples WIN.

    Observably true: an episode dir carrying attempt 1's `samples.yaml` is adopted (the adopt
    predicate is `refuse_claimed_episode` plus no `served/*.jsonl` besides `base.jsonl`, and
    neither inspects this file), and a re-entered `Step.QUESTIONER` replaces the file wholesale
    — no merge, no refusal, no second file.

    This test exists BECAUSE the obligation above it is scoped. O5's byte-identity holds within
    one attempt only; on a resumed episode the judge may grade a world authored in attempt N-1
    against attempt N's samples, and nothing compares across attempts (accepted gap G-2). A
    byte-identity test that simply never exercised a re-entry would pass while the obligation
    was false — so the gap is COVERED here rather than merely uncovered.

    What failure looks like: an implementer "fixes" this by merging the two attempts' samples,
    or by refusing the adopt. Both cost resumability, which exists because a launcher killed
    mid-prime would otherwise make that source and branch point permanently unbranchable.
    """
    cli = W.mod("learning.branch.cli")
    _base, _src, root = W.configured_layout(tmp_path, monkeypatch)
    ep = W.episode(tmp_path, root=root)
    first = {W.EVENTS_PATTERN: {"host": {"name": "FIRST-ATTEMPT"}}}
    second = {W.EVENTS_PATTERN: {"host": {"name": "SECOND-ATTEMPT"}}}
    cli.write_questioner_samples(ep, first)

    cli.write_questioner_samples(ep, second)

    assert W.read_yaml(ep / W.SAMPLES_NAME) == second, (
        "a re-entered `Step.QUESTIONER` did not overwrite — H3 chose overwrite-and-re-derive, "
        "and an implementation that merges or refuses has changed the decision")
    assert "FIRST-ATTEMPT" not in (ep / W.SAMPLES_NAME).read_text(encoding="utf-8")
    assert list((ep).glob("samples*.yaml")) == [ep / W.SAMPLES_NAME], (
        "the first attempt's samples survive under a second filename")


def test_a_re_entered_episode_is_adopted_and_the_second_attempts_samples_win(
        tmp_path, monkeypatch):
    """H3'S OTHER HALF, PINNED AT THE RE-ENTRY ITSELF: the adopt is KEPT, and attempt 2 wins.

    Observably true: `cli.prepare_episode` — the one door a re-entered attempt comes through —
    ADOPTS an episode dir already carrying attempt 1's `samples.yaml`, `review.yaml` and
    `judge.yaml` (returns that dir, raises nothing, runs the primer once), and leaves all three
    untouched; a re-entered `Step.QUESTIONER` then replaces `samples.yaml` wholesale through
    that same adopted dir. The admission predicate H3 chose to KEEP is `refuse_claimed_episode` (no
    `family.yaml`) plus no `served/*.jsonl` besides `base.jsonl`, and it inspects none of the
    three files this change adds — e68-4 executed that exact scenario.

    THE SIBLING TEST BELOW PINS THE WRITER, WHICH IS NOT THE SAME SEAM.
    `test_a_second_attempts_step_2_overwrites_the_first_attempts_samples` calls
    `write_questioner_samples` twice and can only see a merge; it never drives a re-entry, so it
    cannot see a REFUSAL of the adopt. Both halves of H3 are decisions, and the rejected
    alternative was named and costed: refusing the adopt "costs resumability, which exists
    because a launcher killed mid-prime would otherwise make that source and branch point
    permanently unbranchable". G-2 rests on this test rather than on the writer's truncate
    semantics: a byte-identity gap covered one layer away from where it lives is uncovered.

    What failure looks like: an implementer reads "re-entry is a problem" and adds a screen to
    the adopt path — refusing an episode dir that already carries `samples.yaml`, `review.yaml`
    or a `judge.yaml` with the new keys. The suite stays green, the alternative H3 rejected by
    name is in force, and the resumability this run costed is gone with nothing red anywhere.
    """
    cli = W.mod("learning.branch.cli")
    capture = W.mod("learning.branch.capture")
    _base, src, root = W.configured_layout(tmp_path, monkeypatch)
    ep = root / W.EPISODE_ID
    (ep / "served").mkdir(parents=True, exist_ok=True)
    (ep / "served" / "base.jsonl").write_text("", encoding="utf-8")
    first = {W.EVENTS_PATTERN: {"host": {"name": "FIRST-ATTEMPT"}}}
    W.write_yaml(ep / W.SAMPLES_NAME, first)
    W.write_yaml(ep / W.REVIEW_NAME, {"episode": {"outcome": "ATTEMPT-1-REVIEW"}})
    W.write_yaml(ep / W.JUDGE_NAME, {"worlds": [{"world": "b", "bucket": "ATTEMPT-1-JUDGE"}]})
    primed: list[tuple] = []

    def prime(source, base):
        """The primer through `prepare_episode`'s own `prime=` injection seam — its docstring
        calls it "an INJECTION SEAM rather than a module lookup" for exactly this caller."""
        primed.append((source, base))
        base.write_text("", encoding="utf-8")
        return capture.PrimeReport(primed=1)

    adopted = cli.prepare_episode(W.EPISODE_ID, src, prime=prime)

    assert adopted == ep, (
        f"prepare_episode returned {adopted!r} rather than adopting {ep} — a re-entered attempt "
        "on a killed episode is refused, which is the alternative H3 rejected by name")
    assert len(primed) == 1, f"the primer ran {len(primed)} times on the adopted episode"
    assert W.read_yaml(ep / W.SAMPLES_NAME) == first, "the adopt destroyed attempt 1's samples"
    assert W.read_yaml(ep / W.REVIEW_NAME)["episode"]["outcome"] == "ATTEMPT-1-REVIEW"
    assert W.read_yaml(ep / W.JUDGE_NAME)["worlds"][0]["bucket"] == "ATTEMPT-1-JUDGE"

    second = {W.EVENTS_PATTERN: {"host": {"name": "SECOND-ATTEMPT"}}}
    cli.write_questioner_samples(adopted, second)

    assert W.read_yaml(adopted / W.SAMPLES_NAME) == second, (
        "the second attempt's samples did not win through the ADOPTED dir — H3 chose "
        "overwrite-and-re-derive, and a merge or a refusal has changed the decision")
    assert "FIRST-ATTEMPT" not in (adopted / W.SAMPLES_NAME).read_text(encoding="utf-8")


def test_a_re_entered_review_re_derives_every_worlds_reachability_block(
        tmp_path, monkeypatch):
    """A re-entered review RE-DERIVES the reachability block rather than trusting an adopted
    episode's.

    Observably true: an episode carrying a stale `review.yaml` — whose block claims a world was
    reachable — reviewed again with adapters that answer identically on both arms comes back
    with `reachable_by_capture: false`. The block is a measurement of THIS pass; carrying an
    earlier attempt's forward would grade a world against a cluster state that no longer holds.

    What failure looks like: the adopted block is kept "because re-asking costs reads". A
    resumed episode is then graded on measurements taken before the corpus was re-staged.
    """
    review = W.mod("learning.branch.review")
    family_mod = W.mod("runtime.branch._family")
    _base, _src, root = W.configured_layout(tmp_path, monkeypatch)
    doc = W.family_doc(worlds=[W.base_world(), W.world_doc(
        "b", ov=W.overlay(elastic=W.elastic_overlay(inject=[{"_id": "i1"}])))])
    ep = W.episode(tmp_path, doc=doc, root=root)
    W.base_capture(ep, [W.captured_row(key="k1")])
    W.write_review(ep, worlds={"b": W.reviewed_world(
        label="b", reachability=W.reachability_block(
            reachable_by_capture=True,
            capture_replays=[W.replay_entry("stale", differs=True)]))})

    record = review.review(family_mod.parse_family(doc), episode_dir=ep,
                           adapters=W.FakeAdapters({("elastic", "query"): {"hits": []}}),
                           door=W.FakeDoor(), invoke=W.FakeAgent("same"))

    block = record["worlds"]["b"]["reachability"]
    assert "stale" not in json.dumps(block), (
        "the adopted episode's reachability block survived the re-entered review")
    assert block["reachable_by_capture"] is False, (
        f"reachable_by_capture is {block['reachable_by_capture']!r} — the stale measurement "
        "was carried forward rather than re-derived")
