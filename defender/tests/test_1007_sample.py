"""#1007 — M4: the questioner's own samples, the per-world judge prompt, and the evidence scope.

`samples.yaml` moves the real example answers the questioner was shown into the episode archive
so they survive a vanished source run, and the per-world judge is shown that record. #1224 keyed
it per served system (`{system: {verbs: {verb: [answer text]}}}`, `cli.system_samples`) where it
was keyed per staged pattern, and pre-flight's outcome record replaced the replay review's
reachability block in the prompt. S7 widens the evidence-pointer resolver for `subject: world`
findings only.

TWO RECORDED DECISIONS SHAPE WHAT IS AND IS NOT ASSERTED HERE:

* **H2 — wrapper yes, filter no.** The samples section and pre-flight's record carry the same
  run-salted untrusted frame the existing capture sections carry. `redaction.redact_model_
  visible` is deliberately NOT applied (accepted gap G-1): the frame stops the text being read as
  instruction; it does not remove anything from it.
* **H3 / RS-1 — O5 holds WITHIN ONE ATTEMPT.** A second `Step.QUESTIONER` write overwrites
  `samples.yaml`, so the byte-identity obligation is scoped to a single attempt, and the
  overwrite (the second write wins) is pinned by its own test.
"""
from __future__ import annotations

from pathlib import Path

from defender._episode_handle import Episode
from defender.tests import _state1135
from defender.tests import _judge_921 as J
from defender.tests import _world_1007 as W

#: A second served system, for the scenarios that tell two systems' samples apart.
OTHER = "identity"


def rendered_episode(tmp_path: Path, monkeypatch, *, labels=("b",), samples=None,
                     worlds=None, reason: str = "") -> Path:
    _base, _src, root = W.configured_layout(tmp_path, monkeypatch)
    docs = worlds if worlds is not None else [W.base_world()] + [
        W.world_doc(x, facts=[W.fact(f"f-{x}", f"fact-of-world-{x}", (f"host-{x}",))])
        for x in labels]
    ep = W.episode(tmp_path, doc=W.family_doc(worlds=docs), root=root)
    for label in labels:
        W.archived_world(ep, label)
        W.write_served(ep, label, [W.served_row(world=label)])
    W.write_outcome(ep, reason=reason)
    if samples is not False:
        W.write_samples(ep, samples)
    return ep


def render_prompt(ep: Path, label: str = "b") -> str:
    """The per-world judge's whole prompt, through the real render + prompt builder."""
    render = W.mod("learning.judge.render")
    run = W.mod("learning.judge.run")
    return run._build_prompt(render.render(ep, label))


def grade(ep: Path, judge):
    return J.grade_at(ep, judge=judge, state=_state1135.env_state())


def world_buckets(result, label: str = "b") -> list[str]:
    """The buckets of the world findings the pass built for `label` — the queue-row view."""
    return [f["type"] for f in result.world_findings if f.get("world") == label]


def sample_finding(bucket: str, system: str = W.SYSTEM):
    return W.world_finding(bucket=bucket, evidence=[f"{W.SAMPLES_NAME}#{system}"])


# ---------------------------------------------------------------------------------------
# M4 — samples.yaml
# ---------------------------------------------------------------------------------------


def test_the_launcher_writes_samples_yaml_at_step_2(tmp_path, monkeypatch):
    """The launcher writes `samples.yaml` at `Step.QUESTIONER`, holding exactly what the
    questioner was handed.

    Observably true: the questioner step's writer, handed a per-system samples document, leaves
    `<episode>/samples.yaml` on disk carrying that document. It lives in the EPISODE archive,
    not in the source run, so it survives a source run that is later pruned — which is the whole
    reason O5's claim is checkable at grading time at all.

    What failure looks like: the samples stay in the source run (or in memory), and the judge
    at grading time has nothing to compare a shape-invention claim against.
    """
    cli = W.mod("learning.branch.cli")
    _base, src, root = W.configured_layout(tmp_path, monkeypatch)
    ep = W.episode(tmp_path, root=root)
    samples = W.samples_document()

    with Episode.open(ep) as episode:
        cli.write_questioner_samples(episode, samples)

    assert (ep / W.SAMPLES_NAME).is_file(), (
        "`Step.QUESTIONER` wrote no samples.yaml into the episode")
    assert W.read_yaml(ep / W.SAMPLES_NAME) == samples
    assert not (src / W.SAMPLES_NAME).exists(), (
        "the samples were written into the SOURCE run, which a later prune removes")


def test_the_judges_sample_is_byte_identical_to_the_questioners_within_one_attempt(
        tmp_path, monkeypatch):
    """WITHIN ONE ATTEMPT, the judge is shown the same real answers per served system that the
    questioner was shown.

    Observably true: every answer text stored under a system's verbs in `samples.yaml` appears
    in the per-world prompt's samples section byte for byte. That is what makes a
    `shape-invention` claim decidable: the judge and the author saw the same bytes.

    SCOPED, and the scope is the point (RS-1): a second write replaces the record, so the judge
    may be shown a later attempt's samples — accepted gap G-2, pinned by
    `test_a_second_attempts_step_2_overwrites_the_first_attempts_samples`.

    What failure looks like: the judge is shown a re-derived or re-formatted sample. Any claim
    the judge makes about a shape the author invented is then made against a document the
    author never saw.
    """
    ep = rendered_episode(tmp_path, monkeypatch)
    stored = W.read_yaml(ep / W.SAMPLES_NAME)[W.SYSTEM]["verbs"]

    prompt = render_prompt(ep)

    texts = [text for answers in stored.values() for text in answers]
    assert texts, "the fixture's samples record holds no answer, so nothing is compared"
    for text in texts:
        assert text in prompt, (
            f"the answer samples.yaml holds for {W.SYSTEM!r} is not in the judge's prompt "
            f"byte for byte: {text!r}")


def test_a_missing_sample_sets_sample_unavailable_and_refuses_shape_invention(
        tmp_path, monkeypatch):
    """No sample for a served system means the judge cannot claim the author invented a shape
    in that system's answers.

    Observably true: with `samples.yaml` holding no section for the system a `shape-invention`
    finding cites, the finding is refused — it reaches no world-finding row. The refusal is
    anchored on the EVIDENCE (A1(b)), not on the bucket literal — see
    `test_a_finding_citing_an_unavailable_sample_is_refused_whatever_its_bucket`, because an
    open vocabulary lets a model rename around any single string.

    What failure looks like: the judge grades shape invention against a sample nobody has, and
    the questioner corpus learns that authors invent shapes whenever the sampler was empty.
    """
    ep = rendered_episode(tmp_path, monkeypatch, samples=W.samples_document(system=OTHER))
    judge = W.FakeJudge(W.reply_document(findings=[sample_finding("shape-invention")]))

    result = grade(ep, judge)

    assert world_buckets(result) == [], (
        f"a shape-invention finding stood without a sample: {result.world_findings}")


def test_a_present_sample_admits_a_shape_invention_finding(tmp_path, monkeypatch):
    """The positive control: WITH a sample, the same finding stands.

    Observably true: an episode identical to the one above except that `samples.yaml` carries
    the cited system's section keeps the `shape-invention` finding. Without this, the refusal
    above would read as correct on a pass that emits no findings at all.

    What failure looks like: the refusal is written too wide and every world finding citing a
    sample is dropped, so the mechanism reads as working while producing nothing.
    """
    ep = rendered_episode(tmp_path, monkeypatch)
    judge = W.FakeJudge(W.reply_document(findings=[sample_finding("shape-invention")]))

    result = grade(ep, judge)

    assert world_buckets(result) == ["shape-invention"], (
        f"a sample WAS available and the finding was still dropped: {result.world_findings}")


def test_a_corrupt_or_absent_samples_file_sets_sample_unavailable_for_every_pattern(
        tmp_path, monkeypatch):
    """A corrupt, absent or null-valued samples file is no sample for EVERY system — never a
    partial read and never a refusal that ends the pass.

    Observably true: three shapes — no file, unparseable YAML, and a file whose system maps to
    null — each grade to a completed `judge.yaml` with the sample-citing finding refused, while
    a finding citing something else stands (the control). The episode dir is a tree a box can
    write, so all three are shapes to meet rather than impossibilities.

    What failure looks like: `yaml.safe_load` raises out of the grading pass, and one damaged
    file costs every world of the episode its grade after every model call has been paid for.
    """
    for label, prepare in (
            ("absent", lambda ep: (ep / W.SAMPLES_NAME).unlink()),
            ("corrupt", lambda ep: (ep / W.SAMPLES_NAME).write_text(
                "samples: [unclosed\n", encoding="utf-8")),
            ("null", lambda ep: W.write_yaml(ep / W.SAMPLES_NAME, {W.SYSTEM: None})),
    ):
        ep = rendered_episode(tmp_path / label, monkeypatch)
        prepare(ep)
        judge = W.FakeJudge(W.reply_document(findings=[
            sample_finding("cites-the-sample"),
            W.world_finding(bucket="cites-the-outcome", evidence=["outcome.yaml#outcome"])]))

        result = grade(ep, judge)

        assert (ep / W.JUDGE_NAME).is_file(), (
            f"the {label} samples file took the whole pass down")
        assert world_buckets(result) == ["cites-the-outcome"], (
            f"the {label} samples file graded the sample-citing finding as backed (or dropped "
            f"the control): {result.world_findings}")


def test_the_writer_pins_one_document_per_pattern_rather_than_relying_on_last_key_wins(
        tmp_path, monkeypatch):
    """The writer pins ONE section per system; it does not hand a duplicate-keyed mapping to
    YAML and let last-key-wins decide.

    Observably true: writing samples from a source that offers two sections for one system
    refuses, or records exactly one — and the file that lands parses to one key with one value
    and spells the key once. `samples.yaml` is `unique-key` on `(episode, system)`, and
    last-key-wins is a decision taken by a serializer rather than by this design.

    What failure looks like: the sampler walks a table and writes as it goes. Which section the
    questioner and the judge both see then depends on `executed_queries.jsonl` ordering, and the
    byte-identity obligation is satisfied against an arbitrary pick.
    """
    cli = W.mod("learning.branch.cli")
    _base, _src, root = W.configured_layout(tmp_path, monkeypatch)
    ep = W.episode(tmp_path, root=root)
    first = W.samples_document(answers=["web-1"])[W.SYSTEM]
    second = W.samples_document(answers=["web-2"])[W.SYSTEM]

    try:
        with Episode.open(ep) as episode:
            cli.write_questioner_samples(episode, [(W.SYSTEM, first), (W.SYSTEM, second)])
    except W.refusals():
        return                       # a refusal is an equally good answer: one section or none
    doc = W.read_yaml(ep / W.SAMPLES_NAME)
    assert list(doc) == [W.SYSTEM], f"the file carries {list(doc)}"
    assert doc[W.SYSTEM] in (first, second)
    raw = (ep / W.SAMPLES_NAME).read_text(encoding="utf-8")
    assert raw.count(f"{W.SYSTEM}:") == 1, (
        "the system was written twice and a YAML load is deciding which one wins")


def test_a_case_differing_system_misses_the_sample_and_refuses_the_finding(
        tmp_path, monkeypatch):
    """A system is matched EXACTLY. `ELASTIC` does not find the samples stored under `elastic`.

    Observably true: a finding citing a case-differing spelling of the sampled system is
    refused, while the same finding citing the exact spelling stands (the control). System
    names are not case-folded anywhere else in this system (N03), and a fuzzy match here would
    hand the judge's claim evidence from a section the finding never named.

    What failure looks like: a `casefold()` at the lookup, and the shape-invention claim is made
    against evidence from somewhere else entirely.
    """
    ep = rendered_episode(tmp_path, monkeypatch)
    judge = W.FakeJudge(W.reply_document(findings=[
        sample_finding("cites-the-folded-spelling", W.SYSTEM.upper()),
        sample_finding("cites-the-exact-spelling", W.SYSTEM)]))

    result = grade(ep, judge)

    assert world_buckets(result) == ["cites-the-exact-spelling"], (
        "a case-differing system found the sample (the lookup is folding case), or the exact "
        f"spelling was refused too: {result.world_findings}")


def test_a_finding_citing_an_unavailable_sample_is_refused_whatever_its_bucket(
        tmp_path, monkeypatch):
    """The sample-dependent refusal binds to the EVIDENCE, not to a bucket literal.

    Observably true: when the samples record marks a system `unavailable`, ANY `subject: world`
    finding citing `samples.yaml#<system>` is refused — whether its bucket is
    `shape-invention`, an unlisted string, or anything else. A finding for that world citing
    something ELSE stands, which is the control.

    This is A1(b): the open vocabulary (G-3) means a refusal keyed on the string
    `shape-invention` is evadable by renaming, so the refusal is anchored where renaming cannot
    reach it.

    What failure looks like: the refusal reads `if finding.bucket == "shape-invention"`. A
    model that spells the same claim `made-up-field-names` walks straight past it.
    """
    ep = rendered_episode(tmp_path, monkeypatch,
                          samples={W.SYSTEM: {"unavailable": "the capture could not be read"}})
    judge = W.FakeJudge(W.reply_document(findings=[
        sample_finding("a-bucket-nobody-listed"),
        W.world_finding(bucket="another-unlisted-bucket", evidence=["outcome.yaml#outcome"]),
    ]))

    result = grade(ep, judge)

    buckets = world_buckets(result)
    assert "a-bucket-nobody-listed" not in buckets, (
        "a finding citing an unavailable sample stood because its bucket was not the literal "
        "the refusal was written against")
    assert "another-unlisted-bucket" in buckets, (
        f"the control failed — a finding citing something else was dropped too: {buckets}")


def test_a_two_system_family_names_each_systems_sample_availability_independently(
        tmp_path, monkeypatch):
    """A family serving TWO systems is graded — and rendered — per system, never reduced to one
    (O5's own falsifier).

    Observably true: with samples captured for one served system and the other marked
    unavailable, the per-world prompt carries the real answer for the system that WAS sampled
    and the unavailable reason for the one that was not; and a finding citing the AVAILABLE
    system survives while one citing the UNAVAILABLE system is refused — in the SAME grading
    pass, over the SAME world.

    What failure looks like: a single-value reduction (the first system alone) makes the record
    read as sampled because SOME system had a sample, while the judge is rendered nothing for the
    system it was never shown — a `shape-invention` claim then gets made, or refused, against
    the wrong system's evidence.
    """
    answer = '{"marker": "the-sampled-systems-answer"}'
    ep = rendered_episode(tmp_path, monkeypatch, samples={
        **W.samples_document(answers=[answer]),
        OTHER: {"unavailable": "UNAVAILABLE-REASON-MARKER"}})
    judge = W.FakeJudge(W.reply_document(findings=[
        sample_finding("cites-the-available-system", W.SYSTEM),
        sample_finding("cites-the-unavailable-system", OTHER),
    ]))

    result = grade(ep, judge)
    prompt = render_prompt(ep)

    buckets = world_buckets(result)
    assert "cites-the-available-system" in buckets, (
        "a finding citing the system that WAS sampled was refused for a gap in the other one")
    assert "cites-the-unavailable-system" not in buckets, (
        "a finding citing the system that was NOT sampled stood")
    assert answer in prompt, "the judge's prompt carries no rendering of the sampled system"
    assert f"system {OTHER}: unavailable — UNAVAILABLE-REASON-MARKER" in prompt, (
        "the judge's prompt says nothing about the second served system at all — reduced to "
        "the first, O5's own falsifier")


# ---------------------------------------------------------------------------------------
# M4 — the per-world prompt
# ---------------------------------------------------------------------------------------


def test_the_per_world_prompt_holds_no_siblings_facts(tmp_path, monkeypatch):
    """No sibling's facts reach a world's prompt.

    Observably true: world b's rendered prompt contains no value that appears only in world c's
    story or facts, while b's own fact does reach it. The prompt is the model's whole input.

    What failure looks like: the manifest is rendered whole "for context". Every world's judge
    is then told exactly how its siblings differ, which is the one thing a per-world grade must
    not know.
    """
    marker = "sibling-only-marker-value"
    ep = rendered_episode(
        tmp_path, monkeypatch, labels=("b", "c"),
        worlds=[W.base_world(),
                W.world_doc("b", facts=[W.fact("fb", "own-fact-of-b", ("web-1",))]),
                W.world_doc("c", story=marker, facts=[W.fact("fc", marker, ("web-1",))])])

    prompt = render_prompt(ep, "b")

    # THE POSITIVE CONTROL: the GRADED world's own fact does reach its prompt. Without it this
    # negative is satisfied by a prompt that renders no facts at all.
    assert "own-fact-of-b" in prompt, (
        "world b's own fact does not reach its prompt, so the absence asserted below is a "
        "fact about an unrendered section rather than about sibling containment")
    assert marker not in prompt, (
        "a sibling's fact or story reached world b's prompt — the manifest is rendered whole")


def test_the_world_buckets_reach_the_prompt_as_examples_not_as_an_enum(tmp_path, monkeypatch):
    """The example world bucket names reach the prompt as EXAMPLES, phrased so a reader can
    tell they do not close the set.

    Observably true: each example name appears in the rendered prompt, and the prompt does
    NOT tell the model the list is exhaustive — no "one of", "must be one of", "only these" or
    "choose from" governs them. The vocabulary is open by human decision (R2), and a prompt
    that says otherwise closes it in the only place that matters for what the model writes.

    What failure looks like: the names are rendered as an enum. The drift the human wanted to
    observe for a few live episodes never happens, and the decision to keep the set open is
    silently reversed in prose.
    """
    ep = rendered_episode(tmp_path, monkeypatch)

    prompt = render_prompt(ep)

    examples = W.EXAMPLE_WORLD_BUCKETS
    for name in examples:
        assert name in prompt, f"the example bucket {name!r} does not reach the prompt"
    lowered = prompt.lower()
    anchor = lowered.find(examples[0])
    window = lowered[max(0, anchor - 400):anchor + 400]
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
    declined it because the example names are invented and have never fired, and wants live
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
    """The samples section and pre-flight's record carry the SAME run-salted untrusted frame the
    capture sections already carry — parity per cell, at this sink.

    Observably true: a sample answer's own text and pre-flight's recorded reason each appear
    INSIDE a closed `<run-{salt}-untrusted>` frame and nowhere outside one — the same two-sided
    assertion the existing capture sections are held to. Both are attacker-influenced by
    definition: the sample is an answer out of the monitored estate and pre-flight's record is
    derived from live reads of it.

    THIS IS THE WRAPPER ONLY. `redaction.redact_model_visible` is NOT applied here, by human
    decision, and this test deliberately does not imply otherwise (accepted gap G-1).

    What failure looks like: the new sections are spliced in as host text, and an answer out of
    the estate is presented to the judge as part of its own instructions.
    """
    marker_fault = "a-preflight-reason-marker"
    ep = rendered_episode(
        tmp_path, monkeypatch, reason=marker_fault,
        samples=W.samples_document(answers=['{"host": "a-sample-marker-host"}']))

    prompt = render_prompt(ep)

    W.assert_wrapped_untrusted(prompt, "a-sample-marker-host", "the questioner's sample")
    W.assert_wrapped_untrusted(prompt, marker_fault, "pre-flight's recorded reason")


# ---------------------------------------------------------------------------------------
# S7 — the evidence resolver, widened for one subject only
# ---------------------------------------------------------------------------------------


def test_a_world_findings_evidence_pointer_admits_exactly_three_episode_files(
        tmp_path, monkeypatch):
    """A `subject: world` finding may cite exactly three episode-level files, and nothing else
    at the episode level.

    Observably true: `samples.yaml`, `outcome.yaml` and `judge.yaml` resolve for a world-subject
    pointer, while a fourth episode-level file — `family.yaml`, the retired `review.yaml`,
    anything under `served/` — does not. The world's own subtree stays reachable exactly as before.

    What failure looks like: the widen is written as "the episode dir", and a world finding can
    cite a sibling's whole archive — which is precisely the containment J13(a) was written to
    hold and S7 widens only three files' worth.
    """
    run = W.mod("learning.judge.run")
    ep = rendered_episode(tmp_path, monkeypatch)
    W.write_yaml(ep / "review.yaml", {"episode": {"outcome": "accepted"}})
    world_dir = ep / "worlds" / "b"

    for allowed in W.WORLD_EVIDENCE_FILES:
        assert run._resolves(allowed, world_dir, subject=W.SUBJECT_WORLD), (
            f"{allowed} does not resolve for a world-subject finding")
    for refused in ("family.yaml", "review.yaml", "served/base.jsonl", "worlds/a/report.md"):
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
# H3 — a second write overwrites, and the accepted gap that follows
# ---------------------------------------------------------------------------------------


def test_a_second_attempts_step_2_overwrites_the_first_attempts_samples(
        tmp_path, monkeypatch):
    """THE ACCEPTED BEHAVIOUR, PINNED: a second `Step.QUESTIONER` write's samples WIN.

    Observably true: an episode carrying a first write's `samples.yaml` has it replaced
    wholesale by a second — no merge, no refusal, no second file.

    This test exists BECAUSE the obligation above it is scoped. O5's byte-identity holds within
    one attempt only, and nothing compares across attempts (accepted gap G-2). A byte-identity
    test that simply never exercised a second write would pass while the obligation was false —
    so the gap is COVERED here rather than merely uncovered. (#1224: a launch never adopts an
    existing episode directory any more — N17 — so the re-entered launch this once also pinned
    is gone; the writer's overwrite is what remains.)

    What failure looks like: an implementer merges the two writes' samples, and the judge is
    shown a record no single questioner call was ever handed.
    """
    cli = W.mod("learning.branch.cli")
    _base, _src, root = W.configured_layout(tmp_path, monkeypatch)
    ep = W.episode(tmp_path, root=root)
    first = W.samples_document(answers=["FIRST-ATTEMPT"])
    second = W.samples_document(answers=["SECOND-ATTEMPT"])
    with Episode.open(ep) as episode:
        cli.write_questioner_samples(episode, first)

        cli.write_questioner_samples(episode, second)

    assert W.read_yaml(ep / W.SAMPLES_NAME) == second, (
        "a second `Step.QUESTIONER` write did not overwrite — H3 chose overwrite-and-re-derive, "
        "and an implementation that merges or refuses has changed the decision")
    assert "FIRST-ATTEMPT" not in (ep / W.SAMPLES_NAME).read_text(encoding="utf-8")
    assert list((ep).glob("samples*.yaml")) == [ep / W.SAMPLES_NAME], (
        "the first attempt's samples survive under a second filename")
