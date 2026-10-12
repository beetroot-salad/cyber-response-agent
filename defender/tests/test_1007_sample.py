"""#1007 — M4: the questioner's own samples, the per-world judge prompt, and the evidence scope.

`samples.yaml` moves the real example answers the questioner was shown into the episode archive
so they survive a vanished source run, and the per-world judge is shown that record. #1224 keyed
it per served system (`{system: {verbs: {verb: [answer text]}}}`, `cli.system_samples`) where it
was keyed per staged pattern, and pre-flight's outcome record replaced the replay review's
reachability block in the prompt. #1234 kept the per-world sample rule (O16: a world finding
citing `samples.yaml` anywhere but a served system's own section of real answers is set aside,
ledger lane `unqueueable`) and replaced S7's per-subject pointer allowlist with one typed
resolver (A1), pinned by `judge_contrast_1234/test_1234_pointer_resolver.py`.

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

from defender._episode_handle import Episode
from defender.tests import _world_1007 as W
from defender.tests.judge_contrast_1234 import _spec1234 as S

#: The served system the default fixture's samples are recorded for, and a second one, for
#: the scenarios that tell two systems' samples apart (both in `_spec1234.SYSTEMS`).
SYSTEM = "idp"
OTHER = "edr"


def samples_of(system: str = SYSTEM, *answers: str) -> dict:
    """A samples record holding one section of real answers, for `system`."""
    return {system: {"verbs": {"query": list(answers or ['{"user": "alice"}'])}}}


def graded(tmp_path, monkeypatch, *, samples=None, b_reply=None, **kw):
    """An archived triad with `samples`, graded once; returns `(built, judge)`."""
    built = W.contrast_family(tmp_path, monkeypatch,
                              samples=samples if samples is not None else samples_of(), **kw)
    judge = S.judge({"b": b_reply} if b_reply is not None else {})
    S.grade(built, judge)
    return built, judge


def sample_finding(bucket: str = "incoherent", system: str = SYSTEM) -> dict:
    """A design world finding (a plan pointer at b's entry) that also cites one system's
    samples section."""
    return S.wf(bucket, evidence=[S.samples_ptr(system), S.plan_ptr("b")])


def other_finding(bucket: str = "mislabelled") -> dict:
    """A design world finding citing pre-flight's record instead of any sample — the control."""
    return S.wf(bucket, evidence=[S.outcome_ptr("outcome"), S.plan_ptr("b")])


def reply_with(*world: dict) -> dict:
    return S.world_reply(S.NO_BUCKET, [], world=list(world))


def queued_types() -> list[str]:
    """The types of world b's rows on the questioner queue, in filing order."""
    return [r["type"] for r in S.from_world(S.questioner_queue(), "b")]


def assert_set_aside_for_its_sample(built, index: int, what: str) -> None:
    """b's draw-0 finding `index` took the O16 lane (`unqueueable`, naming samples.yaml)."""
    fid = built.finding_id("b", 0, index)
    entries = [e for e in S.ledger(built) if e.get("finding_id") == fid]
    assert [e.get("lane") for e in entries] == [S.LANES["unqueueable"]], (
        f"{what}: the finding was not set aside for its sample citation: {entries}")
    assert "samples.yaml" in str(entries[0].get("reason")), entries


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


def test_a_missing_sample_sets_sample_unavailable_and_refuses_shape_invention(
        tmp_path, monkeypatch):
    """No sample for a served system means the judge cannot ground a claim about that system's
    answer shapes in one.

    Observably true: with `samples.yaml` holding no section for the system a world finding
    cites, the finding is set aside — it reaches no questioner row, and its ledger lane is
    `unqueueable` naming the samples record. The refusal is anchored on the EVIDENCE (A1(b)),
    not on a bucket literal — see
    `test_a_finding_citing_an_unavailable_sample_is_refused_whatever_its_bucket`.

    What failure looks like: the judge grades shape invention against a sample nobody has, and
    the questioner corpus learns that authors invent shapes whenever the sampler was empty.
    """
    built, _judge = graded(tmp_path, monkeypatch, samples=samples_of(OTHER),
                           b_reply=reply_with(sample_finding()))

    assert queued_types() == [], "a sample-citing finding stood without a sample"
    assert_set_aside_for_its_sample(built, 0, "no section for the cited system")


def test_a_present_sample_admits_a_shape_invention_finding(tmp_path, monkeypatch):
    """The positive control: WITH a sample, the same finding stands.

    Observably true: an episode identical to the one above except that `samples.yaml` carries
    the cited system's section keeps the finding — it reaches the questioner queue. Without
    this, the refusal above would read as correct on a pass that emits no findings at all.

    What failure looks like: the refusal is written too wide and every world finding citing a
    sample is dropped, so the mechanism reads as working while producing nothing.
    """
    _built, _judge = graded(tmp_path, monkeypatch, b_reply=reply_with(sample_finding()))

    assert queued_types() == ["incoherent"], (
        "a sample WAS available and the finding was still dropped")


def test_a_corrupt_or_absent_samples_file_sets_sample_unavailable_for_every_pattern(
        tmp_path, monkeypatch):
    """A corrupt, absent or null-valued samples file is no sample for EVERY system — never a
    partial read and never a refusal that ends the pass.

    Observably true: three shapes — no file, unparseable YAML, and a file whose system maps to
    null — each grade to a completed `judge.yaml` with the sample-citing finding set aside,
    while a finding citing something else stands (the control). The episode dir is a tree a box
    can write, so all three are shapes to meet rather than impossibilities.

    What failure looks like: `yaml.safe_load` raises out of the grading pass, and one damaged
    file costs every world of the episode its grade after every model call has been paid for.
    """
    for label, prepare in (
            ("absent", lambda ep: (ep / W.SAMPLES_NAME).unlink()),
            ("corrupt", lambda ep: (ep / W.SAMPLES_NAME).write_text(
                "samples: [unclosed\n", encoding="utf-8")),
            ("null", lambda ep: W.write_yaml(ep / W.SAMPLES_NAME, {SYSTEM: None})),
    ):
        built = W.contrast_family(tmp_path / label, monkeypatch, samples=samples_of())
        prepare(built.ep)
        S.grade(built, S.judge({"b": reply_with(sample_finding(), other_finding())}))

        assert (built.ep / W.JUDGE_NAME).is_file(), (
            f"the {label} samples file took the whole pass down")
        assert queued_types() == ["mislabelled"], (
            f"the {label} samples file graded the sample-citing finding as backed (or dropped "
            f"the control): {queued_types()}")
        assert_set_aside_for_its_sample(built, 0, f"the {label} samples file")


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
    """A system is matched EXACTLY. `IDP` does not find the samples stored under `idp`.

    Observably true: a finding citing a case-differing spelling of the sampled system is set
    aside, while the same finding citing the exact spelling stands (the control). System
    names are not case-folded anywhere else in this system (N03), and a fuzzy match here would
    hand the judge's claim evidence from a section the finding never named.

    What failure looks like: a `casefold()` at the lookup, and the shape-invention claim is made
    against evidence from somewhere else entirely.
    """
    built, _judge = graded(tmp_path, monkeypatch, b_reply=reply_with(
        sample_finding("mislabelled", SYSTEM.upper()), sample_finding("incoherent", SYSTEM)))

    assert queued_types() == ["incoherent"], (
        "a case-differing system found the sample (the lookup is folding case), or the exact "
        f"spelling was refused too: {queued_types()}")
    assert_set_aside_for_its_sample(built, 0, "the case-differing spelling")


def test_a_finding_citing_an_unavailable_sample_is_refused_whatever_its_bucket(
        tmp_path, monkeypatch):
    """The sample-dependent refusal binds to the EVIDENCE, not to a bucket.

    Observably true: when the samples record marks a system `unavailable`, ANY world finding
    citing `samples.yaml#<system>` is set aside, whichever of the world-finding buckets it
    files under; a finding for that world citing something ELSE stands, which is the control.

    This is A1(b): a refusal keyed on one bucket would be evadable by filing the same claim
    under another, so the refusal is anchored where the bucket cannot reach it.

    What failure looks like: the refusal reads `if finding.bucket == "incoherent"`, and a model
    that files the same claim as `mislabelled` walks straight past it.
    """
    built, _judge = graded(
        tmp_path, monkeypatch,
        samples={SYSTEM: {"unavailable": "the capture could not be read"}},
        b_reply=reply_with(sample_finding("incoherent"), sample_finding("mislabelled"),
                           other_finding("unreachable")))

    assert queued_types() == ["unreachable"], (
        "a finding citing an unavailable sample stood, or the control citing something else "
        f"was dropped too: {queued_types()}")
    assert_set_aside_for_its_sample(built, 0, "an unavailable sample, bucket incoherent")
    assert_set_aside_for_its_sample(built, 1, "an unavailable sample, bucket mislabelled")


def test_a_two_system_family_names_each_systems_sample_availability_independently(
        tmp_path, monkeypatch):
    """A family serving TWO systems is graded — and rendered — per system, never reduced to one
    (O5's own falsifier).

    Observably true: with samples captured for one served system and the other marked
    unavailable, the per-world prompt carries the real answer for the system that WAS sampled
    and the unavailable reason for the one that was not; and a finding citing the AVAILABLE
    system survives while one citing the UNAVAILABLE system is set aside — in the SAME grading
    pass, over the SAME world.

    What failure looks like: a single-value reduction (the first system alone) makes the record
    read as sampled because SOME system had a sample, while the judge is rendered nothing for the
    system it was never shown.
    """
    answer = '{"marker": "the-sampled-systems-answer"}'
    built, judge = graded(
        tmp_path, monkeypatch,
        samples={**samples_of(SYSTEM, answer),
                 OTHER: {"unavailable": "UNAVAILABLE-REASON-MARKER"}},
        b_reply=reply_with(sample_finding("incoherent", SYSTEM),
                           sample_finding("mislabelled", OTHER)))
    prompt = judge.prompt_for("b")

    assert queued_types() == ["incoherent"], (
        "the finding citing the sampled system was refused for a gap in the other one, or the "
        f"one citing the unsampled system stood: {queued_types()}")
    assert_set_aside_for_its_sample(built, 1, "the unsampled system")
    assert answer in prompt, "the judge's prompt carries no rendering of the sampled system"
    assert f"system {OTHER}: unavailable — UNAVAILABLE-REASON-MARKER" in prompt, (
        "the judge's prompt says nothing about the second served system at all — reduced to "
        "the first, O5's own falsifier")


# ---------------------------------------------------------------------------------------
# M4 — the per-world prompt
# ---------------------------------------------------------------------------------------


def test_the_world_finding_buckets_reach_the_prompt_as_the_closed_set_they_are(
        tmp_path, monkeypatch):
    """The per-world prompt names exactly the world-finding buckets the validator admits
    (#1234 M4 closed the vocabulary #1007 kept open, so the prompt's list is the set, not
    examples of it), and none of #1007's retired example names.

    Observably true: each of `run.WORLD_FINDING_BUCKETS` appears in world b's prompt, and
    `shape-invention`, `fact-story-gap` and `undiscriminating-family` do not.

    What failure looks like: the prompt keeps offering the retired example names, the model
    files under them, and every such reply is refused and re-asked for a bucket the prompt
    itself suggested.
    """
    run = W.mod("learning.judge.run")
    _built, judge = graded(tmp_path, monkeypatch)

    prompt = judge.prompt_for("b")

    for name in sorted(run.WORLD_FINDING_BUCKETS):
        assert name in prompt, f"the world-finding bucket {name!r} does not reach the prompt"
    for retired in ("shape-invention", "fact-story-gap", "undiscriminating-family"):
        assert retired not in prompt, f"the retired example bucket {retired!r} is still offered"


def test_the_judges_sample_is_byte_identical_to_the_questioners_within_one_attempt(
        tmp_path, monkeypatch):
    """WITHIN ONE ATTEMPT, the judge is shown the same real answers per served system that the
    questioner was shown.

    Observably true: every answer text stored under a system's verbs in `samples.yaml` appears
    in the per-world prompt byte for byte. That is what makes a claim about an invented shape
    decidable: the judge and the author saw the same bytes.

    SCOPED, and the scope is the point (RS-1): a second write replaces the record, so the judge
    may be shown a later attempt's samples — accepted gap G-2, pinned by
    `test_a_second_attempts_step_2_overwrites_the_first_attempts_samples`.

    What failure looks like: the judge is shown a re-derived or re-formatted sample. Any claim
    the judge makes about a shape the author invented is then made against a document the
    author never saw.
    """
    built, judge = graded(tmp_path, monkeypatch, samples=samples_of(
        SYSTEM, '{"user": {"name": "alice"}, "event": "logon"}', "a second answer"))
    stored = W.read_yaml(built.ep / W.SAMPLES_NAME)[SYSTEM]["verbs"]

    prompt = judge.prompt_for("b")

    texts = [text for answers in stored.values() for text in answers]
    assert texts, "the fixture's samples record holds no answer, so nothing is compared"
    for text in texts:
        assert text in prompt, (
            f"the answer samples.yaml holds for {SYSTEM!r} is not in the judge's prompt "
            f"byte for byte: {text!r}")


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
    _built, judge = graded(tmp_path, monkeypatch, outcome_reason=marker_fault,
                           samples=samples_of(SYSTEM, '{"host": "a-sample-marker-host"}'))

    prompt = judge.prompt_for("b")

    W.assert_wrapped_untrusted(prompt, "a-sample-marker-host", "the questioner's sample")
    W.assert_wrapped_untrusted(prompt, marker_fault, "pre-flight's recorded reason")


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
