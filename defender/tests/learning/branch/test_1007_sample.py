"""#1007 — M4: the questioner's own samples, the per-world judge prompt, and the evidence scope."""
from __future__ import annotations

from defender.records._episode_handle import Episode
from defender.tests.support.learning.branch import _world_1007 as W
from defender.tests.learning.judge.contrast_contracts import _spec1234 as S

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


def test_the_launcher_writes_samples_yaml_at_step_2(tmp_path, monkeypatch):
    """The launcher writes `samples.yaml` at `Step.QUESTIONER`, holding exactly what the questioner
    was handed."""
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
    answer shapes in one."""
    built, _judge = graded(tmp_path, monkeypatch, samples=samples_of(OTHER),
                           b_reply=reply_with(sample_finding()))

    assert queued_types() == [], "a sample-citing finding stood without a sample"
    assert_set_aside_for_its_sample(built, 0, "no section for the cited system")


def test_a_present_sample_admits_a_shape_invention_finding(tmp_path, monkeypatch):
    """The positive control: WITH a sample, the same finding stands."""
    _built, _judge = graded(tmp_path, monkeypatch, b_reply=reply_with(sample_finding()))

    assert queued_types() == ["incoherent"], (
        "a sample WAS available and the finding was still dropped")


def test_a_corrupt_or_absent_samples_file_sets_sample_unavailable_for_every_pattern(
        tmp_path, monkeypatch):
    """A corrupt, absent or null-valued samples file is no sample for EVERY system — never a partial
    read and never a refusal that ends the pass."""
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


def test_a_case_differing_system_misses_the_sample_and_refuses_the_finding(
        tmp_path, monkeypatch):
    """A system is matched EXACTLY. `IDP` does not find the samples stored under `idp`."""
    built, _judge = graded(tmp_path, monkeypatch, b_reply=reply_with(
        sample_finding("mislabelled", SYSTEM.upper()), sample_finding("incoherent", SYSTEM)))

    assert queued_types() == ["incoherent"], (
        "a case-differing system found the sample (the lookup is folding case), or the exact "
        f"spelling was refused too: {queued_types()}")
    assert_set_aside_for_its_sample(built, 0, "the case-differing spelling")


def test_a_finding_citing_an_unavailable_sample_is_refused_whatever_its_bucket(
        tmp_path, monkeypatch):
    """The sample-dependent refusal binds to the EVIDENCE, not to a bucket."""
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
    (O5's own falsifier)."""
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


def test_the_judges_sample_is_byte_identical_to_the_questioners_within_one_attempt(
        tmp_path, monkeypatch):
    """WITHIN ONE ATTEMPT, the judge is shown the same real answers per served system that the
    questioner was shown."""
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
    capture sections already carry — parity per cell, at this sink."""
    marker_fault = "a-preflight-reason-marker"
    _built, judge = graded(tmp_path, monkeypatch, outcome_reason=marker_fault,
                           samples=samples_of(SYSTEM, '{"host": "a-sample-marker-host"}'))

    prompt = judge.prompt_for("b")

    W.assert_wrapped_untrusted(prompt, "a-sample-marker-host", "the questioner's sample")
    W.assert_wrapped_untrusted(prompt, marker_fault, "pre-flight's recorded reason")


def test_a_second_attempts_step_2_overwrites_the_first_attempts_samples(
        tmp_path, monkeypatch):
    """THE ACCEPTED BEHAVIOUR, PINNED: a second `Step.QUESTIONER` write's samples WIN."""
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
