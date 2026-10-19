"""The redaction filter hides the branch identities the host KNOWS, not only the ones shaped
like a UTC stamp.

`learning/branch/redaction.py` used to find an episode or world token by its shape alone: a
leading `\\d{8}t\\d{6}z`. An episode forked from a run whose id the operator pinned
(`live-lever-up-20260930-sudo`) carries no stamp, so its episode id, its tokens and every arm's
run id reached the model untouched — and #1187 makes every id a random UUID, which no shape
rule can see. The fix hands the filter the identities themselves: the family's episode id and
token, every world token, and every arm's run id (`_family.family_identities`), bound where the
host knows them — the world's registry for the query tool, the loaded manifest for the
comparator. A natural run knows none and leaves the text unchanged.

The wired channels are pinned beside their neighbours: the query tool's in
`test_947_triplet_served.py` (a driven run), the comparator's prompt here.
"""
from __future__ import annotations

import inspect
import json
from types import SimpleNamespace

import pytest

from defender.episodes._episode_handle import Episode
from defender.tests.support.learning.branch import _triplet_947 as T

MARK = "[a run id]"

#: An operator-pinned source run id and the episode forked from it: no UTC stamp anywhere.
PINNED_SOURCE = "live-lever-up-20260930-sudo"
PINNED_EPISODE = f"{PINNED_SOURCE}-n5"
#: The brief's probe: the world ledger's filename and the arm's run id, as a fault relays them.
PROBE = ("ledger live.lever.up.20260930.sudo.n5.a.jsonl missing; "
         "run live-lever-up-20260930-sudo-n5-a")

#: #1187's shape: a random UUID as the episode id.
UUID_EPISODE = "3f2b8c1e-9d4a-4f6b-8e2a-1c5d7e9f0a3b"


def _family(episode_id: str):
    doc = T.family_doc(episode_id=episode_id, source_run_id=PINNED_SOURCE)
    return T.sym("runtime.branch._family", "parse_family")(doc)


def _known(episode_id: str) -> frozenset[str]:
    return T.sym("runtime.branch._family", "family_identities")(_family(episode_id))


def _redact(detail, known):
    return T.sym("learning.branch.redaction", "redact_model_visible")(detail, known)


# ---------------------------------------------------------------------------------------
# the family's identities: one derivation, every spelling a sibling's process knows
# ---------------------------------------------------------------------------------------


def test_family_identities_are_every_arms_run_id_and_token_plus_the_episodes_own():
    """The set is what the manifest derives and nothing else: the episode id, its token, and
    for every declared world the token and run id `ResumeWorld` itself composes — read off
    `resume_world_from`, the sibling's own derivation, so the two cannot drift."""
    fam = T.mod("runtime.branch._family")
    family = _family(PINNED_EPISODE)
    expected = {PINNED_EPISODE, fam.episode_token_for(PINNED_EPISODE)}
    for world in family.worlds:
        resumed = fam.resume_world_from(family, world.world_id, T.DEFENDER)
        expected |= {resumed.token, resumed.run_id}
    assert fam.family_identities(family) == frozenset(expected)
    assert "live-lever-up-20260930-sudo-n5-c" in expected
    assert "live.lever.up.20260930.sudo.n5.b" in expected


# ---------------------------------------------------------------------------------------
# the filter's contract, given the known set
# ---------------------------------------------------------------------------------------


def test_a_pinned_source_episodes_tokens_are_redacted_whole_when_known():
    """The probe that leaked: a world token inside a ledger filename and an arm's run id. Both
    are removed whole — the world token before the episode token it extends, so no `.a` tail
    survives — and the sentence around them is untouched."""
    assert _redact(PROBE, _known(PINNED_EPISODE)) == f"ledger {MARK}.jsonl missing; run {MARK}"


def test_a_uuid_episode_and_its_arms_are_redacted_when_known_in_any_case():
    """No shape rule can see a UUID; the known set does. An arm's run id, a sibling's world
    token, the bare episode id, and a token in another case all go."""
    token = T.sym("runtime.branch._family", "episode_token_for")(UUID_EPISODE)
    detail = (f"run {UUID_EPISODE}-b refused; sibling {token}.c served; "
              f"episode {UUID_EPISODE} at {token.upper()}.A")
    assert _redact(detail, _known(UUID_EPISODE)) == (
        f"run {MARK} refused; sibling {MARK} served; episode {MARK} at {MARK}")


@pytest.mark.parametrize("detail", [
    "Elasticsearch query failed (HTTP 400): [logs-*] is not a valid index expression",
    "window 2026-09-30T12:00:00Z..2026-09-30T13:00:00Z is outside retention",
    "host live-lever-down and user sudo-admin have no events since 20260930",
])
def test_text_naming_no_known_identity_passes_unchanged(detail):
    """The filter removes identities, not look-alikes: an index pattern, ISO timestamps, and
    names sharing words with the episode id pass through byte for byte."""
    assert _redact(detail, _known(PINNED_EPISODE)) == detail


def test_a_natural_run_leaves_all_text_unchanged():
    """An empty known set never masks a name, regardless of its spelling."""
    assert _redact(PROBE, frozenset()) == PROBE
    stamped = f"run {T.world_token('b')} refused"
    assert _redact(stamped, frozenset()) == stamped


@pytest.mark.parametrize("identity", [
    "20260930t120000z-retention-check",
    "20260930T120000Z.archive",
    "20260930t120000z_arm-record",
])
def test_timestamp_shaped_names_are_only_removed_when_explicitly_known(identity):
    detail = f"archive {identity} missing"
    assert _redact(detail, _known(UUID_EPISODE)) == detail
    assert _redact(detail, frozenset()) == detail
    assert _redact(detail, frozenset({identity})) == f"archive {MARK} missing"


def test_an_empty_or_non_text_member_neither_raises_nor_shreds_the_detail():
    """The filter runs inside fault handlers. A blank member would match between every
    character and a non-string one would fail `re.escape`; neither may happen."""
    plain = "index 'logs-*' falls outside the configured patterns"
    assert _redact(plain, frozenset({"", PINNED_EPISODE})) == plain
    assert _redact(f"run {PINNED_EPISODE}", {7, PINNED_EPISODE}) == f"run {MARK}"
    assert _redact(404, frozenset()) == "404"


def test_the_known_set_is_a_required_argument():
    """A caller cannot forget it: there is no default meaning "none"."""
    params = inspect.signature(
        T.sym("learning.branch.redaction", "redact_model_visible")).parameters
    assert params["known_ids"].default is inspect.Parameter.empty


# ---------------------------------------------------------------------------------------
# where the query tool's set is bound: the registry that serves the world
# ---------------------------------------------------------------------------------------


def test_the_query_capture_requires_the_known_set():
    params = inspect.signature(T.sym("runtime.query_tool", "QueryCapture")).parameters
    assert params["known_ids"].default is inspect.Parameter.empty


def test_a_natural_registry_knows_no_branch_identity():
    """`ModuleVerbRegistry` serves real systems on a run with no siblings."""
    from defender._paths import PATHS
    from defender.runtime.verb_grant import DENY_ALL
    from defender.runtime.verbs import ModuleVerbRegistry, read_roster

    registry = ModuleVerbRegistry(read_roster(PATHS.adapters_dir), DENY_ALL)
    assert registry.branch_identities() == frozenset()


def test_lead_zeros_narrowed_registry_answers_with_the_registry_it_narrows():
    """The correlation lead narrows the run's registry's grant, not its identity."""
    from defender.runtime.lead_zero._items import _NarrowedRegistry
    from defender.runtime.verb_grant import DENY_ALL
    from defender.tests.e2e._replay_harness import FakeVerbs

    known = _known(PINNED_EPISODE)

    class _Branched(FakeVerbs):
        def branch_identities(self) -> frozenset[str]:
            return known

    assert _NarrowedRegistry(_Branched({}), DENY_ALL).branch_identities() == known


def test_a_world_registry_knows_its_whole_family(tmp_path):
    """The sibling's registry holds the manifest it was resumed from, so it answers with every
    arm of the family — a sibling's token in a relayed fault is as much a leak as its own."""
    from defender.tests.learning.oracle.live_contracts import _spec1224 as S

    est = S.estate(tmp_path)
    ep = S.episode_v2(tmp_path, base_rows=[])
    registry = S.world_registry(ep, "b", est)
    fam = T.mod("runtime.branch._family")
    known = registry.branch_identities()
    assert known == fam.family_identities(registry.world.family)
    assert registry.world.run_id in known
    assert f"{registry.world.family.episode_id}-c" in known


# ---------------------------------------------------------------------------------------
# the comparator's prompt
# ---------------------------------------------------------------------------------------


def test_the_comparator_prompt_redacts_known_identities_in_both_payloads_and_the_axis():
    comparator = T.mod("learning.branch.comparator")
    known = _known(PINNED_EPISODE)
    prompt = comparator.build_prompt(
        a=json.dumps({"error": PROBE}),
        b=json.dumps({"note": "served by live.lever.up.20260930.sudo.n5.b"}),
        axis="whether live-lever-up-20260930-sudo-n5-c saw the login",
        known_ids=known)
    for leak in sorted(known):
        assert leak not in prompt, f"{leak!r} reached the comparator prompt"
    assert prompt.count(MARK) == 4, prompt
    assert "saw the login" in prompt


def test_the_comparator_known_set_is_required_and_symmetric():
    """`known_ids` is the family's whole set, the same for both payloads, so it cannot tell the
    comparator which side is the base: the blindness argument still holds. Required on both the
    prompt builder and `compare`."""
    comparator = T.mod("learning.branch.comparator")
    for fn in (comparator.build_prompt, comparator.compare):
        assert inspect.signature(fn).parameters["known_ids"].default is inspect.Parameter.empty


def test_delta_o_hands_the_comparator_the_familys_identities(tmp_path):
    """Driven through the episode reader: a pinned-source family whose world `b` served a
    payload naming a sibling's run id. The prompt the comparator sent names none of the family."""
    from defender.tests.support.learning.judge._judge_921 import comparable_family_stamp

    doc = T.family_doc(episode_id=PINNED_EPISODE, source_run_id=PINNED_SOURCE)
    ep = T.episode(tmp_path, doc=doc, episode_id=PINNED_EPISODE)
    with Episode.open(ep) as episode:
        T.mod("learning.branch.outcome").write_outcome(
            episode, "accepted", reason="every fact world calibrated")
    comparable_family_stamp(ep)
    for w in T.WORLDS:
        T.archived_world(ep, w)
    T.base_capture(ep, [T.captured_row(key="k1")])
    token = T.sym("runtime.branch._family", "episode_token_for")(PINNED_EPISODE)
    leaked = {"hits": [{"_id": "x", "note": f"seen by {PINNED_EPISODE}-c"}]}
    (ep / "served" / f"{token}.b.jsonl").write_text(
        json.dumps(T.captured_row(key="k1", payload=leaked)) + "\n", encoding="utf-8")
    agent = T.FakeAgent("mutation")
    out = T.mod("learning.branch.episode").delta_o(ep, invoke=agent)
    assert out["b"]["k1"] == "mutation"
    assert agent.prompts, "the comparator was never asked"
    assert f"{PINNED_EPISODE}-c" not in agent.prompts[0]
    assert MARK in agent.prompts[0]


def test_world_registry_branch_identities_reads_the_world_it_serves():
    """The one line that binds a sibling's set, without an estate: it reads `self.world`."""
    WorldRegistry = T.sym("learning.branch.estate.registry", "WorldRegistry")
    fam = T.mod("runtime.branch._family")
    family = _family(PINNED_EPISODE)
    world = fam.resume_world_from(family, "b", T.DEFENDER)
    assert WorldRegistry.branch_identities(SimpleNamespace(world=world)) == \
        fam.family_identities(family)
