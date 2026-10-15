"""The redaction filter hides the branch identities the host KNOWS, not only the ones shaped
like a UTC stamp.

`learning/branch/redaction.py` used to find an episode or world token by its shape alone: a
leading `\\d{8}t\\d{6}z`. An episode forked from a run whose id the operator pinned
(`live-lever-up-20260930-sudo`) carries no stamp, so its episode id, its tokens and every arm's
run id reached the model untouched — and #1187 makes every id a random UUID, which no shape
rule can see. The fix hands the filter the identities themselves: the family's episode id and
token, every world token, and every arm's run id (`_family.family_identities`), bound where the
host knows them — the world's registry for the query tool, the loaded manifest for the
comparator. A natural run knows none and keeps the shape rule alone.

The wired channels are pinned beside their neighbours: the query tool's in
`test_947_triplet_served.py` (a driven run), the comparator's prompt here.

#1187 (declared change 15): every arm's run id is the one the host-written arm roster
(`<ep>/arms.json`) holds, so `family_identities(family, arm_ids)` takes them; the comparator
reads them from the walked episode view (`delta_o(view, *, invoke=)`). The unit test of the
registry's one-line binding (`branch_identities` reading `self.world` alone) is retired: the
manifest-derived world no longer holds the family's arm ids. Its replacement is the sibling-built
registry in `ids_1187/test_1187_roster_consumers.py::test_the_siblings_query_tool_knows_every_
roster_arm_id` (exact set) and `test_a_world_registry_knows_its_whole_family` below.
"""
from __future__ import annotations

import inspect
import json

import pytest

from defender.tests import _triplet_947 as T

MARK = "[a run id]"

#: An operator-pinned source run id and the episode forked from it: no UTC stamp anywhere.
PINNED_SOURCE = "live-lever-up-20260930-sudo"
PINNED_EPISODE = f"{PINNED_SOURCE}-n5"
#: The brief's probe: the world ledger's filename and the arm's run id, as a fault relays them.
PROBE = ("ledger live.lever.up.20260930.sudo.n5.a.jsonl missing; "
         "run live-lever-up-20260930-sudo-n5-a")

#: #1187's shape: a random UUID as the episode id, and as its source run's id.
UUID_EPISODE = "3f2b8c1e-9d4a-4f6b-8e2a-1c5d7e9f0a3b"
UUID_SOURCE = "6a1d3f5b-2c4e-4d8a-9b0c-7e5f3a1d2c64"

#: #1187: each declared world's arm id, as the host-written arm roster (`<ep>/arms.json`) holds
#: it — a random UUID, never composed from the episode id and the label (declared change 15).
ROSTER = {"a": "0b5c7e2a-4d1f-4a8e-9c3b-2f6d8e1a7c40",
          "b": "7e3a9c1f-5b2d-4e8a-a6c4-3d1f9b7e5a20",
          "c": "c4d2e6f8-1a3b-4c5d-9e7f-8a0b2c4d6e81"}
#: The probe as a fault relays it after #1187: the world ledger's filename and an arm's
#: roster id.
ROSTER_PROBE = f"ledger live.lever.up.20260930.sudo.n5.a.jsonl missing; run {ROSTER['a']}"


def _family(episode_id: str):
    doc = T.family_doc(episode_id=episode_id, source_run_id=PINNED_SOURCE)
    return T.sym("runtime.branch._family", "parse_family")(doc)


def _arm_ids() -> dict:
    """The roster's ids, as `family_identities` takes them (#1187: `{label: RunId}`)."""
    from defender.run_repository import RunId

    return {label: RunId.parse(text) for label, text in ROSTER.items()}


def _known(episode_id: str) -> frozenset[str]:
    """The family's set over the roster (#1187 declared change 15: `family_identities(family,
    arm_ids)`)."""
    return T.sym("runtime.branch._family", "family_identities")(_family(episode_id), _arm_ids())


def _redact(detail, known):
    return T.sym("learning.branch.redaction", "redact_model_visible")(detail, known)


# ---------------------------------------------------------------------------------------
# the family's identities: one derivation, every spelling a sibling's process knows
# ---------------------------------------------------------------------------------------


def test_family_identities_are_every_arms_run_id_and_token_plus_the_episodes_own():
    """The set is the episode id, its token, every declared world's token — read off
    `resume_world_from`, the sibling's own derivation, so the two cannot drift — and every
    arm's run id AS THE ROSTER HOLDS IT, and nothing else: no `<episode_id>-<label>` is
    composed (#1187 deletes `arm_run_id_for`).
    #1187 declared change 15
    """
    fam = T.mod("runtime.branch._family")
    family = _family(PINNED_EPISODE)
    expected = {PINNED_EPISODE, fam.episode_token_for(PINNED_EPISODE), *ROSTER.values()}
    for world in family.worlds:
        expected.add(fam.resume_world_from(family, world.world_id, T.DEFENDER).token)
    known = {str(member) for member in fam.family_identities(family, _arm_ids())}
    assert known == expected, (
        f"missing {sorted(expected - known)}; unexpected {sorted(known - expected)}")
    assert "live-lever-up-20260930-sudo-n5-c" not in known
    assert "live.lever.up.20260930.sudo.n5.b" in known


# ---------------------------------------------------------------------------------------
# the filter's contract, given the known set
# ---------------------------------------------------------------------------------------


def test_a_pinned_source_episodes_tokens_are_redacted_whole_when_known():
    """The probe that leaked: a world token inside a ledger filename and an arm's run id — the
    ROSTER's id after #1187. Both are removed whole — the world token before the episode token
    it extends, so no `.a` tail survives — and the sentence around them is untouched.
    #1187 declared change 15
    """
    assert _redact(ROSTER_PROBE, _known(PINNED_EPISODE)) == (
        f"ledger {MARK}.jsonl missing; run {MARK}")


def test_a_uuid_episode_and_its_arms_are_redacted_when_known_in_any_case():
    """No shape rule can see a UUID; the known set does. An arm's run id (the roster's, in
    either case), a sibling's world token, the bare episode id, and a token in another case
    all go.
    #1187 declared change 15
    """
    token = T.sym("runtime.branch._family", "episode_token_for")(UUID_EPISODE)
    detail = (f"run {ROSTER['b']} refused; sibling {token}.c served; "
              f"episode {UUID_EPISODE} at {token.upper()}.A; arm {ROSTER['c'].upper()}")
    assert _redact(detail, _known(UUID_EPISODE)) == (
        f"run {MARK} refused; sibling {MARK} served; episode {MARK} at {MARK}; arm {MARK}")


@pytest.mark.parametrize("detail", [
    "Elasticsearch query failed (HTTP 400): [logs-*] is not a valid index expression",
    "window 2026-09-30T12:00:00Z..2026-09-30T13:00:00Z is outside retention",
    "host live-lever-down and user sudo-admin have no events since 20260930",
])
def test_text_naming_no_known_identity_passes_unchanged(detail):
    """The filter removes identities, not look-alikes: an index pattern, ISO timestamps, and
    names sharing words with the episode id pass through byte for byte."""
    assert _redact(detail, _known(PINNED_EPISODE)) == detail


def test_a_natural_run_keeps_todays_behaviour():
    """A natural run knows no branch identity: the pinned-source text passes unchanged (there is
    nothing to hide in a run that has no siblings), and the stamp-shaped token rule still runs."""
    assert _redact(PROBE, frozenset()) == PROBE
    stamped = f"run {T.world_token('b')} refused"
    assert _redact(stamped, frozenset()) == f"run {MARK} refused"


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
    from defender.runtime.verb_grant import DENY_ALL
    from defender.runtime.verbs import ModuleVerbRegistry, read_roster

    registry = ModuleVerbRegistry(read_roster(T.DEFENDER / "scripts" / "adapters"), DENY_ALL)
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
    arm of the family — a sibling's arm id in a relayed fault is as much a leak as its own. After
    #1187 those arm ids are the ROSTER's (`<ep>/arms.json`, random UUIDs), never
    `<episode_id>-<label>`: the registry's identities are exactly the episode id, its token,
    every world token and every roster arm id (the token is the id with its hyphens rendered as
    dots, R2-03).
    #1187 declared change 15
    """
    from defender.tests.ids_1187 import _spec1187 as R
    from defender.tests.live_oracle_1224 import _spec1224 as S

    est = S.estate(tmp_path)
    doc = S.family_v2(episode_id=UUID_EPISODE, source_run_id=UUID_SOURCE)
    ep = S.episode_v2(tmp_path, doc=doc, episode_id=UUID_EPISODE, base_rows=[])
    R.write_roster(ep, ROSTER)
    registry = S.world_registry(ep, "b", est)
    known = {str(member) for member in registry.branch_identities()}
    token = UUID_EPISODE.replace("-", ".")
    expected = {UUID_EPISODE, token, *(f"{token}.{label}" for label in ROSTER), *ROSTER.values()}
    assert known == expected, (
        f"missing {sorted(expected - known)}; unexpected {sorted(known - expected)}")
    assert f"{UUID_EPISODE}-c" not in known


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


def test_delta_o_hands_the_comparator_the_familys_identities(data_root):
    """Driven through the episode reader over the WALKED view (#1187, review F7:
    `delta_o(view, *, invoke=)` reads the episode through `runs.episode(<ep>)` and takes the arm
    ids from that view's roster; no path re-binds the folder and no caller hands them in): world
    `b` served a payload naming a sibling's run id — the ROSTER's id, which nothing but the
    roster spells. The prompt the comparator sent names none of the family, and the payload did
    reach it (its other text survives).
    #1187 declared change 15
    """
    from defender.tests._judge_921 import comparable_family_stamp
    from defender.tests.ids_1187 import _spec1187 as R

    runs = R.tenant(data_root).runs_repository()
    ep = R.make_episode(data_root, R.H5.T_ID, UUID_EPISODE, labels=ROSTER, roster=ROSTER)
    T.write_family(ep, T.family_doc(episode_id=UUID_EPISODE, source_run_id=UUID_SOURCE))
    with runs.episode(UUID_EPISODE) as view:
        T.mod("learning.branch.outcome").write_outcome(
            view.episode, "accepted", reason="every fact world calibrated")
    comparable_family_stamp(ep)
    for w in T.WORLDS:
        T.archived_world(ep, w)
    T.base_capture(ep, [T.captured_row(key="k1")])
    token = T.sym("runtime.branch._family", "episode_token_for")(UUID_EPISODE)
    leaked = {"hits": [{"_id": "x", "note": f"seen by {ROSTER['c']} on host web-7"}]}
    (ep / "served" / f"{token}.b.jsonl").write_text(
        json.dumps(T.captured_row(key="k1", payload=leaked)) + "\n", encoding="utf-8")
    agent = T.FakeAgent("mutation")
    with runs.episode(UUID_EPISODE) as view:
        out = T.mod("learning.branch.episode").delta_o(view, invoke=agent)
    assert out["b"]["k1"] == "mutation"
    assert agent.prompts, "the comparator was never asked"
    assert ROSTER["c"] not in agent.prompts[0]
    assert MARK in agent.prompts[0]
    assert "host web-7" in agent.prompts[0], "the payload never reached the prompt"
