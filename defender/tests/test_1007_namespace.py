"""#1007 — F-R5: an episode has ONE namespace, and the operator door that defeated it.

SCOPE GROWTH, DECIDED BY THE HUMAN, RECORDED HERE SO A REVIEWER IS NOT SURPRISED. Nothing in
#1007's design mentions `--episode-token`; the flag predates this change. It is removed here
rather than deferred, on this run's own executed evidence, and the same decision is written into
the spec graph's `handoff.forks` (F-R5) and named in its PR-facing summary. This is the SECOND
time this round the change grows into pre-existing behaviour — H1's applied counter was the
first — and both are examined decisions rather than drift.

WHY REMOVED RATHER THAN SCREENED. `cli._episode_token`'s own docstring says the override "has
to reach `episode_token_for` or the refusal below names a remedy that does nothing: the operator
re-runs with `--episode-token`, the flag is parsed and dropped, the identical message prints
again". A screen — refusing the override whenever the derived token is nameable — would make
that refusal name a remedy that does nothing for EVERY reachable input: 0 of 16104 exhaustively
swept ids plus `_repo.HOSTILE_NAMES` are `refuse_bad_episode_id`-valid and
`episode_token_for`-untokenable, and `episode_dir_for` runs that gate first
(`f5-override-has-no-reachable-purpose`). Screening manufactures precisely the failure the
incumbent code says it exists to prevent; removal leaves the module self-consistent, and the
refusal that survives stops naming a flag and takes the shape of the launcher's sibling refusals
("name a fresh source run or branch point").

THIS DOES NOT CONTRADICT H3, and a cold reader must not read it that way. H3 refused
INTRODUCING per-attempt-unique episode ids, on the executed ground that they orphan a killed
attempt's live cluster aliases — `staging.sweep` is the only recovery for those names and is
keyed on `episode_token_for(episode_id)` (e68-7). This REMOVES an existing way to reach that
same leak by hand: with the flag, neither attempt's sweep glob matches the other attempt's live
names, in either direction, while the same-token control matches (`f5-override-breaks-sweep-
disjointness-by-hand`). One invariant stands behind both decisions — an episode's namespace is
derived from its episode id and from nothing else.

RED AGAINST HEAD is the expected state: at HEAD the flag parses and the episode stages under the
operator's string while every reader re-derives from the episode id.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from defender.tests import _triplet_947 as T
from defender.tests import _world_1007 as W
from defender.tests.live_oracle_1224 import _spec1224 as S

#: The string an operator would name. Distinctive on purpose: the negative below sweeps every
#: byte the launcher could have written for it, so a value that could occur by accident would
#: make an absence assertion unreadable.
OPERATOR_NAMED = "opnamed.token"

#: The one answer every captured call of `launch`'s source run carries, so a single scripted
#: oracle submission serves every call unchanged and every fact world calibrates.
_BASE = {"rows": [{"user": "alice", "event_id": "e-100", "action": "logon", "host": "web-1",
                   "ts": "2026-07-28T15:00:00Z"}]}


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """Both CONFIGURED roots, and the learning state the judge appends to, inside `tmp_path`."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    T.isolate_learning_state(tmp_path, monkeypatch)


def launch(tmp_path: Path, *, argv_extra=()):
    """One episode through the REAL launcher over `_spec1224`'s fixture tenant (#1224).

    Pre-flight replays the source run's captured calls through each fact world's oracle: an
    oracle serving every call unchanged and a verifier passing it, so the family is accepted and
    its siblings start (on a recording spawn). The role preflight is neutralised so an
    uncredentialed host cannot satisfy a refusal before the check under test is reached.
    Returns `(rc, spawn, episode_dir)`.
    """
    run = S.launch(
        tmp_path, S.estate(tmp_path),
        calls=[S.Call("idp", "query", S.query_params("user:alice"), _BASE),
               S.Call("edr", "query", S.query_params("host:db-1"), _BASE)],
        argv_extra=argv_extra, oracle=S.oracle(then=S.submit(_BASE, S.EMPTY_CLAIM)),
        verifier=S.passing_verifier())
    return run.rc, run.spawn, run.ep


def written_bytes(root: Path) -> str:
    """Every byte the launcher wrote under the episodes root, as one string — the manifest,
    pre-flight's records, the ledgers and the provenance record all sit here, so one sweep
    covers every file surface the operator's string could have reached."""
    return "\n".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in sorted(root.rglob("*")) if p.is_file())


def test_the_launcher_answers_to_no_operator_named_episode_token(tmp_path):
    """An operator cannot name an episode's namespace.

    Observably true: `--episode-token <token>` is not an argument the launcher answers to — the
    real `cli.main` exits non-zero on it — and the operator's string reaches no byte written
    under the episodes root.

    THE POSITIVE CONTROL IS THE SAME ARGV WITHOUT THE FLAG, because a bare absence assertion is
    also green against a launcher that launches nothing at all: it returns 0, and every sibling
    it starts is a world of the namespace derived from the episode id — the manifest's own.

    What failure looks like: the flag stays, and one hand-typed token puts an episode's world
    ledgers in a namespace no reader will ever re-derive.
    """
    cli = W.mod("learning.branch.cli")
    fam = W.mod("runtime.branch._family")

    refused_rc, refused_spawn, _ep = launch(
        tmp_path / "refused", argv_extra=("--episode-token", OPERATOR_NAMED))

    assert refused_rc != 0, (
        f"the launcher accepted --episode-token {OPERATOR_NAMED!r} and exited "
        f"{refused_rc!r} — the operator door onto the episode's namespace is still open")
    assert refused_spawn.launches == [], "the refused launch started a sibling anyway"
    root = Path(cli.episodes_root(tenant=W.current_tenant()))
    if root.is_dir():
        assert OPERATOR_NAMED not in written_bytes(root), (
            "the operator's token was written under the episodes root")

    control_rc, spawn, ep = launch(tmp_path / "control")

    assert control_rc == 0, (
        f"the control launch failed ({control_rc}); the refusal above proves nothing")
    family = fam.parse_family(W.read_yaml(ep / "family.yaml"))
    token = fam.episode_token_for(family.episode_id)
    assert spawn.worlds, "the control launch started no sibling — the absence above is vacuous"
    for label in spawn.worlds:
        world_id = fam.resume_world_from(family, label, ep).world_id
        assert world_id == fam.world_token_for(token, label), (
            f"world {label!r} resumes into {world_id!r}, not under the namespace {token!r} "
            f"derived from the manifest's own episode id {family.episode_id!r}")
    assert OPERATOR_NAMED not in written_bytes(root)


def test_an_episode_is_read_under_one_namespace(tmp_path):
    """An episode's worlds are written and read back under one namespace, and it cannot be
    built any other way.

    Observably true on a real launch, at each reader's own edge rather than at the token:
    `_family.resume_world_from` — the frame a sibling process becomes a world through —
    resolves every started world to `world_token_for(episode_token_for(episode_id), label)`
    with the episode id read back out of the manifest, and `judge.family.world_ledger_name`,
    which reads a sibling's rows back out of `served/`, names the file that same `world_id`
    writes.

    AND BY CONSTRUCTION, which no coherence assertion over one launch can reach on its own: the
    token is a function of the episode id and of nothing else. `episode_token_for` accepts no
    `override`, and `preflight_episode` accepts no `episode_token`, so no caller can hand the
    launch a namespace a reader will not re-derive. (#1224: the staged view names this once
    also pinned went with cluster staging.)

    What failure looks like: the derivation keeps a second input. A sibling then writes its
    ledger under one token while the grader reads another, and the world reads as one that
    served nothing.
    """
    cli = W.mod("learning.branch.cli")
    fam = W.mod("runtime.branch._family")
    judge_family = W.mod("learning.judge.family")

    rc, spawn, ep = launch(tmp_path)

    assert rc == 0, f"the launch failed ({rc}); nothing below observes a namespace"
    family = fam.parse_family(W.read_yaml(ep / "family.yaml"))
    token = fam.episode_token_for(family.episode_id)
    assert spawn.worlds, "the launch started no sibling"
    for label in spawn.worlds:
        resumed = fam.resume_world_from(family, label, ep).world_id
        assert resumed == fam.world_token_for(token, label), (
            f"the sibling for world {label!r} resumes into {resumed!r}, not the token derived "
            f"from the manifest's own episode id {family.episode_id!r}")
        ledger = judge_family.world_ledger_name(label, episode_token=token)
        assert ledger.rsplit("/", 1)[-1] == f"{resumed}.jsonl", (
            f"the grader reads world {label!r}'s rows from {ledger}, which is not the file "
            f"the sibling writing as {resumed!r} appends to")

    with pytest.raises(TypeError):
        fam.episode_token_for(family.episode_id, override=OPERATOR_NAMED)
    with pytest.raises(TypeError):
        cli.preflight_episode(
            source_run_dir=ep, branch_message_id=W.BRANCH_MESSAGE_ID,
            preflight=W.no_preflight, model=None, continuation_prompt="go",
            allow_dirty=False, live_tree=T.source_capture(),
            episode_token=OPERATOR_NAMED)


def test_removing_the_episode_token_flag_leaves_no_orphan_in_the_committed_spec_corpus(tmp_path):
    """Removing `--episode-token` settles the dependent this run's census missed — the committed
    spec corpus the CI ratchet reads — and not only the two production modules.

    Observably true: the flag's own spelling survives in neither production module that carried
    it (`learning/branch/cli.py`'s argument and its threading, `runtime/branch/_family.py`'s
    `override=` keyword), and `spec-flow/specs/spec_graph_947.yaml` — which minted a demand for
    this escape under FORK-4 — names a `discharged_by` that resolves to a test function that
    actually exists in `defender/tests/`, because the test it used to name is renamed by this
    change. Each holder is asserted to EXIST before it is read: a string check is green when the
    channel it looks through is not there, and that is not hypothetical in this suite — the
    sibling census `test_removing_the_flag_leaves_no_orphan_in_the_committed_spec_corpus` named a
    path that did not exist and passed on nothing until existence was asserted first.

    THIS DEPENDENT WAS FOUND BY THE RATCHET, NOT BY THE CENSUS, and that is why it has a test:
    the phase-F sweep for the flag grepped `episode_token=` and missed both the `override=`
    keyword and the graph pointer. `lint_spec_graph` reported the dangling `discharged_by` as an
    orphan on a graph whose ceiling is 0.

    What failure looks like: the flag goes, the committed graph keeps pointing at a test function
    nobody wrote, and CI fails on a corpus two directories from the diff.
    """
    repo = Path(__file__).resolve().parents[2]
    cli_py = repo / "defender" / "learning" / "branch" / "cli.py"
    family_py = repo / "defender" / "runtime" / "branch" / "_family.py"
    graph = repo / "spec-flow" / "specs" / "spec_graph_947.yaml"
    missing = [p for p in (cli_py, family_py, graph) if not p.is_file()]
    assert missing == [], (
        f"{[str(p.relative_to(repo)) for p in missing]} do not exist, so the absence below is a "
        "fact about a file nobody read")

    still_named = [p for p in (cli_py, family_py)
                   if "--episode-token" in p.read_text(encoding="utf-8")]

    assert still_named == [], (
        "these still carry the removed flag: "
        f"{[str(p.relative_to(repo)) for p in still_named]}")
    pointed_at = re.findall(r"discharged_by: (test_\w+)", graph.read_text(encoding="utf-8"))
    assert pointed_at, "the committed 947 graph names no test at all — the census read nothing"
    authored = set()
    for path in sorted((repo / "defender" / "tests").glob("*.py")):
        authored |= set(re.findall(r"^def (test_\w+)", path.read_text(encoding="utf-8"), re.M))
    dangling = sorted(name for name in pointed_at if name not in authored)
    assert dangling == [], (
        f"spec_graph_947.yaml points at {dangling}, which no test function in defender/tests/ "
        "defines — the escape's demand was left naming a test this change renamed")
