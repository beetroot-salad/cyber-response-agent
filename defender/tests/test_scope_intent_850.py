"""#850 — two run-dir scopes that did not say what their design says they say.

Both defects are the same class: a permission scope whose SPELLING drifted from the intent it
encodes, in opposite directions. Neither could be caught by reading the scope, because each was
internally consistent — the drift is only visible against the OTHER half of the system, which is
what these tests hold in one place.

  F-09 (correctness, fail-CLOSED) — `policies/_common.read_shapes` spelled the gather payload
        family `gather_raw/l-\\d+/\\d+\\.json` while every lead-id validator in the system —
        `record_lead.LEAD_ID_RE`, `record_query.LEAD_ID_RE` (the only pre-dispatch gate),
        `lead_repository._LEAD_ID_RE`, `invlang.parser._LEAD_PREFIX_RE` — accepts
        `l-[A-Za-z0-9]+`. Nothing enforces the documented `l-NNN` spelling, so a main loop that
        minted `l-auth1` produced a payload that the query tool handed gather by path and told it
        to `cat`, and that gather's own `cat` grant and `read_file` shapes then refused. Latent,
        never fired (every recorded id is numeric) — which is exactly why it needs a pin rather
        than a fixture.

  F-19 (security, fail-OPEN) — `persist._copy_shared_inputs` + `lead_repository.stage_tables`
        stage the source run's investigation.md, report.md, source_refs.yaml and
        executed_queries.jsonl into `<learning_run_dir>/`, which IS the gray-box actor's own
        `run_dir` and therefore an unconditional read root it declares no shapes over. The
        `gather_raw` carve-out closes the payloads; nothing closed the case's own reasoning and
        disposition. Not present on a clean first pass, because persist runs after that leg's
        actor — but the dir is `mkdir(exist_ok=True)` with no cleanup and no once-only guard, so
        the second pass over a run id (a hand re-drive, `ops/replay_actor.py`, the sibling leg's
        persist landing first on an `inconclusive` case) starts the actor in a dir already
        holding them.

Written against the real seams: ids go through `claim_lead` and `persist_payload`, decisions come
out of `decide_bash`/`decide_read` on policies compiled by `compile_policy_for`/`bind`. Each deny
is paired with the positive control that keeps the fix from being "deny more" — gather still reads
a numeric payload, the judge still reads the investigation it grades, and the actor still reads
the corpus and the alert its role IS given.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("pydantic_ai")

from defender import _run_paths  # noqa: E402
from defender.agents import GATHER_DEF, MAIN_DEF  # noqa: E402
from defender.hooks.record_lead import CLAIMED, LEAD_ID_RE, claim_lead  # noqa: E402
from defender.learning.core import persist  # noqa: E402
from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_definition import (  # noqa: E402
    compile_policy_for,
)
from defender.scripts.gather_tools.record_query import persist_payload  # noqa: E402

#: A lead id the model is free to mint and never has: `LEAD_ID_RE` admits it, the documented
#: spelling (`defender/SKILL.md`'s `lead_id="l-NNN"`, every invlang example `l-001`) does not,
#: and no gate anywhere between the `:L findings` row and the payload read enforces the
#: documentation. That gap is the whole trigger, so the pin uses a lettered id throughout.
LETTERED = "l-2b"
NUMERIC = "l-001"


@pytest.fixture
def env(tmp_path):
    """A run dir and a defender tree, both real on disk — `decide_read` resolves, so symlink and
    parent comparisons need files that exist."""
    run = tmp_path / "run"
    (run / "gather_summaries").mkdir(parents=True)
    for name in ("alert.json", "investigation.md", "report.md", "executed_queries.jsonl",
                 "source_refs.yaml"):
        (run / name).write_text("{}\n", encoding="utf-8")
    dfn = tmp_path / "defender"
    (dfn / "lessons").mkdir(parents=True)
    (dfn / "lessons" / "x.md").write_text("x\n", encoding="utf-8")
    return SimpleNamespace(run=run, dfn=dfn, tmp=tmp_path)


def _bash(env, cmd, policy):
    return permission.decide_bash(cmd, policy=policy, run_dir=env.run, defender_dir=env.dfn)


def _read(env, path, policy, *, run_dir=None):
    return permission.decide_read(
        Path(path), run_dir=run_dir if run_dir is not None else env.run,
        defender_dir=env.dfn, policy=policy,
    )


def _gather(env):
    return compile_policy_for(GATHER_DEF, run_dir=env.run, defender_dir=env.dfn)






# F-09 — the payload shape and the lead-id validators are ONE alphabet

def test_f09_a_lettered_lead_id_survives_claim_persist_and_the_read_gate(env):
    """The end-to-end path the defect broke: a lettered id is CLAIMED, its payload is PERSISTED
    at the path the query tool then hands gather, and gather may `cat` and `read_file` that exact
    path. Driven through the real functions rather than a hand-spelled path, because the bug was
    a disagreement between what one of them writes and what another admits."""
    assert claim_lead({
        "run_dir": str(env.run), "lead_id": LETTERED,
        "goal": "who logged in", "what_to_summarize": ["actor"],
    }) == CLAIMED, "the claim gate accepts a lettered id — that is the premise, not the defect"

    rel = persist_payload(env.run, LETTERED, 0, '{"hits": []}')
    assert rel == f"gather_raw/{LETTERED}/0.json", (
        f"the payload the query tool tells gather to read is {rel!r}")
    payload = env.run / rel

    gather = _gather(env)
    assert _bash(env, f"cat {payload}", gather).allow, (
        "gather is denied the payload its own query tool just wrote for it (#850 F-09)")
    assert _read(env, payload, gather).allow, (
        "read_file and the cat grant share the shape OBJECT — they cannot disagree here")


def test_f09_the_gate_and_the_validators_share_one_alphabet(env):
    """The property, not the instance: for EVERY id the claim gate accepts, the payload it mints
    is readable by gather. Pinned as a shared spelling too, so a future edit to one site is a
    test failure rather than a second silent drift."""
    assert f"gather_raw/l-{_run_paths.LEAD_ID_BODY}/[0-9]+\\.json" == _run_paths.GATHER_RAW_SHAPE
    assert f"^l-{_run_paths.LEAD_ID_BODY}\\Z" == LEAD_ID_RE.pattern

    gather = _gather(env)
    for lead in (NUMERIC, LETTERED, "l-auth1", "l-A", "l-0", "l-999", "l-Ab9z"):
        assert LEAD_ID_RE.match(lead), f"{lead} is outside the lead-id namespace"
        assert claim_lead({"run_dir": str(env.run), "lead_id": lead, "goal": "g",
                           "what_to_summarize": ["x"]}) == CLAIMED
        rel = persist_payload(env.run, lead, 3, "{}")
        assert _read(env, env.run / rel, gather).allow, f"gather cannot read its own {rel}"


def test_f09_the_widening_stays_shut(env):
    """The fix widened the ALPHABET, not the family. The denials `test_grant_gate_575.py::test_a4`
    holds still hold, and `[0-9]` closes the Unicode-digit door `\\d` carried: `٣.json` is a
    filename no writer produces (`seq` is `f"{int}"`) and a str `\\d` admitted it."""
    gather = _gather(env)
    for bad in (f"gather_raw/{NUMERIC}/evil.sh", "gather_raw/evil.json",
                f"gather_raw/{NUMERIC}/٣.json", "gather_raw/l-a b/0.json",
                f"gather_raw/{NUMERIC}/sub/0.json", "gather_raw/x-001/0.json"):
        target = env.run / bad
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("{}\n", encoding="utf-8")
        assert not _read(env, target, gather).allow, f"{bad} is not a payload family member"
        assert not _bash(env, f"cat {target}", gather).allow, f"cat {bad} must deny too"


def test_f09_main_is_still_denied_the_payload_either_way(env):
    """The direction of the fix matters: it may not turn the fail-closed error into a fail-open
    one. MAIN never carries the raw shape, so the widened alphabet must not reach it."""
    main = compile_policy_for(MAIN_DEF, run_dir=env.run, defender_dir=env.dfn)
    rel = persist_payload(env.run, LETTERED, 0, "{}")
    denial = _read(env, env.run / rel, main)
    assert not denial.allow
    assert "gather_raw" in denial.reason


# F-19 — a confined agent's own run dir is not a hole in its confine

def _staged(env, run_dir):
    """A learning run dir in the state the SECOND pass over a run id starts the actor in: the
    previous pass's `persist_run` already staged the case into it. Uses the real
    `_copy_shared_inputs`, so a change to what persist stages shows up here."""
    persist._copy_shared_inputs(env.run, run_dir)
    (run_dir / "source_refs.yaml").write_text("normalized_disposition: malicious\n",
                                              encoding="utf-8")
    (run_dir / "executed_queries.jsonl").write_text("{}\n", encoding="utf-8")
    return run_dir












def test_f19_main_still_reads_its_own_run_artifacts(env):
    """The other control: the run's OWN agents write and re-read these files. MAIN declares no
    confine, so nothing about its access to its own investigation changed."""
    main = compile_policy_for(MAIN_DEF, run_dir=env.run, defender_dir=env.dfn)
    assert main.read_confine == ()
    for name in ("investigation.md", "report.md"):
        assert _read(env, env.run / name, main).allow
        assert _bash(env, f"cat {env.run / name}", main).allow
