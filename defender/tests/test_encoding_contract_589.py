"""The text-IO encoding contract (#589, and #588's read/write pair).

`defender/skills/invlang/corpus.py` guarded its `read_text()` with `except OSError`. A
`UnicodeDecodeError` is a **`ValueError`, not an `OSError`**, so it escaped `_load_one`, escaped
`load_corpus` (which has no `try`), and took down `defender-invlang` — an allowed main-loop shim —
on one undecodable byte in one past run's `investigation.md`. `defender/_corpus.py` already had
this guard right, with a docstring spelling out the exact trap; invlang was a hand-rolled copy of
it that dropped half.

Two halves, and they need different tests:

- **The guard** is locale-INDEPENDENT. Any undecodable byte — a truncated write, a binary blob —
  escapes today, on any machine, under any locale. `test_an_undecodable_*` drive it in-process
  with no locale games at all; that is the point, and a test that reached for a C locale to drive
  it would be testing the wrong half.
- **The pin** is locale-dependent: it needs an ambient encoding that isn't UTF-8. Those tests use
  the subprocess + `_C_LOCALE_ENV` idiom from `test_corpus_fold_584.py::test_d5`, because the
  locale is process-wide and a *bare* `LC_ALL=C` does NOT reproduce (PEP 538 coerces it to
  C.UTF-8) — hence `PYTHONCOERCECLOCALE=0` + `PYTHONUTF8=0`.

The last test is the one a read-only suite structurally cannot catch: a pinned READ beside an
ambient WRITE (#588) does not fail loudly, it loses data — the lesson is written as latin-1,
committed, and then warn-skipped as "malformed" by every walk that reads it back.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.skills.invlang.corpus import load_corpus  # noqa: E402

WORKSPACE_ROOT = Path(__file__).resolve().parents[2]

# The locale that makes the ambient-encoding bug observable. CPython >=3.7 COERCES a bare C locale
# to C.UTF-8 (PEP 538) and would hide it, so coercion and UTF-8 mode are both disabled — the same
# env `test_corpus_fold_584.py::test_d5` and `test_corpus_hardening_586.py` use.
_C_LOCALE_ENV = {
    # The running interpreter's dir is on PATH so the `defender-invlang` shim finds a python3 when
    # the checkout has no `.venv` (a git worktree, e.g.) and falls back to the one on PATH.
    "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin",
    "PYTHONCOERCECLOCALE": "0",
    "PYTHONUTF8": "0",
    "LC_ALL": "C",
    "LANG": "C",
}

# A minimal well-formed dense companion — the three keys `_load_one` requires (prologue /
# findings / conclude), in the real block grammar (see fixtures-e2e/golden-v2sshd).
_COMPANION = """## ORIENT

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|workstation/internal/known-corp|office-ws-1|

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?local-process-ssh-to-localhost|v-001|attempted_auth|process|unclassified-process||null|active

:L findings [id|loop|name|target|tests|system|window]
l-001|1|anchor-event-fetch|v-001|h-001|elastic|±10m

:T conclude
termination.category   adversarial-confirmed
disposition            benign
confidence             high
summary                "{summary}"
```
"""


def _case(runs: Path, case_id: str, *, summary: str = "plain summary",
          investigation: bytes | None = None, alert: bytes | None = None) -> Path:
    """One run dir: investigation.md + its sibling alert.json. Written as BYTES so a case can
    carry an undecodable one without the fixture itself having to pick an encoding."""
    d = runs / case_id
    d.mkdir(parents=True)
    body = _COMPANION.format(summary=summary).encode() if investigation is None else investigation
    (d / "investigation.md").write_bytes(body)
    (d / "alert.json").write_bytes(
        json.dumps({"rule": {"id": f"sig-{case_id}"}}).encode() if alert is None else alert
    )
    return d


def test_an_undecodable_investigation_is_skipped_not_raised(tmp_path):
    """demand (#589) — `load_corpus` must warn-SKIP a file it cannot decode, exactly as it skips
    one it cannot parse. No locale games: this is the locale-INDEPENDENT half, and on `main` it
    raises `UnicodeDecodeError` straight out of the walk on a plain UTF-8 dev box.

    `loaded == 1` is the assertion that matters — it is what separates "skipped the bad file" from
    "the walk died", and a fix that swallowed the whole scan would satisfy a bare `not raises`."""
    runs = tmp_path / "runs"
    _case(runs, "good")
    _case(runs, "corrupt", investigation=b"```invlang\nprologue:\n  summary: \xff\xfe truncated\n")

    companions, report = load_corpus(runs)  # must not raise

    assert report.scanned == 2
    assert report.loaded == 1
    assert [c.case_id for c in companions] == ["good"]
    (skipped_path, reason), = report.skipped
    assert skipped_path.parent.name == "corrupt"
    # The report's message contract — `defender-invlang` prints these skip reasons to the model.
    assert reason.startswith("read error:")


def test_an_undecodable_alert_json_degrades_the_signature_it_does_not_sink_the_case(tmp_path):
    """demand (#589) — the same escape lives a second time in the same file, in
    `_read_signature_id`, and the issue does not mention it. Its guard was
    `except (OSError, json.JSONDecodeError)` — and `JSONDecodeError` is a *sibling* of
    `UnicodeDecodeError` under `ValueError`, not its superclass, so it does not hold one either.

    `alert.json` is vendor-supplied bytes, i.e. the likeliest undecodable file in the run dir. A
    signature that can't be read costs the case its cross-case join key; it must not cost the
    corpus the whole case, and it must not kill the shim."""
    runs = tmp_path / "runs"
    _case(runs, "badalert", alert=b'{"rule": {"id": "sig-\xff\xfe"}}')

    companions, report = load_corpus(runs)  # must not raise

    assert report.loaded == 1
    assert companions[0].case_id == "badalert"
    assert companions[0].signature_id is None  # degraded, not skipped, not raised


def _c_locale_python(script: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, env=_C_LOCALE_ENV,
    )


def test_the_read_pin_keeps_a_valid_utf8_case_under_a_c_locale(tmp_path):
    """demand (#589, the latent half) — a *valid* UTF-8 companion must load where the ambient
    encoding is ascii. Unpinned, `read_text()` raises `UnicodeDecodeError` on the em-dash, the new
    guard warn-skips it, and the case vanishes from the corpus: silent data loss wearing a
    malformed-file costume, invisible on a UTF-8 dev machine.

    The ascii control case is what distinguishes "the em-dash case was dropped" from "the walk
    died"; `enc=` is asserted because without it the C locale may not have taken and the test
    proves nothing."""
    runs = tmp_path / "runs"
    _case(runs, "emdash", summary="auth-log leads expose logins — not post-auth behavior")
    _case(runs, "ascii")

    proc = _c_locale_python(
        f"import sys; sys.path.insert(0, {str(WORKSPACE_ROOT)!r})\n"
        "import locale\n"
        "from pathlib import Path\n"
        "from defender.skills.invlang.corpus import load_corpus\n"
        "print('enc=' + locale.getencoding())\n"
        f"companions, report = load_corpus(Path({str(runs)!r}))\n"
        "print('loaded=' + ','.join(sorted(c.case_id for c in companions)))\n"
    )

    assert proc.returncode == 0, f"the corpus walk crashed under a C locale:\n{proc.stderr}"
    assert "enc=ANSI_X3.4-1968" in proc.stdout, f"the C locale did not take: {proc.stdout!r}"
    assert "loaded=ascii,emdash" in proc.stdout, "the em-dash case was lost, not read"


def test_the_real_invlang_shim_prints_corpus_text_under_a_c_locale(tmp_path):
    """demand (#589 / the #586 finding, one skill over) — end-to-end through the REAL
    `defender-invlang` shim, the command the defender runs at PLAN. Pinning the read without
    pinning stdout only moves the ascii crash from `read_text` to `print`.

    Driven through a RENDERER subcommand on purpose: the `--json` paths are already ascii-safe via
    `json.dump`'s `ensure_ascii=True`, so a JSON subcommand would pass unpinned and prove nothing.
    Asserted on the em-dash reaching stdout, not merely on exit 0 — a CLI that "handled" the error
    by dropping the case would satisfy the exit code."""
    runs = tmp_path / "runs"
    _case(runs, "emdash", summary="auth-log leads expose logins — not post-auth behavior")

    proc = subprocess.run(
        [str(WORKSPACE_ROOT / "defender" / "bin" / "defender-invlang"),
         "hypothesis-vocabulary", "--signature", "sig-emdash"],
        capture_output=True, text=True, encoding="utf-8",
        env={**_C_LOCALE_ENV,
             "DEFENDER_DIR": str(WORKSPACE_ROOT / "defender"),
             "DEFENDER_RUNS_BASE": str(runs)},
    )

    assert proc.returncode == 0, f"defender-invlang died under a C locale:\n{proc.stderr}"
    assert "Traceback" not in proc.stderr
    # The renderer's own header carries an em-dash, so an unpinned stdout dies on the way out even
    # before the corpus text reaches it...
    assert "—" in proc.stdout, "stdout is still decoding under the ambient locale"
    # ...and the ?name row proves the em-dash-bearing case was READ, not warn-skipped as malformed.
    assert "?local-process-ssh-to-localhost" in proc.stdout


def _curator_deps(tmp_path: Path):
    """A real `AgentDeps` for the corpus-author agent — enough to drive `runtime/tools.py`'s
    write/read tools directly, gate and all. Mirrors `test_lesson_read_tool.py`'s scene. Imported
    by the C-locale subprocess below too, so both processes build the same scene."""
    from defender.learning.author.curator_engine import CuratorDeps
    from defender.learning.author.verify_forward.checks import FINDINGS_CHECK

    repo = tmp_path / "wt"
    corpus = repo / "defender" / "lessons"
    corpus.mkdir(parents=True, exist_ok=True)
    runs = tmp_path / "runs"
    runs.mkdir(exist_ok=True)
    pending = tmp_path / "_pending" / "findings.jsonl"
    pending.parent.mkdir(parents=True, exist_ok=True)
    pending.write_text("", encoding="utf-8")
    deps = CuratorDeps.for_run(
        pending.parent, repo, corpus, check=FINDINGS_CHECK, runs_dir=runs,
        pending=pending, queued_ids=frozenset(), run_verify=lambda **kw: "",
    )
    return deps, corpus


def test_a_lesson_the_runtime_wrote_survives_the_walk_that_reads_it_back(tmp_path):
    """demand (#588) — the read pin and the WRITE pin are ONE contract, and only a round trip under
    a hostile locale catches the gap between them. An ambient-locale write beside a utf-8-pinned
    read does not crash, it LOSES: a lesson containing `café` is written as latin-1 bytes,
    committed to the corpus, and then warn-skipped as "malformed" by every walk that reads it back
    — including the actor's retrieval mid-run.

    Driven through the REAL `write_file` tool (gate included) and read back through the real corpus
    walk, in a C-locale subprocess. Both halves are load-bearing: in-process on a UTF-8 dev box an
    unpinned write emits the same bytes as a pinned one, so the test would be vacuous — which is
    exactly the blind spot that let #588 stand. The non-ASCII char is spelled as an escape because
    under `LC_ALL=C` the interpreter cannot decode a `-c` command line carrying a raw `é`."""
    proc = _c_locale_python(
        f"import sys; sys.path.insert(0, {str(WORKSPACE_ROOT)!r})\n"
        "import locale\n"
        "from pathlib import Path\n"
        "from defender.runtime import tools\n"
        "from defender._corpus import iter_lessons\n"
        # the same scene this module's in-process tests use — one definition, two processes
        "from defender.tests.test_encoding_contract_589 import _curator_deps\n"
        "print('enc=' + locale.getencoding())\n"
        f"deps, corpus = _curator_deps(Path({str(tmp_path)!r}))\n"
        "body = '---\\nname: cafe\\ndescription: le caf\\u00e9\\n---\\nbody\\n'\n"
        "tools._tool_write_file(deps, 'defender/lessons/cafe.md', body)\n"
        "raw = (corpus / 'cafe.md').read_bytes()\n"
        "print('utf8_bytes=' + str(raw == body.encode('utf-8')))\n"
        "print('walked=' + ','.join(le.fm['name'] for le in iter_lessons(corpus)))\n"
    )

    assert proc.returncode == 0, f"the runtime write/read round trip died under a C locale:\n{proc.stderr}"
    assert "enc=ANSI_X3.4-1968" in proc.stdout, f"the C locale did not take: {proc.stdout!r}"
    assert "utf8_bytes=True" in proc.stdout, "the runtime wrote the lesson under the ambient locale"
    assert "walked=cafe" in proc.stdout, "the lesson was written, then lost by the walk that read it"


def test_an_undecodable_file_is_a_model_retry_not_a_stage_kill(tmp_path):
    """demand (#588) — pinning the runtime's read is necessary but not sufficient: on a genuinely
    undecodable file `read_text(encoding="utf-8")` still raises `UnicodeDecodeError`, and no gate
    converts a `ValueError`, so it escapes the tool and takes the whole stage down. The agent can
    act on "that file isn't text"; the run cannot act on a traceback. Locale-independent."""
    from pydantic_ai.exceptions import ModelRetry

    from defender.runtime import tools

    deps, corpus = _curator_deps(tmp_path)
    (corpus / "corrupt.md").write_bytes(b"---\nname: x\ndescription: \xff\xfe\n---\nbody\n")

    with pytest.raises(ModelRetry, match="not valid UTF-8"):
        tools._tool_read_file(deps, "defender/lessons/corrupt.md")


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses the mode bits this drives")
def test_an_unreadable_file_is_a_model_retry_too_not_a_stage_kill(tmp_path):
    """`read_text_utf8` is documented to raise TEXT_READ_ERRORS — BOTH halves. The decode half is
    converted to a ModelRetry; the `OSError` half escaped, on the same argument that condemned the
    decode half. `is_file()` is not a read-permission check (the gate is a policy gate, not a
    filesystem one) and it races the read besides."""
    from pydantic_ai.exceptions import ModelRetry

    from defender.runtime import tools

    deps, corpus = _curator_deps(tmp_path)
    unreadable = corpus / "locked.md"
    unreadable.write_text("---\nname: x\n---\nbody\n", encoding="utf-8")
    unreadable.chmod(0o000)

    with pytest.raises(ModelRetry, match="could not read"):
        tools._tool_read_file(deps, "defender/lessons/locked.md")


def test_use_utf8_stdio_moves_the_encoding_and_leaves_the_error_handler_alone():
    """`reconfigure(encoding=…)` with no `errors=` silently RESETS the handler to `strict`, and the
    defaults it clobbers are load-bearing: stderr is `backslashreplace` so an error path can never
    itself raise, stdout is `surrogateescape` so a non-UTF-8 filename — what `Path.glob` hands back
    as lone surrogates — prints instead of exploding.

    The failure it buys is exquisite: `iter_lessons` warn-skips a bad lesson, then dies with a
    `UnicodeEncodeError` printing the path it just skipped. A pin that hardens the read by breaking
    the skip message is not hardening. Driven in a subprocess because stdio is process-wide."""
    proc = _c_locale_python(
        f"import sys; sys.path.insert(0, {str(WORKSPACE_ROOT)!r})\n"
        "from defender._io import use_utf8_stdio\n"
        "use_utf8_stdio()\n"
        "print('handlers=' + sys.stdout.errors + ',' + sys.stderr.errors)\n"
        "print('encodings=' + sys.stdout.encoding + ',' + sys.stderr.encoding)\n"
        # the em-dash the pin exists for...
        "print('emdash=\\u2014')\n"
        # ...and the surrogate-bearing path name a strict handler would explode on
        "print('warn: skipping ' + 'caf\\udce9.md', file=sys.stderr)\n"
        "print('survived=True')\n"
    )

    assert proc.returncode == 0, f"use_utf8_stdio broke its own callers:\n{proc.stderr}"
    assert "encodings=utf-8,utf-8" in proc.stdout, f"the pin did not take: {proc.stdout!r}"
    assert "handlers=surrogateescape,backslashreplace" in proc.stdout, (
        f"use_utf8_stdio reset the error handlers to strict: {proc.stdout!r}"
    )
    assert "emdash=—" in proc.stdout
    assert "survived=True" in proc.stdout


def test_a_vendor_byte_on_the_adapter_pipe_is_replaced_not_raised(tmp_path):
    """The gather ingestion boundary. `record_query.capture` runs the adapter IN-PROCESS (via
    `tools_gather._capture_query`), and the adapter's stdout is vendor telemetry — indexed log
    lines, process cmdlines, filenames — i.e. the likeliest non-UTF-8 byte in the whole system.

    A `subprocess.run(..., text=True, encoding="utf-8")` decodes STRICTLY, so one such byte raises
    `UnicodeDecodeError` inside `run()`. It is a `ValueError`: it sails past the `TimeoutExpired`
    guard, out of `capture()`, out of the gather tool, and kills the stage — the same escape as
    #589, one pipe over. One bad byte must cost one character, not the lead and not the run."""
    from defender.scripts.gather_tools import record_query

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    emit_bad_bytes = [
        sys.executable, "-c",
        r'import sys; sys.stdout.buffer.write(b"{\"host\": \"caf\xe9-01\"}")',
    ]

    passthrough, _stderr, record = record_query.capture(  # must not raise
        run_dir, "l-001", emit_bad_bytes, system="elastic",
    )

    assert record["exit_code"] == 0, "the adapter itself failed — wrong thing under test"
    assert "�" in passthrough, "the undecodable byte was not replaced"
    assert "caf" in passthrough, "the payload before the bad byte was lost"
    assert "-01" in passthrough, "the payload after the bad byte was lost"
    payload = (run_dir / record["payload_path"]).read_text(encoding="utf-8")
    assert "�" in payload, "the by-ref payload defender-sql reads back was not written"
