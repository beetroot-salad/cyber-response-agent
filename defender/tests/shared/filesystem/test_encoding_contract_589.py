"""Text-IO encoding contract: undecodable files are skipped or retried not raised, utf-8 pins hold under a C locale, vendor bytes are replaced."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.skills.invlang.corpus import load_corpus  # noqa: E402
from defender.tests.support.shared.contracts._locale import C_LOCALE_ENV  # noqa: E402
from defender.tests.support.storage._alert_plant import plant_alert

WORKSPACE_ROOT = Path(__file__).resolve().parents[4]


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
    """One run dir: investigation.md + its alert input directory (alert and record). The
    companion is written as BYTES so a case can carry an undecodable one without the fixture
    itself having to pick an encoding."""
    d = runs / case_id
    d.mkdir(parents=True)
    body = _COMPANION.format(summary=summary).encode() if investigation is None else investigation
    (d / "investigation.md").write_bytes(body)
    plant_alert(d, {"rule": {"id": f"sig-{case_id}"}} if alert is None else alert)
    return d


def test_an_undecodable_investigation_is_skipped_not_raised(tmp_path):
    """demand (#589) — `load_corpus` must warn-SKIP a file it cannot decode, exactly as it skips one
    it cannot parse."""
    runs = tmp_path / "runs"
    _case(runs, "good")
    _case(runs, "corrupt", investigation=b"```invlang\nprologue:\n  summary: \xff\xfe truncated\n")

    companions, report = load_corpus(runs)

    assert report.scanned == 2
    assert report.loaded == 1
    assert [c.case_id for c in companions] == ["good"]
    (skipped_path, reason), = report.skipped
    assert skipped_path.parent.name == "corrupt"
    assert reason.startswith("read error:")


def test_an_undecodable_alert_json_degrades_the_signature_it_does_not_sink_the_case(tmp_path):
    """demand (#589) — the same escape lives a second time in the same file, in
    `_read_signature_id`, and the issue does not mention it."""
    runs = tmp_path / "runs"
    _case(runs, "badalert", alert={"alert_id": "no-signature-here"})

    companions, report = load_corpus(runs)

    assert report.loaded == 1
    assert companions[0].case_id == "badalert"
    assert companions[0].signature_id is None


def _c_locale_python(script: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, env=C_LOCALE_ENV,
    )


def test_the_read_pin_keeps_a_valid_utf8_case_under_a_c_locale(tmp_path):
    """demand (#589, the latent half) — a *valid* UTF-8 companion must load where the ambient
    encoding is ascii."""
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
    """demand (#589 / the #586 finding, one skill over) — end-to-end through the REAL `defender-
    invlang` shim, the command the defender runs at PLAN."""
    runs = tmp_path / "runs"
    _case(runs, "emdash", summary="auth-log leads expose logins — not post-auth behavior")

    proc = subprocess.run(
        [str(WORKSPACE_ROOT / "defender" / "bin" / "defender-invlang"),
         "hypothesis-vocabulary", "--signature", "sig-emdash"],
        capture_output=True, text=True, encoding="utf-8",
        env={**C_LOCALE_ENV,
             "DEFENDER_DIR": str(WORKSPACE_ROOT / "defender"),
             "DEFENDER_RUNS_BASE": str(runs)},
    )

    assert proc.returncode == 0, f"defender-invlang died under a C locale:\n{proc.stderr}"
    assert "Traceback" not in proc.stderr
    assert "—" in proc.stdout, "stdout is still decoding under the ambient locale"
    assert "?local-process-ssh-to-localhost" in proc.stdout


def _curator_deps(tmp_path: Path):
    """A real `AgentDeps` for the corpus-author agent — enough to drive `runtime/tools.py`'s
    write/read tools directly, gate and all. Mirrors `test_lesson_read_tool.py`'s scene. Imported
    by the C-locale subprocess below too, so both processes build the same scene."""
    from defender.learning.author.curator_engine import CuratorDeps

    repo = tmp_path / "wt"
    corpus = repo / "defender" / "lessons"
    corpus.mkdir(parents=True, exist_ok=True)
    pending_dir = tmp_path / "_pending"
    pending_dir.mkdir(parents=True, exist_ok=True)
    deps = CuratorDeps.for_run(
        pending_dir,
        repo,
        corpus,
        box=None,
    )
    return deps, corpus


def test_a_lesson_the_runtime_wrote_survives_the_walk_that_reads_it_back(tmp_path):
    """demand (#588) — the read pin and the WRITE pin are ONE contract, and only a round trip under
    a hostile locale catches the gap between them."""
    proc = _c_locale_python(
        f"import sys; sys.path.insert(0, {str(WORKSPACE_ROOT)!r})\n"
        "import locale\n"
        "from pathlib import Path\n"
        "from defender.runtime import tools\n"
        "from defender.knowledge._corpus import iter_lessons\n"
        "from defender.tests.shared.filesystem.test_encoding_contract_589 import _curator_deps\n"
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
    from pydantic_ai.exceptions import ModelRetry

    from defender.runtime import tools

    deps, corpus = _curator_deps(tmp_path)
    (corpus / "corrupt.md").write_bytes(b"---\nname: x\ndescription: \xff\xfe\n---\nbody\n")

    with pytest.raises(ModelRetry, match="not valid UTF-8"):
        tools._tool_read_file(deps, "defender/lessons/corrupt.md")


@pytest.mark.skipif(os.geteuid() == 0, reason="root bypasses the mode bits this drives")
def test_an_unreadable_file_is_a_model_retry_too_not_a_stage_kill(tmp_path):
    from pydantic_ai.exceptions import ModelRetry

    from defender.runtime import tools

    deps, corpus = _curator_deps(tmp_path)
    unreadable = corpus / "locked.md"
    unreadable.write_text("---\nname: x\n---\nbody\n", encoding="utf-8")
    unreadable.chmod(0o000)

    with pytest.raises(ModelRetry, match="could not read"):
        tools._tool_read_file(deps, "defender/lessons/locked.md")


def test_use_utf8_stdio_moves_the_encoding_and_leaves_the_error_handler_alone():
    proc = _c_locale_python(
        f"import sys; sys.path.insert(0, {str(WORKSPACE_ROOT)!r})\n"
        "from defender._io import use_utf8_stdio\n"
        "use_utf8_stdio()\n"
        "print('handlers=' + sys.stdout.errors + ',' + sys.stderr.errors)\n"
        "print('encodings=' + sys.stdout.encoding + ',' + sys.stderr.encoding)\n"
        "print('emdash=\\u2014')\n"
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


def test_a_vendor_byte_from_a_transport_is_replaced_not_raised(tmp_path):
    """The gather ingestion boundary, re-pointed at the TRANSPORT (#611)."""
    from defender.integrations import _stub_transport as transport
    from defender.runtime.verbs import VerbContext
    from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    docker = fake_bin / "docker"
    docker.write_text("#!/bin/sh\nprintf '{\"host\": \"caf\\351-01\"}'\n")
    docker.chmod(0o755)

    env = {"PATH": f"{fake_bin}:{os.environ.get('PATH', '')}"}
    folder = S.plant(tmp_path / "tenants")
    S.set_key(folder, "host-state", "HOST_STATE_DOCKER_CONTEXT", "test-ctx")
    ctx = VerbContext(defender_dir=tmp_path, run_dir=tmp_path, env=env,
                      tenant=S.resolve(tmp_path / "tenants"))

    rc, stdout, _stderr = transport.docker_exec_raw(ctx, "bastion", ["cat", "/x"],
                                                    system="host-state")

    assert rc == 0, "the fake docker exec failed — wrong thing under test"
    assert "�" in stdout, "the undecodable byte was not replaced"
    assert "caf" in stdout, "the payload before the bad byte was lost"
    assert "-01" in stdout, "the payload after the bad byte was lost"
