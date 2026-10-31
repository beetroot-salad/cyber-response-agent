"""#1163 O4 canary census after a real run: `run.main` with production's lifecycle and driver
over replay models, the real identity adapter, the real proxy on loopback and a fake upstream
that echoes the Authorization header. Also the static scan of adapter code."""
from __future__ import annotations

import functools
import logging
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender import box as box_mod  # noqa: E402
from defender._paths import adapters_under  # noqa: E402
from defender.systems.verbs import read_roster  # noqa: E402
from defender.tests.e2e import _replay_harness as RH  # noqa: E402
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A  # noqa: E402
from defender.tests.integrations.credential_proxy_1163 import _harness as H  # noqa: E402
from defender.tests.integrations.credential_proxy_1163 import _tenant as T  # noqa: E402
from defender.tests.integrations.credential_proxy_1163._target import proxy  # noqa: E402
from defender.tests.support.tenancy import _tenants1106 as T6  # noqa: E402
from defender.tests.support.tenancy._launch_publish_p4 import in_process_publish  # noqa: E402
from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S  # noqa: E402

pytestmark = pytest.mark.e2e

API = "/api/v2"
TENANT = "0b8f6a52-1163-4c1e-9d0e-6f2b3a4c5d70"
ARGV_MARKER = "CENSUS-ARGV-MARKER-1163"
ENV_MARKER = "census-env-marker-1163"


class ExecSeam:
    """The box seam (`start_box`): an unboxed executor whose transport records each frame (the
    commands' argv) and the environment its children get, then forwards."""

    def __init__(self) -> None:
        self.frames: list[bytes] = []
        self.envs: list[dict[str, str]] = []

    def __call__(self, *_a, **_k):
        inner = box_mod.unboxed_executor()

        def transport(frame, *, cwd, timeout):
            self.frames.append(frame)
            self.envs.append(dict(inner.transport.env))
            return inner.transport(frame, cwd=cwd, timeout=timeout)

        return box_mod.BoxExecutor(spec=inner.spec, transport=transport, name="")


def test_o4_no_canary_reaches_any_channel_of_a_real_run(tmp_path, data_root, monkeypatch,
                                                         caplog, capsys):
    """The key, the request token and its signature are absent from the run's files, logs, box
    commands and environment and the text the models saw; the token reaches the proxy and the
    query tool's grant is a read on the http-proxy system only. O4, O10, A7."""
    run_py = S.mod("run")

    caplog.set_level(logging.DEBUG)
    monkeypatch.setenv("DEFENDER_CENSUS_1163", ENV_MARKER)
    configs = {**T6.config_texts(TENANT), "identity": A.env_text("identity")}
    with H.upstream() as up:
        planted = S.plant_tenant(TENANT, alert_mapping=S.DEFAULT_MAPPING, table=T6.TABLE_B,
                                 configs=configs)
        for rel, text in H.access_files("identity", H.declaration(up.url + API)).items():
            (planted.knowledge / rel).parent.mkdir(parents=True, exist_ok=True)
            (planted.knowledge / rel).write_text(text, encoding="utf-8")
        store = H.FakeStore({(TENANT, "identity"): T.static_set()})
        app = proxy().create_app(T.deps({TENANT: data_root / TENANT / "exports"}, store))
        tap = A.Tap(app)
        signer, seam = A.MarkedSigner(), ExecSeam()
        main = S.MainScript([
            S.call("bash", command=f"echo {ARGV_MARKER}"),
            S.gather("l-001", "identity", goal="look up dev.dana"), S.text(S.DONE)])
        router = S.LeadRouter({"l-001": [
            S.call("query", system="identity", verb="get-user", params={"user": "dev.dana"}),
            S.text("Summary: asked identity about dev.dana.")]})
        investigate = functools.partial(
            run_py._drive_investigation, investigate=RH.investigate_as_handed(main, router))

        def lifecycle(**kw):
            return run_py._run_investigation_lifecycle(
                **kw, investigate=investigate, start_box=seam,
                stop_box=lambda *_a, **_k: None, scrub=lambda *_a, **_k: None)

        alert = S.operator_input(tmp_path)
        alert.parent.mkdir(parents=True, exist_ok=True)
        alert.write_bytes(S.alert_bytes({"rule": {"id": "R-1", "description": "census"},
                                         "timestamp": "2026-09-28T00:00:00Z"}))
        with H.serve_asgi(tap) as proxy_url:
            rc = run_py.main(
                [str(alert), "--tenant", TENANT, "--no-learn"], lifecycle=lifecycle,
                preflight=lambda *_a, **_k: 0, visualize=lambda *_a, **_k: None,
                ticket_writer=S.NoTicket(), enqueue=lambda *_a, **_k: False,
                roster=read_roster(adapters_under(S.DEFENDER)), publish=in_process_publish(),
                signer=signer, proxy_url=proxy_url)

    assert rc == 0
    assert [A.grant_of(A.claims_of_payload(p)) for p in signer.payloads] == [[("identity", "r")]]
    assert tap.tokens
    assert all(A.SIGNATURE_CANARY in tok for tok in tap.tokens)
    assert [s.headers.get("Authorization") for s in up.seen] == [f"Bearer {H.CANARY_KEY}"]

    out = capsys.readouterr()
    channels = {
        "files": A.text_of(data_root, tmp_path),
        "logs": caplog.text + out.out + out.err,
        "box frames": b"\n".join(seam.frames).decode("utf-8", "replace"),
        "box env": "\n".join(f"{k}={v}" for e in seam.envs for k, v in e.items()),
        "models saw": "\n".join(
            [m.text for m in main.seen]
            + [m.text for script in router.by_lead.values() for m in script.seen]),
    }
    controls = {"files": f"{API}/users/dev.dana", "logs": "run_dir=", "box frames": ARGV_MARKER,
                "box env": ENV_MARKER, "models saw": "census"}
    secrets = [H.CANARY_KEY, A.SIGNATURE_CANARY, *tap.tokens]
    for name, text in channels.items():
        assert controls[name] in text, f"positive control: the {name} channel is not read"
        for secret in secrets:
            assert secret not in text, f"a canary reached the {name} channel"


def test_o4_adapter_code_names_no_credential_field():
    """No adapter module names a declared credential field or a credential accessor. O4, H6.
    Regression guard: it passes on the code as it stands and fails if one is added."""
    import defender.integrations as integrations

    offenders = {}
    for path in sorted(Path(integrations.__file__).parent.glob("*.py")):
        hit = sorted(n for n in A.code_names(path) if A.CREDENTIAL_NAME.search(n))
        if hit:
            offenders[path.name] = hit
    assert offenders == {}
    planted = Path(__file__).parent / "_planted_scan_probe.txt"
    assert A.CREDENTIAL_NAME.search("client_secret"), (
        "positive control: the scan's pattern matches a credential field name")
    assert not planted.exists(), "the planted probe file was left behind"
