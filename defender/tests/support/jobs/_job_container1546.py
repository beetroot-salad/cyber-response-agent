"""#1546 e2e: what runs INSIDE the job container (`runsc-job`): the job's side of the evidence protocol over the job socket,
with the real renderer. Makes its run folder in its own root (a copy of the golden run), renders the page (bytes) with the
real renderer, sends its outcome, stages `page`, packs and pushes its bundle and page, and writes `probe.json` into its own
root: what it could and could not open. Socket verbs and record shapes come from `support/evidence/_facts1546.py`.
Runs only in CI (a real container)."""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
from pathlib import Path

from defender import job_host
from defender.presentation import visualize_run
from defender.tests.support.evidence._facts1546 import (
    BUNDLE,
    RUN_PAGE,
    VERB_OUTCOME,
    VERB_PAGE,
    VERB_PUT,
    closing_found,
    sent_inv_outcome,
    sent_page,
)
from defender.tests.support.shared.contracts._spec1077 import fixture_run

argv = sys.argv[1:]
inv, tenant = argv[argv.index("--job") + 1], argv[argv.index("--tenant") + 1]
root = Path(os.environ["DEFENDER_DATA_ROOT"])
folder = root / tenant
golden = Path(__file__).resolve().parents[2] / "fixtures" / "e2e" / "golden-v2sshd"
run = folder / "runs" / inv
shutil.copytree(golden, run)
page = visualize_run.render_page(fixture_run(run)).encode("utf-8")

probe: dict = {"cwd_root": str(root)}
for name, path in {"outside_tenant_folder": str(root.parent / "canary"), "data_root_parent": str(root.parent)}.items():
    try:
        probe[name] = sorted(os.listdir(path))[:5]
    except OSError as e:
        probe[name] = f"<{type(e).__name__}>"
for place in (root.parent / ".job-inputs", root.parent / ".job-spool", root.parent / ".job-roots"):
    probe[f"lists_{place.name}"] = os.path.exists(place)
(folder / "probe.json").write_text(json.dumps(probe), encoding="utf-8")

sock = os.environ[job_host.SOCKET_ENV]
job_host.ask(sock, VERB_OUTCOME, record=sent_inv_outcome(closing={**closing_found(), "summary": "replay"}, cost_usd=0.0))
job_host.ask(sock, VERB_PAGE, record=sent_page())


def put(name: str, data: bytes) -> None:
    answer = job_host.ask(sock, VERB_PUT, object=name, part=0, last=True, data=data)
    assert answer["sha256"] == hashlib.sha256(data).hexdigest(), answer


out = io.BytesIO()
with tarfile.open(fileobj=out, mode="w:gz") as tar:
    tar.add(folder, arcname=".")
put(RUN_PAGE, page)
put(BUNDLE, out.getvalue())
