"""#1546 e2e worker-lane child: the real per-job host helper over a REAL docker (the `runsc-job` runtime where boxes run
under runsc), whose job container runs `_job_container1546.py` in place of the investigation entry (`command=`, the
helper's own seam). Like `_helper_child1170.py` otherwise: marked signer, launch-time publish answers `fresh` at the commit.
`python _helper_child1546.py <commit> --job <id> --tenant <T> --parent-pid <pid> ...` (the worker's helper argv after it).
Not runnable where there is no native docker with the job runtime: CI's `test` job runs it."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))

from defender import job_host  # noqa: E402
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A  # noqa: E402
from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B  # noqa: E402

CONTAINER = Path(__file__).resolve().with_name("_job_container1546.py")
commit, argv = sys.argv[1], sys.argv[2:]
job_id, tenant = argv[argv.index("--job") + 1], argv[argv.index("--tenant") + 1]
sys.exit(job_host.main(["--kind", "investigation", *argv], signer=A.MarkedSigner(),
                       publish=lambda *a, **k: B.fresh(commit),
                       command=["python3", str(CONTAINER), "--job", job_id, "--tenant", tenant]))
