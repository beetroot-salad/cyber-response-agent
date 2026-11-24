"""#1546 e2e worker-lane child: the real per-job host helper over a REAL docker (the `runsc-job` runtime where boxes run
under runsc), whose job container runs the REAL investigation entry's replay driver (`_job_entry1342.py replay-container`,
inside the code bind; `command=` is the helper's own seam) from the test-only image layer `tooling/testing/Dockerfile.job-replay`
(`DEFENDER_JOB_IMAGE`). Marks go to the container's tmpfs `/tmp`. Like `_helper_child1170.py` otherwise: marked signer,
knowledge through the product's own fetch, in-process, over the test's bare `<remote>` (#1618: the one `fetch=` seam).
The store comes from the worker's environment (`DEFENDER_EVIDENCE_*`), and the tenant's key login is the `evidence_keys` seam,
built from the JSON login in `DEFENDER_TEST_EVIDENCE_LOGIN` (`{addr, role_id, secret_id, mount}`, as
`_helper_child1546_replay.py` takes it): the test's OpenBao slice holds the tenant's AppRole on a mount of its own, which a
generation's recorded login (mount `approle`) cannot name. The login is taken out of the environment here, so the job
container is never handed it.
`python _helper_child1546.py <commit> <remote> --job <id> --tenant <T> --parent-pid <pid> ...` (the worker's helper argv after
it).
Not runnable where there is no native docker with the job runtime: CI's `test` job runs it."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT))

from defender import evidence, job_host  # noqa: E402
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A  # noqa: E402
from defender.tests.support.tenancy._fetch_standin_1618 import in_process_fetch  # noqa: E402

ENTRY = Path(__file__).resolve().with_name("_job_entry1342.py")
commit, remote, argv = sys.argv[1], sys.argv[2], sys.argv[3:]
job_id, tenant = argv[argv.index("--job") + 1], argv[argv.index("--tenant") + 1]
LOGIN_ENV = "DEFENDER_TEST_EVIDENCE_LOGIN"
login = json.loads(os.environ.pop(LOGIN_ENV))
sys.exit(job_host.main(["--kind", "investigation", *argv], signer=A.MarkedSigner(),
                       fetch=in_process_fetch(remote),
                       evidence_keys=evidence.EvidenceKeys(addr=login["addr"], role_id=login["role_id"],
                                                           secret_id=login["secret_id"], mount=login["mount"]),
                       command=["python3", str(ENTRY), "replay-container", commit, "/tmp/marks", "--job", job_id,
                                "--tenant", tenant]))
