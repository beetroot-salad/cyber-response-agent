"""#1412 O1: the real proxy under uvicorn in its own process over fake ports, so its memory can be
read apart from the test's. TestClient finishes the server before the client reads, so only a real
server shows back-pressure and what a stalled reader costs."""
from __future__ import annotations

import concurrent.futures
import contextlib
import os
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import httpx

from defender._git import REPO_ROOT
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _stream1412 as W
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._proxy_process_1412 import GAUGE_PATH

BASE = T.BASE_PATH
PATH = f"{BASE}/users/x"


class _ProxyProcess:
    def __init__(self, process: subprocess.Popen, url: str) -> None:
        self.process, self.url = process, url

    def gauge(self, query: str = "") -> dict[str, int]:
        with httpx.Client(trust_env=False, timeout=30) as client:
            return client.get(f"{self.url}{GAUGE_PATH}{query}").json()

    def high_water(self) -> int:
        """The process's peak resident memory so far, in bytes; 0 once it is gone."""
        with contextlib.suppress(OSError), open(f"/proc/{self.process.pid}/status") as status:
            for line in status:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1]) * 1024
        return 0


@contextlib.contextmanager
def _proxy_process(data_root: Path, tenant: str, *, trace: bool) -> Iterator[_ProxyProcess]:
    port = H.free_port()
    process = subprocess.Popen(
        [sys.executable, "-m", "defender.tests.integrations.credential_proxy_1163._proxy_process_1412",
         str(data_root), tenant, str(port), "trace" if trace else "plain"],
        cwd=REPO_ROOT, env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(REPO_ROOT)})
    running = _ProxyProcess(process, f"http://127.0.0.1:{port}")

    def up() -> bool:
        with contextlib.suppress(httpx.HTTPError):
            return running.gauge()["audited"] == 0
        return False

    try:
        W.until(lambda: process.poll() is not None or up(), 30)
        assert process.poll() is None, f"the proxy process exited with {process.returncode}"
        assert up(), "the proxy process did not start"
        yield running
    finally:
        process.kill()
        process.wait()


def test_o1_a_stalled_reader_of_an_8_mib_reply_costs_under_2_mib_of_allocations(tmp_path, data_root):
    """The proxy's Python allocation peak above its idle level stays under 2 MiB for one 8 MiB
    reply whose reader stalls, and the reader still gets all of it. O1."""
    body = b"x" * W.DEFAULT_LIMIT
    with T.rig(tmp_path / "forge", data_root) as r, \
            _proxy_process(data_root, r.t.tenant_id, trace=True) as proxy:
        r.up.replies[f"{BASE}/big"] = (200, W.JSON, body)
        W.raw_post(proxy.url, r.tok(), W.doc(f"{r.up.url}{PATH}"))  # lazy imports land before the measure
        idle = proxy.gauge("?reset")["traced_now"]
        with W.unread(proxy.url, r.tok(), W.doc(f"{r.up.url}{BASE}/big")) as response:
            stream = response.iter_raw(64 * 1024)
            raw = bytearray(next(stream))
            time.sleep(2)
            for chunk in stream:
                raw += chunk
        peak = proxy.gauge()["traced_peak"]

    assert peak - idle < 2 * W.MIB, f"{(peak - idle) / W.MIB:.1f} MiB allocated above idle"
    forwarded, final = W.decoded(bytes(raw))
    assert (final["status"], final["body_whole"]) == (200, True)
    assert forwarded == body


def test_o1_forty_8_mib_replies_at_once_keep_the_process_under_256_mib(tmp_path, data_root):
    """40 overlapping 8 MiB replies, one worker thread each, keep peak resident memory under 256 MiB
    (killed once past it, so a failure stays cheap). O1, P3."""
    limit = 256 * W.MIB
    with T.rig(tmp_path / "forge", data_root) as r, \
            _proxy_process(data_root, r.t.tenant_id, trace=False) as proxy:
        r.up.replies[f"{BASE}/big"] = (200, W.JSON, b"x" * W.DEFAULT_LIMIT)
        stop, worst = threading.Event(), [0]

        def watch() -> None:
            while not stop.wait(0.02):
                worst[0] = max(worst[0], proxy.high_water())
                if worst[0] >= limit:
                    proxy.process.kill()
                    return

        def read(tok: str) -> int:
            with contextlib.suppress(httpx.HTTPError), \
                    W.unread(proxy.url, tok, W.doc(f"{r.up.url}{BASE}/big")) as response:
                time.sleep(1)  # every reader holds its exchange open until all 40 have begun
                return sum(len(chunk) for chunk in response.iter_raw(64 * 1024))
            return 0

        watcher = threading.Thread(target=watch, daemon=True)
        watcher.start()
        tokens = [r.tok() for _ in range(40)]
        with concurrent.futures.ThreadPoolExecutor(40) as pool:
            sizes = list(pool.map(read, tokens))
        stop.set()
        watcher.join()
        assert worst[0] < limit, f"peak {worst[0] / W.MIB:.0f} MiB"
        gauge = proxy.gauge()

    assert gauge["live_peak"] == 40, gauge
    assert gauge["borrowed_peak"] == 40, f"worker threads lent out at the peak: {gauge}"
    assert gauge["total_tokens"] == 40, f"P3's limit of 40 simultaneous requests: {gauge}"
    assert gauge["audited"] == 40, gauge
    assert all(size > W.DEFAULT_LIMIT for size in sizes), sizes


