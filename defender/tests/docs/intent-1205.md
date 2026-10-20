# #1205 — bounded box responses

Current design: R2, implemented over base `5fb8d8fe18e3ee6560ba22d4a8d71c305aeca66d`.
R1 is superseded for Oracle cancellation ownership; its byte budget, refusal behavior,
and other commitments remain in force. R1's grounding below retains its recorded base.

## Principles

Inherit [the engineering principles](../../../docs/principles.md): attacker-influenced
box data must not exhaust the host; refuse closed, loud, and fast. The owner selected
64 MiB and stopping the entire box/ending the run on overflow. The budget is a
conservative default, not a measured typical response size.

## Intent

- **O1:** Each Docker-backed call buffers at most a constant multiple of 64 MiB on the
  host, regardless of the response's eventual size. This is a per-call bound, not a
  global bound over concurrent calls or a bound on the Python process's total RSS.
- **O2:** The first byte past the aggregate budget causes a clear fatal refusal. Stop
  the entire box, prove it stopped, and refuse further calls on that executor. No
  partial output is a successful result; no model retry or fresh box recovers this run.
- **O3:** Responses at or below the budget retain the existing protocol, raw bytes,
  command exit status, and model-facing formatting.

Non-obligations: change in-box materialization, streaming/filtering algorithms,
unsandboxed execution, model display caps, or output retention in HTML reports.

## Design

The host-only output module owns a fixed `BOX_OUTPUT_LIMIT` and the bounded exchange.
The budget counts actual bytes on Docker stdout plus Docker stderr, including the
response header and its embedded command stdout/stderr, across the entire call.
It does not trust lengths declared inside the response.

A nonblocking selector loop writes request stdin and drains both outputs concurrently.
Reads request at most the remaining budget plus one sentinel byte, in chunks no larger
than 64 KiB. Successful output is decoded only after EOF and process completion. One
monotonic deadline covers request writing, reading, and waiting. Decoder copies mean
the memory promise is a constant multiple of the budget, not literally 64 MiB.

On overflow, close pipes, kill/reap the local Docker client without collecting residual
output, and raise `BoxOutputLimitExceeded`, a `BoxFault` subtype. Local reaping has a
five-second timeout; failure preserves the original exception with a cleanup note.
`BoxExecutor` marks itself unusable before calling the existing `BoxRuns.stop()` through
its carried daemon. Stop/inspection verify `exited` or `dead`; their existing individual
120-second Docker timeouts allow approximately 240 seconds of remote cleanup. Failure
to prove shutdown remains fatal and is chained to the overflow. Existing outer cleanup
retains its fatal-error precedence.

Tool, correlation, learning-stage, and grouped driver catches propagate overflow rather
than translating it into a recoverable result. Oracle Python bypasses its ordinary
lost-box/replacement path; the existing terminal world-fault path preserves the cause.
Review roles have no tools, so their stage-error handling is unaffected. No protocol,
configuration, image, or run-status schema migration is needed.

### R2 — Oracle attempts own their Python workers

A review found that a turn deadline could abandon the tool worker while executor overflow
cleanup was still running. The attempt then saw a retryable timeout and could create a new
box before receiving that worker's fatal exception. The added regression reproduced two
box starts at R1.

The attempt now owns registered Python worker tasks independently of the agent framework's
tool tasks. Cancelling a tool cannot cancel or discard its worker. A deadline stops useful
execution and initiates stop-and-prove through the carried daemon, while the supervisor
drains every retained worker. Container/scratch removal follows settlement. A box lost
during cancellation remains owned until that final removal; startup finishing after
cancellation is discarded without executing a command.

A late normal result remains a timeout. Worker failures survive cancellation; simultaneous
main, worker, and shutdown failures are preserved together rather than letting a recoverable
main failure hide a fatal worker outcome. A result already completed before the watcher ran
remains completed. Shutdown also covers external caller cancellation and an agent return
that leaves an owned worker behind.

External reads and host checks retain their existing abandonable AnyIO workers. Owned
Python work and its shutdown use the asyncio executor, independently of the external-read
pool, so abandoned reads cannot occupy all the slots needed to stop or settle the box.
The useful-work deadline is not a hard return deadline: bounded command/startup and cleanup
must settle before retry or return. No overflow-specific terminal flag is introduced.

The owner approved this lifecycle change in discussion. Independent review checked the
ownership model and its implementation; its error-ordering finding was resolved by preserving
combined failures. Recheck Oracle deadline, startup, shutdown, and retry contracts downstream.

## Review and verification

Independent design review accepted R1 after correcting fatal propagation through broad
exception handlers and mixed exception groups. R2's ownership review also checked error
precedence and settlement; 97 affected Oracle tests passed, including the deadline/overflow
race, direct tool-task cancellation, late startup, failed shutdown proof, and saturation of
the external-read thread pool. Tests cover aggregate boundaries,
concurrent pipe I/O, memory-constrained reading, deadlines, local cleanup, permanent
executor refusal, failed remote-stop proof, and end-run propagation. The live e2e test
uses a finite 64 MiB-plus-one-byte command and verifies stopped-container status, with
an under-limit control. Run both registered runtimes; unavailable runtimes are explicitly
skipped, not counted as verified.

```yaml
claims:
  - id: C1
    kind: referential
    claim: The base Docker transport captures both streams without a byte bound.
    probe: Read defender/box/_spec.py::_DockerTransport at the grounding base.
    probe_kind: read
    observed: subprocess.run uses capture_output=True.
    verdict: holds
  - id: C2
    kind: behavior
    claim: A bounded selector reader can detect overflow without reading to EOF.
    probe: Local Python child emitting 128 KiB per stream; reader budget 65536 bytes.
    probe_kind: executed
    observed: Refused at 65537 bytes; child killed and reaped.
    verdict: holds
  - id: C3
    kind: behavior
    claim: The installed agent framework propagates an ordinary fatal tool exception.
    probe: pydantic-ai 2.43.0 Agent with TestModel and a tool raising ProbeFault.
    probe_kind: executed
    observed: ProbeFault escaped unchanged.
    verdict: holds
  - id: C4
    kind: behavior
    claim: An oversized response under runc is refused and the container is stopped.
    probe: tests/e2e/test_1205_box_output.py::test_live_box_printing_past_limit_is_refused_and_stopped[runc], executed in the focused locked pytest run.
    probe_kind: executed
    observed: Passed, including an under-limit command and stopped-container inspection.
    verdict: holds
  - id: C5
    kind: behavior
    claim: The same live overflow contract holds under runsc.
    probe: The parametrized live test's runsc case; Docker info runtime inventory.
    probe_kind: executed
    observed: Skipped because runsc is not registered with this daemon.
    verdict: unprobed
  - id: C6
    kind: behavior
    claim: R1 can create a second Oracle box after overflow cleanup crosses its deadline.
    probe: Added test_overflow_cleanup_crossing_deadline_is_settled_before_attempt_can_retry at base 5fb8d8fe and ran it through the pytest lock.
    probe_kind: executed
    observed: The regression failed because starts contained two boxes.
    verdict: holds
  - id: C7
    kind: behavior
    claim: R2 settles retained Python outcomes before retry and preserves fatal overflow across deadline and direct tool cancellation.
    probe: Locked pytest run of tests/learning/oracle/test_1205_owned_box_work.py, test_1224_oracle_loop_regressions.py, and live_contracts/test_1224_oracle_context_and_box.py under R2.
    probe_kind: executed
    observed: 97 passed, including the previously failing regression and ordinary-timeout controls.
    verdict: holds
```
