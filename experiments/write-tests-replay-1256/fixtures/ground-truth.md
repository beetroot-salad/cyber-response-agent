## Ground truth (what history found after the original write-tests stage)
| ID | Found at | Item |
|---|---|---|
| G1 | code review → r4 | One owner of system status: judged once at run start, every surface renders from current status |
| G2 | code review → r4 | Down gate must run before the lead claim, for every cause |
| G3 | code review → r4 | One maker of a down cause (start check, call-time escape, scaffold validator); paths hidden only at boundaries |
| G4 | code review → r4 (human) | D5/D5a: lead zero keeps a summary (its final text) written before its system went down |
| G5–G11 | code-stage adversary | A1 fault-type census; A2 run.py ignoring broken adapters; A3 resume drops down status; A4 combined log line; A5 instruction polarity; A6 host paths in model-visible surfaces; A7 exception types at import/check |
| G12 | implementation | `ConfigFault` import would break the #1080 import census |
| G13 | implementation | `.data_root` read banned by the #1210 census; roots come from `Tenant.root_names()` |
| G14 | implementation | `run.main(roster=)` not honoured; the start check must judge the roster handed in |
| G15 | implementation | Contract defects: "no systems" arm deletes a file tenant resolution needs; upper-case run id refused; #1234 retry test broken by the harness change |
| G16 | CI | Query tool spelled the code-folder label as a literal |

Baseline parity: the original write-tests review found R1–R7. The replay's step 4 should find comparable contract-level issues; failing that is a regression signal.
