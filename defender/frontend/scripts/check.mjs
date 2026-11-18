// `bun run check` (#1540 F1 b, F8): the type check and the source check, by `scripts/source-check.mjs`. No "run directly"
// guard: whatever starts this file runs the check, and any problem exits non-zero.
import { check } from "./source-check.mjs";

const problems = check();
if (problems.length > 0) {
  for (const problem of problems) console.error(problem);
  console.error("check: failed");
  process.exit(1);
}
