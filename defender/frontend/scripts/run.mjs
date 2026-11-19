// The one command entry (#1540 F1): `bun scripts/run.mjs <command>`, as package.json's scripts call it. Each script
// module exports a function that returns its problems; this prints them under the command's name and exits non-zero.
// It runs the steps in this process, so no command depends on which runtime started it.
import { build } from "./build.mjs";
import { generate } from "./generate.mjs";
import { check } from "./source-check.mjs";

/** Each command's steps, in order; the first with problems stops the rest. */
const COMMANDS = {
  generate: [generate],
  check: [generate, check],
  build: [generate, check, build],
};

const command = process.argv[2];
const steps = COMMANDS[command];
if (steps === undefined) {
  console.error(`run: the command is one of ${Object.keys(COMMANDS).join(", ")}, not ${command}`);
  process.exit(2);
}
for (const step of steps) {
  const problems = await step();
  if (problems.length > 0) {
    for (const problem of problems) console.error(`${command}: ${problem}`);
    console.error(`${command}: failed`);
    process.exit(1);
  }
}
