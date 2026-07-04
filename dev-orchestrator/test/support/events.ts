// Event builders. Each takes the (stage,status) the caller BELIEVES the card is in — pass a
// card for the honest case, or an explicit {stage,status} to exercise a stale CAS guard.

import type { Event, Stage, Status } from "../../src/contract";

type Believed = { stage: Stage; status: Status };

export const ev = {
  goto(from: Believed, target: Stage, park?: boolean): Event {
    const base = { type: "goto" as const, target, expected_stage: from.stage, expected_status: from.status };
    return park ? { ...base, park: true } : base;
  },
  cancel(from: Believed): Event {
    return { type: "cancel", expected_stage: from.stage, expected_status: from.status };
  },
  archive(from: Believed): Event {
    return { type: "archive", expected_stage: from.stage, expected_status: from.status };
  },
  runSucceeded(run_id: string, extra: { session_id?: string; cost_usd?: number; pr_number?: number } = {}): Event {
    return { type: "run_succeeded", run_id, ...extra };
  },
  runFailed(run_id: string, extra: { session_id?: string; pr_number?: number } = {}): Event {
    return { type: "run_failed", run_id, ...extra };
  },
  prMerged(): Event {
    return { type: "pr_merged" };
  },
  prClosed(): Event {
    return { type: "pr_closed" };
  },
};
