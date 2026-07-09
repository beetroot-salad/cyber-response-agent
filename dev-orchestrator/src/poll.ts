// One poll pass (design §9.4): intake newly-listed issues, then drift-check every card that
// carries a pr_number in a live (non-done) state. Intake and drift are INDEPENDENT halves — a
// gh.issueList blip must not suppress drift (SB-I), and a per-item / per-card gh throw is
// swallowed so one bad row can't blind the whole pass (SB-H). Returns the applied-transition
// counts (a stale / no-op transition is NOT counted).

import type { CardState, DB, Effects, IssueRef, PollSummary } from "./contract";
import { applyEvent, intake } from "./engine";

export async function pollOnce(db: DB, fx: Effects, opts: { label?: string } = {}): Promise<PollSummary> {
  const summary: PollSummary = { intook: 0, merged: 0, closed: 0, errors: 0 };

  // --- intake half: list open issues, create a backlog card for each new one ---
  let issues: IssueRef[] = [];
  try {
    // issueList swallows per-repo blips but REPORTS their count (SB-I) — so an empty list from a
    // failed gh call is distinguishable from a genuinely empty repo. Add those to the error count.
    const listed = fx.gh.issueList({ label: opts.label });
    issues = listed.issues;
    summary.errors += listed.failures;
  } catch {
    // SB-I: a total list-effect failure skips intake this pass (drift below still runs), counted as one.
    summary.errors += 1;
  }
  for (const iss of issues) {
    try {
      // intake is idempotent (a repeat issue → stale, uncounted); a malformed row throws
      // InvalidEventError → SB-H: skip it and continue the batch.
      if (intake(db, fx, { repo: iss.repo, issue_number: iss.issue_number, title: iss.title }).ok) {
        summary.intook += 1;
      }
    } catch {
      // malformed issue (e.g. non-positive number) — skip-and-continue.
    }
  }

  // --- drift half: every card with a PR in a live (non-done, non-archived) state ---
  const eligible = db
    .prepare("SELECT * FROM card WHERE pr_number IS NOT NULL AND stage != 'done' AND archived_at IS NULL")
    .all() as CardState[];
  for (const card of eligible) {
    try {
      const state = fx.gh.prStatus({ repo: card.repo, pr_number: card.pr_number as number });
      if (state === "merged") {
        if (applyEvent(db, fx, card.id, { type: "pr_merged" }).ok) summary.merged += 1;
      } else if (state === "closed") {
        if (applyEvent(db, fx, card.id, { type: "pr_closed" }).ok) summary.closed += 1;
      }
      // "open" → no drift, no count.
    } catch {
      // per-card gh.prStatus blip — leave the card intact, count the error, check the next.
      summary.errors += 1;
    }
  }

  return summary;
}
