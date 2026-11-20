// The alert list's words for what an alert came to (alert list design O5, AP2, AP4): the API states codes, the screen
// chooses the words. The outcome codes are the generated union's (AP4): a code the document adds or drops is a type
// error here until the screen names it.
import type { components } from "../../generated/api";

type AlertSummary = components["schemas"]["AlertSummary"];
/** The five outcome codes, as the OpenAPI document declares them. */
export type Disposition = NonNullable<AlertSummary["outcome"]>;
type InvestigationStatus = NonNullable<AlertSummary["latest_status"]>;

/** How loudly the status cell says it, as its `data-tone` names it. */
export type Tone = "solid" | "outlined" | "quiet" | "muted";

/** Each outcome code with its label and tone, in the Outcome menu's order. The label is the code itself. */
export const OUTCOMES: { readonly [K in Disposition]: { readonly code: K; readonly label: K; readonly tone: Tone } } = {
  malicious: { code: "malicious", label: "malicious", tone: "solid" },
  inconclusive: { code: "inconclusive", label: "inconclusive", tone: "outlined" },
  unresolved: { code: "unresolved", label: "unresolved", tone: "outlined" },
  "false-positive": { code: "false-positive", label: "false-positive", tone: "quiet" },
  benign: { code: "benign", label: "benign", tone: "quiet" },
};

/** The address's and the read's `outcome` for an alert with no completed investigation. */
export const NO_OUTCOME = "none";
/** What the Outcome filter may hold: a code, or no outcome yet. */
export type OutcomeFilter = Disposition | typeof NO_OUTCOME;

/** The outcome codes in the menu's order. */
export const OUTCOME_CODES: readonly Disposition[] = Object.values(OUTCOMES).map((outcome) => outcome.code);

/** `value` as an Outcome filter, or null when it is not one of the six (spelled exactly). */
export function outcomeFilterOf(value: string): OutcomeFilter | null {
  if (value === NO_OUTCOME) return NO_OUTCOME;
  return OUTCOME_CODES.find((code) => code === value) ?? null;
}

/** Where an alert with no outcome stands, by its newest investigation's status. A completed investigation always has
 * an outcome (O10), so `completed` here is a mistake (a worker left running through the upgrade, or a planted row); it
 * is drawn, not thrown, so one such row never costs the screen its others (r3.3). */
const STANDING: Readonly<Record<InvestigationStatus, string>> = {
  completed: "completed",
  queued: "queued",
  running: "investigating",
  aborted: "cancelled",
  failed: "failed",
  unparseable: "failed",
};

/** The status column's word and tone: the outcome when the alert has one, else where its newest investigation stands
 * (never investigated when it has none). */
export function statusOf(alert: Pick<AlertSummary, "outcome" | "latest_status">): {
  readonly word: string;
  readonly tone: Tone;
} {
  if (alert.outcome !== null) return { word: OUTCOMES[alert.outcome].label, tone: OUTCOMES[alert.outcome].tone };
  const status = alert.latest_status;
  if (status === null) return { word: "not investigated", tone: "muted" };
  return { word: STANDING[status], tone: "muted" };
}
