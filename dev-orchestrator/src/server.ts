// The one wire (§9.1, §9.2): a hand-rolled `{ fetch }` app (§9.1's sanctioned "hand-rolled JSON
// /rpc" shape — zero-dep, drop-in swappable for Hono). `POST /rpc` decodes {op,args}, calls the
// engine, and shapes the reply per the §9.2 response table; every GET serves the static board.
// The read model (readBoard/readCard) is the pure DB projection (§9.3) — activity stays null here;
// the live ~/.claude tail is a separate degradable overlay (a documented follow-up).

import type { App, BoardCard, BoardRun, CardDetail, CardState, Config, DB, Effects, PollHealth, RunRow } from "./contract";
import { AlreadyInFlightError, InvalidEventError } from "./contract";
import { applyEvent, intake } from "./engine";

// --- read model (§9.3) ------------------------------------------------------

function projectLatestRun(db: DB, cardId: string): BoardRun | null {
  const r = db
    .prepare("SELECT * FROM run WHERE card_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1")
    .get(cardId) as RunRow | undefined;
  if (!r) return null;
  return {
    id: r.id,
    stage: r.stage,
    attempt: r.attempt,
    status: r.status,
    trigger: r.trigger,
    session_id: r.session_id,
    activity: null, // overlay only; the pure projection never tails ~/.claude
  };
}

/** The board read model — non-archived cards, each joined to its newest run (§9.3). */
export function readBoard(db: DB): BoardCard[] {
  const cards = db.prepare("SELECT * FROM card WHERE archived_at IS NULL ORDER BY created_at, rowid").all() as CardState[];
  return cards.map((c) => ({
    id: c.id,
    repo: c.repo,
    issue_number: c.issue_number,
    pr_number: c.pr_number,
    title: c.title,
    stage: c.stage,
    status: c.status,
    state_entered_at: c.state_entered_at,
    latest_run: projectLatestRun(db, c.id),
  }));
}

/** One card + its full append-only run timeline, oldest first (§9.2). */
export function readCard(db: DB, id: string): CardDetail | null {
  const card = db.prepare("SELECT * FROM card WHERE id = ?").get(id) as CardState | undefined;
  if (!card) return null;
  const runs = db.prepare("SELECT * FROM run WHERE card_id = ? ORDER BY created_at, rowid").all(id) as RunRow[];
  return { card, runs };
}

// --- the /rpc router (§9.2) -------------------------------------------------

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

async function handleRpc(req: Request, db: DB, fx: Effects, health: PollHealth): Promise<Response> {
  let payload: { op?: string; args?: any };
  try {
    payload = (await req.json()) as { op?: string; args?: any };
  } catch {
    return json({ error: "unparseable request body" }, 400);
  }
  const { op, args } = payload ?? {};
  try {
    switch (op) {
      case "getBoard":
        // cards + last-poll health, so the board can show "polling failed" (an empty [] from a gh
        // blip otherwise looks identical to an empty repo — §9.4).
        return json({ cards: readBoard(db), poll: health });
      case "getCard": {
        const detail = readCard(db, args?.cardId);
        return detail ? json(detail) : json({ error: "card not found" }, 404);
      }
      case "dispatchEvent":
        // Returns {ok:true,card} or {ok:false,reason:'stale'} — a stale CAS is a 200 no-op (§9.2).
        return json(applyEvent(db, fx, args.cardId, args.event));
      case "createIssue": {
        const { issue_number } = fx.gh.issueCreate({ repo: args.repo, title: args.title, body: args.body });
        return json(intake(db, fx, { repo: args.repo, issue_number, title: args.title }));
      }
      default:
        return json({ error: `unknown op: ${String(op)}` }, 400);
    }
  } catch (e) {
    if (e instanceof InvalidEventError) return json({ error: e.message }, 400);
    if (e instanceof AlreadyInFlightError) return json({ error: e.message }, 409);
    throw e;
  }
}

const BOARD_HTML = new URL("./board/index.html", import.meta.url);

export function makeApp(db: DB, fx: Effects, _cfg: Config, health: PollHealth): App {
  return {
    fetch(req: Request): Response | Promise<Response> {
      const url = new URL(req.url);
      if (req.method === "POST" && url.pathname === "/rpc") return handleRpc(req, db, fx, health);
      if (req.method === "GET") return new Response(Bun.file(BOARD_HTML), { headers: { "content-type": "text/html; charset=utf-8" } });
      return json({ error: "not found" }, 404);
    },
  };
}
