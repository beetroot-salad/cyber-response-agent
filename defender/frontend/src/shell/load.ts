// The load (#1161 B1, #1540 Am-5, Am-6): one object per document load or back-forward restore, made outside React. It
// holds the attempt record the load took, how it was reached, its target, whether it is leaving, its one network client
// (the one 401 path) and its own TanStack `QueryClient`. Everything it does to the outside goes through four effects,
// so the unit tests drive it with no browser.
import { QueryClient } from "@tanstack/react-query";
import { literalAddress } from "../addresses";
import { decideUnauthorized, type Decision, type Taken } from "./decision";
import type { Person, ReadKey, ReadParams, ReadResult } from "./types";

export interface Effects {
  /** The page's `fetch`. */
  fetch(url: string, init: RequestInit): Promise<Response>;
  /** Record an attempt for `target` (and whether it is a repeat); false when the storage cannot be used. */
  record(target: string | null, again: boolean): boolean;
  /** Navigate away, keeping this page in the history (sign-in). */
  assign(url: string): void;
  /** Navigate away, replacing this page in the history (the failed screen, sign-out). */
  replace(url: string): void;
}

export interface LoadOptions {
  readonly taken: Taken;
  readonly byHistory: boolean;
  /** The pathname when it is a member of a returnable shape: what sign-in brings the person back to. */
  readonly target: string | null;
  readonly effects: Effects;
}

/** What asking `/api/me` came to. */
export type MeResult =
  | { readonly kind: "gone" }
  | { readonly kind: "ok"; readonly me: Person }
  | { readonly kind: "error" };

export type SignOutResult = "left" | "error" | "gone";

export interface Load {
  readonly taken: Taken;
  readonly byHistory: boolean;
  readonly target: string | null;
  readonly queryClient: QueryClient;
  readonly client: {
    /** `/api/me` as this load's own call (`source: "me"`), narrowed to the person shape (F3). */
    me(): Promise<MeResult>;
    /** One screen read (`source: "later"`), keyed by the OpenAPI path key. */
    read<K extends ReadKey>(key: K, params: ReadParams<K>): Promise<ReadResult<K>>;
    /** `POST /api/auth/logout`: 2xx or 401 (already signed out) leaves by replace; anything else is the error state. */
    signOut(): Promise<SignOutResult>;
  };
  /** The one way the shell navigates away: false (and nothing done) when the load is already leaving or superseded. */
  leave(navigate: () => void): boolean;
  /** Sign in again from the failed screen: records an attempt when storage allows, then leaves for the sign-in. */
  signIn(returns: readonly string[]): boolean;
  /** A newer load is the page's: whatever this one reports is ignored. */
  supersede(): void;
  /** Leaving or superseded: the load must do and show nothing more. */
  isGone(): boolean;
  isLeaving(): boolean;
}

const GET: RequestInit = { credentials: "same-origin", headers: { Accept: "application/json" }, cache: "no-store" };

function withReturn(base: string, target: string | null): string {
  return target === null ? base : `${base}${base.includes("?") ? "&" : "?"}return=${encodeURIComponent(target)}`;
}

/** The request path of a read: each `{name}` of the OpenAPI key filled (escaped), then the query. */
function addressOf(key: string, params: unknown): string {
  const { path = {}, query = {} } = (params ?? {}) as { path?: Record<string, unknown>; query?: Record<string, unknown> };
  const filled = key.replace(/\{([^}]+)\}/g, (_, name: string) => encodeURIComponent(String(path[name])));
  const search = new URLSearchParams();
  for (const [name, value] of Object.entries(query)) if (value !== undefined && value !== null) search.append(name, String(value));
  return search.size === 0 ? filled : `${filled}?${search.toString()}`;
}

function isPerson(body: unknown): body is Person {
  const candidate = body as { user?: { email?: unknown } } | null;
  return typeof body === "object" && candidate !== null && typeof candidate.user?.email === "string";
}

export function makeLoad(options: LoadOptions): Load {
  const { taken, byHistory, target, effects } = options;
  let leaving = false;
  let superseded = false;
  const isGone = (): boolean => leaving || superseded;

  function leave(navigate: () => void): boolean {
    if (isGone()) return false;
    leaving = true; // this document is going away: nothing of the running load shows
    navigate();
    return true;
  }

  function toFailedScreen(reason: string): void {
    leave(() => effects.replace(withReturn(`${literalAddress("sign-in-failed")}?reason=${reason}`, target)));
  }

  /** A 401: carry out B1's decision. The load leaves, so a second 401 answered later is gone (point 4). */
  function unauthorized(source: "me" | "later"): void {
    const decision: Decision = decideUnauthorized({ taken, byHistory, source });
    if (decision.kind === "failed") return toFailedScreen(decision.reason);
    if (!effects.record(target, decision.again)) return toFailedScreen("storage-unavailable");
    leave(() => effects.assign(withReturn("/api/auth/login", target)));
  }

  /** The one network path: gone (nothing more), a network failure, or the answer, with a 401 already handled. */
  async function request(
    url: string,
    init: RequestInit,
    source: "me" | "later",
  ): Promise<{ readonly kind: "gone" } | { readonly kind: "failed" } | { readonly kind: "response"; readonly response: Response }> {
    if (isGone()) return { kind: "gone" };
    let response: Response;
    try {
      response = await effects.fetch(url, init);
    } catch {
      return isGone() ? { kind: "gone" } : { kind: "failed" };
    }
    if (isGone()) return { kind: "gone" };
    if (response.status === 401) {
      unauthorized(source);
      return { kind: "gone" };
    }
    return { kind: "response", response };
  }

  /** The answer's JSON body: gone when the load went away while it was read, error when it is not JSON. */
  async function jsonOf(response: Response): Promise<{ readonly kind: "gone" | "failed" } | { readonly kind: "body"; readonly body: unknown }> {
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      return isGone() ? { kind: "gone" } : { kind: "failed" };
    }
    return isGone() ? { kind: "gone" } : { kind: "body", body };
  }

  const client: Load["client"] = {
    async me() {
      const sent = await request("/api/me", GET, "me");
      if (sent.kind === "gone") return { kind: "gone" };
      if (sent.kind === "failed" || sent.response.status !== 200) return { kind: "error" };
      const read = await jsonOf(sent.response);
      if (read.kind === "gone") return { kind: "gone" };
      return read.kind === "body" && isPerson(read.body) ? { kind: "ok", me: read.body } : { kind: "error" };
    },
    async read<K extends ReadKey>(key: K, params: ReadParams<K>): Promise<ReadResult<K>> {
      const sent = await request(addressOf(key, params), GET, "later");
      if (sent.kind === "gone") return { kind: "gone" };
      if (sent.kind === "failed") return { kind: "error" };
      if (sent.response.status === 404) return { kind: "not-available" };
      if (sent.response.status !== 200) return { kind: "error" };
      const read = await jsonOf(sent.response);
      if (read.kind === "gone") return { kind: "gone" };
      return read.kind === "body" ? { kind: "ok", body: read.body as never } : { kind: "error" };
    },
    async signOut() {
      if (isGone()) return "gone";
      let response: Response;
      try {
        response = await effects.fetch("/api/auth/logout", { method: "POST", credentials: "same-origin", headers: { Accept: "application/json" } });
      } catch {
        return isGone() ? "gone" : "error";
      }
      if (isGone()) return "gone";
      // 2xx: signed out. 401: already signed out, the same exit; replace, so Back cannot return to a signed-in page.
      if (!(response.ok || response.status === 401)) return "error";
      return leave(() => effects.replace(literalAddress("root"))) ? "left" : "gone";
    },
  };

  return {
    taken,
    byHistory,
    target,
    // Each read is sent at most once per load: retries off, no refetch on focus or reconnect, data that never goes
    // stale and entries kept for the load's life. The query function never throws, so TanStack's error state is unused.
    queryClient: new QueryClient({
      defaultOptions: {
        queries: { retry: false, refetchOnWindowFocus: false, refetchOnReconnect: false, refetchOnMount: false, staleTime: Infinity, gcTime: Infinity },
      },
    }),
    client,
    leave,
    signIn(returns) {
      // The values are handed to the sign-in route unjudged: the API judges them (P2).
      effects.record(returns[0] ?? null, false); // when storage allows
      const query = returns.map((value) => `return=${encodeURIComponent(value)}`).join("&");
      return leave(() => effects.assign(`/api/auth/login${query === "" ? "" : `?${query}`}`));
    },
    supersede() {
      superseded = true;
    },
    isGone,
    isLeaving: () => leaving,
  };
}
