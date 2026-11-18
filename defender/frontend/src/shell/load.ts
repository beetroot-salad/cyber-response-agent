// The load (#1161 B1, #1540 Am-5, Am-6): one object per document load or back-forward restore, made outside React. It
// holds the attempt record the load took, how it was reached, its target, whether it is leaving, its typed API client
// (the one 401 path) and its own TanStack `QueryClient`. Everything it does to the outside goes through four effects,
// so the unit tests drive it with no browser.
//
// Every API call goes through `openapi-fetch`, typed by the generated `paths` (PR3, F3): a path, a parameter or a field
// the document does not have is a compile error, the client fills paths and encodes queries, and answers come back
// typed, with no cast. Answers are trusted to match the document, which CI checks against the real server.
import { QueryClient } from "@tanstack/react-query";
import createClient, { createQuerySerializer, type MaybeOptionalInit } from "openapi-fetch";
import { literalAddress } from "../addresses";
import type { paths } from "../generated/api";
import { decideUnauthorized, type Decision, type Taken } from "./decision";
import type { Person, ReadBody, ReadKey, ReadParams, ReadResult } from "./types";

export interface Effects {
  /** The page's `fetch`, given the request the typed client made. */
  fetch(request: Request): Promise<Response>;
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
  /** The page's origin, which every API request goes to (the session cookie is same-origin). */
  readonly origin: string;
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

/** The sign-in route, checked against the document (it is a navigation, not a call, so the client does not send it).
 * Its `return` values are not in the document: the API reads them itself and judges them (P2). */
const SIGN_IN = "/api/auth/login" satisfies keyof paths;

/** Every query this module writes that the client does not: each name and value escaped, a list as repeated names. */
const queryOf = createQuerySerializer({ array: { style: "form", explode: true } });

function withQuery(path: string, query: Record<string, string | readonly string[] | null>): string {
  const search = queryOf(Object.fromEntries(Object.entries(query).filter(([, value]) => value !== null)));
  return search === "" ? path : `${path}?${search}`;
}

/** Thrown by the client's `fetch` when the load is gone, a 401 included (B1 has then already been carried out). */
class Gone extends Error {}

/** What one call came to: gone (nothing more), failed (no answer, or not the JSON it should be), or its answer. */
type Sent<T> = { readonly kind: "gone" } | { readonly kind: "failed" } | { readonly kind: "answer"; readonly answer: T };

/** F3: a cookie session is always a person, so `/api/me` is narrowed once, on the generated union's own `kind`. */
function isPerson(body: { readonly kind: string }): body is Person {
  return body.kind === "person";
}

/**
 * `GET key` with `params`, answered with that path's own body type. The client checks a call to one written-out path,
 * but TypeScript cannot follow a path chosen by a type parameter (`K`) through the client's conditional types. So the
 * request goes over every read path at once, and the answer is taken as `K`'s: the frontend's one trusted step. It is
 * sound because `K` picks both: `useRead`'s caller writes one path, and its params and body are that path's (checked
 * there).
 */
async function getFor<K extends ReadKey>(
  client: ReturnType<typeof createClient<paths>>,
  key: K,
  params: ReadParams<K>,
): Promise<{ readonly status: number; readonly body: ReadBody<K> | undefined }> {
  const path: ReadKey = key;
  // trust: `params` are `key`'s own (see above)
  const { data, response } = await client.GET(path, { params } as MaybeOptionalInit<paths[ReadKey], "get">);
  // trust: the answer to `key` is `key`'s body (see above)
  return { status: response.status, body: data as ReadBody<K> | undefined };
}

export function makeLoad(options: LoadOptions): Load {
  const { taken, byHistory, target, origin, effects } = options;
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
    leave(() => effects.replace(withQuery(literalAddress("sign-in-failed"), { reason, return: target })));
  }

  /** A 401: carry out B1's decision. The load leaves, so a second 401 answered later is gone (point 4). */
  function unauthorized(source: "me" | "later"): void {
    const decision: Decision = decideUnauthorized({ taken, byHistory, source });
    if (decision.kind === "failed") return toFailedScreen(decision.reason);
    if (!effects.record(target, decision.again)) return toFailedScreen("storage-unavailable");
    leave(() => effects.assign(withQuery(SIGN_IN, { return: target })));
  }

  /** The typed client whose every request is the load's: none once it is gone, and a 401 is B1's (`source`), or, with
   * no source, an ordinary answer (sign-out's "already signed out"). */
  function clientFor(source: "me" | "later" | null) {
    return createClient<paths>({
      baseUrl: origin,
      credentials: "same-origin",
      cache: "no-store",
      headers: { Accept: "application/json" },
      async fetch(request) {
        if (isGone()) throw new Gone();
        const response = await effects.fetch(request); // a network failure throws: failed
        if (isGone()) throw new Gone();
        if (source !== null && response.status === 401) {
          unauthorized(source);
          throw new Gone();
        }
        return response;
      },
    });
  }
  const api = { me: clientFor("me"), later: clientFor("later"), signOut: clientFor(null) };

  async function send<T>(call: () => Promise<T>): Promise<Sent<T>> {
    try {
      const answer = await call();
      return isGone() ? { kind: "gone" } : { kind: "answer", answer };
    } catch (error) {
      return error instanceof Gone || isGone() ? { kind: "gone" } : { kind: "failed" };
    }
  }

  const client: Load["client"] = {
    async me() {
      const sent = await send(() => api.me.GET("/api/me"));
      if (sent.kind === "gone") return { kind: "gone" };
      if (sent.kind === "failed") return { kind: "error" };
      const { data, response } = sent.answer;
      return response.status === 200 && data !== undefined && isPerson(data) ? { kind: "ok", me: data } : { kind: "error" };
    },
    async read<K extends ReadKey>(key: K, params: ReadParams<K>): Promise<ReadResult<K>> {
      const sent = await send(() => getFor(api.later, key, params));
      if (sent.kind === "gone") return { kind: "gone" };
      if (sent.kind === "failed") return { kind: "error" };
      const { body, status } = sent.answer;
      if (status === 404) return { kind: "not-available" };
      return status === 200 && body !== undefined ? { kind: "ok", body } : { kind: "error" };
    },
    async signOut() {
      const sent = await send(() => api.signOut.POST("/api/auth/logout", { parseAs: "stream" }));
      if (sent.kind === "gone") return "gone";
      if (sent.kind === "failed") return "error";
      const { response } = sent.answer;
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
      return leave(() => {
        effects.record(returns[0] ?? null, false); // when storage allows; a gone load records nothing
        effects.assign(withQuery(SIGN_IN, { return: returns }));
      });
    },
    supersede() {
      superseded = true;
    },
    isGone,
    isLeaving: () => leaving,
  };
}
