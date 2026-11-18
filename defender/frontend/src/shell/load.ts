// The load (#1161 B1, #1540 Am-5, Am-6): one object per document load or back-forward restore, made outside React. It
// carries out what a 401 means for this load, sends every API call through its typed client, and owns its own TanStack
// `QueryClient`. Everything it does to the outside goes through four effects, so the unit tests drive it with no browser.
//
// Every API call goes through `openapi-fetch`, typed by the generated `paths` (PR3, F3): a path, a parameter or a field
// the document does not have is a compile error, the client fills paths and encodes queries, and answers come back
// typed. Answers are trusted to match the document, which CI checks against the real server.
import { QueryClient } from "@tanstack/react-query";
import createClient, { createQuerySerializer, type MaybeOptionalInit } from "openapi-fetch";
import { literalAddress } from "../addresses";
import type { paths } from "../generated/api";
import { decideUnauthorized, type FailedReason, type Source, type Taken } from "./decision";
import type { Outcome, Person, ReadBody, ReadKey, ReadParams, ReadResult } from "./types";

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

interface LoadOptions {
  readonly taken: Taken;
  readonly byHistory: boolean;
  /** The pathname when it is a member of a returnable shape: what sign-in brings the person back to. */
  readonly target: string | null;
  /** The page's origin, which every API request goes to (the session cookie is same-origin). */
  readonly origin: string;
  readonly effects: Effects;
}

export type MeResult = Outcome<{ readonly kind: "ok"; readonly me: Person }>;
export type SignOutResult = Outcome<{ readonly kind: "left" }>;

/** What a call does with a 401 answer: carry out B1's decision for that source, or return it like any other answer
 * (sign-out's "already signed out"). Every call states its own. */
type On401 = Source | "returned";

export interface Load {
  readonly queryClient: QueryClient;
  readonly client: {
    /** `/api/me` as this load's own call (its 401 is B1's for `me`). */
    me(): Promise<MeResult>;
    /** One screen read (its 401 is B1's for a later call), keyed by the OpenAPI path key. */
    read<K extends ReadKey>(key: K, params: ReadParams<K>): Promise<ReadResult<K>>;
    /** `POST /api/auth/logout`: 2xx or 401 (already signed out) leaves by replace; anything else is the error state. */
    signOut(): Promise<SignOutResult>;
  };
  /** Sign in again from the failed screen: records an attempt when storage allows, then leaves for the sign-in. */
  signIn(returns: readonly string[]): void;
  /** A newer load is the page's: whatever this one reports is ignored. */
  supersede(): void;
  /** Neither leaving nor superseded: the one check before the load shows anything. */
  mayShow(): boolean;
}

/** The sign-in route, checked against the document (it is a navigation, not a call, so the client does not send it).
 * Its `return` values are not in the document: the API reads them itself and judges them. */
const SIGN_IN = "/api/auth/login" satisfies keyof paths;

/** The client's own query writer, for the addresses this module writes itself: each name and value escaped, a list as
 * repeated names. */
const serializeQuery = createQuerySerializer({ array: { style: "form", explode: true } });

function withQuery(path: string, query: Record<string, string | readonly string[] | null>): string {
  const search = serializeQuery(Object.fromEntries(Object.entries(query).filter(([, value]) => value !== null)));
  return search === "" ? path : `${path}?${search}`;
}

/** Thrown by the client's `fetch` when the load is gone, a 401 included (B1 has then already been carried out). */
class GoneSignal extends Error {}

/** Thrown by the client's `fetch` when the answer can't be used: none came whole (the request or the body's read
 * failed), or its body is not JSON, which every API answer is. */
class UnusableAnswer extends Error {}

/** True when `text` is JSON. `JSON.parse` throws when it is not; the value itself is the client's to read, and JSON has
 * no `undefined`, so a parsed value is never one. */
function isJson(text: string): boolean {
  try {
    const value: unknown = JSON.parse(text);
    return value !== undefined;
  } catch {
    return false;
  }
}

type Api = ReturnType<typeof createClient<paths>>;

/**
 * `GET key` with `params`, answered with that path's own body type. The client checks a call to one written-out path,
 * but TypeScript cannot follow a path chosen by a type parameter (`K`) through the client's conditional types. So the
 * request goes over every read path at once, and the answer is taken as `K`'s: the frontend's one trusted step. It is
 * sound because `K` picks both: `useRead`'s caller writes one path, and its params and body are that path's (checked
 * there).
 */
async function getByPathKey<K extends ReadKey>(
  api: Api,
  key: K,
  params: ReadParams<K>,
): Promise<{ readonly status: number; readonly body: ReadBody<K> | undefined }> {
  const path: ReadKey = key;
  // trust: `params` are `key`'s own (see above)
  const { data, response } = await api.GET(path, { params } as MaybeOptionalInit<paths[ReadKey], "get">);
  // trust: the answer to `key` is `key`'s body (see above)
  return { status: response.status, body: data as ReadBody<K> | undefined };
}

export function makeLoad(options: LoadOptions): Load {
  const { taken, byHistory, target, origin, effects } = options;
  let leaving = false;
  let superseded = false;
  const mayShow = (): boolean => !leaving && !superseded;

  /** The one way the load navigates away: nothing (and false) when it is already leaving or superseded. Once the
   * navigation has started, the document is going away and nothing of the load shows; a navigation that throws is a
   * fault of the shell's own, and the load is not leaving. */
  function leave(navigate: () => void): boolean {
    if (!mayShow()) return false;
    navigate();
    leaving = true;
    return true;
  }

  function toFailedScreen(reason: FailedReason): void {
    leave(() => effects.replace(withQuery(literalAddress("sign-in-failed"), { reason, return: target })));
  }

  /** A 401: carry out B1's decision. The load leaves, so a second 401 answered later finds it gone. */
  function unauthorized(source: Source): void {
    const decision = decideUnauthorized({ taken, byHistory, source });
    if (decision.kind === "failed") return toFailedScreen(decision.reason);
    if (!effects.record(target, decision.again)) return toFailedScreen("storage-unavailable");
    leave(() => effects.assign(withQuery(SIGN_IN, { return: target })));
  }

  /** A typed client whose every request is the load's: none is sent once the load is gone, and a 401 is `on401`'s. */
  function clientFor(on401: On401): Api {
    return createClient<paths>({
      baseUrl: origin,
      credentials: "same-origin",
      cache: "no-store",
      headers: { Accept: "application/json" },
      async fetch(request) {
        if (!mayShow()) throw new GoneSignal();
        let response: Response;
        let body: string;
        try {
          response = await effects.fetch(request);
          body = await response.text(); // read whole here, so a body cut off is no answer either
        } catch {
          throw mayShow() ? new UnusableAnswer() : new GoneSignal();
        }
        if (!mayShow()) throw new GoneSignal();
        if (on401 !== "returned" && response.status === 401) {
          unauthorized(on401);
          throw new GoneSignal();
        }
        if (body !== "" && !isJson(body)) throw new UnusableAnswer();
        const { status, statusText, headers } = response;
        return new Response(body === "" ? null : body, { status, statusText, headers });
      },
    });
  }
  /** One client per 401 policy. */
  const api: Readonly<Record<On401, Api>> = { me: clientFor("me"), later: clientFor("later"), returned: clientFor("returned") };

  /** One call: gone, the server's error, or its answer. Anything else it throws is the shell's own fault, and goes on
   * to the caller (the error state's "something stopped working"). */
  async function send<T>(call: () => Promise<T>): Promise<Outcome<{ readonly kind: "answer"; readonly answer: T }>> {
    try {
      const answer = await call();
      return mayShow() ? { kind: "answer", answer } : { kind: "gone" };
    } catch (error) {
      if (error instanceof GoneSignal) return { kind: "gone" };
      if (error instanceof UnusableAnswer) return { kind: "error" };
      throw error;
    }
  }

  const client: Load["client"] = {
    async me() {
      const sent = await send(() => api.me.GET("/api/me"));
      if (sent.kind !== "answer") return sent;
      const { data, response } = sent.answer;
      // A cookie session is always a person (F3); the union's own `kind` says so.
      return response.status === 200 && data?.kind === "person" ? { kind: "ok", me: data } : { kind: "error" };
    },
    async read<K extends ReadKey>(key: K, params: ReadParams<K>): Promise<ReadResult<K>> {
      const sent = await send(() => getByPathKey(api.later, key, params));
      if (sent.kind !== "answer") return sent;
      const { body, status } = sent.answer;
      if (status === 404) return { kind: "not-available" };
      return status === 200 && body !== undefined ? { kind: "ok", body } : { kind: "error" };
    },
    async signOut() {
      const sent = await send(() => api.returned.POST("/api/auth/logout", { parseAs: "stream" }));
      if (sent.kind !== "answer") return sent;
      const { response } = sent.answer;
      // 2xx: signed out. 401: already signed out, the same exit; replace, so Back cannot return to a signed-in page.
      if (!(response.ok || response.status === 401)) return { kind: "error" };
      return leave(() => effects.replace(literalAddress("root"))) ? { kind: "left" } : { kind: "gone" };
    },
  };

  return {
    // Each read is sent at most once per load: retries off, no refetch on focus or reconnect, data that never goes
    // stale and entries kept for the load's life. A query function throws only for a fault, which `useRead` rethrows.
    queryClient: new QueryClient({
      defaultOptions: {
        queries: { retry: false, refetchOnWindowFocus: false, refetchOnReconnect: false, refetchOnMount: false, staleTime: Infinity, gcTime: Infinity },
      },
    }),
    client,
    signIn(returns) {
      // The values are handed to the sign-in route unjudged: the API judges them.
      leave(() => {
        effects.record(returns[0] ?? null, false); // when storage allows
        effects.assign(withQuery(SIGN_IN, { return: returns }));
      });
    },
    supersede() {
      superseded = true;
    },
    mayShow,
  };
}
