// The API's types, from the OpenAPI document the API's own app produced (PR3, F3), and what a call of the load comes
// to. Nothing here describes a response by hand but the sign-in callback's reasons, which the document has no field for.
import type { components, paths } from "../generated/api";

/** The OpenAPI path keys that have a GET: what `useRead` and the load's `client.read` are keyed by. */
export type ReadKey = { [K in keyof paths]: paths[K] extends { get: object } ? K : never }[keyof paths];
type GetOperation<K extends ReadKey> = paths[K] extends { get: infer Operation } ? Operation : never;
/** That operation's parameters, path and query together, as the generated types declare them. */
export type ReadParams<K extends ReadKey> = GetOperation<K> extends { parameters: infer P } ? P : never;
export type ReadBody<K extends ReadKey> = GetOperation<K> extends { responses: { 200: { content: { "application/json": infer B } } } }
  ? B
  : never;

/** The load is leaving or is no longer the page's: whatever the answer was, nothing more is done or shown. */
export type Gone = { readonly kind: "gone" };
/** The server did not answer as the call needs: no answer, an answer that is not JSON, or a status the call does not
 * expect (a 500, a 403). The server's failure, not the app's. */
export type ServerError = { readonly kind: "error" };
/** What every call of the load comes to: gone, the server's error, or the call's own results. */
export type Outcome<T> = Gone | ServerError | T;

/** A read's closed result, as the load's client gives it (Am-5 point 4). A screen's `useRead` shows `gone` as loading. */
export type ReadResult<K extends ReadKey> = Outcome<{ readonly kind: "ok"; readonly body: ReadBody<K> } | { readonly kind: "not-available" }>;

export type Person = components["schemas"]["Me"];

/** The reasons the API's sign-in callback sends a person to the failed screen with (the API's identity service). Not in
 * the OpenAPI document: the callback answers with a redirect. */
export type CallbackReason =
  | "prelogin-missing"
  | "login-attempt-invalid"
  | "unknown-account"
  | "otp-required"
  | "unavailable"
  | "bad-request"
  | "error";
