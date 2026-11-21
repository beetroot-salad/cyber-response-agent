// The tenant repository's page on the forge, which the API serves on `/api/me` (`repo_url`), checked as the browser
// reads it. It is the one address a screen may link to that is not the app's own (#1581 r3.3's markup rule, amended
// for Home: we host the forge, so a screen may send a person there). The check is here because only the shell has the
// browser's URL parser and the app's origin; a screen gets the checked value through `useRepoAddress` and writes it
// with `repoLink` (`src/addresses.ts`), the only function that takes one. The type is in `types.ts`, which screens
// compile; this file uses the browser and only the shell imports it.
import type { RepoAddress } from "./types";

/** `value` as a `RepoAddress`, or null when it is missing or fails the check. */
export function repoAddress(value: string | null | undefined, appOrigin: string): RepoAddress | null {
  if (value === null || value === undefined) return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  if (url.hostname === "" || url.username !== "" || url.password !== "") return null;
  if (url.search !== "" || url.hash !== "") return null;
  if (url.origin === new URL(appOrigin).origin) return null;
  // trust: the checks above are what a RepoAddress promises
  return url.href as RepoAddress;
}
