// What a pathname that matches no shape gets. It is not a route. The shell asks `/api/me` for it, so it has the
// top bar.
import { TopBar } from "./TopBar";

export function NotFound() {
  return (
    <>
      <TopBar />
      <main data-screen="not-found">
        <h1>Not found</h1>
        <p>There is nothing at this address.</p>
      </main>
    </>
  );
}
