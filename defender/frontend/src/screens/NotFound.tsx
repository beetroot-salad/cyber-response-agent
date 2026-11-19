/** What a pathname that matches no shape gets. It is not a route. */
export function NotFound() {
  return (
    <main data-screen="not-found">
      <h1>Not found</h1>
      <p>There is nothing at this address.</p>
    </main>
  );
}
