<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

## Project rules

- The onboarding form saves to PostgreSQL through the `submitOnboarding` server function (`src/lib/onboarding-actions.server.ts`, pool in `src/lib/db.ts`). Keep `DATABASE_URL` server-side only: never prefix it with `VITE_` and never import `src/lib/db.ts` from UI code.
