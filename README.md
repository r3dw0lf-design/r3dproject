# RETROOS 86

Retro CRT login + custom desktop OS. Cloudflare Pages + Pages Functions + D1 (for accounts).

## Deploy
1. Push this folder to a GitHub repo.
2. `npx wrangler login` then `npx wrangler d1 create retroos-db` — copy the `database_id` into `wrangler.toml`.
3. Create tables on the live DB: `npx wrangler d1 execute retroos-db --remote --file=schema.sql`
4. Cloudflare dashboard -> Workers & Pages -> Create -> Pages -> Connect to Git -> pick the repo.
   Framework: None. Build command: (empty). Build output directory: `public`.
5. After first deploy: Settings -> Bindings -> Add -> D1 database -> variable name `DB` -> `retroos-db` (do this for Production, and Preview if wanted). Redeploy.

## Local test
`npx wrangler d1 execute retroos-db --local --file=schema.sql`
`npx wrangler pages dev public --d1=DB=retroos-db`
