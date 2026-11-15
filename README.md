# RETROOS 86 (Cloudflare Worker)

Retro CRT login + custom desktop OS. Set up the same way as Sun & Moon: one Worker serves `public/` and the `/api/*` account routes.
Accounts are stored in D1 (usernames are unique, case-insensitive). The database and its tables are created automatically on the first deploy / first request.

## Deploy
Cloudflare dashboard -> Workers & Pages -> Create -> Import a repository (or upload this folder with Git).
Build command: leave empty. Deploy command: `npx wrangler deploy`.
Or from a terminal in this folder: `npx wrangler deploy`.
Nothing else to set up: no database ID to paste, no secrets, no environment variables.

## Notes
- Passwords are stored only as salted PBKDF2 hashes; logins use an HttpOnly cookie backed by a server-side session (30 days).
- 12 login attempts / 10 registrations per 10 minutes per IP, then it asks you to wait.
- Try it locally with `npx wrangler dev` (cookies work over http there).
