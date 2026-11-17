# RETROOS 86 (Cloudflare Worker)

Retro CRT login + custom desktop OS. One Worker serves `public/` and the `/api/*` account routes.
Accounts are stored in D1 (usernames are unique, case-insensitive). The database and its tables are created automatically.

Deploy: `npx wrangler deploy`  (Cloudflare Workers & Pages -> Import a repository; deploy command `npx wrangler deploy`)

Import HTML decks: in Advanced PPT press "Import HTML" (or drag an .html file onto the page). The file runs in a sandboxed frame so its own scripts, animations and styles work exactly as built; text edits it saves are stored in your account.

Desktop: double-click an icon or file to open it. Advanced PPT opens in a window (maximize/restore with the □ button). Your saved decks appear as file icons; double-click one to open it. Drag a .html presentation onto the desktop (or use IMPORT HTML) to import it.
