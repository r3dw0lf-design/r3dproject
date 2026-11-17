# RETROOS 86 (Cloudflare Worker)

Retro CRT login + custom desktop OS. One Worker serves `public/` and the `/api/*` account routes.
Accounts are stored in D1 (usernames are unique, case-insensitive). The database and its tables are created automatically.

Deploy: `npx wrangler deploy`  (Cloudflare Workers & Pages -> Import a repository; deploy command `npx wrangler deploy`)

Import HTML decks: in Advanced PPT press "Import HTML" (or drag an .html file onto the page). The file runs in a sandboxed frame so its own scripts, animations and styles work exactly as built; text edits it saves are stored in your account.

Desktop: double-click an icon to open it. Drag icons anywhere, or onto a folder. Right-click the desktop for New > Folder / Text file and Open in Terminal; right-click an icon for Open / Rename / Delete (F2 and Del also work). Text files open in Notepad. Layout is saved per account in the D1 `desktops` table (created automatically).
Decks are kept inside Advanced PPT (My decks). Use its 'To desktop' button to put a shortcut on the desktop. Drag a .html presentation onto the desktop (or use IMPORT HTML) to import it.
