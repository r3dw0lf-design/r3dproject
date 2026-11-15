// RETROOS account API as a Cloudflare Worker (served at /api/*, static files come from ./public).
// Accounts live in D1; the tables are created automatically on first request.
const enc = new TextEncoder();
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hex = (n) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, '0')).join('');
const json = (d, s = 200, h = {}) => new Response(JSON.stringify(d), { status: s, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...h } });
const sha = async (t) => b64(await crypto.subtle.digest('SHA-256', enc.encode(t)));
const cookie = (v, age) => `sid=${v}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${age}`;
const DAY = 86400;

async function hash(pw, salt) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return b64(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 100000 }, k, 256));
}

async function sessionUser(req, env) {
  const m = (req.headers.get('Cookie') || '').match(/(?:^|;\s*)sid=([a-f0-9]+)/);
  if (!m) return null;
  return env.DB.prepare('SELECT u.id, u.username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ? AND s.expires > ?')
    .bind(await sha(m[1]), Date.now()).first();
}

async function startSession(env, uid) {
  const t = hex(32);
  await env.DB.prepare('INSERT INTO sessions(token, user_id, expires) VALUES(?,?,?)').bind(await sha(t), uid, Date.now() + 30 * DAY * 1000).run();
  return cookie(t, 30 * DAY);
}

let ready = false;
async function ensureSchema(env) {
  if (ready) return;
  await env.DB.batch([
    env.DB.prepare('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE, salt TEXT NOT NULL, hash TEXT NOT NULL, created INTEGER NOT NULL, notes TEXT NOT NULL DEFAULT \'\')'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS decks (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, title TEXT NOT NULL, data TEXT NOT NULL, updated INTEGER NOT NULL)'),
    env.DB.prepare('CREATE INDEX IF NOT EXISTS decks_user ON decks(user_id)'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires INTEGER NOT NULL)'),
  ]);
  ready = true;
}

async function handle(request, env) {
  if (!env.DB) return json({ error: 'DATABASE NOT BOUND' }, 500);
  await ensureSchema(env);
  const route = new URL(request.url).pathname.replace(/^\/api\//, '').replace(/\/$/, '');
  const method = request.method;
  let body = {};
  if (method === 'POST' || method === 'PUT') { try { body = await request.json(); } catch { return json({ error: 'BAD REQUEST' }, 400); } }

  try {
    if (route === 'register' && method === 'POST') {
      const u = String(body.username || '').trim(), p = String(body.password || '');
      if (!/^[A-Za-z0-9_]{3,16}$/.test(u)) return json({ error: 'USERNAME: 3-16 LETTERS, NUMBERS OR _' }, 400);
      if (p.length < 6 || p.length > 100) return json({ error: 'PASSWORD: 6-100 CHARACTERS' }, 400);
      const salt = crypto.getRandomValues(new Uint8Array(16));
      let uid;
      try {
        const r = await env.DB.prepare('INSERT INTO users(username, salt, hash, created) VALUES(?,?,?,?)').bind(u, b64(salt), await hash(p, salt), Date.now()).run();
        uid = r.meta.last_row_id;
      } catch (e) {
        if (/UNIQUE/i.test(String(e.message))) return json({ error: 'USERNAME ALREADY TAKEN' }, 409);
        throw e;
      }
      return json({ username: u }, 200, { 'Set-Cookie': await startSession(env, uid) });
    }

    if (route === 'login' && method === 'POST') {
      const u = String(body.username || '').trim(), p = String(body.password || '');
      const row = await env.DB.prepare('SELECT id, username, salt, hash FROM users WHERE username = ?').bind(u).first();
      const ok = row && (await hash(p, unb64(row.salt))) === row.hash;
      if (!ok) return json({ error: 'INVALID USERNAME OR PASSWORD' }, 401);
      return json({ username: row.username }, 200, { 'Set-Cookie': await startSession(env, row.id) });
    }

    if (route === 'logout' && method === 'POST') {
      const m = (request.headers.get('Cookie') || '').match(/(?:^|;\s*)sid=([a-f0-9]+)/);
      if (m) await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(await sha(m[1])).run();
      return json({ ok: true }, 200, { 'Set-Cookie': cookie('', 0) });
    }

    const user = await sessionUser(request, env);
    if (route === 'me') return user ? json({ username: user.username }) : json({ error: 'NOT LOGGED IN' }, 401);
    if (!user) return json({ error: 'NOT LOGGED IN' }, 401);

    if (route === 'notes' && method === 'GET') {
      const r = await env.DB.prepare('SELECT notes FROM users WHERE id = ?').bind(user.id).first();
      return json({ notes: r ? r.notes : '' });
    }
    if (route === 'notes' && method === 'PUT') {
      const n = String(body.notes || '').slice(0, 20000);
      await env.DB.prepare('UPDATE users SET notes = ? WHERE id = ?').bind(n, user.id).run();
      return json({ ok: true });
    }

    // ---- Advanced PPT: each deck belongs to the logged-in user ----
    if (route === 'decks' && method === 'GET') {
      const r = await env.DB.prepare('SELECT id, title, updated FROM decks WHERE user_id = ? ORDER BY updated DESC').bind(user.id).all();
      return json({ decks: r.results });
    }
    if (route === 'decks' && method === 'POST') {
      const data = JSON.stringify(body.data || {});
      if (data.length > 1800000) return json({ error: 'DECK TOO LARGE (use smaller images)' }, 413);
      const c = await env.DB.prepare('SELECT COUNT(*) AS n FROM decks WHERE user_id = ?').bind(user.id).first();
      if (c.n >= 100) return json({ error: 'DECK LIMIT REACHED (100)' }, 400);
      const id = hex(8);
      await env.DB.prepare('INSERT INTO decks(id, user_id, title, data, updated) VALUES(?,?,?,?,?)').bind(id, user.id, String(body.title || 'Untitled').slice(0, 80), data, Date.now()).run();
      return json({ id });
    }
    const dm = route.match(/^decks\/([a-f0-9]{16})$/);
    if (dm) {
      const id = dm[1];
      if (method === 'GET') {
        const r = await env.DB.prepare('SELECT id, title, data FROM decks WHERE id = ? AND user_id = ?').bind(id, user.id).first();
        return r ? json({ id: r.id, title: r.title, data: JSON.parse(r.data) }) : json({ error: 'DECK NOT FOUND' }, 404);
      }
      if (method === 'PUT') {
        const data = JSON.stringify(body.data || {});
        if (data.length > 1800000) return json({ error: 'DECK TOO LARGE (use smaller images)' }, 413);
        const r = await env.DB.prepare('UPDATE decks SET title = ?, data = ?, updated = ? WHERE id = ? AND user_id = ?').bind(String(body.title || 'Untitled').slice(0, 80), data, Date.now(), id, user.id).run();
        return r.meta.changes ? json({ ok: true }) : json({ error: 'DECK NOT FOUND' }, 404);
      }
      if (method === 'DELETE') {
        await env.DB.prepare('DELETE FROM decks WHERE id = ? AND user_id = ?').bind(id, user.id).run();
        return json({ ok: true });
      }
    }
    return json({ error: 'NOT FOUND' }, 404);
  } catch (e) {
    return json({ error: 'SERVER ERROR' }, 500);
  }
}

export default { fetch: (request, env) => handle(request, env).catch(() => json({ error: 'SERVER ERROR' }, 500)) };
