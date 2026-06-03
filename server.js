import express from 'express';
import session from 'express-session';
import fetch from 'node-fetch';
import cron from 'node-cron';
import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const db = new Database('./data.db');

// ─── DB INIT ─────────────────────────────────────────────────────────────────

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    discord_id TEXT PRIMARY KEY,
    discord_username TEXT,
    discord_avatar TEXT,
    pelican_user_id INTEGER,
    is_admin INTEGER DEFAULT 0,
    is_banned INTEGER DEFAULT 0,
    ban_reason TEXT,
    max_servers INTEGER DEFAULT 2,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pelican_server_id TEXT UNIQUE,
    owner_discord_id TEXT,
    name TEXT,
    expires_at TEXT,
    is_deleted INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (owner_discord_id) REFERENCES users(discord_id)
  );

  CREATE TABLE IF NOT EXISTS default_specs (
    id INTEGER PRIMARY KEY DEFAULT 1,
    cpu INTEGER DEFAULT 100,
    memory INTEGER DEFAULT 512,
    disk INTEGER DEFAULT 1024,
    duration_days INTEGER DEFAULT 3,
    max_servers_per_user INTEGER DEFAULT 2
  );

  INSERT OR IGNORE INTO default_specs (id) VALUES (1);
`);

// ─── ENV ─────────────────────────────────────────────────────────────────────
const {
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,
  PELICAN_PANEL_URL,
  PELICAN_API_KEY,
  SESSION_SECRET,
  PORT = 3000,
} = process.env;

const ADMIN_IDS = ['630804914473402398', '1508050922322788518'];

// ─── PELICAN API HELPERS ──────────────────────────────────────────────────────

async function pelicanRequest(method, endpoint, body = null) {
  const res = await fetch(`${PELICAN_PANEL_URL}/api/application${endpoint}`, {
    method,
    headers: {
      'Authorization': `Bearer ${PELICAN_API_KEY}`,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Pelican API ${method} ${endpoint} → ${res.status}: ${err}`);
  }
  if (res.status === 204) return null;
  return res.json();
}

async function createPelicanUser(discord_id, username, email) {
  const password = crypto.randomUUID().replace(/-/g, '').slice(0, 16) + 'A1!';
  const data = await pelicanRequest('POST', '/users', {
    email,
    username: `dc_${discord_id}`,
    first_name: username,
    last_name: 'User',
    password,
  });
  return data.attributes.id;
}

async function createPelicanServer(name, pelican_user_id, specs) {
  const { cpu, memory, disk } = specs;
  const data = await pelicanRequest('POST', '/servers', {
    name,
    user: pelican_user_id,
    egg: parseInt(process.env.DEFAULT_EGG_ID || '1'),
    docker_image: process.env.DEFAULT_DOCKER_IMAGE || 'ghcr.io/pelican-eggs/generic:java',
    startup: process.env.DEFAULT_STARTUP || 'java -jar server.jar',
    environment: { STARTUP_VAR: 'start' },
    limits: { memory, swap: 0, disk, io: 500, cpu },
    feature_limits: { databases: 0, backups: 0, allocations: 1 },
    allocation: { default: parseInt(process.env.DEFAULT_ALLOCATION_ID || '1') },
    start_on_completion: false,
  });
  return data.attributes.uuid;
}

async function deletePelicanServer(pelican_server_id) {
  try {
    await pelicanRequest('DELETE', `/servers/${pelican_server_id}`);
  } catch (e) {
    console.error('Pelican delete error:', e.message);
  }
}

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 7 * 24 * 60 * 60 * 1000 },
}));

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  const user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(req.session.user.id);
  if (!user?.is_admin) return res.status(403).json({ error: 'Admin only' });
  next();
}

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────

app.get('/auth/discord', (req, res) => {
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: 'code',
    scope: 'identify email',
  });
  res.redirect(`https://discord.com/oauth2/authorize?${params}`);
});

app.get('/auth/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.redirect('/?error=no_code');

  try {
    // Exchange code for token
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: DISCORD_REDIRECT_URI,
      }),
    });
    const tokenData = await tokenRes.json();

    // Get Discord user info
    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const discordUser = await userRes.json();

    const isAdmin = ADMIN_IDS.includes(discordUser.id);

    // Find or create user in DB
    let dbUser = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(discordUser.id);

    if (!dbUser) {
      const specs = db.prepare('SELECT * FROM default_specs WHERE id = 1').get();
      // Create Pelican account
      let pelicanId = null;
      try {
        pelicanId = await createPelicanUser(
          discordUser.id,
          discordUser.username,
          discordUser.email || `${discordUser.id}@discord.placeholder`
        );
      } catch (e) {
        console.error('Pelican user create error:', e.message);
      }

      db.prepare(`
        INSERT INTO users (discord_id, discord_username, discord_avatar, pelican_user_id, is_admin, max_servers)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(
        discordUser.id,
        discordUser.username,
        discordUser.avatar,
        pelicanId,
        isAdmin ? 1 : 0,
        specs.max_servers_per_user
      );
      dbUser = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(discordUser.id);
    } else if (isAdmin && !dbUser.is_admin) {
      db.prepare('UPDATE users SET is_admin = 1 WHERE discord_id = ?').run(discordUser.id);
    }

    if (dbUser.is_banned) return res.redirect('/?error=banned');

    req.session.user = { id: discordUser.id, username: discordUser.username, avatar: discordUser.avatar };
    res.redirect('/dashboard');
  } catch (e) {
    console.error('Auth error:', e);
    res.redirect('/?error=auth_failed');
  }
});

app.post('/auth/logout', requireAuth, (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// ─── API: USER ────────────────────────────────────────────────────────────────

app.get('/api/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(req.session.user.id);
  const servers = db.prepare(`
    SELECT * FROM servers
    WHERE owner_discord_id = ? AND is_deleted = 0
    ORDER BY created_at DESC
  `).all(req.session.user.id);
  const specs = db.prepare('SELECT * FROM default_specs WHERE id = 1').get();
  res.json({ user, servers, specs });
});

// ─── API: SERVERS ─────────────────────────────────────────────────────────────

app.post('/api/servers', requireAuth, async (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(req.session.user.id);
  if (user.is_banned) return res.status(403).json({ error: 'Banned' });

  const activeServers = db.prepare(`
    SELECT COUNT(*) as count FROM servers
    WHERE owner_discord_id = ? AND is_deleted = 0
  `).get(req.session.user.id);

  if (activeServers.count >= user.max_servers) {
    return res.status(400).json({ error: `サーバー上限 (${user.max_servers}個) に達しています` });
  }

  const specs = db.prepare('SELECT * FROM default_specs WHERE id = 1').get();
  const { name } = req.body;
  if (!name || name.length < 2 || name.length > 30) {
    return res.status(400).json({ error: 'サーバー名は2〜30文字で入力してください' });
  }

  try {
    const expiresAt = new Date(Date.now() + specs.duration_days * 24 * 60 * 60 * 1000).toISOString();
    const pelicanId = await createPelicanServer(name, user.pelican_user_id, specs);
    db.prepare(`
      INSERT INTO servers (pelican_server_id, owner_discord_id, name, expires_at)
      VALUES (?, ?, ?, ?)
    `).run(pelicanId, user.discord_id, name, expiresAt);
    res.json({ ok: true, message: 'サーバーを作成しました' });
  } catch (e) {
    console.error('Server create error:', e);
    res.status(500).json({ error: 'サーバー作成に失敗しました: ' + e.message });
  }
});

app.post('/api/servers/:id/extend', requireAuth, async (req, res) => {
  const server = db.prepare('SELECT * FROM servers WHERE id = ? AND is_deleted = 0').get(req.params.id);
  if (!server) return res.status(404).json({ error: 'Not found' });

  const user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(req.session.user.id);
  const isOwner = server.owner_discord_id === req.session.user.id;
  if (!isOwner && !user.is_admin) return res.status(403).json({ error: 'Forbidden' });

  const expiresAt = new Date(server.expires_at);
  const now = new Date();
  const daysLeft = (expiresAt - now) / (1000 * 60 * 60 * 24);

  if (daysLeft > 1 && !user.is_admin) {
    return res.status(400).json({ error: '残り1日以内になるまで延長できません' });
  }

  const specs = db.prepare('SELECT * FROM default_specs WHERE id = 1').get();
  const newExpiry = new Date(expiresAt.getTime() + specs.duration_days * 24 * 60 * 60 * 1000).toISOString();
  db.prepare('UPDATE servers SET expires_at = ? WHERE id = ?').run(newExpiry, server.id);
  res.json({ ok: true, expires_at: newExpiry });
});

app.delete('/api/servers/:id', requireAuth, async (req, res) => {
  const server = db.prepare('SELECT * FROM servers WHERE id = ? AND is_deleted = 0').get(req.params.id);
  if (!server) return res.status(404).json({ error: 'Not found' });

  const user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(req.session.user.id);
  const isOwner = server.owner_discord_id === req.session.user.id;
  if (!isOwner && !user.is_admin) return res.status(403).json({ error: 'Forbidden' });

  await deletePelicanServer(server.pelican_server_id);
  db.prepare('UPDATE servers SET is_deleted = 1 WHERE id = ?').run(server.id);
  res.json({ ok: true });
});

// ─── API: ADMIN ───────────────────────────────────────────────────────────────

app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT u.*, COUNT(s.id) as server_count
    FROM users u
    LEFT JOIN servers s ON s.owner_discord_id = u.discord_id AND s.is_deleted = 0
    GROUP BY u.discord_id
    ORDER BY u.created_at DESC
  `).all();
  res.json(users);
});

app.get('/api/admin/servers', requireAdmin, (req, res) => {
  const servers = db.prepare(`
    SELECT s.*, u.discord_username
    FROM servers s
    JOIN users u ON u.discord_id = s.owner_discord_id
    WHERE s.is_deleted = 0
    ORDER BY s.created_at DESC
  `).all();
  res.json(servers);
});

app.post('/api/admin/users/:id/ban', requireAdmin, (req, res) => {
  const { reason } = req.body;
  if (ADMIN_IDS.includes(req.params.id)) return res.status(400).json({ error: 'Admin cannot be banned' });
  db.prepare('UPDATE users SET is_banned = 1, ban_reason = ? WHERE discord_id = ?').run(reason || 'No reason', req.params.id);
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/unban', requireAdmin, (req, res) => {
  db.prepare('UPDATE users SET is_banned = 0, ban_reason = NULL WHERE discord_id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.patch('/api/admin/users/:id/max-servers', requireAdmin, (req, res) => {
  const { max } = req.body;
  db.prepare('UPDATE users SET max_servers = ? WHERE discord_id = ?').run(max, req.params.id);
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/add-staff', requireAdmin, (req, res) => {
  const requestUser = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(req.session.user.id);
  if (!ADMIN_IDS.includes(req.session.user.id)) return res.status(403).json({ error: 'Only super admins can add staff' });
  db.prepare('UPDATE users SET is_admin = 1 WHERE discord_id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.delete('/api/admin/servers/:id', requireAdmin, async (req, res) => {
  const server = db.prepare('SELECT * FROM servers WHERE id = ? AND is_deleted = 0').get(req.params.id);
  if (!server) return res.status(404).json({ error: 'Not found' });
  await deletePelicanServer(server.pelican_server_id);
  db.prepare('UPDATE servers SET is_deleted = 1 WHERE id = ?').run(server.id);
  res.json({ ok: true });
});

app.post('/api/admin/servers/:id/extend', requireAdmin, (req, res) => {
  const server = db.prepare('SELECT * FROM servers WHERE id = ? AND is_deleted = 0').get(req.params.id);
  if (!server) return res.status(404).json({ error: 'Not found' });
  const specs = db.prepare('SELECT * FROM default_specs WHERE id = 1').get();
  const base = new Date(Math.max(new Date(server.expires_at), Date.now()));
  const newExpiry = new Date(base.getTime() + specs.duration_days * 24 * 60 * 60 * 1000).toISOString();
  db.prepare('UPDATE servers SET expires_at = ? WHERE id = ?').run(newExpiry, server.id);
  res.json({ ok: true, expires_at: newExpiry });
});

app.patch('/api/admin/specs', requireAdmin, (req, res) => {
  const { cpu, memory, disk, duration_days, max_servers_per_user } = req.body;
  db.prepare(`
    UPDATE default_specs SET cpu = ?, memory = ?, disk = ?, duration_days = ?, max_servers_per_user = ?
    WHERE id = 1
  `).run(cpu, memory, disk, duration_days, max_servers_per_user);
  res.json({ ok: true });
});

// ─── CRON: 期限切れサーバー自動削除 ──────────────────────────────────────────

cron.schedule('*/30 * * * *', async () => {
  const expired = db.prepare(`
    SELECT * FROM servers
    WHERE is_deleted = 0 AND expires_at < datetime('now')
  `).all();

  for (const server of expired) {
    console.log(`[CRON] Deleting expired server: ${server.name} (${server.pelican_server_id})`);
    await deletePelicanServer(server.pelican_server_id);
    db.prepare('UPDATE servers SET is_deleted = 1 WHERE id = ?').run(server.id);
  }
  if (expired.length > 0) console.log(`[CRON] Deleted ${expired.length} expired servers`);
});

// ─── SPA FALLBACK ─────────────────────────────────────────────────────────────

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
