import express from 'express';
import session from 'express-session';
import fetch from 'node-fetch';
import cron from 'node-cron';
import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import slowDown from 'express-slow-down';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const db = new Database('./data.db');

// ─── DB INIT ──────────────────────────────────────────────────────────────────

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    discord_id TEXT PRIMARY KEY,
    discord_username TEXT,
    discord_avatar TEXT,
    activevm_user_id INTEGER,
    is_admin INTEGER DEFAULT 0,
    is_banned INTEGER DEFAULT 0,
    ban_reason TEXT,
    max_servers INTEGER DEFAULT 2,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    activevm_server_id TEXT UNIQUE,
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

  CREATE TABLE IF NOT EXISTS blocked_ips (
    ip TEXT PRIMARY KEY,
    reason TEXT,
    blocked_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS request_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT,
    path TEXT,
    status INTEGER,
    ts TEXT DEFAULT (datetime('now'))
  );

  INSERT OR IGNORE INTO default_specs (id) VALUES (1);
`);

// ─── ENV ──────────────────────────────────────────────────────────────────────
const {
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,
  ACTIVEVM_PANEL_URL,
  ACTIVEVM_API_KEY,
  SESSION_SECRET,
  PORT = 3000,
  TRUSTED_PROXIES = '',
} = process.env;

const ADMIN_IDS = ['630804914473402398', '1508050922322788518'];

// ─── IP ブロックリスト（DBベース、即時反映） ──────────────────────────────────

function isBlockedIp(ip) {
  const row = db.prepare('SELECT 1 FROM blocked_ips WHERE ip = ?').get(ip);
  return !!row;
}

function blockIp(ip, reason = 'auto-blocked') {
  db.prepare('INSERT OR IGNORE INTO blocked_ips (ip, reason) VALUES (?, ?)').run(ip, reason);
}

function unblockIp(ip) {
  db.prepare('DELETE FROM blocked_ips WHERE ip = ?').run(ip);
}

// ─── DDoS 対策：ヘルメット（セキュリティヘッダー） ───────────────────────────

app.set('trust proxy', TRUSTED_PROXIES ? TRUSTED_PROXIES.split(',') : 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'https://cdn.discordapp.com'],
      connectSrc: ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// ─── DDoS 対策：グローバル IP ブロックミドルウェア ──────────────────────────

app.use((req, res, next) => {
  const ip = req.ip || req.socket.remoteAddress;
  if (isBlockedIp(ip)) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  next();
});

// ─── DDoS 対策：リクエストサイズ制限 ─────────────────────────────────────────

app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: false, limit: '16kb' }));

// ─── DDoS 対策：グローバルレート制限（全体）────────────────────────────────

const globalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,      // 1分
  max: 200,                       // 1分200リクエストまで
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.ip,
  handler: (req, res) => {
    const ip = req.ip;
    // 5分間に3回超過したら自動ブロック
    const key = `ratelimit:${ip}`;
    globalLimiter._overflowMap = globalLimiter._overflowMap || {};
    const entry = globalLimiter._overflowMap[key] || { count: 0, first: Date.now() };
    entry.count++;
    globalLimiter._overflowMap[key] = entry;
    if (Date.now() - entry.first > 5 * 60 * 1000) {
      entry.count = 1; entry.first = Date.now();
    }
    if (entry.count >= 3) {
      blockIp(ip, 'rate-limit-exceeded');
      console.warn(`[SECURITY] Auto-blocked IP: ${ip} (rate limit exceeded repeatedly)`);
    }
    res.status(429).json({ error: 'Too many requests. Slow down.' });
  },
  skip: (req) => {
    // 静的ファイルはスキップ
    return req.path.startsWith('/assets/') || req.path.endsWith('.ico');
  },
});
app.use(globalLimiter);

// ─── DDoS 対策：APIエンドポイント専用の厳しいレート制限 ──────────────────────

const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 60,
  keyGenerator: (req) => req.ip,
  handler: (req, res) => res.status(429).json({ error: 'API rate limit exceeded' }),
});

const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,     // 10分
  max: 10,                        // 10回まで（ブルートフォース対策）
  keyGenerator: (req) => req.ip,
  handler: (req, res) => {
    blockIp(req.ip, 'auth-brute-force');
    res.status(429).json({ error: 'Too many login attempts. You have been temporarily blocked.' });
  },
});

const serverCreateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,     // 1時間
  max: 5,                         // 1時間に5回まで作成
  keyGenerator: (req) => req.ip,
  handler: (req, res) => res.status(429).json({ error: 'サーバー作成の制限に達しました（1時間に5回まで）' }),
});

// ─── DDoS 対策：スローダウン（帯域圧迫への対応） ─────────────────────────────

const speedLimiter = slowDown({
  windowMs: 30 * 1000,           // 30秒
  delayAfter: 30,                 // 30リクエスト以降から遅延
  delayMs: (hits) => (hits - 30) * 100,  // 1リクエストごとに+100ms遅延
  maxDelayMs: 5000,
});
app.use('/api', speedLimiter);

// ─── DDoS 対策：異常ボディ・Refererチェック ──────────────────────────────────

app.use((req, res, next) => {
  // User-Agentが完全に空のリクエストは拒否（多くのスクリプト系ボット）
  if (req.method !== 'GET' && !req.headers['user-agent']) {
    return res.status(400).json({ error: 'Bad request' });
  }
  next();
});

// ─── セッション ───────────────────────────────────────────────────────────────

app.use(session({
  secret: SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  name: 'avm.sid',
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  },
}));

// ─── 静的ファイル ──────────────────────────────────────────────────────────────

app.use(express.static(path.join(__dirname, 'public'), {
  etag: true,
  maxAge: '1h',
}));

// ─── ログ記録（軽量、非同期）─────────────────────────────────────────────────

app.use((req, res, next) => {
  const ip = req.ip;
  res.on('finish', () => {
    if (res.statusCode >= 400) {
      setImmediate(() => {
        db.prepare('INSERT INTO request_log (ip, path, status) VALUES (?, ?, ?)').run(
          ip, req.path.slice(0, 100), res.statusCode
        );
        // 直近1分間に同一IPから40件以上の4xx/5xxがあれば自動ブロック
        const errorCount = db.prepare(`
          SELECT COUNT(*) as c FROM request_log
          WHERE ip = ? AND status >= 400 AND ts > datetime('now', '-1 minute')
        `).get(ip);
        if (errorCount.c >= 40 && !isBlockedIp(ip)) {
          blockIp(ip, 'auto-error-flood');
          console.warn(`[SECURITY] Auto-blocked IP ${ip} (error flood: ${errorCount.c} errors/min)`);
        }
      });
    }
  });
  next();
});

// ─── 認証ミドルウェア ─────────────────────────────────────────────────────────

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

// ─── ACTIVEVM API ─────────────────────────────────────────────────────────────

async function activeVmRequest(method, endpoint, body = null) {
  const res = await fetch(`${ACTIVEVM_PANEL_URL}/api/application${endpoint}`, {
    method,
    headers: {
      'Authorization': `Bearer ${ACTIVEVM_API_KEY}`,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(10000), // 10秒タイムアウト
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`ActiveVm API ${method} ${endpoint} → ${res.status}: ${err}`);
  }
  if (res.status === 204) return null;
  return res.json();
}

async function createActiveVmUser(discord_id, username, email) {
  const password = crypto.randomUUID().replace(/-/g, '').slice(0, 16) + 'A1!';
  const data = await activeVmRequest('POST', '/users', {
    email,
    username: `dc_${discord_id}`,
    first_name: username,
    last_name: 'User',
    password,
  });
  return data.attributes.id;
}

async function createActiveVmServer(name, activeVm_user_id, specs) {
  const { cpu, memory, disk } = specs;
  const data = await activeVmRequest('POST', '/servers', {
    name,
    user: activeVm_user_id,
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

async function deleteActiveVmServer(activeVm_server_id) {
  try {
    await activeVmRequest('DELETE', `/servers/${activeVm_server_id}`);
  } catch (e) {
    console.error('ActiveVm delete error:', e.message);
  }
}

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────

app.get('/auth/discord', authLimiter, (req, res) => {
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    redirect_uri: DISCORD_REDIRECT_URI,
    response_type: 'code',
    scope: 'identify email',
  });
  res.redirect(`https://discord.com/oauth2/authorize?${params}`);
});

app.get('/auth/callback', authLimiter, async (req, res) => {
  const { code } = req.query;
  if (!code || typeof code !== 'string' || code.length > 64) {
    return res.redirect('/?error=no_code');
  }

  try {
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
      signal: AbortSignal.timeout(8000),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) return res.redirect('/?error=auth_failed');

    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
      signal: AbortSignal.timeout(8000),
    });
    const discordUser = await userRes.json();
    if (!discordUser.id) return res.redirect('/?error=auth_failed');

    const isAdmin = ADMIN_IDS.includes(discordUser.id);
    let dbUser = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(discordUser.id);

    if (!dbUser) {
      const specs = db.prepare('SELECT * FROM default_specs WHERE id = 1').get();
      let activeVmId = null;
      try {
        activeVmId = await createActiveVmUser(
          discordUser.id,
          discordUser.username,
          discordUser.email || `${discordUser.id}@discord.placeholder`
        );
      } catch (e) {
        console.error('ActiveVm user create error:', e.message);
      }

      db.prepare(`
        INSERT INTO users (discord_id, discord_username, discord_avatar, activevm_user_id, is_admin, max_servers)
        VALUES (?, ?, ?, ?, ?, ?)
      `).run(
        discordUser.id,
        discordUser.username,
        discordUser.avatar,
        activeVmId,
        isAdmin ? 1 : 0,
        specs.max_servers_per_user
      );
      dbUser = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(discordUser.id);
    } else if (isAdmin && !dbUser.is_admin) {
      db.prepare('UPDATE users SET is_admin = 1 WHERE discord_id = ?').run(discordUser.id);
    }

    if (dbUser.is_banned) return res.redirect('/?error=banned');

    req.session.regenerate((err) => {  // セッション固定攻撃対策
      if (err) return res.redirect('/?error=auth_failed');
      req.session.user = {
        id: discordUser.id,
        username: discordUser.username,
        avatar: discordUser.avatar,
      };
      res.redirect('/dashboard');
    });
  } catch (e) {
    console.error('Auth error:', e);
    res.redirect('/?error=auth_failed');
  }
});

app.post('/auth/logout', requireAuth, (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// ─── API: USER ────────────────────────────────────────────────────────────────

app.use('/api', apiLimiter);

app.get('/api/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(req.session.user.id);
  const servers = db.prepare(`
    SELECT * FROM servers WHERE owner_discord_id = ? AND is_deleted = 0
    ORDER BY created_at DESC
  `).all(req.session.user.id);
  const specs = db.prepare('SELECT * FROM default_specs WHERE id = 1').get();
  res.json({ user, servers, specs });
});

// ─── API: SERVERS ─────────────────────────────────────────────────────────────

app.post('/api/servers', requireAuth, serverCreateLimiter, async (req, res) => {
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
  if (!name || typeof name !== 'string' || name.length < 2 || name.length > 30) {
    return res.status(400).json({ error: 'サーバー名は2〜30文字で入力してください' });
  }
  // XSS対策：特殊文字を制限
  if (!/^[\w\-\. ぁ-ん亜-熙ァ-ヶ]+$/.test(name)) {
    return res.status(400).json({ error: '使用できない文字が含まれています' });
  }

  try {
    const expiresAt = new Date(Date.now() + specs.duration_days * 24 * 60 * 60 * 1000).toISOString();
    const activeVmId = await createActiveVmServer(name, user.activevm_user_id, specs);
    db.prepare(`
      INSERT INTO servers (activevm_server_id, owner_discord_id, name, expires_at)
      VALUES (?, ?, ?, ?)
    `).run(activeVmId, user.discord_id, name, expiresAt);
    res.json({ ok: true, message: 'サーバーを作成しました' });
  } catch (e) {
    console.error('Server create error:', e);
    res.status(500).json({ error: 'サーバー作成に失敗しました: ' + e.message });
  }
});

app.post('/api/servers/:id/extend', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid ID' });

  const server = db.prepare('SELECT * FROM servers WHERE id = ? AND is_deleted = 0').get(id);
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
  db.prepare('UPDATE servers SET expires_at = ? WHERE id = ?').run(newExpiry, id);
  res.json({ ok: true, expires_at: newExpiry });
});

app.delete('/api/servers/:id', requireAuth, async (req, res) => {
  const id = parseInt(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid ID' });

  const server = db.prepare('SELECT * FROM servers WHERE id = ? AND is_deleted = 0').get(id);
  if (!server) return res.status(404).json({ error: 'Not found' });

  const user = db.prepare('SELECT * FROM users WHERE discord_id = ?').get(req.session.user.id);
  const isOwner = server.owner_discord_id === req.session.user.id;
  if (!isOwner && !user.is_admin) return res.status(403).json({ error: 'Forbidden' });

  await deleteActiveVmServer(server.activevm_server_id);
  db.prepare('UPDATE servers SET is_deleted = 1 WHERE id = ?').run(id);
  res.json({ ok: true });
});

// ─── API: ADMIN ───────────────────────────────────────────────────────────────

app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT u.*, COUNT(s.id) as server_count
    FROM users u
    LEFT JOIN servers s ON s.owner_discord_id = u.discord_id AND s.is_deleted = 0
    GROUP BY u.discord_id ORDER BY u.created_at DESC
  `).all();
  res.json(users);
});

app.get('/api/admin/servers', requireAdmin, (req, res) => {
  const servers = db.prepare(`
    SELECT s.*, u.discord_username FROM servers s
    JOIN users u ON u.discord_id = s.owner_discord_id
    WHERE s.is_deleted = 0 ORDER BY s.created_at DESC
  `).all();
  res.json(servers);
});

app.get('/api/admin/blocked-ips', requireAdmin, (req, res) => {
  const ips = db.prepare('SELECT * FROM blocked_ips ORDER BY blocked_at DESC').all();
  res.json(ips);
});

app.post('/api/admin/blocked-ips', requireAdmin, (req, res) => {
  const { ip, reason } = req.body;
  if (!ip || typeof ip !== 'string') return res.status(400).json({ error: 'Invalid IP' });
  blockIp(ip, reason || 'manual');
  res.json({ ok: true });
});

app.delete('/api/admin/blocked-ips/:ip', requireAdmin, (req, res) => {
  unblockIp(decodeURIComponent(req.params.ip));
  res.json({ ok: true });
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const totalUsers = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const totalServers = db.prepare('SELECT COUNT(*) as c FROM servers WHERE is_deleted = 0').get().c;
  const bannedUsers = db.prepare('SELECT COUNT(*) as c FROM users WHERE is_banned = 1').get().c;
  const blockedIps = db.prepare('SELECT COUNT(*) as c FROM blocked_ips').get().c;
  const recentErrors = db.prepare(`
    SELECT COUNT(*) as c FROM request_log WHERE ts > datetime('now', '-1 hour')
  `).get().c;
  const topErrorIps = db.prepare(`
    SELECT ip, COUNT(*) as c FROM request_log
    WHERE ts > datetime('now', '-1 hour') AND status >= 400
    GROUP BY ip ORDER BY c DESC LIMIT 10
  `).all();
  res.json({ totalUsers, totalServers, bannedUsers, blockedIps, recentErrors, topErrorIps });
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
  const max = parseInt(req.body.max);
  if (!Number.isInteger(max) || max < 0 || max > 50) return res.status(400).json({ error: 'Invalid value' });
  db.prepare('UPDATE users SET max_servers = ? WHERE discord_id = ?').run(max, req.params.id);
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/add-staff', requireAdmin, (req, res) => {
  if (!ADMIN_IDS.includes(req.session.user.id)) return res.status(403).json({ error: 'Only super admins can add staff' });
  db.prepare('UPDATE users SET is_admin = 1 WHERE discord_id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.delete('/api/admin/servers/:id', requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid ID' });
  const server = db.prepare('SELECT * FROM servers WHERE id = ? AND is_deleted = 0').get(id);
  if (!server) return res.status(404).json({ error: 'Not found' });
  await deleteActiveVmServer(server.activevm_server_id);
  db.prepare('UPDATE servers SET is_deleted = 1 WHERE id = ?').run(id);
  res.json({ ok: true });
});

app.post('/api/admin/servers/:id/extend', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid ID' });
  const server = db.prepare('SELECT * FROM servers WHERE id = ? AND is_deleted = 0').get(id);
  if (!server) return res.status(404).json({ error: 'Not found' });
  const specs = db.prepare('SELECT * FROM default_specs WHERE id = 1').get();
  const base = new Date(Math.max(new Date(server.expires_at), Date.now()));
  const newExpiry = new Date(base.getTime() + specs.duration_days * 24 * 60 * 60 * 1000).toISOString();
  db.prepare('UPDATE servers SET expires_at = ? WHERE id = ?').run(newExpiry, id);
  res.json({ ok: true, expires_at: newExpiry });
});

app.patch('/api/admin/specs', requireAdmin, (req, res) => {
  const { cpu, memory, disk, duration_days, max_servers_per_user } = req.body;
  const vals = [cpu, memory, disk, duration_days, max_servers_per_user].map(Number);
  if (vals.some(isNaN)) return res.status(400).json({ error: 'Invalid values' });
  db.prepare(`
    UPDATE default_specs SET cpu=?, memory=?, disk=?, duration_days=?, max_servers_per_user=? WHERE id=1
  `).run(...vals);
  res.json({ ok: true });
});

// ─── CRON: 期限切れサーバー自動削除 ──────────────────────────────────────────

cron.schedule('*/30 * * * *', async () => {
  const expired = db.prepare(`
    SELECT * FROM servers WHERE is_deleted = 0 AND expires_at < datetime('now')
  `).all();

  for (const server of expired) {
    console.log(`[CRON] Deleting expired server: ${server.name} (${server.activevm_server_id})`);
    await deleteActiveVmServer(server.activevm_server_id);
    db.prepare('UPDATE servers SET is_deleted = 1 WHERE id = ?').run(server.id);
  }
  if (expired.length > 0) console.log(`[CRON] Deleted ${expired.length} expired servers`);
});

// ─── CRON: ログのクリーンアップ（7日以上前を削除）────────────────────────────

cron.schedule('0 3 * * *', () => {
  db.prepare("DELETE FROM request_log WHERE ts < datetime('now', '-7 days')").run();
  console.log('[CRON] Cleaned up old request logs');
});

// ─── SPA FALLBACK ─────────────────────────────────────────────────────────────

// 存在しないAPIルートに404を返す（HTMLを返さない）
app.all('/api/*', (req, res) => res.status(404).json({ error: 'Not found' }));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── 起動 ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`[ActiveVm] Server running on http://localhost:${PORT}`);
  console.log(`[ActiveVm] DDoS protection: ON`);
});

// ─── DB エクスポート（bot.jsから共有利用するため）────────────────────────────

export { db, blockIp, unblockIp, deleteActiveVmServer, activeVmRequest, createActiveVmServer, createActiveVmUser };
