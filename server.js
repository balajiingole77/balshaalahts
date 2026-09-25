// Sunday School Tracker server: serves index.html and stores data in Postgres.
//
// Env:
//   DATABASE_URL   Postgres connection string (on Railway: ${{Postgres.DATABASE_URL}})
//   APP_PASSWORD   shared password every teacher enters. Required: without it nothing is served,
//                  because the page and data contain children's names.
//   PORT           set by Railway

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const PORT = Number(process.env.PORT) || 8080;
const APP_PASSWORD = process.env.APP_PASSWORD || '';
const DATABASE_URL = process.env.DATABASE_URL || '';
const MAX_BODY = 1024 * 1024;
const SESSION_KEY = /^[A-Za-z0-9-]{1,64}_\d{4}-\d{2}-\d{2}$/;
const DOC_NAMES = new Set(['classes', 'students']);

const INDEX_HTML = fs.readFileSync(path.join(__dirname, 'index.html'));
const SEED = JSON.parse(fs.readFileSync(path.join(__dirname, 'seed.json'), 'utf8'));

// Railway's private network (*.railway.internal) is unencrypted; public proxy URLs need TLS.
const useSsl = DATABASE_URL && !/\.railway\.internal[:/]/.test(DATABASE_URL) && !/@(localhost|127\.0\.0\.1)[:/]/.test(DATABASE_URL);
const pool = DATABASE_URL ? new Pool({ connectionString: DATABASE_URL, ssl: useSsl ? { rejectUnauthorized: false } : false, max: 5 }) : null;

let dbReady = false;

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS docs (
      name       text PRIMARY KEY,
      data       jsonb NOT NULL,
      version    integer NOT NULL DEFAULT 1,
      updated_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id         text PRIMARY KEY,
      class_id   text NOT NULL,
      date       date NOT NULL,
      marks      jsonb NOT NULL DEFAULT '{}'::jsonb,
      lesson     text NOT NULL DEFAULT '',
      override   text NOT NULL DEFAULT '',
      updated_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS sessions_class_id ON sessions (class_id);
  `);
  // First start only: load the official classes and roster. Never overwrites existing data.
  await pool.query(`INSERT INTO docs (name, data) VALUES ('classes', $1), ('students', $2) ON CONFLICT (name) DO NOTHING`,
    [SEED.classes, SEED.students]);
  dbReady = true;
  console.log('Database ready');
}

async function initDbWithRetry(attempt = 1) {
  try {
    await initDb();
  } catch (e) {
    const wait = Math.min(30000, 1000 * 2 ** attempt);
    console.error(`Database init failed (attempt ${attempt}), retrying in ${wait / 1000}s:`, e.message);
    setTimeout(() => initDbWithRetry(attempt + 1), wait);
  }
}

// ---------- auth ----------

const failures = new Map(); // ip -> { count, since }
const FAIL_LIMIT = 10;
const FAIL_WINDOW_MS = 15 * 60 * 1000;

function clientIp(req) {
  return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
}

function sameSecret(a, b) {
  const ha = crypto.createHash('sha256').update(a).digest();
  const hb = crypto.createHash('sha256').update(b).digest();
  return crypto.timingSafeEqual(ha, hb);
}

// Returns true when the request may proceed; otherwise it has already responded.
function checkAuth(req, res) {
  if (!APP_PASSWORD) {
    send(res, 503, 'text/plain', 'APP_PASSWORD is not set. Add it in the service variables and redeploy.');
    return false;
  }
  const ip = clientIp(req);
  const f = failures.get(ip);
  if (f && Date.now() - f.since < FAIL_WINDOW_MS && f.count >= FAIL_LIMIT) {
    send(res, 429, 'text/plain', 'Too many wrong passwords. Try again in 15 minutes.');
    return false;
  }
  const header = req.headers.authorization || '';
  if (header.startsWith('Basic ')) {
    const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
    const password = decoded.slice(decoded.indexOf(':') + 1);
    if (sameSecret(password, APP_PASSWORD)) {
      failures.delete(ip);
      return true;
    }
    const entry = f && Date.now() - f.since < FAIL_WINDOW_MS ? f : { count: 0, since: Date.now() };
    entry.count++;
    failures.set(ip, entry);
  }
  res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="Sunday School Tracker", charset="UTF-8"', 'Content-Type': 'text/plain' });
  res.end('Password required. Any username works; the password is the one shared with teachers.');
  return false;
}

// ---------- helpers ----------

const BASE_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Robots-Tag': 'noindex, nofollow',
  'Cache-Control': 'no-store'
};

function send(res, status, type, body) {
  res.writeHead(status, Object.assign({ 'Content-Type': type }, BASE_HEADERS));
  res.end(body);
}

function sendJson(res, status, obj) {
  send(res, status, 'application/json; charset=utf-8', JSON.stringify(obj));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > MAX_BODY) { reject(Object.assign(new Error('Body too large'), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); }
      catch (e) { reject(Object.assign(new Error('Invalid JSON'), { status: 400 })); }
    });
    req.on('error', reject);
  });
}

function badRequest(msg) { return Object.assign(new Error(msg), { status: 400 }); }

// ---------- API ----------

async function getState() {
  const docs = await pool.query('SELECT name, data, version FROM docs');
  const sessions = await pool.query(`SELECT id, marks, lesson, override FROM sessions`);
  const out = { classes: null, students: null, versions: {}, sessions: sessions.rows };
  docs.rows.forEach(r => { out[r.name] = r.data; out.versions[r.name] = r.version; });
  return out;
}

async function patchSession(key, body) {
  if (!SESSION_KEY.test(key)) throw badRequest('Bad session key');
  let marks = null;
  if (body.marks !== undefined) {
    if (!body.marks || typeof body.marks !== 'object' || Array.isArray(body.marks)) throw badRequest('marks must be an object');
    const entries = Object.entries(body.marks);
    if (entries.length > 500) throw badRequest('Too many marks');
    for (const [sid, v] of entries) {
      if (sid.length > 200 || !(v === 'present' || v === 'absent' || v === null)) throw badRequest('Bad mark');
    }
    marks = body.marks;
  }
  const lesson = body.lesson === undefined ? null : String(body.lesson).slice(0, 10000);
  const override = body.override === undefined ? null : String(body.override).slice(0, 20);
  const i = key.lastIndexOf('_');
  // One statement, so two teachers marking different students at once both land.
  await pool.query(`
    INSERT INTO sessions (id, class_id, date, marks, lesson, override)
    VALUES ($1, $2, $3, jsonb_strip_nulls(COALESCE($4::jsonb, '{}'::jsonb)), COALESCE($5, ''), COALESCE($6, ''))
    ON CONFLICT (id) DO UPDATE SET
      marks      = jsonb_strip_nulls(sessions.marks || COALESCE($4::jsonb, '{}'::jsonb)),
      lesson     = COALESCE($5, sessions.lesson),
      override   = COALESCE($6, sessions.override),
      updated_at = now()`,
    [key, key.slice(0, i), key.slice(i + 1), marks === null ? null : JSON.stringify(marks), lesson, override]);
}

// Whole-document write guarded by version, so an edit based on stale data is rejected (409)
// instead of silently erasing someone else's change.
async function putDoc(name, body) {
  if (!DOC_NAMES.has(name)) throw badRequest('Unknown document');
  if (!body.data || !Array.isArray(body.data.list)) throw badRequest('data.list must be an array');
  const ifVersion = Number(body.ifVersion);
  const r = await pool.query(`
    INSERT INTO docs (name, data, version) VALUES ($1, $2, 1)
    ON CONFLICT (name) DO UPDATE SET data = EXCLUDED.data, version = docs.version + 1, updated_at = now()
      WHERE docs.version = $3
    RETURNING version`, [name, body.data, Number.isFinite(ifVersion) ? ifVersion : 0]);
  return r.rows.length ? r.rows[0].version : null;
}

async function handleApi(req, res, url) {
  if (!dbReady) return sendJson(res, 503, { error: 'Database is not connected yet' });
  const parts = url.pathname.split('/').filter(Boolean); // ['api', ...]

  if (req.method === 'GET' && url.pathname === '/api/state') {
    return sendJson(res, 200, await getState());
  }
  if (req.method === 'PATCH' && parts[1] === 'sessions' && parts.length === 3) {
    await patchSession(decodeURIComponent(parts[2]), await readJson(req));
    return sendJson(res, 200, { ok: true });
  }
  if (req.method === 'DELETE' && url.pathname === '/api/sessions') {
    const classId = url.searchParams.get('classId');
    if (classId) await pool.query('DELETE FROM sessions WHERE class_id = $1', [classId]);
    else if (url.searchParams.get('all') === 'true') await pool.query('DELETE FROM sessions');
    else throw badRequest('Pass classId or all=true');
    return sendJson(res, 200, { ok: true });
  }
  if (req.method === 'PUT' && parts[1] === 'docs' && parts.length === 3) {
    const version = await putDoc(parts[2], await readJson(req));
    if (version === null) return sendJson(res, 409, { error: 'Someone else changed this. Reload and try again.' });
    return sendJson(res, 200, { ok: true, version });
  }
  return sendJson(res, 404, { error: 'Not found' });
}

// ---------- server ----------

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname === '/healthz') return send(res, dbReady ? 200 : 503, 'text/plain', dbReady ? 'ok' : 'db not ready');
  if (url.pathname === '/favicon.ico') { res.writeHead(204, BASE_HEADERS); return res.end(); }
  if (!checkAuth(req, res)) return;
  try {
    if (url.pathname.startsWith('/api/')) {
      if (!pool) return sendJson(res, 503, { error: 'DATABASE_URL is not set' });
      return await handleApi(req, res, url);
    }
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      return send(res, 200, 'text/html; charset=utf-8', INDEX_HTML);
    }
    send(res, 404, 'text/plain', 'Not found');
  } catch (e) {
    if (e.status) return sendJson(res, e.status, { error: e.message });
    console.error(e);
    sendJson(res, 500, { error: 'Server error' });
  }
});

if (!APP_PASSWORD) console.warn('APP_PASSWORD is not set: every request will get 503 until it is.');
if (pool) initDbWithRetry();
else console.warn('DATABASE_URL is not set: the page will fall back to device-only storage.');

server.listen(PORT, () => console.log('Listening on ' + PORT));
