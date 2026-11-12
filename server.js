'use strict';
// «Мой хомячок» — сервер: регистрация по почте, вход, облачные сохранения.
// Без внешних зависимостей. Нужен Node.js 18+.

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

// ---------- .env ----------
try {
  for (const line of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^(['"])(.*)\1$/, '$2');
  }
} catch (e) { /* .env необязателен */ }

const { sendMail, mode: mailMode } = require('./lib/mail');

const PORT = +process.env.PORT || 3000;
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/+$/, '');
const SECURE_COOKIE = BASE_URL.startsWith('https://');
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const SAVES_DIR = path.join(DATA_DIR, 'saves');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const INDEX = path.join(__dirname, 'public', 'index.html');
const DAY = 864e5;
const SESSION_TTL = 30 * DAY;
const VERIFY_TTL = DAY;

fs.mkdirSync(SAVES_DIR, { recursive: true });

// ---------- хранилище ----------
let db = { users: {}, sessions: {}, tokens: {} };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(DB_FILE, 'utf8'))); } catch (e) { /* первый запуск */ }
const byEmail = new Map(Object.values(db.users).map(u => [u.email, u]));

function persist() {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DB_FILE);
}

const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const rnd = n => crypto.randomBytes(n).toString('base64url');

// ---------- пароли ----------
async function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  const h = await scrypt(pw, salt, 64);
  return salt.toString('hex') + ':' + h.toString('hex');
}
async function checkPw(pw, stored) {
  const [s, h] = stored.split(':');
  const hh = await scrypt(pw, Buffer.from(s, 'hex'), 64);
  const hb = Buffer.from(h, 'hex');
  return hh.length === hb.length && crypto.timingSafeEqual(hh, hb);
}
const dummyHash = hashPw('dummy-password'); // чтобы вход по несуществующей почте занимал столько же времени

// ---------- лимиты запросов ----------
const hits = new Map();
function limited(key, max, windowMs) {
  const now = Date.now();
  const a = (hits.get(key) || []).filter(t => now - t < windowMs);
  if (a.length >= max) { hits.set(key, a); return true; }
  a.push(now); hits.set(key, a);
  return false;
}
const clientIp = req => {
  if (TRUST_PROXY) {
    const x = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (x) return x;
  }
  return req.socket.remoteAddress || '';
};

// ---------- утилиты HTTP ----------
class HttpError extends Error { constructor(status, msg, extra) { super(msg); this.status = status; this.extra = extra; } }

function setCommon(res) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
}
function json(res, code, obj, headers = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(body);
}
function readBody(req, limit = 65536) {
  return new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on('data', c => {
      n += c.length;
      if (n > limit) { reject(new HttpError(413, 'Слишком большой запрос')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
async function readJson(req) {
  if (!/^application\/json\b/i.test(req.headers['content-type'] || '')) throw new HttpError(415, 'Нужен JSON');
  try { const v = JSON.parse((await readBody(req)) || '{}'); if (v && typeof v === 'object') return v; } catch (e) { if (e instanceof HttpError) throw e; }
  throw new HttpError(400, 'Некорректный запрос');
}
function cookie(req, name) {
  for (const p of (req.headers.cookie || '').split(';')) {
    const i = p.indexOf('=');
    if (i > 0 && p.slice(0, i).trim() === name) { try { return decodeURIComponent(p.slice(i + 1).trim()); } catch (e) { return ''; } }
  }
  return '';
}
const cookieStr = (value, maxAge) =>
  `sid=${encodeURIComponent(value)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${SECURE_COOKIE ? '; Secure' : ''}`;

function getUser(req) {
  const t = cookie(req, 'sid');
  if (!t) return null;
  const s = db.sessions[sha(t)];
  if (!s || s.exp < Date.now()) return null;
  return db.users[s.uid] || null;
}
function requireUser(req) {
  const u = getUser(req);
  if (!u) throw new HttpError(401, 'Нужно войти');
  return u;
}

// ---------- проверка данных ----------
const EMAIL_RE = /^[^\s@<>"',;()\\]+@[^\s@<>"',;()\\]+\.[^\s@<>"',;()\\]{2,}$/;
const normEmail = v => String(v || '').trim().toLowerCase();
function checkCreds(email, password) {
  if (email.length > 254 || !EMAIL_RE.test(email)) throw new HttpError(400, 'Введите корректную почту');
  if (password.length < 8) throw new HttpError(400, 'Пароль должен быть не короче 8 символов');
  if (password.length > 128) throw new HttpError(400, 'Пароль слишком длинный (максимум 128 символов)');
}

// Сохранение игры: пропускаем только известные поля с допустимыми значениями.
const num = (v, min, max, d) => { v = Number(v); return Number.isFinite(v) ? Math.min(max, Math.max(min, v)) : d; };
function cleanSave(s) {
  if (!s || typeof s !== 'object' || Array.isArray(s)) return null;
  const strs = a => (Array.isArray(a) ? a.filter(x => typeof x === 'string' && x.length <= 20).slice(0, 50) : []);
  const up = {};
  for (const k of ['play', 'wash', 'sleep', 'feed', 'home']) up[k] = Math.round(num(s.up && s.up[k], 0, 5, 0));
  const now = Date.now();
  return {
    name: String(s.name || '').slice(0, 16),
    coins: num(s.coins, 0, 1e12, 0),
    hunger: num(s.hunger, 0, 100, 80), joy: num(s.joy, 0, 100, 80),
    energy: num(s.energy, 0, 100, 80), clean: num(s.clean, 0, 100, 80),
    own: strs(s.own), color: String(s.color || 'c0').slice(0, 20), hat: String(s.hat || 'h0').slice(0, 20),
    sleep: !!s.sleep, sleepFrom: num(s.sleepFrom, 0, 100, 0), sleepT: num(s.sleepT, 0, 1e6, 0),
    tut: !!s.tut, lvl: Math.round(num(s.lvl, 1, 10, 1)), xp: num(s.xp, 0, 1e6, 0),
    rebirths: Math.round(num(s.rebirths, 0, 1e6, 0)), up, toys: strs(s.toys),
    born: num(s.born, 0, now + DAY, now), last: num(s.last, 0, now + DAY, now)
  };
}
const saveFile = uid => path.join(SAVES_DIR, uid + '.json');

// ---------- письма ----------
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

async function sendVerification(user) {
  const token = rnd(32);
  for (const [h, t] of Object.entries(db.tokens)) if (t.uid === user.id) delete db.tokens[h]; // старые ссылки отзываем
  db.tokens[sha(token)] = { uid: user.id, exp: Date.now() + VERIFY_TTL };
  user.lastMail = Date.now();
  persist();
  const link = `${BASE_URL}/api/verify?token=${token}`;
  await sendMail({
    to: user.email,
    subject: 'Подтвердите почту — «Мой хомячок»',
    text: `Привет!\n\nЧтобы закончить регистрацию в игре «Мой хомячок», подтвердите почту по ссылке (действует 24 часа):\n\n${link}\n\nЕсли вы не регистрировались, просто проигнорируйте это письмо.`,
    html: `<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;color:#4a2a12">
<h2>🐹 Мой хомячок</h2><p>Привет! Чтобы закончить регистрацию, подтвердите почту:</p>
<p><a href="${esc(link)}" style="display:inline-block;background:#ffc933;color:#4a2a12;font-weight:bold;text-decoration:none;padding:12px 22px;border-radius:14px">Подтвердить почту</a></p>
<p style="color:#8a6a4a;font-size:13px">Ссылка действует 24 часа. Если кнопка не работает, откройте адрес:<br>${esc(link)}</p>
<p style="color:#8a6a4a;font-size:13px">Если вы не регистрировались, просто проигнорируйте это письмо.</p></div>`
  });
}

// ---------- маршруты ----------
const publicUser = u => ({ id: u.id, email: u.email });
const COOLDOWN = 60 * 1000;

async function api(req, res, p, url) {
  const m = req.method;

  if (m === 'GET' && p === '/api/me') {
    const u = getUser(req);
    return json(res, 200, { user: u ? publicUser(u) : null });
  }

  if (m === 'GET' && p === '/api/verify') {
    const rec = db.tokens[sha(url.searchParams.get('token') || '')];
    let ok = false;
    if (rec && rec.exp > Date.now() && db.users[rec.uid]) {
      // токен не сгорает при первом переходе: почтовые сканеры часто «открывают» ссылки заранее
      db.users[rec.uid].verified = true;
      persist();
      ok = true;
    }
    res.writeHead(302, { Location: '/?verified=' + (ok ? 1 : 0), 'Cache-Control': 'no-store' });
    return res.end();
  }

  if (m === 'GET' && p === '/api/save') {
    const u = requireUser(req);
    try { return json(res, 200, { save: JSON.parse(fs.readFileSync(saveFile(u.id), 'utf8')) }); }
    catch (e) { return json(res, 200, { save: null }); }
  }

  if (m === 'GET') throw new HttpError(404, 'Не найдено');
  if (m !== 'POST' && m !== 'PUT') throw new HttpError(405, 'Метод не поддерживается');

  // --- защита от CSRF для изменяющих запросов ---
  const origin = req.headers.origin;
  if (origin) {
    let h = ''; try { h = new URL(origin).host; } catch (e) {}
    if (h !== req.headers.host && h !== new URL(BASE_URL).host) throw new HttpError(403, 'Запрещено');
  }
  const ip = clientIp(req);

  if (m === 'PUT' && p === '/api/save') {
    const u = requireUser(req);
    const s = cleanSave(await readJson(req));
    if (!s) throw new HttpError(400, 'Некорректное сохранение');
    const f = saveFile(u.id);
    fs.writeFileSync(f + '.tmp', JSON.stringify(s));
    fs.renameSync(f + '.tmp', f);
    return json(res, 200, { ok: true });
  }

  if (m !== 'POST') throw new HttpError(404, 'Не найдено');
  const body = await readJson(req);

  if (p === '/api/register') {
    if (limited('reg:' + ip, 5, 3600e3)) throw new HttpError(429, 'Слишком много попыток. Попробуйте позже');
    const email = normEmail(body.email), password = String(body.password || '');
    checkCreds(email, password);
    let user = byEmail.get(email);
    try {
      if (!user) {
        user = { id: crypto.randomBytes(12).toString('hex'), email, hash: await hashPw(password), verified: false, created: Date.now() };
        db.users[user.id] = user; byEmail.set(email, user);
        await sendVerification(user);
      } else if (!user.verified && Date.now() - (user.lastMail || 0) > COOLDOWN) {
        await sendVerification(user); // повторная регистрация = повторное письмо (пароль не меняем)
      }
    } catch (e) {
      console.error('Не удалось отправить письмо:', e.message);
      throw new HttpError(502, 'Не удалось отправить письмо. Попробуйте позже');
    }
    // Ответ одинаковый, существует ли уже такая почта или нет
    return json(res, 200, { ok: true });
  }

  if (p === '/api/resend') {
    if (limited('resend:' + ip, 5, 3600e3)) throw new HttpError(429, 'Слишком много попыток. Попробуйте позже');
    const user = byEmail.get(normEmail(body.email));
    if (user && !user.verified && Date.now() - (user.lastMail || 0) > COOLDOWN) {
      try { await sendVerification(user); }
      catch (e) { console.error('Не удалось отправить письмо:', e.message); throw new HttpError(502, 'Не удалось отправить письмо. Попробуйте позже'); }
    }
    return json(res, 200, { ok: true });
  }

  if (p === '/api/login') {
    const email = normEmail(body.email), password = String(body.password || '').slice(0, 128);
    if (limited('login-ip:' + ip, 20, 600e3) || limited('login-em:' + email, 10, 600e3))
      throw new HttpError(429, 'Слишком много попыток входа. Подождите 10 минут');
    const user = byEmail.get(email);
    const ok = await checkPw(password, user ? user.hash : await dummyHash);
    if (!user || !ok) throw new HttpError(401, 'Неверная почта или пароль');
    if (!user.verified) throw new HttpError(403, 'Почта ещё не подтверждена. Откройте ссылку из письма.', { code: 'unverified' });
    const sid = rnd(32);
    db.sessions[sha(sid)] = { uid: user.id, exp: Date.now() + SESSION_TTL };
    persist();
    return json(res, 200, { user: publicUser(user) }, { 'Set-Cookie': cookieStr(sid, SESSION_TTL / 1000) });
  }

  if (p === '/api/logout') {
    const t = cookie(req, 'sid');
    if (t && db.sessions[sha(t)]) { delete db.sessions[sha(t)]; persist(); }
    return json(res, 200, { ok: true }, { 'Set-Cookie': cookieStr('', 0) });
  }

  throw new HttpError(404, 'Не найдено');
}

const server = http.createServer(async (req, res) => {
  try {
    setCommon(res);
    const url = new URL(req.url, 'http://localhost');
    const p = url.pathname;
    if (req.method === 'GET' && (p === '/' || p === '/index.html')) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-cache' });
      return res.end(fs.readFileSync(INDEX));
    }
    if (req.method === 'GET' && p === '/healthz') return json(res, 200, { ok: true });
    if (p.startsWith('/api/')) return await api(req, res, p, url);
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Не найдено');
  } catch (e) {
    if (e instanceof HttpError) return json(res, e.status, { error: e.message, ...(e.extra || {}) });
    console.error(e);
    if (!res.headersSent) json(res, 500, { error: 'Ошибка сервера' });
  }
});

// ---------- уборка ----------
function cleanup() {
  const now = Date.now();
  let changed = false;
  for (const [h, s] of Object.entries(db.sessions)) if (s.exp < now) { delete db.sessions[h]; changed = true; }
  for (const [h, t] of Object.entries(db.tokens)) if (t.exp < now) { delete db.tokens[h]; changed = true; }
  for (const u of Object.values(db.users)) {
    if (!u.verified && now - u.created > 3 * DAY) { // неподтверждённые аккаунты живут 3 дня
      delete db.users[u.id]; byEmail.delete(u.email); changed = true;
    }
  }
  for (const [k, a] of hits) { const f = a.filter(t => now - t < 3600e3); f.length ? hits.set(k, f) : hits.delete(k); }
  if (changed) persist();
}
cleanup();
setInterval(cleanup, 3600e3).unref();

server.listen(PORT, () => {
  console.log(`🐹 Мой хомячок: ${BASE_URL}  (порт ${PORT})`);
  console.log(`Почта: режим «${mailMode()}»` + (mailMode() === 'console' ? ' — письма не отправляются, ссылки подтверждения печатаются сюда. Настройте .env для реальной отправки.' : ''));
});
