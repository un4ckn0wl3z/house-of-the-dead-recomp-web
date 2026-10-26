// Web server for the port: serves the web build and relays online co-op rooms (lockstep, see src/netplay.c).
// No dependencies: a minimal WebSocket implementation is included.
//   node server.js [--port 8080] [--root ../build_web/out] [--password secret]
// The build contains the game's data: keep it private. With --password every request needs HTTP basic auth
// (any user name). Research and educational use only.
'use strict';
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto'), zlib = require('zlib');

const argv = process.argv.slice(2);
const opt = (name, def) => { const i = argv.indexOf('--' + name); return i >= 0 ? argv[i + 1] : (process.env[name.toUpperCase()] || def); };
const PORT = +opt('port', 8080);
const ROOT = path.resolve(opt('root', process.env.WEB_ROOT || path.join(__dirname, '..', 'build_web', 'out')));
const PASSWORD = opt('password', '');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.wasm': 'application/wasm', '.data': 'application/octet-stream',
               '.ogg': 'audio/ogg', '.wav': 'audio/wav', '.mp3': 'audio/mpeg', '.json': 'application/json', '.png': 'image/png', '.ico': 'image/x-icon' };

// ---------------------------------------------------------------- accounts (SQLite, node:sqlite)
// Registration needs a captcha drawn by this server (captcha.js). Passwords are scrypt hashes; a login gives a
// random session token the page keeps and sends as X-Token (not Authorization, which --password's basic auth uses).
const { DatabaseSync } = require('node:sqlite');
const captcha = require('./captcha');
const DB_FILE = opt('db', path.join(__dirname, 'data', 'hotd.db'));
fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
const db = new DatabaseSync(DB_FILE);
db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    salt TEXT NOT NULL, hash TEXT NOT NULL, created_at INTEGER NOT NULL, games INTEGER NOT NULL DEFAULT 0);
  CREATE TABLE IF NOT EXISTS scores (
    id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mode INTEGER NOT NULL, score INTEGER NOT NULL, stage INTEGER NOT NULL, name TEXT NOT NULL, created_at INTEGER NOT NULL);
  CREATE INDEX IF NOT EXISTS scores_by_mode ON scores (mode, score DESC);
  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at INTEGER NOT NULL);
`);
const q = {
  addUser: db.prepare('INSERT INTO users (username, salt, hash, created_at) VALUES (?, ?, ?, ?)'),
  userByName: db.prepare('SELECT * FROM users WHERE username = ?'),
  addSession: db.prepare('INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)'),
  userByToken: db.prepare('SELECT users.* FROM sessions JOIN users ON users.id = sessions.user_id WHERE token = ?'),
  delSession: db.prepare('DELETE FROM sessions WHERE token = ?'),
  countGame: db.prepare('UPDATE users SET games = games + 1 WHERE id = ?'),
  addScore: db.prepare('INSERT INTO scores (user_id, mode, score, stage, name, created_at) VALUES (?, ?, ?, ?, ?, ?)'),
  // each account's best entry per mode, best first: points for Arcade (0) and PC Mode (1), clear times in ms for
  // the Boss Mode tables (2 Chariot, 3 Hangedman, 4 Hermit, 5 Magician, 6 All Bosses: lower is better)
  topPoints: db.prepare(`SELECT s.score, s.stage, s.name, u.username, s.created_at FROM scores s JOIN users u ON u.id = s.user_id
    WHERE s.mode = ? AND s.id = (SELECT id FROM scores WHERE user_id = s.user_id AND mode = s.mode ORDER BY score DESC, created_at LIMIT 1)
    ORDER BY s.score DESC, s.created_at LIMIT ?`),
  topTimes: db.prepare(`SELECT s.score, s.stage, s.name, u.username, s.created_at FROM scores s JOIN users u ON u.id = s.user_id
    WHERE s.mode = ? AND s.id = (SELECT id FROM scores WHERE user_id = s.user_id AND mode = s.mode ORDER BY score ASC, created_at LIMIT 1)
    ORDER BY s.score ASC, s.created_at LIMIT ?`),
  recentByUser: db.prepare('SELECT COUNT(*) AS n FROM scores WHERE user_id = ? AND created_at > ?'),
};
const hashPassword = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
function newSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  q.addSession.run(token, userId, Date.now());
  return token;
}
const userOf = (token) => token ? q.userByToken.get(String(token)) : null;
function readJSON(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', (c) => { body += c; if (body.length > 1e4) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(body || '{}')); } catch (e) { resolve({}); } });
  });
}
// simple per-address limit on account requests
const hits = new Map();
function limited(req) {
  const ip = req.socket.remoteAddress, now = Date.now(), h = hits.get(ip) || { n: 0, t: now };
  if (now - h.t > 60000) { h.n = 0; h.t = now; }
  h.n++; hits.set(ip, h);
  return h.n > 30;
}
async function api(req, res, p) {
  const send = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); };
  if (p === '/api/captcha') return send(200, captcha.create());
  if (p === '/api/scores' && req.method === 'GET') {
    const mode = Math.max(0, Math.min(6, parseInt(new URL(req.url, 'http://x').searchParams.get('mode') || '0', 10) || 0));
    return send(200, { mode, time: mode >= 2, scores: (mode >= 2 ? q.topTimes : q.topPoints).all(mode, 20) });
  }
  if (p === '/api/me') { const u = userOf(req.headers['x-token']); return u ? send(200, { username: u.username, games: u.games }) : send(401, { error: 'not signed in' }); }
  if (req.method !== 'POST') return send(405, { error: 'POST only' });
  if (limited(req)) return send(429, { error: 'Too many attempts, wait a minute.' });
  const b = await readJSON(req);
  if (p === '/api/register') {
    const username = String(b.username || '').trim(), password = String(b.password || '');
    if (!captcha.check(b.captchaId, b.captchaAnswer)) return send(400, { error: 'Wrong captcha code, try the new one.', captcha: true });
    if (!/^[A-Za-z0-9_\-]{3,16}$/.test(username)) return send(400, { error: 'User name: 3-16 letters, digits, _ or -.' });
    if (password.length < 6 || password.length > 200) return send(400, { error: 'Password: at least 6 characters.' });
    if (q.userByName.get(username)) return send(400, { error: 'That name is taken.' });
    const salt = crypto.randomBytes(16).toString('hex');
    const info = q.addUser.run(username, salt, hashPassword(password, salt), Date.now());
    return send(200, { token: newSession(Number(info.lastInsertRowid)), username });
  }
  if (p === '/api/login') {
    const u = q.userByName.get(String(b.username || '').trim());
    if (!u) return send(400, { error: 'Wrong user name or password.' });
    const want = Buffer.from(u.hash, 'hex'), got = Buffer.from(hashPassword(String(b.password || ''), u.salt), 'hex');
    if (!crypto.timingSafeEqual(want, got)) return send(400, { error: 'Wrong user name or password.' });
    return send(200, { token: newSession(u.id), username: u.username });
  }
  if (p === '/api/scores') {
    // a high score the game just filed in its own table (src/game.c host_insert_score); trusted only as far as a
    // signed-in browser is: bounds and a rate limit, no replay verification
    const u = userOf(req.headers['x-token']);
    if (!u) return send(401, { error: 'Sign in to put your score on the scoreboard.' });
    const mode = b.mode | 0, score = Math.floor(Number(b.score)), stage = b.stage | 0;
    const name = String(b.name || '').replace(/[^ -~]/g, '').trim().slice(0, 16) || u.username;
    if (mode < 0 || mode > 6 || !(score > 0 && score <= 9999999) || stage < 1 || stage > 9) return send(400, { error: 'bad score' });
    if (q.recentByUser.get(u.id, Date.now() - 600000).n >= 20) return send(429, { error: 'too many scores' });
    q.addScore.run(u.id, mode, score, stage, name, Date.now());
    return send(200, { ok: true });
  }
  if (p === '/api/rooms/close') {
    const u = userOf(req.headers['x-token']);
    const r = rooms.get(String(b.room || '').toUpperCase());
    if (!u) return send(401, { error: 'not signed in' });
    if (!r) return send(404, { error: 'no such room' });
    if (r.ownerId !== u.id) return send(403, { error: 'only the host can close this room' });
    closeRoom(r, r.hostName + ' closed the room');
    return send(200, {});
  }
  if (p === '/api/logout') { q.delSession.run(String(req.headers['x-token'] || '')); return send(200, {}); }
  send(404, { error: 'unknown' });
}

function authorized(req) {
  if (!PASSWORD) return true;
  const h = req.headers.authorization || '';
  if (!h.startsWith('Basic ')) return false;
  const pass = Buffer.from(h.slice(6), 'base64').toString().split(':').slice(1).join(':');
  const a = Buffer.from(pass), b = Buffer.from(PASSWORD);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---------------------------------------------------------------- static files
const server = http.createServer((req, res) => {
  if (!authorized(req)) { res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="HotD"' }); return res.end('password required'); }
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  // server browser: open rooms
  if (p === '/api/rooms') {
    const list = [...rooms.values()].map(r => ({ code: r.code, host: r.hostName, players: 1 + r.guests.size, max: 2,
      started: r.started, age: Math.round((Date.now() - r.created) / 1000) }));
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    return res.end(JSON.stringify(list));
  }
  if (p.startsWith('/api/')) { api(req, res, p).catch((e) => { console.error(e); res.writeHead(500); res.end('{}'); }); return; }
  if (p === '/') p = '/index.html';
  const file = path.join(ROOT, path.normalize(p).replace(/^([/\\])+/, ''));
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.stat(file, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404); return res.end('not found'); }
    const type = MIME[path.extname(file).toLowerCase()] || 'application/octet-stream';
    // revalidate every time (a rebuild must reach everyone at once: host and guest have to run the same build),
    // but answer 304 when the file has not changed, so the 170 MB data package is downloaded once
    const lastMod = new Date(Math.floor(st.mtimeMs / 1000) * 1000).toUTCString();
    const headers = { 'Content-Type': type, 'Cache-Control': 'no-cache', 'Last-Modified': lastMod };
    const since = Date.parse(req.headers['if-modified-since'] || '');
    if (since && since >= Math.floor(st.mtimeMs / 1000) * 1000) { res.writeHead(304, headers); return res.end(); }
    // compress the code and the packaged data (the data shrinks to about a third)
    const gz = /gzip/.test(req.headers['accept-encoding'] || '') && /\.(js|wasm|data|html)$/.test(file);
    if (gz) {
      const cached = file + '.gz';
      fs.stat(cached, (e2, st2) => {
        if (!e2 && st2.mtimeMs >= st.mtimeMs) {
          res.writeHead(200, Object.assign(headers, { 'Content-Encoding': 'gzip', 'Content-Length': st2.size }));
          return fs.createReadStream(cached).pipe(res);
        }
        res.writeHead(200, Object.assign(headers, { 'Content-Encoding': 'gzip' }));
        const z = zlib.createGzip({ level: 6 });
        fs.createReadStream(file).pipe(z).pipe(res);
        // write the compressed copy for next time
        const tmp = cached + '.' + process.pid;
        fs.createReadStream(file).pipe(zlib.createGzip({ level: 6 })).pipe(fs.createWriteStream(tmp)).on('finish', () => fs.rename(tmp, cached, () => {}));
      });
      return;
    }
    res.writeHead(200, Object.assign(headers, { 'Content-Length': st.size }));
    fs.createReadStream(file).pipe(res);
  });
});

// ---------------------------------------------------------------- minimal WebSocket (RFC 6455)
function wsAccept(req, socket) {
  const key = req.headers['sec-websocket-key'];
  const accept = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + accept + '\r\n\r\n');
  socket.setNoDelay(true);
  const ws = { socket, open: true, onmessage: null, onclose: null, buf: Buffer.alloc(0), frags: [], fragOp: 0 };
  ws.send = (data) => {
    if (!ws.open) return;
    const bin = Buffer.isBuffer(data), payload = bin ? data : Buffer.from(String(data));
    const n = payload.length, head = n < 126 ? Buffer.from([bin ? 0x82 : 0x81, n])
      : n < 65536 ? Buffer.from([bin ? 0x82 : 0x81, 126, n >> 8, n & 255])
      : (() => { const h = Buffer.alloc(10); h[0] = bin ? 0x82 : 0x81; h[1] = 127; h.writeBigUInt64BE(BigInt(n), 2); return h; })();
    socket.write(Buffer.concat([head, payload]));
  };
  const close = () => { if (!ws.open) return; ws.open = false; live.delete(ws); socket.destroy(); if (ws.onclose) ws.onclose(); };
  ws.close = close;
  ws.lastSeen = Date.now();
  live.add(ws);
  socket.on('data', (chunk) => {
    ws.lastSeen = Date.now();
    ws.buf = Buffer.concat([ws.buf, chunk]);
    for (;;) {
      if (ws.buf.length < 2) return;
      const fin = ws.buf[0] & 0x80, op = ws.buf[0] & 15, masked = ws.buf[1] & 0x80;
      let n = ws.buf[1] & 127, off = 2;
      if (n === 126) { if (ws.buf.length < 4) return; n = ws.buf.readUInt16BE(2); off = 4; }
      else if (n === 127) { if (ws.buf.length < 10) return; n = Number(ws.buf.readBigUInt64BE(2)); off = 10; }
      if (n > 64 << 20) return close();
      const mlen = masked ? 4 : 0;
      if (ws.buf.length < off + mlen + n) return;
      let payload = ws.buf.subarray(off + mlen, off + mlen + n);
      if (masked) { const m = ws.buf.subarray(off, off + 4); payload = Buffer.from(payload); for (let i = 0; i < n; i++) payload[i] ^= m[i & 3]; }
      ws.buf = ws.buf.subarray(off + mlen + n);
      if (op === 8) return close();
      if (op === 9) { socket.write(Buffer.concat([Buffer.from([0x8a, payload.length]), payload])); continue; }
      if (op === 10) continue;
      if (op === 0) ws.frags.push(payload); else { ws.frags = [payload]; ws.fragOp = op; }
      if (!fin) continue;
      const msg = Buffer.concat(ws.frags); ws.frags = [];
      if (ws.onmessage) ws.onmessage(msg, ws.fragOp === 2);
    }
  });
  socket.on('close', close); socket.on('error', close);
  return ws;
}
// Heartbeat: a player whose connection died without a close (sleep, network change) would keep a room open forever.
// Ping every 20 s; anyone silent for 60 s is dropped, which closes their room.
const live = new Set();
setInterval(() => {
  const now = Date.now();
  for (const ws of live) {
    if (now - ws.lastSeen > 60000) { ws.close(); continue; }
    try { ws.socket.write(Buffer.from([0x89, 0])); } catch (e) { ws.close(); }
  }
}, 20000);

// ---------------------------------------------------------------- co-op rooms
// The host's game sends one binary bundle per frame; the server keeps them all so a player who joins late can
// replay the game from the start, and forwards them to the guest. The guest's input goes to the host as JSON.
const rooms = new Map();
function closeRoom(r, reason) {
  if (!rooms.has(r.code)) return;
  rooms.delete(r.code);
  for (const g of r.guests.values()) json(g.ws, { t: 'room-closed', reason });
  json(r.host, { t: 'room-closed', reason });
  console.log('room', r.code, 'closed:', reason);
}
const CODE_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
function newCode() { let c; do { c = Array.from({ length: 4 }, () => CODE_CHARS[crypto.randomInt(CODE_CHARS.length)]).join(''); } while (rooms.has(c)); return c; }
const json = (ws, m) => ws && ws.send(JSON.stringify(m));

server.on('upgrade', (req, socket) => {
  if (req.url !== '/ws' || !authorized(req)) { socket.destroy(); return; }
  const ws = wsAccept(req, socket);
  let room = null, role = null, slot = 0, name = 'Player', user = null;
  ws.onmessage = (data, binary) => {
    if (binary) {
      if (role !== 'host' || !room) return;
      room.log.push(Buffer.from(data));
      room.logBytes += data.length;
      if (room.logBytes > 256 << 20) { json(ws, { t: 'error', msg: 'room log full' }); return; }
      for (const g of room.guests.values()) if (g.ready) g.ws.send(data);
      return;
    }
    let m; try { m = JSON.parse(data.toString()); } catch (e) { return; }
    if (m.t === 'auth') {
      user = userOf(m.token);
      if (!user) return json(ws, { t: 'auth-failed' });
      name = user.username;
      return json(ws, { t: 'auth-ok', username: name });
    }
    if (!user) return json(ws, { t: 'auth-failed' });
    if (m.t === 'host') {
      // one room per account: hosting again closes the old one
      for (const r of [...rooms.values()]) if (r.ownerId === user.id) closeRoom(r, r.hostName + ' started a new room');
      room = { code: newCode(), host: ws, hostName: name, ownerId: user.id, guests: new Map(), log: [], logBytes: 0, boot: null,
               started: false, created: Date.now() };
      rooms.set(room.code, room); role = 'host';
      json(ws, { t: 'hosting', room: room.code });
      console.log('room', room.code, 'hosted by', name);
    } else if (m.t === 'join') {
      const r = rooms.get(String(m.room || '').toUpperCase());
      if (!r) return json(ws, { t: 'error', msg: 'No room ' + m.room + '.' });
      if (r.guests.size >= 1) return json(ws, { t: 'error', msg: 'Room ' + r.code + ' already has two players.' });
      room = r; role = 'guest'; slot = 1;
      r.guests.set(slot, { ws, name, ready: false });
      q.countGame.run(user.id);
      json(ws, { t: 'joined', room: r.code, slot, host: r.hostName, started: r.started });
      json(r.host, { t: 'guest-join', slot, name });
      if (r.started) sendBoot(r, slot);
    } else if (m.t === 'start' && role === 'host') {
      // the host's game starts now: its save files go to the guests so they start from the same state
      room.boot = m.files || {}; room.build = String(m.build || ''); room.started = true;
      q.countGame.run(user.id);
      for (const s of room.guests.keys()) sendBoot(room, s);
    } else if (m.t === 'input' && role === 'guest') {
      json(room.host, { t: 'gi', slot, f: m.f | 0, x: +m.x || 0, y: +m.y || 0, c: m.c | 0, k: m.k | 0 });
    } else if (m.t === 'close' && role === 'host' && room) {
      closeRoom(room, room.hostName + ' closed the room');
    } else if (m.t === 'leave' && role === 'guest' && room) {
      room.guests.delete(slot);
      json(room.host, { t: 'guest-leave', slot, name });
      room = null;
    } else if (m.t === 'desync' && room) {
      json(room.host, { t: 'desync', name, frame: m.frame });
    }
  };
  ws.onclose = () => {
    if (!room) return;
    if (role === 'host') {
      if (room.host === ws) closeRoom(room, room.hostName + ' left');
    } else {
      room.guests.delete(slot);
      json(room.host, { t: 'guest-leave', slot, name });
    }
  };
});

function sendBoot(r, s) {
  const g = r.guests.get(s);
  if (!g) return;
  json(g.ws, { t: 'net-boot', files: r.boot, build: r.build });
  for (const b of r.log) g.ws.send(b);
  g.ready = true;
}

server.listen(PORT, () => {
  console.log('The House of the Dead web port: http://localhost:' + PORT + '/  (serving ' + ROOT + ')');
  if (PASSWORD) console.log('password protected');
  else console.log('no password: anyone who can reach this port can download the build (it contains your game data)');
});
