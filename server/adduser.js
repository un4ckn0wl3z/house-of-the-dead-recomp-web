// Operator tool: create an account without the web form (and its captcha), e.g. for yourself.
//   node adduser.js <username> <password> [--db data/hotd.db]
'use strict';
const path = require('path'), crypto = require('crypto'), fs = require('fs');
const { DatabaseSync } = require('node:sqlite');
const [username, password] = process.argv.slice(2);
const i = process.argv.indexOf('--db');
const file = i > 0 ? process.argv[i + 1] : path.join(__dirname, 'data', 'hotd.db');
if (!/^[A-Za-z0-9_\-]{3,16}$/.test(username || '') || !password || password.length < 6)
  { console.error('usage: node adduser.js <name: 3-16 letters/digits/_/-> <password: 6+ chars>'); process.exit(1); }
fs.mkdirSync(path.dirname(file), { recursive: true });
const db = new DatabaseSync(file);
db.exec(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  salt TEXT NOT NULL, hash TEXT NOT NULL, created_at INTEGER NOT NULL, games INTEGER NOT NULL DEFAULT 0)`);
const salt = crypto.randomBytes(16).toString('hex');
db.prepare('INSERT INTO users (username, salt, hash, created_at) VALUES (?, ?, ?, ?)')
  .run(username, salt, crypto.scryptSync(password, salt, 64).toString('hex'), Date.now());
console.log('created', username);
