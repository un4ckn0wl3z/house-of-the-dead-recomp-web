// Registration captcha, made on this server (no third-party service or keys). Characters are drawn as jittered,
// rotated strokes in an SVG, so the answer is not in the image's source as text; each captcha can be used once
// and expires after 10 minutes.
'use strict';
const crypto = require('node:crypto');

// strokes on a 4 x 6 grid
const GLYPHS = {
  A: [[[0, 6], [2, 0], [4, 6]], [[1, 3.6], [3, 3.6]]],
  C: [[[4, 1], [3, 0], [1, 0], [0, 1], [0, 5], [1, 6], [3, 6], [4, 5]]],
  E: [[[4, 0], [0, 0], [0, 6], [4, 6]], [[0, 3], [3, 3]]],
  F: [[[4, 0], [0, 0], [0, 6]], [[0, 3], [3, 3]]],
  H: [[[0, 0], [0, 6]], [[4, 0], [4, 6]], [[0, 3], [4, 3]]],
  K: [[[0, 0], [0, 6]], [[4, 0], [0, 3.5]], [[1.5, 2.6], [4, 6]]],
  L: [[[0, 0], [0, 6], [4, 6]]],
  M: [[[0, 6], [0, 0], [2, 3], [4, 0], [4, 6]]],
  N: [[[0, 6], [0, 0], [4, 6], [4, 0]]],
  P: [[[0, 6], [0, 0], [3, 0], [4, 1], [4, 2], [3, 3], [0, 3]]],
  R: [[[0, 6], [0, 0], [3, 0], [4, 1], [4, 2], [3, 3], [0, 3]], [[2, 3], [4, 6]]],
  T: [[[0, 0], [4, 0]], [[2, 0], [2, 6]]],
  U: [[[0, 0], [0, 5], [1, 6], [3, 6], [4, 5], [4, 0]]],
  V: [[[0, 0], [2, 6], [4, 0]]],
  W: [[[0, 0], [1, 6], [2, 3], [3, 6], [4, 0]]],
  X: [[[0, 0], [4, 6]], [[4, 0], [0, 6]]],
  Y: [[[0, 0], [2, 3], [4, 0]], [[2, 3], [2, 6]]],
  2: [[[0, 1], [1, 0], [3, 0], [4, 1], [4, 2], [0, 6], [4, 6]]],
  3: [[[0, 0], [4, 0], [2, 2.5], [3, 2.5], [4, 3.5], [4, 5], [3, 6], [1, 6], [0, 5]]],
  4: [[[3, 6], [3, 0], [0, 4], [4, 4]]],
  5: [[[4, 0], [0, 0], [0, 3], [3, 3], [4, 4], [4, 5], [3, 6], [0, 6]]],
  7: [[[0, 0], [4, 0], [1, 6]]],
  9: [[[4, 3], [1, 3], [0, 2], [0, 1], [1, 0], [3, 0], [4, 1], [4, 5], [3, 6], [0, 6]]],
};
const CHARS = Object.keys(GLYPHS);
const LEN = 5, W = 170, H = 56, TTL = 10 * 60 * 1000;
const pending = new Map();   // id -> { answer, expires }

const rnd = (a, b) => a + crypto.randomInt(0, 1e6) / 1e6 * (b - a);
const colour = () => `hsl(${crypto.randomInt(0, 360)},${crypto.randomInt(45, 75)}%,${crypto.randomInt(58, 74)}%)`;

function make() {
  let answer = '', paths = '';
  for (let i = 0; i < LEN; i++) {
    const ch = CHARS[crypto.randomInt(0, CHARS.length)];
    answer += ch;
    const s = rnd(4.6, 5.8), ang = rnd(-0.35, 0.35), cos = Math.cos(ang), sin = Math.sin(ang);
    const ox = 16 + i * 30 + rnd(-3, 3), oy = 11 + rnd(-4, 4), skew = rnd(-0.25, 0.25);
    const pt = ([x, y]) => {
      x = (x - 2 + rnd(-0.22, 0.22) + skew * (y - 3)) * s; y = (y - 3 + rnd(-0.22, 0.22)) * s;
      return [(ox + 10 + x * cos - y * sin).toFixed(1), (oy + 16 + x * sin + y * cos).toFixed(1)];
    };
    const c = colour(), w = rnd(2.4, 3.4).toFixed(1);
    for (const stroke of GLYPHS[ch])
      paths += `<path d="M${stroke.map(p => pt(p).join(' ')).join(' L')}" stroke="${c}" stroke-width="${w}" fill="none" stroke-linecap="round" stroke-linejoin="round"/>`;
  }
  let noise = '';
  for (let i = 0; i < 4; i++)
    noise += `<path d="M${rnd(0, 20).toFixed(0)} ${rnd(5, H - 5).toFixed(0)} C${rnd(30, 70).toFixed(0)} ${rnd(0, H).toFixed(0)},${rnd(90, 140).toFixed(0)} ${rnd(0, H).toFixed(0)},${rnd(150, W).toFixed(0)} ${rnd(5, H - 5).toFixed(0)}" stroke="${colour()}" stroke-width="${rnd(1.5, 2.6).toFixed(1)}" fill="none" opacity="0.8"/>`;
  for (let i = 0; i < 40; i++)
    noise += `<circle cx="${rnd(0, W).toFixed(0)}" cy="${rnd(0, H).toFixed(0)}" r="${rnd(0.8, 1.8).toFixed(1)}" fill="${colour()}"/>`;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}"><rect width="100%" height="100%" fill="#1b1e23"/>${noise}${paths}</svg>`;
  return { answer, svg };
}

function create() {
  const now = Date.now();
  for (const [id, c] of pending) if (c.expires < now) pending.delete(id);
  if (pending.size > 20000) pending.delete(pending.keys().next().value);
  const id = crypto.randomBytes(12).toString('hex');
  const { answer, svg } = make();
  pending.set(id, { answer, expires: now + TTL });
  return { id, svg };
}
// true when the answer matches; a captcha is used up by any attempt
function check(id, answer) {
  const c = pending.get(String(id || ''));
  pending.delete(String(id || ''));
  return !!c && c.expires >= Date.now() && String(answer || '').trim().toUpperCase() === c.answer;
}

module.exports = { create, check };
