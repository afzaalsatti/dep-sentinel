// Generates media/icon.png – a shield guarding a dependency tree, with one vulnerable (red) node –
// without any image dependencies (anti-aliased rasteriser + PNG encoder using only zlib).
// Usage: node scripts/make-icon.js [size=256]
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const SIZE = Number(process.argv[2]) || 256;
const SS = 4; // supersampling per axis

// ---- geometry in the 24x24 design space (same as media/shield.svg) ----
function cubic(p0, p1, p2, p3, n = 32) {
  const pts = [];
  for (let i = 1; i <= n; i++) {
    const t = i / n, u = 1 - t;
    pts.push([
      u * u * u * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t * t * t * p3[0],
      u * u * u * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t * t * t * p3[1],
    ]);
  }
  return pts;
}
const shield = [[12, 2.2], [3.6, 5.4], [3.6, 11.4], ...cubic([3.6, 11.4], [3.6, 16.7], [7.2, 20.7], [12, 21.9]), ...cubic([12, 21.9], [16.8, 20.7], [20.4, 16.7], [20.4, 11.4]), [20.4, 5.4]];
const inner = shield.map(([x, y]) => [12 + (x - 12) * 0.86, 12.2 + (y - 12.2) * 0.88]);

const N = {
  root: [12, 7.4],
  a: [8.7, 11.7],
  b: [15.3, 11.7],
  a1: [7.0, 15.9],
  a2: [10.4, 15.9],
  b1: [15.3, 16.2], // the vulnerable one
};
const edges = [['root', 'a'], ['root', 'b'], ['a', 'a1'], ['a', 'a2'], ['b', 'b1']];
const NODE_R = 1.3;
const BAD_R = 1.65;
const EDGE_W = 0.5;

// ---- design space -> pixels ----
const scale = (SIZE * 0.8) / 19.7;
const ox = SIZE / 2 - 12 * scale;
const oy = SIZE / 2 - 12.05 * scale;
const P = ([x, y]) => [ox + x * scale, oy + y * scale];
const shieldPx = shield.map(P);
const innerPx = inner.map(P);
const nodePx = Object.fromEntries(Object.entries(N).map(([k, v]) => [k, P(v)]));

function inPoly(x, y, poly) {
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const [xi, yi] = poly[i], [xj, yj] = poly[j];
    if (yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}
function distSeg(x, y, [ax, ay], [bx, by]) {
  const dx = bx - ax, dy = by - ay;
  const t = Math.max(0, Math.min(1, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)));
  return Math.hypot(x - (ax + t * dx), y - (ay + t * dy));
}
function inRoundRect(x, y, r) {
  const cx = Math.min(Math.max(x, r), SIZE - r), cy = Math.min(Math.max(y, r), SIZE - r);
  return Math.hypot(x - cx, y - cy) <= r;
}
const mix = (a, b, t) => a.map((v, i) => v + (b[i] - v) * Math.max(0, Math.min(1, t)));
const hex = (h) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16));

const C = {
  bgTop: hex('#1e3a8a'), bgBot: hex('#0b1120'),
  rim: hex('#5eead4'),
  shieldTop: hex('#14b8a6'), shieldBot: hex('#0f766e'),
  white: [255, 255, 255],
  bad: hex('#ef4444'), badHalo: hex('#fecaca'),
};

function sample(x, y) {
  if (!inRoundRect(x, y, SIZE * 0.2)) return null;
  const t = y / SIZE;
  if (!inPoly(x, y, shieldPx)) {
    // soft radial glow behind the shield
    const g = Math.max(0, 1 - Math.hypot(x - SIZE / 2, y - SIZE * 0.46) / (SIZE * 0.62));
    return mix(mix(C.bgTop, C.bgBot, t), [59, 130, 246], g * 0.18);
  }
  if (!inPoly(x, y, innerPx)) return mix(C.rim, C.shieldTop, t * 0.6);
  const bad = nodePx.b1;
  const dBad = Math.hypot(x - bad[0], y - bad[1]);
  if (dBad < BAD_R * scale) return C.bad;
  if (dBad < (BAD_R + 0.42) * scale) return C.white;
  if (dBad < (BAD_R + 1.1) * scale) return mix(mix(C.shieldTop, C.shieldBot, t), C.badHalo, 0.28);
  for (const k of Object.keys(N)) {
    if (k === 'b1') continue;
    if (Math.hypot(x - nodePx[k][0], y - nodePx[k][1]) < NODE_R * scale) return C.white;
  }
  for (const [p, q] of edges) {
    if (distSeg(x, y, nodePx[p], nodePx[q]) < (EDGE_W / 2) * scale) return mix(C.white, C.shieldTop, 0.12);
  }
  return mix(C.shieldTop, C.shieldBot, (y - shieldPx[0][1]) / (SIZE * 0.8));
}

// ---- rasterise ----
const stride = SIZE * 4 + 1;
const raw = Buffer.alloc(SIZE * stride);
for (let y = 0; y < SIZE; y++) {
  raw[y * stride] = 0;
  for (let x = 0; x < SIZE; x++) {
    let r = 0, g = 0, b = 0, a = 0;
    for (let sy = 0; sy < SS; sy++) for (let sx = 0; sx < SS; sx++) {
      const c = sample(x + (sx + 0.5) / SS, y + (sy + 0.5) / SS);
      if (c) { r += c[0]; g += c[1]; b += c[2]; a++; }
    }
    const o = y * stride + 1 + x * 4;
    raw[o] = a ? Math.round(r / a) : 0;
    raw[o + 1] = a ? Math.round(g / a) : 0;
    raw[o + 2] = a ? Math.round(b / a) : 0;
    raw[o + 3] = Math.round((a / (SS * SS)) * 255);
  }
}

// ---- PNG encode ----
const crcTable = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
const crc32 = (buf) => {
  let c = 0xffffffff;
  for (const byte of buf) c = crcTable[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};
const chunk = (type, data) => {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
};
const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(SIZE, 0);
ihdr.writeUInt32BE(SIZE, 4);
ihdr[8] = 8;
ihdr[9] = 6;
const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  chunk('IHDR', ihdr),
  chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
  chunk('IEND', Buffer.alloc(0)),
]);
const out = process.argv[3] ? path.resolve(process.argv[3]) : path.join(__dirname, '..', 'media', 'icon.png');
fs.writeFileSync(out, png);
console.log(`wrote ${out} (${SIZE}x${SIZE}, ${png.length} bytes)`);
