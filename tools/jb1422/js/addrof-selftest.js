#!/usr/bin/env node
/* jb1422 / js/addrof-selftest.js — SIM-проверка логики STAGE 9b (addrof/fakeobj).
 *
 * Не эксплойт: здесь моделируется то, что на консоли даёт пост-фри заготовка:
 *   - буфер 104 контролируемых байта (7 numeric props + transform 6 doubles);
 *   - «поддельный ArrayBuffer»: DataView над смоделированной памятью;
 *   - backend {alloc/read/write/addrof/fakeobj}; TypeConfusionPrimitive.read64/write64
 *     ходят через него.
 * Тест доказывает, что битовая логика addrof/fakeobj/read64/write64 корректна и что
 * раскладка State/кандидаты считаются ожидаемо. На консоли тот же код получит backend
 * из реального post-free reclaim (STAGE 9b), а не из симуляции.
 *
 * Run: node tools/jb1422/js/addrof-selftest.js
 */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.resolve(__dirname, '..');
let failures = 0;
function ok(name, cond, detail) {
  console.log((cond ? 'PASS ' : 'FAIL ') + name + (detail ? ' — ' + detail : ''));
  if (!cond) failures++;
}
function hex(bytes) {
  return '0x' + bytes.slice().reverse().map((b) => ('0' + (b & 0xff).toString(16)).slice(-2)).join('');
}

// --- окружение без DOM: util не нужен, primitive не требует document при создании ---
global.window = global;
vm.runInThisContext(fs.readFileSync(path.join(ROOT, 'js/util.js'), 'utf8'), { filename: 'util.js' });
vm.runInThisContext(fs.readFileSync(path.join(ROOT, 'js/primitive.js'), 'utf8'), { filename: 'primitive.js' });
const P = global.JBPrimitive;

console.log('== jb1422 STAGE 9b addrof/fakeobj selftest (SIMULATION) ==');

// 1) раскладка
const tc = new P.TypeConfusionPrimitive({ aliasIdx: -1 }, () => {});
const layout = tc.layoutReport();
ok('controlled span = 104 B', layout.controlled.totalBytes === 104, JSON.stringify(layout.controlled));
ok('State size = 400 B (v923)', layout.stateSize === 400, String(layout.stateSize));
ok('out-of-line buffer = 4400 B (capacity 11)', layout.outOfLineBufferBytes === 4400);
ok('lineWidth offset = +0x30 (measured)', layout.stateLayout[0].offset === 0x30, String(layout.stateLayout[0].offset));
ok('transform = 48 B (6 doubles)', layout.stateLayout.find((f) => f.prop === 'transform').size === 48);
ok('victim candidates содержат JSArray butterfly/ArrayBuffer/ctx 768', layout.victims.length >= 30 &&
  layout.victims.some((v) => v.kind === 'CanvasRenderingContext2D' && v.allocBytes === 768));

// 2) «поддельный ArrayBuffer»: смоделированный буфер State + DataView поверх памяти
// (a) packed 104 байта = 7 props (56 B) + transform (48 B): ровно то, что контролируем
const controlled = new Uint8Array(104);
const ctrlView = new DataView(controlled.buffer);
for (let i = 0; i < 7; i++) ctrlView.setFloat64(i * 8, 1000.5 + i, true);
ctrlView.setFloat64(56, 111.125, true);
ctrlView.setFloat64(64, 222.25, true);
ok('104-byte packed: 7 props (56 B) + transform@56 (48 B)', ctrlView.getFloat64(0, true) === 1000.5 &&
  ctrlView.getFloat64(56, true) === 111.125 && controlled.length === 104);
// (b) State-раскладка: lineWidth +0x30, transform +0x70 (буфер 0xA8 = State-префикс)
const state = new Uint8Array(0xA8);
const stateView = new DataView(state.buffer);
stateView.setFloat64(0x30, 1234.5, true);
stateView.setFloat64(0x70, 111.125, true);
stateView.setFloat64(0x78, 222.25, true);
ok('State model: lineWidth@0x30 readable', stateView.getFloat64(0x30, true) === 1234.5);
ok('State model: transform[0]@0x70 readable', stateView.getFloat64(0x70, true) === 111.125);

// 3) backend: 64 КБ симулированной памяти + fakeobj/addrof
const MEM = 64 * 1024;
const mem = new Uint8Array(MEM);
let next = 0x100;
const objects = new Map();
function alloc(size) { const a = next; next += Math.max(16, (size + 15) & ~15); return a; }
function read(addr, n) { const a = typeof addr === 'string' ? parseInt(addr, 16) : addr; return Array.from(mem.slice(a, a + n)); }
function write(addr, bytes) { const a = typeof addr === 'string' ? parseInt(addr, 16) : addr; for (let i = 0; i < bytes.length; i++) mem[a + i] = bytes[i] & 0xff; }
function addrof(obj) {
  for (const [a, o] of objects) if (o === obj) return '0x' + a.toString(16);
  const a = alloc(8); objects.set(a, obj); return '0x' + a.toString(16);
}
function fakeobj(addr) {
  const a = typeof addr === 'string' ? parseInt(addr, 16) : addr;
  return { __fakeObject: true, addr: '0x' + a.toString(16), backend: true };
}
// «поддельный ArrayBuffer»: DataView поверх смоделированной памяти по базе 0x200
const fakeABBase = 0x200;
const fakeAB = { view: new DataView(mem.buffer, fakeABBase, 0x1000) };
tc.attachBackend({ alloc, read, write, addrof, fakeobj });
ok('backend attached -> tc.ready()', tc.ready() === true);

// 4) addrof / fakeobj / read64 / write64 через backend
const victim = { name: 'victim' };
const victimAddr = tc.addrof(victim);
ok('addrof(object) -> hex-адрес', /^0x[0-9a-f]+$/.test(victimAddr), victimAddr);
ok('fakeobj(addr) -> объект', !!tc.fakeobj(victimAddr));

tc.write64('0x200', '0x4142434445464748');
const readBack = tc.read64('0x200');
ok('write64->read64 round-trip', readBack === '0x4142434445464748', readBack);
ok('bytes совпали (LE)', hex(mem.slice(0x200, 0x208)) === readBack, hex(mem.slice(0x200, 0x208)));

// 5) произвольное чтение по «адресу» через fake ArrayBuffer: кладём 8 байт и читаем DataView
const targetAddr = 0x300;
for (let i = 0; i < 8; i++) mem[targetAddr + i] = 0x10 + i;
ok('read64 arbitrary addr', tc.read64('0x300') === '0x1716151413121110', tc.read64('0x300'));
tc.write64('0x300', '0xdeadbeefcafebabe');
ok('write64 arbitrary addr + readback', tc.read64('0x300') === '0xdeadbeefcafebabe', tc.read64('0x300'));
ok('fake ArrayBuffer DataView видит запись', fakeAB.view.getUint32(0x100, true) === 0xcafebabe,
  '0x' + fakeAB.view.getUint32(0x100, true).toString(16));

// 6) без backend — честный JbNotReady (не «тихий» мусор)
const cold = new P.TypeConfusionPrimitive({ aliasIdx: -1 }, () => {});
let threw = false, reason = '';
try { cold.read64('0x0'); } catch (e) { threw = true; reason = e.reason || e.message; }
ok('без backend read64 -> JbNotReady', threw && /memory backend/.test(reason), String(reason).slice(0, 70));

console.log('');
if (failures === 0) {
  console.log('ADDROF_SELFTEST: PASS (логика 9b верна; на консоли нужен реальный post-free reclaim)');
  process.exit(0);
}
console.log('ADDROF_SELFTEST: FAIL (' + failures + ')');
process.exit(1);