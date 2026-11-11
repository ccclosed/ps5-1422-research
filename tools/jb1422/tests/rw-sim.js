#!/usr/bin/env node
/* jb1422 / tests/rw-sim.js — UNIT-СИМУЛЯЦИЯ (не эксплуатация!).
 *
 * Зачем: на локальной машине WebKitGTK 2.52.5 уже с фиксом (STAGE 2 FAIL — честно),
 * поэтому проверить ЛОГИКУ чтения/записи каналов и self-test можно только на
 * симулированном 2d-контексте. Этот тест:
 *   1) подгружает реальные js/util.js и js/primitive.js (те же файлы, что поедут на консоль);
 *   2) подставляет фейковый document.createElement('canvas').getContext('2d') с настоящей
 *      семантикой Canvas2D (setTransform/getTransform, save/restore, numeric props);
 *   3) гоняет CanvasAliasPrimitive.selfTestHarness() — тот самый HARNESS-тест из стадии H;
 *   4) проверяет f64hex/f64bytes/addStr/close.
 *
 * Ожидаемо: HARNESS PASS xx/xx. Если PASS — значит код записи/чтения/сравнения каналов
 * корректен, и на консоли (после reclaim) те же функции дадут те же результаты.
 *
 * Run: node tools/jb1422/tests/rw-sim.js   (или tools/jsc-lab/jsc с тем же файлом — но
 *      jsc не имеет require/vm; используйте node)
 */
'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.resolve(__dirname, '..', 'js');
let failures = 0;
function ok(name, cond, detail) {
  const line = (cond ? 'PASS ' : 'FAIL ') + name + (detail ? ' — ' + detail : '');
  console.log(line);
  if (!cond) failures++;
}

// ---------------------------------------------------------------- fake DOM --
function FakeContext(canvas) {
  this.canvas = canvas;
  this._props = {
    lineWidth: 1.0, globalAlpha: 1.0, shadowBlur: 0.0,
    shadowOffsetX: 0.0, shadowOffsetY: 0.0, miterLimit: 10.0, lineDashOffset: 0.0,
    fillStyle: '#000000', strokeStyle: '#000000', font: '10px sans-serif',
    lineCap: 'butt', lineJoin: 'miter', globalCompositeOperation: 'source-over',
    textAlign: 'start', textBaseline: 'alphabetic', imageSmoothingEnabled: true
  };
  this._m = [1, 0, 0, 1, 0, 0];
  this._stack = [];
  this._dash = [];
}
FakeContext.prototype.setTransform = function (a, b, c, d, e, f) {
  this._m = [a, b, c, d, e, f];
};
FakeContext.prototype.getTransform = function () {
  const m = this._m;
  return { a: m[0], b: m[1], c: m[2], d: m[3], e: m[4], f: m[5] };
};
FakeContext.prototype.save = function () {
  this._stack.push({
    m: this._m.slice(), props: Object.assign({}, this._props), dash: this._dash.slice()
  });
};
FakeContext.prototype.restore = function () {
  const s = this._stack.pop();
  if (!s) throw new Error('restore without save');
  this._m = s.m; this._props = s.props; this._dash = s.dash;
};
FakeContext.prototype.setLineDash = function (arr) { this._dash = Array.prototype.slice.call(arr); };
FakeContext.prototype.getLineDash = function () { return this._dash.slice(); };
FakeContext.prototype.createLinearGradient = function () { return {__gradient: true}; };
['lineWidth', 'globalAlpha', 'shadowBlur', 'shadowOffsetX', 'shadowOffsetY',
 'miterLimit', 'lineDashOffset', 'fillStyle', 'strokeStyle', 'font', 'lineCap',
 'lineJoin', 'globalCompositeOperation', 'textAlign', 'textBaseline',
 'imageSmoothingEnabled'].forEach(function (name) {
  Object.defineProperty(FakeContext.prototype, name, {
    get: function () { return this._props[name]; },
    set: function (v) { this._props[name] = v; }
  });
});

function FakeCanvas() {
  this.width = 1; this.height = 1; this.id = '';
  this._ctx = null;
}
FakeCanvas.prototype.getContext = function (type) {
  if (type !== '2d') return null;
  if (!this._ctx) this._ctx = new FakeContext(this);
  return this._ctx;
};

const fakeDocument = {
  body: { appendChild: function () {} },
  head: { appendChild: function () {} },
  createElement: function (tag) {
    if (tag !== 'canvas') return {};
    return new FakeCanvas();
  },
  getElementById: function () { return null; }
};

// ------------------------------------------------------ load production code --
function loadInto(file) {
  const code = fs.readFileSync(path.join(ROOT, file), 'utf8');
  vm.runInThisContext(code, { filename: file });
}
global.window = global;                 // production files используют window || globalThis
global.document = fakeDocument;
global.location = { protocol: 'http:', href: 'http://localhost/jb1422/index.html' };
Object.defineProperty(global, 'navigator', {
  value: { userAgent: 'node-sim', hardwareConcurrency: 8 },
  configurable: true, writable: true
});
global.isSecureContext = false;
loadInto('util.js');
loadInto('primitive.js');

const U = global.JBUtil;
const P = global.JBPrimitive;

// ------------------------------------------------------------------- tests --
console.log('== jb1422 rw-sim (UNIT/SIMULATION, not exploit) ==');

// 1) util конверсии
const bits = U.f64hex(1.0);
ok('f64hex(1.0)=3ff0000000000000', bits === '3ff0000000000000', bits);
const b = U.f64bytes(1.0);
ok('f64bytes(1.0) little-endian', b[0] === 0 && b[6] === 0xf0 && b[7] === 0x3f, JSON.stringify(b));
ok('addStr(0x1000,0x20)', U.addStr('0x1000', 0x20) === '0x1020', U.addStr('0x1000', 0x20));
ok('close(0.1+0.2,0.3)', U.close(0.1 + 0.2, 0.3, 1e-12), String(0.1 + 0.2));
ok('u64hex(lo,hi)', U.u64hex(0x89abcdef, 0x01234567) === '0x0123456789abcdef', U.u64hex(0x89abcdef, 0x01234567));

// 2) HARNESS self-test (тот же код, что стадия H)
const prim = new P.CanvasAliasPrimitive(function (m) { console.log('   [prim] ' + m); });
const harness = prim.selfTestHarness();
console.log('   harness: ' + harness.pass + '/' + harness.total + ' checks, failed=' + JSON.stringify(harness.failed));
ok('harness self-test status OK', harness.status === 'OK', harness.status);
ok('harness all checks pass', harness.pass === harness.total, harness.pass + '/' + harness.total);

// 3) default shared-2d: getContext('2d') pair identity (control из STAGE 1)
const c = fakeDocument.createElement('canvas');
ok('control getContext pair identity', c.getContext('2d') === c.getContext('2d'));

// 4) RawMemory: без адреса read64 обязан бросить JbNotReady с причиной про leak
let threw = false, reason = '';
try {
  new P.RawMemory(prim, function () {}).read64('0xdeadbeef');
} catch (e) { threw = true; reason = e.reason || e.message; }
ok('RawMemory.read64 without leak -> JbNotReady', threw && /forged lineDash/.test(reason), reason.slice(0, 80));

// 5) RawMemory.write64 на неготовом канале тоже JbNotReady (не молчит)
threw = false;
try { new P.RawMemory(prim, function () {}).write64('0x10', '0x4141'); } catch (e) { threw = true; }
ok('RawMemory.write64 gated', threw);

// 6) prepareForge(null) -> BLOCKED с причиной (нет leak); с адресом — выполняет попытки
const raw = new P.RawMemory(prim, function () {});
const blocked = raw.prepareForge(null);
ok('prepareForge(null) BLOCKED', blocked.status === 'BLOCKED' && /leak/.test(blocked.reason || ''),
  (blocked.reason || '').slice(0, 70));

// ---------------------------------------------------------------- summary --
console.log('');
if (failures === 0) {
  console.log('SIM_RESULT: PASS (unit simulation; exploit stages still need PS5 14.22)');
  process.exit(0);
}
console.log('SIM_RESULT: FAIL (' + failures + ' failures)');
process.exit(1);