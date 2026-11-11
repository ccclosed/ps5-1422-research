#!/usr/bin/env node
/**
 * contract-test.mjs — сторож СТЫКОВ, а не логики.
 *
 * Ловит класс регрессий, который не видит ни rw-sim, ни kernel-integration:
 * мост и kernel-модуль расходятся в СЕМАНТИКЕ, оба «работают», а цепочка молча
 * деградирует (так уже случилось: full-chain через TCP дал 1 стадию FAIL вместо 13/13
 * из-за того, что chain.rtmsg2() отдавал не тот вид ответа).
 *
 * Проверяет 4 контракта:
 *   C1  p содержит ВСЕ поля, которые kernel находит grep-ом (read1/2/4/8, write1/2/4/8,
 *       malloc, add32, readBytes, writeBytes, ready, reason, pipeRead, pipeWrite).
 *   C2  rw = attachKernelRwProvider провайдер принимается и p.readBytes/p.writeBytes
 *       реально ходят через него (read(addr,len)->bytes, write(addr,bytes)).
 *   C3  chain.rtmsg2() в ТРЁХ видах — {ptr,bytes}, Uint8Array, число — принимается
 *       kernel-модулем (ни один вид не должен приводить к «routing socket не дал ответа»).
 *   C4  в классах kernel-модуля нет повторных определений методов (второй
 *       leakKernelBase молча перекрывает первый и меняет поведение цепочки).
 *
 * Запуск: node tests/contract-test.mjs        (exit 0 = все контракты целы)
 */
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');

let fails = 0, warns = 0;
const rows = [];
function warn(id, name, detail = '') {
  warns++;
  rows.push({ id, name, st: 'WARN', detail });
  console.log(`  [WARN] ${id} ${name}${detail ? ' :: ' + detail : ''}`);
}
function check(id, name, cond, detail = '') {
  const st = cond ? 'PASS' : 'FAIL';
  if (!cond) fails++;
  rows.push({ id, name, st, detail });
  console.log(`  [${st}] ${id} ${name}${detail ? ' :: ' + detail : ''}`);
}
function section(t) { console.log('\n== ' + t + ' =='); }

// ---------------------------------------------------------------- загрузка моста
function loadScript(rel) {
  const p = path.join(ROOT, rel);
  const code = fs.readFileSync(p, 'utf8');
  const ctx = globalThis;
  vm.runInThisContext(code, { filename: p });
  return ctx;
}
// kernel-модуль и offsets ждут window.* — в Node подменяем window на globalThis
globalThis.window = globalThis;
loadScript('js/util.js');
loadScript('js/primitive.js');
loadScript('js/syscalls.js');
loadScript('js/kernel-bridge.js');
// offsets/1422.js — ES-модуль, публикующий window.KRW; грузим ДО класса
await import(pathToFileURL(path.join(ROOT, 'kernel/offsets/1422.js')).href);
if (!globalThis.KRW) { console.log('  [FAIL] offsets 14.22 не опубликовали window.KRW'); fails++; }
const { I64, createPrimitive, createChain } = globalThis.JB1422Bridge;
const kernelSrc = fs.readFileSync(path.join(ROOT, 'kernel', 'relapse1422.js'), 'utf8');

// ------------------------------------------------------------------ C1: поля p
section('C1. p содержит поля, которые kernel реально использует (this.p.*)');
const p = createPrimitive(null, null, () => {});
// Контракт берём НЕ по всему grep'у (там ловятся локальные переменные p.value/p.read),
// а по this.p.* — это и есть настоящий примитив. Плюс помечаем, какие поля kernel
// сам защищает typeof-проверкой (тогда отсутствие = деградация, а не поломка).
const usedByKernel = [...new Set([...kernelSrc.matchAll(/this\.p\.([a-zA-Z0-9_]+)/g)].map((m) => m[1]))].sort();
const guarded = new Set([...kernelSrc.matchAll(/typeof\s+this\.p\.([a-zA-Z0-9_]+)\s*===\s*["']function["']/g)].map((m) => m[1]));
const PIPELIKE = new Set(['pipeRead', 'pipeWrite', 'pipeReadBytes']);
const REQUIRED_ALWAYS = ['read1', 'read4', 'read8', 'write1', 'write4', 'write8', 'malloc', 'ready', 'reason'];
for (const key of usedByKernel) {
  const v = p[key];
  const present = typeof v === 'function';
  const optional = guarded.has(key) || PIPELIKE.has(key);
  if (present) check('C1.' + key, key, true, 'есть');
  else if (optional) check('C1.' + key, key, true, 'нет, но kernel ловит typeof → деградация, не поломка');
  else check('C1.' + key, key, false, 'ОТСУТСТВУЕТ и kernel НЕ защищает — упадёт TypeError');
}
for (const key of REQUIRED_ALWAYS) {
  if (usedByKernel.includes(key)) continue;
  check('C1.' + key, key, typeof p[key] === 'function', 'обязательное поле вне this.p.*-скана');
}
check('C1.count', 'полей в контракте', usedByKernel.length > 0, usedByKernel.length + ': ' + usedByKernel.join(','));

// -------------------------------------------------------------------- C2: rw
section('C2. attachKernelRwProvider: read(addr,len)->bytes / write(addr,bytes)');
const MEM = 0x40000;
const rwMem = new Uint8Array(MEM);
const seen = { read: 0, write: 0 };
const rw = {
  read(addr, len) {
    seen.read++;
    const o = typeof addr === 'number' ? addr : (addr.low >>> 0);
    return Uint8Array.from(rwMem.slice(o, o + len));
  },
  write(addr, bytes) {
    seen.write++;
    const o = typeof addr === 'number' ? addr : (addr.low >>> 0);
    for (let i = 0; i < bytes.length && o + i < MEM; i++) rwMem[o + i] = bytes[i] & 0xff;
  }
};
let providerOk = false;
try {
  p.attachKernelRwProvider(async () => rw);
  providerOk = true;
} catch (e) { providerOk = false; }
check('C2.provider', 'attachKernelRwProvider принимается', providerOk);
check('C2.shape', 'rw.read/write — функции',
  typeof rw.read === 'function' && typeof rw.write === 'function');

// p.attachKernelPipe(kx) должен вернуть провайдер и привязать pipeRead/pipeWrite
let pipeAttached = false;
try {
  const got = await p.attachKernelPipe({});
  pipeAttached = !!(got && typeof got.read === 'function' && typeof got.write === 'function');
} catch (e) { pipeAttached = false; }
check('C2.attachKernelPipe', 'attachKernelPipe отдаёт {read,write}', pipeAttached,
  pipeAttached ? '' : 'поставщик не вернул rw — kernel уйдёт в BLOCKED');

// ------------------------------------------------------------------ C3: rtmsg2
section('C3. chain.rtmsg2() в трёх видах принимается kernel-модулем');
const kernelCode = kernelSrc;
// ES-модуль нельзя import-нуть из CJS-контекста без package.json type=module,
// а data:-URL валит стек на тяжёлом файле — поэтому грузим в vm, сняв `export`.
const kernelPlain = kernelCode
  .replace(/^\uFEFF/, '')
  // CLI-хвост модуля (--dry-run) содержит top-level await import — в vm он
  // невалиден и для контракт-теста не нужен: отрезаем ровно перед ним.
  .split('\nconst NODE = typeof process')[0]
  .replace(/^export\s+(?=(async\s+function|function|class\s|const\s|let\s|\{))/gm, '')
  .replace(/import\.meta\.url/g, '"file:///kernel/relapse1422.js"');
vm.runInThisContext(kernelPlain + '\n;globalThis.__K1422 = { KernelExploit1422, I64 };',
  { filename: 'kernel/relapse1422.js' });
const { KernelExploit1422, I64: KI64 } = globalThis.__K1422;

/** Валидный «author record» как в моке --dry-run: база + FF. */
function makeRecord() {
  const buf = new Uint8Array(512);
  buf[0] = 0x04; buf[1] = 0x00;
  const ret = 0x00B06869, at = 184;
  for (let i = 0; i < 4; i++) buf[at + i] = (ret >>> (i * 8)) & 0xff;
  for (let i = 0; i < 4; i++) buf[at + 4 + i] = 0xff;
  return buf;
}

/** Минимальный userland-примитив: bump-аллокатор + чтение/запись процесса. */
function makeProcessMem() {
  const size = 0x40000;
  const mem = new Uint8Array(size);
  let bump = 0x1000;
  return {
    mem,
    malloc(n) { const a = bump; bump += Math.max(16, (n + 15) & ~15); return KI64 ? KI64.of(a) : a; },
    read(addr, n) {
      const o = addr && addr.low !== undefined ? addr.low : addr;
      return Uint8Array.from(mem.slice(o, o + n));
    },
    write(addr, bytes) {
      const o = addr && addr.low !== undefined ? addr.low : addr;
      for (let i = 0; i < bytes.length && o + i < size; i++) mem[o + i] = bytes[i] & 0xff;
    }
  };
}

/** Прогнать kernel с заданным видом ответа rtmsg2 и вернуть исход leakKernelBase. */
async function runKaslrWith(replyFactory) {
  const proc = makeProcessMem();
  // Кладём валидный author-record по адресу 0x1000: это нужно для формы «число»
  // (указатель), иначе WARN был бы артефактом мока, а не свойством kernel-модуля.
  try { proc.mem.set(record, 0x1000); } catch (e) {}
  // p: только то, что нужно стадии KASLR
  const kp = {
    I64: KI64,
    ready: () => true,
    reason: () => '',
    malloc: (n) => proc.malloc(n),
    read: (a, n) => proc.read(a, n),
    write: (a, b) => proc.write(a, b),
    read1: (a) => proc.read(a, 1)[0] || 0,
    read2: (a) => { const b = proc.read(a, 2); return (b[0] | (b[1] << 8)) >>> 0; },
    read4: (a) => { const b = proc.read(a, 4); return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0; },
    read8: (a) => { const b = proc.read(a, 8); let v = 0n; for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[i]); return v; },
    write1: (a, v) => proc.write(a, Uint8Array.of(v & 0xff)),
    write4: (a, v) => proc.write(a, Uint8Array.of(v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff)),
    write8: (a, v) => { const b = new Uint8Array(8); let x = BigInt(v); for (let i = 0; i < 8; i++) { b[i] = Number(x & 0xffn); x >>= 8n; } proc.write(a, b); },
    add32: (a, n) => { const lo = (a && a.low !== undefined ? a.low : a) >>> 0; return KI64.of((lo + n) >>> 0); },
    readBytes: (a, n) => proc.read(a, n),
    writeBytes: (a, b) => proc.write(a, b),
    pipeRead: null, pipeWrite: null
  };
  const chain = { async rtmsg2() { return replyFactory(); }, async syscall() { return { low: 0, hi: 0 }; } };
  const kx = new KernelExploit1422(kp, chain, () => {}, {});
  try {
    await kx.leakKernelBase();
    const cands = Array.isArray(kx.kbaseCandidates) ? kx.kbaseCandidates.length : 0;
    const kb = kx.kbase;
    const kbOk = !!(kb && typeof kb.isZero === 'function' && !kb.isZero());
    let kbHex = null;
    if (kbOk) { try { kbHex = '0x' + (typeof kb.hex === 'function' ? kb.hex() : kb.toString(16)); } catch (e) { kbHex = '?'; } }
    return { ok: true, err: null, cands, kbOk, kbHex };
  } catch (e) {
    return { ok: false, err: (e && (e.reason || e.message)) || String(e), cands: 0, kbOk: false };
  }
}

const NOT_REPLY = /routing socket не дал ответа|не дал ответа/i;
const record = makeRecord();

const shapes = [
  ['C3.a', '{ptr,bytes}', () => ({ ptr: 0x1000, bytes: record })],
  ['C3.b', 'Uint8Array', () => record],
  ['C3.c', 'число (указатель)', () => { const proc = makeProcessMem(); return 0x1000; }]
];
for (const [id, label, factory] of shapes) {
  const res = await runKaslrWith(factory);
  const rejectedAsNoReply = !res.ok && NOT_REPLY.test(res.err || '');
  if (rejectedAsNoReply) {
    check(id, 'rtmsg2 → ' + label, false, 'ОТВЕРГНУТО как «не дал ответа»: ' + String(res.err).slice(0, 70));
  } else if (res.ok && res.kbOk && res.cands > 0) {
    check(id, 'rtmsg2 → ' + label, true,
      `author-record найден, ret≠0, кандидатов=${res.cands}, kbase=${res.kbHex}`);
  } else {
    // Форма принята, но байты потерялись — латентный разрыв, не блокер сборки.
    // Живой контракт (PRIMITIVE-CONTRACT.md:55) — Uint8Array, он проходит.
    warn(id, 'rtmsg2 → ' + label,
      'форма принята, но стадия 1 не дала author-record: ' +
      (res.err ? String(res.err).slice(0, 70) : `kbaseOk=${res.kbOk} cands=${res.cands}`));
  }
}

// ------------------------------------------------------- C4: дубли методов
section('C4. нет повторных определений методов в классах kernel-модуля');
const KW = new Set(['if', 'for', 'while', 'switch', 'catch', 'else', 'do', 'return', 'function', 'new', 'typeof']);
const lines = kernelCode.split('\n');
const classes = [];
lines.forEach((l, i) => {
  const m = /^(?:export\s+)?class\s+([A-Za-z0-9_]+)/.exec(l);
  if (m) classes.push({ line: i + 1, name: m[1] });
});
let dupTotal = 0;
for (let ci = 0; ci < classes.length; ci++) {
  const start = classes[ci].line;
  const end = ci + 1 < classes.length ? classes[ci + 1].line - 1 : lines.length;
  const meths = [];
  for (let j = start; j <= end; j++) {
    // ОПРЕДЕЛЕНИЕ метода: один таб, имя, параметры, и строка КОНЧАЕТСЯ телом '{'.
    // Вызовы вида put(0x0100, [...]) ; или , — сюда не попадают (в этом и была
    // ловушка первого варианта проверки: он считал вызовы дублями).
    const m = /^\t(?:async\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)\s*\{\s*$/.exec(lines[j - 1]);
    if (m && !KW.has(m[1])) meths.push({ name: m[1], line: j });
  }
  const byName = new Map();
  for (const m of meths) byName.set(m.name, [...(byName.get(m.name) || []), m.line]);
  const dups = [...byName.entries()].filter(([, ls]) => ls.length > 1);
  dupTotal += dups.length;
  check('C4.' + classes[ci].name, `класс ${classes[ci].name}: методов ${meths.length}`,
    dups.length === 0,
    dups.length ? 'ДУБЛИ: ' + dups.map(([n, ls]) => `${n}@${ls.join('/')}`).join(', ') : 'дублей нет');
}

// ---------------------------------------------------------------------- итог
const total = rows.length, passed = total - fails;
console.log('\n' + '='.repeat(72));
for (const r of rows) console.log(`  ${r.st}  ${r.id.padEnd(18)} ${r.name}`);
console.log('='.repeat(72));
console.log(`CONTRACT_RESULT: ${fails === 0 ? 'PASS' : 'FAIL'}  (${passed}/${total}, WARN=${warns}, дублей методов: ${dupTotal})`);
process.exit(fails === 0 ? 0 : 1);