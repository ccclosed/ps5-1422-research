#!/usr/bin/env node
/* jb1422 / tests/kernel-integration.mjs — SIM-интеграция userland-моста и kernel-модуля.
 *
 * Цель: доказать на ПК, что:
 *   1) js/kernel-bridge.js даёт РОВНО тот интерфейс p/chain, который ждёт
 *      kernel/relapse1422.js (read1/4/8, write1/4/8, malloc, add32, ready/reason;
 *      chain.syscall async -> {low}, chain.rtmsg2);
 *   2) kernel-модуль проходит все стадии до done:true, когда ему дают мок
 *      userland-памяти и мок kernel R/W через p.attachKernelPipe (внешний путь);
 *   3) без userland-доступа (как на ПК с фиксированным WebKit) p.ready()=false и
 *      модуль честно возвращает {done:false, stage:0, status:'BLOCKED'} — это то,
 *      что увидит консоль, если leak не добыт.
 *
 * ЭТО МОК: память "ядра" подменена картой значений (как в --dry-run самого модуля).
 * Реальный R/W доказывается только на консоли 14.22.
 *
 * Run: node tools/jb1422/tests/kernel-integration.mjs
 */
'use strict';

import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { pathToFileURL, fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
let failures = 0;
function ok(name, cond, detail) {
  console.log((cond ? 'PASS ' : 'FAIL ') + name + (detail ? ' — ' + detail : ''));
  if (!cond) failures++;
}
function section(t) { console.log('\n== ' + t + ' =='); }

// ------------------------------------------------------------------ window/offsets
globalThis.window = globalThis;
await import(pathToFileURL(path.join(ROOT, 'kernel/offsets/1422.js')).href);
ok('offsets 14.22 loaded (window.KRW)', !!globalThis.KRW && globalThis.KRW.firmware === '14.22');

// ------------------------------------------------------------------ bridge (plain script)
function loadScript(rel) {
  const code = fs.readFileSync(path.join(ROOT, rel), 'utf8');
  vm.runInThisContext(code, { filename: rel });
}
loadScript('js/kernel-bridge.js');
ok('bridge loaded (JB1422Bridge)', !!globalThis.JB1422Bridge);

const { I64, createPrimitive, createChain } = globalThis.JB1422Bridge;

// ------------------------------------------------------------------ I64 sanity
section('I64 (адресная арифметика Relapse)');
ok('I64.of(0x1000).add32(0x20) = 0x1020', I64.of(0x1000).add32(0x20).hex() === '0x1020');
ok('I64 add32 carry', I64.of({ low: 0xffffffff, hi: 0x1 }).add32(1).hex() === '0x200000000');
ok('I64 sub/eq', I64.of(0x2000).sub(I64.of(0x1000)).eq(I64.of(0x1000)));
ok('I64 kernel pointer check', I64.of({ low: 0x88880000, hi: 0xffffffff }).isKernel());

// ------------------------------------------------------------------ mock memory
const MEM = 0x2000000; // 32 МБ: scan-стадия 5 аллоцирует буферы под каждый чанк текста ядра
const mem = new Uint8Array(MEM);
let bump = 0x1000;
const user = {
  read(addr, n) {
    const o = addr.low >>> 0;
    return Array.from(mem.slice(o, o + n));
  },
  write(addr, bytes) {
    const o = addr.low >>> 0;
    for (let i = 0; i < bytes.length && o + i < MEM; i++) mem[o + i] = bytes[i] & 0xff;
  },
  malloc(size) {
    const a = bump; bump += Math.max(16, (size + 15) & ~15); return I64.of(a);
  }
};
function writeBytes(addrLow, bytes) { for (let i = 0; i < bytes.length; i++) mem[addrLow + i] = bytes[i] & 0xff; }
function u64(low, hi) { writeBytes(0, []); }

// userland buffer для KASLR-ответа и прочих: p.malloc делает bump-аллокацию
const p = createPrimitive(null, null, () => {});

// ------------------------------------------------------------------ mock chain
const chain = createChain(p, () => {});
chain.attachSyscallBackend({
  async syscall(nr, args) {
    // GETPID = 0x014
    if (nr === 0x014) return { low: 275, hi: 0 };
    // CPUSET_GETAFFINITY: kernel пишет маску (0x1) в userland-буфер args[last]
    if (nr === 0x1E7) {
      const out = args[args.length - 1];
      if (out && typeof out.low === 'number') writeBytes(out.low, [0x1, 0x0, 0x0, 0x0, 0, 0, 0, 0]);
      return { low: 0, hi: 0 };
    }
    return { low: 0, hi: 0 };
  },
  async rtmsg2() {
    const buf = new Uint8Array(512);
    buf[0] = 0x04; buf[1] = 0x00;   // как в моке --dry-run kernel-модуля: валидный author-record
    const ret = 0x00B06869, at = 184;
    for (let i = 0; i < 4; i++) buf[at + i] = (ret >>> (i * 8)) & 0xff;
    for (let i = 0; i < 4; i++) buf[at + 4 + i] = 0xff;
    return buf;
  }
});
ok('chain.syscall async -> {low}', (await chain.syscall(0x014)).low === 275);
ok('chain.rtmsg2 returns buffer', (await chain.rtmsg2()).length === 512);

// ------------------------------------------------------------------ mock kernel R/W
// Плоская "память ядра" 16 МБ (нужна для scan-стадии 5, которая читает текст ядра).
// Плоская память для НИЗКИХ rva (текст/данные ядра, которые сканирует STAGE 5) +
// разреженная карта для kernel-heap адресов (0xffffffff8888xxxx и т.п.).
const kernelMem = new Uint8Array(0x4000000); // 64 МБ: оффсеты 14.22 до 0x03E3B510
const sparse = new Map();                    // rva -> byte
const KBASE = 0xffffffff00000000; // kbase.low === 0 -> rva === addr.low
const ALLPROC = 0x035B9EA0, KDATA = 0x00CE0000, SFLAGS = 0x01A84064;
const PROC = 0x88880000, UCRED = 0x88881000, FD = 0x88882000;
function kset(rva, bytes) {
  for (let i = 0; i < bytes.length; i++) {
    const a = (rva + i) >>> 0;
    if (a < kernelMem.length) kernelMem[a] = bytes[i] & 0xff;
    else sparse.set(a, bytes[i] & 0xff);
  }
}
function kptrBytes(v) {
  return [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff, 0xff, 0xff, 0xff, 0xff];
}
function ksetPtr(rva, v) { kset(rva, kptrBytes(v)); }
// allproc: головы на curproc (pointer) в +0x0/+0x8/+0x10
ksetPtr(ALLPROC, PROC); ksetPtr(ALLPROC + 8, PROC); ksetPtr(ALLPROC + 16, PROC);
kset(KDATA, [1, 0, 0, 0]);          // kernelData != 0/-1 -> verify OK
kset(SFLAGS, [0x13, 0x01, 0, 0]);   // security_flags = 0x113 (до escalate)
// proc: next=0 (не указатель -> break), pid @0xbc = 275, ucred @0x40, fd @0x48
kset(PROC, [0, 0, 0, 0, 0, 0, 0, 0]);
kset(PROC + 0xbc, [0x13, 0x01, 0, 0]); // pid 275 = 0x113 LE
ksetPtr(PROC + 0x40, UCRED);
ksetPtr(PROC + 0x48, FD);
kset(FD, [0, 0, 0, 0, 0, 0, 0, 0]);  // таблица ofiles = NULL -> locatePipes DEGRADED (без fail)

function kread(addr, len) {
  if (!addr || addr.hi !== 0xffffffff) throw new Error('mock kread: not a kernel address ' + JSON.stringify(addr));
  const rva = addr.low >>> 0;
  if (rva + len <= kernelMem.length) return kernelMem.slice(rva, rva + len);
  const out = new Uint8Array(len);
  for (let i = 0; i < len; i++) out[i] = sparse.get((rva + i) >>> 0) || 0;
  return out;
}
function kwrite(addr, bytes) {
  if (!addr || addr.hi !== 0xffffffff) throw new Error('mock kwrite: not a kernel address');
  const rva = addr.low >>> 0;
  for (let i = 0; i < bytes.length; i++) {
    const a = (rva + i) >>> 0;
    if (a < kernelMem.length) kernelMem[a] = bytes[i] & 0xff;
    else sparse.set(a, bytes[i] & 0xff);
  }
}
p.attachKernelRwProvider(async () => ({ read: kread, write: kwrite }));
p.attachUserlandAccessor(user);

// ------------------------------------------------------------------ run kernel module
section('kernel module через мост (мок памяти)');
const rel = await import(pathToFileURL(path.join(ROOT, 'kernel/relapse1422.js')).href);
const logs = [];
const res = await rel.runKernelExploit(p, chain, (t) => logs.push(String(t)));
const stageTable = res.stages || [];
const cnt = (s) => stageTable.filter((x) => x.status === s).length;

ok('kernel result is object', !!res && typeof res === 'object');
ok('kernel stages table >= 9', stageTable.length >= 9, 'stages=' + stageTable.length);
ok('kernel done=true на моке', res.done === true, 'done=' + res.done + ' stage=' + res.stage + ' err=' + (res.error || ''));
ok('kbase посчитан', !!res.kbase && (res.kbase.low !== undefined), res.kbase ? JSON.stringify(res.kbase) : 'null');
ok('OK-стадий >= 5', cnt('OK') >= 5, 'OK=' + cnt('OK') + ' DEGRADED=' + cnt('DEGRADED') + ' FAIL=' + cnt('FAIL'));
ok('FAIL-стадий = 0', cnt('FAIL') === 0, 'FAIL=' + cnt('FAIL'));
console.log('   stages: ' + stageTable.map((s) => s.n + ':' + s.status).join(' '));

// ------------------------------------------------------------------ нет accessor -> BLOCKED
section('без userland-доступа (ПК-путь) -> честный BLOCKED');
const pCold = createPrimitive(null, null, () => {});
const chainCold = createChain(pCold, () => {});
const resCold = await rel.runKernelExploit(pCold, chainCold, () => {});
ok('p.ready()=false на ПК', pCold.ready() === false);
ok('kernel: done=false, stage=0', resCold.done === false && resCold.stage === 0,
  'done=' + resCold.done + ' stage=' + resCold.stage + ' status=' + resCold.status);
ok('kernel: причина = userland primitive', /userland|примитив/i.test(JSON.stringify(resCold)),
  JSON.stringify(resCold).slice(0, 140));

// ------------------------------------------------------------------ summary
console.log('');
if (failures === 0) {
  console.log('SIM_RESULT: PASS (интерфейс моста/модуля совпал; мок-цепочка done:true; ПК-путь BLOCKED)');
  process.exit(0);
}
console.log('SIM_RESULT: FAIL (' + failures + ' checks failed)');
process.exit(1);