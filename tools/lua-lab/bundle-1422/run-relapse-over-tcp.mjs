// bundle-1422 / run-relapse-over-tcp.mjs
// Запускает НАШУ kernel-цепочку (tools/jb1422/kernel/relapse1422.js) поверх примитива,
// который приходит по TCP из Python (kernel-runner.py --mock-kernel).
//
// Это интеграционная точка: kernel-модуль не трогаем — он по-прежнему получает
// runKernelExploitWith(p, chain, log, options), только p/chain/rw теперь ходят в TCP.
//
//   node run-relapse-over-tcp.mjs --addr=127.0.0.1:9139
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { readFile } from 'node:fs/promises';

import { openSyncPrimitive, AsyncClient, makeChain, makeRw, attachPipes } from './pb-tcp.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const JB1422 = path.resolve(HERE, '../../jb1422');

function argValue(name, fallback) {
  const hit = process.argv.find((a) => a.startsWith('--' + name + '='));
  return hit ? hit.split('=').slice(1).join('=') : fallback;
}

const addrSpec = argValue('addr', '127.0.0.1:9139');
const [host, portStr] = addrSpec.split(':');
const port = Number(portStr);

console.log(`=== full-chain через Python-примитив (TCP ${host}:${port}) ===`);

// окно нужно до импорта модуля (он проверяет globalThis.window для экспорта)
globalThis.window = globalThis;

const kernelUrl = pathToFileURL(path.join(JB1422, 'kernel', 'relapse1422.js')).href;
const kernel = await import(kernelUrl);
const offsetsUrl = pathToFileURL(path.join(JB1422, 'kernel', 'offsets', '1422.js')).href;
await import(offsetsUrl);
const KRW = globalThis.window.KRW;
if (!KRW) {
  console.error('offsets/1422.js не загрузились — нет globalThis.window.KRW');
  process.exit(2);
}

// payload ищем как в dry-run CLI
let payload = null;
let payloadLabel = '(нет)';
const candidates = [
  path.resolve(HERE, '../../payload/payloads/elfldr-ps5-v0.27.elf'),   // ps5jb/tools/payload
  path.resolve(HERE, '../../jb1422/../payload/payloads/elfldr-ps5-v0.27.elf'),
  path.resolve(process.cwd(), '../payload/payloads/elfldr-ps5-v0.27.elf'),
  path.resolve(process.cwd(), 'payload/payloads/elfldr-ps5-v0.27.elf'),
];
for (const candidate of candidates) {
  try {
    payload = new Uint8Array(await readFile(candidate));
    payloadLabel = `${candidate} (${payload.length} байт)`;
    break;
  } catch { /* пробуем следующий */ }
}

// stage 13: триггер t1_aio_wait_race.elf (кладём в options.triggerPayload)
let triggerPayload = null;
let triggerName = 't1_aio_wait_race.elf';
const triggerCandidates = [
  path.resolve(HERE, '../../jb1422/payloads/triggers/t1_aio_wait_race.elf'),
  path.resolve(HERE, '../../kexpl/t1_aio_wait_race.elf'),
  path.resolve(process.cwd(), 'tools/jb1422/payloads/triggers/t1_aio_wait_race.elf'),
];
for (const candidate of triggerCandidates) {
  try {
    triggerPayload = new Uint8Array(await readFile(candidate));
    triggerName = path.basename(candidate);
    break;
  } catch { /* пробуем следующий */ }
}

const p = openSyncPrimitive(host, port);
const client = await new AsyncClient(host, port).connect();
const chain = makeChain(client, p);
const rw = makeRw(client);
attachPipes(p, client);   // stage 8: cross-pipes через p.pipeRead/p.pipeWrite

console.log(`primitive: p.ready=${p.ready()} p.reason=${p.reason()}`);
console.log(`firmware: ${KRW.firmware}; payload: ${payloadLabel}`);
console.log('');

const lines = [];
let result;
try {
  result = await kernel.runKernelExploitWith(
    p,
    chain,
    (text) => lines.push(text),
    { attachKernelRw: () => rw, payload, elfldrNoWait: true,
      triggerPayload, triggerName },
  );
} finally {
  p.close();
  client.sock?.destroy();
}

for (const line of lines) console.log('  ' + line);

console.log('\n=== ТАБЛИЦА СТАДИЙ (через TCP-примитив) ===');
console.log('  n | стадия                                      | статус   | деталь');
console.log('  --+---------------------------------------------+----------+------------------------------------------');
const stages = result.stages || [];
for (const st of stages) {
  console.log(`  ${String(st.n).padStart(2)} | ${String(st.name).padEnd(44).slice(0, 44)} | ` +
              `${String(st.status).padEnd(8)} | ${(st.detail || '').slice(0, 60)}`);
}
const count = (status) => stages.filter((s) => s.status === status).length;
console.log(`\nИТОГ: done=${result.done}, стадий=${stages.length}, OK=${count('OK')}, ` +
            `DEGRADED=${count('DEGRADED')}, FAIL=${count('FAIL')}`);
process.exitCode = result.done ? 0 : 1;