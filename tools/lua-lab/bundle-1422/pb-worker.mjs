// bundle-1422 / pb-worker.mjs — поток, который держит TCP-сокет к kernel-runner
// и обслуживает СИНХРОННЫЕ вызовы p.read*/write*/malloc из главного потока.
//
// Схема: SharedArrayBuffer (Int32Array управление + Uint8Array данные).
// Главный поток: заполнить запрос -> Atomics.store(req,1) -> notify -> Atomics.wait(resp) -> прочитать.
// Воркер: Atomics.wait(req) -> забрать параметры -> async I/O по сокету -> записать ответ -> notify.
import net from 'node:net';
import { workerData } from 'node:worker_threads';

const CMD = { READ: 1, WRITE: 2, MALLOC: 3, SYSCALL: 4, READY: 5, REASON: 6, PING: 7 };
const DATA_OFF = 1024;
const DATA_SIZE = 1 << 16;

const SAB = workerData.sab;
const control = new Int32Array(SAB, 0, 16);
const data = new Uint8Array(SAB, DATA_OFF, DATA_SIZE);

let sock = null;
let rbuf = Buffer.alloc(0);
let port = workerData.port;
let host = workerData.host || '127.0.0.1';

function connect() {
  return new Promise((resolve, reject) => {
    sock = net.connect({ host, port }, () => resolve());
    sock.on('error', reject);
    sock.on('data', (chunk) => { rbuf = Buffer.concat([rbuf, chunk]); });
  });
}

function recvExact(n) {
  return new Promise((resolve, reject) => {
    const tick = () => {
      if (rbuf.length >= n) {
        const out = rbuf.subarray(0, n);
        rbuf = rbuf.subarray(n);
        resolve(out);
      } else {
        setTimeout(tick, 1);
      }
    };
    tick();
  });
}

async function roundTrip(frame, need) {
  sock.write(frame);
  const status = (await recvExact(1))[0];
  if (status !== 0) {
    const msg = (await recvExact(1)).toString();
    throw new Error('runner error: ' + msg);
  }
  return need ? await recvExact(need) : Buffer.alloc(0);
}

function u64le(buf, off) {
  return buf.readBigUInt64LE(off);
}

function packU64(v) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(v));
  return b;
}

async function serve() {
  await connect();
  // сообщаем главному потоку, что соединение готово
  Atomics.store(control, 1, 1);
  Atomics.notify(control, 1);

  for (;;) {
    // ждём запрос: [0]=req flag
    while (Atomics.load(control, 0) === 0) Atomics.wait(control, 0, 0, 1000);
    const op = Atomics.load(control, 2);
    const addrLo = control[3], addrHi = control[4], len = control[5];
    const addr = (BigInt(addrHi >>> 0) << 32n) | BigInt(addrLo >>> 0);
    let status = 0;
    try {
      if (op === CMD.READ) {
        const buf = await roundTrip(Buffer.concat([Buffer.from([CMD.READ]), packU64(addr), packU64(len)]), len);
        data.set(buf.subarray(0, Math.min(len, DATA_SIZE)), 0);
        control[6] = buf.length;
      } else if (op === CMD.WRITE) {
        const payload = data.subarray(0, len);
        await roundTrip(Buffer.concat([Buffer.from([CMD.WRITE]), packU64(addr), packU64(len), Buffer.from(payload)]), 0);
      } else if (op === CMD.MALLOC) {
        const out = await roundTrip(Buffer.concat([Buffer.from([CMD.MALLOC]), packU64(addr), packU64(len)]), 8);
        const value = u64le(out, 0);
        control[3] = Number(value & 0xFFFFFFFFn);
        control[4] = Number((value >> 32n) & 0xFFFFFFFFn);
      } else if (op === CMD.SYSCALL) {
        const argc = Atomics.load(control, 7);
        const parts = [Buffer.from([CMD.SYSCALL]), packU64(addr), Buffer.from([argc])];
        for (let i = 0; i < argc; i++) {
          const a = (BigInt(control[8 + i * 2 + 1] >>> 0) << 32n) | BigInt(control[8 + i * 2] >>> 0);
          parts.push(packU64(a));
        }
        const out = await roundTrip(Buffer.concat(parts), 8);
        const value = out.readBigInt64LE(0);
        control[3] = Number(value & 0xFFFFFFFFn);
        control[4] = Number((value >> 32n) & 0xFFFFFFFFn);
      } else if (op === CMD.PING) {
        await roundTrip(Buffer.from([CMD.PING]), 4);
      } else {
        status = 1;
      }
    } catch (e) {
      status = 1;
      control[7] = 0;
    }
    control[6] = control[6] || 0;
    Atomics.store(control, 2, status);   // reuse slot 2 for status после выполнения
    Atomics.store(control, 0, 0);        // сброс запроса
    Atomics.store(control, 1, 2);        // resp flag: 2 = done
    Atomics.notify(control, 1);
  }
}

serve().catch((e) => {
  console.error('worker failed:', e && e.message);
  Atomics.store(control, 1, -1);
  Atomics.notify(control, 1);
});