// bundle-1422 / pb-tcp.mjs — примитив `p` поверх TCP к kernel-runner.py.
//
// Зачем: наша kernel-цепочка (tools/jb1422/kernel/relapse1422.js) вызывает p.read*/write*/malloc
// СИНХРОННО, а сеть — асинхронная. Поэтому синхронные операции обслуживает worker-поток
// (pb-worker.mjs) через SharedArrayBuffer + Atomics.wait: главный поток блокируется на время
// запроса, воркер держит сокет. Асинхронные операции (chain.syscall, rw.read/write) идут
// отдельным обычным сокетом.
//
// Интерфейс p совпадает с тем, что ждёт kernel-модуль:
//   p.read1/read4/read8(addr) -> number | {low,hi}
//   p.write1/write4/write8(addr, value)
//   p.malloc(size, align=1) -> {low, hi, add32(n) -> {low,hi,add32}}
//   p.ready() -> true, p.reason() -> "tcp"
//   p.syscall(num, ...args) -> {low, hi}
import net from 'node:net';
import { Worker } from 'node:worker_threads';

const CMD = { READ: 1, WRITE: 2, MALLOC: 3, SYSCALL: 4, READY: 5, REASON: 6, PING: 7,
              // память ЯДРА отдельным пространством (см. jb1422 §15.4)
              READK: 8, WRITEK: 9 };
const SAB_SIZE = 1024 + (1 << 16);
const DATA_OFF = 1024;
const MAX_DATA = 1 << 16;

function toBigInt(value) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') return BigInt(Math.trunc(value));
  if (value && typeof value === 'object') {
    if ('low' in value) {
      return (BigInt(value.hi >>> 0) << 32n) | BigInt(value.low >>> 0);
    }
    if (value.add32) return toBigInt(value.add32(0));
  }
  throw new Error('cannot convert address: ' + String(value));
}

function split64(value) {
  const v = toBigInt(value);
  return [Number(v & 0xFFFFFFFFn), Number((v >> 32n) & 0xFFFFFFFFn)];
}

function handle(value) {
  const [low, hi] = split64(value);
  return {
    low, hi,
    add32(n) { return handle(((BigInt(hi) << 32n) | BigInt(low)) + BigInt(n | 0)); },
    add(n) { return this.add32(n); },
  };
}

// ---------------------------------------------------------------- sync primitive (worker)
export function openSyncPrimitive(host, port, timeoutMs = 30000) {
  const sab = new SharedArrayBuffer(SAB_SIZE);
  const ctl = new Int32Array(sab, 0, 16);
  const data = new Uint8Array(sab, DATA_OFF, MAX_DATA);
  const worker = new Worker(new URL('./pb-worker.mjs', import.meta.url), {
    workerData: { sab, host, port },
  });
  worker.unref?.();

  // ждём, пока воркер подключится: resp-флаг (ctl[1]) станет 1
  const readyDeadline = Date.now() + timeoutMs;
  while (Atomics.load(ctl, 1) === 0) {
    if (Date.now() > readyDeadline) throw new Error('worker did not connect to ' + host + ':' + port);
    Atomics.wait(ctl, 1, 0, 50);
  }
  if (Atomics.load(ctl, 1) === -1) throw new Error('worker connection failed');

  function call(op, addr, len, payload, argv) {
    Atomics.store(ctl, 1, 0);
    ctl[2] = op;
    const [lo, hi] = split64(addr || 0);
    ctl[3] = lo; ctl[4] = hi; ctl[5] = len | 0;
    if (argv) {
      ctl[7] = argv.length;
      argv.forEach((a, i) => {
        const [alo, ahi] = split64(a);
        ctl[8 + i * 2] = alo;
        ctl[8 + i * 2 + 1] = ahi;
      });
    }
    if (payload) data.set(payload.subarray(0, Math.min(payload.length, MAX_DATA)), 0);
    Atomics.store(ctl, 0, 1);
    Atomics.notify(ctl, 0);
    const deadline = Date.now() + timeoutMs;
    while (Atomics.load(ctl, 1) !== 2) {
      if (Date.now() > deadline) throw new Error('primitive op timeout (op=' + op + ')');
      Atomics.wait(ctl, 1, 0, 50);
    }
    const status = Atomics.load(ctl, 2);
    if (status !== 0) throw new Error('primitive op failed (op=' + op + ')');
    return { value: { low: ctl[3] >>> 0, hi: ctl[4] >>> 0 }, len: ctl[6] | 0 };
  }

  // Батчинг последовательных write1: kernel-staging пишет ELF побайтно; без этого
  // 394k однобайтовых TCP-раундтрипов превращают прогон в часы. Батч сбрасывается
  // перед любым чтением/непрерывным разрывом и по достижении 32 KiB — семантика та же.
  let pending = null;
  const PEND_MAX = 32768;
  // кэш чтения: сканеры цепочки читают байты по одному (4096 на чанк), без кэша
  // это 4604 мс на один чанк. Префетчим страницу и обслуживаем read1 локально.
  let rcache = null;
  const PREFETCH = 4096;
  function flushPending() {
    if (pending && pending.bytes.length) {
      call(CMD.WRITE, pending.addr, pending.bytes.length, Uint8Array.from(pending.bytes));
    }
    pending = null;
    rcache = null;                       // любая запись инвалидирует кэш чтения
  }
  function readCached(addrBig) {
    if (rcache && addrBig >= rcache.addr && addrBig < rcache.addr + BigInt(rcache.buf.length)) {
      return { buf: rcache.buf, off: Number(addrBig - rcache.addr) };
    }
    flushPending();
    let buf;
    try {
      const res = call(CMD.READ, addrBig, PREFETCH);
      buf = Uint8Array.from(data.subarray(0, Math.max(1, res.len)));
    } catch {
      const res = call(CMD.READ, addrBig, 1);   // у границы маппинга префетч может упасть
      buf = Uint8Array.from(data.subarray(0, Math.max(1, res.len)));
    }
    rcache = { addr: addrBig, buf };
    return { buf, off: 0 };
  }

  const p = {
    flush() { flushPending(); },
    invalidate() { rcache = null; },
    ready() { return true; },
    reason() { return 'tcp'; },
    read1(addr) { const { buf, off } = readCached(toBigInt(addr)); return buf[off]; },
    read4(addr) {
      flushPending();
      call(CMD.READ, addr, 4);
      return (data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)) >>> 0;
    },
    read8(addr) {
      flushPending();
      call(CMD.READ, addr, 8);
      const lo = (data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24)) >>> 0;
      const hi = (data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24)) >>> 0;
      return { low: lo, hi };
    },
    read(addr, len) {
      flushPending();
      call(CMD.READ, addr, len);
      return Uint8Array.from(data.subarray(0, len));
    },
    write1(addr, value) {
      const a = toBigInt(addr);
      if (pending && a === pending.addr + BigInt(pending.bytes.length)) {
        pending.bytes.push(value & 0xFF);
      } else {
        flushPending();
        pending = { addr: a, bytes: [value & 0xFF] };
      }
      if (pending.bytes.length >= PEND_MAX) flushPending();
    },
    write4(addr, value) {
      flushPending();
      const b = new Uint8Array(4);
      for (let i = 0; i < 4; i++) b[i] = (value >>> (i * 8)) & 0xFF;
      call(CMD.WRITE, addr, 4, b);
    },
    write8(addr, value) {
      flushPending();
      const v = toBigInt(value);
      const b = new Uint8Array(8);
      for (let i = 0; i < 8; i++) b[i] = Number((v >> BigInt(i * 8)) & 0xFFn);
      call(CMD.WRITE, addr, 8, b);
    },
    write(addr, bytes) {
      flushPending();
      call(CMD.WRITE, addr, bytes.length, Uint8Array.from(bytes));
    },
    malloc(size, align = 1) {
      flushPending();
      const { value } = call(CMD.MALLOC, size, align);
      return handle((BigInt(value.hi) << 32n) | BigInt(value.low));
    },
    syscall(num, ...args) {
      const { value } = call(CMD.SYSCALL, num, 0, null, args);
      return value;
    },
    close() { flushPending(); worker.terminate(); },
  };
  return p;
}

// ---------------------------------------------------------------- async client (chain/rw)
export class AsyncClient {
  constructor(host, port) {
    this.host = host;
    this.port = port;
    this.sock = null;
    this.rbuf = Buffer.alloc(0);
  }

  connect() {
    return new Promise((resolve, reject) => {
      this.sock = net.connect({ host: this.host, port: this.port }, () => resolve(this));
      this.sock.on('error', reject);
      this.sock.on('data', (c) => { this.rbuf = Buffer.concat([this.rbuf, c]); });
    });
  }

  recvExact(n) {
    return new Promise((resolve) => {
      const tick = () => {
        if (this.rbuf.length >= n) {
          const out = this.rbuf.subarray(0, n);
          this.rbuf = this.rbuf.subarray(n);
          resolve(out);
        } else setTimeout(tick, 1);
      };
      tick();
    });
  }

  async roundTrip(frame, need) {
    this.sock.write(frame);
    const status = (await this.recvExact(1))[0];
    if (status !== 0) throw new Error('runner error');
    return need ? await this.recvExact(need) : Buffer.alloc(0);
  }

  async callSyscall(num, args) {
    const parts = [Buffer.from([CMD.SYSCALL])];
    const nb = Buffer.alloc(8); nb.writeBigUInt64LE(BigInt(num)); parts.push(nb);
    parts.push(Buffer.from([args.length]));
    for (const a of args) {
      const ab = Buffer.alloc(8); ab.writeBigUInt64LE(toBigInt(a)); parts.push(ab);
    }
    const out = await this.roundTrip(Buffer.concat(parts), 8);
    const v = out.readBigInt64LE(0);
    return { low: Number(v & 0xFFFFFFFFn), hi: Number((v >> 32n) & 0xFFFFFFFFn) };
  }

  async syscall(num, ...args) { return this.callSyscall(num, args); }

  async readKernel(addr, len) {
    const parts = [Buffer.from([CMD.READK])];
    const ab = Buffer.alloc(8); ab.writeBigUInt64LE(toBigInt(addr)); parts.push(ab);
    const lb = Buffer.alloc(8); lb.writeBigUInt64LE(BigInt(len)); parts.push(lb);
    return Uint8Array.from(await this.roundTrip(Buffer.concat(parts), len));
  }

  async writeKernel(addr, bytes) {
    const parts = [Buffer.from([CMD.WRITEK])];
    const ab = Buffer.alloc(8); ab.writeBigUInt64LE(toBigInt(addr)); parts.push(ab);
    const lb = Buffer.alloc(8); lb.writeBigUInt64LE(BigInt(bytes.length)); parts.push(lb);
    parts.push(Buffer.from(bytes));
    await this.roundTrip(Buffer.concat(parts), 0);
  }

  async read(addr, len) {
    const parts = [Buffer.from([CMD.READ])];
    const ab = Buffer.alloc(8); ab.writeBigUInt64LE(toBigInt(addr)); parts.push(ab);
    const lb = Buffer.alloc(8); lb.writeBigUInt64LE(BigInt(len)); parts.push(lb);
    return Uint8Array.from(await this.roundTrip(Buffer.concat(parts), len));
  }

  async write(addr, bytes) {
    const parts = [Buffer.from([CMD.WRITE])];
    const ab = Buffer.alloc(8); ab.writeBigUInt64LE(toBigInt(addr)); parts.push(ab);
    const lb = Buffer.alloc(8); lb.writeBigUInt64LE(BigInt(bytes.length)); parts.push(lb);
    parts.push(Buffer.from(bytes));
    await this.roundTrip(Buffer.concat(parts), 0);
  }
}


export const pipeStats = { pipeReadBytesCalls: 0, pipeReadBytesBytes: 0, pipeReadCalls: 0,
                           pipeWriteCalls: 0, pipeWriteBytesCalls: 0, pipeWriteBytesBytes: 0 };

export function attachPipes(p, client) {
  // bulk-чтение: kernel-модуль предпочитает p.readBytes(addr,len) в crossPipes (1 round-trip)
  p.readBytes = async function (addr, len) { p.flush(); return client.read(addr, len); };
  p.writeBytes = async function (addr, bytes) { const r = await client.write(addr, bytes); p.invalidate(); return r; };
  // pipeReadBytes: bulk-чтение ЯДРА через pipe (p.readBytes — это ПРОЦЕСС, не путать)
  p.pipeReadBytes = async function (addr, len) {
    p.flush();
    pipeStats.pipeReadBytesCalls++;
    pipeStats.pipeReadBytesBytes += len;
    return client.readKernel(addr, len);
  };
  p.pipeRead = async function (addr, len, out) {
    pipeStats.pipeReadCalls++;
    p.flush();
    const bytes = await client.readKernel(addr, len);
    p.flush();
    for (let i = 0; i < len; i++) p.write1(out.add32(i), bytes[i]);
    p.flush();
    return len;
  };
  // pipeWriteBytes: bulk-ЗАПИСЬ ЯДРА через pipe (1 round-trip); симметрично pipeReadBytes.
  p.pipeWriteBytes = async function (addr, bytes) {
    p.flush();
    pipeStats.pipeWriteBytesCalls++;
    pipeStats.pipeWriteBytesBytes += bytes.length;
    await client.writeKernel(addr, bytes);
    p.invalidate();
    return bytes.length;
  };
  p.pipeWrite = async function (addr, val, len) {
    pipeStats.pipeWriteCalls++;
    const v = toBigInt(val);
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = Number((v >> BigInt(8 * i)) & 0xFFn);
    await client.writeKernel(addr, bytes);
    p.invalidate();
    return len;
  };
  return p;
}

export function makeChain(asyncClient, syncPrimitive) {
  return {
    async syscall(num, ...args) { return asyncClient.callSyscall(num, args); },
    async rtmsg2() {
      // 512-байтный ответ routing-socket, побайтно как в makeDryRunMocks():
      // buf[0]=0x04, buf[1]=0x00; ret (predict) в слоте 184; buf[188..191]=0xffffffff.
      const bufAddr = syncPrimitive.malloc(512, 1);
      const payload = new Uint8Array(512);
      payload[0] = 0x04;
      payload[1] = 0x00;
      const ret = 0x00B06869;
      for (let i = 0; i < 4; i++) payload[184 + i] = (ret >>> (i * 8)) & 0xFF;
      for (let i = 0; i < 4; i++) payload[188 + i] = 0xFF;
      // Возвращаем ПРОСТОЙ Uint8Array: kernel-модуль в routingSocketReply() делает
      // copyIntoProcess(bytes) (p.write1 в память процесса) и затем читает ответ
      // обратно через p.readBytes — именно этот путь и надо проверить на TCP.
      // Объект вида {ptr, bytes} kernel-модуль не принимает (new Uint8Array(obj) => пусто).
      syncPrimitive.write(bufAddr, payload);
      if (syncPrimitive.flush) syncPrimitive.flush();
      // Контракт моста (важно, зафиксировано в README):
      //   chain.rtmsg2() -> Uint8Array(512) с дополнительными полями:
      //       .ptr   — адрес этого же буфера в памяти ПРОЦЕССА (как на консоли);
      //       .bytes — он же (для kernel-кода, который ждёт {ptr, bytes}).
      // Гибрид нужен потому, что kernel.copyIntoProcess() принимает Uint8Array
      // напрямую (`new Uint8Array(obj)` от чистого объекта даёт 0 байт).
      // Контракт моста (зафиксировано с kernel-владельцем): по умолчанию —
      // ОБЪЕКТ { ptr, bytes }, где bytes — Uint8Array(512). PB_RTMSG2=hybrid
      // возвращает Uint8Array с полями .ptr/.bytes (совместимость со старым kernel,
      // который звал new Uint8Array(obj) и получал 0 байт).
      // КОНТРАКТ (финальный, согласован с владельцем kernel-модуля): chain.rtmsg2()
      // возвращает ОБЪЕКТ { ptr, bytes }, где ptr — адрес буфера в памяти ПРОЦЕССА,
      // bytes — Uint8Array(512). Kernel принимает его через routingSocketReply():
      //   const bytes = KernelExploit1422.toBytes(reply) ||
      //                 KernelExploit1422.toBytes(reply && reply.bytes);
      // PB_RTMSG2=hybrid — legacy: Uint8Array с полями .ptr/.bytes (для старого kernel,
      // который звал new Uint8Array(obj)). По умолчанию — чистый object.
      const mode = process.env.PB_RTMSG2 || 'object';
      let reply;
      if (mode === 'hybrid') {
        payload.ptr = bufAddr;
        payload.bytes = payload;
        reply = payload;
      } else {
        reply = { ptr: bufAddr, bytes: payload };
      }
      if (process.env.PB_DEBUG) {
        const head = Array.from(payload.slice(0, 8)).map(function (x) { return x.toString(16).padStart(2, '0'); }).join(' ');
        const ret184 = Array.from(payload.slice(184, 192)).map(function (x) { return x.toString(16).padStart(2, '0'); }).join(' ');
        console.error('[rtmsg2] mode=' + mode + ' type=' + reply.constructor.name +
                      ' bytesType=' + payload.constructor.name + ' len=' + payload.length +
                      ' first8=' + head + ' ret@184=' + ret184 +
                      ' ptr=0x' + Number(bufAddr.low).toString(16));
      }
      return reply;
    },
    add_syscall() {},
    add_syscall_ret() {},
  };
}

export function makeRw(asyncClient) {
  return {
    // rw — ЕДИНСТВЕННЫЙ путь чтения/записи ЯДРА (не путать с p.readBytes = процесс)
    async read(addr, len) { return asyncClient.readKernel(addr, len); },
    async write(addr, bytes) { return asyncClient.writeKernel(addr, bytes); },
  };
}