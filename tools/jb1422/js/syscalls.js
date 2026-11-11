/* jb1422 / syscalls.js — объект chain для kernel-стадии (контракт runKernelExploit(p, chain, log)).
 *
 * Проблема: из JS нельзя вызвать syscall напрямую — нужен userland code-exec (ROP/vtable hijack)
 * внутри WebProcess. Поэтому chain = тонкая обёртка, которой kernel-модуль даёт "call primitive":
 *
 *   chain.bindCall(fn)  — fn(addr, argsArray) -> {rax, rdx}  (реализуется kernel-модулем:
 *                         ROP-цепочка/виртуальный вызов по адресу в libkernel)
 *   chain.setGadgets(g)  — адреса функций libkernel/гейджетов:
 *                         {syscall, malloc, mmap, mprotect, close, __error, ...}
 *   chain.syscall(nr, a1..a6)
 *   chain.mmap(size, prot) / chain.malloc(size) / chain.mprotect(addr,size,prot)
 *   chain.resolve(name)  — по имени находит адрес в таблице гейджетов
 *
 * Пока bindCall/setGadgets не заданы — методы бросают JbNotReady с точной причиной
 * (это не заглушка, а требование входных данных: base/libkernel leak и code-exec).
 * Код методов полностью реализован и начинает работать сразу после bindCall+setGadgets.
 */
(function (global) {
  'use strict';

  var NotReady = (global.JBPrimitive && global.JBPrimitive.JbNotReady) || function (r) {
    var e = new Error(r); e.name = 'JbNotReady'; e.reason = r; return e;
  };

  function createChain(p, log) {
    log = log || function () {};
    var state = {
      call: null,          // fn(addr, args) -> {rax, rdx}
      gadgets: {},         // name -> '0x...'
      lastErr: 'chain not bound: no call primitive / gadget addresses'
    };

    function need(what) {
      if (!state.call) throw new NotReady('chain.' + what + ': ' + state.lastErr);
      return true;
    }

    var chain = {
      // ---- установка возможностей (делает kernel-модуль после leak/code-exec) ----
      bindCall: function (fn) { state.call = fn; state.lastErr = fn ? '' : 'call cleared'; return chain; },
      setGadgets: function (g) {
        if (g && typeof g === 'object') {
          Object.keys(g).forEach(function (k) { if (g[k]) state.gadgets[k] = g[k]; });
        }
        return chain;
      },
      hasCall: function () { return typeof state.call === 'function'; },
      hasGadgets: function () { return Object.keys(state.gadgets).length > 0; },
      reason: function () { return state.lastErr; },
      gadget: function (name) {
        if (!state.gadgets[name]) throw new NotReady('gadget "' + name + '" not set (needs libkernel base)');
        return state.gadgets[name];
      },
      resolve: function (name) {
        if (state.gadgets[name]) return state.gadgets[name];
        if (name === '__error') return '0x0'; // будет заменено на реальный адрес в bindCall-обвязке
        throw new NotReady('resolve("' + name + '"): address table empty (kernel module must supply)');
      },
      // ---- сырой вызов по адресу ----
      call: function (addr, args) {
        if (!state.call) throw new NotReady('chain.call: no call primitive');
        return state.call(addr, args || []);
      },
      // ---- syscall через libkernel: адрес syscall-гейджета даёт kernel-модуль ----
      syscall: function (nr, a1, a2, a3, a4, a5, a6) {
        need('syscall');
        var addr = chain.gadget('syscall');
        var res = state.call(addr, [nr, a1 || 0, a2 || 0, a3 || 0, a4 || 0, a5 || 0, a6 || 0]);
        return res; // {rax, rdx} или число — как вернёт call primitive
      },
      // ---- обёртки FreeBSD libc/mmap ----
      mmap: function (size, prot, flags) {
        need('mmap');
        var addr = chain.gadget('mmap');
        return state.call(addr, [0, size, prot || 3, flags || 0x1002, -1, 0]);
      },
      malloc: function (size) {
        need('malloc');
        var addr = chain.gadget('malloc');
        return state.call(addr, [size]);
      },
      free: function (ptr) {
        need('free');
        return state.call(chain.gadget('free'), [ptr]);
      },
      mprotect: function (addr, size, prot) {
        need('mprotect');
        return state.call(chain.gadget('mprotect'), [addr, size, prot]);
      },
      close: function (fd) {
        need('close');
        return state.call(chain.gadget('close'), [fd]);
      },
      // ---- удобные типизированные чтения/записи через p (userland R/W) ----
      read64: function (addr) { return p.read64(addr); },
      write64: function (addr, val) { return p.write64(addr, val); },
      read32: function (addr, off) { return p.read32(addr, off); },
      write32: function (addr, off, val) { return p.write32(addr, off, val); },
      add: function (addr, off) { return p.add(addr, off); },
      describe: function () {
        return {
          call: typeof state.call === 'function',
          gadgetCount: Object.keys(state.gadgets).length,
          gadgets: Object.keys(state.gadgets),
          reason: state.lastErr || 'bound'
        };
      }
    };
    return chain;
  }

  global.JBSyscalls = { createChain: createChain };
})(typeof window !== 'undefined' ? window : globalThis);